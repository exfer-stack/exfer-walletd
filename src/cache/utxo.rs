//! L3 — per-address UTXO cache, dual-semantics.
//!
//! Two readers, very different correctness requirements:
//!
//! - **Display readers** (`get_address_utxos`, `get_script_utxos`, and
//!   the `list_balances` UTXO-count column) want a cheap, frequently
//!   reused snapshot. They are happy with cached data and **must
//!   subtract in-flight outpoints** so a UTXO claimed by an unbroadcast
//!   transfer doesn't appear "spendable" to the caller.
//!
//! - **Spend readers** (the `transfer` engine, src/tx/mod.rs:65) need
//!   the freshest possible view: a stale cache hit could pick an
//!   already-spent UTXO and have it rejected at broadcast. The spend
//!   path therefore **always hits upstream**, then writes the response
//!   back to the cache as a side effect (priming subsequent display
//!   reads for free). Inflight subtraction is already handled by the
//!   existing `InFlightUtxos::select_and_claim` atomic lock in the
//!   transfer engine — we don't add a second filter there.
//!
//! ## Eager invalidation
//!
//! When a `transfer` broadcast succeeds, the L3 entry for `from` is
//! invalidated (the spent UTXOs are now stale). If `to` is a locally
//! managed address *and* `to != from`, `to`'s L3 entry is also
//! invalidated so a subsequent display read sees up-to-date inputs as
//! soon as the upstream confirms. The `to == from` case skips the
//! second invalidation — a self-transfer redundantly invalidating its
//! own entry can't widen the bug window but does cost one extra
//! refresher fetch with no benefit.
//!
//! ## CAS-on-generation
//!
//! Same rule as L2: writes are CAS on `generation`; only `invalidate`
//! advances generation. Refresher races against transfer-commit lose
//! the CAS and are dropped on the floor.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use exfer::types::transaction::OutPoint;
use exfer::types::Hash256;

use crate::cache::balance::verify_address;
use crate::cache::entry::{EntryStore, Generation};
use crate::error::Result;
use crate::inflight::InFlightUtxos;
use crate::upstream::{ExferNode, UtxoListResponse};

/// Cached + inflight-subtracted snapshot a display reader returns.
#[derive(Debug, Clone)]
pub struct UtxoPeek {
    pub utxos: Option<UtxoListResponse>,
    pub generation: Generation,
    pub fetched_at: Option<Instant>,
    pub tip_at_fetch: u64,
    pub stale: bool,
    pub last_error: Option<String>,
}

pub struct UtxoCache {
    pub(crate) by_addr: EntryStore<String, UtxoListResponse>,
    pub(crate) by_script: EntryStore<String, UtxoListResponse>,
    ttl: Duration,
}

impl UtxoCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            by_addr: EntryStore::new(),
            by_script: EntryStore::new(),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    // ====================================================================
    // Address-keyed reads
    // ====================================================================

    /// Display path for `get_address_utxos`. Returns the cached entry
    /// with in-flight outpoints subtracted; falls through to upstream
    /// + write-back when the cache is cold or stale.
    pub async fn read_address_for_display(
        &self,
        addr: &str,
        node: &ExferNode,
        inflight: &InFlightUtxos,
        tip_height: u64,
    ) -> Result<UtxoListResponse> {
        // Fresh hit → return cached + inflight-subtract.
        if let Some(cached) = self.peek_address_fresh(addr) {
            return Ok(subtract_inflight(cached, inflight));
        }
        // Stale or cold → upstream + write-back; then subtract.
        let resp = self.read_address_for_spend(addr, node, tip_height).await?;
        Ok(subtract_inflight(resp, inflight))
    }

    /// Spend path: always upstream, write-back, no inflight filter.
    /// The transfer engine subtracts inflight via the existing
    /// `select_and_claim` atomic lock — adding another filter here
    /// would double-count.
    pub async fn read_address_for_spend(
        &self,
        addr: &str,
        node: &ExferNode,
        tip_height: u64,
    ) -> Result<UtxoListResponse> {
        let resp = node.get_address_utxos(addr).await?;
        if let Some(returned) = resp.address.as_deref() {
            verify_address(returned, addr)?;
        }
        let snap = self.by_addr.get(&addr.to_string());
        let _ =
            self.by_addr
                .try_write(&addr.to_string(), snap.generation, resp.clone(), tip_height);
        Ok(resp)
    }

    /// Cache-only peek for `list_balances`. Returns whatever is stored
    /// right now, with a `stale` flag if the entry is past TTL or
    /// missing. Never touches upstream.
    pub fn peek_address(&self, addr: &str, inflight: &InFlightUtxos) -> UtxoPeek {
        let snap = self.by_addr.get(&addr.to_string());
        let now = Instant::now();
        let stale = match snap.fetched_at {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.ttl,
        };
        let utxos = snap
            .value
            .clone()
            .map(|resp| subtract_inflight(resp, inflight));
        UtxoPeek {
            utxos,
            generation: snap.generation,
            fetched_at: snap.fetched_at,
            tip_at_fetch: snap.tip_at_fetch,
            stale,
            last_error: snap.last_error,
        }
    }

    fn peek_address_fresh(&self, addr: &str) -> Option<UtxoListResponse> {
        let snap = self.by_addr.get(&addr.to_string());
        let (value, fetched_at) = (snap.value?, snap.fetched_at?);
        let age = Instant::now().saturating_duration_since(fetched_at);
        if age >= self.ttl {
            return None;
        }
        Some(value)
    }

    /// Eager invalidation, called from the `transfer` commit hook.
    pub fn invalidate_address(&self, addr: &str) -> Generation {
        self.by_addr.invalidate(&addr.to_string())
    }

    /// Refresher's CAS write-back.
    pub fn cas_write_address(
        &self,
        addr: &str,
        expected_generation: Generation,
        value: UtxoListResponse,
        tip_at_fetch: u64,
    ) -> bool {
        self.by_addr
            .try_write(&addr.to_string(), expected_generation, value, tip_at_fetch)
    }

    pub fn note_address_error(&self, addr: &str, err: String) {
        self.by_addr.note_error(&addr.to_string(), err);
    }

    pub fn seed_address_empty(&self, addr: &str, tip_height: u64) {
        // tip_at_fetch=0 forces refresher to refresh on next tick even
        // though we just "wrote" — same force-stale rule as L2.
        let _ = tip_height; // accepted for symmetry; intentionally unused
        let resp = UtxoListResponse {
            address: Some(addr.to_string()),
            script_hex: None,
            tip_height: 0,
            truncated: false,
            utxos: Vec::new(),
        };
        self.by_addr.seed(addr.to_string(), resp, 0);
    }

    pub fn invalidate_all(&self) {
        self.by_addr.invalidate_all();
        self.by_script.invalidate_all();
    }

    pub fn address_len(&self) -> usize {
        self.by_addr.len()
    }

    pub fn for_each_address_snapshot<F>(&self, visitor: F)
    where
        F: FnMut(&String, crate::cache::entry::EntrySnapshot<UtxoListResponse>),
    {
        self.by_addr.for_each(visitor);
    }

    // ====================================================================
    // Script-hex-keyed reads (same shape, different keyspace)
    // ====================================================================

    pub async fn read_script_for_display(
        &self,
        script_hex: &str,
        node: &ExferNode,
        inflight: &InFlightUtxos,
        tip_height: u64,
    ) -> Result<UtxoListResponse> {
        if let Some(cached) = self.peek_script_fresh(script_hex) {
            return Ok(subtract_inflight(cached, inflight));
        }
        let resp = node.get_script_utxos(script_hex).await?;
        let snap = self.by_script.get(&script_hex.to_string());
        let _ = self.by_script.try_write(
            &script_hex.to_string(),
            snap.generation,
            resp.clone(),
            tip_height,
        );
        Ok(subtract_inflight(resp, inflight))
    }

    fn peek_script_fresh(&self, script_hex: &str) -> Option<UtxoListResponse> {
        let snap = self.by_script.get(&script_hex.to_string());
        let (value, fetched_at) = (snap.value?, snap.fetched_at?);
        let age = Instant::now().saturating_duration_since(fetched_at);
        if age >= self.ttl {
            return None;
        }
        Some(value)
    }
}

/// Subtract inflight-claimed outpoints from a UTXO list. Used by all
/// display paths. Malformed `tx_id` hex (defensively unreachable) is
/// passed through — better to show a UTXO that might be stale than to
/// silently drop it.
fn subtract_inflight(mut resp: UtxoListResponse, inflight: &InFlightUtxos) -> UtxoListResponse {
    let pending: HashSet<OutPoint> = inflight.pending().into_iter().collect();
    if pending.is_empty() {
        return resp;
    }
    resp.utxos.retain(|u| !is_pending(u, &pending));
    resp
}

fn is_pending(u: &crate::upstream::UtxoEntry, pending: &HashSet<OutPoint>) -> bool {
    let Ok(bytes) = hex::decode(&u.tx_id) else {
        return false;
    };
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let op = OutPoint {
        tx_id: Hash256(arr),
        output_index: u.output_index,
    };
    pending.contains(&op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::UtxoEntry as WireUtxo;
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_node(server: &MockServer) -> ExferNode {
        ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap()
    }

    fn utxo_response(addr: &str, utxos: Vec<(String, u32, u64)>) -> serde_json::Value {
        let utxos_json: Vec<_> = utxos
            .into_iter()
            .map(|(tx_id, output_index, value)| {
                serde_json::json!({
                    "tx_id": tx_id,
                    "output_index": output_index,
                    "value": value,
                    "height": 1,
                    "is_coinbase": false,
                })
            })
            .collect();
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "address": addr,
                "tip_height": 100,
                "truncated": false,
                "utxos": utxos_json,
            }
        })
    }

    fn op_for_utxo(u: &WireUtxo) -> OutPoint {
        let bytes = hex::decode(&u.tx_id).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        OutPoint {
            tx_id: Hash256(arr),
            output_index: u.output_index,
        }
    }

    #[tokio::test]
    async fn spend_path_always_hits_upstream() {
        let server = MockServer::start().await;
        let addr = "aa".repeat(32);
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"get_address_utxos"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(utxo_response(&addr, vec![("ab".repeat(32), 0, 1000)])),
            )
            .expect(3) // three spend calls → three upstream hits
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = UtxoCache::new(Duration::from_secs(60));

        for _ in 0..3 {
            c.read_address_for_spend(&addr, &node, 100).await.unwrap();
        }
    }

    #[tokio::test]
    async fn display_path_serves_from_cache_after_spend_populates() {
        let server = MockServer::start().await;
        let addr = "bb".repeat(32);
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(utxo_response(&addr, vec![("cd".repeat(32), 1, 2000)])),
            )
            .expect(1) // exactly one upstream call — display reads after
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let inflight = InFlightUtxos::new();
        let c = UtxoCache::new(Duration::from_secs(60));

        // Spend path primes the cache.
        c.read_address_for_spend(&addr, &node, 100).await.unwrap();

        // Two display reads → no upstream traffic.
        for _ in 0..2 {
            let r = c
                .read_address_for_display(&addr, &node, &inflight, 100)
                .await
                .unwrap();
            assert_eq!(r.utxos.len(), 1);
        }
    }

    #[tokio::test]
    async fn display_subtracts_inflight() {
        let server = MockServer::start().await;
        let addr = "cc".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(utxo_response(
                &addr,
                vec![
                    ("11".repeat(32), 0, 1_000),
                    ("22".repeat(32), 1, 2_000),
                    ("33".repeat(32), 2, 3_000),
                ],
            )))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let inflight = InFlightUtxos::new();
        let c = UtxoCache::new(Duration::from_secs(60));

        // Prime cache.
        let resp = c.read_address_for_spend(&addr, &node, 100).await.unwrap();
        let claimed = op_for_utxo(&resp.utxos[1]); // claim the 2_000-value one
        inflight.claim(&[claimed]);

        let view = c
            .read_address_for_display(&addr, &node, &inflight, 100)
            .await
            .unwrap();
        assert_eq!(view.utxos.len(), 2);
        assert!(
            view.utxos.iter().all(|u| u.value != 2_000),
            "inflight UTXO must be filtered out of display"
        );
    }

    #[tokio::test]
    async fn invalidate_address_loses_refresher_cas() {
        // §9-trap repeat, for the UTXO layer.
        let server = MockServer::start().await;
        let addr = "dd".repeat(32);
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(utxo_response(&addr, vec![("ee".repeat(32), 0, 99)])),
            )
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = UtxoCache::new(Duration::from_secs(60));

        let resp = c.read_address_for_spend(&addr, &node, 100).await.unwrap();
        let gen_at_sample = c.by_addr.get(&addr).generation;

        // Transfer commit invalidates.
        let new_gen = c.invalidate_address(&addr);
        assert_eq!(new_gen, gen_at_sample + 1);

        // Refresher's stale write loses.
        let accepted = c.cas_write_address(&addr, gen_at_sample, resp, 100);
        assert!(!accepted);

        let snap = c.by_addr.get(&addr);
        assert!(snap.value.is_none(), "invalidation must persist");
    }

    #[tokio::test]
    async fn address_mismatch_rejected_and_not_cached() {
        let server = MockServer::start().await;
        let requested = "aa".repeat(32);
        let returned = "bb".repeat(32);
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(utxo_response(&returned, vec![("ee".repeat(32), 0, 99)])),
            )
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = UtxoCache::new(Duration::from_secs(60));

        let r = c.read_address_for_spend(&requested, &node, 100).await;
        assert!(r.is_err());

        let snap = c.by_addr.get(&requested);
        assert!(
            snap.value.is_none(),
            "mismatched address response must not poison cache"
        );
    }
}
