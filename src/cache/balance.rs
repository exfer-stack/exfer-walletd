//! L2 — per-address balance cache.
//!
//! Backed by [`EntryStore<String, u64>`]. Wire shape (`address`,
//! `balance`) is reconstructed on read — the address is redundant
//! with the cache key, so we only store `u64`.
//!
//! ## Two read modes
//!
//! - [`BalanceCache::read_through`] — used by the `get_balance` JSON-RPC
//!   handler. Returns a *fresh* value: if the cache entry is younger
//!   than TTL, serves from cache; otherwise hits upstream and writes
//!   back under CAS.
//! - [`BalanceCache::peek`] — used by the `list_balances` JSON-RPC
//!   handler. Returns whatever is in the cache *right now*, with a
//!   `stale` flag and `last_error` for the caller to decide. Never
//!   touches upstream.
//!
//! ## Refresher integration (Stage 4)
//!
//! - [`BalanceCache::for_each_snapshot`] — enumerate entries so the
//!   refresher can pick the oldest N to refresh.
//! - [`BalanceCache::cas_write`] — refresher's write-back path. Lost
//!   CAS races are dropped silently.
//! - [`BalanceCache::note_error`] — refresher's per-address failure
//!   path. Keeps the prior cached value; populates `last_error`.
//!
//! ## Address-mismatch validation
//!
//! Every upstream response is checked: if the node returned a balance
//! for a different address than we asked (LB misrouting, sharding bug,
//! whatever), the cache rejects the write, logs an ERROR, and surfaces
//! [`Error::UpstreamUnexpected`] to the caller. Without this, a single
//! confused upstream replica can poison the cache for one entry per
//! mismatch.

use std::time::{Duration, Instant};

use crate::cache::entry::{EntryStore, Generation};
use crate::error::{Error, Result};
use crate::upstream::{BalanceResponse, ExferNode};

/// Snapshot a `list_balances` row is built from.
#[derive(Debug, Clone)]
pub struct BalancePeek {
    pub balance: Option<u64>,
    pub generation: Generation,
    pub fetched_at: Option<Instant>,
    pub tip_at_fetch: u64,
    pub stale: bool,
    pub last_error: Option<String>,
}

pub struct BalanceCache {
    pub(crate) store: EntryStore<String, u64>,
    ttl: Duration,
}

impl BalanceCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            store: EntryStore::new(),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Cache-aside read with write-back. Returns the canonical
    /// `BalanceResponse` for direct serialization into the JSON-RPC
    /// reply. `tip_height` is the chain head to record as
    /// `tip_at_fetch` on successful write.
    pub async fn read_through(
        &self,
        addr: &str,
        node: &ExferNode,
        tip_height: u64,
    ) -> Result<BalanceResponse> {
        let snap = self.store.get(&addr.to_string());
        if let (Some(value), Some(fetched_at)) = (snap.value, snap.fetched_at) {
            let age = Instant::now().saturating_duration_since(fetched_at);
            if age < self.ttl {
                return Ok(BalanceResponse {
                    address: addr.to_string(),
                    balance: value,
                });
            }
        }
        let resp = node.get_balance(addr).await?;
        verify_address(&resp.address, addr)?;
        // Drop the write on lost CAS — a `transfer` commit bumped the
        // generation between our sample and now, and that invalidation
        // wins.
        let _ = self
            .store
            .try_write(&addr.to_string(), snap.generation, resp.balance, tip_height);
        Ok(resp)
    }

    /// Cached read for `list_balances`. Returns whatever is currently
    /// stored. Never touches upstream — the refresher fills the cache.
    pub fn peek(&self, addr: &str) -> BalancePeek {
        let snap = self.store.get(&addr.to_string());
        let now = Instant::now();
        let stale = match snap.fetched_at {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.ttl,
        };
        BalancePeek {
            balance: snap.value,
            generation: snap.generation,
            fetched_at: snap.fetched_at,
            tip_at_fetch: snap.tip_at_fetch,
            stale,
            last_error: snap.last_error,
        }
    }

    /// Eager invalidation. Called from the `transfer` commit hook.
    /// Bumps generation so any in-flight refresher write loses CAS.
    pub fn invalidate(&self, addr: &str) -> Generation {
        self.store.invalidate(&addr.to_string())
    }

    /// Refresher's write-back path. Returns `false` if CAS lost.
    pub fn cas_write(
        &self,
        addr: &str,
        expected_generation: Generation,
        balance: u64,
        tip_at_fetch: u64,
    ) -> bool {
        self.store.try_write(
            &addr.to_string(),
            expected_generation,
            balance,
            tip_at_fetch,
        )
    }

    /// Refresher's per-address failure path. Preserves the cached
    /// value; populates `last_error`.
    pub fn note_error(&self, addr: &str, err: String) {
        self.store.note_error(&addr.to_string(), err);
    }

    /// Pre-seed for `generate_address`. `tip_at_fetch=0` forces the
    /// next refresher tick to treat the entry as maximally stale —
    /// catches the rare case where someone funded the freshly-derived
    /// public key out-of-band before we generated locally.
    pub fn seed_zero(&self, addr: &str) {
        self.store.seed(addr.to_string(), 0, 0);
    }

    /// Visit every (addr, snapshot) pair. Used by the refresher to
    /// pick the oldest N for stratified refresh.
    pub fn for_each_snapshot<F>(&self, visitor: F)
    where
        F: FnMut(&String, crate::cache::entry::EntrySnapshot<u64>),
    {
        self.store.for_each(visitor);
    }

    /// Wholesale invalidate every entry. Refresher calls this on
    /// reorg detection.
    pub fn invalidate_all(&self) {
        self.store.invalidate_all();
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// Confirm the address an upstream node says it answered for matches
/// the address we asked about. Lowercase / trim defensively — Exfer
/// addresses are 64-hex but a future shape could include `0x` prefix
/// or mixed case.
pub fn verify_address(returned: &str, requested: &str) -> Result<()> {
    let canon = |s: &str| s.trim().trim_start_matches("0x").to_ascii_lowercase();
    let r = canon(returned);
    let q = canon(requested);
    if r != q {
        tracing::error!(
            requested = requested,
            returned = returned,
            "upstream returned balance for a different address — rejecting"
        );
        return Err(Error::UpstreamUnexpected(format!(
            "upstream returned address {returned:?} but we asked about {requested:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_node(server: &MockServer) -> ExferNode {
        ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap()
    }

    fn balance_response(addr: &str, value: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "address": addr, "balance": value }
        })
    }

    #[tokio::test]
    async fn read_through_caches_then_serves_from_cache() {
        let server = MockServer::start().await;
        // Only ONE upstream call permitted — second call would be a
        // cache bypass and fail.
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"get_balance"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(balance_response("aa".repeat(32).as_str(), 500_000)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = BalanceCache::new(Duration::from_secs(60));
        let addr = "aa".repeat(32);

        let r1 = c.read_through(&addr, &node, 100).await.unwrap();
        assert_eq!(r1.balance, 500_000);

        // Second call must come from cache.
        let r2 = c.read_through(&addr, &node, 100).await.unwrap();
        assert_eq!(r2.balance, 500_000);
    }

    #[tokio::test]
    async fn read_through_refreshes_after_ttl_expiry() {
        let server = MockServer::start().await;
        let addr = "bb".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(balance_response(&addr, 1_000)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(balance_response(&addr, 2_000)))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = BalanceCache::new(Duration::from_millis(20));
        assert_eq!(
            c.read_through(&addr, &node, 100).await.unwrap().balance,
            1_000
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            c.read_through(&addr, &node, 100).await.unwrap().balance,
            2_000
        );
    }

    #[tokio::test]
    async fn read_through_rejects_address_mismatch() {
        let server = MockServer::start().await;
        let requested = "aa".repeat(32);
        let returned = "bb".repeat(32);
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(balance_response(&returned, 999)),
            )
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = BalanceCache::new(Duration::from_secs(60));
        let err = c.read_through(&requested, &node, 100).await.unwrap_err();
        match err {
            Error::UpstreamUnexpected(msg) => assert!(
                msg.contains(&returned),
                "error must surface the wrong address: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Crucially: the cache must NOT have been written.
        let peek = c.peek(&requested);
        assert!(
            peek.balance.is_none(),
            "mismatched response must not be cached"
        );
    }

    #[tokio::test]
    async fn invalidate_drops_value_and_bumps_generation_so_refresher_loses_cas() {
        // The §9 trap from the design review: refresher mid-fetch must
        // not overwrite a transfer-commit invalidation.
        let server = MockServer::start().await;
        let addr = "cc".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(balance_response(&addr, 7_777)))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = Arc::new(BalanceCache::new(Duration::from_secs(60)));
        // Prime cache.
        c.read_through(&addr, &node, 100).await.unwrap();

        // Simulate refresher: sample gen=G, then…
        let snap = c.store.get(&addr);
        let expected_gen = snap.generation;
        assert_eq!(expected_gen, 0);

        // …transfer commits → invalidation bumps gen.
        let new_gen = c.invalidate(&addr);
        assert_eq!(new_gen, 1);

        // …refresher's write lands with the stale gen → must lose CAS.
        let accepted = c.cas_write(&addr, expected_gen, 5_555, 101);
        assert!(
            !accepted,
            "refresher write must lose CAS after invalidation"
        );

        // Post-condition: cache is empty (invalidated), generation bumped.
        let peek = c.peek(&addr);
        assert!(peek.balance.is_none(), "value cleared by invalidation");
        assert_eq!(peek.generation, 1);
    }

    #[tokio::test]
    async fn note_error_preserves_value_for_serving_stale() {
        let c = BalanceCache::new(Duration::from_millis(10));
        let addr = "dd".repeat(32);
        c.store.try_write(&addr, 0, 9_000, 100);
        tokio::time::sleep(Duration::from_millis(20)).await;
        c.note_error(&addr, "upstream timeout".into());

        let peek = c.peek(&addr);
        assert_eq!(
            peek.balance,
            Some(9_000),
            "stale value must remain available"
        );
        assert!(peek.stale);
        assert_eq!(peek.last_error.as_deref(), Some("upstream timeout"));
    }

    #[tokio::test]
    async fn seed_zero_is_stale_at_any_positive_tip() {
        // The seed must force the next refresher tick to re-fetch —
        // even if `generate_address` raced an out-of-band fund.
        let c = BalanceCache::new(Duration::from_secs(60));
        let addr = "ee".repeat(32);
        c.seed_zero(&addr);
        let peek = c.peek(&addr);
        assert_eq!(peek.balance, Some(0));
        assert_eq!(peek.tip_at_fetch, 0, "seed must record tip=0 (force stale)");
    }

    #[test]
    fn verify_address_accepts_canonical_match() {
        assert!(verify_address("aabbcc", "aabbcc").is_ok());
    }

    #[test]
    fn verify_address_accepts_case_variant() {
        assert!(verify_address("AABBCC", "aabbcc").is_ok());
    }

    #[test]
    fn verify_address_trims_whitespace() {
        assert!(verify_address("  aabbcc  \n", "aabbcc").is_ok());
    }

    #[test]
    fn verify_address_strips_0x_prefix() {
        assert!(verify_address("0xaabbcc", "aabbcc").is_ok());
    }

    #[test]
    fn verify_address_rejects_mismatch() {
        let err = verify_address("aabbcc", "ddeeff").unwrap_err();
        assert!(matches!(err, Error::UpstreamUnexpected(_)));
    }
}
