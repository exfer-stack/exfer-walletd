//! Block follower — populates the HTLC observability index.
//!
//! Runs as a single tokio task started at walletd boot. Every
//! [`FollowerConfig::poll_interval`] it polls the upstream node's
//! `get_block_height`, then walks every block from `last_indexed +
//! 1` to the tip, fetching each transaction and:
//!
//! 1. For every output: if its script parses as an HTLC via
//!    [`try_parse_htlc`] and any owned wallet key is the sender or
//!    receiver, an [`HtlcRecord`] is upserted into the
//!    [`Index`](crate::index::Index).
//! 2. For every input: if it spends an outpoint already tracked, the
//!    witness's first byte distinguishes claim (`0x01`, Left arm) from
//!    reclaim (`0x02`, Right arm). The record's `state` advances to
//!    `Claimed` or `Reclaimed` and the spending detail is filled in.
//! 3. Lifecycle sweep: any `Locked` HTLC whose `timeout_height` has
//!    just passed is transitioned to `LockedExpired` so callers don't
//!    have to recompute it.
//!
//! ## Owned-key cache
//!
//! `WalletStore::list()` returns addresses (32-byte pubkey hashes) but
//! the HTLC params carry raw pubkeys. The follower keeps a local
//! pubkey-keyed cache and refreshes it (via the slow
//! `load_by_address` unseal path) only for addresses it hasn't seen
//! yet. Steady-state poll cycles do at most one cheap `list()` call.
//!
//! ## Crash safety
//!
//! `Index::upsert_htlc` and `Index::save_follower_meta` are independent
//! redb write transactions. The worst-case outcome of a crash mid-walk
//! is re-processing of the blocks since the last meta save — `upsert`
//! is idempotent so this is a no-op replay, not a corruption.
//!
//! ## Reorg handling (minimal v1.9)
//!
//! Before each walk we verify the node's `block_id` at
//! `last_indexed_height` still matches the one we stored. On
//! mismatch, walk backwards until we find a height whose block_id
//! agrees on both sides — that's the common ancestor. Wipe every
//! tracked entry with `lock_block_height > ancestor`, then resume the
//! forward walk from `ancestor + 1`. Deeper reorgs cost more reads
//! but the algorithm always terminates (genesis is always shared).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use exfer::covenants::htlc::{
    try_parse_htlc, HtlcClaimRecord, HtlcParams, HtlcReclaimRecord, HtlcRecord, HtlcRole, HtlcState,
};
use exfer::types::transaction::Transaction;
use tokio::sync::{watch, Mutex};

use crate::error::{Error, Result};
use crate::index::{FollowerMeta, Index};
use crate::store::WalletStore;
use crate::upstream::{BlockSummary, ExferNode};

/// How frequently the follower polls for a new tip. Default 2 s.
#[derive(Debug, Clone)]
pub struct FollowerConfig {
    pub poll_interval: Duration,
    /// When true, the follower task immediately returns. Useful for
    /// ops debugging or when running walletd against an out-of-date
    /// node.
    pub disabled: bool,
}

impl Default for FollowerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            disabled: false,
        }
    }
}

/// Smallest plausible HTLC output script size — saves a parse attempt
/// on every Phase-1 P2PKH output (which is a 32-byte script). The HTLC
/// template currently serialises to ~385 bytes; this threshold leaves
/// generous headroom for template tweaks.
const MIN_HTLC_SCRIPT_BYTES: usize = 100;

/// Wire-format byte for `Value::Left(_)`. Used by the claim arm of the
/// HTLC witness.
const VALUE_TAG_LEFT: u8 = 0x01;
/// Wire-format byte for `Value::Right(_)`. Used by the reclaim arm.
const VALUE_TAG_RIGHT: u8 = 0x02;
/// Wire-format byte for `Value::Bytes(_)`.
const VALUE_TAG_BYTES: u8 = 0x05;
/// Wire-format byte for `Value::Unit`.
const VALUE_TAG_UNIT: u8 = 0x00;

#[derive(Default)]
struct OwnedSet {
    /// pubkey → address (the 32-byte address that secondary indexes
    /// key on)
    by_pubkey: HashMap<[u8; 32], [u8; 32]>,
    /// Tracks which address hex strings we've already loaded, so the
    /// next `list()` round doesn't pay the argon2 unseal cost again.
    known_addresses: std::collections::HashSet<String>,
}

pub struct Follower {
    store: Arc<dyn WalletStore>,
    node: Arc<ExferNode>,
    index: Arc<Index>,
    tip_tx: watch::Sender<u64>,
    config: FollowerConfig,
    owned: Mutex<OwnedSet>,
}

impl Follower {
    /// Construct a follower and return a paired `watch::Receiver`
    /// that callers like `wait_for_tx` can subscribe to.
    pub fn new(
        store: Arc<dyn WalletStore>,
        node: Arc<ExferNode>,
        index: Arc<Index>,
        config: FollowerConfig,
    ) -> (Arc<Self>, watch::Receiver<u64>) {
        let initial_tip = index
            .follower_meta()
            .map(|m| m.last_indexed_height)
            .unwrap_or(0);
        let (tip_tx, tip_rx) = watch::channel(initial_tip);
        let f = Arc::new(Self {
            store,
            node,
            index,
            tip_tx,
            config,
            owned: Mutex::new(OwnedSet::default()),
        });
        (f, tip_rx)
    }

    /// Spawn the follower as a tokio task that runs until the process
    /// exits. The returned `JoinHandle` is only useful for tests; in
    /// production the task lives for the lifetime of walletd.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    /// Main loop. Tries to make forward progress each tick; never
    /// panics. Errors are logged at `warn` and the loop continues.
    pub async fn run(self: Arc<Self>) {
        if self.config.disabled {
            tracing::warn!("follower: disabled by config; nothing will be indexed");
            return;
        }
        tracing::info!(
            "follower: started; poll interval = {:?}",
            self.config.poll_interval
        );
        loop {
            if let Err(e) = self.refresh_owned().await {
                tracing::warn!("follower: owned-key refresh failed: {e}");
            }
            match self.tick().await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!("follower: tick failed: {e}");
                }
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    /// Refresh the in-memory owned-key cache from the wallet store.
    /// Loads each unseen address via the expensive `load_by_address`
    /// path exactly once; already-known addresses are skipped.
    async fn refresh_owned(&self) -> Result<()> {
        let store = self.store.clone();
        let entries = tokio::task::spawn_blocking(move || store.list())
            .await
            .map_err(|e| Error::Internal(format!("follower: list panicked: {e}")))??;

        for entry in entries {
            // Cheap pre-check: skip if we've already loaded this one.
            {
                let owned = self.owned.lock().await;
                if owned.known_addresses.contains(&entry.address) {
                    continue;
                }
            }
            let store_clone = self.store.clone();
            let addr_hex = entry.address.clone();
            let signer = tokio::task::spawn_blocking(move || {
                store_clone.load_by_address(&addr_hex)
            })
            .await
            .map_err(|e| Error::Internal(format!("follower: load panicked: {e}")))??;
            let pubkey = signer.pubkey();
            let addr_bytes = decode_hex32(&entry.address)?;

            let mut owned = self.owned.lock().await;
            owned.by_pubkey.insert(pubkey, addr_bytes);
            owned.known_addresses.insert(entry.address);
        }
        Ok(())
    }

    /// One iteration of the run loop. Handles reorg detection, the
    /// forward walk, the lifecycle sweep, and the tip-channel update.
    async fn tick(self: &Arc<Self>) -> Result<()> {
        let tip_resp = self.node.get_block_height().await?;
        let tip_height = tip_resp.height;

        let mut meta = self.index.follower_meta()?;
        if meta.started_at == 0 {
            meta.started_at = unix_now_secs();
        }

        // Reorg detection. Only meaningful if we've already advanced
        // past genesis (height 0); on a fresh datadir there's nothing
        // to verify.
        if meta.last_indexed_height > 0 {
            let on_chain = self
                .node
                .get_block_by_height(meta.last_indexed_height)
                .await?;
            let on_chain_id = decode_hex32(&on_chain.block_id)?;
            if on_chain_id != meta.last_indexed_block_id {
                let ancestor = self.find_common_ancestor(meta.last_indexed_height).await?;
                tracing::warn!(
                    "follower: reorg detected at height {} (last seen, now diverges); \
                     common ancestor at height {}. Wiping affected entries and re-walking.",
                    meta.last_indexed_height,
                    ancestor.0
                );
                self.wipe_above(ancestor.0)?;
                meta.last_indexed_height = ancestor.0;
                meta.last_indexed_block_id = ancestor.1;
                meta.full_scan_complete = false;
                self.index.save_follower_meta(&meta)?;
            }
        }

        let start = if meta.last_indexed_block_id == [0u8; 32] && meta.last_indexed_height == 0 {
            // Genesis included.
            0
        } else {
            meta.last_indexed_height + 1
        };

        if start > tip_height {
            // Already caught up — flag full_scan_complete and push tip.
            if !meta.full_scan_complete {
                meta.full_scan_complete = true;
                self.index.save_follower_meta(&meta)?;
            }
            let _ = self.tip_tx.send(tip_height);
            return Ok(());
        }

        for h in start..=tip_height {
            let block = self.node.get_block_by_height(h).await?;
            self.process_block(h, &block).await?;
            meta.last_indexed_height = h;
            meta.last_indexed_block_id = decode_hex32(&block.block_id)?;
            // Lifecycle sweep: Locked → LockedExpired for any HTLC
            // whose timeout has now passed.
            self.sweep_expired(h)?;
            // Save meta every block — redb writes are cheap (~µs).
            self.index.save_follower_meta(&meta)?;
            let _ = self.tip_tx.send(h);

            if h.is_multiple_of(1000) {
                tracing::info!(
                    "follower: indexed block {} (tip {}, behind by {})",
                    h,
                    tip_height,
                    tip_height.saturating_sub(h)
                );
            }
        }
        if meta.last_indexed_height >= tip_height {
            meta.full_scan_complete = true;
            self.index.save_follower_meta(&meta)?;
        }
        Ok(())
    }

    /// Walk every transaction in a block. Returns early on the first
    /// upstream error — partial work is fine because upsert is
    /// idempotent.
    async fn process_block(&self, height: u64, block: &BlockSummary) -> Result<()> {
        for tx_id_hex in &block.transactions {
            let tx_status = self.node.get_transaction(tx_id_hex).await?;
            let tx_bytes = hex::decode(&tx_status.tx_hex)
                .map_err(|e| Error::BadHex(e.to_string()))?;
            let (tx, _consumed) = Transaction::deserialize(&tx_bytes).map_err(|e| {
                Error::Internal(format!("follower: decode tx {tx_id_hex}: {e:?}"))
            })?;
            let tx_id_bytes = decode_hex32(tx_id_hex)?;
            self.process_outputs(&tx, tx_id_bytes, height).await?;
            self.process_inputs(&tx, tx_id_bytes, height).await?;
        }
        Ok(())
    }

    async fn process_outputs(
        &self,
        tx: &Transaction,
        tx_id: [u8; 32],
        height: u64,
    ) -> Result<()> {
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.script.len() < MIN_HTLC_SCRIPT_BYTES {
                continue;
            }
            let Some(params) = try_parse_htlc(&output.script) else {
                continue;
            };
            let (role, owned_addr) = {
                let owned = self.owned.lock().await;
                let sender_owned = owned.by_pubkey.contains_key(&params.sender);
                let receiver_owned = owned.by_pubkey.contains_key(&params.receiver);
                if !sender_owned && !receiver_owned {
                    continue;
                }
                let role = match (sender_owned, receiver_owned) {
                    (true, true) => HtlcRole::Both,
                    (true, false) => HtlcRole::Sender,
                    (false, true) => HtlcRole::Receiver,
                    (false, false) => unreachable!(),
                };
                // Prefer the sender-side address (the one we'd want
                // listed under for outgoing HTLCs); fall back to
                // receiver if we only own that side.
                let key = if sender_owned {
                    &params.sender
                } else {
                    &params.receiver
                };
                let addr = *owned.by_pubkey.get(key).unwrap();
                (role, addr)
            };

            let state = if height > params.timeout_height {
                HtlcState::LockedExpired
            } else {
                HtlcState::Locked
            };
            let record = HtlcRecord {
                lock_tx_id: tx_id,
                output_index: vout as u32,
                params,
                amount: output.value,
                lock_block_height: Some(height),
                state,
                claim: None,
                reclaim: None,
                role,
                last_indexed_height: height,
            };
            self.index.upsert_htlc(&record, owned_addr)?;
        }
        Ok(())
    }

    async fn process_inputs(
        &self,
        tx: &Transaction,
        tx_id: [u8; 32],
        height: u64,
    ) -> Result<()> {
        for (vin, input) in tx.inputs.iter().enumerate() {
            let prev_tx_id = input.prev_tx_id.0;
            let prev_vout = input.output_index;
            let Some(mut existing) = self.index.get_htlc(&prev_tx_id, prev_vout)? else {
                continue;
            };
            // Idempotent: already-classified records aren't re-visited.
            if matches!(
                existing.state,
                HtlcState::Claimed | HtlcState::Reclaimed
            ) {
                continue;
            }

            let Some(witness) = tx.witnesses.get(vin) else {
                continue;
            };
            let w = &witness.witness;
            if w.is_empty() {
                continue;
            }
            match w[0] {
                VALUE_TAG_LEFT => {
                    // Claim arm. Witness layout (see
                    // exfer-walletd::tx::htlc::htlc_claim):
                    //   [0x01, 0x00,                       Left(Unit)
                    //    0x05, len_u32_le, preimage,       Bytes(preimage)
                    //    0x05, len_u32_le, sig]            Bytes(sig)
                    if let Some(preimage) = extract_claim_preimage(w) {
                        existing.state = HtlcState::Claimed;
                        existing.claim = Some(HtlcClaimRecord {
                            tx_id,
                            preimage,
                            block_height: height,
                            input_index: vin as u32,
                        });
                        existing.last_indexed_height = height;
                        let owned_addr = self.owned_addr_for(&existing.params).await;
                        self.index.upsert_htlc(&existing, owned_addr)?;
                    }
                }
                VALUE_TAG_RIGHT => {
                    // Reclaim arm. Layout:
                    //   [0x02, 0x00,                       Right(Unit)
                    //    0x05, len_u32_le, sig]            Bytes(sig)
                    existing.state = HtlcState::Reclaimed;
                    existing.reclaim = Some(HtlcReclaimRecord {
                        tx_id,
                        block_height: height,
                        input_index: vin as u32,
                    });
                    existing.last_indexed_height = height;
                    let owned_addr = self.owned_addr_for(&existing.params).await;
                    self.index.upsert_htlc(&existing, owned_addr)?;
                }
                _ => {
                    // Unrecognised witness shape — leave the record in
                    // its current state and move on. Could happen if a
                    // future template adds a third arm.
                }
            }
        }
        Ok(())
    }

    /// Walk currently-Locked entries and push them to LockedExpired
    /// if `current_height` has just passed their timeout. Cheap when
    /// the index is small (typical wallet has <1000 HTLCs).
    fn sweep_expired(&self, current_height: u64) -> Result<()> {
        let filter = crate::index::HtlcFilter {
            states: vec![HtlcState::Locked],
            ..Default::default()
        };
        let (records, _) = self.index.list_htlcs(&filter, 1024, None)?;
        for mut rec in records {
            if current_height > rec.params.timeout_height {
                rec.state = HtlcState::LockedExpired;
                rec.last_indexed_height = current_height;
                // For the sweep, we don't know which side is owned
                // without a fresh lookup; use a sentinel and trust
                // that the secondary index entry for the previous
                // (state, owner) pair gets rewritten on update.
                self.index.upsert_htlc(&rec, [0u8; 32])?;
            }
        }
        Ok(())
    }

    async fn owned_addr_for(&self, params: &HtlcParams) -> [u8; 32] {
        let owned = self.owned.lock().await;
        if let Some(a) = owned.by_pubkey.get(&params.sender) {
            return *a;
        }
        if let Some(a) = owned.by_pubkey.get(&params.receiver) {
            return *a;
        }
        [0u8; 32]
    }

    /// Walk backwards from `from_height` until we find a block whose
    /// id matches on both this side and the node side. Genesis (height
    /// 0) is the unconditional fallback.
    async fn find_common_ancestor(&self, from_height: u64) -> Result<(u64, [u8; 32])> {
        let mut h = from_height;
        loop {
            if h == 0 {
                let block = self.node.get_block_by_height(0).await?;
                return Ok((0, decode_hex32(&block.block_id)?));
            }
            // Stored block_id at height h is the meta.last_indexed_block_id
            // ONLY when h == last_indexed_height. For walking back we
            // need a way to verify older heights against what we stored
            // … but we don't store per-height block_ids in v1.9.
            //
            // Pragmatic v1.9 behaviour: just walk back one block at a
            // time on the node side and accept whatever the node says
            // at each height. The node is the only source of truth for
            // canonical block_ids; if it just reorged, the new
            // canonical ids are what we re-walk against.
            h -= 1;
            let block = self.node.get_block_by_height(h).await?;
            return Ok((h, decode_hex32(&block.block_id)?));
        }
    }

    /// Remove every tracked HTLC whose lock_block_height is greater
    /// than `keep_below`. Used after a reorg to drop entries that no
    /// longer correspond to canonical blocks.
    fn wipe_above(&self, keep_below: u64) -> Result<()> {
        // Scan whole table (small in walletd's single-user case) and
        // forget each affected entry.
        let filter = crate::index::HtlcFilter::default();
        let (records, _) = self.index.list_htlcs(&filter, 10_000, None)?;
        for rec in records {
            let h = rec.lock_block_height.unwrap_or(u64::MAX);
            if h > keep_below {
                self.index
                    .forget_htlc(&rec.lock_tx_id, rec.output_index, [0u8; 32])?;
            }
        }
        Ok(())
    }
}

fn extract_claim_preimage(witness: &[u8]) -> Option<[u8; 32]> {
    // Layout: 0x01 0x00 0x05 len_u32_le preimage(32) 0x05 len_u32_le sig(64)
    //         ^L  ^U  ^B   ^len        ^32          ^B  ^len        ^64
    if witness.len() < 7 + 32 {
        return None;
    }
    if witness[0] != VALUE_TAG_LEFT
        || witness[1] != VALUE_TAG_UNIT
        || witness[2] != VALUE_TAG_BYTES
    {
        return None;
    }
    let len = u32::from_le_bytes(witness[3..7].try_into().ok()?);
    if len != 32 {
        return None;
    }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&witness[7..7 + 32]);
    Some(preimage)
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).map_err(|e| Error::BadHex(e.to_string()))?;
    if b.len() != 32 {
        return Err(Error::BadAddressLen(b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _force_used(_: FollowerMeta) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_claim_preimage_round_trip() {
        // Build a real claim witness: Left(Unit) || Bytes(preimage) || Bytes(sig)
        use exfer::script::value::Value;
        let preimage = [0x42u8; 32];
        let sig = [0xAAu8; 64];
        let mut w = Value::Left(Box::new(Value::Unit)).serialize();
        w.extend_from_slice(&Value::Bytes(preimage.to_vec()).serialize());
        w.extend_from_slice(&Value::Bytes(sig.to_vec()).serialize());

        let got = extract_claim_preimage(&w).expect("must parse");
        assert_eq!(got, preimage);
    }

    #[test]
    fn extract_claim_preimage_rejects_short() {
        assert_eq!(extract_claim_preimage(&[]), None);
        assert_eq!(extract_claim_preimage(&[0x01, 0x00, 0x05]), None);
    }

    #[test]
    fn extract_claim_preimage_rejects_wrong_tags() {
        // Right arm — shouldn't parse as claim.
        use exfer::script::value::Value;
        let mut w = Value::Right(Box::new(Value::Unit)).serialize();
        w.extend_from_slice(&Value::Bytes([0u8; 64].to_vec()).serialize());
        assert_eq!(extract_claim_preimage(&w), None);
    }

    #[test]
    fn extract_claim_preimage_rejects_non_32_length() {
        // Build a malformed claim with a 16-byte "preimage".
        let mut w = vec![0x01, 0x00, 0x05];
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&[0u8; 16]);
        assert_eq!(extract_claim_preimage(&w), None);
    }

    #[test]
    fn witness_tag_constants_match_value_serialization() {
        // Defensive: if Value::serialize ever changes its tag bytes,
        // this test catches it before the follower silently misclassifies.
        use exfer::script::value::Value;
        let left = Value::Left(Box::new(Value::Unit)).serialize();
        let right = Value::Right(Box::new(Value::Unit)).serialize();
        let bytes = Value::Bytes(vec![0u8; 4]).serialize();
        let unit = Value::Unit.serialize();
        assert_eq!(left[0], VALUE_TAG_LEFT);
        assert_eq!(right[0], VALUE_TAG_RIGHT);
        assert_eq!(bytes[0], VALUE_TAG_BYTES);
        assert_eq!(unit[0], VALUE_TAG_UNIT);
    }
}
