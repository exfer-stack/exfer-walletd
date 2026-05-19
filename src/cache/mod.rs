//! Multi-layer cache for the wallet daemon.
//!
//! See `/home/rufus/.claude/plans/gh-exfer-stack-cheeky-eich.md` for the
//! full design. Brief recap:
//!
//! - **L1 tip** — current chain head, 200ms TTL; all other caches store
//!   `tip_at_fetch` for staleness comparison.
//! - **L2 balance** — per-address `(balance, tip_at_fetch, generation,
//!   last_error)`. CAS-on-generation writes. Wired in Stage 2.
//! - **L3 UTXO** — per-address UTXO list. Dual-semantics: display path
//!   subtracts inflight; spend path always upstream + write-back.
//!   Wired in Stage 3.
//! - **L4 block** — confirmed blocks (by-hash permanent, by-height short
//!   within reorg-depth then permanent). Wired in Stage 5.
//! - **L5 tx** — transaction lookups. mempool→confirmed transition
//!   handled on hit. Wired in Stage 5.
//! - **Refresher** — single supervisor task that polls tip, detects
//!   reorgs, and stratified-refreshes L2/L3 oldest-first. Wired in
//!   Stage 4.
//!
//! Non-negotiable invariant: every L2/L3 write is CAS-on-generation.
//! See [`entry::EntryStore::try_write`] for the mechanics.

pub mod balance;
pub mod block;
pub mod entry;
pub mod profile;
pub mod refresher;
pub mod tip;
pub mod tx;
pub mod utxo;

pub use balance::{BalanceCache, BalancePeek};
pub use block::BlockCache;
pub use entry::{EntrySnapshot, EntryStore, Generation};
pub use profile::{CacheParams, CacheProfile};
pub use refresher::{spawn as spawn_refresher, RefresherHandle};
pub use tip::{TipCache, TipSnapshot};
pub use tx::TxCache;
pub use utxo::{UtxoCache, UtxoPeek};

use std::sync::Arc;

use crate::upstream::ExferNode;

/// Top-level cache handle injected into [`crate::api::ApiState`].
///
/// In Stage 1 this holds only L1 + profile params. Later stages bolt
/// L2, L3, L4, L5 onto this struct without changing call sites — the
/// `Arc<WalletCache>` already lives in `ApiState`.
pub struct WalletCache {
    pub params: CacheParams,
    pub tip: TipCache,
    pub balance: BalanceCache,
    pub utxo: UtxoCache,
    pub block: BlockCache,
    pub tx: TxCache,
}

impl WalletCache {
    /// Construct a cache from a profile. `--cache-profile=off` builds
    /// a cache whose every read path bypasses straight to upstream;
    /// see individual cache method docs for how they honor
    /// `params.enabled`.
    pub fn new(profile: CacheProfile, refresh_secs_override: Option<u64>) -> Self {
        let params = profile.params().with_refresh_secs(refresh_secs_override);
        // When disabled, TTLs are zero — every peek() looks stale and
        // we fall through to upstream. This keeps the cache module's
        // semantics monotonic (off = same code path, smaller TTLs).
        let tip_ttl = if params.enabled {
            params.tip_ttl
        } else {
            std::time::Duration::ZERO
        };
        let balance_ttl = if params.enabled {
            params.balance_ttl
        } else {
            std::time::Duration::ZERO
        };
        let utxo_ttl = if params.enabled {
            params.utxo_ttl
        } else {
            std::time::Duration::ZERO
        };
        let block_lru = if params.enabled { params.block_lru } else { 0 };
        let tx_lru = if params.enabled { params.tx_lru } else { 0 };
        Self {
            params,
            tip: TipCache::new(tip_ttl),
            balance: BalanceCache::new(balance_ttl),
            utxo: UtxoCache::new(utxo_ttl),
            block: BlockCache::new(block_lru, params.reorg_depth.max(1)),
            tx: TxCache::new(tx_lru),
        }
    }

    /// Convenience for tests: a cache with the `Off` profile. Every
    /// read path falls through to upstream.
    pub fn disabled() -> Self {
        Self::new(CacheProfile::Off, None)
    }

    /// Convenience: shared handle. We almost always want one.
    pub fn shared(profile: CacheProfile, refresh_secs_override: Option<u64>) -> Arc<Self> {
        Arc::new(Self::new(profile, refresh_secs_override))
    }

    pub fn is_enabled(&self) -> bool {
        self.params.enabled
    }

    /// Read tip — cached when enabled, direct otherwise. Returns the
    /// raw [`crate::upstream::BlockTip`] for callers that don't care
    /// about staleness metadata.
    pub async fn get_tip(&self, node: &ExferNode) -> crate::error::Result<TipSnapshot> {
        if !self.params.enabled {
            // Bypass: always upstream.
            let tip = node.get_block_height().await?;
            return Ok(TipSnapshot {
                tip,
                fetched_at: std::time::Instant::now(),
                stale: false,
                last_error: None,
            });
        }
        self.tip.get_or_fetch(node).await
    }

    /// Read balance for a single address. Cached when enabled
    /// (cache-aside + write-back through L2); direct otherwise. Always
    /// validates the upstream response address against the requested
    /// address so a misrouting LB / sharding bug can't poison the
    /// cache (or, on the bypass path, can't return a wrong-address
    /// value to the caller).
    pub async fn get_balance(
        &self,
        addr: &str,
        node: &ExferNode,
    ) -> crate::error::Result<crate::upstream::BalanceResponse> {
        if !self.params.enabled {
            let resp = node.get_balance(addr).await?;
            balance::verify_address(&resp.address, addr)?;
            return Ok(resp);
        }
        // Sample tip cheaply for the `tip_at_fetch` field. Don't fail
        // the balance call if tip lookup hiccups — record 0.
        let tip_height = self.tip.peek().map(|s| s.tip.height).unwrap_or(0);
        self.balance.read_through(addr, node, tip_height).await
    }

    /// Read UTXOs for an address — *display* semantics. Cached when
    /// enabled (with in-flight outpoints subtracted); direct otherwise.
    pub async fn get_address_utxos(
        &self,
        addr: &str,
        node: &ExferNode,
        inflight: &crate::inflight::InFlightUtxos,
    ) -> crate::error::Result<crate::upstream::UtxoListResponse> {
        if !self.params.enabled {
            let resp = node.get_address_utxos(addr).await?;
            if let Some(returned) = resp.address.as_deref() {
                balance::verify_address(returned, addr)?;
            }
            return Ok(resp);
        }
        let tip_height = self.tip.peek().map(|s| s.tip.height).unwrap_or(0);
        self.utxo
            .read_address_for_display(addr, node, inflight, tip_height)
            .await
    }

    /// Read UTXOs for an address — *spend* semantics. Always upstream,
    /// always write-back to prime display reads. Used internally by the
    /// `transfer` engine.
    pub async fn get_address_utxos_for_spend(
        &self,
        addr: &str,
        node: &ExferNode,
    ) -> crate::error::Result<crate::upstream::UtxoListResponse> {
        if !self.params.enabled {
            let resp = node.get_address_utxos(addr).await?;
            if let Some(returned) = resp.address.as_deref() {
                balance::verify_address(returned, addr)?;
            }
            return Ok(resp);
        }
        let tip_height = self.tip.peek().map(|s| s.tip.height).unwrap_or(0);
        self.utxo
            .read_address_for_spend(addr, node, tip_height)
            .await
    }

    /// Read UTXOs for a script_hex — display semantics with in-flight
    /// subtraction. Same `--cache-profile=off` bypass as
    /// [`Self::get_address_utxos`].
    pub async fn get_script_utxos(
        &self,
        script_hex: &str,
        node: &ExferNode,
        inflight: &crate::inflight::InFlightUtxos,
    ) -> crate::error::Result<crate::upstream::UtxoListResponse> {
        if !self.params.enabled {
            return node.get_script_utxos(script_hex).await;
        }
        let tip_height = self.tip.peek().map(|s| s.tip.height).unwrap_or(0);
        self.utxo
            .read_script_for_display(script_hex, node, inflight, tip_height)
            .await
    }

    /// Read a transaction by id. Cached through L5 when enabled.
    /// Used both by the `get_transaction` handler and by the
    /// `decode_with_inputs` parent-tx fetch path (the latter is the
    /// big amortization win — a tx with N inputs becomes ~free on
    /// cache hit).
    pub async fn get_transaction(
        &self,
        tx_id: &str,
        node: &ExferNode,
    ) -> crate::error::Result<crate::upstream::TxStatus> {
        if !self.params.enabled {
            return node.get_transaction(tx_id).await;
        }
        self.tx.get_or_fetch(tx_id, node).await
    }

    /// Read a block by height. Cached through L4 when enabled.
    pub async fn get_block_by_height(
        &self,
        height: u64,
        node: &ExferNode,
    ) -> crate::error::Result<crate::upstream::BlockSummary> {
        if !self.params.enabled {
            return node.get_block_by_height(height).await;
        }
        let tip = self.tip.peek().map(|s| s.tip.height).unwrap_or(0);
        self.block.get_by_height(height, node, tip).await
    }

    /// Read a block by hash. Cached through L4 when enabled. By-hash
    /// is permanent absent reorg invalidation.
    pub async fn get_block_by_hash(
        &self,
        hash: &str,
        node: &ExferNode,
    ) -> crate::error::Result<crate::upstream::BlockSummary> {
        if !self.params.enabled {
            return node.get_block_by_hash(hash).await;
        }
        self.block.get_by_hash(hash, node).await
    }

    /// **Manual refresh** for a single address — force a fresh fetch
    /// from upstream and write back to L2 + L3. Used by the
    /// `refresh_address` JSON-RPC method.
    ///
    /// Why this exists: the v0.14.0 `balanced` profile defaults to
    /// `refresh_interval = 0` (manual mode) because automatic polling
    /// can't scale on rate-limited public RPCs (see operations.md
    /// "4N math"). Applications drive the cadence themselves —
    /// expensive deposit-watcher addresses get frequent refreshes,
    /// cold archives get refreshed on user demand.
    ///
    /// On address-mismatch from upstream OR per-call failure, the
    /// failure is recorded in `last_error` and the cached value (if
    /// any) is preserved — same contract as the automatic refresher.
    /// Returns `()` on completion (errors are reflected in the cache
    /// rows, not raised here).
    pub async fn refresh_address(&self, addr: &str, node: &ExferNode) {
        if !self.params.enabled {
            // Cache profile = off → no cache state to refresh.
            return;
        }
        // Best-effort tip fetch first (so post-refresh rows record an
        // accurate tip_at_fetch). If tip itself fails, fall back to
        // whatever was cached.
        let tip_height = match self.tip.force_fetch(node).await {
            Ok(s) => s.tip.height,
            Err(_) => self.tip.peek().map(|s| s.tip.height).unwrap_or(0),
        };

        // Sample generations *before* fetching so a `transfer` commit
        // that lands between sample and write loses CAS — same
        // happens-after invariant the auto-refresher relies on.
        let bal_gen = self.balance.peek(addr).generation;
        let utxo_gen = self.utxo.by_addr.get(&addr.to_string()).generation;

        let (bal_res, utxo_res) =
            tokio::join!(node.get_balance(addr), node.get_address_utxos(addr));

        match bal_res {
            Ok(b) => {
                if balance::verify_address(&b.address, addr).is_ok() {
                    let _ = self.balance.cas_write(addr, bal_gen, b.balance, tip_height);
                } else {
                    self.balance
                        .note_error(addr, "address-mismatch from upstream".into());
                }
            }
            Err(e) => self.balance.note_error(addr, e.to_string()),
        }

        match utxo_res {
            Ok(u) => {
                let address_ok = match u.address.as_deref() {
                    None => true,
                    Some(returned) => balance::verify_address(returned, addr).is_ok(),
                };
                if address_ok {
                    let _ = self.utxo.cas_write_address(addr, utxo_gen, u, tip_height);
                } else {
                    self.utxo
                        .note_address_error(addr, "address-mismatch from upstream".into());
                }
            }
            Err(e) => self.utxo.note_address_error(addr, e.to_string()),
        }
    }

    /// Eager invalidation hook called from the `transfer` engine after
    /// `guard.commit()` (i.e. after upstream confirms broadcast and the
    /// in-flight UTXOs are persisted). Invalidates L2/L3 entries for
    /// `from_hex` unconditionally and for `to_hex` only when `to ≠ from`
    /// AND `to ∈ store`. The self-transfer skip is deliberate: see the
    /// module-level docstring for utxo.rs and the design note in the
    /// plan file.
    pub fn on_transfer_commit(
        &self,
        from_hex: &str,
        to_hex: &str,
        store: &dyn crate::store::WalletStore,
    ) {
        if !self.params.enabled {
            return;
        }
        self.balance.invalidate(from_hex);
        self.utxo.invalidate_address(from_hex);
        if from_hex != to_hex && store.exists(to_hex) {
            self.balance.invalidate(to_hex);
            self.utxo.invalidate_address(to_hex);
            tracing::debug!(
                from = from_hex,
                to = to_hex,
                "transfer-commit: invalidated both addresses"
            );
        } else {
            tracing::debug!(
                from = from_hex,
                to = to_hex,
                "transfer-commit: invalidated from only"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_cache_reports_disabled() {
        let c = WalletCache::disabled();
        assert!(!c.is_enabled());
        assert!(!c.params.enabled);
    }

    #[test]
    fn balanced_cache_carries_balanced_params() {
        let c = WalletCache::new(CacheProfile::Balanced, None);
        assert!(c.is_enabled());
        assert_eq!(c.params.concurrency, 8);
    }

    #[test]
    fn refresh_override_threads_through() {
        let c = WalletCache::new(CacheProfile::Balanced, Some(10));
        assert_eq!(c.params.refresh_interval.as_secs(), 10);
    }
}
