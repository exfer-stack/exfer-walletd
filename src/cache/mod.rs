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

pub mod entry;
pub mod profile;
pub mod tip;

pub use entry::{EntrySnapshot, EntryStore, Generation};
pub use profile::{CacheParams, CacheProfile};
pub use tip::{TipCache, TipSnapshot};

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
        Self {
            params,
            tip: TipCache::new(tip_ttl),
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
