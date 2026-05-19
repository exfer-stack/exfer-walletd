//! Cache profile — one knob to derive every TTL / LRU / concurrency
//! parameter from. Operators set `--cache-profile {off|balanced|aggressive}`
//! instead of tuning nine separate flags.
//!
//! Rationale: with nine independent flags, you ship nine independent
//! support questions ("what does `--cache-l4-block-ttl=0` do when
//! `--cache-profile=off`?"). One enum, three meanings.

use std::time::Duration;

/// User-facing cache profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheProfile {
    /// No caching — every read goes direct to upstream. Matches pre-0.13
    /// behavior exactly. Useful for monitoring / reconciliation jobs
    /// that need ground-truth or for paranoid deployments that don't
    /// want any background traffic.
    Off,
    /// The default. Tuned for "exchange backend pinging a public RPC
    /// every few seconds." 30s TTLs, 5s refresh, 8-wide concurrency.
    #[default]
    Balanced,
    /// Tighter TTLs and a heavier refresher. Tuned for "I have a
    /// dedicated node and I want the freshest possible view."
    Aggressive,
}

impl CacheProfile {
    pub fn params(self) -> CacheParams {
        match self {
            CacheProfile::Off => CacheParams::off(),
            CacheProfile::Balanced => CacheParams::balanced(),
            CacheProfile::Aggressive => CacheParams::aggressive(),
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, CacheProfile::Off)
    }
}

impl std::fmt::Display for CacheProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CacheProfile::Off => "off",
            CacheProfile::Balanced => "balanced",
            CacheProfile::Aggressive => "aggressive",
        })
    }
}

impl std::str::FromStr for CacheProfile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" => Ok(CacheProfile::Off),
            "balanced" | "default" => Ok(CacheProfile::Balanced),
            "aggressive" | "tight" => Ok(CacheProfile::Aggressive),
            other => Err(format!(
                "expected one of off|balanced|aggressive, got {other:?}"
            )),
        }
    }
}

/// Derived knobs. Profile → params is total and deterministic.
#[derive(Debug, Clone, Copy)]
pub struct CacheParams {
    pub enabled: bool,
    /// Time-to-live for the L1 tip cache.
    pub tip_ttl: Duration,
    /// Time-to-live for L2 per-address balance entries.
    pub balance_ttl: Duration,
    /// Time-to-live for L3 per-address UTXO entries.
    pub utxo_ttl: Duration,
    /// Maximum number of confirmed block entries kept (LRU).
    pub block_lru: usize,
    /// Maximum number of transaction entries kept (LRU).
    pub tx_lru: usize,
    /// How often the refresher wakes (in addition to eager invalidations).
    pub refresh_interval: Duration,
    /// Per-tick parallelism when fanning out upstream reads.
    pub concurrency: usize,
    /// Stratified-refresh cap: refresh at most this many oldest entries
    /// per tick. Keeps deployments with 100k+ addresses responsive.
    pub max_per_tick: usize,
    /// Reorg depth used to decide whether by-height block entries are
    /// short-TTL (within depth) or permanent (beyond depth).
    pub reorg_depth: u64,
}

impl CacheParams {
    fn off() -> Self {
        Self {
            enabled: false,
            tip_ttl: Duration::ZERO,
            balance_ttl: Duration::ZERO,
            utxo_ttl: Duration::ZERO,
            block_lru: 0,
            tx_lru: 0,
            refresh_interval: Duration::ZERO,
            concurrency: 0,
            max_per_tick: 0,
            reorg_depth: 0,
        }
    }

    fn balanced() -> Self {
        // v0.14.0 breaking change: `refresh_interval = 0` means
        // *manual* mode — the background refresher does NOT fire on
        // its own. Callers refresh on demand via the `refresh_address`
        // / `refresh_addresses` RPC methods.
        //
        // Why: on a rate-limited public RPC like rpc.exfer.dev (30
        // balance/utxo queries/min), the automatic refresher requires
        // `refresh_interval >= 4N` seconds where N is the managed
        // address count — at 100 addresses that's 6.7 minutes, at
        // 1000 it's 67 minutes. Auto-polling doesn't scale; the right
        // primitive at scale is "app tells walletd when it cares."
        //
        // Operators with their own (un-rate-limited) node should
        // pass `--cache-refresh-secs=5` to opt back into the old
        // automatic behavior, or use `--cache-profile aggressive`
        // which keeps the 2s tick.
        Self {
            enabled: true,
            tip_ttl: Duration::from_millis(200),
            balance_ttl: Duration::from_secs(30),
            utxo_ttl: Duration::from_secs(30),
            block_lru: 1000,
            tx_lru: 10_000,
            refresh_interval: Duration::ZERO,
            concurrency: 8,
            max_per_tick: 10_000,
            reorg_depth: 6,
        }
    }

    fn aggressive() -> Self {
        Self {
            enabled: true,
            tip_ttl: Duration::from_millis(100),
            balance_ttl: Duration::from_secs(5),
            utxo_ttl: Duration::from_secs(5),
            block_lru: 5000,
            tx_lru: 50_000,
            refresh_interval: Duration::from_secs(2),
            concurrency: 16,
            max_per_tick: 50_000,
            reorg_depth: 6,
        }
    }

    /// Apply operator overrides on top of the profile. Currently only
    /// `--cache-refresh-secs` is exposed as an escape hatch; everything
    /// else stays profile-derived.
    ///
    /// `None` keeps the profile's default. `Some(0)` explicitly
    /// disables auto-refresh (manual mode — caller drives refreshes
    /// via the `refresh_address` RPC). `Some(N)` for N >= 1 sets the
    /// auto-refresh interval to N seconds.
    ///
    /// As of v0.14.0 the `balanced` profile defaults to manual mode
    /// (`refresh_interval = 0`), so passing `None` on `balanced` ==
    /// passing `Some(0)`. Operators who want the pre-v0.14.0 automatic
    /// 5s tick must explicitly pass `Some(5)`.
    pub fn with_refresh_secs(mut self, refresh_secs: Option<u64>) -> Self {
        if let Some(secs) = refresh_secs {
            if self.enabled {
                self.refresh_interval = Duration::from_secs(secs);
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_is_disabled() {
        assert!(!CacheProfile::Off.params().enabled);
        assert!(!CacheProfile::Off.is_enabled());
    }

    #[test]
    fn balanced_and_aggressive_are_enabled() {
        assert!(CacheProfile::Balanced.params().enabled);
        assert!(CacheProfile::Aggressive.params().enabled);
    }

    #[test]
    fn aggressive_is_tighter_than_balanced() {
        let b = CacheProfile::Balanced.params();
        let a = CacheProfile::Aggressive.params();
        assert!(a.balance_ttl < b.balance_ttl);
        // balanced is now manual (refresh_interval == 0); aggressive
        // still auto-polls. So aggressive's interval > balanced's, not <.
        assert!(a.refresh_interval > Duration::ZERO);
        assert_eq!(b.refresh_interval, Duration::ZERO);
        assert!(a.concurrency >= b.concurrency);
    }

    #[test]
    fn balanced_defaults_to_manual_refresh() {
        // v0.14.0 breaking change: caller must opt into auto via
        // --cache-refresh-secs or --cache-profile aggressive.
        assert_eq!(
            CacheProfile::Balanced.params().refresh_interval,
            Duration::ZERO
        );
    }

    #[test]
    fn refresh_secs_override_applied_when_enabled() {
        let p = CacheProfile::Balanced.params().with_refresh_secs(Some(10));
        assert_eq!(p.refresh_interval, Duration::from_secs(10));
    }

    #[test]
    fn refresh_secs_override_ignored_when_off() {
        let p = CacheProfile::Off.params().with_refresh_secs(Some(10));
        assert_eq!(p.refresh_interval, Duration::ZERO);
    }

    #[test]
    fn refresh_secs_zero_explicitly_disables_auto_refresh() {
        // v0.14.0 semantic change: Some(0) now means "manual mode";
        // the previous behavior (Some(0) → fall back to profile
        // default) was misleading and made it impossible to disable
        // auto-refresh on a profile whose default was nonzero.
        // Now: None → profile default; Some(N) → set N (including 0).
        let p = CacheProfile::Aggressive.params().with_refresh_secs(Some(0));
        assert_eq!(p.refresh_interval, Duration::ZERO);
    }

    #[test]
    fn parse_accepts_canonical_names() {
        assert_eq!("off".parse::<CacheProfile>().unwrap(), CacheProfile::Off);
        assert_eq!(
            "balanced".parse::<CacheProfile>().unwrap(),
            CacheProfile::Balanced
        );
        assert_eq!(
            "aggressive".parse::<CacheProfile>().unwrap(),
            CacheProfile::Aggressive
        );
    }

    #[test]
    fn parse_is_case_insensitive_and_trims() {
        assert_eq!(
            "  BALANCED  ".parse::<CacheProfile>().unwrap(),
            CacheProfile::Balanced
        );
    }

    #[test]
    fn parse_accepts_aliases() {
        assert_eq!(
            "disabled".parse::<CacheProfile>().unwrap(),
            CacheProfile::Off
        );
        assert_eq!(
            "default".parse::<CacheProfile>().unwrap(),
            CacheProfile::Balanced
        );
        assert_eq!(
            "tight".parse::<CacheProfile>().unwrap(),
            CacheProfile::Aggressive
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!("nonsense".parse::<CacheProfile>().is_err());
    }
}
