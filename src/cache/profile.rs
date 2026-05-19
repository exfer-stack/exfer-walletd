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
        Self {
            enabled: true,
            tip_ttl: Duration::from_millis(200),
            balance_ttl: Duration::from_secs(30),
            utxo_ttl: Duration::from_secs(30),
            block_lru: 1000,
            tx_lru: 10_000,
            refresh_interval: Duration::from_secs(5),
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
    pub fn with_refresh_secs(mut self, refresh_secs: Option<u64>) -> Self {
        if let Some(secs) = refresh_secs {
            if secs > 0 && self.enabled {
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
        assert!(a.refresh_interval < b.refresh_interval);
        assert!(a.concurrency >= b.concurrency);
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
    fn refresh_secs_zero_does_not_zero_the_interval() {
        // Operators may set the env var to "0" expecting "default";
        // honor that by leaving the profile-derived value untouched.
        let p = CacheProfile::Balanced.params().with_refresh_secs(Some(0));
        assert_eq!(p.refresh_interval, Duration::from_secs(5));
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
