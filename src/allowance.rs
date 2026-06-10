//! redb-backed spend allowance ledger.
//!
//! A safety cap on native-EXFER outflow so that a leaked or misbehaving
//! `spend`-scope token cannot drain a wallet without bound. Two
//! independent ceilings, both **operator configuration** (set via CLI /
//! env at start, never mutable over the RPC) so a compromised spend
//! token cannot raise its own limit:
//!
//! - **`per_tx`** — the largest single spend (in exfers) the daemon will
//!   broadcast.
//! - **`per_period`** — the most that may be spent, in total, inside one
//!   tumbling time window of `period_secs`.
//!
//! Both default to **unlimited**. With no caps configured the ledger is
//! inert: [`AllowanceLedger::check`] always succeeds and
//! [`AllowanceLedger::record`] is a no-op, so existing deployments and
//! every downstream client (mobile, desktop, mcp, py, honor) behave
//! exactly as before. This is the zero-break contract.
//!
//! ## Scope (v1)
//!
//! Native-EXFER spends that carry an amount in the request are metered:
//! `transfer` (sum of outputs) and `htlc_lock` (the locked amount), via
//! [`reserve`](AllowanceLedger::reserve) before broadcast and
//! [`refund`](AllowanceLedger::refund) if the broadcast fails.
//!
//! The one other path that moves native EXFER the daemon signs from a
//! managed wallet under the same `Spend` scope is the `exfer_to_bnb` swap
//! leg. The swap engine does not yet call this ledger, so to avoid a silent
//! cap bypass the API layer **fails that swap closed** (rejects it) whenever
//! caps are active — see `api::swap::swap_get_quote`. Metering the swap leg
//! is the v1 follow-up.
//!
//! Deliberately *not* metered, and why it's safe under the "leaked spend
//! token" threat model: `send_raw_transaction` broadcasts an
//! already-signed tx (an attacker with only a spend token cannot produce
//! the signature — that needs the keystore passphrase via
//! `reveal_private_key`), and `bsc_send_bnb` / `lp_withdraw_self` move
//! non-EXFER assets (BNB / LP shares), which an EXFER ceiling does not
//! govern.
//!
//! ## File layout
//!
//! ```text
//!   <datadir>/allowance.redb
//!     └── spent_by_bucket   (bucket_u64_be) → spent_exfers_u64_be
//! ```
//!
//! The window is a **tumbling** bucket: `bucket = now_unix / period_secs`.
//! Each bucket holds the cumulative exfers spent while it was current.
//! A new window starts a fresh bucket (spent resets to zero), so the
//! ledger needs no background sweeper — stale buckets simply stop being
//! read. This is deliberately simpler than a true sliding window: a cap
//! is a safety rail, not an accounting system, and a tumbling window can
//! never *under*-count within its own window.

use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};

use crate::error::{Error, Result};

/// `bucket_u64_be → spent_exfers_u64_be`. Mirrors the `&[u8]`-keyed redb
/// convention used by [`crate::index`] (big-endian so a lexicographic
/// range matches a numeric range, should we ever range-scan).
const SPENT_BY_BUCKET: TableDefinition<&[u8], &[u8]> = TableDefinition::new("spent_by_bucket");

/// Current wall-clock Unix time in seconds. Saturates to 0 if the system
/// clock is somehow before the epoch. The window bucketing tolerates a
/// jumpy clock: a backwards step at worst reuses an earlier bucket
/// (counts against an already-partly-spent window — fail-safe), never
/// under-counts the current one.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Operator-configured spend ceilings. All-unset (the [`Default`]) means
/// no limit — the ledger is inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowanceCaps {
    /// Largest single spend in exfers. `None` = no per-transaction cap.
    pub per_tx: Option<u64>,
    /// Most that may be spent per tumbling window, in exfers. `None` =
    /// no per-period cap.
    pub per_period: Option<u64>,
    /// Window length in seconds for `per_period`. Must be > 0 whenever
    /// `per_period` is set (enforced by [`AllowanceCaps::validate`]).
    pub period_secs: u64,
}

impl Default for AllowanceCaps {
    fn default() -> Self {
        AllowanceCaps {
            per_tx: None,
            per_period: None,
            period_secs: 86_400, // 1 day; only consulted when per_period is set
        }
    }
}

impl AllowanceCaps {
    /// True when at least one ceiling is active. When false the ledger
    /// short-circuits every operation.
    pub fn is_active(&self) -> bool {
        self.per_tx.is_some() || self.per_period.is_some()
    }

    /// Reject a nonsensical configuration (a per-period cap with a
    /// zero-length window). Called once at startup so a misconfig fails
    /// loudly rather than silently disabling the cap.
    pub fn validate(&self) -> Result<()> {
        if self.per_period.is_some() && self.period_secs == 0 {
            return Err(Error::Internal(
                "allowance: --spend-cap-per-period requires --spend-cap-period-secs > 0".into(),
            ));
        }
        Ok(())
    }
}

/// A read-only snapshot of the ledger for the `allowance_status` RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowanceStatus {
    pub per_tx: Option<u64>,
    pub per_period: Option<u64>,
    pub period_secs: u64,
    /// Exfers spent so far in the current window (0 when no per-period
    /// cap is configured).
    pub spent_this_period: u64,
    /// Remaining headroom this window (`None` when unlimited).
    pub remaining_this_period: Option<u64>,
    /// Unix second at which the current window rolls over (`None` when no
    /// per-period cap is configured).
    pub window_resets_at: Option<u64>,
}

/// The durable allowance counter store.
pub struct AllowanceLedger {
    db: Database,
    caps: AllowanceCaps,
}

impl AllowanceLedger {
    /// Open or create `<datadir>/allowance.redb` with the given caps.
    pub fn open(datadir: &Path, caps: AllowanceCaps) -> Result<Self> {
        caps.validate()?;
        std::fs::create_dir_all(datadir)
            .map_err(|e| Error::Internal(format!("allowance: create datadir: {e}")))?;
        let path = datadir.join("allowance.redb");
        let db = Database::create(&path)
            .map_err(|e| Error::Internal(format!("allowance: open redb: {e}")))?;

        // Ensure the table exists so read transactions on a fresh datadir
        // don't fail with "table not found".
        let write = db
            .begin_write()
            .map_err(|e| Error::Internal(format!("allowance: begin write: {e}")))?;
        {
            let _ = write
                .open_table(SPENT_BY_BUCKET)
                .map_err(|e| Error::Internal(format!("allowance: open table: {e}")))?;
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("allowance: commit init: {e}")))?;

        Ok(Self { db, caps })
    }

    /// Open an ephemeral in-memory ledger (no file). Carries the same
    /// semantics as [`AllowanceLedger::open`] but nothing persists across
    /// process restart. Used by tests and any caller that wants allowance
    /// behaviour without touching disk.
    pub fn in_memory(caps: AllowanceCaps) -> Result<Self> {
        caps.validate()?;
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| Error::Internal(format!("allowance: in-memory redb: {e}")))?;
        let write = db
            .begin_write()
            .map_err(|e| Error::Internal(format!("allowance: begin write: {e}")))?;
        {
            let _ = write
                .open_table(SPENT_BY_BUCKET)
                .map_err(|e| Error::Internal(format!("allowance: open table: {e}")))?;
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("allowance: commit init: {e}")))?;
        Ok(Self { db, caps })
    }

    /// The configured caps.
    pub fn caps(&self) -> AllowanceCaps {
        self.caps
    }

    /// Current tumbling-window bucket index. Guards against a zero window
    /// (treated as "no bucketing").
    fn bucket(&self, now: u64) -> u64 {
        // A zero window collapses every spend into bucket 0 (no
        // bucketing); validate() already rejects per_period with a zero
        // window, so this only guards the per_tx-only path.
        now.checked_div(self.caps.period_secs).unwrap_or(0)
    }

    /// Exfers already spent in `bucket`. Absent bucket → 0.
    fn spent_in_bucket(&self, bucket: u64) -> Result<u64> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| Error::Internal(format!("allowance: begin read: {e}")))?;
        let table = read
            .open_table(SPENT_BY_BUCKET)
            .map_err(|e| Error::Internal(format!("allowance: open table: {e}")))?;
        let key = bucket.to_be_bytes();
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Internal(format!("allowance: get bucket: {e}")))?
        {
            Some(v) => {
                let bytes = v.value();
                if bytes.len() != 8 {
                    return Err(Error::Internal(
                        "allowance: corrupt counter (expected 8 bytes)".into(),
                    ));
                }
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            None => Ok(0),
        }
    }

    /// Stateless **per-transaction** ceiling check only — no window state is
    /// touched. Safe to call up-front (before expensive keystore I/O) for a
    /// fast fail, and safe to re-run on an idempotent retry because it reads
    /// nothing and the cap is immutable config. The per-period window is the
    /// job of [`reserve`](Self::reserve) / [`refund`](Self::refund).
    pub fn check_per_tx(&self, amount: u64) -> Result<()> {
        if let Some(limit) = self.caps.per_tx {
            if amount > limit {
                return Err(Error::AllowanceExceeded {
                    scope: "per_tx",
                    limit,
                    spent: 0,
                    requested: amount,
                    period_secs: 0,
                });
            }
        }
        Ok(())
    }

    /// Atomically check a prospective spend of `amount` exfers against both
    /// ceilings and, if it fits, **reserve** it against the current window.
    ///
    /// The per-period check-and-increment runs inside a **single** redb
    /// write transaction (redb serializes writers), so two concurrent
    /// reserves can never both pass against a stale snapshot — no
    /// lost-update, no TOCTOU. Returns `Err(Error::AllowanceExceeded)`
    /// **without reserving anything** if either ceiling would be breached;
    /// a no-op (`Ok`) when no caps are configured.
    ///
    /// Call before broadcast. On a broadcast failure, call
    /// [`AllowanceLedger::refund`] so a failed spend doesn't permanently
    /// consume the window.
    pub fn reserve(&self, amount: u64, now: u64) -> Result<()> {
        // Per-transaction ceiling — stateless, no persistence.
        if let Some(limit) = self.caps.per_tx {
            if amount > limit {
                return Err(Error::AllowanceExceeded {
                    scope: "per_tx",
                    limit,
                    spent: 0,
                    requested: amount,
                    period_secs: 0,
                });
            }
        }

        // Per-period ceiling — atomic check-and-reserve in ONE write txn.
        let Some(limit) = self.caps.per_period else {
            return Ok(());
        };
        let key = self.bucket(now).to_be_bytes();
        let write = self
            .db
            .begin_write()
            .map_err(|e| Error::Internal(format!("allowance: begin write: {e}")))?;
        let outcome = {
            let mut table = write
                .open_table(SPENT_BY_BUCKET)
                .map_err(|e| Error::Internal(format!("allowance: open table: {e}")))?;
            let spent = match table
                .get(key.as_slice())
                .map_err(|e| Error::Internal(format!("allowance: get bucket: {e}")))?
            {
                Some(v) => {
                    let b = v.value();
                    if b.len() != 8 {
                        return Err(Error::Internal(
                            "allowance: corrupt counter (expected 8 bytes)".into(),
                        ));
                    }
                    u64::from_be_bytes(b.try_into().unwrap())
                }
                None => 0,
            };
            // saturating: a counter at u64::MAX can't wrap the sum, so an
            // over-cap spend can only ever be rejected, never admitted.
            if spent.saturating_add(amount) > limit {
                Err(Error::AllowanceExceeded {
                    scope: "per_period",
                    limit,
                    spent,
                    requested: amount,
                    period_secs: self.caps.period_secs,
                })
            } else {
                table
                    .insert(
                        key.as_slice(),
                        spent.saturating_add(amount).to_be_bytes().as_slice(),
                    )
                    .map_err(|e| Error::Internal(format!("allowance: insert: {e}")))?;
                Ok(())
            }
        };
        match outcome {
            Ok(()) => {
                write
                    .commit()
                    .map_err(|e| Error::Internal(format!("allowance: commit: {e}")))?;
                Ok(())
            }
            // Over-cap: drop the (un-inserted) write txn so nothing persists.
            Err(e) => {
                drop(write);
                Err(e)
            }
        }
    }

    /// Release a previously [`reserve`](Self::reserve)d `amount` back to the
    /// current window — call when a reserved spend fails to broadcast.
    ///
    /// **Best-effort**: a ledger hiccup here only leaves the window slightly
    /// over-counted (conservative — it can reject a later spend early, never
    /// admit an over-cap one), so it never turns the caller's original error
    /// into a different one. No-op when no per-period cap is configured.
    pub fn refund(&self, amount: u64, now: u64) {
        if self.caps.per_period.is_none() {
            return;
        }
        if let Err(e) = self.refund_inner(amount, now) {
            tracing::warn!("allowance: refund failed (non-fatal): {e}");
        }
    }

    fn refund_inner(&self, amount: u64, now: u64) -> Result<()> {
        let key = self.bucket(now).to_be_bytes();
        let write = self
            .db
            .begin_write()
            .map_err(|e| Error::Internal(format!("allowance: begin write: {e}")))?;
        {
            let mut table = write
                .open_table(SPENT_BY_BUCKET)
                .map_err(|e| Error::Internal(format!("allowance: open table: {e}")))?;
            let spent = match table
                .get(key.as_slice())
                .map_err(|e| Error::Internal(format!("allowance: get bucket: {e}")))?
            {
                Some(v) => {
                    let b = v.value();
                    if b.len() != 8 {
                        return Err(Error::Internal(
                            "allowance: corrupt counter (expected 8 bytes)".into(),
                        ));
                    }
                    u64::from_be_bytes(b.try_into().unwrap())
                }
                None => 0,
            };
            table
                .insert(
                    key.as_slice(),
                    spent.saturating_sub(amount).to_be_bytes().as_slice(),
                )
                .map_err(|e| Error::Internal(format!("allowance: insert: {e}")))?;
        }
        write
            .commit()
            .map_err(|e| Error::Internal(format!("allowance: commit: {e}")))?;
        Ok(())
    }

    /// Snapshot for the `allowance_status` RPC.
    pub fn status(&self, now: u64) -> Result<AllowanceStatus> {
        let (spent_this_period, remaining_this_period, window_resets_at) =
            match self.caps.per_period {
                Some(limit) => {
                    let bucket = self.bucket(now);
                    let spent = self.spent_in_bucket(bucket)?;
                    let resets_at = bucket
                        .saturating_add(1)
                        .saturating_mul(self.caps.period_secs);
                    (spent, Some(limit.saturating_sub(spent)), Some(resets_at))
                }
                None => (0, None, None),
            };
        Ok(AllowanceStatus {
            per_tx: self.caps.per_tx,
            per_period: self.caps.per_period,
            period_secs: self.caps.period_secs,
            spent_this_period,
            remaining_this_period,
            window_resets_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ledger(caps: AllowanceCaps) -> (TempDir, AllowanceLedger) {
        let dir = TempDir::new().unwrap();
        let l = AllowanceLedger::open(dir.path(), caps).unwrap();
        (dir, l)
    }

    #[test]
    fn unlimited_is_inert() {
        let (_d, l) = ledger(AllowanceCaps::default());
        assert!(!l.caps().is_active());
        // any amount reserves, refund is a no-op
        l.reserve(u64::MAX, 1_000).unwrap();
        l.refund(u64::MAX, 1_000);
        l.reserve(u64::MAX, 1_000).unwrap();
    }

    #[test]
    fn per_tx_cap_rejects_oversize() {
        let (_d, l) = ledger(AllowanceCaps {
            per_tx: Some(1_000),
            ..Default::default()
        });
        l.reserve(1_000, 0).unwrap(); // exactly at the cap is allowed
        let err = l.reserve(1_001, 0).unwrap_err();
        match err {
            Error::AllowanceExceeded {
                scope,
                limit,
                requested,
                ..
            } => {
                assert_eq!(scope, "per_tx");
                assert_eq!(limit, 1_000);
                assert_eq!(requested, 1_001);
            }
            other => panic!("wrong error: {other:?}"),
        }
        // per_tx is stateless: reserving does not accumulate.
        l.reserve(1_000, 0).unwrap();
        l.reserve(1_000, 0).unwrap();
    }

    #[test]
    fn per_period_cap_accumulates_then_rejects() {
        let caps = AllowanceCaps {
            per_period: Some(10_000),
            period_secs: 100,
            ..Default::default()
        };
        let (_d, l) = ledger(caps);
        let now = 12_345; // bucket = 123
        l.reserve(6_000, now).unwrap(); // 6_000 spent; 4_000 headroom
        l.reserve(4_000, now).unwrap(); // window full
        let err = l.reserve(1, now).unwrap_err();
        match err {
            Error::AllowanceExceeded {
                scope,
                limit,
                spent,
                requested,
                period_secs,
            } => {
                assert_eq!(scope, "per_period");
                assert_eq!(limit, 10_000);
                assert_eq!(spent, 10_000);
                assert_eq!(requested, 1);
                assert_eq!(period_secs, 100);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejected_reserve_does_not_consume_window() {
        let (_d, l) = ledger(AllowanceCaps {
            per_period: Some(100),
            period_secs: 100,
            ..Default::default()
        });
        l.reserve(60, 0).unwrap();
        // This one is over the remaining 40 → rejected, and must NOT have
        // persisted any reservation.
        l.reserve(50, 0).unwrap_err();
        assert_eq!(l.status(0).unwrap().spent_this_period, 60);
        // 40 of headroom is genuinely still there.
        l.reserve(40, 0).unwrap();
        assert_eq!(l.status(0).unwrap().spent_this_period, 100);
    }

    #[test]
    fn refund_returns_headroom() {
        let (_d, l) = ledger(AllowanceCaps {
            per_period: Some(10_000),
            period_secs: 100,
            ..Default::default()
        });
        l.reserve(8_000, 0).unwrap();
        l.refund(3_000, 0); // a failed broadcast hands the 3_000 back
        assert_eq!(l.status(0).unwrap().spent_this_period, 5_000);
        l.reserve(5_000, 0).unwrap(); // headroom restored
        l.reserve(1, 0).unwrap_err();
    }

    #[test]
    fn new_window_resets_spent() {
        let caps = AllowanceCaps {
            per_period: Some(10_000),
            period_secs: 100,
            ..Default::default()
        };
        let (_d, l) = ledger(caps);
        let now = 100; // bucket 1
        l.reserve(10_000, now).unwrap();
        l.reserve(1, now).unwrap_err(); // window 1 full
                                        // advance to the next tumbling window
        let later = 205; // bucket 2
        let st = l.status(later).unwrap();
        assert_eq!(st.spent_this_period, 0);
        assert_eq!(st.remaining_this_period, Some(10_000));
        assert_eq!(st.window_resets_at, Some(300));
        l.reserve(10_000, later).unwrap(); // fresh window has full headroom
    }

    #[test]
    fn counters_persist_across_reopen() {
        let dir = TempDir::new().unwrap();
        let caps = AllowanceCaps {
            per_period: Some(10_000),
            period_secs: 100,
            ..Default::default()
        };
        {
            let l = AllowanceLedger::open(dir.path(), caps).unwrap();
            l.reserve(7_000, 50).unwrap(); // bucket 0
        }
        let l2 = AllowanceLedger::open(dir.path(), caps).unwrap();
        assert_eq!(l2.status(50).unwrap().spent_this_period, 7_000);
        // 3_000 headroom survived the reopen
        l2.reserve(3_000, 50).unwrap();
        l2.reserve(1, 50).unwrap_err();
    }

    #[test]
    fn per_period_without_window_is_rejected_at_open() {
        let dir = TempDir::new().unwrap();
        let bad = AllowanceCaps {
            per_period: Some(1),
            period_secs: 0,
            ..Default::default()
        };
        assert!(AllowanceLedger::open(dir.path(), bad).is_err());
    }

    // ---- concurrency regression tests (the reviewer-flagged race) --------

    #[test]
    fn concurrent_reserve_has_no_lost_update() {
        use std::sync::Arc;
        let l = Arc::new(
            AllowanceLedger::in_memory(AllowanceCaps {
                per_period: Some(1_000),
                period_secs: 100,
                ..Default::default()
            })
            .unwrap(),
        );
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let l = l.clone();
                std::thread::spawn(move || l.reserve(1, 0))
            })
            .collect();
        let oks = handles
            .into_iter()
            .filter(|_| true)
            .map(|h| h.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(oks, 50, "all 50 reserves fit under the 1_000 cap");
        // The atomic in-txn RMW means every increment landed — no lost update.
        assert_eq!(l.status(0).unwrap().spent_this_period, 50);
    }

    #[test]
    fn concurrent_reserve_never_overshoots_cap() {
        use std::sync::Arc;
        let l = Arc::new(
            AllowanceLedger::in_memory(AllowanceCaps {
                per_period: Some(10),
                period_secs: 100,
                ..Default::default()
            })
            .unwrap(),
        );
        let handles: Vec<_> = (0..40)
            .map(|_| {
                let l = l.clone();
                std::thread::spawn(move || l.reserve(1, 0))
            })
            .collect();
        let oks = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(Result::is_ok)
            .count();
        // Exactly cap-many reserves may succeed, no matter the interleaving —
        // this is the property the two-transaction RMW used to violate.
        assert_eq!(oks, 10, "atomic check-and-reserve admits exactly the cap");
        assert_eq!(l.status(0).unwrap().spent_this_period, 10);
    }
}
