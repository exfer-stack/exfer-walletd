//! Lock-confirmation watchdog.
//!
//! `htlc_lock` is otherwise fire-and-forget: once broadcast, nothing
//! re-checks that the lock actually confirms. An EXFER mempool eviction
//! would leave the lock silently un-confirmed — the swap pool's
//! `verify_pool_exfer_lock` never passes and a BUY slow-aborts (safe, no
//! funds moved, but invisible).
//!
//! This watchdog tracks every just-broadcast operator HTLC lock and, if
//! the node no longer shows the tx (evicted / never propagated) and a
//! refractory interval has elapsed, **rebroadcasts the same signed
//! bytes** (same covenant — idempotent) and refreshes the in-flight
//! reservation TTL so a concurrent selection can't grab the same inputs.
//! A lock that confirms is dropped from the set; one that ages out past
//! `LOCK_WATCH_MAX_AGE` is given up on safely (the swap times out and the
//! pool reclaims — funds are never at risk).
//!
//! Gated OFF by default (`Config::lock_watchdog`) so the embedded
//! mobile/desktop walletds add no polling; the pool sidecar deploy sets
//! the flag.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use exfer::types::transaction::OutPoint;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::inflight::InFlightUtxos;
use crate::upstream::ExferNode;

/// How often the watchdog wakes to re-check pending locks.
const LOCK_WATCH_TICK: Duration = Duration::from_secs(10);
/// Refractory interval between rebroadcasts of the same evicted lock.
/// Shorter than swap.rs `CLAIM_REBROADCAST_SECS` (60s) because a lock is
/// more time-sensitive — the user's BNB-lock budget is ticking.
const LOCK_REBROADCAST_SECS: u64 = 30;
/// Give up watching a lock after this long. Past it the swap's own
/// timeout/reclaim path is the safety net; no funds are at risk.
const LOCK_WATCH_MAX_AGE: Duration = Duration::from_secs(1800);

#[derive(Clone)]
struct PendingLock {
    /// Serialized signed tx, hex — the exact bytes to rebroadcast.
    tx_hex: String,
    /// Inputs this lock consumed; re-claimed on rebroadcast to refresh
    /// the reservation TTL.
    outpoints: Vec<OutPoint>,
    first_broadcast: Instant,
    last_rebroadcast: Instant,
}

impl PendingLock {
    /// Due for a rebroadcast attempt at `now`?
    fn due(&self, now: Instant) -> bool {
        now.duration_since(self.last_rebroadcast) >= Duration::from_secs(LOCK_REBROADCAST_SECS)
    }

    /// Aged out — stop watching at `now`?
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.first_broadcast) >= LOCK_WATCH_MAX_AGE
    }
}

/// Set of operator HTLC locks awaiting confirmation, keyed by tx_id hex.
#[derive(Default)]
pub struct LockWatch {
    pending: Mutex<HashMap<String, PendingLock>>,
}

impl LockWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a just-broadcast lock for watching. Infallible and
    /// idempotent — re-registering the same tx_id overwrites in place.
    /// Called best-effort right after a successful broadcast; never
    /// affects the lock result.
    pub fn register(&self, tx_id_hex: String, tx_hex: String, outpoints: Vec<OutPoint>) {
        let now = Instant::now();
        self.pending.lock().unwrap().insert(
            tx_id_hex,
            PendingLock {
                tx_hex,
                outpoints,
                first_broadcast: now,
                last_rebroadcast: now,
            },
        );
    }

    /// Stop watching a tx (confirmed, or given up).
    pub fn remove(&self, tx_id_hex: &str) {
        self.pending.lock().unwrap().remove(tx_id_hex);
    }

    /// Current count of watched locks.
    pub fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot (tx_id, entry) for the watchdog tick to iterate without
    /// holding the lock across `.await`.
    fn snapshot(&self) -> Vec<(String, PendingLock)> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Mark a rebroadcast as having just happened (refresh the refractory
    /// timer) without disturbing `first_broadcast`.
    fn touch_rebroadcast(&self, tx_id_hex: &str, now: Instant) {
        if let Some(e) = self.pending.lock().unwrap().get_mut(tx_id_hex) {
            e.last_rebroadcast = now;
        }
    }
}

/// Watchdog loop. Polls each pending lock; rebroadcasts evicted ones.
/// Runs until `shutdown` is cancelled.
pub async fn run_lock_watchdog(
    watch: Arc<LockWatch>,
    node: Arc<ExferNode>,
    inflight: Arc<InFlightUtxos>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = sleep(LOCK_WATCH_TICK) => {}
        }

        for (tx_id, entry) in watch.snapshot() {
            let now = Instant::now();
            if entry.expired(now) {
                tracing::warn!(tx_id = %tx_id, "lock watchdog: giving up (max age); swap timeout/reclaim is the safety net");
                watch.remove(&tx_id);
                continue;
            }

            match node.get_transaction_opt(&tx_id).await {
                // Confirmed — done.
                Ok(Some(s)) if s.block_height.is_some() => {
                    watch.remove(&tx_id);
                }
                // Still in mempool — keep waiting.
                Ok(Some(s)) if s.in_mempool => {}
                // Evicted (present-but-neither) or gone (None) — rebroadcast if due.
                Ok(_) => {
                    if entry.due(now) {
                        match node.send_raw_transaction(&entry.tx_hex).await {
                            Ok(_) => {
                                // Refresh the reservation so nothing re-selects these inputs.
                                inflight.claim(&entry.outpoints);
                                watch.touch_rebroadcast(&tx_id, now);
                                tracing::info!(tx_id = %tx_id, "lock watchdog: rebroadcast evicted lock");
                            }
                            Err(e) => {
                                // Idempotent: an "already in chain" reject means it
                                // actually confirmed — harmless. Always warn-level.
                                tracing::warn!(tx_id = %tx_id, error = %e, "lock watchdog: rebroadcast failed (will retry)");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(tx_id = %tx_id, error = %e, "lock watchdog: status check failed (will retry)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfer::types::Hash256;

    fn op(byte: u8) -> OutPoint {
        OutPoint {
            tx_id: Hash256([byte; 32]),
            output_index: 0,
        }
    }

    #[test]
    fn register_and_remove() {
        let w = LockWatch::new();
        assert!(w.is_empty());
        w.register("aa".into(), "deadbeef".into(), vec![op(0x11)]);
        assert_eq!(w.len(), 1);
        w.register("bb".into(), "cafe".into(), vec![op(0x22)]);
        assert_eq!(w.len(), 2);
        w.remove("aa");
        assert_eq!(w.len(), 1);
        w.remove("missing"); // no-op
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn due_predicate_respects_refractory_interval() {
        let t0 = Instant::now();
        let e = PendingLock {
            tx_hex: "00".into(),
            outpoints: vec![],
            first_broadcast: t0,
            last_rebroadcast: t0,
        };
        // Just broadcast: not due.
        assert!(!e.due(t0));
        assert!(!e.due(t0 + Duration::from_secs(LOCK_REBROADCAST_SECS - 1)));
        // Past the refractory interval: due.
        assert!(e.due(t0 + Duration::from_secs(LOCK_REBROADCAST_SECS)));
        assert!(e.due(t0 + Duration::from_secs(LOCK_REBROADCAST_SECS + 5)));
    }

    #[test]
    fn expired_predicate_respects_max_age() {
        let t0 = Instant::now();
        let e = PendingLock {
            tx_hex: "00".into(),
            outpoints: vec![],
            first_broadcast: t0,
            last_rebroadcast: t0,
        };
        assert!(!e.expired(t0));
        assert!(!e.expired(t0 + LOCK_WATCH_MAX_AGE - Duration::from_secs(1)));
        assert!(e.expired(t0 + LOCK_WATCH_MAX_AGE));
    }

    #[test]
    fn touch_rebroadcast_refreshes_timer_not_first_broadcast() {
        let w = LockWatch::new();
        let t0 = Instant::now();
        w.register("aa".into(), "00".into(), vec![]);
        let later = t0 + Duration::from_secs(100);
        w.touch_rebroadcast("aa", later);
        let snap = w.snapshot();
        let (_, e) = &snap[0];
        assert_eq!(e.last_rebroadcast, later);
        // first_broadcast was set at register time (~t0), not moved.
        assert!(e.first_broadcast < later);
    }
}
