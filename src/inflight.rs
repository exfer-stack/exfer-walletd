//! In-flight UTXO tracker.
//!
//! When `transfer` selects a UTXO as an input, it stays in this set
//! until either (a) a TTL elapses or (b) the caller explicitly
//! releases it on a failure path. While in-flight, the same UTXO will
//! be skipped by *concurrent or subsequent* transfer requests so they
//! don't race onto the same outpoint and lose to the node's mempool-
//! level double-spend rejection.
//!
//! Failure modes this protects against:
//!
//! - **Back-to-back transfers from the same wallet.** Without
//!   tracking, the second call sees the same confirmed UTXO set the
//!   first call did (upstream `get_address_utxos` is confirmed-only
//!   on most node implementations), picks the same outpoints, and the
//!   node rejects the second tx as double-spend.
//! - **Concurrent transfers from the same wallet on different request
//!   handlers.** Atomicity of "filter + claim" under a single
//!   Mutex acquisition ensures no two callers select the same set.
//!
//! What this does NOT protect against:
//!
//! - **Daemon restart.** The table is in-memory. A pre-restart pending
//!   tx whose UTXO is still in mempool will collide with a post-
//!   restart selection. Same behavior as before this module existed.
//! - **A broadcast that succeeded on the wire but returned a transport
//!   error to walletd.** We release the claim on transport error, so a
//!   client retry can hit the same UTXOs; the upstream's mempool then
//!   rejects the retry as double-spend. Surfaces correctly to the
//!   client as -32020 with the mempool error in the message.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use exfer::types::transaction::OutPoint;
use exfer::types::Hash256;

use crate::error::Result;
use crate::store::WalletStore;
use crate::upstream::ExferNode;

/// Auto-eviction interval. Comfortably longer than typical chain block
/// time so a normal transfer's UTXOs stay claimed until well after the
/// tx has confirmed, but short enough that a daemon left running with
/// a broken upstream doesn't permanently block its own wallets.
const TTL: Duration = Duration::from_secs(600);

/// How long, after a boot that could not reconcile reservations from the
/// mempool (the upstream predates `get_address_mempool`), `htlc_lock` is
/// briefly held off so a restart mid-burst can't re-select an outpoint a
/// still-unconfirmed pre-restart lock already consumed. Sized to comfortably
/// exceed one EXFER block (~9s); on a slower-block node, raise it.
pub const LOCK_HOLD_SECS: Duration = Duration::from_secs(12);

#[derive(Default)]
pub struct InFlightUtxos {
    pending: Mutex<HashMap<OutPoint, Instant>>,
    /// When `Some(t)` and `now < t`, `htlc_lock` is held off (returns a
    /// retryable `InFlightExhausted`). Set only by the boot reconcile
    /// fallback; never blocks claims/reclaims/transfers.
    ready_at: Mutex<Option<Instant>>,
}

impl InFlightUtxos {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of outpoints currently claimed. Stale entries are GC'd
    /// as a side effect.
    pub fn pending(&self) -> Vec<OutPoint> {
        let mut g = self.pending.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, exp| now < *exp);
        g.keys().copied().collect()
    }

    /// Claim the given outpoints. Idempotent — re-claiming an
    /// already-claimed outpoint refreshes its TTL.
    pub fn claim(&self, outpoints: &[OutPoint]) {
        if outpoints.is_empty() {
            return;
        }
        let mut g = self.pending.lock().unwrap();
        let exp = Instant::now() + TTL;
        for op in outpoints {
            g.insert(*op, exp);
        }
    }

    /// Release claims (on failure paths). After release, the outpoints
    /// are immediately re-selectable by the next transfer.
    pub fn release(&self, outpoints: &[OutPoint]) {
        if outpoints.is_empty() {
            return;
        }
        let mut g = self.pending.lock().unwrap();
        for op in outpoints {
            g.remove(op);
        }
    }

    /// Current size, after GC. Useful for logs / diagnostics.
    pub fn len(&self) -> usize {
        let mut g = self.pending.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, exp| now < *exp);
        g.len()
    }

    /// True iff nothing is currently in-flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hold `htlc_lock` off until instant `t` (boot-reconcile fallback).
    pub fn hold_locks_until(&self, t: Instant) {
        *self.ready_at.lock().unwrap() = Some(t);
    }

    /// True iff `htlc_lock` is currently being held off (boot grace
    /// window not yet elapsed). Claims/reclaims/transfers ignore this.
    pub fn locks_held(&self) -> bool {
        match *self.ready_at.lock().unwrap() {
            Some(t) => Instant::now() < t,
            None => false,
        }
    }

    /// Atomic "snapshot pending set, run caller's selection, claim the
    /// chosen outpoints." All three happen under one Mutex acquisition,
    /// so two concurrent transfers from the same wallet can't both
    /// race onto the same outpoint between snapshot and claim.
    ///
    /// `select` receives the live in-flight set and decides which
    /// outpoints to claim. On `Ok`, walletd inserts the returned
    /// outpoints into the in-flight set and gives the caller a
    /// `ClaimGuard` that releases them on drop unless `commit()` is
    /// called.
    ///
    /// On `Err`, no outpoints are claimed — the caller's error path
    /// surfaces unchanged.
    pub fn select_and_claim<F, T, E>(
        &self,
        select: F,
    ) -> std::result::Result<(ClaimGuard<'_>, T), E>
    where
        F: FnOnce(&HashSet<OutPoint>) -> std::result::Result<(Vec<OutPoint>, T), E>,
    {
        let mut g = self.pending.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, exp| now < *exp);
        let snapshot: HashSet<OutPoint> = g.keys().copied().collect();
        let (claimed, value) = select(&snapshot)?;
        let exp = now + TTL;
        for op in &claimed {
            g.insert(*op, exp);
        }
        drop(g);
        Ok((
            ClaimGuard {
                inflight: self,
                outpoints: claimed,
                committed: false,
            },
            value,
        ))
    }
}

/// Seed the in-flight reservation set from the operator address(es)'
/// **mempool** at startup. Because `InFlightUtxos` is in-memory, a daemon
/// bounce mid-burst would otherwise drop every reservation and a fresh
/// selection could re-collide with a still-unconfirmed pre-restart lock.
/// This claims each outpoint that an unconfirmed tx is spending out of a
/// managed address, so the next `htlc_lock` skips them — exactly the
/// outpoints a naive selection must avoid.
///
/// Returns `(outpoints_seeded, mempool_rpc_available)`. When the upstream
/// predates `get_address_mempool` (`-32601` → `Ok(None)`), availability is
/// `false` and the caller applies the one-block hold fallback instead.
///
/// Pure-additive: this only ever **claims** (reserves); it never spends.
/// Best-effort and bounded by the managed-address count (1 for the pool
/// sidecar).
pub async fn reconcile_from_mempool(
    inflight: &InFlightUtxos,
    store: &dyn WalletStore,
    node: &ExferNode,
) -> Result<(usize, bool)> {
    let mut seeded = 0usize;
    let mut available = true;
    for entry in store.list()? {
        match node.get_address_mempool_opt(&entry.address).await? {
            Some(resp) => {
                let mut ops: Vec<OutPoint> = Vec::new();
                for tx in &resp.mempool {
                    for s in &tx.spent {
                        // `MempoolSpent.tx_id`/`output_index` identify
                        // THIS address's own output being consumed by an
                        // unconfirmed tx — the outpoint a fresh selection
                        // must not re-pick.
                        let bytes = crate::tx::decode_hash(&s.tx_id)?;
                        ops.push(OutPoint {
                            tx_id: Hash256(bytes),
                            output_index: s.output_index,
                        });
                    }
                }
                if !ops.is_empty() {
                    inflight.claim(&ops);
                    seeded += ops.len();
                }
            }
            None => available = false,
        }
    }
    Ok((seeded, available))
}

/// RAII guard that releases claimed outpoints on drop unless `commit`
/// is called first. Keeps the failure-path bookkeeping in `transfer`
/// straightforward: errors short-circuit with `?`, the guard's `Drop`
/// runs, and the claims are released.
pub struct ClaimGuard<'a> {
    inflight: &'a InFlightUtxos,
    outpoints: Vec<OutPoint>,
    committed: bool,
}

impl<'a> ClaimGuard<'a> {
    pub fn new(inflight: &'a InFlightUtxos, outpoints: Vec<OutPoint>) -> Self {
        inflight.claim(&outpoints);
        Self {
            inflight,
            outpoints,
            committed: false,
        }
    }

    /// Mark the claim as kept past the lifetime of this guard. After
    /// `commit`, the outpoints stay in-flight until TTL evicts them.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.inflight.release(&self.outpoints);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfer::types::Hash256;

    fn op(byte: u8, idx: u32) -> OutPoint {
        OutPoint {
            tx_id: Hash256([byte; 32]),
            output_index: idx,
        }
    }

    #[test]
    fn claim_and_release_round_trip() {
        let f = InFlightUtxos::new();
        let a = op(0xaa, 0);
        let b = op(0xbb, 1);
        f.claim(&[a, b]);
        assert_eq!(f.len(), 2);
        f.release(&[a]);
        assert_eq!(f.len(), 1);
        assert!(f.pending().contains(&b));
    }

    #[test]
    fn locks_held_gate_defaults_open_and_respects_deadline() {
        let f = InFlightUtxos::new();
        // No hold set → open.
        assert!(!f.locks_held());
        // Future deadline → held.
        f.hold_locks_until(Instant::now() + Duration::from_secs(60));
        assert!(f.locks_held());
        // Past deadline → open again.
        f.hold_locks_until(Instant::now() - Duration::from_secs(1));
        assert!(!f.locks_held());
    }

    #[test]
    fn empty_calls_are_noops() {
        let f = InFlightUtxos::new();
        f.claim(&[]);
        f.release(&[]);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn re_claim_does_not_double_count() {
        let f = InFlightUtxos::new();
        let a = op(0xaa, 0);
        f.claim(&[a]);
        f.claim(&[a]);
        f.claim(&[a]);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn guard_releases_on_drop() {
        let f = InFlightUtxos::new();
        let a = op(0x11, 0);
        {
            let _g = ClaimGuard::new(&f, vec![a]);
            assert_eq!(f.len(), 1);
        }
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn guard_keeps_claim_after_commit() {
        let f = InFlightUtxos::new();
        let a = op(0x22, 0);
        {
            let g = ClaimGuard::new(&f, vec![a]);
            g.commit();
        }
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn select_and_claim_atomically_excludes_concurrent_picks() {
        // Two consecutive select_and_claim calls from the same wallet
        // mustn't both pick outpoint A. The first commits its claim; the
        // second's selection sees A in `pending` and skips it.
        let f = InFlightUtxos::new();
        let a = op(0xaa, 0);
        let b = op(0xbb, 0);

        // First "transfer" picks A.
        let (g1, picked1) = f
            .select_and_claim::<_, _, ()>(|pending| {
                assert!(pending.is_empty());
                Ok((vec![a], a))
            })
            .unwrap();
        assert_eq!(picked1, a);
        g1.commit();

        // Second "transfer" — A must be visible as pending.
        let (g2, picked2) = f
            .select_and_claim::<_, _, ()>(|pending| {
                assert!(pending.contains(&a), "first claim must be visible");
                Ok((vec![b], b))
            })
            .unwrap();
        assert_eq!(picked2, b);
        g2.commit();

        assert_eq!(f.len(), 2);
    }

    #[test]
    fn select_and_claim_err_path_claims_nothing() {
        let f = InFlightUtxos::new();
        let res: std::result::Result<(ClaimGuard, ()), &'static str> =
            f.select_and_claim(|_pending| Err("nope"));
        assert!(matches!(res, Err("nope")));
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn select_and_claim_guard_releases_on_drop() {
        let f = InFlightUtxos::new();
        let a = op(0xaa, 0);
        {
            let (_guard, _v) = f
                .select_and_claim::<_, _, ()>(|_p| Ok((vec![a], ())))
                .unwrap();
            assert_eq!(f.len(), 1);
            // drop without commit
        }
        assert_eq!(f.len(), 0);
    }
}
