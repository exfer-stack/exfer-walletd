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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use exfer::types::transaction::OutPoint;

/// Auto-eviction interval. Comfortably longer than typical chain block
/// time so a normal transfer's UTXOs stay claimed until well after the
/// tx has confirmed, but short enough that a daemon left running with
/// a broken upstream doesn't permanently block its own wallets.
const TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub struct InFlightUtxos {
    pending: Mutex<HashMap<OutPoint, Instant>>,
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
}
