//! Per-transfer idempotency cache.
//!
//! When a client supplies `transfer.client_token`, walletd guarantees:
//!
//! - The first call runs normally and the receipt is cached under the
//!   token for `TTL` (1h).
//! - Subsequent calls with the **same** token and **same fingerprint**
//!   return the cached receipt without re-running the transfer. This
//!   makes "transport timed out, retrying" idempotent — the second call
//!   returns the same `tx_id` as the first instead of double-spending.
//! - Concurrent calls with the same token block on a shared `Notify`
//!   so only one transfer actually fires.
//! - Different-fingerprint reuse of a still-cached token surfaces as
//!   `Error::IdempotencyConflict` so a client bug (token reuse with
//!   different `outputs`) can't accidentally pass through.
//!
//! Failures are NOT cached — an erroring call leaves the slot empty so
//! a corrected retry under the same token can proceed.
//!
//! The cache is in-memory only; daemon restart wipes it. That matches
//! the in-flight-UTXO tracker's lifetime — both are best-effort
//! protection against client retries within a short window.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::tx::TransferReceipt;

const TTL: Duration = Duration::from_secs(3600);

/// Maximum number of `Done` entries kept in the cache. The TTL is the
/// primary GC; this cap defends against a misbehaving caller that
/// rotates tokens faster than they expire.
const MAX_DONE_ENTRIES: usize = 10_000;

pub struct IdempotencyCache {
    inner: Mutex<HashMap<String, Slot>>,
}

enum Slot {
    InFlight(Arc<Notify>),
    Done {
        stored_at: Instant,
        fingerprint: u64,
        receipt: Arc<TransferReceipt>,
    },
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Approximate count after GC. Useful for `get_status`.
    pub fn len(&self) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        gc(&mut g);
        g.len()
    }

    /// True iff no entries are currently cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run `f` exactly once per `(token, fingerprint)` combination, or
    /// return the cached receipt if the same combination has run within
    /// TTL. Different fingerprints under the same token → `Conflict`.
    pub async fn get_or_run<F, Fut>(
        &self,
        token: &str,
        fingerprint: u64,
        f: F,
    ) -> Result<Arc<TransferReceipt>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<TransferReceipt>>,
    {
        loop {
            let action = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                gc(&mut g);
                match g.get(token) {
                    Some(Slot::Done {
                        fingerprint: stored_fp,
                        receipt,
                        ..
                    }) => {
                        if *stored_fp == fingerprint {
                            Action::Return(Ok(receipt.clone()))
                        } else {
                            Action::Return(Err(Error::IdempotencyConflict {
                                token: token.to_string(),
                            }))
                        }
                    }
                    Some(Slot::InFlight(n)) => Action::Wait(n.clone()),
                    None => {
                        let notify = Arc::new(Notify::new());
                        g.insert(token.to_string(), Slot::InFlight(notify.clone()));
                        Action::Compute(notify)
                    }
                }
            };
            match action {
                Action::Return(r) => return r,
                Action::Wait(n) => n.notified().await,
                Action::Compute(notify) => {
                    let result = f().await;
                    let stored = {
                        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        match &result {
                            Ok(receipt) => {
                                let arc = Arc::new(receipt.clone());
                                // Honour the cap by evicting the
                                // oldest Done slot before inserting.
                                if g.len() >= MAX_DONE_ENTRIES {
                                    drop_oldest_done(&mut g);
                                }
                                g.insert(
                                    token.to_string(),
                                    Slot::Done {
                                        stored_at: Instant::now(),
                                        fingerprint,
                                        receipt: arc.clone(),
                                    },
                                );
                                Ok(arc)
                            }
                            Err(_) => {
                                // Failed runs leave no trace — a fixed
                                // retry should be allowed.
                                g.remove(token);
                                Err(())
                            }
                        }
                    };
                    notify.notify_waiters();
                    return match stored {
                        Ok(arc) => Ok(arc),
                        Err(_) => Err(result.unwrap_err()),
                    };
                }
            }
        }
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

enum Action {
    Return(Result<Arc<TransferReceipt>>),
    Wait(Arc<Notify>),
    Compute(Arc<Notify>),
}

fn gc(map: &mut HashMap<String, Slot>) {
    let now = Instant::now();
    map.retain(|_, slot| match slot {
        Slot::Done { stored_at, .. } => now.duration_since(*stored_at) < TTL,
        Slot::InFlight(_) => true,
    });
}

fn drop_oldest_done(map: &mut HashMap<String, Slot>) {
    let oldest = map
        .iter()
        .filter_map(|(k, v)| match v {
            Slot::Done { stored_at, .. } => Some((k.clone(), *stored_at)),
            Slot::InFlight(_) => None,
        })
        .min_by_key(|(_, t)| *t)
        .map(|(k, _)| k);
    if let Some(k) = oldest {
        map.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn dummy_receipt(tx_id: &str) -> TransferReceipt {
        TransferReceipt {
            tx_id: tx_id.to_string(),
            size: 0,
            fee: 0,
            fee_rate: 0,
            inputs: vec![],
            outputs: vec![],
            built_at_height: 0,
        }
    }

    #[tokio::test]
    async fn cache_miss_runs_and_caches() {
        let cache = IdempotencyCache::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let c1 = calls.clone();
        let r1 = cache
            .get_or_run("tok", 7, move || async move {
                c1.fetch_add(1, Ordering::SeqCst);
                Ok(dummy_receipt("first"))
            })
            .await
            .unwrap();
        assert_eq!(r1.tx_id, "first");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Same token + same fingerprint → cached, f does not run.
        let c2 = calls.clone();
        let r2 = cache
            .get_or_run("tok", 7, move || async move {
                c2.fetch_add(1, Ordering::SeqCst);
                Ok(dummy_receipt("second"))
            })
            .await
            .unwrap();
        assert_eq!(r2.tx_id, "first", "must return cached receipt");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "f must not re-run");
    }

    #[tokio::test]
    async fn same_token_different_fingerprint_conflicts() {
        let cache = IdempotencyCache::new();
        let _ = cache
            .get_or_run("tok", 1, || async { Ok(dummy_receipt("a")) })
            .await
            .unwrap();
        let err = cache
            .get_or_run("tok", 2, || async { Ok(dummy_receipt("b")) })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::IdempotencyConflict { .. }));
    }

    #[tokio::test]
    async fn failure_does_not_poison_token() {
        let cache = IdempotencyCache::new();
        let err = cache
            .get_or_run("tok", 1, || async {
                Err(Error::TxBuild("synthetic".into()))
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::TxBuild(_)));

        // Retry under same token must now succeed and cache.
        let r = cache
            .get_or_run("tok", 1, || async { Ok(dummy_receipt("retry")) })
            .await
            .unwrap();
        assert_eq!(r.tx_id, "retry");
    }

    #[tokio::test]
    async fn concurrent_same_token_runs_f_exactly_once() {
        let cache = Arc::new(IdempotencyCache::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_run("tok", 42, || async {
                        // Yield to let other peers contend.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(dummy_receipt("once"))
                    })
                    .await
                    .unwrap()
            }));
        }
        for h in handles {
            let r = h.await.unwrap();
            assert_eq!(r.tx_id, "once");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
