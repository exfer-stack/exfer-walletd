//! Background cache refresher — single supervisor task.
//!
//! One tokio task drives every tick of the cache. Owning the schedule
//! in one place is intentional: reorg detection is a global decision
//! ("a new tip's `prev_block_id` doesn't match our cached tip's
//! `block_id` → invalidate L2 + L3 everywhere"), and splitting it
//! across per-cache tasks would race on the detection itself.
//!
//! ## Tick loop
//!
//! Self-rescheduling (NOT `tokio::time::interval`):
//!
//! ```text
//!   loop:
//!     1. if shutdown signaled → break
//!     2. force-fetch tip
//!     3. detect reorg vs. previous tip:
//!          - height < prev   → invalidate L2/L3 (deep reorg)
//!          - prev_hash break → invalidate L2/L3 (shallow reorg)
//!          - jump > 32       → invalidate L2/L3 (fell behind)
//!          - else            → incremental
//!     4. snapshot addresses; stratify oldest-first; cap at max_per_tick
//!     5. fan out (concurrency-bounded): get_balance + get_address_utxos
//!     6. per-address: CAS write or note_error
//!     7. if every fan-out call failed → exponential backoff
//!     8. sleep refresh_interval (or backoff_secs)
//! ```
//!
//! `tokio::time::interval` was rejected because the default
//! `MissedTickBehavior::Burst` pile-ups multiple ticks against a slow
//! upstream — a single 8-second RTT spike would queue every subsequent
//! tick. Self-rescheduling guarantees one tick at a time; an overrun
//! just delays the next start, no pile-up.
//!
//! ## All-fail backoff
//!
//! If every single per-address call in a tick fails, we assume upstream
//! is fully down and back off exponentially: 5s → 10s → 20s → 40s → 60s
//! (cap). Reset to base on the first successful tick. Partial failures
//! (some addresses succeed, others fail) do NOT back off — they are
//! per-address noise, not systemic outage.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::cache::WalletCache;
use crate::store::WalletStore;
use crate::upstream::{BlockTip, ExferNode};

/// Cap on tip-height jump that we'll consider "normal advance" instead
/// of "we lost contact and fell catastrophically behind." Per the
/// design plan.
const FELL_BEHIND_THRESHOLD: u64 = 32;

/// Maximum exponential backoff between ticks when upstream is fully
/// down. Roughly 1 minute is the sweet spot — fast enough to recover
/// when the outage ends, slow enough to not hammer the upstream while
/// it's down.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Handle returned by [`spawn`]. Drop the handle to leave the
/// refresher running; call [`RefresherHandle::shutdown`] to ask it to
/// stop and await its exit.
pub struct RefresherHandle {
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RefresherHandle {
    /// Signal shutdown and await the supervisor task. If the supervisor
    /// is mid-tick, it finishes the current per-address batch before
    /// exiting (no cancellation of in-flight HTTP requests).
    pub async fn shutdown(self) {
        // Errors on send mean the receiver was dropped — supervisor
        // already exited. Either way, await join.
        let _ = self.shutdown_tx.send(true);
        let _ = self.join.await;
    }

    /// Abort without waiting. For tests where the runtime is about
    /// to be torn down anyway.
    #[cfg(test)]
    pub fn abort(self) {
        self.join.abort();
    }
}

/// Spawn the supervisor task. Returns immediately; the task runs in
/// the background.
///
/// Does nothing (and returns a "no-op" handle whose shutdown is
/// instantaneous) when `cache.params.enabled == false`.
pub fn spawn(
    cache: Arc<WalletCache>,
    node: Arc<ExferNode>,
    store: Arc<dyn WalletStore>,
) -> RefresherHandle {
    let (tx, rx) = watch::channel(false);

    if !cache.params.enabled {
        // No-op supervisor — exits immediately when shutdown is signaled.
        let mut rx = rx;
        let join = tokio::spawn(async move {
            let _ = rx.changed().await;
        });
        return RefresherHandle {
            shutdown_tx: tx,
            join,
        };
    }

    let interval = cache.params.refresh_interval;
    let concurrency = cache.params.concurrency.max(1);
    let max_per_tick = cache.params.max_per_tick.max(1);

    let join = tokio::spawn(async move {
        tracing::info!(
            refresh_interval_ms = interval.as_millis() as u64,
            concurrency = concurrency,
            max_per_tick = max_per_tick,
            "cache refresher: starting"
        );
        run_loop(cache, node, store, rx, interval, concurrency, max_per_tick).await;
        tracing::info!("cache refresher: stopped");
    });

    RefresherHandle {
        shutdown_tx: tx,
        join,
    }
}

async fn run_loop(
    cache: Arc<WalletCache>,
    node: Arc<ExferNode>,
    store: Arc<dyn WalletStore>,
    mut shutdown_rx: watch::Receiver<bool>,
    base_interval: Duration,
    concurrency: usize,
    max_per_tick: usize,
) {
    let mut prev_tip: Option<BlockTip> = None;
    let mut consecutive_full_failures: u32 = 0;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let tick_started = Instant::now();
        let outcome = run_one_tick(
            cache.clone(),
            node.clone(),
            store.as_ref(),
            &mut prev_tip,
            concurrency,
            max_per_tick,
        )
        .await;

        let next_wait = match outcome {
            TickOutcome::Ok | TickOutcome::PartialFailure => {
                consecutive_full_failures = 0;
                base_interval
            }
            TickOutcome::AllFailed => {
                consecutive_full_failures = consecutive_full_failures.saturating_add(1);
                let backoff = backoff_for_attempt(base_interval, consecutive_full_failures);
                tracing::warn!(
                    attempt = consecutive_full_failures,
                    backoff_ms = backoff.as_millis() as u64,
                    "cache refresher: all upstream calls failed, backing off"
                );
                backoff
            }
            TickOutcome::NoWork => {
                // Cache is empty + store is empty; sleep normally.
                base_interval
            }
        };

        // Self-reschedule: sleep what's left after this tick's work,
        // with at-most-one tick in flight. If we already exceeded the
        // interval (slow upstream), the next tick fires immediately
        // (i.e. no negative sleep / pile-up).
        let elapsed = tick_started.elapsed();
        let sleep = next_wait.saturating_sub(elapsed);

        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            _ = tokio::time::sleep(sleep) => {}
        }
    }
}

/// Exponential backoff: 5s base → 5, 10, 20, 40, 60 (cap).
fn backoff_for_attempt(base: Duration, attempt: u32) -> Duration {
    let mult = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX);
    let candidate = base.saturating_mul(mult as u32);
    if candidate > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        candidate
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TickOutcome {
    /// Every address that we attempted succeeded.
    Ok,
    /// At least one succeeded; at least one failed. Per-address noise,
    /// no backoff.
    PartialFailure,
    /// Every per-address call failed (and we tried at least one).
    /// Suggests systemic upstream issue; back off.
    AllFailed,
    /// Nothing to do this tick (store empty, no entries to refresh).
    NoWork,
}

async fn run_one_tick(
    cache: Arc<WalletCache>,
    node: Arc<ExferNode>,
    store: &dyn WalletStore,
    prev_tip: &mut Option<BlockTip>,
    concurrency: usize,
    max_per_tick: usize,
) -> TickOutcome {
    // Step 1: refresh tip (always upstream; refresher is the source).
    let tip_snap = match cache.tip.force_fetch(&node).await {
        Ok(s) if !s.stale => s,
        Ok(s) => {
            // Stale (i.e. served-stale on upstream failure). Treat as a
            // full failure for backoff purposes — we couldn't get tip.
            tracing::warn!(
                last_error = ?s.last_error,
                "cache refresher: tip fetch returned stale value"
            );
            return TickOutcome::AllFailed;
        }
        Err(e) => {
            tracing::warn!(error = %e, "cache refresher: tip force_fetch failed");
            return TickOutcome::AllFailed;
        }
    };

    // Step 2: reorg detection.
    detect_reorg_and_invalidate(prev_tip.as_ref(), &tip_snap.tip, &cache);
    *prev_tip = Some(tip_snap.tip.clone());
    let tip_height = tip_snap.tip.height;

    // Step 3: snapshot addresses.
    let addrs = match store.list() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "cache refresher: store.list failed");
            return TickOutcome::AllFailed;
        }
    };

    if addrs.is_empty() {
        return TickOutcome::NoWork;
    }

    // Step 4: stratify oldest-first. Addresses with no L2 entry
    // (fetched_at=None) sort as maximally stale (front of the list).
    let mut ranked: Vec<(String, Option<Instant>)> = addrs
        .into_iter()
        .map(|a| {
            let snap = cache.balance.peek(&a);
            (a, snap.fetched_at)
        })
        .collect();
    ranked.sort_by(|a, b| compare_age(a.1, b.1));
    ranked.truncate(max_per_tick);

    let total = ranked.len();
    if total == 0 {
        return TickOutcome::NoWork;
    }

    // Step 5: per-address concurrent fan-out. Each future owns an Arc
    // clone — buffer_unordered futures must be 'static-friendly.
    let results: Vec<bool> = stream::iter(ranked)
        .map(|(addr, _age)| {
            let c = cache.clone();
            let n = node.clone();
            async move { refresh_one(&c, &n, &addr, tip_height).await }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let ok = results.iter().filter(|x| **x).count();
    let failed = total - ok;
    tracing::debug!(
        total,
        ok,
        failed,
        tip_height,
        "cache refresher: tick complete"
    );

    if failed == 0 {
        TickOutcome::Ok
    } else if ok == 0 {
        TickOutcome::AllFailed
    } else {
        TickOutcome::PartialFailure
    }
}

/// Per-address refresh: parallel get_balance + get_address_utxos,
/// CAS-write each that succeeds, note_error each that fails. Returns
/// `true` if at least one of the two succeeded (so the caller can
/// distinguish "this address had any progress" from "everything broke").
async fn refresh_one(cache: &WalletCache, node: &ExferNode, addr: &str, tip_height: u64) -> bool {
    // Sample generation *before* fetching so a transfer-commit
    // invalidation that happens during our fetch loses our CAS.
    let bal_gen = cache.balance.peek(addr).generation;
    let utxo_gen = cache.utxo.by_addr.get(&addr.to_string()).generation;

    let (bal_res, utxo_res) = tokio::join!(node.get_balance(addr), node.get_address_utxos(addr));

    let mut any_ok = false;

    match bal_res {
        Ok(b) => {
            if crate::cache::balance::verify_address(&b.address, addr).is_ok() {
                let accepted = cache
                    .balance
                    .cas_write(addr, bal_gen, b.balance, tip_height);
                if !accepted {
                    tracing::debug!(addr, "refresher balance write lost CAS — invalidation wins");
                }
                any_ok = true;
            } else {
                cache
                    .balance
                    .note_error(addr, "address-mismatch from upstream".into());
            }
        }
        Err(e) => {
            cache.balance.note_error(addr, e.to_string());
        }
    }

    match utxo_res {
        Ok(u) => {
            let address_ok = match u.address.as_deref() {
                None => true,
                Some(returned) => crate::cache::balance::verify_address(returned, addr).is_ok(),
            };
            if address_ok {
                let accepted = cache.utxo.cas_write_address(addr, utxo_gen, u, tip_height);
                if !accepted {
                    tracing::debug!(addr, "refresher utxo write lost CAS — invalidation wins");
                }
                any_ok = true;
            } else {
                cache
                    .utxo
                    .note_address_error(addr, "address-mismatch from upstream".into());
            }
        }
        Err(e) => {
            cache.utxo.note_address_error(addr, e.to_string());
        }
    }

    any_ok
}

fn detect_reorg_and_invalidate(prev: Option<&BlockTip>, new: &BlockTip, cache: &WalletCache) {
    let Some(prev) = prev else {
        // First tick — nothing to compare.
        return;
    };
    if new.block_id == prev.block_id {
        // No advance.
        return;
    }
    let mut reason: Option<&'static str> = None;

    if new.height < prev.height {
        reason = Some("deep-reorg (tip height went backwards)");
    } else if new.height == prev.height && new.block_id != prev.block_id {
        reason = Some("shallow-reorg (same height, different block_id)");
    } else if new.height > prev.height.saturating_add(FELL_BEHIND_THRESHOLD) {
        reason = Some("fell-behind (jumped more than threshold)");
    }
    // Note: a deeper "prev.block_id chains backward from new" check would
    // require fetching every intermediate block_id, which is expensive.
    // For now we trust the height delta + the upstream's tip. A hash-chain
    // walk can be added if reorgs become a problem.

    if let Some(r) = reason {
        tracing::warn!(
            prev_height = prev.height,
            new_height = new.height,
            prev_block = %prev.block_id,
            new_block = %new.block_id,
            reason = r,
            "cache refresher: invalidating L2 + L3 + L4 + L5 due to chain divergence"
        );
        cache.balance.invalidate_all();
        cache.utxo.invalidate_all();
        // L4/L5 are LRU caches with no generation; full clear is the
        // simplest correct path on reorg. Re-population is cheap.
        cache.block.invalidate_all();
        cache.tx.invalidate_all();
    }
}

fn compare_age(a: Option<Instant>, b: Option<Instant>) -> Ordering {
    // None = "never fetched" = maximally stale → sorts first (Less).
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(ta), Some(tb)) => ta.cmp(&tb),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheProfile, WalletCache};
    use crate::store::FsWalletStore;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tip_body(height: u64, block_id: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{"height":height,"block_id":block_id}
        })
    }

    fn balance_body(addr: &str, balance: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{"address": addr, "balance": balance}
        })
    }

    fn utxo_body(addr: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{"address": addr, "tip_height":1, "truncated":false, "utxos":[]}
        })
    }

    fn make_cache(profile: CacheProfile) -> Arc<WalletCache> {
        // Aggressive in tests so refresh_interval is short.
        Arc::new(WalletCache::new(profile, Some(1)))
    }

    #[tokio::test]
    async fn refresher_no_op_when_disabled() {
        let server = MockServer::start().await;
        // No mocks needed — refresher shouldn't hit upstream.
        let cache = Arc::new(WalletCache::disabled());
        let node = Arc::new(ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn WalletStore> = Arc::new(FsWalletStore::open(dir.path()).unwrap());

        let h = spawn(cache, node, store);
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.shutdown().await;
    }

    #[tokio::test]
    async fn refresher_populates_cache_for_managed_addresses() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let store_fs = FsWalletStore::open(dir.path()).unwrap();
        // Pre-create 2 wallets so list() returns 2 addresses.
        let (_w1, addr1) = store_fs.create().unwrap();
        let (_w2, addr2) = store_fs.create().unwrap();
        let store: Arc<dyn WalletStore> = Arc::new(store_fs);

        // Tip mock: any number of calls.
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"get_block_height"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(tip_body(7, "aa")))
            .mount(&server)
            .await;
        // Per-address mocks.
        for a in [&addr1, &addr2] {
            Mock::given(method("POST"))
                .and(body_partial_json(serde_json::json!({
                    "method":"get_balance",
                    "params":{"address": a}
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(a, 12345)))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(body_partial_json(serde_json::json!({
                    "method":"get_address_utxos",
                    "params":{"address": a}
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(utxo_body(a)))
                .mount(&server)
                .await;
        }

        let cache = make_cache(CacheProfile::Balanced);
        let node = Arc::new(ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap());

        let h = spawn(cache.clone(), node, store);
        // Refresh interval is 1s; wait a bit longer than one tick.
        tokio::time::sleep(Duration::from_millis(1300)).await;
        h.shutdown().await;

        // Both addresses must have balance populated.
        assert_eq!(cache.balance.peek(&addr1).balance, Some(12345));
        assert_eq!(cache.balance.peek(&addr2).balance, Some(12345));
    }

    #[tokio::test]
    async fn refresher_serves_stale_on_upstream_partial_failure() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let store_fs = FsWalletStore::open(dir.path()).unwrap();
        let (_w1, addr_ok) = store_fs.create().unwrap();
        let (_w2, addr_fail) = store_fs.create().unwrap();
        let store: Arc<dyn WalletStore> = Arc::new(store_fs);

        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"get_block_height"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(tip_body(1, "aa")))
            .mount(&server)
            .await;
        // Good address: balance + utxos succeed.
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_balance",
                "params":{"address": addr_ok}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(&addr_ok, 1)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_address_utxos",
                "params":{"address": addr_ok}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(utxo_body(&addr_ok)))
            .mount(&server)
            .await;
        // Bad address: balance fails 5xx (after exhausting retries).
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_balance",
                "params":{"address": addr_fail}
            })))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_address_utxos",
                "params":{"address": addr_fail}
            })))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let cache = make_cache(CacheProfile::Balanced);
        let node = Arc::new(ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap());
        let h = spawn(cache.clone(), node, store);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        h.shutdown().await;

        // Good address populated.
        assert_eq!(cache.balance.peek(&addr_ok).balance, Some(1));
        // Bad address: empty value + last_error populated (partial-failure isolation).
        let peek = cache.balance.peek(&addr_fail);
        assert!(peek.balance.is_none());
        assert!(
            peek.last_error.is_some(),
            "last_error must reflect upstream failure"
        );
    }

    #[tokio::test]
    async fn reorg_detection_invalidates_l2_l3_on_height_drop() {
        let cache = WalletCache::new(CacheProfile::Balanced, None);
        // Seed an entry.
        cache.balance.cas_write("aa".repeat(32).as_str(), 0, 100, 5);
        cache.utxo.cas_write_address(
            "aa".repeat(32).as_str(),
            0,
            crate::upstream::UtxoListResponse {
                address: Some("aa".repeat(32)),
                script_hex: None,
                tip_height: 5,
                truncated: false,
                utxos: vec![],
            },
            5,
        );

        let prev = BlockTip {
            height: 10,
            block_id: "old".into(),
        };
        let new = BlockTip {
            height: 8,
            block_id: "new".into(),
        };

        detect_reorg_and_invalidate(Some(&prev), &new, &cache);

        let addr = "aa".repeat(32);
        assert!(cache.balance.peek(&addr).balance.is_none());
        assert_eq!(cache.balance.peek(&addr).generation, 1);
    }

    #[tokio::test]
    async fn reorg_detection_invalidates_on_shallow_reorg() {
        let cache = WalletCache::new(CacheProfile::Balanced, None);
        let addr = "bb".repeat(32);
        cache.balance.cas_write(&addr, 0, 100, 5);

        let prev = BlockTip {
            height: 10,
            block_id: "A".into(),
        };
        let new = BlockTip {
            height: 10,
            block_id: "B".into(),
        };
        detect_reorg_and_invalidate(Some(&prev), &new, &cache);
        assert!(cache.balance.peek(&addr).balance.is_none());
    }

    #[tokio::test]
    async fn reorg_detection_invalidates_when_fallen_behind() {
        let cache = WalletCache::new(CacheProfile::Balanced, None);
        let addr = "cc".repeat(32);
        cache.balance.cas_write(&addr, 0, 100, 5);

        let prev = BlockTip {
            height: 10,
            block_id: "A".into(),
        };
        let new = BlockTip {
            height: 100,
            block_id: "Z".into(),
        };
        detect_reorg_and_invalidate(Some(&prev), &new, &cache);
        assert!(cache.balance.peek(&addr).balance.is_none());
    }

    #[tokio::test]
    async fn reorg_detection_does_not_invalidate_on_normal_advance() {
        let cache = WalletCache::new(CacheProfile::Balanced, None);
        let addr = "dd".repeat(32);
        cache.balance.cas_write(&addr, 0, 100, 5);

        let prev = BlockTip {
            height: 10,
            block_id: "A".into(),
        };
        let new = BlockTip {
            height: 11,
            block_id: "B".into(),
        };
        detect_reorg_and_invalidate(Some(&prev), &new, &cache);
        assert_eq!(cache.balance.peek(&addr).balance, Some(100));
    }

    #[test]
    fn backoff_grows_then_caps() {
        let base = Duration::from_secs(5);
        assert_eq!(backoff_for_attempt(base, 1), Duration::from_secs(5));
        assert_eq!(backoff_for_attempt(base, 2), Duration::from_secs(10));
        assert_eq!(backoff_for_attempt(base, 3), Duration::from_secs(20));
        assert_eq!(backoff_for_attempt(base, 4), Duration::from_secs(40));
        assert_eq!(backoff_for_attempt(base, 5), MAX_BACKOFF);
        assert_eq!(backoff_for_attempt(base, 100), MAX_BACKOFF);
    }

    #[test]
    fn compare_age_treats_none_as_oldest() {
        let now = Instant::now();
        assert_eq!(compare_age(None, None), Ordering::Equal);
        assert_eq!(compare_age(None, Some(now)), Ordering::Less);
        assert_eq!(compare_age(Some(now), None), Ordering::Greater);
    }
}
