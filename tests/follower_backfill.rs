//! Initial-backfill fast-forward tests for the block follower.
//!
//! The follower indexes only owned-key HTLCs and the wallet records its own
//! sends eagerly at lock time, so re-walking ancient history on a fresh/reset
//! index is wasted work that can leave the follower hundreds of thousands of
//! blocks behind the chain. `FollowerConfig.backfill_lookback` bounds the
//! first catch-up to `tip - lookback`. These tests drive a mock node that
//! records the LOWEST block height it was ever asked for, proving ancient
//! blocks are skipped on a fresh index but never on an already-caught-up one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::follower::{Follower, FollowerConfig};
use exfer_walletd::index::{FollowerMeta, Index};
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Deterministic block id for a height (so reorg detection is stable).
fn block_hash(h: u64) -> String {
    format!("{h:064x}")
}

/// Custom `get_block` responder: returns a valid empty `BlockSummary` for
/// whatever height is requested, while recording the minimum height seen.
struct BlockResponder(Arc<AtomicU64>);

impl Respond for BlockResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let h = body["params"]["height"].as_u64().unwrap_or(0);
        self.0.fetch_min(h, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "hash": block_hash(h),
                "height": h,
                "timestamp": 0,
                "tx_count": 0,
                "transactions": [],
                "prev_block_id": block_hash(h.saturating_sub(1)),
                "difficulty_target": "00",
                "nonce": 0,
                "state_root": "00".repeat(32),
                "tx_root": "00".repeat(32),
            },
            "id": 1
        }))
    }
}

async fn mount_node(mock: &MockServer, tip: u64, min_seen: Arc<AtomicU64>) {
    // get_block_height → tip
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_block_height" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": { "height": tip, "block_id": block_hash(tip), "genesis_block_id": block_hash(0) },
            "id": 1
        })))
        .mount(mock)
        .await;
    // get_block (by height) → empty block, records min height seen
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_block" })))
        .respond_with(BlockResponder(min_seen))
        .mount(mock)
        .await;
}

fn make_follower(mock_uri: String) -> (Arc<Follower>, Arc<Index>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap());
    let node = Arc::new(
        ExferNode::with_retry_policy(mock_uri, Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let cfg = FollowerConfig {
        backfill_lookback: Some(10),
        ..Default::default()
    };
    let (follower, _rx) = Follower::new(store, node, index.clone(), cfg);
    (follower, index, dir)
}

#[tokio::test]
async fn fresh_index_fast_forwards_past_ancient_blocks() {
    let mock = MockServer::start().await;
    let min_seen = Arc::new(AtomicU64::new(u64::MAX));
    mount_node(&mock, 100, min_seen.clone()).await;

    let (follower, index, _dir) = make_follower(mock.uri());
    // Fresh index (last_indexed_height == 0). lookback = 10, tip = 100.
    follower.tick().await.unwrap();

    let meta = index.follower_meta().unwrap();
    // Walked all the way to the tip in one tick…
    assert_eq!(meta.last_indexed_height, 100);
    assert!(meta.full_scan_complete);
    // …but never touched a block below the anchor (tip - lookback - 1 = 89).
    // If it had crawled from genesis, min_seen would be 0.
    assert_eq!(
        min_seen.load(Ordering::SeqCst),
        89,
        "follower fetched a block below the lookback anchor — ancient history was NOT skipped"
    );
}

#[tokio::test]
async fn caught_up_index_does_not_skip_a_real_gap() {
    let mock = MockServer::start().await;
    let min_seen = Arc::new(AtomicU64::new(u64::MAX));
    mount_node(&mock, 100, min_seen.clone()).await;

    let (follower, index, _dir) = make_follower(mock.uri());
    // Pre-seed a meta that HAS caught up before, now 50 blocks behind tip.
    let mut h50 = [0u8; 32];
    h50.copy_from_slice(&hex::decode(block_hash(50)).unwrap());
    index
        .save_follower_meta(&FollowerMeta {
            last_indexed_height: 50,
            last_indexed_block_id: h50,
            full_scan_complete: true,
            started_at: 1,
        })
        .unwrap();

    follower.tick().await.unwrap();

    let meta = index.follower_meta().unwrap();
    assert_eq!(meta.last_indexed_height, 100);
    // A caught-up follower must index the real gap (51..=100), NOT fast-forward
    // to tip-lookback. The reorg check touches 50; the walk starts at 51.
    assert!(
        min_seen.load(Ordering::SeqCst) <= 51,
        "caught-up follower skipped real blocks (min_seen={})",
        min_seen.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn tip_only_mode_tracks_tip_without_indexing() {
    // With an indexer configured the follower runs tip-only: it advances the
    // meta to the tip (so wait_for_tx/get_follower_status work) but indexes NO
    // HTLCs — it must never even fetch a block.
    let mock = MockServer::start().await;
    let min_seen = Arc::new(AtomicU64::new(u64::MAX));
    mount_node(&mock, 100, min_seen.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap());
    let node = Arc::new(
        ExferNode::with_retry_policy(mock.uri(), Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let cfg = FollowerConfig {
        tip_only: true,
        ..Default::default()
    };
    let (follower, rx) = Follower::new(store, node, index.clone(), cfg);

    follower.tick_tip_only().await.unwrap();

    let meta = index.follower_meta().unwrap();
    assert_eq!(meta.last_indexed_height, 100, "tip tracked");
    assert!(meta.full_scan_complete, "reports caught-up, not 'behind'");
    assert_eq!(*rx.borrow(), 100, "tip_rx nudged (wait_for_tx wakes)");
    assert_eq!(
        min_seen.load(Ordering::SeqCst),
        u64::MAX,
        "tip-only must NOT fetch any block"
    );
    assert_eq!(index.count().unwrap(), 0, "no HTLCs indexed locally");
}
