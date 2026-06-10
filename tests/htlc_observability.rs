//! Dispatch-layer tests for the v1.9 HTLC observability methods:
//! `htlc_status`, `htlc_list`, `htlc_forget`, `get_follower_status`.
//!
//! These exercise the handler shape independently of the block
//! follower. Test data is inserted directly into the redb index;
//! the follower's end-to-end behaviour is covered separately by the
//! smoke script that runs against a live node.

use std::sync::Arc;
use std::time::Duration;

use exfer::covenants::htlc::{HtlcClaimRecord, HtlcParams, HtlcRecord, HtlcRole, HtlcState};
use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::index::Index;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Ctx {
    state: ApiState,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    index: Arc<Index>,
}

fn make_ctx(mock_uri: String) -> Ctx {
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::with_retry_policy(mock_uri, Duration::from_secs(5), RetryPolicy::none())
        .unwrap();
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index: index.clone(),
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),
        engine: None,
        allowance: std::sync::Arc::new(
            exfer_walletd::allowance::AllowanceLedger::in_memory(Default::default()).unwrap(),
        ),
    };
    Ctx { state, dir, index }
}

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: Some(json!(1)),
    }
}

fn make_record(
    lock_tx_id: [u8; 32],
    output_index: u32,
    height: u64,
    state: HtlcState,
    role: HtlcRole,
) -> HtlcRecord {
    HtlcRecord {
        lock_tx_id,
        output_index,
        params: HtlcParams {
            sender: [0x11; 32],
            receiver: [0x22; 32],
            hash_lock: [0x33; 32],
            timeout_height: 1000,
        },
        amount: 5_000,
        lock_block_height: Some(height),
        state,
        claim: None,
        reclaim: None,
        role,
        last_indexed_height: height,
    }
}

// ---------------------------------------------------------------------------
// htlc_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn htlc_status_returns_record_when_present() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let mut rec = make_record([0xAA; 32], 0, 50, HtlcState::Locked, HtlcRole::Sender);
    rec.amount = 12_345;
    ctx.index.upsert_htlc(&rec, [0x11; 32]).unwrap();

    let lock_tx_id_hex = hex::encode([0xAA; 32]);
    let resp = dispatch(
        &ctx.state,
        rpc(
            "htlc_status",
            json!({ "lock_tx_id": lock_tx_id_hex, "output_index": 0 }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp["state"].as_str().unwrap(), "locked");
    assert_eq!(resp["role"].as_str().unwrap(), "sender");
    assert_eq!(resp["amount"].as_u64().unwrap(), 12_345);
    assert_eq!(resp["lock_block_height"].as_u64().unwrap(), 50);
    assert_eq!(resp["output_index"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn htlc_status_returns_error_when_absent() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let err = dispatch(
        &ctx.state,
        rpc(
            "htlc_status",
            json!({ "lock_tx_id": "aa".repeat(32), "output_index": 0 }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Wallet(_)), "got {err:?}");
}

#[tokio::test]
async fn htlc_status_rejects_short_id() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let err = dispatch(
        &ctx.state,
        rpc("htlc_status", json!({ "lock_tx_id": "dead" })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// htlc_list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn htlc_list_empty_index_returns_no_records() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let resp = dispatch(&ctx.state, rpc("htlc_list", json!({})))
        .await
        .unwrap();
    assert_eq!(resp["htlcs"].as_array().unwrap().len(), 0);
    assert!(resp.get("next_cursor").is_none());
}

#[tokio::test]
async fn htlc_list_returns_sorted_records() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    for h in [100, 50, 200] {
        let mut tx_id = [0u8; 32];
        tx_id[0] = h as u8;
        let rec = make_record(tx_id, 0, h, HtlcState::Locked, HtlcRole::Sender);
        ctx.index.upsert_htlc(&rec, [0x11; 32]).unwrap();
    }

    let resp = dispatch(&ctx.state, rpc("htlc_list", json!({})))
        .await
        .unwrap();
    let arr = resp["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 3);
    let heights: Vec<u64> = arr
        .iter()
        .map(|r| r["lock_block_height"].as_u64().unwrap())
        .collect();
    assert_eq!(heights, vec![50, 100, 200]);
}

#[tokio::test]
async fn htlc_list_filters_by_single_state() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let mut a = make_record([0x01; 32], 0, 10, HtlcState::Locked, HtlcRole::Sender);
    let mut b = make_record([0x02; 32], 0, 20, HtlcState::Claimed, HtlcRole::Receiver);
    let _ = &mut a;
    let _ = &mut b;
    ctx.index.upsert_htlc(&a, [0x11; 32]).unwrap();
    ctx.index.upsert_htlc(&b, [0x22; 32]).unwrap();

    let resp = dispatch(&ctx.state, rpc("htlc_list", json!({ "state": "claimed" })))
        .await
        .unwrap();
    let arr = resp["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["state"].as_str().unwrap(), "claimed");
}

#[tokio::test]
async fn htlc_list_filters_by_multiple_states() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    ctx.index
        .upsert_htlc(
            &make_record([0x01; 32], 0, 10, HtlcState::Locked, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();
    ctx.index
        .upsert_htlc(
            &make_record([0x02; 32], 0, 20, HtlcState::Claimed, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();
    ctx.index
        .upsert_htlc(
            &make_record([0x03; 32], 0, 30, HtlcState::Reclaimed, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();

    let resp = dispatch(
        &ctx.state,
        rpc("htlc_list", json!({ "state": ["claimed", "reclaimed"] })),
    )
    .await
    .unwrap();
    let arr = resp["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
}

#[tokio::test]
async fn htlc_list_filters_by_role() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    ctx.index
        .upsert_htlc(
            &make_record([0x01; 32], 0, 10, HtlcState::Locked, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();
    ctx.index
        .upsert_htlc(
            &make_record([0x02; 32], 0, 20, HtlcState::Locked, HtlcRole::Receiver),
            [0x22; 32],
        )
        .unwrap();

    let resp = dispatch(&ctx.state, rpc("htlc_list", json!({ "role": "receiver" })))
        .await
        .unwrap();
    let arr = resp["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["role"].as_str().unwrap(), "receiver");
}

#[tokio::test]
async fn htlc_list_pagination_advances_cursor() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    for h in [10, 20, 30, 40, 50] {
        let mut tx_id = [0u8; 32];
        tx_id[0] = h as u8;
        ctx.index
            .upsert_htlc(
                &make_record(tx_id, 0, h, HtlcState::Locked, HtlcRole::Sender),
                [0x11; 32],
            )
            .unwrap();
    }

    let page1 = dispatch(&ctx.state, rpc("htlc_list", json!({ "limit": 2 })))
        .await
        .unwrap();
    let arr1 = page1["htlcs"].as_array().unwrap();
    assert_eq!(arr1.len(), 2);
    assert_eq!(arr1[0]["lock_block_height"], 10);
    assert_eq!(arr1[1]["lock_block_height"], 20);
    let cur = page1["next_cursor"].as_str().unwrap().to_string();

    let page2 = dispatch(
        &ctx.state,
        rpc("htlc_list", json!({ "limit": 2, "cursor": cur })),
    )
    .await
    .unwrap();
    let arr2 = page2["htlcs"].as_array().unwrap();
    assert_eq!(arr2.len(), 2);
    assert_eq!(arr2[0]["lock_block_height"], 30);
    assert_eq!(arr2[1]["lock_block_height"], 40);
    let cur2 = page2["next_cursor"].as_str().unwrap().to_string();

    let page3 = dispatch(
        &ctx.state,
        rpc("htlc_list", json!({ "limit": 2, "cursor": cur2 })),
    )
    .await
    .unwrap();
    let arr3 = page3["htlcs"].as_array().unwrap();
    assert_eq!(arr3.len(), 1);
    assert_eq!(arr3[0]["lock_block_height"], 50);
    assert!(
        page3.get("next_cursor").is_none(),
        "final page must not advertise more"
    );
}

#[tokio::test]
async fn htlc_list_clamps_limit_to_max() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    // Asking for 5000 returns the same as asking for HTLC_LIST_MAX_LIMIT (1000).
    let resp = dispatch(&ctx.state, rpc("htlc_list", json!({ "limit": 5000 })))
        .await
        .unwrap();
    // Empty index ⇒ empty result; success here just proves the
    // method didn't fail-fast on the oversize limit.
    assert_eq!(resp["htlcs"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn htlc_list_rejects_garbage_cursor() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let err = dispatch(
        &ctx.state,
        rpc("htlc_list", json!({ "cursor": "!!!not-valid-base64!!!" })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// htlc_forget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn htlc_forget_removes_settled_record() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let mut rec = make_record([0xDD; 32], 1, 100, HtlcState::Claimed, HtlcRole::Receiver);
    rec.claim = Some(HtlcClaimRecord {
        tx_id: [0xEE; 32],
        preimage: [0x99; 32].to_vec(),
        block_height: 101,
        input_index: 0,
    });
    ctx.index.upsert_htlc(&rec, [0x22; 32]).unwrap();

    let resp = dispatch(
        &ctx.state,
        rpc(
            "htlc_forget",
            json!({ "lock_tx_id": hex::encode([0xDD; 32]), "output_index": 1 }),
        ),
    )
    .await
    .unwrap();
    assert!(resp["removed"].as_bool().unwrap());
    // The record is actually gone.
    assert!(ctx.index.get_htlc(&[0xDD; 32], 1).unwrap().is_none());
}

#[tokio::test]
async fn htlc_forget_refuses_locked_record() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    ctx.index
        .upsert_htlc(
            &make_record([0xCC; 32], 0, 50, HtlcState::Locked, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();
    let err = dispatch(
        &ctx.state,
        rpc(
            "htlc_forget",
            json!({ "lock_tx_id": hex::encode([0xCC; 32]) }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
    // Still present — refused, not removed.
    assert!(ctx.index.get_htlc(&[0xCC; 32], 0).unwrap().is_some());
}

#[tokio::test]
async fn htlc_forget_returns_false_for_unknown() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri());

    let resp = dispatch(
        &ctx.state,
        rpc(
            "htlc_forget",
            json!({ "lock_tx_id": hex::encode([0xAB; 32]) }),
        ),
    )
    .await
    .unwrap();
    assert!(!resp["removed"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// get_follower_status
// ---------------------------------------------------------------------------

async fn mount_tip(mock: &MockServer, tip_height: u64) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_block_height" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  {
                "height": tip_height,
                "block_id": "ff".repeat(32),
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn get_follower_status_empty_index() {
    let mock = MockServer::start().await;
    mount_tip(&mock, 0).await;
    let ctx = make_ctx(mock.uri());

    let resp = dispatch(&ctx.state, rpc("get_follower_status", json!({})))
        .await
        .unwrap();
    assert_eq!(resp["last_indexed_height"].as_u64().unwrap(), 0);
    assert_eq!(resp["tip_height"].as_u64().unwrap(), 0);
    assert_eq!(resp["lag"].as_i64().unwrap(), 0);
    assert_eq!(resp["indexed_htlc_count"].as_u64().unwrap(), 0);
    assert!(!resp["full_scan_complete"].as_bool().unwrap());
}

#[tokio::test]
async fn get_follower_status_reports_lag() {
    let mock = MockServer::start().await;
    mount_tip(&mock, 1_000).await;
    let ctx = make_ctx(mock.uri());

    // Pretend the follower advanced to height 750.
    let meta = exfer_walletd::index::FollowerMeta {
        last_indexed_height: 750,
        last_indexed_block_id: [0xAB; 32],
        full_scan_complete: false,
        started_at: 1_700_000_000,
    };
    ctx.index.save_follower_meta(&meta).unwrap();

    // Insert a record so indexed_htlc_count > 0.
    ctx.index
        .upsert_htlc(
            &make_record([0x01; 32], 0, 700, HtlcState::Locked, HtlcRole::Sender),
            [0x11; 32],
        )
        .unwrap();

    let resp = dispatch(&ctx.state, rpc("get_follower_status", json!({})))
        .await
        .unwrap();
    assert_eq!(resp["last_indexed_height"].as_u64().unwrap(), 750);
    assert_eq!(resp["tip_height"].as_u64().unwrap(), 1_000);
    assert_eq!(resp["lag"].as_i64().unwrap(), 250);
    assert_eq!(resp["indexed_htlc_count"].as_u64().unwrap(), 1);
    assert_eq!(resp["follower_started_at"].as_u64().unwrap(), 1_700_000_000);
    assert!(!resp["full_scan_complete"].as_bool().unwrap());
    assert_eq!(
        resp["last_indexed_block_id"].as_str().unwrap(),
        "ab".repeat(32)
    );
}

#[tokio::test]
async fn get_follower_status_full_scan_done_reports_true() {
    let mock = MockServer::start().await;
    mount_tip(&mock, 500).await;
    let ctx = make_ctx(mock.uri());

    let meta = exfer_walletd::index::FollowerMeta {
        last_indexed_height: 500,
        last_indexed_block_id: [0xCD; 32],
        full_scan_complete: true,
        started_at: 1_700_000_000,
    };
    ctx.index.save_follower_meta(&meta).unwrap();

    let resp = dispatch(&ctx.state, rpc("get_follower_status", json!({})))
        .await
        .unwrap();
    assert_eq!(resp["lag"].as_i64().unwrap(), 0);
    assert!(resp["full_scan_complete"].as_bool().unwrap());
}

#[tokio::test]
async fn scope_mapping_for_new_methods() {
    use exfer_walletd::auth::Scope;
    assert_eq!(Scope::for_method("htlc_status"), Scope::Read);
    assert_eq!(Scope::for_method("htlc_list"), Scope::Read);
    assert_eq!(Scope::for_method("get_follower_status"), Scope::Read);
    assert_eq!(Scope::for_method("htlc_forget"), Scope::Manage);
}
