//! Dispatch-layer tests for `wait_for_tx`.
//!
//! Drives the tip-watch channel manually (no real follower task) so
//! tests stay deterministic and fast. The mock node serves a single
//! transaction confirmed at a configurable height, and pushes through
//! the tip channel simulate the follower advancing.

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::index::Index;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use tokio::sync::watch;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Drive-able test fixture.
struct Ctx {
    state: ApiState,
    tip_tx: watch::Sender<u64>,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

fn make_ctx(mock_uri: String, initial_tip: u64) -> Ctx {
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::with_retry_policy(mock_uri, Duration::from_secs(5), RetryPolicy::none())
        .unwrap();
    let index = Arc::new(Index::open(dir.path()).unwrap());
    let (tip_tx, tip_rx) = watch::channel(initial_tip);
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
    };
    Ctx { state, tip_tx, dir }
}

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: Some(json!(1)),
    }
}

/// Mount `get_transaction` to return a confirmed result at the given height.
async fn mount_confirmed(mock: &MockServer, tx_id_hex: &str, block_height: u64) {
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_transaction", "params": {"hash": tx_id_hex} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id": tx_id_hex,
                "tx_hex": "",
                "in_mempool": false,
                "block_hash": "ab".repeat(32),
                "block_height": block_height,
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

/// Mount `get_transaction` to return an unconfirmed result.
async fn mount_unconfirmed(mock: &MockServer, tx_id_hex: &str) {
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_transaction", "params": {"hash": tx_id_hex} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id": tx_id_hex,
                "tx_hex": "",
                "in_mempool": true,
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

/// Mount `get_transaction` to return a node-side "not found" error.
async fn mount_not_found(mock: &MockServer, tx_id_hex: &str) {
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_transaction", "params": {"hash": tx_id_hex} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "transaction not found" },
            "id": 1
        })))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn wait_for_tx_rejects_short_id() {
    let mock = MockServer::start().await;
    let ctx = make_ctx(mock.uri(), 0);
    let err = dispatch(
        &ctx.state,
        rpc("wait_for_tx", json!({ "tx_id": "deadbeef" })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

#[tokio::test]
async fn wait_for_tx_returns_immediately_when_already_confirmed() {
    let mock = MockServer::start().await;
    let tx_id = "aa".repeat(32);
    mount_confirmed(&mock, &tx_id, 100).await;
    // Tip already advanced past the tx's block.
    let ctx = make_ctx(mock.uri(), 100);

    let resp = dispatch(
        &ctx.state,
        rpc("wait_for_tx", json!({ "tx_id": tx_id, "min_confirmations": 1 })),
    )
    .await
    .unwrap();
    assert_eq!(resp["tx_id"].as_str().unwrap(), tx_id);
    assert_eq!(resp["block_height"].as_u64().unwrap(), 100);
    assert_eq!(resp["confirmations"].as_u64().unwrap(), 1);
    assert_eq!(resp["block_id"].as_str().unwrap(), "ab".repeat(32));
}

#[tokio::test]
async fn wait_for_tx_returns_after_tip_advances() {
    let mock = MockServer::start().await;
    let tx_id = "bb".repeat(32);
    mount_confirmed(&mock, &tx_id, 100).await;
    let ctx = make_ctx(mock.uri(), 99);

    // Spawn the wait, then advance the tip.
    let state = ctx.state.clone();
    let tx_id_owned = tx_id.clone();
    let waiter = tokio::spawn(async move {
        dispatch(
            &state,
            rpc("wait_for_tx", json!({ "tx_id": tx_id_owned, "min_confirmations": 1 })),
        )
        .await
    });

    // Give the wait task a moment to fire its first lookup.
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctx.tip_tx.send(100).unwrap();

    let resp = waiter.await.unwrap().unwrap();
    assert_eq!(resp["block_height"].as_u64().unwrap(), 100);
    assert!(resp["confirmations"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn wait_for_tx_requires_min_confirmations_depth() {
    let mock = MockServer::start().await;
    let tx_id = "cc".repeat(32);
    mount_confirmed(&mock, &tx_id, 100).await;
    // Tip at 100 means 1 confirmation. We want 3.
    let ctx = make_ctx(mock.uri(), 100);

    let state = ctx.state.clone();
    let tx_id_owned = tx_id.clone();
    let waiter = tokio::spawn(async move {
        dispatch(
            &state,
            rpc("wait_for_tx", json!({ "tx_id": tx_id_owned, "min_confirmations": 3 })),
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    ctx.tip_tx.send(101).unwrap(); // 2 confs — still not enough
    tokio::time::sleep(Duration::from_millis(30)).await;
    ctx.tip_tx.send(102).unwrap(); // 3 confs — released

    let resp = waiter.await.unwrap().unwrap();
    assert!(
        resp["confirmations"].as_u64().unwrap() >= 3,
        "expected >= 3 confs, got {}",
        resp["confirmations"]
    );
}

#[tokio::test]
async fn wait_for_tx_times_out_when_tx_never_confirms() {
    let mock = MockServer::start().await;
    let tx_id = "dd".repeat(32);
    mount_unconfirmed(&mock, &tx_id).await;
    let ctx = make_ctx(mock.uri(), 100);

    let err = dispatch(
        &ctx.state,
        rpc(
            "wait_for_tx",
            json!({ "tx_id": tx_id, "min_confirmations": 1, "timeout_secs": 1 }),
        ),
    )
    .await
    .unwrap_err();
    match err {
        Error::WaitTimeout {
            tx_id: t,
            min_confirmations,
            elapsed_secs,
        } => {
            assert_eq!(t, "dd".repeat(32));
            assert_eq!(min_confirmations, 1);
            assert_eq!(elapsed_secs, 1);
        }
        other => panic!("expected WaitTimeout, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_tx_treats_not_found_as_pending() {
    let mock = MockServer::start().await;
    let tx_id = "ee".repeat(32);
    mount_not_found(&mock, &tx_id).await;
    let ctx = make_ctx(mock.uri(), 0);

    // Should time out (we never push the tip) rather than erroring on
    // the upstream "not found".
    let err = dispatch(
        &ctx.state,
        rpc(
            "wait_for_tx",
            json!({ "tx_id": tx_id, "timeout_secs": 1 }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::WaitTimeout { .. }), "got {err:?}");
}

#[tokio::test]
async fn wait_for_tx_clamps_oversize_timeout() {
    // Asking for 5_000 seconds is silently capped to
    // WAIT_FOR_TX_MAX_TIMEOUT_SECS (600). We can't easily assert the
    // exact cap without slowing the test out — but we can confirm the
    // request is at least *accepted* (and would have run for ≤600 s).
    // A confirmed tx returns immediately.
    let mock = MockServer::start().await;
    let tx_id = "ff".repeat(32);
    mount_confirmed(&mock, &tx_id, 10).await;
    let ctx = make_ctx(mock.uri(), 10);

    let resp = dispatch(
        &ctx.state,
        rpc(
            "wait_for_tx",
            json!({ "tx_id": tx_id, "timeout_secs": 5_000 }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp["confirmations"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn wait_for_tx_default_values_apply() {
    // No min_confirmations or timeout_secs in the request → defaults
    // (1, 60) kick in. With a confirmed tx and matching tip, returns
    // immediately.
    let mock = MockServer::start().await;
    let tx_id = "11".repeat(32);
    mount_confirmed(&mock, &tx_id, 50).await;
    let ctx = make_ctx(mock.uri(), 50);

    let resp = dispatch(&ctx.state, rpc("wait_for_tx", json!({ "tx_id": tx_id })))
        .await
        .unwrap();
    assert_eq!(resp["confirmations"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn scope_for_wait_for_tx_is_read() {
    use exfer_walletd::auth::Scope;
    assert_eq!(Scope::for_method("wait_for_tx"), Scope::Read);
}
