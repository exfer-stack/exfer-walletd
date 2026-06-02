//! Dispatch-layer tests for `payment_uri_encode` / `payment_uri_decode`.
//!
//! Core codec behaviour lives in unit tests next to `src/payment_uri.rs`.
//! This file just asserts the JSON-RPC wire shape: the methods are
//! registered, accept the documented params, and emit the expected JSON.

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use wiremock::MockServer;

fn make_state(node_url: String, wallet_dir: tempfile::TempDir) -> (ApiState, tempfile::TempDir) {
    let store = HdSeedStore::open_or_init_fresh(wallet_dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::with_retry_policy(node_url, Duration::from_secs(5), RetryPolicy::none())
        .unwrap();
    let index = Arc::new(exfer_walletd::index::Index::open(wallet_dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),    };
    (state, wallet_dir)
}

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: Some(json!(1)),
    }
}

#[tokio::test]
async fn payment_uri_encode_then_decode_round_trips() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let addr = "aa".repeat(32);
    let hash_lock = "bb".repeat(32);

    let enc = dispatch(
        &state,
        rpc(
            "payment_uri_encode",
            json!({
                "address":   addr,
                "amount":    1_000_000_000u64,
                "memo":      "coffee & donuts",
                "hash_lock": hash_lock,
                "timeout":   42_000u64,
                "label":     "Bob",
            }),
        ),
    )
    .await
    .unwrap();
    let uri = enc["uri"].as_str().unwrap().to_string();
    assert!(uri.starts_with(&format!("exfer:{addr}?")));

    let dec = dispatch(&state, rpc("payment_uri_decode", json!({ "uri": uri })))
        .await
        .unwrap();
    assert_eq!(dec["address"].as_str().unwrap(), addr);
    assert_eq!(dec["amount"].as_u64().unwrap(), 1_000_000_000);
    assert_eq!(dec["memo"].as_str().unwrap(), "coffee & donuts");
    assert_eq!(dec["hash_lock"].as_str().unwrap(), hash_lock);
    assert_eq!(dec["timeout"].as_u64().unwrap(), 42_000);
    assert_eq!(dec["label"].as_str().unwrap(), "Bob");
}

#[tokio::test]
async fn payment_uri_encode_address_only_omits_query() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let addr = "cc".repeat(32);
    let enc = dispatch(
        &state,
        rpc("payment_uri_encode", json!({ "address": addr })),
    )
    .await
    .unwrap();
    assert_eq!(enc["uri"].as_str().unwrap(), format!("exfer:{addr}"));
}

#[tokio::test]
async fn payment_uri_encode_rejects_short_address() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("payment_uri_encode", json!({ "address": "deadbeef" })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

#[tokio::test]
async fn payment_uri_encode_rejects_short_hash_lock() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "payment_uri_encode",
            json!({
                "address":   "aa".repeat(32),
                "hash_lock": "short",
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

#[tokio::test]
async fn payment_uri_decode_rejects_wrong_scheme() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("payment_uri_decode", json!({ "uri": "bitcoin:abcd" })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

#[tokio::test]
async fn payment_uri_decode_omits_optional_fields_when_absent() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let addr = "dd".repeat(32);
    let dec = dispatch(
        &state,
        rpc(
            "payment_uri_decode",
            json!({ "uri": format!("exfer:{addr}") }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(dec["address"].as_str().unwrap(), addr);
    assert!(dec.get("amount").is_none());
    assert!(dec.get("memo").is_none());
    assert!(dec.get("hash_lock").is_none());
    assert!(dec.get("timeout").is_none());
    assert!(dec.get("label").is_none());
}

#[tokio::test]
async fn payment_uri_methods_do_not_call_upstream() {
    // The MockServer is up but no endpoints are mounted. If either
    // method ever called get_block_height / get_address_utxos / etc,
    // wiremock would 404 and the response would surface as an error.
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let addr = "ee".repeat(32);
    let _ = dispatch(
        &state,
        rpc(
            "payment_uri_encode",
            json!({ "address": addr, "amount": 1 }),
        ),
    )
    .await
    .unwrap();
    let _ = dispatch(
        &state,
        rpc(
            "payment_uri_decode",
            json!({ "uri": format!("exfer:{addr}?amount=1") }),
        ),
    )
    .await
    .unwrap();
}
