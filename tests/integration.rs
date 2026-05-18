//! Integration tests for the wrapper's HTTP API + dispatch layer.
//!
//! The upstream Exfer node is mocked with `wiremock`, so these tests
//! exercise every part of the wrapper that doesn't depend on a live chain:
//! HTTP framing, JSON-RPC envelope handling, auth, address generation,
//! passthrough methods. The end-to-end test against a real synced node
//! lives in `tests/e2e.rs`.

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::store::FsWalletStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_state(node_url: String, wallet_dir: tempfile::TempDir) -> (ApiState, tempfile::TempDir) {
    make_state_with_retry(node_url, wallet_dir, RetryPolicy::none())
}

fn make_state_with_retry(
    node_url: String,
    wallet_dir: tempfile::TempDir,
    retry: RetryPolicy,
) -> (ApiState, tempfile::TempDir) {
    let store = FsWalletStore::open(wallet_dir.path()).unwrap();
    let node = ExferNode::with_retry_policy(node_url, Duration::from_secs(5), retry).unwrap();
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
    };
    (state, wallet_dir)
}

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: json!(1),
    }
}

// --- generate_address ------------------------------------------------------

#[tokio::test]
async fn generate_address_creates_64_hex_address_and_persists_file() {
    let mock = MockServer::start().await;
    let (state, dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let result = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    let addr = result["address"].as_str().unwrap();
    let pubkey = result["pubkey"].as_str().unwrap();
    assert_eq!(addr.len(), 64);
    assert_eq!(pubkey.len(), 64);

    let file = dir.path().join(format!("{addr}.key"));
    assert!(file.exists(), "wallet file should be on disk");

    // Loading the wallet back must yield the same address (round-trip).
    let listed = dispatch(&state, rpc("list_addresses", json!({})))
        .await
        .unwrap();
    let addresses = listed["addresses"].as_array().unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].as_str().unwrap(), addr);
}

#[tokio::test]
async fn list_addresses_is_sorted_and_filters_non_keys() {
    let mock = MockServer::start().await;
    let (state, dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // Drop a stray file that should be ignored.
    std::fs::write(dir.path().join("README.md"), "ignored").unwrap();
    std::fs::write(dir.path().join("not-hex.key"), "ignored").unwrap();

    let a = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let b = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();

    let listed = dispatch(&state, rpc("list_addresses", json!({})))
        .await
        .unwrap();
    let addrs: Vec<String> = listed["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let mut expected = vec![a, b];
    expected.sort();
    assert_eq!(addrs, expected);
}

// --- unknown method --------------------------------------------------------

#[tokio::test]
async fn unknown_method_returns_typed_error() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(&state, rpc("nope", json!({}))).await.unwrap_err();
    assert!(matches!(err, Error::UnknownMethod(_)));
    assert_eq!(err.rpc_code(), -32601);
}

// --- passthrough: get_block_height ----------------------------------------

#[tokio::test]
async fn get_block_height_passes_through_to_upstream() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "get_block_height" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "height": 559000, "block_id": "deadbeef" },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(&state, rpc("get_block_height", json!({})))
        .await
        .unwrap();
    assert_eq!(result["height"].as_u64().unwrap(), 559000);
    assert_eq!(result["block_id"].as_str().unwrap(), "deadbeef");
}

// --- passthrough: get_balance ---------------------------------------------

#[tokio::test]
async fn get_balance_passes_through() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "get_balance" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "address": "ff".repeat(32), "balance": 1234567 },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(
        &state,
        rpc("get_balance", json!({ "address": "ff".repeat(32) })),
    )
    .await
    .unwrap();
    assert_eq!(result["balance"].as_u64().unwrap(), 1234567);
}

// --- upstream errors are surfaced typed ----------------------------------

#[tokio::test]
async fn upstream_rpc_error_is_surfaced_with_code() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error":   { "code": -32602, "message": "Block not found" },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let err = dispatch(&state, rpc("get_block_height", json!({})))
        .await
        .unwrap_err();
    match err {
        Error::UpstreamRpc { code, .. } => assert_eq!(code, -32602),
        other => panic!("expected UpstreamRpc, got {other:?}"),
    }
}

// --- transfer: input validation -------------------------------------------

#[tokio::test]
async fn transfer_rejects_short_address() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from":   "deadbeef",   // too short
                "to":     "ff".repeat(32),
                "amount": 1000,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadAddressLen(_)),
        "expected BadAddressLen, got {err:?}",
    );
}

#[tokio::test]
async fn transfer_rejects_missing_wallet() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from":   "ab".repeat(32),  // valid format, no wallet on disk
                "to":     "ff".repeat(32),
                "amount": 1000,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::WalletNotFound(_)), "got {err:?}");
}

// --- ping (health) --------------------------------------------------------

#[tokio::test]
async fn ping_returns_ok() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let result = dispatch(&state, rpc("ping", json!({}))).await.unwrap();
    assert_eq!(result["ok"].as_bool(), Some(true));
}

// --- retry: transient 5xx then success ------------------------------------

#[tokio::test]
async fn retry_recovers_from_transient_5xx() {
    let mock = MockServer::start().await;

    // First two calls fail transport-side; third succeeds.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .expect(2)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "height": 7, "block_id": "abcd" },
            "id": 1
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let retry = RetryPolicy {
        attempts: 4,
        backoff_ms: 0,
    };
    let (state, _dir) = make_state_with_retry(mock.uri(), tempfile::tempdir().unwrap(), retry);
    let result = dispatch(&state, rpc("get_block_height", json!({})))
        .await
        .unwrap();
    assert_eq!(result["height"].as_u64().unwrap(), 7);
}

// --- retry: application errors are NOT retried ----------------------------

#[tokio::test]
async fn application_errors_are_not_retried() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error":   { "code": -32602, "message": "Block not found" },
            "id": 1
        })))
        .expect(1) // exactly one HTTP call despite a generous retry budget
        .mount(&mock)
        .await;

    let retry = RetryPolicy {
        attempts: 5,
        backoff_ms: 0,
    };
    let (state, _dir) = make_state_with_retry(mock.uri(), tempfile::tempdir().unwrap(), retry);
    let err = dispatch(&state, rpc("get_block_height", json!({})))
        .await
        .unwrap_err();
    match err {
        Error::UpstreamRpc { code, .. } => assert_eq!(code, -32602),
        other => panic!("expected UpstreamRpc, got {other:?}"),
    }
}

// --- retry: gives up after exhausting attempts ----------------------------

#[tokio::test]
async fn retries_give_up_and_return_transport_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(503))
        .expect(3)
        .mount(&mock)
        .await;

    let retry = RetryPolicy {
        attempts: 3,
        backoff_ms: 0,
    };
    let (state, _dir) = make_state_with_retry(mock.uri(), tempfile::tempdir().unwrap(), retry);
    let err = dispatch(&state, rpc("get_block_height", json!({})))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::UpstreamUnreachable(_)),
        "expected UpstreamUnreachable, got {err:?}",
    );
}
