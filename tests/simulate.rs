//! Integration tests for `simulate_transfer` and `simulate_htlc_lock`.
//!
//! These methods are dry-runs: they exercise the same build/sign path
//! as `transfer` and `htlc_lock` but never broadcast and never move
//! funds. The upstream node is mocked with `wiremock` — only the
//! `get_address_utxos` endpoint is consulted (no `send_raw_transaction`
//! call should ever happen during a simulate).

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// Wire up `get_address_utxos` to return one fat UTXO worth `value`
/// confirmed at height 1, so subsequent simulate / transfer calls have
/// something to spend.
async fn mount_utxos(mock: &MockServer, address: &str, tx_id: &str, value: u64) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(
            json!({ "method": "get_address_utxos", "params": {"address": address} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "address": address,
                "tip_height": 1,
                "truncated": false,
                "utxos": [
                    {
                        "tx_id": tx_id,
                        "output_index": 0,
                        "value": value,
                        "height": 1,
                        "is_coinbase": false,
                    }
                ],
            },
            "id": 1
        })))
        .mount(mock)
        .await;
}

// ---------------------------------------------------------------------------
// simulate_transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn simulate_transfer_rejects_empty_outputs() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    "ab".repeat(32),
                "outputs": [],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_transfer_rejects_short_address() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    "deadbeef",
                "outputs": [{"to": "ff".repeat(32), "amount": 1000}],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_transfer_rejects_fee_and_fee_rate_together() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":     "ab".repeat(32),
                "outputs":  [{"to": "ff".repeat(32), "amount": 1000}],
                "fee":      100,
                "fee_rate": 1,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_transfer_rejects_too_many_outputs() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let outputs: Vec<serde_json::Value> = (0..17)
        .map(|i| json!({ "to": format!("{:02x}", i).repeat(32), "amount": 1000 }))
        .collect();
    let err = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    "ab".repeat(32),
                "outputs": outputs,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::TooManyOutputs { .. }), "got {err:?}");
}

#[tokio::test]
async fn simulate_transfer_rejects_unknown_wallet() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    "ab".repeat(32), // well-formed but no wallet derived
                "outputs": [{ "to": "ff".repeat(32), "amount": 1000 }],
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::WalletNotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_transfer_happy_path_returns_built_receipt() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // Derive a wallet so load_signer succeeds.
    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let to = "11".repeat(32);

    let prev_tx_id = "aa".repeat(32);
    mount_utxos(&mock, &from, &prev_tx_id, 1_000_000).await;

    let receipt = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    from,
                "outputs": [{ "to": to, "amount": 200_000 }],
            }),
        ),
    )
    .await
    .unwrap();

    // Field shape — see SimulateTransferReceipt in src/tx/mod.rs.
    assert!(receipt["size"].as_u64().unwrap() > 0);
    assert!(receipt["fee"].as_u64().unwrap() > 0);
    assert!(receipt["fee_rate"].as_u64().unwrap() >= 1);
    assert_eq!(receipt["built_at_height"].as_u64().unwrap(), 1);

    // Exactly one input (the only UTXO we mounted).
    let inputs = receipt["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["tx_id"].as_str().unwrap(), prev_tx_id);
    assert_eq!(inputs[0]["output_index"].as_u64().unwrap(), 0);
    assert_eq!(inputs[0]["value"].as_u64().unwrap(), 1_000_000);

    // Outputs: 1 recipient + 1 change.
    let outputs = receipt["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0]["to"].as_str().unwrap(), to);
    assert_eq!(outputs[0]["amount"].as_u64().unwrap(), 200_000);
    assert!(!outputs[0]["is_change"].as_bool().unwrap());
    assert!(outputs[1]["is_change"].as_bool().unwrap());

    // Conservation: total_in = total_out + fee.
    let total_in = receipt["total_in"].as_u64().unwrap();
    let total_out = receipt["total_out"].as_u64().unwrap();
    let fee = receipt["fee"].as_u64().unwrap();
    let change = receipt["change"].as_u64().unwrap();
    assert_eq!(total_in, 1_000_000);
    assert_eq!(total_in, total_out + fee);
    assert_eq!(change, total_in - 200_000 - fee);
}

#[tokio::test]
async fn simulate_transfer_is_deterministic_across_calls() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let to = "22".repeat(32);
    mount_utxos(&mock, &from, &"bb".repeat(32), 500_000).await;

    let params = json!({
        "from":    from,
        "outputs": [{ "to": to, "amount": 50_000 }],
        "fee_rate": 3,
    });

    let r1 = dispatch(&state, rpc("simulate_transfer", params.clone()))
        .await
        .unwrap();
    let r2 = dispatch(&state, rpc("simulate_transfer", params))
        .await
        .unwrap();
    assert_eq!(r1, r2, "simulate_transfer must be deterministic");
}

#[tokio::test]
async fn simulate_transfer_does_not_broadcast() {
    // If walletd ever called send_raw_transaction, this mock would
    // count the request — and the assert at the end would catch it.
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    mount_utxos(&mock, &from, &"cc".repeat(32), 1_000_000).await;

    // Deliberately do NOT mount send_raw_transaction. If simulate ever
    // tries to broadcast, wiremock's default 404 will surface as an
    // upstream error and the dispatch result would be Err.
    let result = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    from,
                "outputs": [{ "to": "dd".repeat(32), "amount": 100_000 }],
            }),
        ),
    )
    .await;
    assert!(
        result.is_ok(),
        "simulate must not call send_raw_transaction; got {:?}",
        result.err()
    );
}

#[tokio::test]
async fn simulate_transfer_releases_inflight_reservation() {
    // After simulate returns, the inflight set must be empty — the
    // selected UTXOs must be re-usable by subsequent transfers.
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    mount_utxos(&mock, &from, &"ee".repeat(32), 1_000_000).await;

    let _ = dispatch(
        &state,
        rpc(
            "simulate_transfer",
            json!({
                "from":    from,
                "outputs": [{ "to": "ff".repeat(32), "amount": 200_000 }],
            }),
        ),
    )
    .await
    .unwrap();

    assert!(
        state.inflight.is_empty(),
        "simulate_transfer must release its inflight reservation on return"
    );
}

// ---------------------------------------------------------------------------
// simulate_htlc_lock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn simulate_htlc_lock_rejects_short_receiver() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_htlc_lock",
            json!({
                "from":      "ab".repeat(32),
                "receiver":  "deadbeef",
                "hash_lock": "cc".repeat(32),
                "timeout":   1000,
                "amount":    1_000,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_htlc_lock_rejects_short_hash_lock() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_htlc_lock",
            json!({
                "from":      "ab".repeat(32),
                "receiver":  "cc".repeat(32),
                "hash_lock": "shortlock",
                "timeout":   1000,
                "amount":    1_000,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadAddressLen(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_htlc_lock_rejects_fee_and_fee_rate_together() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "simulate_htlc_lock",
            json!({
                "from":      "ab".repeat(32),
                "receiver":  "cc".repeat(32),
                "hash_lock": "dd".repeat(32),
                "timeout":   1000,
                "amount":    1_000,
                "fee":       100,
                "fee_rate":  1,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}

#[tokio::test]
async fn simulate_htlc_lock_happy_path_returns_built_receipt() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let receiver = "11".repeat(32);
    let hash_lock = "22".repeat(32);
    mount_utxos(&mock, &from, &"33".repeat(32), 2_000_000).await;

    let receipt = dispatch(
        &state,
        rpc(
            "simulate_htlc_lock",
            json!({
                "from":      from,
                "receiver":  receiver,
                "hash_lock": hash_lock,
                "timeout":   12345,
                "amount":    500_000,
            }),
        ),
    )
    .await
    .unwrap();

    assert!(receipt["size"].as_u64().unwrap() > 0);
    assert!(receipt["fee"].as_u64().unwrap() > 0);
    assert_eq!(receipt["htlc_output_index"].as_u64().unwrap(), 0);
    assert_eq!(receipt["amount"].as_u64().unwrap(), 500_000);
    assert_eq!(receipt["hash_lock"].as_str().unwrap(), hash_lock);
    assert_eq!(receipt["timeout"].as_u64().unwrap(), 12345);
    assert_eq!(receipt["receiver"].as_str().unwrap(), receiver);
    assert_eq!(receipt["total_in"].as_u64().unwrap(), 2_000_000);

    // change = total_in - amount - fee. Must be >= 0 and consistent.
    let change = receipt["change"].as_u64().unwrap();
    let fee = receipt["fee"].as_u64().unwrap();
    assert_eq!(change, 2_000_000 - 500_000 - fee);
}

#[tokio::test]
async fn simulate_htlc_lock_does_not_broadcast() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    mount_utxos(&mock, &from, &"44".repeat(32), 2_000_000).await;

    // send_raw_transaction not mounted. If simulate broadcasts, error.
    let result = dispatch(
        &state,
        rpc(
            "simulate_htlc_lock",
            json!({
                "from":      from,
                "receiver":  "55".repeat(32),
                "hash_lock": "66".repeat(32),
                "timeout":   9999,
                "amount":    300_000,
            }),
        ),
    )
    .await;
    assert!(result.is_ok(), "simulate_htlc_lock must not broadcast");
}
