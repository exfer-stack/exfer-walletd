//! Integration tests for the wrapper's HTTP API + dispatch layer.
//!
//! The upstream Exfer node is mocked with `wiremock`, so these tests
//! exercise every part of the wrapper that doesn't depend on a live chain:
//! HTTP framing, JSON-RPC envelope handling, auth, address generation,
//! passthrough methods. The end-to-end test against a real synced node
//! lives in `tests/e2e.rs`.

use std::sync::Arc;
use std::time::Duration;

use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::Hash256;
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
        cache: Arc::new(exfer_walletd::cache::WalletCache::disabled()),
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

// --- read-path hex validation ---------------------------------------------
//
// Without wrapper-level validation, walletd would forward garbage like
// `"address": "not_hex"` to the upstream and surface whatever it sent back —
// in the worst case a misleading `balance: 0` for a typo'd address. Reject
// at the boundary so callers can never confuse "wallet empty" with "address
// malformed".

#[tokio::test]
async fn get_balance_rejects_non_hex_address() {
    let mock = MockServer::start().await;
    // Mock must NOT be called — validation should short-circuit.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("get_balance", json!({"address": "not_hex_at_all"})),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadAddressLen(_)),
        "expected BadAddressLen, got {err:?}",
    );
}

#[tokio::test]
async fn get_balance_rejects_64_char_non_hex_address() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // Right length, wrong alphabet — must be caught by the hex-char check.
    let err = dispatch(
        &state,
        rpc("get_balance", json!({"address": "z".repeat(64)})),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadHex(_)),
        "expected BadHex, got {err:?}"
    );
}

#[tokio::test]
async fn get_address_utxos_rejects_bad_address() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("get_address_utxos", json!({"address": "deadbeef"})),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadAddressLen(_)),
        "expected BadAddressLen, got {err:?}",
    );
}

#[tokio::test]
async fn get_transaction_rejects_bad_hash() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(&state, rpc("get_transaction", json!({"hash": "deadbeef"})))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadAddressLen(_)),
        "expected BadAddressLen, got {err:?}",
    );
}

#[tokio::test]
async fn get_block_by_hash_rejects_bad_hash() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(&state, rpc("get_block", json!({"hash": "zz".repeat(32)})))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadHex(_)),
        "expected BadHex, got {err:?}"
    );
}

#[tokio::test]
async fn get_script_utxos_rejects_odd_length_hex() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("get_script_utxos", json!({"script_hex": "abc"})),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadHex(_)),
        "expected BadHex, got {err:?}"
    );
}

#[tokio::test]
async fn send_raw_transaction_rejects_non_hex() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("send_raw_transaction", json!({"tx_hex": "not hex!"})),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::BadHex(_)),
        "expected BadHex, got {err:?}"
    );
}

// --- get_transaction: decoded inputs/outputs/fee --------------------------

/// Build a serialized exfer transaction. Witnesses are filled in (one per
/// input) since the wire format requires it; the decoder under test only
/// reads inputs and outputs.
fn build_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
    let witnesses = inputs
        .iter()
        .map(|_| TxWitness {
            witness: Vec::new(),
            redeemer: None,
        })
        .collect();
    Transaction {
        inputs,
        outputs,
        witnesses,
    }
}

fn p2pkh(value: u64, addr_byte: u8) -> TxOutput {
    TxOutput {
        value,
        script: vec![addr_byte; 32],
        datum: None,
        datum_hash: None,
    }
}

#[tokio::test]
async fn get_transaction_returns_decoded_inputs_outputs_and_fee() {
    // Parent tx: two outputs (10_000 -> 0xaa, 5_000 -> 0xbb).
    let parent = build_tx(
        vec![TxInput {
            prev_tx_id: Hash256([0x00; 32]),
            output_index: 0,
        }],
        vec![p2pkh(10_000, 0xaa), p2pkh(5_000, 0xbb)],
    );
    let parent_hex = hex::encode(parent.serialize().unwrap());
    let parent_id_hex = hex::encode(parent.tx_id().unwrap().as_bytes());

    // Child spends parent[0] (the 10_000 -> 0xaa output) and pays
    // 7_000 -> 0xcc + 2_500 -> 0xaa change. Implicit fee = 500.
    let child = build_tx(
        vec![TxInput {
            prev_tx_id: parent.tx_id().unwrap(),
            output_index: 0,
        }],
        vec![p2pkh(7_000, 0xcc), p2pkh(2_500, 0xaa)],
    );
    let child_hex = hex::encode(child.serialize().unwrap());
    let child_id_hex = hex::encode(child.tx_id().unwrap().as_bytes());

    let mock = MockServer::start().await;

    // Look up child first, then parent (the decoder fetches parents to
    // resolve input addresses + value).
    let child_id_for_match = child_id_hex.clone();
    let child_hex_for_resp = child_hex.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": child_id_for_match }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id":        child_id_hex,
                "tx_hex":       child_hex_for_resp,
                "in_mempool":   false,
                "block_hash":   "0".repeat(64),
                "block_height": 100,
            },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let parent_id_for_match = parent_id_hex.clone();
    let parent_hex_for_resp = parent_hex.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": parent_id_for_match }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id":        parent_id_hex,
                "tx_hex":       parent_hex_for_resp,
                "in_mempool":   false,
                "block_hash":   "1".repeat(64),
                "block_height": 99,
            },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(
        &state,
        rpc("get_transaction", json!({ "hash": child.tx_id().unwrap().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>() })),
    )
    .await
    .unwrap();

    // Pass-through fields are untouched.
    assert_eq!(result["in_mempool"], false);
    assert_eq!(result["block_height"], 100);

    // Outputs are decoded.
    let outs = result["outputs"].as_array().unwrap();
    assert_eq!(outs.len(), 2);
    assert_eq!(outs[0]["address"], "cc".repeat(32));
    assert_eq!(outs[0]["value"], 7_000);
    assert_eq!(outs[1]["address"], "aa".repeat(32));
    assert_eq!(outs[1]["value"], 2_500);

    // Inputs are resolved from the parent fetch.
    let ins = result["inputs"].as_array().unwrap();
    assert_eq!(ins.len(), 1);
    assert_eq!(
        ins[0]["prev_tx_id"],
        parent
            .tx_id()
            .unwrap()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(ins[0]["output_index"], 0);
    assert_eq!(ins[0]["address"], "aa".repeat(32));
    assert_eq!(ins[0]["value"], 10_000);

    // Fee + totals computed.
    assert_eq!(result["total_in"], 10_000);
    assert_eq!(result["total_out"], 9_500);
    assert_eq!(result["fee"], 500);

    // Size = serialized byte count (tx_hex.len() / 2).
    assert_eq!(result["size"], (child_hex.len() / 2) as u64);
}

#[tokio::test]
async fn get_transaction_omits_fee_when_parent_unreachable() {
    // Child references a parent the upstream doesn't know about.
    let unknown_parent = Hash256([0xee; 32]);
    let child = build_tx(
        vec![TxInput {
            prev_tx_id: unknown_parent,
            output_index: 0,
        }],
        vec![p2pkh(3_000, 0xdd)],
    );
    let child_hex = hex::encode(child.serialize().unwrap());
    let child_id_hex = hex::encode(child.tx_id().unwrap().as_bytes());

    let mock = MockServer::start().await;

    let child_id_for_match = child_id_hex.clone();
    let child_hex_for_resp = child_hex.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": child_id_for_match }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id":        child_id_hex,
                "tx_hex":       child_hex_for_resp,
                "in_mempool":   true,
                "block_hash":   null,
                "block_height": null,
            },
            "id": 1
        })))
        .mount(&mock)
        .await;

    // Parent lookup fails (upstream returns -32004 tx not found).
    let unknown_hex = hex::encode(unknown_parent.as_bytes());
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": unknown_hex }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error":   { "code": -32004, "message": "tx not found" },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(
        &state,
        rpc("get_transaction", json!({ "hash": child.tx_id().unwrap().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>() })),
    )
    .await
    .unwrap();

    // Outputs still decoded.
    assert_eq!(result["outputs"][0]["address"], "dd".repeat(32));
    assert_eq!(result["outputs"][0]["value"], 3_000);

    // Input is present as a bare outpoint, address/value null.
    let inp = &result["inputs"][0];
    assert_eq!(inp["output_index"], 0);
    assert!(
        inp.get("address").is_none(),
        "expected no address, got {inp:?}"
    );
    assert!(inp.get("value").is_none());

    // Fee + total_in omitted when any input failed to resolve.
    assert!(result.get("fee").is_none() || result["fee"].is_null());
    assert!(result.get("total_in").is_none() || result["total_in"].is_null());
    assert_eq!(result["total_out"], 3_000);
}

// --- get_block_hash: height -> hash lookup ---------------------------------

#[tokio::test]
async fn get_block_hash_returns_height_and_block_id() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "get_block",
            "params": { "height": 1234 }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "hash":              "ab".repeat(32),
                "height":            1234,
                "timestamp":         1700000000_u64,
                "tx_count":          2,
                "transactions":      ["aa".repeat(32), "bb".repeat(32)],
                "prev_block_id":     "00".repeat(32),
                "difficulty_target": "ff".repeat(32),
                "nonce":             42_u64,
                "state_root":        "11".repeat(32),
                "tx_root":           "22".repeat(32),
            },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(&state, rpc("get_block_hash", json!({ "height": 1234 })))
        .await
        .unwrap();

    assert_eq!(result["height"], 1234);
    assert_eq!(result["block_id"], "ab".repeat(32));
    // Body of the upstream block must NOT leak into the response —
    // get_block_hash returns only the tip-shaped pair.
    assert!(result.get("transactions").is_none());
    assert!(result.get("tx_root").is_none());
}

#[tokio::test]
async fn get_block_hash_rejects_missing_height_param() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let err = dispatch(&state, rpc("get_block_hash", json!({})))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadEnvelope(_)),
        "expected BadEnvelope, got {err:?}"
    );
}

// --- sign_message / verify_message ---------------------------------------

#[tokio::test]
async fn sign_message_then_verify_message_roundtrip() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // 1. Mint a new wallet via the public API.
    let gen = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let address = gen["address"].as_str().unwrap().to_string();

    // 2. Sign.
    let signed = dispatch(
        &state,
        rpc(
            "sign_message",
            json!({ "address": address, "message": "challenge:nonce-1234abcd" }),
        ),
    )
    .await
    .unwrap();
    let signature = signed["signature"].as_str().unwrap().to_string();
    let pubkey = signed["pubkey"].as_str().unwrap().to_string();
    assert_eq!(signed["address"], address);
    assert_eq!(signature.len(), 128, "ed25519 sig hex must be 128 chars");
    assert_eq!(pubkey.len(), 64);

    // 3. Verify — sig + pubkey only (no address check).
    let v = dispatch(
        &state,
        rpc(
            "verify_message",
            json!({
                "pubkey":    pubkey,
                "signature": signature,
                "message":   "challenge:nonce-1234abcd",
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(v["valid"], true);
    assert_eq!(v["address"], address, "computed address must match");

    // 4. Verify with the claimed address — must still succeed.
    let v_with_addr = dispatch(
        &state,
        rpc(
            "verify_message",
            json!({
                "pubkey":    pubkey,
                "signature": signature,
                "message":   "challenge:nonce-1234abcd",
                "address":   address,
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(v_with_addr["valid"], true);

    // 5. Tampered message → invalid.
    let v_bad_msg = dispatch(
        &state,
        rpc(
            "verify_message",
            json!({
                "pubkey":    pubkey,
                "signature": signature,
                "message":   "tampered",
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(v_bad_msg["valid"], false);

    // 6. Wrong claimed address → invalid even though sig is good.
    let v_wrong_addr = dispatch(
        &state,
        rpc(
            "verify_message",
            json!({
                "pubkey":    pubkey,
                "signature": signature,
                "message":   "challenge:nonce-1234abcd",
                "address":   "ff".repeat(32),
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(v_wrong_addr["valid"], false);
    assert_eq!(
        v_wrong_addr["address"], address,
        "still report the real address"
    );
}

#[tokio::test]
async fn sign_message_unknown_address_returns_wallet_not_found() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "sign_message",
            json!({ "address": "ab".repeat(32), "message": "anything" }),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, Error::WalletNotFound(_)),
        "expected WalletNotFound, got {err:?}"
    );
}

#[tokio::test]
async fn witness_decoded_inline_with_pubkey_signature_and_size() {
    // Build a transaction that carries a Phase-1 P2PKH witness:
    // witness.witness = pubkey(32) || signature(64) = 96 bytes.
    // The decoder must surface witness.pubkey + witness.signature
    // verbatim from tx_hex, and derive `address` by hashing the pubkey
    // (no parent fetch needed).
    let pubkey = [0xab_u8; 32];
    let signature = [0xcd_u8; 64];
    let expected_address =
        hex::encode(exfer::types::transaction::TxOutput::pubkey_hash_from_key(&pubkey).as_bytes());

    let mut witness_blob = Vec::with_capacity(96);
    witness_blob.extend_from_slice(&pubkey);
    witness_blob.extend_from_slice(&signature);

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256([0xee; 32]),
            output_index: 0,
        }],
        outputs: vec![p2pkh(1_000, 0xff)],
        witnesses: vec![TxWitness {
            witness: witness_blob,
            redeemer: None,
        }],
    };
    let tx_hex = hex::encode(tx.serialize().unwrap());
    let tx_id_hex = hex::encode(tx.tx_id().unwrap().as_bytes());

    let mock = MockServer::start().await;

    // get_transaction(tx_id) returns the tx itself.
    let id_for_match = tx_id_hex.clone();
    let hex_for_resp = tx_hex.clone();
    let tx_id_resp = tx_id_hex.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": id_for_match }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id":        tx_id_resp,
                "tx_hex":       hex_for_resp,
                "in_mempool":   true,
                "block_hash":   null,
                "block_height": null,
            },
            "id": 1
        })))
        .mount(&mock)
        .await;

    // Parent lookup deliberately fails — we want to prove the address
    // survives WITHOUT a parent fetch (the perf win).
    let parent_hex = hex::encode([0xee_u8; 32]);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method": "get_transaction",
            "params": { "hash": parent_hex }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error":   { "code": -32004, "message": "tx not found" },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(&state, rpc("get_transaction", json!({ "hash": tx_id_hex })))
        .await
        .unwrap();

    let inp = &result["inputs"][0];

    // Witness fields surfaced verbatim from tx_hex.
    let witness = &inp["witness"];
    assert_eq!(witness["pubkey"], hex::encode(pubkey));
    assert_eq!(witness["signature"], hex::encode(signature));
    assert!(witness.get("witness_hex").is_none());

    // Address derived from witness pubkey — even though the parent
    // fetch returned -32004. This is the perf-survives-degradation
    // guarantee.
    assert_eq!(inp["address"], expected_address);

    // Value still missing (parent unreachable), so fee + total_in too.
    assert!(inp.get("value").is_none() || inp["value"].is_null());
    assert!(result.get("fee").is_none() || result["fee"].is_null());

    // Size is always populated.
    assert_eq!(result["size"], (tx_hex.len() / 2) as u64);
}

#[tokio::test]
async fn non_phase1_witness_falls_back_to_witness_hex() {
    // Some weird future witness blob that isn't 96 bytes — surface as
    // raw `witness_hex` instead of guessing at pubkey/signature.
    let weird = vec![0x77u8; 10];
    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256([0x00; 32]),
            output_index: 0,
        }],
        outputs: vec![p2pkh(500, 0xee)],
        witnesses: vec![TxWitness {
            witness: weird.clone(),
            redeemer: None,
        }],
    };
    let tx_hex = hex::encode(tx.serialize().unwrap());
    let tx_id_hex = hex::encode(tx.tx_id().unwrap().as_bytes());

    let mock = MockServer::start().await;
    let id_for_match = tx_id_hex.clone();
    let hex_for_resp = tx_hex.clone();
    let tx_id_resp = tx_id_hex.clone();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tx_id":        tx_id_resp,
                "tx_hex":       hex_for_resp,
                "in_mempool":   true,
                "block_hash":   null,
                "block_height": null,
            },
            "id": 1
        })))
        .mount(&mock)
        .await;
    // Parent fetch will hit the same catch-all mock and return our
    // tx pretending to be its own parent — that's fine, we only care
    // about the witness path here. The mismatched parent_id check
    // would normally matter but Phase-1 witness handling doesn't
    // depend on it.
    let _ = id_for_match;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(&state, rpc("get_transaction", json!({ "hash": tx_id_hex })))
        .await
        .unwrap();

    let witness = &result["inputs"][0]["witness"];
    assert!(witness.get("pubkey").is_none());
    assert!(witness.get("signature").is_none());
    assert_eq!(witness["witness_hex"], hex::encode(&weird));
}
