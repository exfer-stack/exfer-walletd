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
use exfer_walletd::store::HdSeedStore;
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
    let store = HdSeedStore::open_or_init_fresh(wallet_dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::with_retry_policy(node_url, Duration::from_secs(5), retry).unwrap();
    // Tests don't run a follower; share the wallet_dir for the redb
    // file and create a dead tip_rx (sender dropped → receiver still
    // valid, just never updated).
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
        events: exfer_walletd::sse_client::WalletEvents::new(),
        engine: None,
        allowance: std::sync::Arc::new(
            exfer_walletd::allowance::AllowanceLedger::in_memory(Default::default()).unwrap(),
        ),
    };
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

/// Make the upstream behave like a node that predates the batch query
/// methods: `get_balances` / `get_address_utxos_batch` answer JSON-RPC
/// -32601 so the `_opt` wrappers return `None` and `get_wallet_balance`
/// falls back to the per-address calls these tests mount.
async fn mount_batch_unsupported(mock: &MockServer) {
    for m in ["get_balances", "get_address_utxos_batch"] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({ "method": m })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "error":   { "code": -32601, "message": "method not found" },
                "id": 1
            })))
            .mount(mock)
            .await;
    }
}

// --- generate_address ------------------------------------------------------

#[tokio::test]
async fn generate_address_derives_hd_index_zero_first() {
    let mock = MockServer::start().await;
    let (state, dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let result = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    let addr = result["address"].as_str().unwrap();
    let pubkey = result["pubkey"].as_str().unwrap();
    let index = result["index"].as_u64().unwrap();
    assert_eq!(addr.len(), 64);
    assert_eq!(pubkey.len(), 64);
    assert_eq!(index, 0, "first derived address must be at HD index 0");

    // Keystore state files are present (single sealed seed, no per-addr files).
    assert!(
        dir.path().join("seed.enc").exists(),
        "sealed HD seed should be on disk"
    );
    assert!(
        dir.path().join("state.json").exists(),
        "keystore state file should record next_index"
    );

    // list_addresses surfaces the entry as a structured row.
    let listed = dispatch(&state, rpc("list_addresses", json!({})))
        .await
        .unwrap();
    let entries = listed["addresses"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["address"].as_str().unwrap(), addr);
    assert_eq!(entries[0]["index"].as_u64().unwrap(), 0);
    assert!(!entries[0]["imported"].as_bool().unwrap());
}

#[tokio::test]
async fn list_addresses_returns_rows_in_derivation_order() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let a = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let b = dispatch(
        &state,
        rpc("generate_address", json!({ "label": "user-1" })),
    )
    .await
    .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();

    let listed = dispatch(&state, rpc("list_addresses", json!({})))
        .await
        .unwrap();
    let entries = listed["addresses"].as_array().unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["address"].as_str().unwrap(), a);
    assert_eq!(entries[0]["index"].as_u64().unwrap(), 0);
    assert!(entries[0].get("label").is_none(), "no label on first");
    assert_eq!(entries[1]["address"].as_str().unwrap(), b);
    assert_eq!(entries[1]["index"].as_u64().unwrap(), 1);
    assert_eq!(entries[1]["label"].as_str().unwrap(), "user-1");
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
                "from":    "deadbeef",   // too short
                "outputs": [{"to": "ff".repeat(32), "amount": 1000}],
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
async fn transfer_rejects_empty_outputs() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "transfer",
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
async fn transfer_rejects_too_many_outputs() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let outputs: Vec<serde_json::Value> = (0..17)
        .map(|i| json!({"to": format!("{:02x}", i).repeat(32), "amount": 1000}))
        .collect();
    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from":    "ab".repeat(32),
                "outputs": outputs,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::TooManyOutputs { .. }), "got {err:?}");
    assert_eq!(err.rpc_code(), -32034);
}

#[tokio::test]
async fn transfer_rejects_fee_and_fee_rate_together() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "transfer",
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
async fn transfer_rejects_short_client_token() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc(
            "transfer",
            json!({
                "from":         "ab".repeat(32),
                "outputs":      [{"to": "ff".repeat(32), "amount": 1000}],
                "client_token": "abc",
            }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
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
                "from":    "ab".repeat(32),  // valid format, no wallet derived/imported
                "outputs": [{"to": "ff".repeat(32), "amount": 1000}],
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

    let err = dispatch(&state, rpc("get_transaction", json!({"tx_id": "deadbeef"})))
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

    let err = dispatch(
        &state,
        rpc("get_block_by_id", json!({"block_id": "zz".repeat(32)})),
    )
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
        rpc("get_transaction", json!({ "tx_id": child.tx_id().unwrap().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>() })),
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
        rpc("get_transaction", json!({ "tx_id": child.tx_id().unwrap().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>() })),
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
    let result = dispatch(
        &state,
        rpc("get_block_id_at_height", json!({ "height": 1234 })),
    )
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
    let err = dispatch(&state, rpc("get_block_id_at_height", json!({})))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadParams(_)),
        "expected BadParams, got {err:?}"
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
    let result = dispatch(
        &state,
        rpc("get_transaction", json!({ "tx_id": tx_id_hex })),
    )
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
    let result = dispatch(
        &state,
        rpc("get_transaction", json!({ "tx_id": tx_id_hex })),
    )
    .await
    .unwrap();

    let witness = &result["inputs"][0]["witness"];
    assert!(witness.get("pubkey").is_none());
    assert!(witness.get("signature").is_none());
    assert_eq!(witness["witness_hex"], hex::encode(&weird));
}

// --- validate_address ------------------------------------------------------

#[tokio::test]
async fn validate_address_returns_valid_true_for_64_hex() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(
        &state,
        rpc("validate_address", json!({ "address": "AB".repeat(32) })),
    )
    .await
    .unwrap();
    assert_eq!(result["valid"], true);
    // Normalised to lowercase.
    assert_eq!(result["normalized"].as_str().unwrap(), "ab".repeat(32));
}

#[tokio::test]
async fn validate_address_returns_valid_false_for_garbage() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let result = dispatch(
        &state,
        rpc("validate_address", json!({ "address": "not-a-hash" })),
    )
    .await
    .unwrap();
    assert_eq!(result["valid"], false);
    assert!(result["normalized"].is_null());
}

// --- get_status -----------------------------------------------------------

#[tokio::test]
async fn get_status_reports_version_wallet_count_and_inflight() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_block_height" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "height": 100, "block_id": "ff".repeat(32) },
            "id": 1
        })))
        .mount(&mock)
        .await;

    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    // Mint two addresses.
    dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    let result = dispatch(&state, rpc("get_status", json!({})))
        .await
        .unwrap();
    assert_eq!(
        result["version"].as_str().unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(result["upstream_ok"], true);
    assert_eq!(result["wallet_count"], 2);
    assert_eq!(result["tip"]["height"], 100);
    assert!(!result["upstream_nodes"].as_array().unwrap().is_empty());
    assert_eq!(result["in_flight_utxos"], 0);
    assert_eq!(result["in_flight_transfers"], 0);
}

// --- get_wallet_balance ---------------------------------------------------

#[tokio::test]
async fn get_wallet_balance_aggregates_per_address() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // Two addresses.
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

    // Per-address get_balance + get_address_utxos responses.
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_balance", "params": {"address": a.clone()} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "address": a, "balance": 1_000 },
            "id": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_balance", "params": {"address": b.clone()} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "address": b, "balance": 9_000 },
            "id": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "get_address_utxos" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "tip_height": 1, "truncated": false, "utxos": [] },
            "id": 1
        })))
        .mount(&mock)
        .await;

    mount_batch_unsupported(&mock).await;

    let result = dispatch(&state, rpc("get_wallet_balance", json!({})))
        .await
        .unwrap();
    assert_eq!(result["total"], 10_000);
    assert_eq!(result["entries"].as_array().unwrap().len(), 2);
    // Default includes per-address utxo_count.
    assert!(result["entries"][0].get("utxo_count").is_some());
}

#[tokio::test]
async fn get_wallet_balance_skips_utxos_when_disabled() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    let a = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();

    // Only get_balance is wired up — get_address_utxos is intentionally
    // NOT mounted, so the call would 404 if it were made.
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_balance", "params": {"address": a.clone()} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "address": a, "balance": 4_200 },
            "id": 1
        })))
        .mount(&mock)
        .await;

    mount_batch_unsupported(&mock).await;

    let result = dispatch(&state, rpc("get_wallet_balance", json!({ "utxos": false })))
        .await
        .unwrap();
    assert_eq!(result["total"], 4_200);
    let entry = &result["entries"][0];
    assert_eq!(entry["balance"], 4_200);
    // utxo_count / truncated are omitted when utxos == false.
    assert!(entry.get("utxo_count").is_none());
    assert!(entry.get("truncated").is_none());
}

#[tokio::test]
async fn get_wallet_balance_filters_to_given_addresses() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

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

    // Only address `a` gets a get_balance mock. If the filter leaks and
    // `b` is scanned, the call 404s and the whole request fails.
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({ "method": "get_balance", "params": {"address": a.clone()} }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result":  { "address": a, "balance": 7_000 },
            "id": 1
        })))
        .mount(&mock)
        .await;

    mount_batch_unsupported(&mock).await;

    let result = dispatch(
        &state,
        rpc(
            "get_wallet_balance",
            json!({ "utxos": false, "addresses": [a.clone()] }),
        ),
    )
    .await
    .unwrap();

    // Only `a` is scanned and returned; `b` is excluded entirely.
    let entries = result["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["address"], a);
    assert_eq!(result["total"], 7_000);
    assert!(!entries.iter().any(|e| e["address"] == b));
}

// --- abandon_transfer -----------------------------------------------------

#[tokio::test]
async fn abandon_transfer_releases_in_flight_outpoints() {
    use exfer::types::transaction::OutPoint;
    use exfer::types::Hash256;

    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());

    // Manually claim two outpoints.
    let op1 = OutPoint {
        tx_id: Hash256([0xaa; 32]),
        output_index: 0,
    };
    let op2 = OutPoint {
        tx_id: Hash256([0xbb; 32]),
        output_index: 1,
    };
    state.inflight.claim(&[op1, op2]);
    assert_eq!(state.inflight.len(), 2);

    let result = dispatch(
        &state,
        rpc(
            "abandon_transfer",
            json!({
                "outpoints": [
                    { "tx_id": "aa".repeat(32), "output_index": 0 },
                    { "tx_id": "bb".repeat(32), "output_index": 1 },
                ]
            }),
        ),
    )
    .await
    .unwrap();

    assert_eq!(result["released_count"], 2);
    assert_eq!(result["remaining_in_flight"], 0);
}

#[tokio::test]
async fn abandon_transfer_rejects_empty_outpoints() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), tempfile::tempdir().unwrap());
    let err = dispatch(&state, rpc("abandon_transfer", json!({ "outpoints": [] })))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BadParams(_)), "got {err:?}");
}
