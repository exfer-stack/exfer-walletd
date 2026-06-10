//! Tests for the v1.9.1 indexer delegation:
//! when `--indexer-rpc` is unset, the new proxied methods must
//! return `-32041 IndexerNotConfigured`; when set, they must forward
//! to the configured upstream and return whatever it answered.

use std::sync::Arc;
use std::time::Duration;

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::error::Error;
use exfer_walletd::indexer::IndexerClient;
use exfer_walletd::store::HdSeedStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_state(
    node_url: String,
    indexer: Option<IndexerClient>,
    wallet_dir: tempfile::TempDir,
) -> (ApiState, tempfile::TempDir) {
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
        indexer,
        events: exfer_walletd::sse_client::WalletEvents::new(),
        engine: None,
        allowance: std::sync::Arc::new(
            exfer_walletd::allowance::AllowanceLedger::in_memory(Default::default()).unwrap(),
        ),
    };
    (state, wallet_dir)
}

fn rpc(method_name: &str, params: Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method_name.into(),
        params,
        id: Some(json!(1)),
    }
}

#[tokio::test]
async fn list_settlements_returns_not_configured_without_indexer() {
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), None, tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc("list_settlements", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::IndexerNotConfigured), "got {err:?}");
    assert_eq!(err.rpc_code(), -32041);
}

#[tokio::test]
async fn contract_stats_returns_not_configured_without_indexer() {
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), None, tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc("contract_stats", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::IndexerNotConfigured));
}

#[tokio::test]
async fn get_address_history_returns_not_configured_without_indexer() {
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), None, tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc("get_address_history", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::IndexerNotConfigured));
}

#[tokio::test]
async fn htlc_lookup_by_hashlock_returns_not_configured_without_indexer() {
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), None, tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc(
            "htlc_lookup_by_hashlock",
            json!({ "hash_lock": "33".repeat(32) }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::IndexerNotConfigured));
}

#[tokio::test]
async fn get_output_spent_by_returns_not_configured_without_indexer() {
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), None, tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc(
            "get_output_spent_by",
            json!({ "tx_id": "ee".repeat(32), "output_index": 0 }),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::IndexerNotConfigured));
}

#[tokio::test]
async fn list_settlements_proxies_when_indexer_configured() {
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "list_settlements" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "settlements": [
                    {
                        "tx_id":             "aa".repeat(32),
                        "block_height":      100,
                        "contract_hash":     "bb".repeat(32),
                        "outcome":           "claimed",
                        "observer_address":  "55".repeat(32),
                        "counterparty":      "66".repeat(32),
                        "amount":            1000,
                        "lock_tx_id":        "cc".repeat(32),
                        "lock_output_index": 0,
                    }
                ]
            },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;

    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());

    let v = dispatch(
        &state,
        rpc("list_settlements", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap();
    let arr = v["settlements"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["outcome"].as_str(), Some("claimed"));
    assert_eq!(arr[0]["amount"].as_u64(), Some(1000));
}

#[tokio::test]
async fn contract_stats_proxies_when_indexer_configured() {
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "contract_stats" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "stats": [
                    {
                        "contract_hash":        "bb".repeat(32),
                        "total":                47,
                        "succeeded":            44,
                        "refunded":             3,
                        "avg_settle_blocks":    8,
                        "last_settled_at_height": 12345,
                    }
                ]
            },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;

    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());

    let v = dispatch(
        &state,
        rpc("contract_stats", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap();
    let stats = v["stats"].as_array().unwrap();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0]["total"].as_u64(), Some(47));
    assert_eq!(stats[0]["succeeded"].as_u64(), Some(44));
    assert_eq!(stats[0]["refunded"].as_u64(), Some(3));
}

#[tokio::test]
async fn indexer_rpc_errors_surface_with_original_code() {
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "invalid params from indexer" },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;
    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());

    let err = dispatch(
        &state,
        rpc("list_settlements", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap_err();
    match err {
        Error::UpstreamRpc { code, message } => {
            assert_eq!(code, -32602);
            assert!(message.contains("invalid params from indexer"));
        }
        other => panic!("expected UpstreamRpc, got {other:?}"),
    }
}

#[tokio::test]
async fn indexer_unreachable_surfaces_as_upstream_unreachable() {
    // Build a client pointed at an unbound port → transport error.
    let indexer = IndexerClient::new("http://127.0.0.1:1", None, Duration::from_millis(50))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());
    let err = dispatch(
        &state,
        rpc("list_settlements", json!({ "address": "55".repeat(32) })),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::UpstreamUnreachable(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// HTLC observability delegation (htlc_status / htlc_list)
// ---------------------------------------------------------------------------

use exfer::covenants::htlc::{HtlcParams, HtlcRecord, HtlcRole, HtlcState};

/// Seed one HTLC into walletd's local owned index.
fn seed_local_htlc(state: &ApiState, role: HtlcRole, lock_block_height: Option<u64>) {
    let rec = HtlcRecord {
        lock_tx_id: [0xcc; 32],
        output_index: 0,
        params: HtlcParams {
            sender: [0xaa; 32],
            receiver: [0xbb; 32],
            hash_lock: [0xdd; 32],
            timeout_height: 999,
        },
        amount: 1000,
        lock_block_height,
        state: HtlcState::Locked,
        claim: None,
        reclaim: None,
        role,
        last_indexed_height: 100,
    };
    state.index.upsert_htlc(&rec, [0xaa; 32]).unwrap();
}

#[tokio::test]
async fn htlc_status_prefers_indexer_but_restores_local_role() {
    // Indexer is authoritative for the confirmed lifecycle (claimed @ 500),
    // but reports the global `observer` role. We hold the same outpoint locally
    // as Sender, so the result must carry the indexer's lifecycle AND our role.
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "htlc_status" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "lock_tx_id": "cc".repeat(32),
                "output_index": 0,
                "params": { "sender": "aa".repeat(32), "receiver": "bb".repeat(32),
                            "hash_lock": "dd".repeat(32), "timeout_height": 999 },
                "amount": 1000,
                "lock_block_height": 500,
                "state": "claimed",
                "claim": null, "reclaim": null,
                "role": "observer",
                "last_indexed_height": 510
            },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;

    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());
    seed_local_htlc(&state, HtlcRole::Sender, Some(50));

    let v = dispatch(
        &state,
        rpc(
            "htlc_status",
            json!({ "lock_tx_id": "cc".repeat(32), "output_index": 0 }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        v["state"].as_str(),
        Some("claimed"),
        "lifecycle from indexer"
    );
    assert_eq!(
        v["lock_block_height"].as_u64(),
        Some(500),
        "height from indexer"
    );
    assert_eq!(
        v["role"].as_str(),
        Some("sender"),
        "role restored from local"
    );
}

#[tokio::test]
async fn htlc_status_falls_back_to_local_when_indexer_has_none() {
    // A lock we just broadcast: not on chain yet, so the indexer 404s, but our
    // eager local record (mempool, role Sender) must still surface.
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "htlc_status" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "no indexed HTLC at (cc.., 0)" },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;

    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());
    seed_local_htlc(&state, HtlcRole::Sender, None); // mempool-pending

    let v = dispatch(
        &state,
        rpc(
            "htlc_status",
            json!({ "lock_tx_id": "cc".repeat(32), "output_index": 0 }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(v["role"].as_str(), Some("sender"));
    assert!(v["lock_block_height"].is_null(), "still mempool-pending");
}

#[tokio::test]
async fn htlc_list_with_address_proxies_to_indexer() {
    // An explicit address filter delegates to the indexer's global view.
    let indexer_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "htlc_list" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": { "htlcs": [
                { "lock_tx_id": "ee".repeat(32), "output_index": 0,
                  "params": { "sender": "11".repeat(32), "receiver": "22".repeat(32),
                              "hash_lock": "33".repeat(32), "timeout_height": 10 },
                  "amount": 7, "lock_block_height": 9, "state": "locked",
                  "claim": null, "reclaim": null, "role": "observer", "last_indexed_height": 9 }
            ], "next_cursor": null },
            "id": 1
        })))
        .mount(&indexer_server)
        .await;

    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());

    let v = dispatch(
        &state,
        rpc("htlc_list", json!({ "address": "11".repeat(32) })),
    )
    .await
    .unwrap();
    let arr = v["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["lock_tx_id"].as_str(),
        Some("ee".repeat(32).as_str())
    );
    assert_eq!(arr[0]["amount"].as_u64(), Some(7));
}

#[tokio::test]
async fn htlc_list_without_address_stays_local() {
    // No address → local owned index, even with an indexer configured (the
    // indexer mock is NOT mounted for htlc_list, so a proxy would error).
    let indexer_server = MockServer::start().await;
    let indexer = IndexerClient::new(&indexer_server.uri(), None, Duration::from_secs(5))
        .unwrap()
        .with_retry(1, 0);
    let node = MockServer::start().await;
    let (state, _dir) = make_state(node.uri(), Some(indexer), tempfile::tempdir().unwrap());
    seed_local_htlc(&state, HtlcRole::Sender, Some(50));

    let v = dispatch(&state, rpc("htlc_list", json!({}))).await.unwrap();
    let arr = v["htlcs"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "served from local owned index");
    assert_eq!(arr[0]["role"].as_str(), Some("sender"));
}
