//! Cache integration tests — wiremock-driven scenarios that exercise
//! the end-to-end API surface (`dispatch`) with cache enabled.
//!
//! Mirrors `tests/integration.rs` setup style. New tests added per stage
//! land here. Stage 2 covers: cache-enabled `get_balance` hits cache,
//! address-mismatch rejection, generate_address seeds the cache.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::cache::{CacheProfile, WalletCache};
use exfer_walletd::store::FsWalletStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};

fn p2pkh_out(value: u64, addr_byte: u8) -> TxOutput {
    TxOutput {
        value,
        script: vec![addr_byte; 32],
        datum: None,
        datum_hash: None,
    }
}

fn build_tx_for_test(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
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

fn rpc(method: &str, params: serde_json::Value) -> RpcRequest {
    RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: json!(1),
    }
}

fn make_state(node_url: String, profile: CacheProfile) -> (ApiState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsWalletStore::open(dir.path()).unwrap();
    let node = ExferNode::with_retry_policy(node_url, Duration::from_secs(5), RetryPolicy::none())
        .unwrap();
    let cache = Arc::new(WalletCache::new(profile, None));
    let state = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        cache,
    };
    (state, dir)
}

fn balance_body(addr: &str, balance: u64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "address": addr, "balance": balance }
    })
}

#[tokio::test]
async fn balance_cache_serves_repeat_call_from_cache() {
    let mock = MockServer::start().await;
    let addr = "aa".repeat(32);
    // Only ONE upstream call permitted — repeats must hit cache.
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(&addr, 1_234_567)))
        .up_to_n_times(1)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r1 = dispatch(&state, rpc("get_balance", json!({"address": addr})))
        .await
        .unwrap();
    assert_eq!(r1["balance"], 1_234_567);

    // Second call would 404 if it reached upstream.
    let r2 = dispatch(&state, rpc("get_balance", json!({"address": addr})))
        .await
        .unwrap();
    assert_eq!(r2["balance"], 1_234_567);
}

#[tokio::test]
async fn balance_cache_off_profile_hits_upstream_every_time() {
    let mock = MockServer::start().await;
    let addr = "bb".repeat(32);
    // Exactly two calls expected — cache disabled, no read-side caching.
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(&addr, 1)))
        .expect(2)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Off);

    dispatch(&state, rpc("get_balance", json!({"address": addr.clone()})))
        .await
        .unwrap();
    dispatch(&state, rpc("get_balance", json!({"address": addr})))
        .await
        .unwrap();
    // Drop the mock and assertions run.
}

#[tokio::test]
async fn balance_cache_rejects_upstream_address_mismatch() {
    // LB / sharding-bug simulation: upstream answers a `get_balance` for
    // address A with `{address: B, balance: ...}`. Must be rejected.
    let mock = MockServer::start().await;
    let requested = "aa".repeat(32);
    let returned = "bb".repeat(32);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(&returned, 999)))
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r = dispatch(
        &state,
        rpc("get_balance", json!({"address": requested.clone()})),
    )
    .await;
    assert!(r.is_err(), "address mismatch must surface as RPC error");

    // And the cache must not have been written.
    let peek = state.cache.balance.peek(&requested);
    assert!(
        peek.balance.is_none(),
        "mismatched response must not be cached"
    );
}

#[tokio::test]
async fn generate_address_seeds_balance_cache() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let addr = r["address"].as_str().unwrap().to_string();

    let peek = state.cache.balance.peek(&addr);
    assert_eq!(peek.balance, Some(0), "fresh address must be seeded at 0");
    assert_eq!(peek.tip_at_fetch, 0, "seed must force-stale (tip=0)");
}

#[tokio::test]
async fn on_transfer_commit_invalidates_from_only_for_self_transfer() {
    // Self-transfer must NOT invalidate `to` — that would cause the
    // refresher to refetch a pre-mempool state and dip balance.
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    // Generate one managed address to be both from and to.
    let r = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let addr = r["address"].as_str().unwrap().to_string();

    // Pre-condition: cache has seeded entries (gen=0).
    assert_eq!(state.cache.balance.peek(&addr).generation, 0);

    state.cache.on_transfer_commit(&addr, &addr, &*state.store);

    // Self-transfer: from=to bumps generation exactly once (single key).
    let after = state.cache.balance.peek(&addr);
    assert_eq!(after.generation, 1, "single bump on self-transfer");
    assert!(after.balance.is_none(), "invalidated");
}

#[tokio::test]
async fn on_transfer_commit_invalidates_both_when_to_is_managed() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r_from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let from = r_from["address"].as_str().unwrap().to_string();
    let r_to = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let to = r_to["address"].as_str().unwrap().to_string();
    assert_ne!(from, to);

    state.cache.on_transfer_commit(&from, &to, &*state.store);

    assert_eq!(state.cache.balance.peek(&from).generation, 1);
    assert_eq!(state.cache.balance.peek(&to).generation, 1);
    assert!(state.cache.balance.peek(&from).balance.is_none());
    assert!(state.cache.balance.peek(&to).balance.is_none());
}

#[tokio::test]
async fn on_transfer_commit_invalidates_from_only_when_to_is_external() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r_from = dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();
    let from = r_from["address"].as_str().unwrap().to_string();
    let external_to = "ff".repeat(32);

    state
        .cache
        .on_transfer_commit(&from, &external_to, &*state.store);

    assert_eq!(state.cache.balance.peek(&from).generation, 1);
    // External `to`: never touched the cache, generation remains 0.
    assert_eq!(state.cache.balance.peek(&external_to).generation, 0);
}

#[tokio::test]
async fn tx_cache_amortizes_repeat_get_transaction() {
    // The L5 win: repeat get_transaction on a confirmed tx must hit
    // upstream exactly once. (Note: get_transaction's decode path also
    // fetches each input's parent; we use a coinbase-shaped tx with no
    // inputs to keep this test focused on the L5 self-cache.)
    let mock = MockServer::start().await;
    // Coinbase-style: no inputs, one output.
    let tx = build_tx_for_test(vec![], vec![p2pkh_out(10_000, 0xaa)]);
    let tx_hex = hex::encode(tx.serialize().unwrap());
    let tx_id = hex::encode(tx.tx_id().unwrap().as_bytes());
    let block_hash = "cd".repeat(32);
    let tx_hex_for_resp = tx_hex.clone();
    let tx_id_for_resp = tx_id.clone();
    let block_hash_for_resp = block_hash.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method":"get_transaction",
            "params":{"hash": tx_id}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{
                "tx_id": tx_id_for_resp,
                "tx_hex": tx_hex_for_resp,
                "in_mempool": false,
                "block_hash": block_hash_for_resp,
                "block_height": 100,
            }
        })))
        .up_to_n_times(1)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r1 = dispatch(&state, rpc("get_transaction", json!({"hash": tx_id})))
        .await
        .unwrap();
    assert_eq!(r1["tx_id"], tx_id);

    for _ in 0..2 {
        let r = dispatch(&state, rpc("get_transaction", json!({"hash": tx_id})))
            .await
            .unwrap();
        assert_eq!(r["tx_id"], tx_id);
    }
}

#[tokio::test]
async fn block_cache_amortizes_repeat_by_height() {
    let mock = MockServer::start().await;
    let h = "11".repeat(32);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method":"get_block",
            "params":{"height": 7}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{
                "hash": h, "height":7, "timestamp":1, "tx_count":0,
                "transactions":[], "prev_block_id":"00",
                "difficulty_target":"ff", "nonce":0,
                "state_root":"00", "tx_root":"00"
            }
        })))
        .up_to_n_times(1)
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    for _ in 0..3 {
        let r = dispatch(&state, rpc("get_block", json!({"height": 7})))
            .await
            .unwrap();
        assert_eq!(r["height"], 7);
    }
}

#[tokio::test]
async fn list_balances_returns_envelope_with_addresses() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    // Generate three addresses (each seeded with balance=0 in L2).
    for _ in 0..3 {
        dispatch(&state, rpc("generate_address", json!({})))
            .await
            .unwrap();
    }

    let r = dispatch(&state, rpc("list_balances", json!({})))
        .await
        .unwrap();

    // Envelope shape.
    assert!(r.get("tip").is_some(), "must include tip object");
    assert!(r.get("as_of_ms_ago").is_some(), "must include as_of_ms_ago");
    let rows = r["addresses"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "one row per managed address");

    for row in rows {
        assert!(row["address"].is_string());
        // Seeded balance=0 means balance field is present (Some(0)).
        assert_eq!(row["balance"], 0);
        // L3 UTXO was not seeded → utxo_count is null.
        assert!(row["utxo_count"].is_null());
        // tip_at_fetch=0 on seed → stale must be true.
        assert_eq!(row["stale"], true);
        assert!(row["last_error"].is_null());
    }
}

#[tokio::test]
async fn list_addresses_with_balance_forwards_to_list_balances() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);
    dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    // Bare list_addresses still returns the legacy array shape.
    let legacy = dispatch(&state, rpc("list_addresses", json!({})))
        .await
        .unwrap();
    assert!(legacy["addresses"][0].is_string());

    // Extended shape forwards to list_balances.
    let extended = dispatch(&state, rpc("list_addresses", json!({"with_balance": true})))
        .await
        .unwrap();
    assert!(extended.get("tip").is_some());
    assert!(extended["addresses"][0]["address"].is_string());
}

#[tokio::test]
async fn list_balances_with_cache_off_still_works_but_all_stale() {
    let mock = MockServer::start().await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Off);
    dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    // With cache off, the seed_zero call inside generate_address writes
    // to the cache anyway (cache is constructed; just the refresher
    // doesn't run). Caller gets the row as stale because tip is never
    // primed.
    let r = dispatch(&state, rpc("list_balances", json!({})))
        .await
        .unwrap();
    assert_eq!(r["addresses"].as_array().unwrap().len(), 1);
    assert_eq!(r["addresses"][0]["stale"], true);
}

#[tokio::test]
async fn cache_stats_endpoint_returns_expected_shape() {
    use exfer_walletd::server::{build_app_state_for_tests, build_router};

    let mock = MockServer::start().await;
    let (api, _dir) = make_state(mock.uri(), CacheProfile::Balanced);
    let app_state = build_app_state_for_tests(api, None);
    let app = build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resp = reqwest::get(format!("http://{addr}/cache/stats"))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["profile"], "on");
    // v0.14.0: balanced default is manual mode (refresh_interval=0).
    // 0 is a valid + intentional value, not a "missing config" signal.
    assert!(body["refresh_interval_ms"].as_u64().is_some());
    assert!(body["sizes"]["balance"].is_number());
    assert!(body["sizes"]["tx"].is_number());
}

#[tokio::test]
async fn refresh_address_force_fetches_and_populates_cache() {
    let mock = MockServer::start().await;
    let addr = "ab".repeat(32);
    let block_id = "bb".repeat(32);
    // Tip + balance + utxos — refresh_address force-fetches all three.
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_block_height"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{"height": 100, "block_id": block_id}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{"address": addr, "balance": 7_777_777}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_address_utxos"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{"address": addr, "tip_height":100, "truncated":false, "utxos":[
                {"tx_id":"cc".repeat(32), "output_index":0, "value":7_777_777, "height":50, "is_coinbase":false}
            ]}
        })))
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r = dispatch(
        &state,
        rpc("refresh_address", json!({"address": addr.clone()})),
    )
    .await
    .unwrap();

    // Response shape: { address: <row> } with the freshly-refreshed fields.
    let row = &r["address"];
    assert_eq!(row["address"], addr);
    assert_eq!(row["balance"], 7_777_777);
    assert_eq!(row["utxo_count"], 1);
    assert_eq!(row["stale"], false);
    assert_eq!(row["tip_at_fetch"], 100);
    assert!(row["last_error"].is_null());
}

#[tokio::test]
async fn refresh_addresses_batch_refreshes_only_listed_addrs() {
    let mock = MockServer::start().await;
    let a1 = "11".repeat(32);
    let a2 = "22".repeat(32);
    let block_id = "bb".repeat(32);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_block_height"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"height":50,"block_id":block_id}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method":"get_balance", "params":{"address": a1}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"address": a1, "balance": 100}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({
            "method":"get_balance", "params":{"address": a2}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"address": a2, "balance": 200}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_address_utxos"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "result":{"address": a1, "tip_height":50, "truncated":false, "utxos":[]}
        })))
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    let r = dispatch(
        &state,
        rpc(
            "refresh_addresses",
            json!({"addresses": [a1.clone(), a2.clone()]}),
        ),
    )
    .await
    .unwrap();

    let rows = r["addresses"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let by_addr: std::collections::HashMap<_, _> = rows
        .iter()
        .map(|row| (row["address"].as_str().unwrap().to_string(), row.clone()))
        .collect();
    assert_eq!(by_addr[&a1]["balance"], 100);
    assert_eq!(by_addr[&a2]["balance"], 200);
}

#[tokio::test]
async fn refresh_address_records_last_error_on_upstream_failure() {
    let mock = MockServer::start().await;
    let addr = "33".repeat(32);
    let block_id = "bb".repeat(32);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_block_height"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"height":1,"block_id":block_id}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "error":{"code":-32603,"message":"Rate limit exceeded: max 30/min"}
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_address_utxos"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,
            "error":{"code":-32603,"message":"Rate limit exceeded: max 30/min"}
        })))
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    // refresh_address returns 200 even on per-call failure — the error
    // surfaces in the row's last_error, not as a JSON-RPC error.
    let r = dispatch(
        &state,
        rpc("refresh_address", json!({"address": addr.clone()})),
    )
    .await
    .unwrap();
    let row = &r["address"];
    assert_eq!(row["address"], addr);
    assert!(
        row["balance"].is_null(),
        "no prior cache → balance stays null"
    );
    assert!(
        row["last_error"].as_str().unwrap().contains("Rate limit"),
        "row carries last_error: {:?}",
        row["last_error"]
    );
}

#[tokio::test]
async fn refresher_in_manual_mode_does_not_auto_tick() {
    // Default v0.14.0 balanced profile = refresh_interval 0 → refresher
    // is a no-op. Verify by setting up a mock that 404s every call
    // (would surface as upstream errors in logs if refresher fired)
    // and confirming the cache stays cold for the test window.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0) // ZERO upstream calls expected
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    // Generate an address — this seeds L2 with balance=0 (no upstream).
    dispatch(&state, rpc("generate_address", json!({})))
        .await
        .unwrap();

    // Sit quietly for 2 seconds. If the refresher were firing, it
    // would burn at least one tick and the mock's expect(0) would fail
    // when the wiremock server drops.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // expect(0) is verified on Mock drop.
}

#[tokio::test]
async fn cas_loss_protects_against_silent_clobber() {
    // The §9 trap from the Plan-agent design review: refresher mid-fetch
    // must not overwrite a transfer-commit invalidation. This drives the
    // race directly through the public cache API (the transfer-commit
    // hook lands in stage 3; for now we simulate the invalidation
    // explicitly).
    let mock = MockServer::start().await;
    let addr = "cc".repeat(32);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"get_balance"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(balance_body(&addr, 5_000_000)))
        .mount(&mock)
        .await;
    let (state, _dir) = make_state(mock.uri(), CacheProfile::Balanced);

    // Prime cache.
    dispatch(&state, rpc("get_balance", json!({"address": addr.clone()})))
        .await
        .unwrap();

    // Simulate refresher: it samples the current generation, fetches
    // upstream, but takes a long time…
    let gen_at_sample = state.cache.balance.peek(&addr).generation;

    // …meanwhile, a `transfer` commits and invalidates the entry.
    let new_gen = state.cache.balance.invalidate(&addr);
    assert_eq!(new_gen, gen_at_sample + 1);

    // …refresher's stale write must lose CAS.
    let accepted = state
        .cache
        .balance
        .cas_write(&addr, gen_at_sample, 999_999, 100);
    assert!(!accepted, "stale refresher write must lose CAS");

    // Post-condition: cache is empty (no silent clobber).
    let peek = state.cache.balance.peek(&addr);
    assert!(
        peek.balance.is_none(),
        "invalidation must remain in force after lost-CAS refresher write"
    );
}
