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

use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::cache::{CacheProfile, WalletCache};
use exfer_walletd::store::FsWalletStore;
use exfer_walletd::upstream::{ExferNode, RetryPolicy};

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
