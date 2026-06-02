//! End-to-end test for `wait_for_payment`.
//!
//! Exercises the real pipeline that delivers the "sub-second inbound
//! receipt" capability: a real HTTP node serves the node's `/sse` push
//! shape, a real `SseClient` consumes it onto the real `WalletEvents`
//! bus, and `wait_for_payment` subscribes to that bus and re-queries the
//! node's mempool on each nudge.
//!
//! The node's mempool returns *no* credit for the baseline snapshot and
//! the first post-baseline check, then the watched credit. The follower
//! tip channel is never advanced, so the ONLY thing that can wake
//! `wait_for_payment` past its first empty check is an SSE
//! `script_changed` nudge — a successful return therefore proves the
//! SSE → bus → wait_for_payment wake path, not just polling.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use exfer_walletd::api::{dispatch, ApiState, RpcRequest};
use exfer_walletd::index::Index;
use exfer_walletd::sse_client::{SseClient, WalletEvents};
use exfer_walletd::store::{KeyringStore, WalletStore};
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

// The watched receiving address and the incoming payment.
const RECV_ADDR: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PAY_TXID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PAY_AMOUNT: u64 = 5_000;

#[derive(Clone)]
struct NodeState {
    /// Number of `get_address_mempool` calls served so far. The first two
    /// (baseline + first detect) report no credit; later calls report the
    /// payment, so only a wake-up driven re-check can observe it.
    mempool_calls: Arc<AtomicUsize>,
}

async fn sse_handler() -> Response {
    // Exactly the node's rpc_sse wire shape: one script_changed for the
    // watched address, then EOF. The SseClient reconnects on EOF, so this
    // yields a fresh nudge on every (re)connect.
    let body = format!(
        "event: script_changed\n\
         data: {{\"script\":\"{RECV_ADDR}\"}}\n\
         \n\
         : heartbeat\n\
         \n"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .unwrap()
}

async fn rpc_handler(State(st): State<NodeState>, Json(req): Json<Value>) -> Json<Value> {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(json!(1));
    let address = req
        .get("params")
        .and_then(|p| p.get("address"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let result = match method {
        "get_balance" => json!({ "address": address, "balance": 0 }),
        "get_address_mempool" => {
            let n = st.mempool_calls.fetch_add(1, Ordering::SeqCst) + 1;
            // Calls 1 (baseline) and 2 (first detect) see nothing; the
            // payment only becomes visible from call 3, which requires a
            // nudge to have woken the waiter.
            let mempool = if n >= 3 && address == RECV_ADDR {
                json!([{
                    "tx_id": PAY_TXID,
                    "received": [{ "output_index": 0, "value": PAY_AMOUNT }],
                    "spent": [],
                }])
            } else {
                json!([])
            };
            json!({ "address": address, "tip_height": 100, "mempool": mempool })
        }
        other => json!({ "ok": true, "_unhandled": other }),
    };
    Json(json!({ "jsonrpc": "2.0", "result": result, "id": id }))
}

async fn spin_up_node() -> (String, NodeState) {
    let state = NodeState {
        mempool_calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/sse", get(sse_handler))
        .route("/", post(rpc_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), state)
}

#[tokio::test]
async fn wait_for_payment_returns_on_sse_nudge() {
    let (node_url, _node_state) = spin_up_node().await;

    // Real keyring store with one owned address so the SseClient has
    // something to subscribe to (the mock node ignores the query set and
    // pushes RECV_ADDR regardless).
    let dir = tempfile::tempdir().unwrap();
    let store = KeyringStore::open_keyring(dir.path(), b"test-pass").unwrap();
    let _ = store.create_independent(Some("a".to_string())).unwrap();
    let store: Arc<dyn WalletStore> = Arc::new(store);

    let node = Arc::new(
        ExferNode::with_retry_policy(node_url, Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );

    // Real event bus + real SSE client feeding it from the mock node.
    let events = WalletEvents::new();
    let sse = SseClient::new(store.clone(), node.clone(), events.clone());
    let shutdown = CancellationToken::new();
    let _sse_task = sse.clone().spawn(shutdown.clone());

    // Follower tip channel is never advanced — keep the sender alive so
    // `tip_rx.changed()` blocks rather than erroring. This guarantees the
    // SSE nudge is the only possible wake source.
    let (_tip_tx, tip_rx) = watch::channel(100u64);
    let index = Arc::new(Index::open(dir.path()).unwrap());

    let state = ApiState {
        store,
        node,
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events,
    };

    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "wait_for_payment".to_string(),
        params: json!({ "address": RECV_ADDR, "timeout_secs": 15 }),
        id: Some(json!(1)),
    };

    let started = Instant::now();
    let out = dispatch(&state, req)
        .await
        .expect("wait_for_payment dispatch");
    let elapsed = started.elapsed();

    shutdown.cancel();

    assert_eq!(
        out["received"],
        json!(true),
        "should observe the credit: {out}"
    );
    assert_eq!(out["tx_id"], json!(PAY_TXID), "tx_id mismatch: {out}");
    assert_eq!(out["amount"], json!(PAY_AMOUNT), "amount mismatch: {out}");
    assert_eq!(
        out["confirmations"],
        json!(0),
        "mempool credit is 0-conf: {out}"
    );
    // It returned via an SSE nudge well inside the 15 s budget (the tip
    // channel never ticked, so this is the push path, not polling).
    assert!(
        elapsed < Duration::from_secs(10),
        "took too long: {elapsed:?}"
    );
}
