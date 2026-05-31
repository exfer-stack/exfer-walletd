//! End-to-end Phase 2 SSE client test: real HTTP server (no mock) emits
//! SSE-format events on a port; SseClient connects, parses them, and
//! forwards onto WalletEvents. Asserts every event variant survives
//! round-trip from the wire to the in-process broadcast channel.
//!
//! Covers the full nudge path that the Tauri supervisors then bridge
//! to "wallet-nudge" frontend events.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use exfer_walletd::sse_client::{SseClient, WalletEvents, WalletNudge};
use exfer_walletd::store::{KeyringStore, WalletStore};
use exfer_walletd::upstream::{ExferNode, RetryPolicy};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

async fn spin_up_test_node() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/sse",
        get(|| async {
            // Emit exactly the same shape the real node's rpc_sse does,
            // covering all three event variants the walletd client must
            // parse: script_changed, tip, resync.
            let body = "event: script_changed\n\
                        data: {\"script\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n\
                        \n\
                        event: tip\n\
                        data: {\"height\":12345}\n\
                        \n\
                        event: resync\n\
                        data: {}\n\
                        \n\
                        : heartbeat\n\
                        \n";
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from(body))
                .unwrap()
        }),
    );
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), join)
}

#[tokio::test]
async fn sse_client_forwards_all_event_variants_to_wallet_events() {
    // Stand up a test node that serves one canonical SSE payload covering
    // every event variant, then close the stream.
    let (node_url, _server) = spin_up_test_node().await;

    // Build a real walletd store containing one address so the
    // SseClient has something to subscribe to. KeyringStore::open_keyring
    // creates a fresh seedless keyring; address generation goes via
    // generate_address.
    let datadir = tempfile::tempdir().unwrap();
    let store = KeyringStore::open_keyring(datadir.path(), b"test-pass").unwrap();
    let _ = store.create_independent(Some("a".to_string())).unwrap();
    let store: Arc<dyn WalletStore> = Arc::new(store);

    let node = Arc::new(
        ExferNode::with_retry_policy(node_url, Duration::from_secs(5), RetryPolicy::none())
            .unwrap(),
    );
    let events = WalletEvents::new();
    let client = SseClient::new(store, node, events.clone());

    let mut rx = events.subscribe();
    let shutdown = CancellationToken::new();
    let _task = client.spawn(shutdown.clone());

    // Collect events with a short overall timeout. The order is
    // script_changed -> tip -> resync. We assert presence rather than
    // strict ordering so a heartbeat or extra script_changed doesn't
    // flake the test.
    let mut saw_script = false;
    let mut saw_tip = false;
    let mut saw_resync = false;
    let deadline = timeout(Duration::from_secs(10), async {
        while !(saw_script && saw_tip && saw_resync) {
            match rx.recv().await {
                Ok(WalletNudge::Script(s)) => {
                    assert_eq!(s, vec![0xaa; 32], "script bytes round-trip mismatch");
                    saw_script = true;
                }
                Ok(WalletNudge::Tip(h)) => {
                    assert_eq!(h, 12345, "tip height round-trip mismatch");
                    saw_tip = true;
                }
                Ok(WalletNudge::Resync) => saw_resync = true,
                Err(e) => panic!("recv error before all three variants arrived: {e:?}"),
            }
        }
    })
    .await;

    shutdown.cancel();
    assert!(
        deadline.is_ok(),
        "timed out before observing script({saw_script}) tip({saw_tip}) resync({saw_resync})"
    );
}
