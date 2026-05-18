//! Tests that exercise the actual HTTP server: auth headers, JSON-RPC
//! envelope correctness, error responses. Spins up the axum app on a
//! random port, then makes real HTTP requests against it.

use std::time::Duration;

use exfer_walletd::api::ApiState;
use exfer_walletd::store::FsWalletStore;
use exfer_walletd::upstream::ExferNode;
use serde_json::json;
use wiremock::MockServer;

use std::sync::Arc;

/// Spin up the wrapper bound to a fresh ephemeral port. Returns
/// `(http_url, _keepalive)` — the keepalive guard owns the tempdir and
/// mock server so they outlive the test.
async fn boot(auth: Option<&str>) -> (String, KeepAlive) {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    let store = FsWalletStore::open(dir.path()).unwrap();
    let node = ExferNode::new(mock.uri(), Duration::from_secs(5)).unwrap();
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app_state = exfer_walletd::server::build_app_state_for_tests(api, auth.map(String::from));
    let app = exfer_walletd::server::build_router(app_state);

    let _server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (
        format!("http://{addr}"),
        KeepAlive {
            _dir: dir,
            _mock: mock,
            _server: _server_task,
        },
    )
}

struct KeepAlive {
    _dir: tempfile::TempDir,
    _mock: MockServer,
    _server: tokio::task::JoinHandle<()>,
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (base, _g) = boot(None).await;
    let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert!(resp.status().is_success());
    assert!(resp.text().await.unwrap().contains("ok"));
}

#[tokio::test]
async fn rpc_envelope_returns_jsonrpc_response() {
    let (base, _g) = boot(None).await;
    let body = json!({
        "jsonrpc": "2.0",
        "method":  "ping",
        "params":  {},
        "id":      42
    });
    let resp = reqwest::Client::new()
        .post(&base)
        .json(&body)
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 42);
    assert_eq!(v["result"]["ok"], true);
}

#[tokio::test]
async fn auth_required_when_token_set() {
    let (base, _g) = boot(Some("secret-token")).await;
    let body = json!({ "jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1 });

    // missing token: 401
    let resp = reqwest::Client::new()
        .post(&base)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // wrong token: 401
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer not-it")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // right token: 200
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer secret-token")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["ok"], true);
}

#[tokio::test]
async fn unknown_method_returns_error_with_code_minus_32601() {
    let (base, _g) = boot(None).await;
    let body = json!({
        "jsonrpc": "2.0",
        "method":  "nonexistent",
        "params":  {},
        "id":      7
    });
    let resp = reqwest::Client::new()
        .post(&base)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn malformed_envelope_returns_400_with_parse_error() {
    let (base, _g) = boot(None).await;
    let resp = reqwest::Client::new()
        .post(&base)
        .header("content-type", "application/json")
        .body("this is not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32700);
}
