//! Tests that exercise the actual HTTP server: auth headers, JSON-RPC
//! envelope correctness, error responses. Spins up the axum app on a
//! random port, then makes real HTTP requests against it.

use std::time::Duration;

use exfer_walletd::api::ApiState;
use exfer_walletd::store::HdSeedStore;
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

    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::new(mock.uri(), Duration::from_secs(5)).unwrap();
    let index = Arc::new(exfer_walletd::index::Index::open(dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),
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

/// Boot the server with explicit scoped tokens (read + manage + spend).
async fn boot_scoped(
    read: Option<&str>,
    manage: Option<&str>,
    spend: Option<&str>,
) -> (String, KeepAlive) {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::new(mock.uri(), Duration::from_secs(5)).unwrap();
    let index = Arc::new(exfer_walletd::index::Index::open(dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app_state = exfer_walletd::server::build_app_state_for_tests_scoped(
        api,
        read.map(String::from),
        manage.map(String::from),
        spend.map(String::from),
    );
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

#[tokio::test]
async fn read_token_cannot_call_transfer() {
    let (base, _g) = boot_scoped(Some("READ"), Some("MANAGE"), Some("SPEND")).await;

    let body = json!({
        "jsonrpc": "2.0",
        "method":  "transfer",
        "params":  {
            "from":   "ab".repeat(32),
            "to":     "cd".repeat(32),
            "amount": 1000
        },
        "id": 1
    });

    // Read token: 401 (unauthorized for spend scope)
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer READ")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Spend token: gets past auth (will fail later because no wallet exists,
    // but that's a different error code — not 401).
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer SPEND")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success() || resp.status() == reqwest::StatusCode::OK);
    let v: serde_json::Value = resp.json().await.unwrap();
    // Either auth-pass (some other error) or unauthorized — must NOT be unauthorized.
    if let Some(code) = v["error"]["code"].as_i64() {
        assert_ne!(code, -32001, "spend token should not get -32001");
    }
}

#[tokio::test]
async fn read_token_can_call_read_methods() {
    let (base, _g) = boot_scoped(Some("READ"), Some("MANAGE"), Some("SPEND")).await;
    let body = json!({ "jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1 });
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer READ")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["ok"], true);
}

#[tokio::test]
async fn spend_token_grants_read_too() {
    let (base, _g) = boot_scoped(Some("READ"), Some("MANAGE"), Some("SPEND")).await;
    let body = json!({ "jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1 });
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer SPEND")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["ok"], true);
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

#[tokio::test]
async fn invalid_jsonrpc_id_type_returns_invalid_request() {
    let (base, _g) = boot(None).await;
    let body = json!({
        "jsonrpc": "2.0",
        "method":  "ping",
        "params":  {},
        "id":      { "not": "a valid json-rpc id" }
    });

    let resp = reqwest::Client::new()
        .post(&base)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32600);
    assert_eq!(v["id"], serde_json::Value::Null);
    assert!(v.get("result").is_none());
}

/// Bootstrap endpoints are mounted only when `--tls` is on. In these
/// tests we don't run actual TLS, but `add_tls_bootstrap_routes` is
/// content-agnostic, so we can exercise it on the plaintext test
/// server and verify shape (status, content-type, body). The "must
/// not exist when TLS is off" half is covered by the default `boot()`
/// fixture below — those tests would 404 if they accidentally hit a
/// bootstrap path on a non-TLS server.
async fn boot_with_bootstrap(cert_pem: &str, fingerprint: &str) -> (String, KeepAlive) {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = HdSeedStore::open_or_init_fresh(dir.path(), b"test-passphrase").unwrap();
    let node = ExferNode::new(mock.uri(), Duration::from_secs(5)).unwrap();
    let index = Arc::new(exfer_walletd::index::Index::open(dir.path()).unwrap());
    let (_tip_tx, tip_rx) = tokio::sync::watch::channel(0u64);
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(exfer_walletd::inflight::InFlightUtxos::new()),
        idempotency: Arc::new(exfer_walletd::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer: None,
        events: exfer_walletd::sse_client::WalletEvents::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app_state = exfer_walletd::server::build_app_state_for_tests(api, None);
    let app = exfer_walletd::server::add_tls_bootstrap_routes(
        exfer_walletd::server::build_router(app_state),
        cert_pem.to_string(),
        fingerprint.to_string(),
    );
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

#[tokio::test]
async fn bootstrap_serves_cert_pem_verbatim() {
    let cert = "-----BEGIN CERTIFICATE-----\nMIIBHTCB...\n-----END CERTIFICATE-----\n";
    let fp = "sha256:b66953c47263ac0da8192676e4770f0f799563322985c57246a6fab1bf24aa86";
    let (base, _g) = boot_with_bootstrap(cert, fp).await;
    let resp = reqwest::get(format!("{base}/exfer-walletd/cert.pem"))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/x-pem-file"
    );
    assert_eq!(resp.text().await.unwrap(), cert);
}

#[tokio::test]
async fn bootstrap_serves_fingerprint_with_trailing_newline() {
    let cert = "-----BEGIN CERTIFICATE-----\n...\n";
    let fp = "sha256:b66953c47263ac0da8192676e4770f0f799563322985c57246a6fab1bf24aa86";
    let (base, _g) = boot_with_bootstrap(cert, fp).await;
    let resp = reqwest::get(format!("{base}/exfer-walletd/cert.fingerprint"))
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/plain"));
    // Matches what walletd writes to <datadir>/cert.fingerprint —
    // single line, trailing newline, sha256:HEX form.
    assert_eq!(resp.text().await.unwrap(), format!("{fp}\n"));
}

#[tokio::test]
async fn bootstrap_endpoints_are_unauthenticated() {
    // The cert and fingerprint are public information — never require
    // a token. (The cert is what TLS hands every client anyway.)
    let (base, _g) = boot_with_bootstrap("-----BEGIN CERTIFICATE-----\n...\n", "sha256:abcd").await;
    for path in ["/exfer-walletd/cert.pem", "/exfer-walletd/cert.fingerprint"] {
        let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert!(
            resp.status().is_success(),
            "{path} should be reachable without an Authorization header"
        );
    }
}

#[tokio::test]
async fn bootstrap_endpoints_absent_on_default_router() {
    // Mirrors the production safety: production only registers these
    // routes when --tls is on; tests boot the bare router (no TLS, no
    // bootstrap routes) and assert the paths 404.
    let (base, _g) = boot(None).await;
    for path in ["/exfer-walletd/cert.pem", "/exfer-walletd/cert.fingerprint"] {
        let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{path} must not be served when TLS is off"
        );
    }
}

#[tokio::test]
async fn read_token_cannot_call_sign_message() {
    // sign_message produces a proof of ownership over a wallet key.
    // It doesn't move funds, but the artifact is value-bearing in
    // KYC / exchange flows, so it's gated behind spend scope.
    let (base, _g) = boot_scoped(Some("READ"), Some("MANAGE"), Some("SPEND")).await;

    let body = json!({
        "jsonrpc": "2.0",
        "method":  "sign_message",
        "params":  { "address": "ab".repeat(32), "message": "challenge" },
        "id": 1
    });
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer READ")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_token_can_call_verify_message() {
    // Verification is pure crypto with no key access — read scope.
    let (base, _g) = boot_scoped(Some("READ"), Some("MANAGE"), Some("SPEND")).await;
    let body = json!({
        "jsonrpc": "2.0",
        "method":  "verify_message",
        "params":  {
            "pubkey":    "ab".repeat(32),
            "signature": "cd".repeat(64),
            "message":   "challenge",
        },
        "id": 1
    });
    let resp = reqwest::Client::new()
        .post(&base)
        .header("authorization", "Bearer READ")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    // Auth passed; the (random) pubkey + sig don't verify, but `valid`
    // should be a clean false rather than an auth error.
    assert_eq!(v["result"]["valid"], false);
}
