//! HTTP server. JSON-RPC 2.0 over `POST /`.
//!
//! Two checks before a request reaches the dispatcher:
//!
//! 1. **Auth** — [`auth::Tokens::authenticate`] looks up the required
//!    [`auth::Scope`] for the method and verifies the bearer token in
//!    constant time.
//! 2. **Dispatch** — [`api::dispatch`] runs the actual method.
//!
//! `GET /healthz` is unauthenticated.

use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand::{rngs::OsRng, RngCore};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use tower_http::trace::TraceLayer;

use crate::api::{dispatch, ApiState, RpcRequest, RpcResponse};
use crate::auth::{Scope, Tokens};
use crate::config::Config;
use crate::error::Error;

#[derive(Clone)]
pub struct AppState {
    pub api: ApiState,
    pub tokens: Arc<Tokens>,
}

/// Test-only constructor — exposed so integration tests can build an
/// `AppState` without going through CLI/env config parsing.
///
/// `single_token`, when `Some`, is installed as the **spend** token
/// (the broadest scope; satisfies every request). For per-scope
/// control use [`build_app_state_for_tests_scoped`].
#[doc(hidden)]
pub fn build_app_state_for_tests(api: ApiState, single_token: Option<String>) -> AppState {
    let tokens = Tokens::from_config(None, None, single_token.as_deref());
    AppState {
        api,
        tokens: Arc::new(tokens),
    }
}

/// Test helper that lets integration tests inject any subset of the
/// three scoped tokens. Production callers go through [`run`].
#[doc(hidden)]
pub fn build_app_state_for_tests_scoped(
    api: ApiState,
    read: Option<String>,
    manage: Option<String>,
    spend: Option<String>,
) -> AppState {
    let tokens = Tokens::from_config(read.as_deref(), manage.as_deref(), spend.as_deref());
    AppState {
        api,
        tokens: Arc::new(tokens),
    }
}

/// Build the axum router. Public so integration tests can boot it on an
/// arbitrary listener; production callers go through [`run`].
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        .route("/healthz", get(healthz))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Bolt on the `/exfer-walletd/cert.pem` + `/exfer-walletd/cert.fingerprint`
/// bootstrap endpoints. Production only calls this from [`run`] when
/// `--tls` is enabled — serving the cert files over plaintext HTTP would
/// be trivially MitM-able and would defeat the whole pinning model.
/// Test code can call it directly to verify endpoint shape without
/// standing up rustls.
///
/// Both endpoints are unauthenticated: cert.pem is the same bytes the
/// TLS handshake hands every client anyway, and the fingerprint is the
/// SHA-256 of that public data.
pub fn add_tls_bootstrap_routes(router: Router, cert_pem: String, fingerprint: String) -> Router {
    let cert_pem_for_handler = cert_pem;
    let fingerprint_line = format!("{fingerprint}\n");
    router
        .route(
            "/exfer-walletd/cert.pem",
            get(move || {
                let body = cert_pem_for_handler.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/x-pem-file")],
                        body,
                    )
                }
            }),
        )
        .route(
            "/exfer-walletd/cert.fingerprint",
            get(move || {
                let body = fingerprint_line.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; charset=utf-8",
                        )],
                        body,
                    )
                }
            }),
        )
}

/// Daemon entry point. Reads `WALLETD_KEYSTORE_PASSPHRASE` from the
/// environment, wires `tokio::signal::ctrl_c()` to a cancellation
/// token, delegates the actual setup + serve to
/// [`crate::embed::run_embedded`], and awaits the server task.
///
/// Library callers (Tauri shells, integration tests, anything that
/// wants to drive shutdown programmatically or surface the bound
/// port) should call `run_embedded` directly.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let passphrase = std::env::var("WALLETD_KEYSTORE_PASSPHRASE").unwrap_or_default();
    if passphrase.is_empty() {
        anyhow::bail!(
            "WALLETD_KEYSTORE_PASSPHRASE is required. \
             walletd v1 encrypts the HD seed at rest with argon2id + ChaCha20-Poly1305 \
             and refuses to start without an explicit passphrase. \
             Set it in env (or your container/secret manager) before launching."
        );
    }

    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    let handle = crate::embed::run_embedded(cfg, &passphrase, shutdown).await?;
    handle.wait().await
}

/// Create a directory (and any parents) with the given mode, OR if
/// it already exists, tighten its mode to match. The doc claims
/// `<datadir>` is `0700`; without this enforcement, an operator who
/// pre-creates the dir with `mkdir` (default umask → `0755`) would
/// silently end up with a world-listable parent for the `token` file
/// and `wallets/`.
///
/// Mode is honored only on Unix.
pub(crate) fn ensure_dir(path: &std::path::Path, mode: u32) -> anyhow::Result<()> {
    if path.exists() {
        if !path.is_dir() {
            anyhow::bail!("{} exists but is not a directory", path.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let current = fs::metadata(path)?.permissions().mode() & 0o777;
            if current != mode {
                tracing::warn!(
                    path = %path.display(),
                    from = format!("{current:o}"),
                    to = format!("{mode:o}"),
                    "tightening directory permissions to match walletd policy",
                );
                fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            }
        }
        #[cfg(not(unix))]
        let _ = mode;
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    b.create(path)?;
    Ok(())
}

/// Read the token at `path`, or generate + persist a fresh one and
/// print it prominently to stderr the first time we mint it.
///
/// `pub(crate)` so the embedded entry point ([`crate::embed::run_embedded`])
/// can reuse the same precedence + side effects without re-implementing
/// them.
pub(crate) fn ensure_token_file(path: &std::path::Path, scope: &str) -> anyhow::Result<String> {
    if let Ok(s) = fs::read_to_string(path) {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")?;

    eprintln!();
    eprintln!("  ┌─ first run: {scope} token ─────────────────────────────────────────────");
    eprintln!("  │ generated bearer token (saved to {}):", path.display());
    eprintln!("  │");
    eprintln!("  │     {token}");
    eprintln!("  │");
    eprintln!("  │ use as:  Authorization: Bearer {token}");
    eprintln!("  └───────────────────────────────────────────────────────────────────────");
    eprintln!();

    Ok(token)
}

/// Print the freshly-generated BIP-39 mnemonic to stderr exactly once
/// (only after a brand-new keystore was initialised). Matches the style
/// of `ensure_token_file` so first-run output reads as one boxed
/// section.
///
/// `pub(crate)` so [`crate::embed::run_embedded`] can call it on the
/// same fresh-init signal.
pub(crate) fn print_fresh_mnemonic(words: &[String]) {
    eprintln!();
    eprintln!("  ┌─ first run: HD seed ──────────────────────────────────────────────────");
    eprintln!("  │ A new BIP-39 mnemonic has been generated and the seed has been");
    eprintln!("  │ encrypted at rest with your WALLETD_KEYSTORE_PASSPHRASE.");
    eprintln!("  │");
    eprintln!("  │ ⚠  WRITE THESE 24 WORDS DOWN. They are the ONLY way to recover");
    eprintln!("  │    every address this daemon will ever derive. They will NEVER be");
    eprintln!("  │    shown again.");
    eprintln!("  │");
    for (chunk_idx, chunk) in words.chunks(6).enumerate() {
        let row: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {:<10}", chunk_idx * 6 + i + 1, w))
            .collect();
        eprintln!("  │    {}", row.join(" "));
    }
    eprintln!("  └───────────────────────────────────────────────────────────────────────");
    eprintln!();
}

async fn healthz() -> &'static str {
    "ok\n"
}

/// Extract the caller's IP for audit logging. Honors the first hop of
/// `X-Forwarded-For` when present (the request came through a reverse
/// proxy), else falls back to the direct peer address.
fn audit_client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(peer)
}

async fn rpc_handler(
    State(app): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Parse the body as a generic Value first so we can distinguish a
    // single request envelope (Object) from a batch (Array) per
    // JSON-RPC 2.0 § 6.
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error_response(Value::Null, &Error::ParseError(e.to_string())),
    };

    let peer_ip: IpAddr = connect_info
        .as_ref()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::Ipv4Addr::UNSPECIFIED.into());

    match parsed {
        Value::Array(items) => {
            // § 6: an empty array is invalid; respond with a single
            // Invalid Request, id null.
            if items.is_empty() {
                return error_response(Value::Null, &Error::InvalidRequest("empty batch".into()));
            }
            let futs = items.into_iter().map(|item| {
                let app = app.clone();
                let headers = headers.clone();
                async move { process_single(&app, item, &headers, peer_ip).await }
            });
            let results: Vec<Option<RpcResponse>> = futures::future::join_all(futs).await;
            let responses: Vec<RpcResponse> = results.into_iter().flatten().collect();
            // § 6: "If there are no Response objects contained within
            // the Response array as it is to be sent to the client, the
            // server MUST NOT return an empty Array and should return
            // nothing at all."
            if responses.is_empty() {
                return StatusCode::NO_CONTENT.into_response();
            }
            (StatusCode::OK, Json(responses)).into_response()
        }
        Value::Object(_) => match process_single(&app, parsed, &headers, peer_ip).await {
            Some(resp) => {
                // Auth / envelope-shape errors get non-200 statuses; all
                // other JSON-RPC errors ride inside a 200 body per
                // convention.
                let status = match resp.error.as_ref().map(|e| e.code) {
                    Some(-32001) => StatusCode::UNAUTHORIZED,
                    Some(-32600) | Some(-32700) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::OK,
                };
                (status, Json(resp)).into_response()
            }
            None => StatusCode::NO_CONTENT.into_response(),
        },
        _ => error_response(
            Value::Null,
            &Error::InvalidRequest("request must be a JSON object or array".into()),
        ),
    }
}

/// Process one envelope (single request or one batch element). Returns
/// `None` if the request was a JSON-RPC notification (envelope parsed
/// successfully and had no `id` field) — per § 4.1, notifications get
/// no reply at all.
async fn process_single(
    app: &AppState,
    raw: Value,
    headers: &HeaderMap,
    peer_ip: IpAddr,
) -> Option<RpcResponse> {
    // Each batch element must itself be a JSON object envelope.
    if !raw.is_object() {
        return Some(RpcResponse::err(
            Value::Null,
            &Error::InvalidRequest("request must be a JSON object".into()),
        ));
    }

    let req: RpcRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => {
            // Parse failure on the envelope. We cannot reliably recover
            // the id, so respond with id: null per spec.
            return Some(RpcResponse::err(
                Value::Null,
                &Error::InvalidRequest(e.to_string()),
            ));
        }
    };

    let id_owned = req.id.clone();
    let is_notification = id_owned.is_none();
    let response_id = id_owned.unwrap_or(Value::Null);

    if !is_valid_jsonrpc_id(&response_id) {
        return Some(RpcResponse::err(
            Value::Null,
            &Error::InvalidRequest("id must be a JSON string, number, or null when present".into()),
        ));
    }

    if req.jsonrpc != "2.0" {
        if is_notification {
            return None;
        }
        return Some(RpcResponse::err(
            response_id,
            &Error::InvalidRequest(format!(
                "unsupported jsonrpc version: {:?} (must be \"2.0\")",
                req.jsonrpc
            )),
        ));
    }

    let required = Scope::for_method(&req.method);
    if let Err(err) = app.tokens.authenticate(headers, required) {
        if is_notification {
            return None;
        }
        return Some(RpcResponse::err(response_id, &err));
    }

    let method = req.method.clone();
    let is_spend = matches!(required, Scope::Spend);
    let ip = if is_spend {
        Some(audit_client_ip(headers, peer_ip))
    } else {
        None
    };

    let request_id = if matches!(response_id, Value::Null) {
        "null".to_string()
    } else {
        response_id.to_string()
    };

    let result = dispatch(&app.api, req).await;
    match &result {
        Ok(_) => {
            if let Some(ip) = ip {
                tracing::info!(
                    method = %method,
                    client_ip = %ip,
                    request_id = %request_id,
                    outcome = "ok",
                    "spend audit",
                );
            }
        }
        Err(err) => {
            if let Some(ip) = ip {
                tracing::warn!(
                    method = %method,
                    client_ip = %ip,
                    request_id = %request_id,
                    outcome = "error",
                    error = %err,
                    "spend audit",
                );
            }
        }
    }

    if is_notification {
        return None;
    }
    Some(match result {
        Ok(v) => RpcResponse::ok(response_id, v),
        Err(err) => RpcResponse::err(response_id, &err),
    })
}

fn is_valid_jsonrpc_id(id: &Value) -> bool {
    matches!(id, Value::String(_) | Value::Number(_) | Value::Null)
}

fn error_response(id: Value, err: &Error) -> Response {
    tracing::warn!(error = %err, "rpc error");
    let status = err.http_status();
    (status, Json(RpcResponse::err(id, err))).into_response()
}

#[cfg(all(test, unix))]
mod tests {
    use super::ensure_dir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &std::path::Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_missing_dir_with_target_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh");
        ensure_dir(&path, 0o700).unwrap();
        assert!(path.is_dir());
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn tightens_existing_dir_with_loose_mode() {
        // Simulate a user pre-creating --datadir with `mkdir` (default
        // umask → 0755). walletd must tighten it to 0700 so the token
        // file and wallets/ aren't world-listable through the parent.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preexisting");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(mode_of(&path), 0o755);

        ensure_dir(&path, 0o700).unwrap();
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn leaves_correctly_moded_dir_alone() {
        // No-op path: existing dir already at the target mode.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("already-tight");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        ensure_dir(&path, 0o700).unwrap();
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn refuses_when_path_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-dir");
        fs::write(&path, b"hi").unwrap();

        let err = ensure_dir(&path, 0o700).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
    }
}
