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
use std::time::Duration;

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
use crate::auth::{check_bind_is_safe, Scope, Tokens};
use crate::config::Config;
use crate::error::Error;
use crate::inflight::InFlightUtxos;
use crate::store::FsWalletStore;
use crate::upstream::{ExferNode, RetryPolicy};

#[derive(Clone)]
pub struct AppState {
    pub api: ApiState,
    pub tokens: Arc<Tokens>,
}

/// Test-only constructor — exposed so integration tests can build an
/// `AppState` without going through CLI/env config parsing.
#[doc(hidden)]
pub fn build_app_state_for_tests(api: ApiState, legacy_token: Option<String>) -> AppState {
    let tokens = Tokens::from_config(legacy_token.as_deref(), None, None);
    AppState {
        api,
        tokens: Arc::new(tokens),
    }
}

/// Test helper that lets integration tests inject explicit scoped
/// tokens. Production callers go through [`run`].
#[doc(hidden)]
pub fn build_app_state_for_tests_scoped(
    api: ApiState,
    read: Option<String>,
    spend: Option<String>,
) -> AppState {
    let tokens = Tokens::from_config(None, read.as_deref(), spend.as_deref());
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

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let datadir = cfg.resolved_datadir();
    let wallet_dir = cfg.resolved_wallet_dir();

    // Create datadir + wallet dir on first run. Mode 0700 — only the
    // running user should ever read these.
    ensure_dir(&datadir, 0o700)?;
    ensure_dir(&wallet_dir, 0o700)?;

    // Resolve the auth token: explicit override wins, else read or
    // auto-generate `<datadir>/token`. If the operator opts into the
    // two-scope model with --auth-token-{read,spend}, we don't touch
    // the on-disk token at all.
    let scoped_in_use = cfg.auth_token_read.is_some() || cfg.auth_token_spend.is_some();
    let effective_legacy = if scoped_in_use {
        cfg.auth_token.clone()
    } else if let Some(t) = cfg.auth_token.clone() {
        Some(t)
    } else {
        Some(ensure_token_file(&cfg.token_file())?)
    };

    let tokens = Tokens::from_config(
        effective_legacy.as_deref(),
        cfg.auth_token_read.as_deref(),
        cfg.auth_token_spend.as_deref(),
    );

    // Fail closed: refuse public binds without a token, and refuse
    // public binds *with* a token unless either --tls is on (we
    // terminate TLS ourselves) or --allow-public-bind is set (the
    // operator is acknowledging an external TLS terminator / VPN).
    check_bind_is_safe(cfg.bind, &tokens, cfg.allow_public_bind, cfg.tls)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let store = FsWalletStore::open(&wallet_dir)?;
    let retry = RetryPolicy {
        attempts: cfg.upstream_attempts,
        backoff_ms: cfg.upstream_retry_backoff_ms,
    };
    let node = ExferNode::with_retry_policy(
        cfg.node_rpc.clone(),
        Duration::from_secs(cfg.upstream_timeout_secs),
        retry,
    )?;
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
        inflight: Arc::new(InFlightUtxos::new()),
    };
    let app_state = AppState {
        api,
        tokens: Arc::new(tokens.clone()),
    };

    // Load (or generate, on first run) the TLS material if --tls is on.
    // We do this *before* logging "starting" so the first-run cert box
    // appears next to the token box, not after a misleading "starting"
    // line.
    let tls_material = if cfg.tls {
        let mut extra_sans: Vec<String> = cfg.tls_san.clone();
        // Auto-include the bound IP. `--bind 0.0.0.0` / `::` is filtered
        // out inside `ensure_cert_files`; operators with wildcard binds
        // must pass real hostnames/IPs via `--tls-san`.
        extra_sans.push(cfg.bind.ip().to_string());
        Some(crate::tls::ensure_cert_files(
            &cfg.resolved_tls_cert_path(),
            &cfg.resolved_tls_key_path(),
            &cfg.tls_fingerprint_path(),
            &extra_sans,
        )?)
    } else {
        None
    };

    let scheme = if cfg.tls { "https" } else { "http" };
    let fingerprint_log = tls_material
        .as_ref()
        .map(|m| m.fingerprint.clone())
        .unwrap_or_default();

    tracing::info!(
        bind         = %cfg.bind,
        scheme       = %scheme,
        tls          = cfg.tls,
        fingerprint  = %fingerprint_log,
        node_rpc     = %cfg.node_rpc,
        datadir      = %datadir.display(),
        wallet_dir   = %wallet_dir.display(),
        auth         = %tokens.description(),
        attempts     = retry.attempts,
        backoff_ms   = retry.backoff_ms,
        "exfer-walletd starting",
    );

    let mut app = build_router(app_state);

    // Bootstrap endpoints only mounted when --tls is on — see
    // [`add_tls_bootstrap_routes`] for the rationale.
    if let Some(material) = tls_material.as_ref() {
        app =
            add_tls_bootstrap_routes(app, material.cert_pem.clone(), material.fingerprint.clone());
    }

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    if let Some(material) = tls_material {
        // axum-server owns the listen+accept loop on the TLS path.
        // Graceful shutdown wiring differs from axum::serve but the
        // handle is straightforward.
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
        });
        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
        axum_server::bind_rustls(cfg.bind, rustls_cfg)
            .handle(handle)
            .serve(make_service)
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
        axum::serve(listener, make_service)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

/// Create a directory (and any parents) with the given mode, OR if
/// it already exists, tighten its mode to match. The doc claims
/// `<datadir>` is `0700`; without this enforcement, an operator who
/// pre-creates the dir with `mkdir` (default umask → `0755`) would
/// silently end up with a world-listable parent for the `token` file
/// and `wallets/`.
///
/// Mode is honored only on Unix.
fn ensure_dir(path: &std::path::Path, mode: u32) -> anyhow::Result<()> {
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
/// print it prominently to stderr (so the operator sees it once on
/// first run).
fn ensure_token_file(path: &std::path::Path) -> anyhow::Result<String> {
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
    eprintln!("  ┌─ first run ───────────────────────────────────────────────────────────");
    eprintln!("  │ generated bearer token (saved to {}):", path.display());
    eprintln!("  │");
    eprintln!("  │     {token}");
    eprintln!("  │");
    eprintln!("  │ use as:  Authorization: Bearer {token}");
    eprintln!("  └───────────────────────────────────────────────────────────────────────");
    eprintln!();

    Ok(token)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
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
    // ---- Parse envelope first so we know the method (needed for
    //      scope-based auth and audit logging). ----
    let req: RpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let err = Error::BadEnvelope(e.to_string());
            return error_response(Value::Null, &err);
        }
    };

    if req.jsonrpc != "2.0" && !req.jsonrpc.is_empty() {
        let err = Error::BadEnvelope(format!("unsupported jsonrpc version: {}", req.jsonrpc));
        return error_response(req.id.clone(), &err);
    }

    let id = req.id.clone();

    // ---- Auth (scope-aware). ----
    let required = Scope::for_method(&req.method);
    if let Err(err) = app.tokens.authenticate(&headers, required) {
        return error_response(id, &err);
    }

    // ---- Dispatch. ----
    let method = req.method.clone();
    let is_spend = matches!(required, Scope::Spend);
    let ip = if is_spend {
        let peer: IpAddr = connect_info
            .as_ref()
            .map(|ci| ci.0.ip())
            .unwrap_or_else(|| std::net::Ipv4Addr::UNSPECIFIED.into());
        Some(audit_client_ip(&headers, peer))
    } else {
        None
    };

    // Render the JSON-RPC id for the audit log. Stringified so logs
    // tolerate the spec's "number | string | null" types uniformly.
    let request_id = if matches!(id, Value::Null) {
        "null".to_string()
    } else {
        id.to_string()
    };

    match dispatch(&app.api, req).await {
        Ok(result) => {
            if let Some(ip) = ip {
                tracing::info!(
                    method = %method,
                    client_ip = %ip,
                    request_id = %request_id,
                    outcome = "ok",
                    "spend audit",
                );
            }
            (StatusCode::OK, Json(RpcResponse::ok(id, result))).into_response()
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
            error_response(id, &err)
        }
    }
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
