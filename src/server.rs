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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

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
use crate::upstream::ExferNode;

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

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let tokens = Tokens::from_config(
        cfg.auth_token.as_deref(),
        cfg.auth_token_read.as_deref(),
        cfg.auth_token_spend.as_deref(),
    );

    // Fail closed: refuse public binds without a token, and refuse
    // public binds *with* a token unless --allow-public-bind is set
    // (the operator must acknowledge that TLS termination is in front).
    check_bind_is_safe(cfg.bind, &tokens, cfg.allow_public_bind)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let store = FsWalletStore::open(&cfg.wallet_dir)?;
    let node = ExferNode::new(
        cfg.node_rpc.clone(),
        Duration::from_secs(cfg.upstream_timeout_secs),
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

    tracing::info!(
        bind        = %cfg.bind,
        node_rpc    = %cfg.node_rpc,
        wallet_dir  = %cfg.wallet_dir.display(),
        auth        = %tokens.description(),
        "exfer-walletd starting",
    );

    let app = build_router(app_state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
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

    match dispatch(&app.api, req).await {
        Ok(result) => {
            if let Some(ip) = ip {
                tracing::info!(
                    method = %method,
                    client_ip = %ip,
                    "spend method succeeded",
                );
            }
            (StatusCode::OK, Json(RpcResponse::ok(id, result))).into_response()
        }
        Err(err) => {
            if let Some(ip) = ip {
                tracing::warn!(
                    method = %method,
                    client_ip = %ip,
                    error = %err,
                    "spend method failed",
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
