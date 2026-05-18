//! HTTP server. JSON-RPC 2.0 over `POST /`. Bearer-token auth (optional).
//! Plain `GET /healthz` for liveness probes.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use tower_http::trace::TraceLayer;

use crate::api::{dispatch, ApiState, RpcRequest, RpcResponse};
use crate::config::Config;
use crate::error::Error;
use crate::store::FsWalletStore;
use crate::upstream::ExferNode;

#[derive(Clone)]
pub struct AppState {
    pub api: ApiState,
    pub auth_token: Option<Arc<str>>,
}

/// Test-only constructor — exposed so integration tests can build an
/// `AppState` without going through CLI/env config parsing.
#[doc(hidden)]
pub fn build_app_state_for_tests(api: ApiState, auth_token: Option<String>) -> AppState {
    AppState {
        api,
        auth_token: auth_token.map(Into::into),
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
    let store = FsWalletStore::open(&cfg.wallet_dir)?;
    let node = ExferNode::new(
        cfg.node_rpc.clone(),
        Duration::from_secs(cfg.upstream_timeout_secs),
    )?;
    let api = ApiState {
        store: Arc::new(store),
        node: Arc::new(node),
    };
    let app_state = AppState {
        api,
        auth_token: cfg.auth_token.as_deref().map(Into::into),
    };

    tracing::info!(
        bind        = %cfg.bind,
        node_rpc    = %cfg.node_rpc,
        wallet_dir  = %cfg.wallet_dir.display(),
        auth_token  = if cfg.auth_token.is_some() { "set" } else { "UNSET (open API)" },
        "exfer-walletd starting",
    );

    let app = build_router(app_state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    axum::serve(listener, app)
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

async fn rpc_handler(State(app): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    // ---- Auth ----
    if let Some(expected) = &app.auth_token {
        let supplied = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if supplied != expected.as_ref() {
            return error_response(Value::Null, &Error::Unauthorized);
        }
    }

    // ---- Parse envelope ----
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
    match dispatch(&app.api, req).await {
        Ok(result) => (StatusCode::OK, Json(RpcResponse::ok(id, result))).into_response(),
        Err(err) => error_response(id, &err),
    }
}

fn error_response(id: Value, err: &Error) -> Response {
    tracing::warn!(error = %err, "rpc error");
    let status = err.http_status();
    (status, Json(RpcResponse::err(id, err))).into_response()
}
