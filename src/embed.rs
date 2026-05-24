//! Library entry point for embedding walletd inside another process
//! (e.g. the Tauri desktop app `exfer-walletd-desktop`).
//!
//! [`run_embedded`] differs from [`server::run`](crate::server::run) in
//! three ways:
//!
//! 1. **Passphrase is a parameter**, not read from
//!    `WALLETD_KEYSTORE_PASSPHRASE`. Desktop callers prompt the user
//!    once and pass the secret in directly.
//! 2. **Returns after bind succeeds**, not after the server stops. The
//!    listener is bound up front so the actual local port (useful when
//!    callers pass `127.0.0.1:0`) and the TLS fingerprint can be
//!    surfaced to the caller before any client request lands.
//! 3. **Shutdown is driven by a `CancellationToken`**, not
//!    `ctrl_c()`. Tauri triggers it from the window-close handler;
//!    headless callers can wire it to whatever signal they like.
//!
//! The on-disk state (datadir, sealed seed, tokens, TLS material) is
//! identical to what the daemon `run()` produces — embedded callers
//! can later switch to running the daemon binary against the same
//! datadir and pick up where they left off.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api::ApiState;
use crate::auth::{check_bind_is_safe, Tokens};
use crate::config::Config;
use crate::inflight::InFlightUtxos;
use crate::server::{add_tls_bootstrap_routes, build_router, AppState};
use crate::store::HdSeedStore;
use crate::upstream::{ExferNode, RetryPolicy};

/// Bearer tokens minted (or loaded) during [`run_embedded`]. The Tauri
/// shell uses these to authenticate its own JSON-RPC calls back into
/// the embedded walletd; never expose them to the frontend.
#[derive(Clone, Debug)]
pub struct EmbeddedTokens {
    pub read: String,
    pub manage: String,
    pub spend: String,
}

/// Handle to a running embedded walletd. Drop or [`shutdown`] to stop
/// the server.
///
/// [`shutdown`]: ServerHandle::shutdown
#[derive(Debug)]
pub struct ServerHandle {
    /// Actual address the listener bound to. When the caller passed a
    /// `:0` port, this carries the OS-assigned port — read this, not
    /// `cfg.bind`, when telling clients where to connect.
    pub local_addr: SocketAddr,
    /// `sha256:<hex>` of the self-signed leaf cert, `Some` iff
    /// `cfg.tls` was `true`. Pin this on the client side.
    pub fingerprint: Option<String>,
    /// Resolved auth tokens (auto-generated to `<datadir>/token-*`
    /// when not supplied via `cfg`).
    pub tokens: EmbeddedTokens,
    shutdown: CancellationToken,
    join: JoinHandle<anyhow::Result<()>>,
}

impl ServerHandle {
    /// A clone of the shutdown token. Useful for plumbing into
    /// long-running tasks that should also stop when the server does.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Wait for the server task to finish on its own (i.e. someone
    /// else cancelled the shutdown token, or the server errored).
    /// Returns whatever the server task returned.
    pub async fn wait(self) -> anyhow::Result<()> {
        match self.join.await {
            Ok(r) => r,
            Err(join_err) => Err(anyhow::anyhow!("walletd task join failed: {join_err}")),
        }
    }

    /// Cancel the shutdown token and wait for the server task to
    /// finish. Idempotent — calling on an already-cancelled handle
    /// just awaits the join.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        self.wait().await
    }
}

/// Boot walletd inside the calling process and return once the listener
/// is accepting connections. The actual `axum::serve` / `axum_server`
/// loop runs on a `tokio::spawn`ed task driven by the runtime the caller
/// owns.
///
/// `passphrase` MUST NOT be empty — same fail-closed semantics as the
/// daemon's `WALLETD_KEYSTORE_PASSPHRASE` check.
///
/// `shutdown` is cloned: the returned [`ServerHandle`] keeps its own
/// clone (for [`ServerHandle::shutdown`]), the caller can also clone the
/// token before calling to wire it to other shutdown sources.
pub async fn run_embedded(
    cfg: Config,
    passphrase: &str,
    shutdown: CancellationToken,
) -> anyhow::Result<ServerHandle> {
    if passphrase.is_empty() {
        anyhow::bail!(
            "run_embedded: passphrase must not be empty. \
             walletd encrypts the HD seed at rest with argon2id + ChaCha20-Poly1305 \
             and refuses to start without one."
        );
    }

    let datadir = cfg.resolved_datadir();
    let wallet_dir = cfg.resolved_wallet_dir();
    crate::server::ensure_dir(&datadir, 0o700)?;
    crate::server::ensure_dir(&wallet_dir, 0o700)?;

    // Resolve scoped tokens. Same precedence as `server::run`: explicit
    // value in cfg wins; otherwise auto-generate to disk on first run.
    // First-run prints land on stderr — invisible to GUI hosts (Tauri
    // swallows stderr) and useful to daemon operators; no harm either
    // way, so we don't gate the prints.
    let paths = cfg.token_files();
    let read = match cfg.auth_token_read.clone() {
        Some(t) => t,
        None => crate::server::ensure_token_file(&paths.read, "read")?,
    };
    let manage = match cfg.auth_token_manage.clone() {
        Some(t) => t,
        None => crate::server::ensure_token_file(&paths.manage, "manage")?,
    };
    let spend = match cfg.auth_token_spend.clone() {
        Some(t) => t,
        None => crate::server::ensure_token_file(&paths.spend, "spend")?,
    };
    let tokens_auth = Tokens::from_config(Some(&read), Some(&manage), Some(&spend));

    check_bind_is_safe(cfg.bind, &tokens_auth, cfg.allow_public_bind, cfg.tls)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let store = HdSeedStore::open_or_init_fresh(&wallet_dir, passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // First-run mnemonic print goes to stderr — same channel as the
    // token / cert first-run boxes. Daemon operators see it; GUI hosts
    // (Tauri swallows stderr) silently drop it, which matches the
    // desktop UX choice of "user-set password is the only secret to
    // remember."
    if let Some(words) = store.take_fresh_mnemonic() {
        crate::server::print_fresh_mnemonic(&words);
    }

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
        idempotency: Arc::new(crate::idempotency::IdempotencyCache::new()),
    };
    let app_state = AppState {
        api,
        tokens: Arc::new(tokens_auth.clone()),
    };

    let tls_material = if cfg.tls {
        let mut extra_sans: Vec<String> = cfg.tls_san.clone();
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

    let fingerprint = tls_material.as_ref().map(|m| m.fingerprint.clone());

    tracing::info!(
        bind        = %cfg.bind,
        tls         = cfg.tls,
        fingerprint = %fingerprint.clone().unwrap_or_default(),
        node_rpc    = %cfg.node_rpc,
        datadir     = %datadir.display(),
        wallet_dir  = %wallet_dir.display(),
        attempts    = retry.attempts,
        backoff_ms  = retry.backoff_ms,
        mode        = "embedded",
        "exfer-walletd starting",
    );

    let mut app = build_router(app_state);
    if let Some(material) = tls_material.as_ref() {
        app = add_tls_bootstrap_routes(
            app,
            material.cert_pem.clone(),
            material.fingerprint.clone(),
        );
    }
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    let (local_addr, join) = if let Some(material) = tls_material {
        // TLS path. axum-server's `from_tcp_rustls` takes a
        // pre-bound std listener, which is the only way to surface the
        // OS-assigned port back to the caller when bind port is 0.
        let std_listener = std::net::TcpListener::bind(cfg.bind)?;
        std_listener.set_nonblocking(true)?;
        let local_addr = std_listener.local_addr()?;

        let handle = axum_server::Handle::new();
        let shutdown_watcher = shutdown.clone();
        let handle_for_watcher = handle.clone();
        tokio::spawn(async move {
            shutdown_watcher.cancelled().await;
            handle_for_watcher.graceful_shutdown(Some(Duration::from_secs(5)));
        });

        let rustls_cfg =
            axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
        let join = tokio::spawn(async move {
            axum_server::from_tcp_rustls(std_listener, rustls_cfg)
                .handle(handle)
                .serve(make_service)
                .await
                .map_err(anyhow::Error::from)
        });
        (local_addr, join)
    } else {
        // Plain HTTP path. axum::serve accepts the bound tokio listener
        // and consumes a graceful-shutdown future, which we drive from
        // the cancellation token.
        let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
        let local_addr = listener.local_addr()?;
        let shutdown_fut = shutdown.clone();
        let join = tokio::spawn(async move {
            axum::serve(listener, make_service)
                .with_graceful_shutdown(async move { shutdown_fut.cancelled().await })
                .await
                .map_err(anyhow::Error::from)
        });
        (local_addr, join)
    };

    Ok(ServerHandle {
        local_addr,
        fingerprint,
        tokens: EmbeddedTokens {
            read,
            manage,
            spend,
        },
        shutdown,
        join,
    })
}

