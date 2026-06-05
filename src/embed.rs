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
use crate::store::KeyringStore;
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
    /// Push-event channel for embedders (the Tauri supervisor / future
    /// in-process consumers). Forwards Phase 2 SSE nudges from the
    /// upstream node so the UI can re-render the moment a balance
    /// changes instead of waiting for the next poll. Returns an empty
    /// stream when the upstream node has no /sse endpoint (the
    /// SseClient stays in fallback mode and the existing follower poll
    /// loop covers the gap).
    pub events: Arc<crate::sse_client::WalletEvents>,
    shutdown: CancellationToken,
    join: JoinHandle<anyhow::Result<()>>,
    /// The block-follower task. Held so [`shutdown`](Self::shutdown) can
    /// await its exit — the follower owns a clone of the wallet store, and
    /// the datadir isn't free for an embedded restart until it drops.
    follower_task: JoinHandle<()>,
    /// The SSE push-client task. Also owns a clone of the wallet store, so
    /// it must drain on shutdown for the datadir to be released.
    sse_task: JoinHandle<()>,
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
        let r = match self.join.await {
            Ok(r) => r,
            Err(join_err) => Err(anyhow::anyhow!("walletd task join failed: {join_err}")),
        };
        // Also await the follower and SSE client so their holds on the wallet
        // store are released before we return — an embedded restart reopens
        // the same datadir immediately after, and redb won't grant a second
        // handle while either task is still alive.
        let _ = self.follower_task.await;
        let _ = self.sse_task.await;
        r
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

    // Embedded (desktop) opens a seedless keyring: brand-new wallets get
    // no HD seed at all (new addresses are independent 1:1 keys, backup is
    // the vault / per-address phrases). Existing seeded wallets still load
    // their seed normally — `open_keyring` is seedless only when there is
    // no `seed.enc` to begin with.
    let store = KeyringStore::open_keyring(&wallet_dir, passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // A fresh seedless keyring has no mnemonic to surface; only a legacy
    // seeded wallet would (then it goes to stderr — Tauri swallows it).
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
    let store = Arc::new(store);
    let node = Arc::new(node);
    let index = Arc::new(crate::index::Index::open(&datadir)?);

    // Spawn the block follower wired to the shutdown token. It must stop on
    // shutdown (not "run until process exit") — otherwise, for an embedded
    // restart, the old follower keeps polling and holding the wallet store,
    // so the new instance can't reopen the datadir. `tip_rx` is what
    // `wait_for_tx` will subscribe to.
    let (follower, tip_rx) = crate::follower::Follower::new(
        store.clone(),
        node.clone(),
        index.clone(),
        crate::follower::FollowerConfig::default(),
    );
    let follower_task = follower.spawn_with_shutdown(shutdown.clone());

    // Phase 2 SSE: connect to the upstream node's /sse push endpoint and
    // forward every script_changed / tip / resync nudge onto an
    // in-process broadcast channel. Probe-and-fallback semantics:
    // unreachable / 404 nodes (pre-1.12) leave the channel empty and
    // the follower's poll loop handles updates unchanged. Successful
    // streams reduce the "tx submitted → wallet observes" gap from
    // poll-interval-bounded (2 s) to network-RTT-bounded.
    let events = crate::sse_client::WalletEvents::new();
    let sse_shutdown = shutdown.clone();
    let sse_client = crate::sse_client::SseClient::new(store.clone(), node.clone(), events.clone());
    let sse_task = sse_client.spawn(sse_shutdown);

    // Optional indexer delegation — only lights up when --indexer-rpc
    // (or WALLETD_INDEXER_RPC) is set. Methods that need data outside
    // the wallet's owned keys (`list_settlements`, `contract_stats`,
    // `get_address_history`, `htlc_lookup_by_hashlock`,
    // `get_output_spent_by`) proxy through this client; when unset
    // they return -32041 IndexerNotConfigured.
    let indexer = match cfg.indexer_rpc.as_deref() {
        Some(urls) => {
            let timeout = std::time::Duration::from_secs(
                cfg.indexer_timeout_secs
                    .unwrap_or(cfg.upstream_timeout_secs),
            );
            tracing::info!(indexer_rpc = %urls, "indexer delegation enabled");
            Some(crate::indexer::IndexerClient::new(
                urls,
                cfg.indexer_token.as_deref(),
                timeout,
            )?)
        }
        None => None,
    };

    let inflight = Arc::new(InFlightUtxos::new());

    // Cross-chain swap engine — only when --swap-pool is configured. Opens the
    // encrypted journal (recovering any in-flight swaps) and spawns the monitor
    // that advances them to settlement / timeout-refund.
    let engine = match cfg.swap_pool_url.clone() {
        Some(pool_url) => {
            let journal = Arc::new(crate::swap::Journal::open(&wallet_dir, store.clone())?);
            let bnb_log = Arc::new(crate::swap::BnbTxLog::open(&wallet_dir, store.clone())?);
            let eng = Arc::new(crate::swap::SwapEngine::new(
                store.clone(),
                node.clone(),
                inflight.clone(),
                indexer.clone(),
                journal,
                bnb_log,
                crate::swap::EngineConfig {
                    pool_url,
                    pool_ca_pem: cfg.swap_pool_ca.clone(),
                    bsc_rpc_url: cfg.bsc_rpc_url.clone(),
                    bsc_chain_id: cfg.bsc_chain_id,
                },
            ));
            let mon = eng.clone();
            let mon_shutdown = shutdown.clone();
            tokio::spawn(async move { crate::swap::run_monitor(mon, mon_shutdown).await });
            tracing::info!(chain_id = cfg.bsc_chain_id, "swap engine enabled");
            Some(eng)
        }
        None => None,
    };

    let api = ApiState {
        store,
        node,
        inflight,
        idempotency: Arc::new(crate::idempotency::IdempotencyCache::new()),
        index,
        tip_rx,
        indexer,
        events: events.clone(),
        engine,
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
        app =
            add_tls_bootstrap_routes(app, material.cert_pem.clone(), material.fingerprint.clone());
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

        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
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
        events,
        shutdown,
        join,
        follower_task,
        sse_task,
    })
}
