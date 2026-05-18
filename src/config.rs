//! Runtime configuration. Sourced from CLI args (highest priority),
//! then environment variables, then defaults.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "exfer-walletd",
    about = "Exfer Wallet Daemon — independent service that manages wallets and exposes generate_address / transfer / balance over JSON-RPC, talking to one or more Exfer nodes (local or remote)",
    version
)]
pub struct Config {
    /// HTTP address the daemon listens on.
    #[arg(long, env = "WALLETD_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// JSON-RPC URL of one or more upstream Exfer nodes.
    /// Accepts a single URL or a comma-separated list — calls round-robin
    /// across them, failing over to the next on transport / 5xx error.
    /// The daemon is decoupled from the node: any reachable Exfer JSON-RPC
    /// endpoint works (loopback, LAN, internet, fly internal network).
    #[arg(long, env = "EXFER_NODE_RPC", default_value = "http://127.0.0.1:9334")]
    pub node_rpc: String,

    /// Directory holding `.key` wallet files.
    /// One file per managed address; filename is `<address>.key`.
    #[arg(
        long,
        env = "WALLETD_WALLET_DIR",
        default_value = "/var/lib/exfer-wallets"
    )]
    pub wallet_dir: PathBuf,

    /// Legacy single-scope bearer token. If set, treated as the
    /// **spend** token (full access). Prefer the two-scope flags below
    /// for new deployments.
    ///
    /// When neither this nor a scoped token is set, requests are
    /// permitted — but only when the daemon binds to loopback.
    /// Public-interface binds (e.g. `0.0.0.0`) without any token are
    /// refused at startup.
    #[arg(long, env = "WALLETD_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Read-scope bearer token. Grants every method **except** value-
    /// moving operations (`transfer`, `send_raw_transaction`). A
    /// deposit-watcher service typically only needs this scope —
    /// leaking it cannot lose funds.
    #[arg(long, env = "WALLETD_AUTH_TOKEN_READ")]
    pub auth_token_read: Option<String>,

    /// Spend-scope bearer token. Grants every method including
    /// `transfer` and `send_raw_transaction`. Implicitly grants read
    /// access too (so the spend service never needs both tokens).
    #[arg(long, env = "WALLETD_AUTH_TOKEN_SPEND")]
    pub auth_token_spend: Option<String>,

    /// Request timeout for upstream node calls (seconds).
    #[arg(long, env = "WALLETD_UPSTREAM_TIMEOUT_SECS", default_value_t = 30)]
    pub upstream_timeout_secs: u64,
}

impl Config {
    /// Load from CLI args + environment. Falls back to defaults for any
    /// unset value.
    pub fn from_env() -> Self {
        Self::parse()
    }
}
