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

    /// Optional bearer token for incoming requests. If unset, the API
    /// is open — only do this on a trusted private network.
    #[arg(long, env = "WALLETD_AUTH_TOKEN")]
    pub auth_token: Option<String>,

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
