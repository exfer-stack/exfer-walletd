//! Runtime configuration for the daemon. Sourced from CLI args
//! (highest priority), then environment variables, then defaults.
//!
//! `Config` is `clap::Args`, not `clap::Parser`, because it flattens
//! into [`crate::cli::Cli`] alongside the optional subcommands.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// HTTP address the daemon listens on.
    ///
    /// Default is loopback. Public-interface binds (`0.0.0.0`, any
    /// globally-routable IP) require `--allow-public-bind` because
    /// walletd does not terminate TLS itself — the bearer token would
    /// otherwise travel plaintext on the wire.
    #[arg(long, env = "WALLETD_BIND", default_value = "127.0.0.1:8080")]
    pub bind: SocketAddr,

    /// Acknowledge that a TLS terminator (Caddy, nginx, Cloudflare,
    /// k8s ingress, an upstream cloud load balancer, …) sits in front
    /// of walletd, and bind a public interface anyway. Without this
    /// flag, public binds are refused at startup so the bearer token
    /// can't accidentally travel plaintext.
    ///
    /// As an env var, accepts `1` / `true` / `yes` / `on` (case-
    /// insensitive). Anything else is treated as "off."
    #[arg(
        long,
        env = "WALLETD_ALLOW_PUBLIC_BIND",
        value_parser = parse_lenient_bool,
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
    )]
    pub allow_public_bind: bool,

    /// JSON-RPC URL of one or more upstream Exfer nodes.
    /// Accepts a single URL or a comma-separated list — calls round-robin
    /// across them, failing over to the next on transport / 5xx error.
    /// The daemon is decoupled from the node: any reachable Exfer JSON-RPC
    /// endpoint works (loopback, LAN, VPC, public RPC).
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

    /// Legacy single-token mode. If set, grants every method (read +
    /// spend). Prefer the two-scope flags below for new deployments.
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

/// Accept Unix-style booleans ("1", "yes", "on") in addition to the
/// Rust-style "true"/"false" that clap's default parser expects.
fn parse_lenient_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(format!(
            "expected 1/0, true/false, yes/no, or on/off — got {other:?}"
        )),
    }
}
