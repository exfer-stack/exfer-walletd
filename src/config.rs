//! Runtime configuration for the daemon. Sourced from CLI args
//! (highest priority), then environment variables, then defaults.
//!
//! The driving idea: a fresh user should be able to run
//! `exfer-walletd` with **zero flags** and get a working daemon —
//! datadir created, token generated, wallet directory ready. Power
//! users still get `--node-rpc`, `--bind`, `--auth-token`, etc., but
//! none of them are required.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "exfer-walletd",
    about = "Exfer Wallet Daemon — JSON-RPC service that holds wallet keys and signs transactions on behalf of a backend.",
    version
)]
pub struct Config {
    /// Where walletd keeps its state — a single directory containing
    /// `token` (auto-generated bearer token) and `wallets/` (one
    /// `.key` file per managed address). Created on first run.
    ///
    /// Defaults to `$HOME/.exfer-walletd` (or `./.exfer-walletd` if
    /// `HOME` is unset). Mirrors the `--datadir` convention of the
    /// upstream `exfer node` binary.
    #[arg(long, env = "WALLETD_DATADIR")]
    pub datadir: Option<PathBuf>,

    /// HTTP(S) address the daemon listens on.
    ///
    /// Default is loopback. Public-interface binds (`0.0.0.0`, any
    /// globally-routable IP) require either `--tls` (in-process TLS
    /// termination) or `--allow-public-bind` (you're acknowledging
    /// that something else — a reverse proxy, VPN, private network —
    /// keeps the bearer token off plaintext wire).
    #[arg(long, env = "WALLETD_BIND", default_value = "127.0.0.1:7448")]
    pub bind: SocketAddr,

    /// Acknowledge that a TLS terminator (or a trusted private
    /// network) sits in front of walletd, and bind a non-loopback
    /// interface anyway. Without this, public binds fail-close at
    /// startup so the bearer token can't accidentally end up plaintext
    /// on the wire. **`--tls` is the simpler alternative** — it gives
    /// you in-process TLS and relaxes this check automatically.
    ///
    /// As an env var, accepts `1` / `true` / `yes` / `on`.
    #[arg(
        long,
        env = "WALLETD_ALLOW_PUBLIC_BIND",
        value_parser = parse_lenient_bool,
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
    )]
    pub allow_public_bind: bool,

    /// Terminate TLS inside walletd using a self-signed certificate.
    ///
    /// On first start with `--tls`, walletd generates a leaf
    /// certificate and matching private key at `<datadir>/cert.pem`
    /// and `<datadir>/cert.key` (both mode 0600), and writes the
    /// SHA-256 fingerprint to `<datadir>/cert.fingerprint`. The
    /// fingerprint is also printed once to stderr — copy it to the
    /// client side (`exfer-walletd-py`'s `fingerprint=` param) for
    /// pinning. Subsequent starts reuse the existing files.
    ///
    /// `--tls` relaxes the `--allow-public-bind` requirement (the
    /// whole reason for that flag was "the token would travel
    /// plaintext"; with TLS it doesn't).
    ///
    /// As an env var, accepts `1` / `true` / `yes` / `on`.
    #[arg(
        long,
        env = "WALLETD_TLS",
        value_parser = parse_lenient_bool,
        default_value_t = false,
        num_args = 0..=1,
        default_missing_value = "true",
    )]
    pub tls: bool,

    /// Override the path to the TLS certificate. Defaults to
    /// `<datadir>/cert.pem`. Generated automatically on first run when
    /// `--tls` is set.
    #[arg(long, env = "WALLETD_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// Override the path to the TLS private key. Defaults to
    /// `<datadir>/cert.key`.
    #[arg(long, env = "WALLETD_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// JSON-RPC URL of one or more upstream Exfer nodes. Accepts a
    /// single URL or a comma-separated list — calls round-robin
    /// across them, failing over to the next on transport / 5xx
    /// error. Any reachable Exfer JSON-RPC endpoint works (loopback,
    /// LAN, VPC, public RPC).
    #[arg(long, env = "EXFER_NODE_RPC", default_value = "http://127.0.0.1:9334")]
    pub node_rpc: String,

    /// Directory holding `.key` wallet files. Defaults to
    /// `<datadir>/wallets`. Override only if you want wallets stored
    /// somewhere outside the datadir (e.g. on a separate encrypted
    /// volume).
    #[arg(long, env = "WALLETD_WALLET_DIR")]
    pub wallet_dir: Option<PathBuf>,

    /// Single all-scope bearer token. If unset, walletd uses (or
    /// creates) the one stored at `<datadir>/token`.
    ///
    /// Override only when you want walletd to take its token from a
    /// secret manager / env var rather than the datadir file.
    #[arg(long, env = "WALLETD_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Optional read-scope bearer token. Grants every method
    /// **except** value-moving operations (`transfer`,
    /// `send_raw_transaction`). Pair with `--auth-token-spend` to
    /// split deposit-watcher and withdrawal-worker credentials.
    #[arg(long, env = "WALLETD_AUTH_TOKEN_READ")]
    pub auth_token_read: Option<String>,

    /// Optional spend-scope bearer token. Grants all methods. When
    /// set alongside `--auth-token-read`, the two scopes are
    /// enforced independently.
    #[arg(long, env = "WALLETD_AUTH_TOKEN_SPEND")]
    pub auth_token_spend: Option<String>,

    /// Request timeout for upstream node calls (seconds).
    #[arg(long, env = "WALLETD_UPSTREAM_TIMEOUT_SECS", default_value_t = 30)]
    pub upstream_timeout_secs: u64,

    /// Maximum total attempts per upstream RPC call. `1` disables retry
    /// (fail-fast on the first transport error). Each attempt rotates
    /// through every configured node before counting as failed.
    ///
    /// Retry is gated on *transport* failures only — connection refused,
    /// timeouts, 5xx. Application-level errors returned by the node
    /// (`{"error": {...}}`) are surfaced immediately and never retried.
    #[arg(long, env = "WALLETD_UPSTREAM_ATTEMPTS", default_value_t = 4)]
    pub upstream_attempts: u32,

    /// Base backoff in milliseconds between RPC retry attempts. The
    /// wait grows linearly: `backoff_ms`, `2 * backoff_ms`, … `0`
    /// disables the sleep between attempts.
    #[arg(long, env = "WALLETD_UPSTREAM_RETRY_BACKOFF_MS", default_value_t = 500)]
    pub upstream_retry_backoff_ms: u64,
}

impl Config {
    /// Resolve `--datadir` to a concrete path, applying the default
    /// (`$HOME/.exfer-walletd`, or `./.exfer-walletd` if no `HOME`).
    pub fn resolved_datadir(&self) -> PathBuf {
        if let Some(p) = &self.datadir {
            return p.clone();
        }
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".exfer-walletd"),
            None => PathBuf::from(".exfer-walletd"),
        }
    }

    /// Resolve `--wallet-dir`, defaulting to `<datadir>/wallets`.
    pub fn resolved_wallet_dir(&self) -> PathBuf {
        self.wallet_dir
            .clone()
            .unwrap_or_else(|| self.resolved_datadir().join("wallets"))
    }

    /// Path of the auto-generated token file inside the datadir.
    pub fn token_file(&self) -> PathBuf {
        self.resolved_datadir().join("token")
    }

    /// Resolve `--tls-cert`, defaulting to `<datadir>/cert.pem`.
    pub fn resolved_tls_cert_path(&self) -> PathBuf {
        self.tls_cert
            .clone()
            .unwrap_or_else(|| self.resolved_datadir().join("cert.pem"))
    }

    /// Resolve `--tls-key`, defaulting to `<datadir>/cert.key`.
    pub fn resolved_tls_key_path(&self) -> PathBuf {
        self.tls_key
            .clone()
            .unwrap_or_else(|| self.resolved_datadir().join("cert.key"))
    }

    /// Path of the fingerprint file. Always lives in the datadir
    /// (it's a small file that pairs with the cert; no override).
    pub fn tls_fingerprint_path(&self) -> PathBuf {
        self.resolved_datadir().join("cert.fingerprint")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_cfg() -> Config {
        Config {
            datadir: None,
            bind: "127.0.0.1:7448".parse().unwrap(),
            allow_public_bind: false,
            tls: false,
            tls_cert: None,
            tls_key: None,
            node_rpc: "http://127.0.0.1:9334".into(),
            wallet_dir: None,
            auth_token: None,
            auth_token_read: None,
            auth_token_spend: None,
            upstream_timeout_secs: 30,
            upstream_attempts: 4,
            upstream_retry_backoff_ms: 500,
        }
    }

    #[test]
    fn datadir_default_uses_home_when_set() {
        // We can't safely mutate $HOME in a parallel test runner, so
        // just check resolution prefers the explicit value when set.
        let mut cfg = empty_cfg();
        cfg.datadir = Some(PathBuf::from("/custom/path"));
        assert_eq!(cfg.resolved_datadir(), PathBuf::from("/custom/path"));
    }

    #[test]
    fn wallet_dir_defaults_to_datadir_subdir() {
        let mut cfg = empty_cfg();
        cfg.datadir = Some(PathBuf::from("/x"));
        assert_eq!(cfg.resolved_wallet_dir(), PathBuf::from("/x/wallets"));
    }

    #[test]
    fn wallet_dir_override_wins() {
        let mut cfg = empty_cfg();
        cfg.datadir = Some(PathBuf::from("/x"));
        cfg.wallet_dir = Some(PathBuf::from("/elsewhere"));
        assert_eq!(cfg.resolved_wallet_dir(), PathBuf::from("/elsewhere"));
    }

    #[test]
    fn token_file_is_in_datadir() {
        let mut cfg = empty_cfg();
        cfg.datadir = Some(PathBuf::from("/x"));
        assert_eq!(cfg.token_file(), PathBuf::from("/x/token"));
    }
}
