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

/// On-disk paths for the three auto-generated scoped token files.
#[derive(Debug, Clone)]
pub struct ScopedTokenPaths {
    pub read: PathBuf,
    pub manage: PathBuf,
    pub spend: PathBuf,
}

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

    /// Extra `subjectAltName` entries to add to the auto-generated
    /// self-signed cert. Comma-separated, each entry is either an IP
    /// or a DNS name; loopback and `0.0.0.0` are ignored.
    ///
    /// The bound IP is always included automatically. Use this when
    /// `--bind 0.0.0.0:7448` is paired with clients that connect by
    /// hostname or VPC IP and do strict CA-style verification
    /// (`curl --cacert`, Java HttpsURLConnection, …). The SDK's
    /// fingerprint-pinning path is unaffected — it never looks at SAN.
    ///
    /// Only consulted on first-run cert generation. After the cert
    /// trio exists, delete `cert.{pem,key,fingerprint}` and restart to
    /// regenerate with a new SAN set.
    #[arg(long, env = "WALLETD_TLS_SAN", value_delimiter = ',')]
    pub tls_san: Vec<String>,

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

    /// Read-scope bearer token. Grants query-only methods (`get_*`,
    /// `list_addresses`, `validate_address`, `verify_message`, `ping`).
    /// If all three `--auth-token-*` flags are unset, walletd
    /// auto-generates them on first run and stores them at
    /// `<datadir>/token-{read,manage,spend}`.
    #[arg(long, env = "WALLETD_AUTH_TOKEN_READ")]
    pub auth_token_read: Option<String>,

    /// Manage-scope bearer token. Grants methods that mutate local
    /// walletd state but cannot move funds (`generate_address`,
    /// `abandon_transfer`). Implies `read`.
    #[arg(long, env = "WALLETD_AUTH_TOKEN_MANAGE")]
    pub auth_token_manage: Option<String>,

    /// Spend-scope bearer token. Grants value-moving methods
    /// (`transfer`, `send_raw_transaction`, `sign_message`). Implies
    /// `manage` and `read`.
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

    /// Optional URL of an exfer-indexer service. When set, the
    /// observability methods that need data outside this wallet's
    /// owned keys (`htlc_status` on an unknown lock_tx_id,
    /// `htlc_list` with an explicit non-owned `address`, plus the
    /// new `list_settlements` / `contract_stats` /
    /// `get_address_history` / `htlc_lookup_by_hashlock` proxies)
    /// transparently delegate to the indexer.
    ///
    /// When unset, queries for non-owned data return
    /// `-32007 IndexerNotConfigured`. Queries for owned data continue
    /// to work entirely from walletd's local index.
    ///
    /// Multiple comma-separated URLs are accepted; the indexer client
    /// round-robins across them with the same retry semantics as the
    /// node-RPC fan-out.
    #[arg(long, env = "WALLETD_INDEXER_RPC")]
    pub indexer_rpc: Option<String>,

    /// Bearer token for the indexer (matches the indexer's
    /// `--auth-token`). Only meaningful when `--indexer-rpc` is set.
    #[arg(long, env = "WALLETD_INDEXER_TOKEN")]
    pub indexer_token: Option<String>,

    /// Request timeout for indexer calls (seconds). Defaults to the
    /// upstream-node timeout.
    #[arg(long, env = "WALLETD_INDEXER_TIMEOUT_SECS")]
    pub indexer_timeout_secs: Option<u64>,

    /// exfer-pool base URL (the market-maker bot for EXFER↔USDT swaps). When
    /// set, the swap engine + monitor light up and the `swap_*` / `bsc_*` RPCs
    /// become answerable. Unset → swaps return -32602 ("swap not configured").
    #[arg(long, env = "WALLETD_SWAP_POOL")]
    pub swap_pool_url: Option<String>,

    /// BSC JSON-RPC endpoint for the swap engine's USDT leg. Defaults to BSC
    /// mainnet; point at a testnet dataseed (chain 97) for QA.
    #[arg(
        long,
        env = "WALLETD_BSC_RPC",
        default_value = "https://bsc-dataseed1.binance.org"
    )]
    pub bsc_rpc_url: String,

    /// BSC chain id (56 mainnet, 97 Chapel testnet).
    #[arg(long, env = "WALLETD_BSC_CHAIN_ID", default_value_t = 56)]
    pub bsc_chain_id: u64,

    /// USDT (BEP-20) token address on BSC — used to show the derived address's
    /// USDT balance for the buy-direction pre-flight. Defaults to mainnet USDT;
    /// override for testnet.
    #[arg(
        long,
        env = "WALLETD_BSC_USDT",
        default_value = "0x55d398326f99059fF775485246999027B3197955"
    )]
    pub bsc_usdt_address: String,
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

    /// Paths of the three auto-generated scoped token files inside the
    /// datadir. Only consulted on first-run when an `auth_token_*` flag
    /// is unset; once written, the env-supplied value wins on later
    /// starts (so an operator can transition to a secret manager
    /// without re-keying).
    pub fn token_files(&self) -> ScopedTokenPaths {
        let dd = self.resolved_datadir();
        ScopedTokenPaths {
            read: dd.join("token-read"),
            manage: dd.join("token-manage"),
            spend: dd.join("token-spend"),
        }
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
            tls_san: Vec::new(),
            node_rpc: "http://127.0.0.1:9334".into(),
            wallet_dir: None,
            auth_token_read: None,
            auth_token_manage: None,
            auth_token_spend: None,
            upstream_timeout_secs: 30,
            upstream_attempts: 4,
            upstream_retry_backoff_ms: 500,
            indexer_rpc: None,
            indexer_token: None,
            indexer_timeout_secs: None,
            swap_pool_url: None,
            bsc_rpc_url: "https://bsc-dataseed1.binance.org".into(),
            bsc_chain_id: 56,
            bsc_usdt_address: "0x55d398326f99059fF775485246999027B3197955".into(),
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
    fn token_files_live_in_datadir() {
        let mut cfg = empty_cfg();
        cfg.datadir = Some(PathBuf::from("/x"));
        let p = cfg.token_files();
        assert_eq!(p.read, PathBuf::from("/x/token-read"));
        assert_eq!(p.manage, PathBuf::from("/x/token-manage"));
        assert_eq!(p.spend, PathBuf::from("/x/token-spend"));
    }
}
