//! Bearer-token authentication with three scopes — `read` < `manage` < `spend`.
//!
//! The wrapper supports configuring **three independent tokens**:
//!
//! - **`read`**: query-only methods (`get_balance`, `get_address_utxos`,
//!   `get_status`, `validate_address`, `list_addresses`, `verify_message`,
//!   `ping`, …). Deposit-watcher services usually need only this scope.
//! - **`manage`**: methods that mutate local walletd state but do not move
//!   funds (`generate_address`, `abandon_transfer`). A provisioning
//!   service that mints deposit addresses needs this.
//! - **`spend`**: value-moving methods (`transfer`, `send_raw_transaction`,
//!   `sign_message`). A withdrawal worker needs this.
//!
//! Containment: presenting the `spend` token satisfies any required scope;
//! `manage` satisfies `manage` and `read`; `read` only satisfies `read`.
//!
//! All three tokens are optional, but the daemon refuses to bind a public
//! interface without at least one configured (see `check_bind_is_safe`).
//!
//! All token comparisons are **constant-time** to defeat timing attacks.

use std::str::FromStr;

use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

// ----------------------------------------------------------------------------
// Scope
// ----------------------------------------------------------------------------

/// Per-method authority requirement. Ordered so that `Spend > Manage >
/// Read` — a presented token satisfies its own scope and every lower
/// scope (see [`Tokens::authenticate`]).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Read-only RPC (no state mutation, no funds movement).
    Read,
    /// Methods that mutate local walletd state but cannot move funds:
    /// `generate_address`, `abandon_transfer`.
    Manage,
    /// Operations that move funds OR mint value-bearing proofs.
    Spend,
}

impl Scope {
    /// Map an RPC method name to the scope it requires.
    ///
    /// `sign_message` is `Spend` even though it doesn't move funds: the
    /// signature is a verifiable proof of ownership over the wallet's
    /// key, and value-bearing in exchange / KYC contexts. A leaked
    /// read-only token must not be able to mint such proofs.
    ///
    /// `generate_address` is `Manage` (not `Read` as in v0.x): it
    /// creates persistent state on the keystore. Read-scope tokens
    /// must not write.
    pub fn for_method(method: &str) -> Scope {
        match method {
            "transfer"
            | "htlc_lock"
            | "htlc_claim"
            | "htlc_reclaim"
            | "send_raw_transaction"
            | "sign_message"
            | "reveal_mnemonic"
            | "reveal_private_key" => Scope::Spend,
            "generate_address" | "import_private_key" | "abandon_transfer" | "htlc_forget" => {
                Scope::Manage
            }
            _ => Scope::Read,
        }
    }
}

// ----------------------------------------------------------------------------
// Token bundle
// ----------------------------------------------------------------------------

/// Configured tokens. Any subset may be empty.
///
/// Containment is enforced at authenticate-time: presenting the
/// `spend` token always passes; `manage` passes for `manage` and `read`;
/// `read` only passes for `read`.
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    read: Option<Vec<u8>>,
    manage: Option<Vec<u8>>,
    spend: Option<Vec<u8>>,
}

impl Tokens {
    /// Build from the three scoped values. All three are independent;
    /// any combination of `None`s is legal.
    pub fn from_config(
        scoped_read: Option<&str>,
        scoped_manage: Option<&str>,
        scoped_spend: Option<&str>,
    ) -> Self {
        Self {
            read: scoped_read.map(|s| s.as_bytes().to_vec()),
            manage: scoped_manage.map(|s| s.as_bytes().to_vec()),
            spend: scoped_spend.map(|s| s.as_bytes().to_vec()),
        }
    }

    /// Whether at least one token is configured.
    pub fn any_set(&self) -> bool {
        self.read.is_some() || self.manage.is_some() || self.spend.is_some()
    }

    /// Authenticate an incoming request for the given scope. Constant
    /// time. Returns `Ok(())` if a configured token matches AND has
    /// sufficient scope; `Err(Unauthorized)` otherwise.
    pub fn authenticate(&self, headers: &HeaderMap, required: Scope) -> Result<()> {
        if !self.any_set() {
            // No tokens configured anywhere → open API. Startup safety
            // check ensures this only happens on loopback / private binds.
            return Ok(());
        }

        let supplied = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("")
            .as_bytes();

        // Spend token satisfies every scope.
        if let Some(ref t) = self.spend {
            if ct_eq(supplied, t) {
                return Ok(());
            }
        }
        // Manage token satisfies Manage and Read.
        if required <= Scope::Manage {
            if let Some(ref t) = self.manage {
                if ct_eq(supplied, t) {
                    return Ok(());
                }
            }
        }
        // Read token satisfies Read only.
        if required == Scope::Read {
            if let Some(ref t) = self.read {
                if ct_eq(supplied, t) {
                    return Ok(());
                }
            }
        }
        Err(Error::Unauthorized)
    }

    /// Stable description of which tokens are configured. Used in
    /// startup logs.
    pub fn description(&self) -> String {
        match (
            self.read.is_some(),
            self.manage.is_some(),
            self.spend.is_some(),
        ) {
            (false, false, false) => "no auth (open API — loopback only)".into(),
            (r, m, s) => {
                let mut parts = Vec::new();
                if r {
                    parts.push("read");
                }
                if m {
                    parts.push("manage");
                }
                if s {
                    parts.push("spend");
                }
                format!("scoped tokens: {}", parts.join(" + "))
            }
        }
    }
}

/// Constant-time byte comparison. Returns true iff `a == b`.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ----------------------------------------------------------------------------
// Bind-address safety
// ----------------------------------------------------------------------------

/// Coarse classification of where a bind address actually listens.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BindClass {
    /// 127.0.0.0/8, ::1 — never leaves the host's kernel.
    Loopback,
    /// RFC1918 (10/8, 172.16/12, 192.168/16), RFC3927 link-local
    /// (169.254/16), IPv6 ULA (fc00::/7), IPv6 link-local (fe80::/10).
    /// Reachable from a single LAN / VPC; not routable on the public
    /// internet.
    Private,
    /// Globally-routable IPs, plus the catch-all binds `0.0.0.0` and
    /// `::` which listen on *every* interface including any public one.
    Public,
}

pub fn classify_bind(ip: std::net::IpAddr) -> BindClass {
    use std::net::IpAddr;
    if ip.is_loopback() {
        return BindClass::Loopback;
    }
    if ip.is_unspecified() {
        // 0.0.0.0 / :: bind on every interface — must be treated as
        // public because we have no way to know whether the host has a
        // public NIC.
        return BindClass::Public;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                BindClass::Private
            } else {
                BindClass::Public
            }
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // fc00::/7 (Unique Local Address) — first byte is 0xfc or 0xfd.
            let ula = ((segs[0] >> 8) as u8 & 0xfe) == 0xfc;
            // fe80::/10 (link-local) — top 10 bits are 1111111010.
            let link_local = (segs[0] & 0xffc0) == 0xfe80;
            if ula || link_local {
                BindClass::Private
            } else {
                BindClass::Public
            }
        }
    }
}

/// Startup safety check on the bind address.
///
/// Rules:
///
/// - **Loopback** binds (127.x, ::1) are always permitted. No wire,
///   nothing to encrypt.
/// - **Private** binds (RFC1918, fc00::/7, link-local) are permitted.
///   Emit a warning if no token is set — clients on the same LAN can
///   call the API unauthenticated.
/// - **Public** binds (any globally routable IP, plus the catch-all
///   `0.0.0.0` / `::` that listens on every interface) are *refused*
///   by default. Without a TLS terminator in front of walletd, the
///   bearer token rides the wire as plaintext and can be captured by
///   any in-path observer. Pass `--allow-public-bind` (or set
///   `WALLETD_ALLOW_PUBLIC_BIND=1`) to acknowledge the risk — that's
///   the right opt-in for "I have Caddy / nginx / a cloud LB in front."
pub fn check_bind_is_safe(
    bind: std::net::SocketAddr,
    tokens: &Tokens,
    allow_public: bool,
    tls_enabled: bool,
) -> Result<()> {
    match classify_bind(bind.ip()) {
        BindClass::Loopback => Ok(()),
        BindClass::Private => {
            if !tokens.any_set() {
                tracing::warn!(
                    "binding to private address {bind} without an auth token \
                     — any client on this LAN can call walletd anonymously. \
                     Set WALLETD_AUTH_TOKEN_SPEND (and optionally _READ) \
                     unless you fully trust the network."
                );
            }
            Ok(())
        }
        BindClass::Public => {
            // No token + public bind is always wrong, regardless of TLS.
            // TLS protects the wire; it doesn't authenticate anyone.
            if !tokens.any_set() {
                return Err(Error::Internal(format!(
                    "refusing to bind {bind} on a public interface without any \
                     auth token. Set WALLETD_AUTH_TOKEN_SPEND before starting, \
                     or bind to 127.0.0.1 / a private address."
                )));
            }
            // TLS-on means the bearer token is encrypted on the wire,
            // so the explicit --allow-public-bind acknowledgement isn't
            // needed.
            if tls_enabled {
                return Ok(());
            }
            if !allow_public {
                return Err(Error::Internal(format!(
                    "refusing to bind {bind} directly on a public interface.\n\n\
                     Without TLS, the bearer token rides the wire as plaintext \
                     and any in-path observer (ISP, transit, target network) \
                     can capture it and spend every managed wallet.\n\n\
                     Recommended fix (in-process TLS, zero config):\n  \
                       --tls\n  \
                     walletd will generate a self-signed cert on first run \
                     and print the SHA-256 fingerprint for SDK pinning. See \
                     https://exfer-stack.github.io/exfer-walletd/quick-start.html.\n\n\
                     If you have an external TLS terminator (Caddy, nginx, \
                     k8s ingress, ALB, …) in front, acknowledge it with:\n  \
                       --allow-public-bind\n  \
                       (or WALLETD_ALLOW_PUBLIC_BIND=1)"
                )));
            }
            tracing::warn!(
                "binding to public interface {bind} with --allow-public-bind. \
                 walletd assumes you have a TLS terminator in front; if you \
                 don't, the bearer token will travel plaintext."
            );
            Ok(())
        }
    }
}

// ----------------------------------------------------------------------------
// Optional helper: parse Bearer header out of a HeaderMap.
// ----------------------------------------------------------------------------

/// Helper for tests and other diagnostics. Returns whatever the client
/// sent in `Authorization: Bearer <…>` or an empty string.
#[allow(dead_code)]
pub fn extract_bearer(headers: &HeaderMap) -> &str {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
}

// ----------------------------------------------------------------------------
// `Scope` <-> string (for logging only)
// ----------------------------------------------------------------------------

impl FromStr for Scope {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "read" => Ok(Scope::Read),
            "manage" => Ok(Scope::Manage),
            "spend" => Ok(Scope::Spend),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::Read => "read",
            Scope::Manage => "manage",
            Scope::Spend => "spend",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::SocketAddr;

    fn hdrs(token: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
            );
        }
        h
    }

    #[test]
    fn unset_tokens_accept_anything() {
        let toks = Tokens::default();
        assert!(toks.authenticate(&hdrs(None), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(None), Scope::Spend).is_ok());
        assert!(toks.authenticate(&hdrs(Some("x")), Scope::Spend).is_ok());
    }

    #[test]
    fn spend_token_grants_every_scope() {
        let toks = Tokens::from_config(None, None, Some("S"));
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Manage).is_ok());
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Spend).is_ok());
        assert!(matches!(
            toks.authenticate(&hdrs(Some("wrong")), Scope::Read),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn manage_token_grants_manage_and_read_but_not_spend() {
        let toks = Tokens::from_config(None, Some("M"), Some("S"));
        assert!(toks.authenticate(&hdrs(Some("M")), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(Some("M")), Scope::Manage).is_ok());
        assert!(matches!(
            toks.authenticate(&hdrs(Some("M")), Scope::Spend),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn read_token_grants_read_only() {
        let toks = Tokens::from_config(Some("R"), Some("M"), Some("S"));
        assert!(toks.authenticate(&hdrs(Some("R")), Scope::Read).is_ok());
        assert!(matches!(
            toks.authenticate(&hdrs(Some("R")), Scope::Manage),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            toks.authenticate(&hdrs(Some("R")), Scope::Spend),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn all_three_tokens_independent() {
        let toks = Tokens::from_config(Some("R"), Some("M"), Some("S"));
        // Each token only grants its own + lower scopes.
        for (tok, ok_read, ok_manage, ok_spend) in [
            ("R", true, false, false),
            ("M", true, true, false),
            ("S", true, true, true),
            ("WRONG", false, false, false),
        ] {
            assert_eq!(
                toks.authenticate(&hdrs(Some(tok)), Scope::Read).is_ok(),
                ok_read,
                "{tok} vs Read"
            );
            assert_eq!(
                toks.authenticate(&hdrs(Some(tok)), Scope::Manage).is_ok(),
                ok_manage,
                "{tok} vs Manage"
            );
            assert_eq!(
                toks.authenticate(&hdrs(Some(tok)), Scope::Spend).is_ok(),
                ok_spend,
                "{tok} vs Spend"
            );
        }
    }

    #[test]
    fn classify_bind_partitions_correctly() {
        use std::net::IpAddr;
        let cases = [
            ("127.0.0.1", BindClass::Loopback),
            ("127.4.5.6", BindClass::Loopback),
            ("::1", BindClass::Loopback),
            ("10.0.0.1", BindClass::Private),
            ("172.16.5.5", BindClass::Private),
            ("172.31.255.255", BindClass::Private),
            ("192.168.1.1", BindClass::Private),
            ("169.254.1.1", BindClass::Private), // link-local v4
            ("fc00::1", BindClass::Private),     // ULA
            ("fd12:3456::1", BindClass::Private),
            ("fe80::1", BindClass::Private), // link-local v6
            ("0.0.0.0", BindClass::Public),
            ("::", BindClass::Public),
            ("8.8.8.8", BindClass::Public),
            ("172.32.0.1", BindClass::Public), // just outside RFC1918 172.16/12
            ("2001:db8::1", BindClass::Public),
        ];
        for (ip_str, expected) in cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert_eq!(
                classify_bind(ip),
                expected,
                "{ip_str} should be {expected:?}"
            );
        }
    }

    #[test]
    fn bind_check_loopback_always_ok() {
        let lo: SocketAddr = "127.0.0.1:7448".parse().unwrap();
        assert!(check_bind_is_safe(lo, &Tokens::default(), false, false).is_ok());
        assert!(check_bind_is_safe(lo, &Tokens::default(), true, false).is_ok());
        assert!(check_bind_is_safe(lo, &Tokens::default(), false, true).is_ok());
    }

    #[test]
    fn bind_check_private_always_ok_but_warns_without_token() {
        let priv_addr: SocketAddr = "10.0.0.5:7448".parse().unwrap();
        assert!(check_bind_is_safe(priv_addr, &Tokens::default(), false, false).is_ok());
        let with_token = Tokens::from_config(None, None, Some("x"));
        assert!(check_bind_is_safe(priv_addr, &with_token, false, false).is_ok());
    }

    #[test]
    fn bind_check_public_without_token_refused_regardless_of_tls_or_ack() {
        let public: SocketAddr = "0.0.0.0:7448".parse().unwrap();
        let empty = Tokens::default();
        assert!(check_bind_is_safe(public, &empty, false, false).is_err());
        // --allow-public-bind without a token = still refused.
        assert!(check_bind_is_safe(public, &empty, true, false).is_err());
        // --tls without a token = still refused. TLS protects the wire,
        // not the API — anyone can hit it without auth.
        assert!(check_bind_is_safe(public, &empty, false, true).is_err());
    }

    #[test]
    fn bind_check_public_with_token_refused_without_tls_or_ack() {
        let public: SocketAddr = "0.0.0.0:7448".parse().unwrap();
        let with_token = Tokens::from_config(None, None, Some("x"));
        let err = check_bind_is_safe(public, &with_token, false, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to bind"));
        assert!(msg.contains("--tls"));
        assert!(msg.contains("--allow-public-bind"));
    }

    #[test]
    fn bind_check_public_with_token_and_allow_flag_succeeds() {
        let public: SocketAddr = "0.0.0.0:7448".parse().unwrap();
        let with_token = Tokens::from_config(None, None, Some("x"));
        assert!(check_bind_is_safe(public, &with_token, true, false).is_ok());
    }

    #[test]
    fn bind_check_public_with_token_and_tls_succeeds_without_ack() {
        let public: SocketAddr = "0.0.0.0:7448".parse().unwrap();
        let with_token = Tokens::from_config(None, None, Some("x"));
        // TLS-on relaxes the --allow-public-bind requirement.
        assert!(check_bind_is_safe(public, &with_token, false, true).is_ok());
    }

    #[test]
    fn method_scope_mapping_is_strict() {
        assert_eq!(Scope::for_method("transfer"), Scope::Spend);
        assert_eq!(Scope::for_method("htlc_lock"), Scope::Spend);
        assert_eq!(Scope::for_method("htlc_claim"), Scope::Spend);
        assert_eq!(Scope::for_method("htlc_reclaim"), Scope::Spend);
        assert_eq!(Scope::for_method("send_raw_transaction"), Scope::Spend);
        assert_eq!(Scope::for_method("sign_message"), Scope::Spend);
        assert_eq!(Scope::for_method("generate_address"), Scope::Manage);
        assert_eq!(Scope::for_method("abandon_transfer"), Scope::Manage);
        assert_eq!(Scope::for_method("get_block_height"), Scope::Read);
        assert_eq!(Scope::for_method("verify_message"), Scope::Read);
        assert_eq!(Scope::for_method("ping"), Scope::Read);
    }
}
