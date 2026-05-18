//! Bearer-token authentication with two scopes (`read` and `spend`).
//!
//! The wrapper supports configuring **two independent tokens**:
//!
//! - The **read** token grants every method *except* spending: balance
//!   lookups, UTXO listings, address generation, list, ping. A deposit-
//!   watcher service typically only needs this scope.
//! - The **spend** token grants everything, including `transfer` and
//!   `send_raw_transaction`. A withdrawal worker needs this.
//!
//! Operators can:
//!
//! - Set both tokens and split duties between services.
//! - Set only `auth_token_spend` (or the legacy single `auth_token`) and
//!   use one token for everything.
//! - Set neither — but only if the daemon binds to a loopback address.
//!   Public binds without a token are refused at startup.
//!
//! All token comparisons are **constant-time** to defeat timing attacks.

use std::str::FromStr;

use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

// ----------------------------------------------------------------------------
// Scope
// ----------------------------------------------------------------------------

/// Per-method authority requirement.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Read-only RPC + address management (no value at risk).
    Read,
    /// Operations that move funds. Includes `Read`.
    Spend,
}

impl Scope {
    /// Map an RPC method name to the scope it requires.
    pub fn for_method(method: &str) -> Scope {
        match method {
            "transfer" | "send_raw_transaction" => Scope::Spend,
            _ => Scope::Read,
        }
    }
}

// ----------------------------------------------------------------------------
// Token bundle
// ----------------------------------------------------------------------------

/// Configured tokens. Either or both may be empty.
///
/// Construction rules (see [`Tokens::from_config`]):
///
/// - Legacy `auth_token` is treated as the **spend** token if set
///   alone. If both legacy and scoped tokens are set, scoped wins.
/// - The spend token implicitly grants read access (you don't need to
///   present it twice).
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    read: Option<Vec<u8>>,
    spend: Option<Vec<u8>>,
}

impl Tokens {
    pub fn from_config(
        legacy: Option<&str>,
        scoped_read: Option<&str>,
        scoped_spend: Option<&str>,
    ) -> Self {
        let read = scoped_read.map(|s| s.as_bytes().to_vec());
        // Legacy single-token folds into spend (everything-grants).
        let spend = scoped_spend
            .map(|s| s.as_bytes().to_vec())
            .or_else(|| legacy.map(|s| s.as_bytes().to_vec()));
        Self { read, spend }
    }

    /// Whether at least one token is configured.
    pub fn any_set(&self) -> bool {
        self.read.is_some() || self.spend.is_some()
    }

    /// Authenticate an incoming request for the given scope. Constant
    /// time. Returns `Ok(())` if a configured token matches; `Err` if
    /// the supplied token is wrong, missing, or insufficient for the
    /// required scope.
    pub fn authenticate(&self, headers: &HeaderMap, required: Scope) -> Result<()> {
        // If no tokens configured anywhere, requests are permitted —
        // the startup check ensures this is only allowed on loopback.
        if !self.any_set() {
            return Ok(());
        }

        let supplied = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("")
            .as_bytes();

        // Spend token grants every scope.
        if let Some(ref spend) = self.spend {
            if ct_eq(supplied, spend) {
                return Ok(());
            }
        }
        // Read scope additionally accepts the read token.
        if required == Scope::Read {
            if let Some(ref read) = self.read {
                if ct_eq(supplied, read) {
                    return Ok(());
                }
            }
        }
        Err(Error::Unauthorized)
    }

    /// Stable description of which tokens are configured. Used in
    /// startup logs.
    pub fn description(&self) -> String {
        match (self.read.is_some(), self.spend.is_some()) {
            (false, false) => "no auth (open API — loopback only)".into(),
            (false, true) => "single token (spend, grants all)".into(),
            (true, false) => "single token (read-only — spend disabled)".into(),
            (true, true) => "two tokens (read + spend)".into(),
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
            if !tokens.any_set() {
                return Err(Error::Internal(format!(
                    "refusing to bind {bind} on a public interface without any \
                     auth token. Set WALLETD_AUTH_TOKEN_SPEND before starting, \
                     or bind to 127.0.0.1 / a private address."
                )));
            }
            if !allow_public {
                return Err(Error::Internal(format!(
                    "refusing to bind {bind} directly on a public interface.\n\n\
                     Without a TLS terminator (Caddy, nginx, Cloudflare, \
                     k8s ingress, a cloud load balancer, …) in front of \
                     walletd, the bearer token rides the wire as plaintext \
                     and any in-path observer (ISP, transit, target \
                     network) can capture it and spend every managed \
                     wallet.\n\n\
                     Recommended fix:\n  \
                       --bind 127.0.0.1:8080\n  \
                     and put Caddy in front for automatic TLS. See \
                     https://exfer-stack.github.io/exfer-walletd/#production-deploy.\n\n\
                     If you really do have a TLS terminator in front \
                     (k8s ingress, ALB, …), acknowledge it with:\n  \
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
            "spend" => Ok(Scope::Spend),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::Read => "read",
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
    fn spend_token_grants_read() {
        let toks = Tokens::from_config(None, None, Some("S"));
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Spend).is_ok());
        assert!(matches!(
            toks.authenticate(&hdrs(Some("wrong")), Scope::Read),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn read_token_does_not_grant_spend() {
        let toks = Tokens::from_config(None, Some("R"), Some("S"));
        // R is only valid for Read
        assert!(toks.authenticate(&hdrs(Some("R")), Scope::Read).is_ok());
        assert!(matches!(
            toks.authenticate(&hdrs(Some("R")), Scope::Spend),
            Err(Error::Unauthorized)
        ));
        // S is valid for both
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(Some("S")), Scope::Spend).is_ok());
    }

    #[test]
    fn legacy_token_acts_as_spend() {
        let toks = Tokens::from_config(Some("L"), None, None);
        assert!(toks.authenticate(&hdrs(Some("L")), Scope::Read).is_ok());
        assert!(toks.authenticate(&hdrs(Some("L")), Scope::Spend).is_ok());
    }

    #[test]
    fn scoped_spend_overrides_legacy() {
        let toks = Tokens::from_config(Some("LEGACY"), None, Some("NEW"));
        // Legacy no longer authenticates if scoped spend is set.
        assert!(matches!(
            toks.authenticate(&hdrs(Some("LEGACY")), Scope::Spend),
            Err(Error::Unauthorized)
        ));
        assert!(toks.authenticate(&hdrs(Some("NEW")), Scope::Spend).is_ok());
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
        let lo: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(check_bind_is_safe(lo, &Tokens::default(), false).is_ok());
        assert!(check_bind_is_safe(lo, &Tokens::default(), true).is_ok());
    }

    #[test]
    fn bind_check_private_always_ok_but_warns_without_token() {
        let priv_addr: SocketAddr = "10.0.0.5:8080".parse().unwrap();
        assert!(check_bind_is_safe(priv_addr, &Tokens::default(), false).is_ok());
        let with_token = Tokens::from_config(None, None, Some("x"));
        assert!(check_bind_is_safe(priv_addr, &with_token, false).is_ok());
    }

    #[test]
    fn bind_check_public_without_token_refused_either_way() {
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let empty = Tokens::default();
        assert!(check_bind_is_safe(public, &empty, false).is_err());
        // Even with --allow-public-bind, no token = still refused.
        assert!(check_bind_is_safe(public, &empty, true).is_err());
    }

    #[test]
    fn bind_check_public_with_token_refused_without_allow_flag() {
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let with_token = Tokens::from_config(None, None, Some("x"));
        let err = check_bind_is_safe(public, &with_token, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to bind"));
        assert!(msg.contains("--allow-public-bind"));
    }

    #[test]
    fn bind_check_public_with_token_and_allow_flag_succeeds() {
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let with_token = Tokens::from_config(None, None, Some("x"));
        assert!(check_bind_is_safe(public, &with_token, true).is_ok());
    }

    #[test]
    fn method_scope_mapping_is_strict() {
        assert_eq!(Scope::for_method("transfer"), Scope::Spend);
        assert_eq!(Scope::for_method("send_raw_transaction"), Scope::Spend);
        assert_eq!(Scope::for_method("get_block_height"), Scope::Read);
        assert_eq!(Scope::for_method("generate_address"), Scope::Read);
        assert_eq!(Scope::for_method("ping"), Scope::Read);
    }
}
