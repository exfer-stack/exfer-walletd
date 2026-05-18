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

/// Startup check: refuse to bind a public interface without any token.
///
/// "Public" means an IP that is not a loopback. `0.0.0.0`, any LAN
/// address, and `::` (IPv6 any) all trip the check.
pub fn check_bind_is_safe(bind: std::net::SocketAddr, tokens: &Tokens) -> Result<()> {
    let is_loopback = bind.ip().is_loopback();
    if !is_loopback && !tokens.any_set() {
        return Err(Error::Internal(format!(
            "refusing to bind {bind} without any auth token configured. \
             Either set WALLETD_AUTH_TOKEN (or WALLETD_AUTH_TOKEN_SPEND) \
             before starting, or bind to 127.0.0.1 / ::1 to opt into the \
             open-API mode used for local development."
        )));
    }
    Ok(())
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
    fn bind_check_blocks_public_without_token() {
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let empty = Tokens::default();
        let one_token = Tokens::from_config(None, None, Some("x"));
        assert!(check_bind_is_safe(public, &empty).is_err());
        assert!(check_bind_is_safe(public, &one_token).is_ok());
        assert!(check_bind_is_safe(loopback, &empty).is_ok());
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
