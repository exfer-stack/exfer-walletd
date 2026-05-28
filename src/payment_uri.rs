//! `exfer:` URI codec — a BIP21-style payment request encoding.
//!
//! Format
//!
//! ```text
//!   exfer:<address>[?amount=N[&memo=...][&hash_lock=HEX][&timeout=N][&label=...]]
//! ```
//!
//! - `<address>` is the canonical 64-character lowercase hex Exfer
//!   address (Phase 1 = `domain_hash(EXFER-ADDR, pubkey)`).
//! - `amount` is a u64 in base units (`exfers`); `1 EXFER =
//!   100_000_000 exfers`. Omitted for "any amount" requests.
//! - `memo` and `label` are free-form UTF-8 strings, percent-encoded
//!   per RFC 3986 unreserved (`[A-Za-z0-9-._~]` literal, everything
//!   else `%HH`). Decoders MUST tolerate any sequence that round-trips.
//! - `hash_lock` and `timeout` accompany HTLC requests so the payer
//!   has every parameter needed to call `htlc_lock` against the payee.
//! - Unknown query parameters are silently ignored on decode for
//!   forward-compatibility.
//!
//! This module is a **pure** codec: no I/O, no clock, no key access.
//! It is exposed via the `payment_uri_encode` / `payment_uri_decode`
//! JSON-RPC methods (Read scope) so any client can roundtrip URIs
//! without re-implementing the format. Wallets that prefer to format
//! URIs themselves can use this crate as a reference.

use serde::{Deserialize, Serialize};

/// Decoded URI fields. Matches the JSON-RPC params/response shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentUri {
    /// 64-character lowercase hex address.
    pub address: String,
    /// Amount in base units (exfers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Free-form payer-visible memo (UTF-8, percent-decoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// 64-character lowercase hex SHA-256 hashlock (for HTLC requests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_lock: Option<String>,
    /// Absolute timeout block height (for HTLC requests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Optional short label, distinct from `memo` (typically the payee
    /// name as seen by the payer's wallet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Errors raised by [`decode`]. [`encode`] is infallible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentUriError {
    WrongScheme,
    BadAddress,
    MalformedQuery,
    BadAmount,
    BadHashLock,
    BadTimeout,
    InvalidUtf8,
}

impl std::fmt::Display for PaymentUriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            PaymentUriError::WrongScheme => "URI does not start with `exfer:`",
            PaymentUriError::BadAddress => {
                "address must be 64 lowercase hex characters"
            }
            PaymentUriError::MalformedQuery => "malformed query string",
            PaymentUriError::BadAmount => "amount must be a non-negative integer",
            PaymentUriError::BadHashLock => {
                "hash_lock must be 64 lowercase hex characters"
            }
            PaymentUriError::BadTimeout => "timeout must be a non-negative integer",
            PaymentUriError::InvalidUtf8 => "percent-decoded bytes are not valid UTF-8",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PaymentUriError {}

/// Encode a [`PaymentUri`] into its canonical wire form. Caller is
/// responsible for ensuring `address` / `hash_lock` are well-formed —
/// `encode` does not re-validate them on the assumption it's getting
/// data that already passed through the JSON-RPC layer.
pub fn encode(p: &PaymentUri) -> String {
    let mut uri = String::with_capacity(72 + p.address.len());
    uri.push_str("exfer:");
    uri.push_str(&p.address);

    let mut first = true;
    let mut push_param = |uri: &mut String, key: &str, value: &str| {
        uri.push(if first { '?' } else { '&' });
        first = false;
        uri.push_str(key);
        uri.push('=');
        uri.push_str(value);
    };

    if let Some(a) = p.amount {
        push_param(&mut uri, "amount", &a.to_string());
    }
    if let Some(ref m) = p.memo {
        push_param(&mut uri, "memo", &percent_encode(m));
    }
    if let Some(ref h) = p.hash_lock {
        push_param(&mut uri, "hash_lock", h);
    }
    if let Some(t) = p.timeout {
        push_param(&mut uri, "timeout", &t.to_string());
    }
    if let Some(ref l) = p.label {
        push_param(&mut uri, "label", &percent_encode(l));
    }
    uri
}

/// Decode an `exfer:` URI. Unknown query keys are tolerated and
/// dropped — clients implementing future extensions can include
/// parameters that older decoders simply ignore.
pub fn decode(uri: &str) -> Result<PaymentUri, PaymentUriError> {
    let rest = uri
        .strip_prefix("exfer:")
        .ok_or(PaymentUriError::WrongScheme)?;
    let (address, query) = match rest.find('?') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };

    if address.len() != 64 {
        return Err(PaymentUriError::BadAddress);
    }
    // Phase 1 addresses are lowercase hex. Accept any-case for input
    // tolerance, but normalise to lowercase before storing so the
    // round-trip is canonical.
    if !address.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PaymentUriError::BadAddress);
    }

    let mut out = PaymentUri {
        address: address.to_ascii_lowercase(),
        ..Default::default()
    };

    let Some(q) = query else {
        return Ok(out);
    };
    // An empty query (`exfer:<addr>?`) is technically valid; just no params.
    if q.is_empty() {
        return Ok(out);
    }
    for kv in q.split('&') {
        let (k, v) = kv.split_once('=').ok_or(PaymentUriError::MalformedQuery)?;
        match k {
            "amount" => {
                out.amount = Some(v.parse().map_err(|_| PaymentUriError::BadAmount)?);
            }
            "memo" => {
                out.memo = Some(percent_decode(v)?);
            }
            "hash_lock" => {
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(PaymentUriError::BadHashLock);
                }
                out.hash_lock = Some(v.to_ascii_lowercase());
            }
            "timeout" => {
                out.timeout = Some(v.parse().map_err(|_| PaymentUriError::BadTimeout)?);
            }
            "label" => {
                out.label = Some(percent_decode(v)?);
            }
            _ => { /* forward-compatible: ignore unknown */ }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Percent-encoding (RFC 3986 unreserved set only)
// ---------------------------------------------------------------------------

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 0x0F));
            }
        }
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

fn percent_decode(s: &str) -> Result<String, PaymentUriError> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(PaymentUriError::MalformedQuery);
            }
            let hi = parse_hex_nibble(bytes[i + 1])?;
            let lo = parse_hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            // BIP21 uses %20 for spaces; we deliberately do NOT decode
            // '+' as space (that's form-data, not URI). Pass through.
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PaymentUriError::InvalidUtf8)
}

fn parse_hex_nibble(b: u8) -> Result<u8, PaymentUriError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PaymentUriError::MalformedQuery),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> String {
        "aa".repeat(32)
    }

    #[test]
    fn encode_address_only() {
        let p = PaymentUri {
            address: addr(),
            ..Default::default()
        };
        assert_eq!(encode(&p), format!("exfer:{}", addr()));
    }

    #[test]
    fn round_trip_full() {
        let p = PaymentUri {
            address: addr(),
            amount: Some(123_456_789),
            memo: Some("coffee & donuts".into()),
            hash_lock: Some("bb".repeat(32)),
            timeout: Some(99_999),
            label: Some("Alice's Café".into()),
        };
        let uri = encode(&p);
        let back = decode(&uri).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn encode_orders_params_canonically() {
        // amount, memo, hash_lock, timeout, label — in that order.
        let p = PaymentUri {
            address: addr(),
            amount: Some(10),
            memo: Some("hi".into()),
            hash_lock: Some("cc".repeat(32)),
            timeout: Some(5),
            label: Some("L".into()),
        };
        let uri = encode(&p);
        assert!(uri.starts_with(&format!("exfer:{}?amount=10&memo=hi&hash_lock=", addr())));
        let q = uri.split_once('?').unwrap().1;
        let keys: Vec<&str> = q.split('&').map(|kv| kv.split('=').next().unwrap()).collect();
        assert_eq!(keys, vec!["amount", "memo", "hash_lock", "timeout", "label"]);
    }

    #[test]
    fn decode_tolerates_uppercase_hex_address() {
        let upper_addr = "AA".repeat(32);
        let uri = format!("exfer:{upper_addr}");
        let back = decode(&uri).unwrap();
        assert_eq!(back.address, addr()); // normalized to lowercase
    }

    #[test]
    fn decode_rejects_wrong_scheme() {
        assert_eq!(
            decode("bitcoin:..."),
            Err(PaymentUriError::WrongScheme)
        );
        assert_eq!(decode("EXFER:foo"), Err(PaymentUriError::WrongScheme));
    }

    #[test]
    fn decode_rejects_short_address() {
        assert_eq!(decode("exfer:dead"), Err(PaymentUriError::BadAddress));
    }

    #[test]
    fn decode_rejects_non_hex_address() {
        let bad = "g".repeat(64);
        assert_eq!(
            decode(&format!("exfer:{bad}")),
            Err(PaymentUriError::BadAddress)
        );
    }

    #[test]
    fn decode_rejects_bad_amount() {
        assert_eq!(
            decode(&format!("exfer:{}?amount=NaN", addr())),
            Err(PaymentUriError::BadAmount)
        );
        // Negative amounts overflow u64::parse → BadAmount.
        assert_eq!(
            decode(&format!("exfer:{}?amount=-5", addr())),
            Err(PaymentUriError::BadAmount)
        );
    }

    #[test]
    fn decode_rejects_bad_hash_lock() {
        let bad_uri = format!("exfer:{}?hash_lock=tooshort", addr());
        assert_eq!(decode(&bad_uri), Err(PaymentUriError::BadHashLock));
    }

    #[test]
    fn decode_ignores_unknown_params() {
        let uri = format!("exfer:{}?amount=1&future_field=xyz&label=L", addr());
        let back = decode(&uri).unwrap();
        assert_eq!(back.amount, Some(1));
        assert_eq!(back.label.as_deref(), Some("L"));
    }

    #[test]
    fn decode_accepts_empty_query() {
        let uri = format!("exfer:{}?", addr());
        let back = decode(&uri).unwrap();
        assert_eq!(back.address, addr());
        assert!(back.amount.is_none());
    }

    #[test]
    fn percent_encoding_handles_ascii_specials() {
        // & and = must be encoded inside memo so they don't break the query.
        let p = PaymentUri {
            address: addr(),
            memo: Some("a&b=c".into()),
            ..Default::default()
        };
        let uri = encode(&p);
        assert_eq!(uri, format!("exfer:{}?memo=a%26b%3Dc", addr()));
        assert_eq!(decode(&uri).unwrap().memo.as_deref(), Some("a&b=c"));
    }

    #[test]
    fn percent_encoding_handles_utf8() {
        let p = PaymentUri {
            address: addr(),
            memo: Some("é日本".into()),
            ..Default::default()
        };
        let uri = encode(&p);
        let back = decode(&uri).unwrap();
        assert_eq!(back.memo.as_deref(), Some("é日本"));
    }

    #[test]
    fn percent_decode_handles_truncated_escape() {
        // `%` followed by nothing → MalformedQuery (not panic).
        let uri = format!("exfer:{}?memo=hi%2", addr());
        assert_eq!(decode(&uri), Err(PaymentUriError::MalformedQuery));
    }

    #[test]
    fn percent_decode_handles_invalid_hex() {
        let uri = format!("exfer:{}?memo=hi%2Z", addr());
        assert_eq!(decode(&uri), Err(PaymentUriError::MalformedQuery));
    }

    #[test]
    fn decode_rejects_malformed_query_with_missing_equals() {
        let uri = format!("exfer:{}?amount", addr());
        assert_eq!(decode(&uri), Err(PaymentUriError::MalformedQuery));
    }

    #[test]
    fn round_trip_addr_only_preserves_no_query_marker() {
        let p = PaymentUri {
            address: addr(),
            ..Default::default()
        };
        let uri = encode(&p);
        assert!(!uri.contains('?'));
        assert_eq!(decode(&uri).unwrap(), p);
    }
}
