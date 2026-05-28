//! `payment_uri_encode` / `payment_uri_decode` — JSON-RPC bindings for
//! the BIP21-style `exfer:` URI codec in [`crate::payment_uri`].
//!
//! Both methods are pure (no upstream calls, no key access) and live in
//! the Read scope.

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::payment_uri::{decode, encode, PaymentUri};

#[derive(Debug, Deserialize)]
pub struct PaymentUriDecodeParams {
    pub uri: String,
}

pub async fn payment_uri_encode(params: Value) -> Result<Value> {
    let p: PaymentUri = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("payment_uri_encode params: {e}")))?;

    // Light sanity — the codec doesn't re-validate, so do it here at
    // the JSON-RPC boundary.
    if p.address.len() != 64 || !p.address.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadAddressLen(p.address.len() / 2));
    }
    if let Some(ref h) = p.hash_lock {
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::BadParams(
                "payment_uri_encode: hash_lock must be 64 hex chars".into(),
            ));
        }
    }

    let uri = encode(&p);
    Ok(serde_json::json!({ "uri": uri }))
}

pub async fn payment_uri_decode(params: Value) -> Result<Value> {
    let p: PaymentUriDecodeParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("payment_uri_decode params: {e}")))?;
    let decoded =
        decode(&p.uri).map_err(|e| Error::BadParams(format!("payment_uri_decode: {e}")))?;
    serde_json::to_value(&decoded).map_err(|e| Error::Internal(e.to_string()))
}
