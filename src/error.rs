//! Crate-wide error type. The HTTP layer maps each variant to a
//! JSON-RPC error code so clients can branch programmatically rather
//! than scraping `message` strings.
//!
//! Error code allocation (see `docs/src/errors.md`):
//!
//! | Range           | Meaning                  |
//! |-----------------|--------------------------|
//! | `-32700`        | JSON parse error         |
//! | `-32600`        | Invalid request envelope |
//! | `-32601`        | Method not found         |
//! | `-32602`        | Invalid params           |
//! | `-32603`        | Internal error           |
//! | `-32001..-32009`| Auth                     |
//! | `-32010..-32019`| Wallet / keystore        |
//! | `-32020..-32029`| Upstream node            |
//! | `-32030..-32039`| Transaction / fee        |
//! | `-32040..`      | Reserved                 |

use std::io;

use serde_json::{json, Value};
use thiserror::Error;

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // ---- envelope / decode ----------------------------------------------
    /// JSON syntax error — body could not be parsed at all.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Envelope parsed but failed validation (wrong `jsonrpc`, missing
    /// `method`, malformed batch, etc.). Distinct from `BadParams`,
    /// which is a per-method `params` shape error.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Method-level `params` did not match the expected shape.
    #[error("invalid params: {0}")]
    BadParams(String),

    #[error("invalid hex: {0}")]
    BadHex(String),

    #[error("invalid address: expected 32 bytes (64 hex chars), got {0} bytes")]
    BadAddressLen(usize),

    #[error("invalid amount: {0}")]
    BadAmount(String),

    #[error("unknown method: {0}")]
    UnknownMethod(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    // ---- wallet / keystore ----------------------------------------------
    #[error("wallet not found for address {0}")]
    WalletNotFound(String),

    #[error("wallet already exists at {0}")]
    WalletAlreadyExists(String),

    /// Keystore is locked — passphrase missing, wrong, or seed file
    /// corrupted. Surfaces at startup and on every load attempt.
    #[error("keystore locked: {0}")]
    KeystoreLocked(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    // ---- upstream node --------------------------------------------------
    #[error("upstream node unreachable: {0}")]
    UpstreamUnreachable(String),

    #[error("upstream node returned error code {code}: {message}")]
    UpstreamRpc { code: i32, message: String },

    #[error("upstream returned unexpected response: {0}")]
    UpstreamUnexpected(String),

    // ---- transaction / fee ----------------------------------------------
    #[error("transaction build failed: {0}")]
    TxBuild(String),

    #[error("transaction serialization failed: {0}")]
    TxSerialize(String),

    #[error("{}", insufficient_balance_message(*needed, *available, *utxo_count, *in_flight_value, *in_flight_count))]
    InsufficientBalance {
        /// `amount + fee` — what the transfer asked for.
        needed: u64,
        /// Sum of UTXOs walletd could actually use (post in-flight filter).
        available: u64,
        /// Count of UTXOs that fed `available`.
        utxo_count: usize,
        /// Sum of UTXOs that exist on chain but are claimed by other
        /// in-flight transfers from this daemon.
        in_flight_value: u64,
        /// Count of in-flight outpoints that fed `in_flight_value`.
        in_flight_count: usize,
    },

    /// User-supplied fee (or fee_rate-derived fee) would exceed the
    /// `max_fee` safety cap. Surfaces before broadcast so a typo can't
    /// burn real money.
    #[error("fee {fee} exfers exceeds max_fee {max_fee} — refusing to broadcast")]
    FeeTooHigh { fee: u64, max_fee: u64 },

    /// One of the `transfer.outputs[].amount` values is below the dust
    /// threshold (consensus would reject the tx anyway).
    #[error("output amount {amount} is below dust threshold {dust_threshold}")]
    DustOutput { amount: u64, dust_threshold: u64 },

    /// `transfer.outputs` longer than the per-tx cap.
    #[error("too many outputs: got {n}, max {max}")]
    TooManyOutputs { n: usize, max: usize },

    /// Idempotency key was reused with materially different params — the
    /// cached receipt's request shape disagrees with the new call.
    #[error("idempotency token {token:?} was used with different parameters")]
    IdempotencyConflict { token: String },

    // ---- auth -----------------------------------------------------------
    #[error("authentication required")]
    Unauthorized,

    // ---- infra ----------------------------------------------------------
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// JSON-RPC 2.0 error code.
    pub fn rpc_code(&self) -> i32 {
        match self {
            Error::ParseError(_) => -32700,
            Error::InvalidRequest(_) => -32600,
            Error::UnknownMethod(_) => -32601,
            Error::BadParams(_)
            | Error::BadHex(_)
            | Error::BadAddressLen(_)
            | Error::BadAmount(_)
            | Error::MissingField(_) => -32602,
            Error::Unauthorized => -32001,
            Error::WalletNotFound(_) => -32010,
            Error::WalletAlreadyExists(_) => -32011,
            Error::KeystoreLocked(_) => -32012,
            Error::UpstreamUnreachable(_)
            | Error::UpstreamRpc { .. }
            | Error::UpstreamUnexpected(_) => -32020,
            Error::TxBuild(_) => -32030,
            Error::InsufficientBalance { .. } => -32031,
            Error::FeeTooHigh { .. } => -32032,
            Error::DustOutput { .. } => -32033,
            Error::TooManyOutputs { .. } => -32034,
            Error::IdempotencyConflict { .. } => -32035,
            Error::TxSerialize(_) | Error::Wallet(_) | Error::Io(_) | Error::Internal(_) => -32603,
        }
    }

    /// HTTP status used when the error escapes to the transport layer.
    /// JSON-RPC normally uses 200 with a body-level error; we only emit
    /// non-200 for auth and transport-level envelope failures.
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::ParseError(_) | Error::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        }
    }

    /// Structured payload for the JSON-RPC `error.data` field. Lets
    /// clients branch on machine-readable signals (e.g.
    /// `in_flight_reserved`) instead of grepping the message string.
    pub fn rpc_data(&self) -> Option<Value> {
        match self {
            Error::InsufficientBalance {
                needed,
                available,
                utxo_count,
                in_flight_value,
                in_flight_count,
            } => Some(json!({
                "in_flight_reserved": *in_flight_count > 0,
                "needed":           needed,
                "available":        available,
                "utxo_count":       utxo_count,
                "in_flight_value":  in_flight_value,
                "in_flight_count":  in_flight_count,
            })),
            Error::FeeTooHigh { fee, max_fee } => Some(json!({
                "fee": fee,
                "max_fee": max_fee,
            })),
            Error::DustOutput {
                amount,
                dust_threshold,
            } => Some(json!({
                "amount": amount,
                "dust_threshold": dust_threshold,
            })),
            Error::TooManyOutputs { n, max } => Some(json!({
                "n": n,
                "max": max,
            })),
            Error::IdempotencyConflict { token } => Some(json!({
                "token": token,
            })),
            _ => None,
        }
    }
}

/// Build the human-readable `InsufficientBalance` message.
fn insufficient_balance_message(
    needed: u64,
    available: u64,
    utxo_count: usize,
    in_flight_value: u64,
    in_flight_count: usize,
) -> String {
    let mut s = format!(
        "insufficient balance: need {needed} exfers (amount + fee), \
         wallet has {available} spendable across {utxo_count} UTXO(s)"
    );
    if in_flight_count > 0 {
        s.push_str(&format!(
            " ({in_flight_count} more UTXO(s) worth {in_flight_value} exfers reserved \
             by pending transfers from this daemon; retry once they confirm or use a \
             different sending wallet)"
        ));
    }
    s
}
