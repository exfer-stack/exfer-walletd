//! Crate-wide error type. The HTTP layer maps each variant to a
//! JSON-RPC error code so clients can branch programmatically rather
//! than scraping `message` strings.

use std::io;

use thiserror::Error;

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // ---- input / decode -------------------------------------------------
    #[error("invalid hex: {0}")]
    BadHex(String),

    #[error("invalid address: expected 32 bytes (64 hex chars), got {0} bytes")]
    BadAddressLen(usize),

    #[error("invalid amount: {0}")]
    BadAmount(String),

    #[error("invalid JSON-RPC envelope: {0}")]
    BadEnvelope(String),

    #[error("unknown method: {0}")]
    UnknownMethod(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    // ---- wallet / store -------------------------------------------------
    #[error("wallet not found for address {0}")]
    WalletNotFound(String),

    #[error("wallet already exists at {0}")]
    WalletAlreadyExists(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    // ---- upstream node --------------------------------------------------
    #[error("upstream node unreachable: {0}")]
    UpstreamUnreachable(String),

    #[error("upstream node returned error code {code}: {message}")]
    UpstreamRpc { code: i32, message: String },

    #[error("upstream returned unexpected response: {0}")]
    UpstreamUnexpected(String),

    // ---- transaction ----------------------------------------------------
    #[error("transaction build failed: {0}")]
    TxBuild(String),

    #[error("transaction serialization failed: {0}")]
    TxSerialize(String),

    #[error("UTXO authentication failed: {0}")]
    UtxoAuth(String),

    #[error(
        "insufficient balance: need {needed} exfers (amount + fee), \
         wallet has {available} across {utxo_count} UTXOs"
    )]
    InsufficientBalance {
        needed: u64,
        available: u64,
        utxo_count: usize,
    },

    // ---- auth ----------------------------------------------------------
    #[error("authentication required")]
    Unauthorized,

    // ---- infra ----------------------------------------------------------
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// JSON-RPC 2.0 error code. We follow the standard codes for
    /// parse/method/params and use the application-defined range
    /// (-32000..-32099) for everything else.
    pub fn rpc_code(&self) -> i32 {
        match self {
            Error::BadEnvelope(_) => -32700,
            Error::UnknownMethod(_) => -32601,
            Error::BadHex(_)
            | Error::BadAddressLen(_)
            | Error::BadAmount(_)
            | Error::MissingField(_) => -32602,
            Error::Unauthorized => -32001,
            Error::WalletNotFound(_) => -32010,
            Error::WalletAlreadyExists(_) => -32011,
            Error::UpstreamUnreachable(_)
            | Error::UpstreamRpc { .. }
            | Error::UpstreamUnexpected(_) => -32020,
            Error::TxBuild(_) | Error::UtxoAuth(_) => -32030,
            Error::InsufficientBalance { .. } => -32031,
            Error::TxSerialize(_) | Error::Wallet(_) | Error::Io(_) | Error::Internal(_) => -32603,
        }
    }

    /// HTTP status used when the error escapes to the transport layer.
    /// JSON-RPC normally uses 200 with a body-level error; we only emit
    /// non-200 for auth and transport failures.
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::BadEnvelope(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        }
    }
}
