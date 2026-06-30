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
//!
//! Within those ranges, currently used: `-32020` (upstream RPC),
//! `-32021` (double-spend reject, see [`Error::DoubleSpendRejected`]),
//! and the full `-32030..-32038` transaction set plus `-32039`
//! (in-flight exhausted, see [`Error::InFlightExhausted`]).

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

    /// No BSC/EVM key is available: a seedless wallet that has not yet created
    /// (or imported) an independent BNB key. Distinct from `BadParams` so the
    /// UI can branch into a "create your BNB wallet" flow instead of showing a
    /// raw error.
    #[error("no BSC/EVM key has been created for this wallet")]
    EvmKeyNotCreated,

    // ---- upstream node --------------------------------------------------
    #[error("upstream node unreachable: {0}")]
    UpstreamUnreachable(String),

    #[error("upstream node returned error code {code}: {message}")]
    UpstreamRpc { code: i32, message: String },

    #[error("upstream returned unexpected response: {0}")]
    UpstreamUnexpected(String),

    /// The node rejected a broadcast because one of the inputs is
    /// already spent (a double-spend / input-conflict). Distinct typed
    /// code so the pool's idempotent-retry guard treats it as
    /// **non-retryable-blind**: it MUST reconcile via address history /
    /// mempool before any retry, never blind-retry (a blind retry would
    /// re-select the same outpoints and conflict again). This is a
    /// best-effort upgrade of a subset of `-32020` reject phrasings; an
    /// unrecognised reject still surfaces as `-32020`.
    #[error("input already spent (node rejected as double-spend): {message}")]
    DoubleSpendRejected { message: String },

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

    /// Funds exist on this address but **this daemon** has them reserved
    /// in its own pending (in-flight) locks — a *transient* shortfall
    /// that clears as those locks confirm. Distinct from
    /// [`Error::InsufficientBalance`] (a *genuine* shortfall: the wallet
    /// is actually short even counting reserved value) so a caller —
    /// notably the swap pool's BUY pool-lock — can branch deterministically
    /// on the error CODE (`-32039`) and re-tick after the next block
    /// instead of marking the swap failed.
    #[error("{}", in_flight_exhausted_message(*needed, *available, *in_flight_value, *in_flight_count))]
    InFlightExhausted {
        /// `amount + fee` — what the lock/transfer asked for.
        needed: u64,
        /// Sum of UTXOs spendable right now (post in-flight filter).
        available: u64,
        /// Sum of UTXOs this daemon has reserved in pending locks.
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

    /// An htlc claim/reclaim named an on-chain output that did not match
    /// the locally reconstructed HTLC script (or could not be parsed) —
    /// guards against a malicious node feeding a phantom output to spend.
    #[error("htlc output authentication failed: {0}")]
    HtlcOutputAuth(String),

    /// htlc reclaim attempted before the refund timeout height.
    #[error("htlc timeout not reached: current height {current_height} <= timeout {timeout}")]
    TimeoutNotReached { current_height: u64, timeout: u64 },

    /// A native-EXFER spend would breach an operator-configured allowance
    /// ceiling. `scope` is `"per_tx"` (single-spend cap) or `"per_period"`
    /// (rolling-window cap). Surfaces before broadcast, so the funds never
    /// move. Caps are set via walletd config and cannot be raised over the
    /// RPC, so this is a hard stop a leaked spend token cannot lift.
    #[error("{}", allowance_exceeded_message(scope, *limit, *spent, *requested, *period_secs))]
    // `scope` is already `&&'static str` in this context; the helper takes
    // `&str`, which `&&str` coerces to at the call site.
    AllowanceExceeded {
        /// Which ceiling fired: `"per_tx"` or `"per_period"`.
        scope: &'static str,
        /// The configured ceiling in exfers.
        limit: u64,
        /// Already spent in the current window (0 for `per_tx`).
        spent: u64,
        /// What this spend asked for, in exfers.
        requested: u64,
        /// Window length in seconds (0 for `per_tx`).
        period_secs: u64,
    },

    /// `wait_for_tx` reached its `timeout_secs` before the transaction
    /// accumulated enough confirmations. The caller may retry, and the
    /// transaction may yet land — this only says "no result within the
    /// budget you gave me."
    #[error(
        "wait_for_tx timed out after {elapsed_secs}s waiting for {min_confirmations} confirmation(s) on {tx_id}"
    )]
    WaitTimeout {
        tx_id: String,
        min_confirmations: u32,
        elapsed_secs: u64,
    },

    /// The query requested data outside this wallet's owned keys, but
    /// `--indexer-rpc` is not configured. Walletd's local index only
    /// covers HTLCs paying its own keys; set the indexer flag to
    /// answer multi-tenant queries.
    #[error("indexer not configured: this query requires an --indexer-rpc upstream")]
    IndexerNotConfigured,

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
    /// Classify a coin-selection shortfall as *transient* (this daemon's
    /// own in-flight reservations are hiding otherwise-spendable funds —
    /// [`Error::InFlightExhausted`], code `-32039`, retryable) versus
    /// *genuine* (the wallet is actually short even counting reserved
    /// value — [`Error::InsufficientBalance`], code `-32031`).
    ///
    /// Predicate: transient iff `in_flight_count > 0` AND
    /// `available + in_flight_value >= needed` (the funds exist, this
    /// daemon just reserved them). Otherwise genuine.
    pub fn classify_shortfall(
        needed: u64,
        available: u64,
        utxo_count: usize,
        in_flight_value: u64,
        in_flight_count: usize,
    ) -> Error {
        let covered_with_inflight = available.saturating_add(in_flight_value);
        if in_flight_count > 0 && covered_with_inflight >= needed {
            Error::InFlightExhausted {
                needed,
                available,
                in_flight_value,
                in_flight_count,
            }
        } else {
            Error::InsufficientBalance {
                needed,
                available,
                utxo_count,
                in_flight_value,
                in_flight_count,
            }
        }
    }

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
            Error::EvmKeyNotCreated => -32013,
            Error::UpstreamUnreachable(_)
            | Error::UpstreamRpc { .. }
            | Error::UpstreamUnexpected(_) => -32020,
            Error::DoubleSpendRejected { .. } => -32021,
            Error::TxBuild(_) => -32030,
            Error::InsufficientBalance { .. } => -32031,
            Error::FeeTooHigh { .. } => -32032,
            Error::DustOutput { .. } => -32033,
            Error::TooManyOutputs { .. } => -32034,
            Error::IdempotencyConflict { .. } => -32035,
            Error::HtlcOutputAuth(_) => -32036,
            Error::TimeoutNotReached { .. } => -32037,
            Error::AllowanceExceeded { .. } => -32038,
            Error::InFlightExhausted { .. } => -32039,
            Error::WaitTimeout { .. } => -32040,
            Error::IndexerNotConfigured => -32041,
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
            Error::InFlightExhausted {
                needed,
                available,
                in_flight_value,
                in_flight_count,
            } => Some(json!({
                "retryable":        true,
                "retry_after":      "next_block",
                "needed":           needed,
                "available":        available,
                "in_flight_value":  in_flight_value,
                "in_flight_count":  in_flight_count,
            })),
            Error::DoubleSpendRejected { .. } => Some(json!({
                "input_conflict": true,
                "retryable":      false,
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
            Error::WaitTimeout {
                tx_id,
                min_confirmations,
                elapsed_secs,
            } => Some(json!({
                "tx_id": tx_id,
                "min_confirmations": min_confirmations,
                "elapsed_secs": elapsed_secs,
            })),
            Error::AllowanceExceeded {
                scope,
                limit,
                spent,
                requested,
                period_secs,
            } => Some(json!({
                "scope": scope,
                "limit": limit,
                "spent": spent,
                "requested": requested,
                "remaining": limit.saturating_sub(*spent),
                "period_secs": period_secs,
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

/// Build the human-readable `InFlightExhausted` message.
fn in_flight_exhausted_message(
    needed: u64,
    available: u64,
    in_flight_value: u64,
    in_flight_count: usize,
) -> String {
    format!(
        "funding temporarily exhausted: need {needed} exfers, {available} spendable now; \
         {in_flight_count} UTXO(s) worth {in_flight_value} reserved by this daemon's pending \
         locks — retry after next block"
    )
}

/// Build the human-readable `AllowanceExceeded` message for both ceilings.
fn allowance_exceeded_message(
    scope: &str,
    limit: u64,
    spent: u64,
    requested: u64,
    period_secs: u64,
) -> String {
    match scope {
        "per_period" => format!(
            "spend allowance exceeded: per-period cap {limit} exfers / {period_secs}s window, \
             already spent {spent}, this request {requested} (remaining {})",
            limit.saturating_sub(spent)
        ),
        _ => format!(
            "spend allowance exceeded: per-transaction cap {limit} exfers, \
             this request {requested}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_shortfall_picks_in_flight_exhausted_when_reserved_covers() {
        // Funds exist but this daemon reserved them → transient -32039.
        let e = Error::classify_shortfall(100, 40, 1, 70, 2);
        assert!(matches!(e, Error::InFlightExhausted { .. }));
        assert_eq!(e.rpc_code(), -32039);
        let d = e.rpc_data().unwrap();
        assert_eq!(d["retryable"], serde_json::json!(true));
        assert_eq!(d["retry_after"], serde_json::json!("next_block"));
        assert_eq!(d["in_flight_count"], serde_json::json!(2));
    }

    #[test]
    fn classify_shortfall_picks_insufficient_when_genuinely_short() {
        // Even counting reserved value the wallet is short → genuine -32031.
        let e = Error::classify_shortfall(100, 40, 1, 10, 1);
        assert!(matches!(e, Error::InsufficientBalance { .. }));
        assert_eq!(e.rpc_code(), -32031);
    }

    #[test]
    fn classify_shortfall_no_in_flight_is_genuine() {
        // No reservations at all → genuine regardless of arithmetic.
        let e = Error::classify_shortfall(100, 40, 1, 0, 0);
        assert!(matches!(e, Error::InsufficientBalance { .. }));
        assert_eq!(e.rpc_code(), -32031);
    }

    #[test]
    fn double_spend_rejected_code_and_data() {
        let e = Error::DoubleSpendRejected {
            message: "txn-mempool-conflict".into(),
        };
        assert_eq!(e.rpc_code(), -32021);
        let d = e.rpc_data().unwrap();
        assert_eq!(d["input_conflict"], serde_json::json!(true));
        assert_eq!(d["retryable"], serde_json::json!(false));
    }
}
