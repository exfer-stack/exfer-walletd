//! `simulate_transfer` / `simulate_htlc_lock` — dry-run versions of the
//! corresponding spend methods.
//!
//! These methods return the exact (size, fee, fee_rate, inputs, outputs,
//! change, built_at_height) tuple that a real call would produce, but
//! never broadcast and never move funds. An agent uses them to prove a
//! cost ceiling holds before committing to spend.
//!
//! ## Scope
//!
//! Read. Simulate methods do touch the keystore (so we know the change
//! address and the signer for placeholder signing), but they never sign
//! anything that leaves the process and the inflight UTXO reservation
//! is released immediately on return. Treat them like any other read
//! query against the wallet's UTXO set.
//!
//! ## Idempotency
//!
//! Not applicable — there's nothing to deduplicate when no transaction
//! is broadcast. `client_token` is not accepted.

use serde::Deserialize;
use serde_json::Value;

use super::{ensure_64_hex, ApiState, TransferOutput, DEFAULT_MAX_FEE, MAX_OUTPUTS};
use crate::error::{Error, Result};
use crate::tx::FeeChoice;

#[derive(Debug, Deserialize)]
pub struct SimulateTransferParams {
    pub from: String,
    pub outputs: Vec<TransferOutput>,
    #[serde(default)]
    pub fee_rate: Option<u64>,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub max_fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SimulateHtlcLockParams {
    pub from: String,
    pub receiver: String,
    pub hash_lock: String,
    pub timeout: u64,
    pub amount: u64,
    #[serde(default)]
    pub fee_rate: Option<u64>,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub max_fee: Option<u64>,
}

pub async fn simulate_transfer_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: SimulateTransferParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("simulate_transfer params: {e}")))?;

    ensure_64_hex(&p.from)?;
    if p.outputs.is_empty() {
        return Err(Error::BadParams(
            "simulate_transfer: outputs[] must not be empty".into(),
        ));
    }
    if p.outputs.len() > MAX_OUTPUTS {
        return Err(Error::TooManyOutputs {
            n: p.outputs.len(),
            max: MAX_OUTPUTS,
        });
    }
    for o in &p.outputs {
        ensure_64_hex(&o.to)?;
    }
    if p.fee.is_some() && p.fee_rate.is_some() {
        return Err(Error::BadParams(
            "simulate_transfer: `fee` and `fee_rate` are mutually exclusive".into(),
        ));
    }
    let fee_choice = match (p.fee, p.fee_rate) {
        (Some(f), None) => FeeChoice::Absolute(f),
        (None, Some(r)) => FeeChoice::Rate(r),
        (None, None) => FeeChoice::Rate(1),
        (Some(_), Some(_)) => unreachable!("guarded above"),
    };
    let max_fee = p.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    let mut recipients: Vec<(exfer::types::Hash256, u64)> = Vec::with_capacity(p.outputs.len());
    for o in &p.outputs {
        let bytes = hex::decode(&o.to).map_err(|e| Error::BadHex(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        recipients.push((exfer::types::Hash256(arr), o.amount));
    }

    let store = state.store.clone();
    let from = p.from.clone();
    let signer = tokio::task::spawn_blocking(move || store.load_by_address(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    let receipt = crate::tx::simulate_transfer(
        &signer,
        recipients,
        fee_choice,
        max_fee,
        &state.node,
        &state.inflight,
    )
    .await?;
    serde_json::to_value(&receipt).map_err(|e| Error::Internal(e.to_string()))
}

pub async fn simulate_htlc_lock_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: SimulateHtlcLockParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("simulate_htlc_lock params: {e}")))?;
    ensure_64_hex(&p.from)?;
    ensure_64_hex(&p.receiver)?;
    ensure_64_hex(&p.hash_lock)?;
    if p.fee.is_some() && p.fee_rate.is_some() {
        return Err(Error::BadParams(
            "simulate_htlc_lock: `fee` and `fee_rate` are mutually exclusive".into(),
        ));
    }
    let fee_choice = match (p.fee, p.fee_rate) {
        (Some(f), None) => FeeChoice::Absolute(f),
        (None, Some(r)) => FeeChoice::Rate(r),
        (None, None) => FeeChoice::Rate(1),
        (Some(_), Some(_)) => unreachable!("guarded above"),
    };
    let max_fee = p.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    let receiver = crate::tx::decode_hash(&p.receiver)?;
    let hash_lock = exfer::types::Hash256(crate::tx::decode_hash(&p.hash_lock)?);

    let store = state.store.clone();
    let from = p.from.clone();
    let signer = tokio::task::spawn_blocking(move || store.load_by_address(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    let receipt = crate::tx::htlc::simulate_htlc_lock(
        &signer,
        receiver,
        hash_lock,
        p.timeout,
        p.amount,
        fee_choice,
        max_fee,
        &state.node,
        &state.inflight,
    )
    .await?;
    serde_json::to_value(&receipt).map_err(|e| Error::Internal(e.to_string()))
}
