//! JSON-RPC surface for the cross-chain swap engine (EXFER ↔ BNB).
//!
//! All methods require `--swap-pool` to be configured; otherwise they return
//! `-32602` with a clear message. The heavy lifting lives in [`crate::swap`];
//! these are thin param-validation + dispatch wrappers.

use serde::Deserialize;
use serde_json::Value;

use super::ApiState;
use crate::error::{Error, Result};
use crate::swap::{Direction, SwapEngine};

fn engine(state: &ApiState) -> Result<&std::sync::Arc<SwapEngine>> {
    state
        .engine
        .as_ref()
        .ok_or_else(|| Error::BadParams("swap not configured (set --swap-pool)".into()))
}

fn parse_direction(s: &str) -> Result<Direction> {
    match s {
        "exfer_to_bnb" => Ok(Direction::ExferToBnb),
        "bnb_to_exfer" => Ok(Direction::BnbToExfer),
        other => Err(Error::BadParams(format!("unknown swap direction: {other}"))),
    }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Internal(e.to_string()))
}

#[derive(Deserialize)]
struct QuoteParams {
    direction: String,
    amount_in: String,
    /// EXFER address that funds (sell) or receives (buy) the EXFER leg.
    from: String,
}

pub async fn swap_get_quote(state: &ApiState, params: Value) -> Result<Value> {
    let p: QuoteParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("swap_get_quote params: {e}")))?;
    let dir = parse_direction(&p.direction)?;
    let rec = engine(state)?.get_quote(dir, p.amount_in, p.from).await?;
    to_value(rec)
}

#[derive(Deserialize)]
struct SwapIdParams {
    swap_id: String,
}

pub async fn swap_execute(state: &ApiState, params: Value) -> Result<Value> {
    let p: SwapIdParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("swap_execute params: {e}")))?;
    to_value(engine(state)?.execute(&p.swap_id).await?)
}

pub async fn swap_refund(state: &ApiState, params: Value) -> Result<Value> {
    let p: SwapIdParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("swap_refund params: {e}")))?;
    to_value(engine(state)?.refund(&p.swap_id).await?)
}

pub async fn swap_status(state: &ApiState, params: Value) -> Result<Value> {
    let p: SwapIdParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("swap_status params: {e}")))?;
    let eng = engine(state)?;
    let rec = eng
        .journal()
        .get(&p.swap_id)
        .ok_or_else(|| Error::BadParams(format!("unknown swap_id {}", p.swap_id)))?;
    to_value(rec)
}

pub async fn swap_list(state: &ApiState) -> Result<Value> {
    to_value(engine(state)?.journal().list())
}

pub async fn swap_pool_info(state: &ApiState) -> Result<Value> {
    engine(state)?.pool_info().await
}

pub async fn swap_price_klines(state: &ApiState, params: Value) -> Result<Value> {
    let interval = params.get("interval").and_then(|v| v.as_str()).unwrap_or("1d");
    // Keep the interval token URL-safe; the pool clamps the limit itself.
    let interval = if interval.len() <= 4 && interval.chars().all(|c| c.is_ascii_alphanumeric()) {
        interval
    } else {
        "1d"
    };
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(120).min(500) as u32;
    engine(state)?.price_klines(interval, limit).await
}

/// Return the wallet's BSC/EVM address (EIP-55) and whether one exists.
/// Hits the store directly (not the swap engine) so it answers even with the
/// pool unconfigured, and NEVER errors when no key exists — `created:false`
/// is the signal for the UI to offer "create your BNB wallet".
pub async fn bsc_get_address(state: &ApiState) -> Result<Value> {
    let addr = state.store.evm_address_opt()?;
    Ok(serde_json::json!({ "address": addr, "created": addr.is_some() }))
}

#[derive(Deserialize)]
struct CreateEvmParams {
    /// Force creation of an independent key on a seeded wallet (the
    /// seed-derived BSC address would no longer be used).
    #[serde(default)]
    force: bool,
}

/// Create a fresh independent BNB wallet (24-word mnemonic → secp256k1).
/// Returns `{address, mnemonic:[…]}`. Argon2id sealing blocks, so run on a
/// blocking thread.
pub async fn bsc_create_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: CreateEvmParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_create_address params: {e}")))?;
    let store = state.store.clone();
    let (address, mnemonic) = tokio::task::spawn_blocking(move || store.create_evm_key(p.force))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(%address, "bsc_create_address served — fresh BNB key created");
    Ok(serde_json::json!({ "address": address, "mnemonic": mnemonic }))
}

#[derive(Deserialize)]
struct PassphraseParams {
    passphrase: String,
}

/// Reveal the BNB wallet's 24-word recovery phrase (passphrase-gated, Spend).
pub async fn bsc_reveal_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: PassphraseParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_reveal_mnemonic params: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    let words = tokio::task::spawn_blocking(move || store.reveal_evm_mnemonic(pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(count = words.len(), "bsc_reveal_mnemonic served — sensitive output");
    Ok(serde_json::json!({ "mnemonic": words }))
}

#[derive(Deserialize)]
struct ImportEvmMnemonicParams {
    mnemonic: String,
    #[serde(default)]
    overwrite: bool,
}

/// Import a MetaMask-style BIP-39 phrase (12 or 24 words) as the BNB wallet.
pub async fn bsc_import_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: ImportEvmMnemonicParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_import_mnemonic params: {e}")))?;
    let store = state.store.clone();
    let phrase = p.mnemonic;
    let overwrite = p.overwrite;
    let address =
        tokio::task::spawn_blocking(move || store.import_evm_mnemonic(&phrase, overwrite))
            .await
            .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(%address, "bsc_import_mnemonic served — BNB key imported");
    Ok(serde_json::json!({ "address": address }))
}

#[derive(Deserialize)]
struct ImportEvmKeyParams {
    /// 0x-prefixed (or bare) 64-hex secp256k1 private key.
    private_key_hex: String,
    #[serde(default)]
    overwrite: bool,
}

/// Import a MetaMask-style raw private key as the BNB wallet.
pub async fn bsc_import_key(state: &ApiState, params: Value) -> Result<Value> {
    let p: ImportEvmKeyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_import_key params: {e}")))?;
    let h = p.private_key_hex.trim();
    let h = h.strip_prefix("0x").unwrap_or(h);
    let raw =
        hex::decode(h).map_err(|e| Error::BadHex(format!("bsc_import_key private_key: {e}")))?;
    let secret: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadParams("private key must be 32 bytes (64 hex chars)".into()))?;
    let store = state.store.clone();
    let overwrite = p.overwrite;
    let mut secret = zeroize::Zeroizing::new(secret);
    let s = *secret;
    let address = tokio::task::spawn_blocking(move || store.import_evm_key(&s, overwrite))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    secret.iter_mut().for_each(|b| *b = 0);
    tracing::warn!(%address, "bsc_import_key served — BNB key imported");
    Ok(serde_json::json!({ "address": address }))
}

/// Delete the BNB wallet's independent key (passphrase-gated, Spend).
pub async fn bsc_delete_key(state: &ApiState, params: Value) -> Result<Value> {
    let p: PassphraseParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_delete_key params: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    tokio::task::spawn_blocking(move || store.delete_evm_key(pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!("bsc_delete_key served — BNB key deleted");
    Ok(serde_json::json!({ "deleted": true }))
}

// ── liquidity-provider proxies ──
#[derive(Deserialize)]
struct LpAddrParams {
    address: String,
}
#[derive(Deserialize)]
struct LpDepositStartParams {
    exfer_address: String,
    bsc_address: String,
}
#[derive(Deserialize)]
struct LpIdParams {
    id: String,
}
#[derive(Deserialize)]
struct LpWithdrawParams {
    exfer_address: String,
    shares: String,
}

pub async fn lp_pool_info(state: &ApiState) -> Result<Value> {
    engine(state)?.lp_pool_info().await
}
pub async fn lp_position(state: &ApiState, params: Value) -> Result<Value> {
    let p: LpAddrParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("lp_position params: {e}")))?;
    engine(state)?.lp_position(&p.address).await
}
pub async fn lp_deposit_start(state: &ApiState, params: Value) -> Result<Value> {
    let p: LpDepositStartParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("lp_deposit_start params: {e}")))?;
    engine(state)?.lp_deposit_start(&p.exfer_address, &p.bsc_address).await
}
pub async fn lp_deposit_status(state: &ApiState, params: Value) -> Result<Value> {
    let p: LpIdParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("lp_deposit_status params: {e}")))?;
    engine(state)?.lp_deposit_status(&p.id).await
}
pub async fn lp_withdraw_self(state: &ApiState, params: Value) -> Result<Value> {
    let p: LpWithdrawParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("lp_withdraw_self params: {e}")))?;
    engine(state)?.lp_withdraw_self(&p.exfer_address, &p.shares).await
}

pub async fn bsc_get_balances(state: &ApiState) -> Result<Value> {
    let bnb = engine(state)?.bsc_balances().await?;
    Ok(serde_json::json!({ "bnb_wei": bnb }))
}

#[derive(Deserialize)]
struct SendBnbParams {
    to: String,
    /// BNB amount (≤18 dp). Empty or "max" sends the whole balance minus gas.
    #[serde(default)]
    amount: String,
}

pub async fn bsc_send_bnb(state: &ApiState, params: Value) -> Result<Value> {
    let p: SendBnbParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("bsc_send_bnb params: {e}")))?;
    let txhash = engine(state)?.send_bnb(&p.to, &p.amount).await?;
    Ok(serde_json::json!({ "txhash": txhash }))
}
