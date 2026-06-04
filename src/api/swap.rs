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

pub async fn bsc_get_address(state: &ApiState) -> Result<Value> {
    let addr = engine(state)?.bsc_address()?;
    Ok(serde_json::json!({ "address": addr }))
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
