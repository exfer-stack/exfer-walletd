//! HTTP API surface — JSON-RPC 2.0 over POST /.
//!
//! The wrapper exposes a *strict superset* of the upstream node's RPC:
//! every node method is mirrored as a passthrough, plus two new methods
//! the node itself cannot offer (because it doesn't hold keys):
//!
//! - `generate_address` — creates a new wallet, returns address + pubkey
//! - `transfer` — loads wallet, fetches+authenticates UTXOs,
//!   builds+signs locally, broadcasts via send_raw_transaction
//!
//! Plus a non-RPC convenience method:
//!
//! - `list_addresses` — enumerate every managed address
//!
//! Authentication: optional bearer token via the `Authorization` header.
//! See [`crate::config::Config::auth_token`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::inflight::InFlightUtxos;
use crate::store::WalletStore;
use crate::tx::TransferReceipt;
use crate::upstream::ExferNode;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn WalletStore>,
    pub node: Arc<ExferNode>,
    pub inflight: Arc<InFlightUtxos>,
}

// ============================================================================
// JSON-RPC 2.0 envelope
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }
    pub fn err(id: Value, err: &Error) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError {
                code: err.rpc_code(),
                message: err.to_string(),
            }),
            id,
        }
    }
}

// ============================================================================
// Method param shapes
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TransferParams {
    pub from: String,
    pub to: String,
    pub amount: u64,
    #[serde(default = "default_fee")]
    pub fee: u64,
}
fn default_fee() -> u64 {
    100_000 // 0.001 EXFER
}

#[derive(Debug, Deserialize)]
pub struct AddressParam {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct HashParam {
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ScriptHexParam {
    pub script_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct TxHexParam {
    pub tx_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum BlockSelector {
    ByHash { hash: String },
    ByHeight { height: u64 },
}

// ============================================================================
// Method dispatch
// ============================================================================

/// Dispatch a parsed JSON-RPC request to the right handler.
pub async fn dispatch(state: &ApiState, req: RpcRequest) -> Result<Value> {
    match req.method.as_str() {
        // ---- generate / list (wrapper-only) ----
        "generate_address" => generate_address(state).await,
        "list_addresses" => list_addresses(state).await,

        // ---- transfer (wrapper-only) ----
        "transfer" => transfer_method(state, req.params).await,

        // ---- read passthroughs ----
        "get_block_height" => get_block_height(state).await,
        "get_block" => get_block(state, req.params).await,
        "get_transaction" => get_transaction(state, req.params).await,
        "get_balance" => get_balance(state, req.params).await,
        "get_address_utxos" => get_address_utxos(state, req.params).await,
        "get_script_utxos" => get_script_utxos(state, req.params).await,

        // ---- broadcast passthrough ----
        "send_raw_transaction" => send_raw_transaction(state, req.params).await,

        // ---- health ----
        "ping" => Ok(serde_json::json!({ "ok": true })),

        unknown => Err(Error::UnknownMethod(unknown.to_string())),
    }
}

// ----------------------------------------------------------------------------
// Wrapper-only methods
// ----------------------------------------------------------------------------

async fn generate_address(state: &ApiState) -> Result<Value> {
    let store = state.store.clone();
    let (wallet, addr_hex) = tokio::task::spawn_blocking(move || store.create())
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    let pubkey_hex = hex::encode(wallet.pubkey());
    tracing::info!(address = %addr_hex, "generated new address");
    Ok(serde_json::json!({
        "address": addr_hex,
        "pubkey":  pubkey_hex,
    }))
}

async fn list_addresses(state: &ApiState) -> Result<Value> {
    let store = state.store.clone();
    let addrs = tokio::task::spawn_blocking(move || store.list())
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    Ok(serde_json::json!({ "addresses": addrs }))
}

async fn transfer_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: TransferParams = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("transfer params: {e}")))?;

    ensure_64_hex(&p.from)?;
    ensure_64_hex(&p.to)?;

    // Wallet load is sync FS I/O — run on a blocking worker so we
    // don't tie up a tokio runtime thread under concurrent transfers.
    let store = state.store.clone();
    let from = p.from.clone();
    let wallet = tokio::task::spawn_blocking(move || store.load(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    let to_bytes = hex::decode(&p.to).map_err(|e| Error::BadHex(e.to_string()))?;
    let mut to_arr = [0u8; 32];
    to_arr.copy_from_slice(&to_bytes);

    let receipt: TransferReceipt = crate::tx::transfer(
        &wallet,
        exfer::types::Hash256(to_arr),
        p.amount,
        p.fee,
        &state.node,
        &state.inflight,
    )
    .await?;

    serde_json::to_value(&receipt).map_err(|e| Error::Internal(e.to_string()))
}

// ----------------------------------------------------------------------------
// Read passthroughs (typed; we don't re-emit raw JSON unchecked)
// ----------------------------------------------------------------------------

async fn get_block_height(state: &ApiState) -> Result<Value> {
    let tip = state.node.get_block_height().await?;
    serde_json::to_value(&tip).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_block(state: &ApiState, params: Value) -> Result<Value> {
    let sel: BlockSelector = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("get_block params: {e}")))?;
    let blk = match sel {
        BlockSelector::ByHeight { height } => state.node.get_block_by_height(height).await?,
        BlockSelector::ByHash { hash } => {
            ensure_64_hex(&hash)?;
            state.node.get_block_by_hash(&hash).await?
        }
    };
    serde_json::to_value(&blk).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_transaction(state: &ApiState, params: Value) -> Result<Value> {
    let p: HashParam = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("get_transaction params: {e}")))?;
    ensure_64_hex(&p.hash)?;
    let tx = state.node.get_transaction(&p.hash).await?;
    serde_json::to_value(&tx).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_balance(state: &ApiState, params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("get_balance params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let bal = state.node.get_balance(&p.address).await?;
    serde_json::to_value(&bal).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_address_utxos(state: &ApiState, params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("get_address_utxos params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let u = state.node.get_address_utxos(&p.address).await?;
    serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_script_utxos(state: &ApiState, params: Value) -> Result<Value> {
    let p: ScriptHexParam = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("get_script_utxos params: {e}")))?;
    ensure_hex(&p.script_hex)?;
    let u = state.node.get_script_utxos(&p.script_hex).await?;
    serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))
}

async fn send_raw_transaction(state: &ApiState, params: Value) -> Result<Value> {
    let p: TxHexParam = serde_json::from_value(params)
        .map_err(|e| Error::BadEnvelope(format!("send_raw_transaction params: {e}")))?;
    ensure_hex(&p.tx_hex)?;
    let r = state.node.send_raw_transaction(&p.tx_hex).await?;
    serde_json::to_value(&r).map_err(|e| Error::Internal(e.to_string()))
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Validate a 32-byte hash hex string (address or block/tx hash).
/// Length mismatch → `BadAddressLen` (`-32602`); right length but
/// non-hex chars → `BadHex` (`-32602`).
fn ensure_64_hex(s: &str) -> Result<()> {
    if s.len() != 64 {
        return Err(Error::BadAddressLen(s.len() / 2));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadHex(format!("non-hex character in {s:?}")));
    }
    Ok(())
}

/// Validate a variable-length hex string (script, raw tx). Must be
/// even-length and all hex digits. Empty is allowed — the upstream
/// will reject empty payloads with a more specific error.
fn ensure_hex(s: &str) -> Result<()> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::BadHex(format!("odd-length hex ({} chars)", s.len())));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadHex("non-hex character".to_string()));
    }
    Ok(())
}
