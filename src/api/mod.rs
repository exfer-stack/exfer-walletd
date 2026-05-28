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
use crate::idempotency::IdempotencyCache;
use crate::inflight::InFlightUtxos;
use crate::store::WalletStore;
use crate::tx::{FeeChoice, TransferReceipt};
use crate::upstream::ExferNode;

pub mod payment_uri;
pub mod signmsg;
pub mod simulate;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn WalletStore>,
    pub node: Arc<ExferNode>,
    pub inflight: Arc<InFlightUtxos>,
    pub idempotency: Arc<IdempotencyCache>,
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
    /// `None` distinguishes a JSON-RPC *notification* (no `id` field
    /// present in the request) from a request that explicitly passed
    /// `id: null` (`Some(Value::Null)`). Notifications get no response
    /// per spec § 4.1.
    #[serde(default)]
    pub id: Option<Value>,
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
    /// Optional machine-readable payload — JSON-RPC 2.0 § 5.1 `data`.
    /// Currently populated for `InsufficientBalance` (`-32031`) so SDKs
    /// can branch on `in_flight_reserved` etc. without grepping the
    /// message string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
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
                data: err.rpc_data(),
            }),
            id,
        }
    }
}

// ============================================================================
// Method param shapes
// ============================================================================

/// `transfer` request shape. Multi-output, fee/fee_rate optional with
/// `max_fee` safety cap, plus optional `client_token` for idempotent
/// retries.
#[derive(Debug, Deserialize)]
pub struct TransferParams {
    /// Sender address (HD-derived or imported). Identifies the wallet
    /// walletd should spend from.
    pub from: String,
    /// One or more recipient outputs. Empty array → `BadParams`;
    /// > [`MAX_OUTPUTS`] → `TooManyOutputs`.
    pub outputs: Vec<TransferOutput>,
    /// Fee in exfers per cost-unit. Mutually exclusive with `fee`.
    /// If both are omitted, defaults to `1` (= consensus minimum).
    #[serde(default)]
    pub fee_rate: Option<u64>,
    /// Absolute fee in exfers. Mutually exclusive with `fee_rate`.
    #[serde(default)]
    pub fee: Option<u64>,
    /// Safety cap on the final fee. The transfer is rejected with
    /// [`Error::FeeTooHigh`] before broadcast if the computed fee
    /// exceeds this. Defaults to [`DEFAULT_MAX_FEE`].
    #[serde(default)]
    pub max_fee: Option<u64>,
    /// Optional idempotency key — see [`crate::idempotency`].
    /// 8..=128 ASCII chars.
    #[serde(default)]
    pub client_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransferOutput {
    pub to: String,
    pub amount: u64,
}

/// Maximum number of outputs in a single transfer. Bounds the
/// transfer engine's work and the fee-estimation iteration depth.
pub const MAX_OUTPUTS: usize = 16;

/// Default `max_fee` cap (0.02 EXFER). At consensus' min_fee floor a
/// well-formed 1-input/2-output transfer costs ~150 exfers; the cap is
/// four orders of magnitude above that, so it never trips on legitimate
/// transfers but catches the "off-by-zero" mistake (e.g. operator types
/// `fee: 50000000` thinking it's exfers/byte).
pub const DEFAULT_MAX_FEE: u64 = 2_000_000;

#[derive(Debug, Deserialize)]
pub struct AddressParam {
    pub address: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct GenerateAddressParams {
    #[serde(default)]
    pub label: Option<String>,
}

/// Parameter for any method that takes a single transaction id.
#[derive(Debug, Deserialize)]
pub struct TxIdParam {
    pub tx_id: String,
}

/// Parameter for `get_block_by_id`.
#[derive(Debug, Deserialize)]
pub struct BlockIdParam {
    pub block_id: String,
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
pub struct HeightParam {
    pub height: u64,
}

/// `htlc_lock` — fund an HTLC payable to `receiver` (a pubkey) against
/// `hash_lock`, refundable to `from` after `timeout`. Fee handling
/// mirrors `transfer` (`fee` xor `fee_rate`, `max_fee` cap).
#[derive(Debug, Deserialize)]
pub struct HtlcLockParams {
    /// Sender wallet address (the wallet walletd funds + signs from).
    pub from: String,
    /// Receiver's 32-byte pubkey (64 hex) — the key that can claim with
    /// the preimage.
    pub receiver: String,
    /// SHA-256 hash lock (64 hex).
    pub hash_lock: String,
    /// Refund timeout, as an absolute block height.
    pub timeout: u64,
    /// Amount to lock (exfers).
    pub amount: u64,
    #[serde(default)]
    pub fee_rate: Option<u64>,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub max_fee: Option<u64>,
}

/// `htlc_claim` — spend an HTLC output via the hashlock arm by revealing
/// `preimage`. `from` is the receiver wallet.
#[derive(Debug, Deserialize)]
pub struct HtlcClaimParams {
    /// Receiver wallet address (claims and receives the funds).
    pub from: String,
    /// Lock transaction id (64 hex).
    pub lock_tx_id: String,
    /// Output index of the HTLC output in the lock tx (default 0).
    #[serde(default)]
    pub output_index: u32,
    /// Preimage whose SHA-256 equals the lock's hash (hex, any length).
    pub preimage: String,
    /// Sender's 32-byte pubkey (64 hex) — needed to reconstruct the script.
    pub sender: String,
    /// The lock's timeout height — needed to reconstruct the script.
    pub timeout: u64,
    /// Absolute fee (exfers). Defaults to the consensus minimum.
    #[serde(default)]
    pub fee: Option<u64>,
}

/// `htlc_reclaim` — spend an HTLC output via the refund arm after
/// `timeout`. `from` is the original sender wallet.
#[derive(Debug, Deserialize)]
pub struct HtlcReclaimParams {
    /// Sender wallet address (reclaims the funds).
    pub from: String,
    /// Lock transaction id (64 hex).
    pub lock_tx_id: String,
    /// Output index of the HTLC output in the lock tx (default 0).
    #[serde(default)]
    pub output_index: u32,
    /// Receiver's 32-byte pubkey (64 hex) — needed to reconstruct the script.
    pub receiver: String,
    /// SHA-256 hash lock (64 hex) — needed to reconstruct the script.
    pub hash_lock: String,
    /// The lock's timeout height.
    pub timeout: u64,
    /// Absolute fee (exfers). Defaults to the consensus minimum.
    #[serde(default)]
    pub fee: Option<u64>,
}

/// Upper bound on accepted preimage length (bytes). A preimage is just
/// the secret behind an HTLC; cap it so a malformed request can't make
/// us hash megabytes.
pub const MAX_PREIMAGE_BYTES: usize = 1024;

// ============================================================================
// Method dispatch
// ============================================================================

/// Dispatch a parsed JSON-RPC request to the right handler.
pub async fn dispatch(state: &ApiState, req: RpcRequest) -> Result<Value> {
    match req.method.as_str() {
        // ---- generate / list (wrapper-only) ----
        "generate_address" => generate_address(state, req.params).await,
        "import_private_key" => import_private_key(state, req.params).await,
        "list_addresses" => list_addresses(state).await,

        // ---- transfer (wrapper-only) ----
        "transfer" => transfer_method(state, req.params).await,

        // ---- htlc lifecycle (wrapper-only) ----
        "htlc_lock" => htlc_lock_method(state, req.params).await,
        "htlc_claim" => htlc_claim_method(state, req.params).await,
        "htlc_reclaim" => htlc_reclaim_method(state, req.params).await,

        // ---- dry-run cost simulation ----
        "simulate_transfer" => simulate::simulate_transfer_method(state, req.params).await,
        "simulate_htlc_lock" => simulate::simulate_htlc_lock_method(state, req.params).await,

        // ---- payment URI codec (pure) ----
        "payment_uri_encode" => payment_uri::payment_uri_encode(req.params).await,
        "payment_uri_decode" => payment_uri::payment_uri_decode(req.params).await,

        // ---- read passthroughs ----
        "get_block_height" => get_block_height(state).await,
        "get_block_by_id" => get_block_by_id(state, req.params).await,
        "get_block_by_height" => get_block_by_height(state, req.params).await,
        "get_block_id_at_height" => get_block_id_at_height(state, req.params).await,
        "get_transaction" => get_transaction(state, req.params).await,
        "get_balance" => get_balance(state, req.params).await,
        "get_address_utxos" => get_address_utxos(state, req.params).await,
        "get_script_utxos" => get_script_utxos(state, req.params).await,

        // ---- broadcast passthrough ----
        "send_raw_transaction" => send_raw_transaction(state, req.params).await,

        // ---- proof-of-ownership signatures ----
        "sign_message" => signmsg::sign_message(state, req.params).await,
        "verify_message" => signmsg::verify_message(state, req.params).await,

        // ---- sensitive recovery export (passphrase-gated, spend-scope) ----
        "reveal_mnemonic" => reveal_mnemonic(state, req.params).await,
        "reveal_private_key" => reveal_private_key(state, req.params).await,

        // ---- wallet-side conveniences ----
        "validate_address" => validate_address(req.params).await,
        "get_wallet_balance" => get_wallet_balance(state, req.params).await,
        "get_status" => get_status(state).await,
        "abandon_transfer" => abandon_transfer(state, req.params).await,

        // ---- health ----
        "ping" => Ok(serde_json::json!({ "ok": true })),

        unknown => Err(Error::UnknownMethod(unknown.to_string())),
    }
}

// ----------------------------------------------------------------------------
// Wrapper-only methods
// ----------------------------------------------------------------------------

async fn generate_address(state: &ApiState, params: Value) -> Result<Value> {
    // Accept either {} or {"label": "..."} — label is optional.
    let p: GenerateAddressParams = if params.is_null() {
        GenerateAddressParams::default()
    } else {
        serde_json::from_value(params)
            .map_err(|e| Error::BadParams(format!("generate_address params: {e}")))?
    };
    let store = state.store.clone();
    let label = p.label.clone();
    let derived = tokio::task::spawn_blocking(move || store.create(label))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %derived.address, index = derived.index, "generated new address");
    serde_json::to_value(&derived).map_err(|e| Error::Internal(e.to_string()))
}

async fn list_addresses(state: &ApiState) -> Result<Value> {
    let store = state.store.clone();
    let entries = tokio::task::spawn_blocking(move || store.list())
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    Ok(serde_json::json!({ "addresses": entries }))
}

#[derive(Debug, Deserialize)]
struct ImportPrivateKeyParams {
    /// Raw 32-byte ed25519 secret, hex-encoded (64 chars).
    secret_hex: String,
    #[serde(default)]
    label: Option<String>,
}

/// `import_private_key` — register an externally-supplied ed25519 secret
/// as a non-derived ("imported") address. The secret is sealed at rest
/// with the keystore passphrase, same as HD-derived keys. Returns the
/// resulting address. Errors with `WalletAlreadyExists` if the address
/// is already managed by this keystore.
///
/// Manage-scope: this writes persistent state but does not spend funds.
/// The caller already holds the secret being imported, so the auth
/// requirement matches `generate_address`, not `reveal_private_key`.
async fn import_private_key(state: &ApiState, params: Value) -> Result<Value> {
    let p: ImportPrivateKeyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("import_private_key params: {e}")))?;
    if p.secret_hex.len() != 64 {
        return Err(Error::BadParams(format!(
            "import_private_key: secret_hex must be 64 hex chars (got {})",
            p.secret_hex.len()
        )));
    }
    let mut secret = [0u8; 32];
    hex::decode_to_slice(&p.secret_hex, &mut secret)
        .map_err(|e| Error::BadHex(format!("import_private_key secret_hex: {e}")))?;
    let store = state.store.clone();
    let label = p.label.clone();
    let address = tokio::task::spawn_blocking(move || {
        let r = store.import(&secret, label);
        // Best-effort scrub of the local copy. The caller's hex string
        // remains in the request body until the request guard drops it.
        secret.fill(0);
        r
    })
    .await
    .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %address, "imported private key");
    Ok(serde_json::json!({ "address": address, "imported": true }))
}

async fn transfer_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: TransferParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("transfer params: {e}")))?;

    // ---- envelope-level validation (cheap, no upstream calls) --------
    ensure_64_hex(&p.from)?;
    if p.outputs.is_empty() {
        return Err(Error::BadParams(
            "transfer: outputs[] must not be empty".into(),
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
            "transfer: `fee` and `fee_rate` are mutually exclusive".into(),
        ));
    }
    if let Some(ref t) = p.client_token {
        let n = t.len();
        if !(8..=128).contains(&n) || !t.is_ascii() {
            return Err(Error::BadParams(format!(
                "transfer: client_token must be 8..=128 ASCII characters (got {n})"
            )));
        }
    }
    let fee_choice = match (p.fee, p.fee_rate) {
        (Some(f), None) => FeeChoice::Absolute(f),
        (None, Some(r)) => FeeChoice::Rate(r),
        // Default: rate = 1 (consensus minimum).
        (None, None) => FeeChoice::Rate(1),
        (Some(_), Some(_)) => unreachable!("guarded above"),
    };
    let max_fee = p.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    // Convert recipient addresses into Hash256s.
    let mut recipients: Vec<(exfer::types::Hash256, u64)> = Vec::with_capacity(p.outputs.len());
    for o in &p.outputs {
        let bytes = hex::decode(&o.to).map_err(|e| Error::BadHex(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        recipients.push((exfer::types::Hash256(arr), o.amount));
    }

    // ---- load the signer (blocking FS I/O on the keystore) -----------
    let store = state.store.clone();
    let from = p.from.clone();
    let signer = tokio::task::spawn_blocking(move || store.load_by_address(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    // ---- run, possibly through the idempotency cache -----------------
    let receipt: std::sync::Arc<TransferReceipt> = match p.client_token.as_deref() {
        Some(token) => {
            let fingerprint = fingerprint_transfer(&p, &fee_choice, max_fee);
            let recipients_for_run = recipients.clone();
            state
                .idempotency
                .get_or_run(token, fingerprint, move || async move {
                    crate::tx::transfer(
                        &signer,
                        recipients_for_run,
                        fee_choice,
                        max_fee,
                        &state.node,
                        &state.inflight,
                    )
                    .await
                })
                .await?
        }
        None => {
            let r = crate::tx::transfer(
                &signer,
                recipients,
                fee_choice,
                max_fee,
                &state.node,
                &state.inflight,
            )
            .await?;
            std::sync::Arc::new(r)
        }
    };

    serde_json::to_value(&*receipt).map_err(|e| Error::Internal(e.to_string()))
}

/// Deterministic fingerprint over the *meaningful* request shape: which
/// inputs would yield "the same" transfer result. Captured so the
/// idempotency layer can detect token reuse with different parameters.
fn fingerprint_transfer(p: &TransferParams, fee_choice: &FeeChoice, max_fee: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    p.from.to_ascii_lowercase().hash(&mut h);
    for o in &p.outputs {
        o.to.to_ascii_lowercase().hash(&mut h);
        o.amount.hash(&mut h);
    }
    match fee_choice {
        FeeChoice::Absolute(f) => (0u8, *f).hash(&mut h),
        FeeChoice::Rate(r) => (1u8, *r).hash(&mut h),
    }
    max_fee.hash(&mut h);
    h.finish()
}

// ----------------------------------------------------------------------------
// HTLC lifecycle (wrapper-only)
// ----------------------------------------------------------------------------

/// Load the signer for a managed address off the async runtime (keystore
/// I/O is blocking). Shared by the htlc handlers and mirrors the pattern
/// in `transfer_method`.
async fn load_signer(state: &ApiState, address_hex: &str) -> Result<crate::store::Signer> {
    let store = state.store.clone();
    let from = address_hex.to_string();
    tokio::task::spawn_blocking(move || store.load_by_address(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))?
}

async fn htlc_lock_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcLockParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("htlc_lock params: {e}")))?;
    ensure_64_hex(&p.from)?;
    ensure_64_hex(&p.receiver)?;
    ensure_64_hex(&p.hash_lock)?;
    if p.fee.is_some() && p.fee_rate.is_some() {
        return Err(Error::BadParams(
            "htlc_lock: `fee` and `fee_rate` are mutually exclusive".into(),
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

    let signer = load_signer(state, &p.from).await?;
    let receipt = crate::tx::htlc::htlc_lock(
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

async fn htlc_claim_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcClaimParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("htlc_claim params: {e}")))?;
    ensure_64_hex(&p.from)?;
    ensure_64_hex(&p.lock_tx_id)?;
    ensure_64_hex(&p.sender)?;
    let preimage = hex::decode(&p.preimage).map_err(|e| Error::BadHex(e.to_string()))?;
    if preimage.is_empty() || preimage.len() > MAX_PREIMAGE_BYTES {
        return Err(Error::BadParams(format!(
            "htlc_claim: preimage must be 1..={MAX_PREIMAGE_BYTES} bytes (got {})",
            preimage.len()
        )));
    }
    let lock_tx_id = exfer::types::Hash256(crate::tx::decode_hash(&p.lock_tx_id)?);
    let sender = crate::tx::decode_hash(&p.sender)?;

    let signer = load_signer(state, &p.from).await?;
    let receipt = crate::tx::htlc::htlc_claim(
        &signer,
        lock_tx_id,
        p.output_index,
        preimage,
        sender,
        p.timeout,
        p.fee,
        &state.node,
    )
    .await?;
    serde_json::to_value(&receipt).map_err(|e| Error::Internal(e.to_string()))
}

async fn htlc_reclaim_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: HtlcReclaimParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("htlc_reclaim params: {e}")))?;
    ensure_64_hex(&p.from)?;
    ensure_64_hex(&p.lock_tx_id)?;
    ensure_64_hex(&p.receiver)?;
    ensure_64_hex(&p.hash_lock)?;
    let lock_tx_id = exfer::types::Hash256(crate::tx::decode_hash(&p.lock_tx_id)?);
    let receiver = crate::tx::decode_hash(&p.receiver)?;
    let hash_lock = exfer::types::Hash256(crate::tx::decode_hash(&p.hash_lock)?);

    let signer = load_signer(state, &p.from).await?;
    let receipt = crate::tx::htlc::htlc_reclaim(
        &signer,
        lock_tx_id,
        p.output_index,
        receiver,
        hash_lock,
        p.timeout,
        p.fee,
        &state.node,
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

async fn get_block_by_id(state: &ApiState, params: Value) -> Result<Value> {
    let p: BlockIdParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_block_by_id params: {e}")))?;
    ensure_64_hex(&p.block_id)?;
    let blk = state.node.get_block_by_hash(&p.block_id).await?;
    serde_json::to_value(&blk).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_block_by_height(state: &ApiState, params: Value) -> Result<Value> {
    let p: HeightParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_block_by_height params: {e}")))?;
    let blk = state.node.get_block_by_height(p.height).await?;
    serde_json::to_value(&blk).map_err(|e| Error::Internal(e.to_string()))
}

/// Bitcoin-style explicit `height → block_id` lookup. Returns the
/// same `{block_id, height}` shape as `get_block_height` so clients
/// can treat both uniformly.
///
/// Performance note: upstream Exfer node has no height→block_id index,
/// so this call fetches the full block and discards everything but the
/// id. Cost is identical to `get_block_by_height`. If the caller's next
/// step is to read the block itself, prefer `get_block_by_height`
/// — one round trip instead of two.
async fn get_block_id_at_height(state: &ApiState, params: Value) -> Result<Value> {
    let p: HeightParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_block_id_at_height params: {e}")))?;
    let blk = state.node.get_block_by_height(p.height).await?;
    Ok(serde_json::json!({
        "height":   blk.height,
        "block_id": blk.block_id,
    }))
}

async fn get_transaction(state: &ApiState, params: Value) -> Result<Value> {
    let p: TxIdParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_transaction params: {e}")))?;
    ensure_64_hex(&p.tx_id)?;
    let tx = state.node.get_transaction(&p.tx_id).await?;

    // Always decode. Outputs are free; inputs need parent-tx fetches
    // (concurrent, cap 8) and degrade gracefully if any parent is
    // unreachable — partial decode is more useful than a failed call.
    let decoded = crate::tx::decode::decode_with_inputs(&state.node, &tx.tx_hex).await?;

    let mut v = serde_json::to_value(&tx).map_err(|e| Error::Internal(e.to_string()))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| Error::Internal("tx response is not an object".into()))?;
    let decoded_value =
        serde_json::to_value(&decoded).map_err(|e| Error::Internal(e.to_string()))?;
    if let Some(decoded_obj) = decoded_value.as_object() {
        for (k, val) in decoded_obj {
            obj.insert(k.clone(), val.clone());
        }
    }
    Ok(v)
}

async fn get_balance(state: &ApiState, params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_balance params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let bal = state.node.get_balance(&p.address).await?;
    serde_json::to_value(&bal).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_address_utxos(state: &ApiState, params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_address_utxos params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let u = state.node.get_address_utxos(&p.address).await?;
    serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_script_utxos(state: &ApiState, params: Value) -> Result<Value> {
    let p: ScriptHexParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_script_utxos params: {e}")))?;
    ensure_hex(&p.script_hex)?;
    let u = state.node.get_script_utxos(&p.script_hex).await?;
    serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))
}

async fn send_raw_transaction(state: &ApiState, params: Value) -> Result<Value> {
    let p: TxHexParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("send_raw_transaction params: {e}")))?;
    ensure_hex(&p.tx_hex)?;
    let r = state.node.send_raw_transaction(&p.tx_hex).await?;
    serde_json::to_value(&r).map_err(|e| Error::Internal(e.to_string()))
}

#[derive(serde::Deserialize)]
struct RevealMnemonicParams {
    passphrase: String,
}

async fn reveal_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: RevealMnemonicParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("reveal_mnemonic params: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    let words = tokio::task::spawn_blocking(move || store.reveal_mnemonic(pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(
        count = words.len(),
        "reveal_mnemonic served — sensitive output"
    );
    Ok(serde_json::json!({ "mnemonic": words }))
}

#[derive(serde::Deserialize)]
struct RevealPrivateKeyParams {
    address: String,
    passphrase: String,
}

async fn reveal_private_key(state: &ApiState, params: Value) -> Result<Value> {
    let p: RevealPrivateKeyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("reveal_private_key params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let address = p.address.to_ascii_lowercase();
    let store = state.store.clone();
    let pass = p.passphrase;
    let addr_for_blocking = address.clone();
    let secret = tokio::task::spawn_blocking(move || {
        store.reveal_secret(&addr_for_blocking, pass.as_bytes())
    })
    .await
    .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    let secret_hex = hex::encode(secret.as_ref());
    tracing::warn!(address = %address, "reveal_private_key served — sensitive output");
    Ok(serde_json::json!({
        "address":    address,
        "secret_hex": secret_hex,
    }))
}

// ----------------------------------------------------------------------------
// New wallet-side conveniences (v1.0)
// ----------------------------------------------------------------------------

/// `validate_address` — pure check that a string is a syntactically
/// well-formed 64-char lowercase hex address. No upstream calls.
async fn validate_address(params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("validate_address params: {e}")))?;
    let trimmed = p.address.trim();
    let valid = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
    let normalized = if valid {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    };
    Ok(serde_json::json!({
        "valid": valid,
        "normalized": normalized,
    }))
}

/// `get_wallet_balance` — aggregate balance across every managed
/// address. Fans out `get_balance` calls concurrently (cap 8).
///
/// Optional param `utxos` (bool, default `true`): when `false`, the
/// per-address `get_address_utxos` call is skipped and `utxo_count` /
/// `truncated` are omitted. Clients that poll only for balance (e.g. a
/// live deposit watcher) pass `false` to halve upstream address scans
/// and stay further under the public node's rate limit.
///
/// Optional param `addresses` (hex string array): when present, only
/// these managed addresses are scanned (others are ignored). Lets a
/// client poll a subset — e.g. skip addresses the user has hidden — so
/// the scan count, and thus the achievable poll rate, tracks how many
/// addresses are actually on screen. Unknown addresses are silently
/// dropped. Absent ⇒ every managed address (current behaviour).
async fn get_wallet_balance(state: &ApiState, params: Value) -> Result<Value> {
    use futures::stream::{self, StreamExt, TryStreamExt};

    let include_utxos = params.get("utxos").and_then(Value::as_bool).unwrap_or(true);

    let address_filter: Option<std::collections::HashSet<String>> = params
        .get("addresses")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.to_lowercase())
                .collect()
        });

    let store = state.store.clone();
    let entries = tokio::task::spawn_blocking(move || store.list())
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    let entries: Vec<_> = match &address_filter {
        Some(set) => entries
            .into_iter()
            .filter(|e| set.contains(&e.address.to_lowercase()))
            .collect(),
        None => entries,
    };

    let node = state.node.clone();
    let rows: Vec<Value> = stream::iter(entries.clone())
        .map(|entry| {
            let node = node.clone();
            async move {
                let bal = node.get_balance(&entry.address).await?;
                let mut row = serde_json::json!({
                    "address": entry.address,
                    "index": entry.index,
                    "label": entry.label,
                    "imported": entry.imported,
                    "balance": bal.balance,
                });
                if include_utxos {
                    let utxos = node.get_address_utxos(&entry.address).await?;
                    let obj = row.as_object_mut().expect("row is an object");
                    obj.insert("utxo_count".into(), serde_json::json!(utxos.utxos.len()));
                    obj.insert("truncated".into(), serde_json::json!(utxos.truncated));
                }
                Ok::<Value, Error>(row)
            }
        })
        .buffer_unordered(8)
        .try_collect()
        .await?;

    // Sort by index ascending then address (matches list_addresses).
    let mut rows = rows;
    rows.sort_by(|a, b| {
        let ai = a["index"].as_u64();
        let bi = b["index"].as_u64();
        match (ai, bi) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a["address"].as_str().cmp(&b["address"].as_str()),
        }
    });
    let total: u64 = rows
        .iter()
        .map(|r| r["balance"].as_u64().unwrap_or(0))
        .sum();
    Ok(serde_json::json!({
        "entries": rows,
        "total": total,
    }))
}

/// `get_status` — single round-trip operator dashboard. Includes the
/// daemon's version, current chain tip (one upstream RPC), wallet
/// count, configured upstream URLs, and in-flight counters.
async fn get_status(state: &ApiState) -> Result<Value> {
    let store = state.store.clone();
    let wallet_count_fut = tokio::task::spawn_blocking(move || store.list().map(|v| v.len()));
    let tip_fut = state.node.get_block_height();
    let (wallet_count_res, tip_res) = tokio::join!(wallet_count_fut, tip_fut);

    let wallet_count =
        wallet_count_res.map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    // Tip may be unreachable (offline upstream); surface what we have
    // and leave tip null in that case rather than failing the whole
    // status call.
    let (tip_block_id, tip_height, upstream_ok) = match tip_res {
        Ok(t) => (Some(t.block_id), Some(t.height), true),
        Err(_) => (None, None, false),
    };

    Ok(serde_json::json!({
        "version":             env!("CARGO_PKG_VERSION"),
        "tip": {
            "block_id": tip_block_id,
            "height":   tip_height,
        },
        "upstream_ok":         upstream_ok,
        "upstream_nodes":      state.node.nodes(),
        "wallet_count":        wallet_count,
        "in_flight_utxos":     state.inflight.len(),
        "in_flight_transfers": state.idempotency.len(),
    }))
}

#[derive(Debug, Deserialize)]
struct AbandonTransferParams {
    pub outpoints: Vec<OutpointParam>,
}

#[derive(Debug, Deserialize)]
struct OutpointParam {
    pub tx_id: String,
    pub output_index: u32,
}

/// `abandon_transfer` — manually release outpoints from the in-flight
/// claim set. Use when a `transfer` failed transport-side and you've
/// confirmed (via `get_transaction(tx_id)`) that the broadcast did NOT
/// land. After release, the same outpoints become re-selectable.
async fn abandon_transfer(state: &ApiState, params: Value) -> Result<Value> {
    let p: AbandonTransferParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("abandon_transfer params: {e}")))?;
    if p.outpoints.is_empty() {
        return Err(Error::BadParams(
            "abandon_transfer: outpoints[] must not be empty".into(),
        ));
    }
    let before = state.inflight.len();
    let mut converted: Vec<exfer::types::transaction::OutPoint> =
        Vec::with_capacity(p.outpoints.len());
    for o in &p.outpoints {
        ensure_64_hex(&o.tx_id)?;
        let bytes = hex::decode(&o.tx_id).map_err(|e| Error::BadHex(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        converted.push(exfer::types::transaction::OutPoint {
            tx_id: exfer::types::Hash256(arr),
            output_index: o.output_index,
        });
    }
    state.inflight.release(&converted);
    let after = state.inflight.len();
    let released = before.saturating_sub(after);
    Ok(serde_json::json!({
        "released_count": released,
        "remaining_in_flight": after,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rpc_error_envelope_carries_structured_data_for_insufficient_balance() {
        // With in-flight UTXOs — SDKs need `in_flight_reserved=true` to
        // know "retry once the pending transfer confirms" is the right
        // recovery vs. "wallet is genuinely under-funded".
        let err = Error::InsufficientBalance {
            needed: 5_100_000,
            available: 4_000_000,
            utxo_count: 1,
            in_flight_value: 9_000_000,
            in_flight_count: 2,
        };
        let resp = RpcResponse::err(json!(7), &err);
        let v = serde_json::to_value(&resp).unwrap();

        assert_eq!(v["error"]["code"], -32031);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("reserved by pending transfers"),
            "message should still carry the human hint for log readers"
        );
        assert_eq!(v["error"]["data"]["in_flight_reserved"], true);
        assert_eq!(v["error"]["data"]["needed"], 5_100_000);
        assert_eq!(v["error"]["data"]["available"], 4_000_000);
        assert_eq!(v["error"]["data"]["utxo_count"], 1);
        assert_eq!(v["error"]["data"]["in_flight_value"], 9_000_000);
        assert_eq!(v["error"]["data"]["in_flight_count"], 2);
    }

    #[test]
    fn rpc_error_data_present_but_in_flight_reserved_false_when_no_pending() {
        let err = Error::InsufficientBalance {
            needed: 1_000_000,
            available: 100_000,
            utxo_count: 1,
            in_flight_value: 0,
            in_flight_count: 0,
        };
        let v = serde_json::to_value(RpcResponse::err(json!(1), &err)).unwrap();
        assert_eq!(v["error"]["data"]["in_flight_reserved"], false);
        assert_eq!(v["error"]["data"]["in_flight_count"], 0);
    }

    #[test]
    fn rpc_error_data_omitted_for_errors_without_payload() {
        // Other variants must not start emitting a phantom `data: null` —
        // the field is skip-serialized when None.
        let err = Error::Unauthorized;
        let v = serde_json::to_value(RpcResponse::err(json!(1), &err)).unwrap();
        assert!(v["error"].get("data").is_none(), "got {:?}", v["error"]);
    }
}
