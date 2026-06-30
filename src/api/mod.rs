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
use tokio::sync::watch;

use crate::error::{Error, Result};
use crate::idempotency::IdempotencyCache;
use crate::index::Index;
use crate::indexer::IndexerClient;
use crate::inflight::InFlightUtxos;
use crate::store::WalletStore;
use crate::tx::{FeeChoice, TransferReceipt};
use crate::upstream::ExferNode;
use exfer::covenants::htlc::{HtlcParams, HtlcRecord, HtlcRole, HtlcState};

pub mod htlc;
pub mod payment_uri;
pub mod quote;
pub mod signmsg;
pub mod simulate;
pub mod swap;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn WalletStore>,
    pub node: Arc<ExferNode>,
    pub inflight: Arc<InFlightUtxos>,
    pub idempotency: Arc<IdempotencyCache>,
    /// HTLC observability index. Populated by the block follower at
    /// boot and updated every poll cycle; read by `htlc_status` /
    /// `htlc_list` / `get_follower_status` (v1.9 +).
    pub index: Arc<Index>,
    /// Receiver end of the follower's tip-height watch channel. Each
    /// observation is the height the follower has finished
    /// processing. `wait_for_tx` subscribes to this to avoid polling.
    pub tip_rx: watch::Receiver<u64>,
    /// Optional upstream indexer client. When `Some`, methods that
    /// need data outside the wallet's owned keys (HTLCs we never
    /// locked, settlement history of other addresses, etc.) delegate
    /// to this client transparently. When `None`, those queries
    /// return `-32041 IndexerNotConfigured`.
    pub indexer: Option<IndexerClient>,
    /// In-process push bus fed by the upstream-node SSE client. When the
    /// node's `/sse` endpoint is reachable, `Script` / `Tip` / `Resync`
    /// nudges arrive here within a network RTT. `wait_for_payment`
    /// subscribes to it for sub-second inbound-credit detection, falling
    /// back to the follower tip channel when SSE is unavailable.
    pub events: Arc<crate::sse_client::WalletEvents>,
    /// Cross-chain swap engine (EXFER↔USDT). `Some` only when `--swap-pool`
    /// is configured; the `swap_*` / `bsc_*` RPCs return `-32602` otherwise.
    pub engine: Option<Arc<crate::swap::SwapEngine>>,
    /// Spend allowance ledger. Enforces the operator-configured per-tx and
    /// per-period EXFER spend ceilings on `transfer` / `htlc_lock`. Inert
    /// (always allows) when no `--spend-cap-*` flags are set.
    pub allowance: Arc<crate::allowance::AllowanceLedger>,
    /// Lock-confirmation watchdog. `Some` only when `--lock-watchdog` is
    /// set (the pool sidecar deploy); rebroadcasts an evicted operator
    /// HTLC lock so it isn't silently lost. `None` for the embedded
    /// mobile/desktop walletds (no extra polling).
    pub lock_watch: Option<Arc<crate::lock_watch::LockWatch>>,
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
    /// Optional datum (hex): a generic, app-defined on-chain blob carried
    /// by the payment, attached to the primary (first) recipient output.
    /// The chain validates only size (<= MAX_DATUM_SIZE = 4096 bytes);
    /// the meaning of the bytes is entirely the application's. Read it
    /// back with `get_output_datum`.
    #[serde(default)]
    pub datum: Option<String>,
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
        "generate_independent_address" => generate_independent_address(state, req.params).await,
        "generate_standard_address" => generate_standard_address(state, req.params).await,
        "import_private_key" => import_private_key(state, req.params).await,
        "export_vault" => export_vault(state, req.params).await,
        "import_vault" => import_vault(state, req.params).await,
        "export_address" => export_address(state, req.params).await,
        "import_mnemonic" => import_mnemonic(state, req.params).await,
        "import_standard_mnemonic" => import_standard_mnemonic(state, req.params).await,
        "delete_address" => delete_address(state, req.params).await,
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

        // ---- cross-chain swap (EXFER ↔ BNB), needs --swap-pool ----
        "swap_get_quote" => swap::swap_get_quote(state, req.params).await,
        "swap_execute" => swap::swap_execute(state, req.params).await,
        "swap_refund" => swap::swap_refund(state, req.params).await,
        "swap_status" => swap::swap_status(state, req.params).await,
        "swap_refresh" => swap::swap_refresh(state, req.params).await,
        "swap_list" => swap::swap_list(state).await,
        "swap_pool_info" => swap::swap_pool_info(state).await,
        "swap_price_klines" => swap::swap_price_klines(state, req.params).await,
        "lp_pool_info" => swap::lp_pool_info(state).await,
        "lp_position" => swap::lp_position(state, req.params).await,
        "lp_deposit_start" => swap::lp_deposit_start(state, req.params).await,
        "lp_deposit_status" => swap::lp_deposit_status(state, req.params).await,
        "lp_withdraw_self" => swap::lp_withdraw_self(state, req.params).await,
        "bsc_get_address" => swap::bsc_get_address(state).await,
        "bsc_create_address" => swap::bsc_create_address(state, req.params).await,
        "bsc_reveal_mnemonic" => swap::bsc_reveal_mnemonic(state, req.params).await,
        "bsc_import_mnemonic" => swap::bsc_import_mnemonic(state, req.params).await,
        "bsc_import_key" => swap::bsc_import_key(state, req.params).await,
        "bsc_delete_key" => swap::bsc_delete_key(state, req.params).await,
        "bsc_get_balances" => swap::bsc_get_balances(state).await,
        "bsc_send_bnb" => swap::bsc_send_bnb(state, req.params).await,
        "bsc_tx_history" => swap::bsc_tx_history(state).await,

        // ---- payment URI codec (pure) ----
        "payment_uri_encode" => payment_uri::payment_uri_encode(req.params).await,
        "payment_uri_decode" => payment_uri::payment_uri_decode(req.params).await,

        // ---- HTLC observability (index-backed) ----
        "htlc_status" => htlc::htlc_status_method(state, req.params).await,
        "htlc_list" => htlc::htlc_list_method(state, req.params).await,
        "htlc_forget" => htlc::htlc_forget_method(state, req.params).await,
        "get_follower_status" => htlc::get_follower_status_method(state, req.params).await,
        "wait_for_tx" => htlc::wait_for_tx_method(state, req.params).await,
        "wait_for_payment" => htlc::wait_for_payment_method(state, req.params).await,

        // ---- Indexer-delegated methods (v1.9.1+, --indexer-rpc) ----
        //
        // These four methods are *only* answerable by a multi-tenant
        // indexer — they ask about addresses walletd does not own
        // keys for. When --indexer-rpc is unset, every method here
        // returns -32041 IndexerNotConfigured and the operator knows
        // to wire one up.
        "list_settlements" => proxy_to_indexer(state, "list_settlements", req.params).await,
        "contract_stats" => proxy_to_indexer(state, "contract_stats", req.params).await,
        "get_address_history" => proxy_to_indexer(state, "get_address_history", req.params).await,
        "get_attestation_edges" => {
            proxy_to_indexer(state, "get_attestation_edges", req.params).await
        }
        "detect_in_chain_swaps" => {
            proxy_to_indexer(state, "detect_in_chain_swaps", req.params).await
        }
        "htlc_lookup_by_hashlock" => {
            proxy_to_indexer(state, "htlc_lookup_by_hashlock", req.params).await
        }
        "get_output_spent_by" => proxy_to_indexer(state, "get_output_spent_by", req.params).await,
        "get_output_datum" => proxy_to_indexer(state, "get_output_datum", req.params).await,
        "find_settlements_by_quote_id" => {
            proxy_to_indexer(state, "find_settlements_by_quote_id", req.params).await
        }

        // ---- read passthroughs ----
        "get_block_height" => get_block_height(state).await,
        "get_block_by_id" => get_block_by_id(state, req.params).await,
        "get_block_by_height" => get_block_by_height(state, req.params).await,
        "get_block_id_at_height" => get_block_id_at_height(state, req.params).await,
        "get_transaction" => get_transaction(state, req.params).await,
        "get_balance" => get_balance(state, req.params).await,
        "get_address_utxos" => get_address_utxos(state, req.params).await,
        "get_script_utxos" => get_script_utxos(state, req.params).await,
        "get_address_mempool" => get_address_mempool(state, req.params).await,

        // ---- broadcast passthrough ----
        "send_raw_transaction" => send_raw_transaction(state, req.params).await,

        // ---- proof-of-ownership signatures ----
        "sign_message" => signmsg::sign_message(state, req.params).await,
        "verify_message" => signmsg::verify_message(state, req.params).await,

        // ---- EXFER-QUOTE signed price credential ----
        "quote_issue" => quote::quote_issue(state, req.params).await,
        "quote_verify" => quote::quote_verify(state, req.params).await,

        // ---- spend allowance (read-only introspection of the caps) ----
        "allowance_status" => allowance_status_method(state),

        // ---- sensitive recovery export (passphrase-gated, spend-scope) ----
        "reveal_mnemonic" => reveal_mnemonic(state, req.params).await,
        "reveal_private_key" => reveal_private_key(state, req.params).await,
        "reveal_evm_private_key" => reveal_evm_private_key(state, req.params).await,
        "reveal_address_mnemonic" => reveal_address_mnemonic(state, req.params).await,

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

/// Forward a request to the configured `--indexer-rpc` upstream, or
/// return `IndexerNotConfigured` if no indexer is configured.
async fn proxy_to_indexer(state: &ApiState, method: &str, params: Value) -> Result<Value> {
    match state.indexer.as_ref() {
        Some(client) => client.call(method, params).await,
        None => Err(Error::IndexerNotConfigured),
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

/// `generate_independent_address` — a fresh address whose key is its own
/// (1:1), not derived from the shared HD seed. Individually exportable; a
/// leak of one key doesn't touch the others.
async fn generate_independent_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: GenerateAddressParams = if params.is_null() {
        GenerateAddressParams::default()
    } else {
        serde_json::from_value(params)
            .map_err(|e| Error::BadParams(format!("generate_independent_address params: {e}")))?
    };
    let store = state.store.clone();
    let label = p.label.clone();
    let (address, pubkey) = tokio::task::spawn_blocking(move || store.create_independent(label))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %address, "generated independent (1:1) address");
    Ok(serde_json::json!({ "address": address, "pubkey": pubkey, "imported": true }))
}

/// `generate_standard_address` — the DEFAULT for new addresses. A fresh 1:1
/// address derived from a random standard BIP-39 phrase (matches exfer.dev /
/// the apps); its phrase is sealed so it can be revealed and re-imported to the
/// same address anywhere. Manage-scoped, like the other generators.
async fn generate_standard_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: GenerateAddressParams = if params.is_null() {
        GenerateAddressParams::default()
    } else {
        serde_json::from_value(params)
            .map_err(|e| Error::BadParams(format!("generate_standard_address params: {e}")))?
    };
    let store = state.store.clone();
    let label = p.label.clone();
    let (address, pubkey) = tokio::task::spawn_blocking(move || store.create_standard(label))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %address, "generated standard (BIP-39) address");
    Ok(serde_json::json!({ "address": address, "pubkey": pubkey, "imported": true }))
}

#[derive(serde::Deserialize)]
struct VaultExportParams {
    passphrase: String,
}

/// `export_vault` — one passphrase-sealed blob backing up EVERY key in the
/// wallet (a single-file backup that doesn't hinge on a mnemonic). Sensitive:
/// the blob decrypts to every private key. Spend-scoped.
async fn export_vault(state: &ApiState, params: Value) -> Result<Value> {
    let p: VaultExportParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("export_vault params: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    let blob = tokio::task::spawn_blocking(move || store.export_vault(pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(
        bytes = blob.len(),
        "vault exported — sensitive output (all keys)"
    );
    Ok(serde_json::json!({ "vault_hex": hex::encode(&blob) }))
}

#[derive(serde::Deserialize)]
struct VaultImportParams {
    vault_hex: String,
    passphrase: String,
}

/// `import_vault` — restore keys from an `export_vault` blob, each as an
/// independent key. Already-present addresses are skipped.
async fn import_vault(state: &ApiState, params: Value) -> Result<Value> {
    let p: VaultImportParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("import_vault params: {e}")))?;
    let blob = hex::decode(&p.vault_hex).map_err(|e| Error::BadHex(format!("vault_hex: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    let imported = tokio::task::spawn_blocking(move || store.import_vault(&blob, pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(count = imported.len(), "vault imported");
    Ok(serde_json::json!({ "imported": imported }))
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

#[derive(serde::Deserialize)]
struct ExportAddressParams {
    address: String,
    passphrase: String,
}

/// `export_address` — one passphrase-sealed blob backing up a SINGLE
/// address's key (same WDV1 vault format, so it restores via
/// `import_vault`). Sensitive: decrypts to that private key. Spend-scoped.
async fn export_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: ExportAddressParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("export_address params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let address = p.address.to_ascii_lowercase();
    let store = state.store.clone();
    let pass = p.passphrase;
    let addr_for_blocking = address.clone();
    let blob = tokio::task::spawn_blocking(move || {
        store.export_selected(std::slice::from_ref(&addr_for_blocking), pass.as_bytes())
    })
    .await
    .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(address = %address, bytes = blob.len(), "export_address served — sensitive (one key)");
    Ok(serde_json::json!({ "address": address, "vault_hex": hex::encode(&blob) }))
}

#[derive(serde::Deserialize)]
struct ImportMnemonicParams {
    mnemonic: String,
    #[serde(default)]
    label: Option<String>,
}

/// `import_mnemonic` — register a 24-word BIP-39 phrase as an independent
/// address (its 256-bit entropy is the ed25519 secret). The per-address
/// recovery-phrase counterpart of `reveal_address_mnemonic`. Manage-scope,
/// matching `import_private_key`.
async fn import_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: ImportMnemonicParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("import_mnemonic params: {e}")))?;
    let store = state.store.clone();
    let label = p.label.clone();
    let phrase = p.mnemonic.clone();
    let address = tokio::task::spawn_blocking(move || store.import_mnemonic(&phrase, label))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %address, "imported address from recovery phrase");
    Ok(serde_json::json!({ "address": address, "imported": true }))
}

/// `import_standard_mnemonic` — import a STANDARD phrase to the same address it
/// has elsewhere (exfer.dev / the apps), sealing the phrase so it reveals back.
/// Use for standard phrases; `import_mnemonic` is the legacy raw-key path.
async fn import_standard_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: ImportMnemonicParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("import_standard_mnemonic params: {e}")))?;
    let store = state.store.clone();
    let label = p.label.clone();
    let phrase = p.mnemonic.clone();
    let address =
        tokio::task::spawn_blocking(move || store.import_standard_mnemonic(&phrase, label))
            .await
            .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::info!(address = %address, "imported address from standard recovery phrase");
    Ok(serde_json::json!({ "address": address, "imported": true }))
}

#[derive(serde::Deserialize)]
struct DeleteAddressParams {
    address: String,
    passphrase: String,
    /// Delete even when the address still holds (or might hold) funds.
    /// Without it, a non-zero confirmed balance — or an upstream we can't
    /// reach to check — blocks the delete so a key with money on it isn't
    /// dropped by accident.
    #[serde(default)]
    force: bool,
}

/// `delete_address` — permanently remove an address from the keystore.
/// Passphrase-gated. For an independent/imported key the sealed secret is
/// erased (gone unless separately backed up). A funds guard refuses the
/// delete when the address still has a confirmed balance, or when the
/// balance can't be verified, unless `force` is set. Spend-scoped: this is
/// destructive and can strand value.
async fn delete_address(state: &ApiState, params: Value) -> Result<Value> {
    let p: DeleteAddressParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("delete_address params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let address = p.address.to_ascii_lowercase();

    if !p.force {
        match state.node.get_balance(&address).await {
            Ok(b) if b.balance > 0 => {
                return Err(Error::BadParams(format!(
                    "address {address} still holds {} exfers — sweep it first, or pass \
                     \"force\": true to delete anyway (the key is erased unless backed up)",
                    b.balance
                )));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(Error::BadParams(format!(
                    "could not verify the balance of {address} ({e}); refusing to delete a \
                     possibly-funded key. Retry when upstream is reachable, or pass \
                     \"force\": true to delete without checking."
                )));
            }
        }

        // Off-chain LP guard. The on-chain balance check above is blind to the
        // pool's off-chain LP share ledger: an address with a 0 on-chain
        // balance can still own a position, and deleting it strands the funds
        // (a self-serve withdrawal auto-returns EXFER to this now-unspendable
        // address). When swap is configured, ask the pool for the position; a
        // non-zero share count — OR an unreachable pool we can't clear — blocks
        // the (irreversible) delete unless `force` is set. Fail CLOSED.
        if let Some(engine) = state.engine.as_ref() {
            match engine.lp_position(&address).await {
                Ok(pos) => {
                    let has = pos
                        .get("has_position")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let shares = pos.get("shares").and_then(|v| v.as_str()).unwrap_or("0");
                    let has_shares = shares != "0" && !shares.is_empty();
                    if has || has_shares {
                        return Err(Error::BadParams(format!(
                            "address {address} still owns liquidity-pool shares ({shares}) — \
                             withdraw the position first, or pass \"force\": true to delete \
                             anyway (the LP funds are stranded if you do)."
                        )));
                    }
                }
                Err(e) => {
                    return Err(Error::BadParams(format!(
                        "could not verify the liquidity-pool position of {address} ({e}); \
                         refusing to delete a key that might still own LP shares. Retry when \
                         the pool is reachable, or pass \"force\": true to delete without \
                         checking."
                    )));
                }
            }
        }
    }

    let store = state.store.clone();
    let pass = p.passphrase;
    let addr_for_blocking = address.clone();
    tokio::task::spawn_blocking(move || store.delete(&addr_for_blocking, pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(address = %address, force = p.force, "address deleted from keystore");
    Ok(serde_json::json!({ "deleted": address }))
}

async fn transfer_method(state: &ApiState, params: Value) -> Result<Value> {
    let p: TransferParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("transfer params: {e}")))?;

    // ---- envelope-level validation (cheap, no upstream calls) --------
    // Accept-both: `from` and every recipient may be legacy 64-hex or bech32m
    // for this network. Normalize `from` to canonical hex for the hex-keyed
    // keystore lookup below; recipients are decoded to bytes further down.
    let (from_hex, _) = parse_address_hex(&p.from)?;
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
        parse_address(&o.to)?;
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

    // Sum the EXFER leaving this wallet for the allowance ledger.
    // Saturating: an absurd sum that overflows u64 can only exceed a finite
    // cap, never wrap under it. The reserve/refund happens *inside* the
    // idempotency unit below, so an idempotent retry neither double-charges
    // nor re-checks an already-completed spend.
    let allowance_amount: u64 = p
        .outputs
        .iter()
        .fold(0u64, |a, o| a.saturating_add(o.amount));
    let allowance_now = crate::allowance::now_unix();
    // Fast-fail the stateless per-tx ceiling before any keystore I/O. The
    // per-period window is reserved atomically inside the idempotency unit
    // below (re-running this stateless check on a retry is harmless).
    state.allowance.check_per_tx(allowance_amount)?;

    let fee_choice = match (p.fee, p.fee_rate) {
        (Some(f), None) => FeeChoice::Absolute(f),
        (None, Some(r)) => FeeChoice::Rate(r),
        // Default: rate = 1 (consensus minimum).
        (None, None) => FeeChoice::Rate(1),
        (Some(_), Some(_)) => unreachable!("guarded above"),
    };
    let max_fee = p.max_fee.unwrap_or(DEFAULT_MAX_FEE);

    // Convert recipient addresses into Hash256s (accept-both via the codec).
    let mut recipients: Vec<(exfer::types::Hash256, u64)> = Vec::with_capacity(p.outputs.len());
    for o in &p.outputs {
        recipients.push((exfer::types::Hash256(parse_address(&o.to)?), o.amount));
    }

    // ---- load the signer (blocking FS I/O on the keystore) -----------
    let store = state.store.clone();
    let from = from_hex;
    let signer = tokio::task::spawn_blocking(move || store.load_by_address(&from))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;

    // ---- optional datum: a generic app-defined blob on the payment ----
    let recipient_datum: Option<Vec<u8>> = match p.datum.as_deref() {
        None => None,
        Some(h) => {
            let b = hex::decode(h).map_err(|e| Error::BadHex(e.to_string()))?;
            if b.len() > exfer::types::MAX_DATUM_SIZE {
                return Err(Error::BadParams(format!(
                    "datum is {} bytes, exceeds MAX_DATUM_SIZE {}",
                    b.len(),
                    exfer::types::MAX_DATUM_SIZE
                )));
            }
            Some(b)
        }
    };

    // ---- run, possibly through the idempotency cache -----------------
    let receipt: std::sync::Arc<TransferReceipt> = match p.client_token.as_deref() {
        Some(token) => {
            let fingerprint = fingerprint_transfer(&p, &fee_choice, max_fee);
            let recipients_for_run = recipients.clone();
            let datum_for_run = recipient_datum.clone();
            state
                .idempotency
                .get_or_run(token, fingerprint, move || async move {
                    // Atomic check-and-reserve before broadcast; refund if
                    // the broadcast itself fails so a failed spend doesn't
                    // consume the window.
                    state.allowance.reserve(allowance_amount, allowance_now)?;
                    match crate::tx::transfer(
                        &signer,
                        recipients_for_run,
                        datum_for_run,
                        fee_choice,
                        max_fee,
                        &state.node,
                        &state.inflight,
                    )
                    .await
                    {
                        Ok(r) => Ok(r),
                        Err(e) => {
                            state.allowance.refund(allowance_amount, allowance_now);
                            Err(e)
                        }
                    }
                })
                .await?
        }
        None => {
            state.allowance.reserve(allowance_amount, allowance_now)?;
            match crate::tx::transfer(
                &signer,
                recipients,
                recipient_datum,
                fee_choice,
                max_fee,
                &state.node,
                &state.inflight,
            )
            .await
            {
                Ok(r) => std::sync::Arc::new(r),
                Err(e) => {
                    state.allowance.refund(allowance_amount, allowance_now);
                    return Err(e);
                }
            }
        }
    };

    serde_json::to_value(&*receipt).map_err(|e| Error::Internal(e.to_string()))
}

/// `allowance_status` — report the operator-configured spend ceilings and
/// the current rolling-window consumption. Read scope: pure, touches no
/// funds and reveals only policy + a counter.
fn allowance_status_method(state: &ApiState) -> Result<Value> {
    let s = state.allowance.status(crate::allowance::now_unix())?;
    Ok(serde_json::json!({
        "per_tx": s.per_tx,
        "per_period": s.per_period,
        "period_secs": s.period_secs,
        "spent_this_period": s.spent_this_period,
        "remaining_this_period": s.remaining_this_period,
        "window_resets_at": s.window_resets_at,
    }))
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
    // A different datum yields a different transfer, so it must change the
    // idempotency fingerprint too.
    p.datum.as_deref().map(str::to_ascii_lowercase).hash(&mut h);
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

    // Boot grace gate: if a startup reconcile couldn't seed reservations
    // from the mempool, `htlc_lock` is briefly held off so a restart
    // mid-burst can't re-collide with a still-unconfirmed pre-restart
    // lock. Surfaces as the same retryable -32039 the pool re-ticks on.
    // Gate ONLY htlc_lock (the collision surface); claims/reclaims/
    // transfers are unaffected.
    if state.inflight.locks_held() {
        return Err(Error::InFlightExhausted {
            needed: p.amount,
            available: 0,
            in_flight_value: 0,
            in_flight_count: 0,
        });
    }

    let receiver = crate::tx::decode_hash(&p.receiver)?;
    let hash_lock = exfer::types::Hash256(crate::tx::decode_hash(&p.hash_lock)?);

    // ---- spend allowance ----
    // Fast-fail the stateless per-tx ceiling before keystore I/O; reserve
    // the per-period window right before the lock so a signer-load failure
    // can't leak a reservation. htlc_lock has no idempotency token, so
    // reserve/refund sit directly around the lock call.
    let allowance_now = crate::allowance::now_unix();
    state.allowance.check_per_tx(p.amount)?;

    let signer = load_signer(state, &p.from).await?;
    state.allowance.reserve(p.amount, allowance_now)?;
    let receipt = match crate::tx::htlc::htlc_lock(
        &signer,
        receiver,
        hash_lock,
        p.timeout,
        p.amount,
        fee_choice,
        max_fee,
        &state.node,
        &state.inflight,
        state.lock_watch.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            state.allowance.refund(p.amount, allowance_now);
            return Err(e);
        }
    };

    // Eagerly record our own outgoing HTLC so `htlc_status` / `htlc_list`
    // surface it IMMEDIATELY, rather than only after the block follower
    // re-discovers it from chain — which can lag badly. Best-effort: the lock
    // has already broadcast, so an index hiccup must not fail the call.
    if let Ok(lock_tx_id) = crate::tx::decode_hash(&receipt.tx_id) {
        let record = eager_lock_record(
            lock_tx_id,
            receipt.htlc_output_index,
            signer.pubkey(),
            receiver,
            hash_lock.0,
            p.timeout,
            receipt.amount,
            receipt.built_at_height,
        );
        if let Ok(owned_addr) = crate::tx::decode_hash(&p.from) {
            if let Err(e) = state.index.upsert_htlc(&record, owned_addr) {
                tracing::warn!("htlc_lock: eager index write failed (non-fatal): {e}");
            }
        }
    }

    serde_json::to_value(&receipt).map_err(|e| Error::Internal(e.to_string()))
}

/// Build the optimistic mempool `HtlcRecord` for a just-broadcast OUTGOING
/// HTLC lock. `lock_block_height: None` marks it mempool-pending (the
/// documented wallet-daemon optimistic case); `role: Sender` because we
/// funded it; `state: Locked`. The follower reconciles the confirmed height
/// and any claim/reclaim once the lock lands in a block.
#[allow(clippy::too_many_arguments)]
fn eager_lock_record(
    lock_tx_id: [u8; 32],
    output_index: u32,
    sender_pubkey: [u8; 32],
    receiver: [u8; 32],
    hash_lock: [u8; 32],
    timeout_height: u64,
    amount: u64,
    observed_height: u64,
) -> HtlcRecord {
    HtlcRecord {
        lock_tx_id,
        output_index,
        params: HtlcParams {
            sender: sender_pubkey,
            receiver,
            hash_lock,
            timeout_height,
        },
        amount,
        lock_block_height: None,
        state: HtlcState::Locked,
        claim: None,
        reclaim: None,
        role: HtlcRole::Sender,
        last_indexed_height: observed_height,
    }
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
    let (addr, _) = parse_address_hex(&p.address)?;
    let bal = state.node.get_balance(&addr).await?;
    serde_json::to_value(&bal).map_err(|e| Error::Internal(e.to_string()))
}

async fn get_address_utxos(state: &ApiState, params: Value) -> Result<Value> {
    // Opt-in per-UTXO availability annotation (default off → unchanged
    // shape + no extra mempool scan). Read before `params` is consumed.
    let with_status = params
        .get("status")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_address_utxos params: {e}")))?;
    let (addr, _) = parse_address_hex(&p.address)?;
    let u = state.node.get_address_utxos(&addr).await?;
    let mut out = serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))?;
    if with_status {
        annotate_utxo_status(state, &addr, u.tip_height, &mut out).await?;
    }
    Ok(out)
}

/// Tag each UTXO in a `get_address_utxos` response with an availability
/// `status`, and add response-level `available_value` + `status_supported`.
///
/// `get_address_utxos` is the node's *confirmed* UTXO set with no
/// per-output state — a UTXO can be listed yet not actually spendable.
/// This reconciles three signals the bare list can't:
///
/// - `immature`  — a coinbase output younger than `COINBASE_MATURITY`.
/// - `reserved`  — claimed by an in-flight transfer *this* daemon is
///   broadcasting (ephemeral, in-memory; see [`crate::inflight`]).
/// - `spending`  — being spent by a tx already in the node's mempool
///   (from `get_address_mempool`'s spent set) — covers spends by another
///   wallet, or this wallet's own after a restart dropped the in-flight
///   set. Without the node method (pre-v1.11.3) this can't be detected;
///   `status_supported` then reports `false` and no row is marked
///   `spending`.
/// - `available` — none of the above.
///
/// Priority when several apply: immature > reserved > spending >
/// available.
/// Pure UTXO availability classification. Priority: immature > reserved
/// > spending > available.
fn classify_utxo_status(
    is_coinbase: bool,
    height: u64,
    tip_height: u64,
    reserved: bool,
    spending: bool,
) -> &'static str {
    if is_coinbase && tip_height.saturating_sub(height) < exfer::types::COINBASE_MATURITY {
        "immature"
    } else if reserved {
        "reserved"
    } else if spending {
        "spending"
    } else {
        "available"
    }
}

async fn annotate_utxo_status(
    state: &ApiState,
    address: &str,
    tip_height: u64,
    out: &mut Value,
) -> Result<()> {
    use std::collections::HashSet;

    // Reserved: this daemon's in-flight claims, keyed (tx_id hex, vout).
    let reserved: HashSet<(String, u32)> = state
        .inflight
        .pending()
        .into_iter()
        .map(|op| (hex::encode(op.tx_id.as_bytes()), op.output_index))
        .collect();

    // Spending: outpoints of this address being spent in the mempool.
    // None ⇒ upstream predates get_address_mempool; spending unknown.
    let mempool = state.node.get_address_mempool_opt(address).await?;
    let status_supported = mempool.is_some();
    let spending: HashSet<(String, u32)> = mempool
        .map(|m| {
            m.mempool
                .iter()
                .flat_map(|t| t.spent.iter())
                .map(|s| (s.tx_id.clone(), s.output_index))
                .collect()
        })
        .unwrap_or_default();

    let mut available_value: u64 = 0;
    if let Some(arr) = out.get_mut("utxos").and_then(Value::as_array_mut) {
        for entry in arr.iter_mut() {
            let txid = entry["tx_id"].as_str().unwrap_or_default().to_string();
            let vout = entry["output_index"].as_u64().unwrap_or(0) as u32;
            let value = entry["value"].as_u64().unwrap_or(0);
            let is_coinbase = entry["is_coinbase"].as_bool().unwrap_or(false);
            let height = entry["height"].as_u64().unwrap_or(0);
            let key = (txid, vout);

            let status = classify_utxo_status(
                is_coinbase,
                height,
                tip_height,
                reserved.contains(&key),
                spending.contains(&key),
            );
            if status == "available" {
                available_value += value;
            }
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("status".into(), serde_json::json!(status));
            }
        }
    }
    if let Some(obj) = out.as_object_mut() {
        obj.insert("available_value".into(), serde_json::json!(available_value));
        obj.insert(
            "status_supported".into(),
            serde_json::json!(status_supported),
        );
    }
    Ok(())
}

async fn get_script_utxos(state: &ApiState, params: Value) -> Result<Value> {
    let p: ScriptHexParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_script_utxos params: {e}")))?;
    ensure_hex(&p.script_hex)?;
    let u = state.node.get_script_utxos(&p.script_hex).await?;
    serde_json::to_value(&u).map_err(|e| Error::Internal(e.to_string()))
}

/// `get_address_mempool` — thin passthrough exposing the node's
/// unconfirmed view of one address (pending incoming/outgoing with
/// amounts). Lets a deposit watcher show "+X pending" the moment a
/// transfer hits the mempool, ahead of confirmation.
async fn get_address_mempool(state: &ApiState, params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("get_address_mempool params: {e}")))?;
    let (addr, _) = parse_address_hex(&p.address)?;
    let m = state.node.get_address_mempool(&addr).await?;
    serde_json::to_value(&m).map_err(|e| Error::Internal(e.to_string()))
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

#[derive(serde::Deserialize)]
struct RevealEvmKeyParams {
    passphrase: String,
}

/// Reveal the BSC/EVM (secp256k1) private key for the wallet's BNB address —
/// the `m/44'/60'/0'/0/0` key — so the user can import it into MetaMask-style
/// wallets ("Import account → Private key"). Returns the 0x-prefixed hex plus
/// the address it controls, for confirmation. Spend-scoped + passphrase-gated.
async fn reveal_evm_private_key(state: &ApiState, params: Value) -> Result<Value> {
    let p: RevealEvmKeyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("reveal_evm_private_key params: {e}")))?;
    let store = state.store.clone();
    let pass = p.passphrase;
    let secret = tokio::task::spawn_blocking(move || store.reveal_evm_secret(pass.as_bytes()))
        .await
        .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    let address = crate::evm::evm_address(&secret)?;
    let private_key_hex = format!("0x{}", hex::encode(secret.as_ref()));
    tracing::warn!(address = %address, "reveal_evm_private_key served — sensitive output");
    Ok(serde_json::json!({
        "address":         address,
        "private_key_hex": private_key_hex,
    }))
}

/// `reveal_address_mnemonic` — that one address's OWN 24-word recovery
/// phrase (its ed25519 secret encoded as BIP-39), distinct from the
/// whole-wallet seed phrase served by `reveal_mnemonic`. Spend-scoped.
async fn reveal_address_mnemonic(state: &ApiState, params: Value) -> Result<Value> {
    let p: RevealPrivateKeyParams = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("reveal_address_mnemonic params: {e}")))?;
    ensure_64_hex(&p.address)?;
    let address = p.address.to_ascii_lowercase();
    let store = state.store.clone();
    let pass = p.passphrase;
    let addr_for_blocking = address.clone();
    let words = tokio::task::spawn_blocking(move || {
        store.reveal_address_mnemonic(&addr_for_blocking, pass.as_bytes())
    })
    .await
    .map_err(|e| Error::Internal(format!("blocking task panicked: {e}")))??;
    tracing::warn!(address = %address, "reveal_address_mnemonic served — sensitive output");
    Ok(serde_json::json!({ "address": address, "mnemonic": words }))
}

// ----------------------------------------------------------------------------
// New wallet-side conveniences (v1.0)
// ----------------------------------------------------------------------------

/// `validate_address` — pure check that a string is a well-formed address in
/// either accepted form (legacy 64-hex or bech32m for this network). Returns
/// the canonical lowercase 64-hex `normalized` spelling when valid, so callers
/// can key/compare on one form regardless of which the user typed. No upstream
/// calls.
async fn validate_address(params: Value) -> Result<Value> {
    let p: AddressParam = serde_json::from_value(params)
        .map_err(|e| Error::BadParams(format!("validate_address params: {e}")))?;
    match parse_address(p.address.trim()) {
        Ok(bytes) => Ok(serde_json::json!({
            "valid": true,
            "normalized": hex::encode(bytes),
        })),
        Err(_) => Ok(serde_json::json!({
            "valid": false,
            "normalized": Value::Null,
        })),
    }
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
///
/// Optional param `pending` (bool, default `false`): when `true`, also
/// fans out `get_address_mempool` per address and adds the unconfirmed
/// `pending_received` / `pending_spent` to each row plus wallet-level
/// `pending_received_total` / `pending_spent_total` / `projected_total`
/// (confirmed + received − spent). This is the receiver-side pending
/// signal — incoming funds become visible the moment they hit the
/// mempool, seconds ahead of confirmation, instead of only after a
/// block. Costs one extra scan-budget slot per address (same envelope
/// as `utxos`), so it's opt-in.
async fn get_wallet_balance(state: &ApiState, params: Value) -> Result<Value> {
    use futures::stream::{self, StreamExt, TryStreamExt};

    let include_utxos = params.get("utxos").and_then(Value::as_bool).unwrap_or(true);
    let include_pending = params
        .get("pending")
        .and_then(Value::as_bool)
        .unwrap_or(false);

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
    let addresses: Vec<String> = entries.iter().map(|e| e.address.clone()).collect();

    // ---- Balances: one batched node call (get_balances), which costs a
    //      single scan-rate slot for the whole wallet instead of one per
    //      address. Forward-compatible: a node predating the batch method
    //      answers -32601 → `None` → fall back to the per-address fan-out. ----
    let balances: std::collections::HashMap<String, u64> = if addresses.is_empty() {
        Default::default()
    } else if let Some(list) = node.get_balances_opt(&addresses).await? {
        list.into_iter().map(|b| (b.address, b.balance)).collect()
    } else {
        stream::iter(addresses.clone())
            .map(|addr| {
                let node = node.clone();
                async move {
                    Ok::<_, Error>((addr.clone(), node.get_balance(&addr).await?.balance))
                }
            })
            .buffer_unordered(8)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .collect()
    };

    // ---- UTXO counts (only when requested): batched the same way, same
    //      -32601 fallback to per-address get_address_utxos. ----
    let utxo_info: std::collections::HashMap<String, (usize, bool)> =
        if !include_utxos || addresses.is_empty() {
            Default::default()
        } else if let Some(batch) = node.get_address_utxos_batch_opt(&addresses).await? {
            batch
                .addresses
                .into_iter()
                .map(|a| (a.address, (a.utxos.len(), a.truncated)))
                .collect()
        } else {
            stream::iter(addresses.clone())
                .map(|addr| {
                    let node = node.clone();
                    async move {
                        let u = node.get_address_utxos(&addr).await?;
                        Ok::<_, Error>((addr.clone(), (u.utxos.len(), u.truncated)))
                    }
                })
                .buffer_unordered(8)
                .try_collect::<Vec<_>>()
                .await?
                .into_iter()
                .collect()
        };

    // ---- Pending (mempool): one batched node call when supported, which
    //      costs a SINGLE scan-rate slot for the whole wallet instead of one
    //      per address. A node predating the batch method answers -32601 →
    //      `None` → fall back to the per-address fan-out in the row loop. ----
    let pending_map: Option<std::sync::Arc<std::collections::HashMap<String, (u64, u64)>>> =
        if !include_pending || addresses.is_empty() {
            None
        } else {
            node.get_address_mempool_batch_opt(&addresses)
                .await?
                .map(|b| {
                    std::sync::Arc::new(
                        b.addresses
                            .into_iter()
                            .map(|e| {
                                (
                                    e.address.to_lowercase(),
                                    (e.pending_received(), e.pending_spent()),
                                )
                            })
                            .collect(),
                    )
                })
        };

    // ---- Assemble rows from the batched maps. ----
    let rows: Vec<Value> = stream::iter(entries.clone())
        .map(|entry| {
            let node = node.clone();
            let bal = balances.get(&entry.address).copied().unwrap_or(0);
            let utxo = utxo_info.get(&entry.address).copied();
            let pending_map = pending_map.clone();
            async move {
                let mut row = serde_json::json!({
                    "address": entry.address,
                    "index": entry.index,
                    "label": entry.label,
                    "imported": entry.imported,
                    "balance": bal,
                });
                if include_utxos {
                    if let Some((count, truncated)) = utxo {
                        let obj = row.as_object_mut().expect("row is an object");
                        obj.insert("utxo_count".into(), serde_json::json!(count));
                        obj.insert("truncated".into(), serde_json::json!(truncated));
                    }
                }
                if include_pending {
                    // Batch path: O(1) map lookup (absent address ⇒ no pending).
                    // Fallback path (old node): per-address get_address_mempool.
                    let pending = if let Some(map) = &pending_map {
                        map.get(&entry.address.to_lowercase()).copied()
                    } else {
                        node.get_address_mempool_opt(&entry.address)
                            .await?
                            .map(|mp| (mp.pending_received(), mp.pending_spent()))
                    };
                    if let Some((pr, ps)) = pending {
                        let obj = row.as_object_mut().expect("row is an object");
                        obj.insert("pending_received".into(), serde_json::json!(pr));
                        obj.insert("pending_spent".into(), serde_json::json!(ps));
                    }
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
    let mut out = serde_json::json!({
        "entries": rows,
        "total": total,
    });
    if include_pending {
        // Compute everything off an immutable borrow first, then mutate
        // `out` — the two borrows can't overlap.
        //
        // Every row carries pending_* only if its upstream answered
        // get_address_mempool. A row missing them means that scan hit a
        // node predating the method (-32601). If any row is missing, the
        // aggregate can't be trusted — report pending_supported:false and
        // omit the totals rather than publish a partial, misleading
        // projected balance.
        let (pending_supported, pending_received_total, pending_spent_total) = {
            let entries = out["entries"].as_array().unwrap();
            let supported = entries.iter().all(|r| r.get("pending_received").is_some());
            let recv: u64 = entries
                .iter()
                .map(|r| r["pending_received"].as_u64().unwrap_or(0))
                .sum();
            let spent: u64 = entries
                .iter()
                .map(|r| r["pending_spent"].as_u64().unwrap_or(0))
                .sum();
            (supported, recv, spent)
        };
        let obj = out.as_object_mut().expect("out is an object");
        obj.insert(
            "pending_supported".into(),
            serde_json::json!(pending_supported),
        );
        if pending_supported {
            // Projected = confirmed + unconfirmed credit − unconfirmed
            // debit. Saturating so a mempool spend the confirmed set
            // hasn't dropped yet can't underflow the displayed number.
            let projected_total = total
                .saturating_add(pending_received_total)
                .saturating_sub(pending_spent_total);
            obj.insert(
                "pending_received_total".into(),
                serde_json::json!(pending_received_total),
            );
            obj.insert(
                "pending_spent_total".into(),
                serde_json::json!(pending_spent_total),
            );
            obj.insert("projected_total".into(), serde_json::json!(projected_total));
        }
    }
    Ok(out)
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
        // The network this walletd is genesis-bound to ("mainnet"/"testnet"/
        // "devnet"). Same source as parse_any's HRP gate, so a client can pick
        // the right bech32m HRP for display without a second round-trip.
        "network":             exfer::types::address::current_network().name(),
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

/// Parse a user-supplied ADDRESS in either accepted form into its raw 32-byte
/// hash: legacy 64-hex (mixed case preserved, bit-for-bit `hex::decode`
/// semantics) or bech32m for THIS node's network.
///
/// Delegates to the node's single authoritative codec
/// ([`exfer::types::address::parse_any`]) so walletd can never accept a string
/// the chain would decode differently — there is exactly one decoder in the
/// stack. Wrong-network, bad checksum, wrong-checksum-variant, bad length,
/// mixed case, and non-canonical padding all surface as a `-32602` client
/// error carrying the codec's specific message (e.g. "testnet address not
/// valid on this mainnet node").
///
/// Scope: use ONLY for true addresses (transfer recipients, balance/utxo
/// queries). Covenant pubkeys, hash-locks, tx-ids and block-ids stay hex-only
/// via [`ensure_64_hex`] — encoding them as addresses would invite confusion.
fn parse_address(s: &str) -> Result<[u8; 32]> {
    exfer::types::address::parse_any(s, exfer::types::address::current_network())
        .map_err(|e| Error::BadHex(e.to_string()))
}

/// Like [`parse_address`] but also returns the canonical lowercase 64-hex
/// spelling. For the sites that forward an address *string* to the upstream
/// node (which always speaks hex) or look it up in the hex-keyed keystore:
/// bech32m is normalized to hex HERE so the node never needs the codec and
/// walletd stays the sole accept-both boundary, independent of the remote
/// node's build.
fn parse_address_hex(s: &str) -> Result<(String, [u8; 32])> {
    let bytes = parse_address(s)?;
    Ok((hex::encode(bytes), bytes))
}

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
    fn eager_lock_record_is_sender_locked_mempool() {
        let rec = eager_lock_record(
            [0x11; 32], // lock_tx_id
            0,          // output_index
            [0xAA; 32], // sender pubkey (ours)
            [0xBB; 32], // receiver
            [0xCC; 32], // hash_lock
            999,        // timeout_height
            50_000,     // amount
            761_000,    // observed tip
        );
        // The whole point of the eager write: visible before confirmation.
        assert_eq!(rec.lock_block_height, None, "must be mempool-pending");
        assert_eq!(rec.state, HtlcState::Locked);
        assert_eq!(rec.role, HtlcRole::Sender, "we funded it → Sender");
        assert_eq!(rec.claim, None);
        assert_eq!(rec.reclaim, None);
        // Params round-trip exactly so htlc_status reflects the real lock.
        assert_eq!(rec.params.sender, [0xAA; 32]);
        assert_eq!(rec.params.receiver, [0xBB; 32]);
        assert_eq!(rec.params.hash_lock, [0xCC; 32]);
        assert_eq!(rec.params.timeout_height, 999);
        assert_eq!(rec.amount, 50_000);
        assert_eq!(rec.last_indexed_height, 761_000);
    }

    #[test]
    fn utxo_status_classification_priority() {
        let tip = 1000;
        // immature coinbase wins over everything (even if also flagged).
        assert_eq!(classify_utxo_status(true, 700, tip, true, true), "immature");
        // mature coinbase is not immature.
        assert_eq!(
            classify_utxo_status(true, 600, tip, false, false),
            "available"
        );
        // non-coinbase never immature regardless of height.
        assert_eq!(
            classify_utxo_status(false, 999, tip, false, false),
            "available"
        );
        // reserved beats spending.
        assert_eq!(classify_utxo_status(false, 0, tip, true, true), "reserved");
        // spending when only mempool-spent.
        assert_eq!(classify_utxo_status(false, 0, tip, false, true), "spending");
        // plain available.
        assert_eq!(
            classify_utxo_status(false, 0, tip, false, false),
            "available"
        );
    }

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
