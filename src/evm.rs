//! BSC / EVM leg of the cross-chain swap.
//!
//! Keeps secret material inside the daemon: the swap engine derives the BSC
//! secp256k1 key via [`crate::store::WalletStore::evm_secret`] and hands the raw
//! 32 bytes here only to sign. We use `alloy` for EIP-1559 encoding + signing
//! and ABI encoding, but deliberately NOT alloy's provider/transport stack —
//! all chain I/O goes over a plain `reqwest` JSON-RPC client so the mobile
//! cross-compile stays lean.
//!
//! ```text
//!  swap engine ──evm_secret()──▶ EvmClient
//!                                  │ eth_sendRawTransaction (signed EIP-1559)
//!                                  │ eth_call / eth_getTransactionCount / ...
//!                                  ▼
//!                              BSC node ──▶ ExferHtlc.sol + USDT (BEP-20)
//! ```

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use serde_json::{json, Value};

use crate::error::{Error, Result};

// ───────────────────────── ABI ─────────────────────────

sol! {
    function lock(bytes32 hashlock, address recipient, uint64 timeoutSec) external payable;
    function claim(bytes32 preimage) external;
    function refund(bytes32 hashlock) external;
    function getSwap(bytes32 hashlock) external view returns (address sender, address recipient, uint256 amount, uint64 timeoutSec, uint8 state);

    // Emitted on every lock. `sender` is indexed (topic[2]) so the stranded-BNB
    // sweep can enumerate a user's locks by their own BSC address via eth_getLogs,
    // without any local swap record. `hashlock` is indexed (topic[1]).
    event Locked(bytes32 indexed hashlock, address indexed sender, address indexed recipient, uint256 amount, uint64 timeoutSec);
}

/// On-chain HTLC state mirror (ExferHtlc.sol `enum State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcState {
    None,
    Locked,
    Claimed,
    Refunded,
}

impl HtlcState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => HtlcState::Locked,
            2 => HtlcState::Claimed,
            3 => HtlcState::Refunded,
            _ => HtlcState::None,
        }
    }
}

/// Result of reading a swap from the HTLC contract.
#[derive(Debug, Clone)]
pub struct OnChainSwap {
    pub recipient: Address,
    pub amount: U256,
    pub timeout_sec: u64,
    pub state: HtlcState,
}

// ───────────────────────── key / address ─────────────────────────

fn signer_from_secret(secret: &[u8; 32]) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_slice(secret)
        .map_err(|e| Error::Internal(format!("invalid BSC secp256k1 secret: {e}")))
}

/// EIP-55 checksummed BSC address for the wallet's derived secp256k1 key.
pub fn evm_address(secret: &[u8; 32]) -> Result<String> {
    Ok(signer_from_secret(secret)?.address().to_checksum(None))
}

fn parse_address(s: &str) -> Result<Address> {
    s.parse::<Address>()
        .map_err(|e| Error::BadParams(format!("bad EVM address {s}: {e}")))
}

fn parse_b256(s: &str) -> Result<B256> {
    let h = s.trim_start_matches("0x");
    let bytes =
        hex::decode(h).map_err(|e| Error::BadParams(format!("bad 32-byte hex {s}: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::BadParams(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// The hashlock (`topic[1]`) of an `eth_getLogs` entry for the `Locked` event,
/// as a `0x`-prefixed string. Pure so the topic indexing / shape handling — the
/// part that silently mis-decodes — is unit-testable against real RPC JSON.
/// Returns `None` on any shape mismatch (skips the row).
fn hashlock_from_log(log: &Value) -> Option<String> {
    let topics = log.get("topics")?.as_array()?;
    // topic[0] = event signature, [1] = hashlock, [2] = sender, [3] = recipient.
    let h = topics.get(1)?.as_str()?;
    // Normalize through the strict 32-byte parser so a malformed topic is dropped.
    Some(format!("0x{}", hex::encode(parse_b256(h).ok()?)))
}

// ───────────────────────── client ─────────────────────────

#[derive(Clone)]
pub struct EvmClient {
    http: reqwest::Client,
    rpc_url: String,
    chain_id: u64,
}

/// Minimum priority fee on BSC (1 gwei).
const MIN_PRIORITY_FEE_WEI: u128 = 1_000_000_000;
/// Hard cap on gas limit so a bad estimate can't drain BNB.
const GAS_LIMIT_CAP: u64 = 800_000;
/// Gas to hold back when sweeping the whole native balance. A plain BNB send is
/// 21k gas; 60k leaves ~2.3× headroom (the estimator's +25%, a contract
/// recipient, a price bump between read and send) while leaving far less dust
/// than a fixed reserve. Fallback price when the node can't be reached.
const SWEEP_GAS_BUDGET: u64 = 60_000;
const FALLBACK_GAS_PRICE_WEI: u128 = 5_000_000_000;

/// Block window for the stranded-BNB sweep's `eth_getLogs` scan. publicnode (the
/// configured BSC RPC) caps a getLogs range at 50000 blocks (`-32701 exceed
/// maximum block range`), which this matches to minimize calls. Halved and
/// retried on any range/result-limit error, down to [`BSC_GETLOGS_WINDOW_MIN`],
/// so a stricter RPC still completes the scan.
const BSC_GETLOGS_WINDOW: u64 = 50_000;
const BSC_GETLOGS_WINDOW_MIN: u64 = 2_000;
/// Consecutive min-window getLogs failures after which the stranded-lock scan
/// gives up THIS cycle instead of crawling millions of windows. A RPC that
/// gates archive `eth_getLogs` entirely (e.g. publicnode testnet: "Archive
/// requests require a personal token") would otherwise fail every window and
/// wedge the monitor for hours. The sweep is best-effort recovery — skipping a
/// cycle is fine; it retries on the next reconcile with the in-memory cursor.
const BSC_GETLOGS_MAX_CONSEC_FAIL: u32 = 5;

impl EvmClient {
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url: rpc_url.into(),
            chain_id,
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("BSC {method}: {e}")))?
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("BSC {method} decode: {e}")))?;
        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
                .to_string();
            return Err(Error::UpstreamRpc { code, message });
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::UpstreamUnexpected(format!("BSC {method}: no result")))
    }

    fn result_hex(v: &Value) -> Result<&str> {
        v.as_str()
            .ok_or_else(|| Error::UpstreamUnexpected("expected hex string result".into()))
    }

    fn hex_to_u64(s: &str) -> Result<u64> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u64 hex {s}: {e}")))
    }

    fn hex_to_u128(s: &str) -> Result<u128> {
        u128::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u128 hex {s}: {e}")))
    }

    fn hex_to_u256(s: &str) -> Result<U256> {
        U256::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::UpstreamUnexpected(format!("bad u256 hex {s}: {e}")))
    }

    // ---- reads ----

    /// Pending nonce for `addr` (accounts for in-flight txs).
    pub async fn pending_nonce(&self, addr: Address) -> Result<u64> {
        let r = self
            .rpc(
                "eth_getTransactionCount",
                json!([addr.to_checksum(None), "pending"]),
            )
            .await?;
        Self::hex_to_u64(Self::result_hex(&r)?)
    }

    /// Native BNB balance (wei).
    pub async fn bnb_balance(&self, addr: Address) -> Result<U256> {
        let r = self
            .rpc("eth_getBalance", json!([addr.to_checksum(None), "latest"]))
            .await?;
        Self::hex_to_u256(Self::result_hex(&r)?)
    }

    /// Read a swap entry from the HTLC contract.
    pub async fn get_swap(&self, htlc: Address, hashlock: B256) -> Result<OnChainSwap> {
        let data = getSwapCall { hashlock }.abi_encode();
        let out = self.eth_call(htlc, &data).await?;
        let dec = getSwapCall::abi_decode_returns(&out)
            .map_err(|e| Error::UpstreamUnexpected(format!("getSwap decode: {e}")))?;
        Ok(OnChainSwap {
            recipient: dec.recipient,
            amount: dec.amount,
            timeout_sec: dec.timeoutSec,
            state: HtlcState::from_u8(dec.state),
        })
    }

    /// String-typed convenience wrapper around [`get_swap`] for the swap engine
    /// (which holds addresses/hashlocks as hex strings from the quote).
    pub async fn get_htlc_swap(&self, htlc: &str, hashlock: &str) -> Result<OnChainSwap> {
        self.get_swap(parse_address(htlc)?, parse_b256(hashlock)?)
            .await
    }

    /// EIP-55 checksummed address for a raw secret (so the engine can compare
    /// the on-chain recipient against our own derived address).
    pub fn address_of(secret: &[u8; 32]) -> Result<Address> {
        Ok(signer_from_secret(secret)?.address())
    }

    /// Latest block height.
    pub async fn block_number(&self) -> Result<u64> {
        let r = self.rpc("eth_blockNumber", json!([])).await?;
        Self::hex_to_u64(Self::result_hex(&r)?)
    }

    /// `block.timestamp` of the latest block — the clock the HTLC's refund gate
    /// (`block.timestamp >= timeoutSec`) is measured against.
    pub async fn latest_block_timestamp(&self) -> Result<u64> {
        let r = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let ts = r
            .get("timestamp")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::UpstreamUnexpected("latest block: no timestamp".into()))?;
        Self::hex_to_u64(ts)
    }

    /// Every hashlock `sender` has ever locked in `contract`, read from the
    /// indexed `Locked` event over `[from_block, to_block]`. Journal-independent:
    /// the only input is the user's own BSC address, so it recovers stranded BNB
    /// even when the local swap record is gone (reinstall / new device).
    ///
    /// Scans in bounded windows so a public RPC with a getLogs range/result cap
    /// still serves a full-history scan; a window that trips the cap is halved and
    /// retried. Best-effort: a span that keeps failing at the minimum window is
    /// logged and skipped so one bad range never blocks the rest. Returns the
    /// `0x`-prefixed hashlocks (deduped) for the caller to check + refund.
    pub async fn locked_hashlocks_by_sender(
        &self,
        contract: &str,
        sender: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<String>> {
        let contract = parse_address(contract)?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut start = from_block;
        let mut window = BSC_GETLOGS_WINDOW;
        let mut consecutive_fail = 0u32;
        while start <= to_block {
            let end = (start + window - 1).min(to_block);
            match self.get_logs_locked(contract, sender, start, end).await {
                Ok(hashlocks) => {
                    consecutive_fail = 0;
                    for h in hashlocks {
                        if seen.insert(h.clone()) {
                            out.push(h);
                        }
                    }
                    start = end + 1;
                    // Recover toward the full window after a forced split.
                    if window < BSC_GETLOGS_WINDOW {
                        window = (window * 2).min(BSC_GETLOGS_WINDOW);
                    }
                }
                Err(e) if window > BSC_GETLOGS_WINDOW_MIN => {
                    window = (window / 2).max(BSC_GETLOGS_WINDOW_MIN);
                    tracing::debug!(start, end, error = %e, new_window = window, "getLogs window too wide; halving");
                }
                Err(e) => {
                    consecutive_fail += 1;
                    // Persistent failure at the minimum window means the RPC gates
                    // archive getLogs entirely. Bail out of this cycle's scan rather
                    // than crawling every remaining min-window (millions of them) and
                    // wedging the monitor — the sweep is best-effort and retries next
                    // reconcile.
                    if consecutive_fail >= BSC_GETLOGS_MAX_CONSEC_FAIL {
                        tracing::warn!(
                            start, to_block, consecutive_fail, error = %e,
                            "getLogs persistently failing at min window; aborting stranded-lock scan this cycle"
                        );
                        return Ok(out);
                    }
                    tracing::debug!(start, end, error = %e, "getLogs span failed at min window; skipping");
                    start = end + 1;
                }
            }
        }
        Ok(out)
    }

    /// One `eth_getLogs` page for the `Locked` event, filtered to `sender`.
    async fn get_logs_locked(
        &self,
        contract: Address,
        sender: Address,
        from: u64,
        to: u64,
    ) -> Result<Vec<String>> {
        let params = json!([{
            "address": contract.to_checksum(None),
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
            "topics": [
                format!("0x{}", hex::encode(Locked::SIGNATURE_HASH)),
                Value::Null,                                   // hashlock: any
                format!("0x{}", hex::encode(sender.into_word())), // sender: us
            ],
        }]);
        let r = self.rpc("eth_getLogs", params).await?;
        let arr = r
            .as_array()
            .ok_or_else(|| Error::UpstreamUnexpected("eth_getLogs: expected array".into()))?;
        Ok(arr.iter().filter_map(hashlock_from_log).collect())
    }

    async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>> {
        let r = self
            .rpc(
                "eth_call",
                json!([{ "to": to.to_checksum(None), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
            )
            .await?;
        let hexstr = Self::result_hex(&r)?;
        hex::decode(hexstr.trim_start_matches("0x"))
            .map_err(|e| Error::UpstreamUnexpected(format!("eth_call result decode: {e}")))
    }

    async fn gas_price(&self) -> Result<u128> {
        let r = self.rpc("eth_gasPrice", json!([])).await?;
        Self::hex_to_u128(Self::result_hex(&r)?)
    }

    /// Wei to hold back from a full-balance sweep so the transfer's own gas is
    /// covered. Priced at the live gas price + priority fee (falling back to a
    /// fixed price if the node is unreachable) over [`SWEEP_GAS_BUDGET`]. The
    /// real fee is lower — the surplus stays in the wallet — but this guarantees
    /// the sweep never under-funds its own gas.
    pub async fn sweep_gas_reserve(&self) -> U256 {
        let gas_price = self.gas_price().await.unwrap_or(FALLBACK_GAS_PRICE_WEI);
        let max_fee = gas_price.saturating_add(MIN_PRIORITY_FEE_WEI);
        U256::from(SWEEP_GAS_BUDGET).saturating_mul(U256::from(max_fee))
    }

    async fn estimate_gas_value(
        &self,
        from: Address,
        to: Address,
        data: &[u8],
        value: U256,
    ) -> Result<u64> {
        let r = self
            .rpc(
                "eth_estimateGas",
                json!([{
                    "from": from.to_checksum(None),
                    "to": to.to_checksum(None),
                    "data": format!("0x{}", hex::encode(data)),
                    "value": format!("0x{:x}", value),
                }]),
            )
            .await?;
        let est = Self::hex_to_u64(Self::result_hex(&r)?)?;
        // +25% headroom, capped.
        Ok((est.saturating_mul(125) / 100).min(GAS_LIMIT_CAP))
    }

    // ---- writes (build + sign + send) ----

    /// Build, sign and broadcast an EIP-1559 call. Returns the tx hash.
    /// Caller is responsible for serializing concurrent sends from the same
    /// account (nonce safety) — the swap engine holds a per-account lock.
    async fn send_call(&self, secret: &[u8; 32], to: Address, data: Vec<u8>) -> Result<String> {
        self.send_call_value(secret, to, data, U256::ZERO).await
    }

    /// As [`send_call`] but attaches native `value` (wei) — used to lock native
    /// BNB into the HTLC (and to send BNB withdrawals).
    async fn send_call_value(
        &self,
        secret: &[u8; 32],
        to: Address,
        data: Vec<u8>,
        value: U256,
    ) -> Result<String> {
        let signer = signer_from_secret(secret)?;
        let from = signer.address();

        let nonce = self.pending_nonce(from).await?;
        let gas_price = self.gas_price().await?;
        let max_priority_fee_per_gas = MIN_PRIORITY_FEE_WEI;
        let max_fee_per_gas = gas_price.saturating_add(max_priority_fee_per_gas);
        let gas_limit = self.estimate_gas_value(from, to, &data, value).await?;

        let tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: TxKind::Call(to),
            value,
            access_list: Default::default(),
            input: Bytes::from(data),
        };

        let sighash = tx.signature_hash();
        let sig = signer
            .sign_hash_sync(&sighash)
            .map_err(|e| Error::Internal(format!("BSC sign failed: {e}")))?;
        let signed = tx.into_signed(sig);
        let envelope: TxEnvelope = signed.into();
        let mut raw = Vec::new();
        envelope.encode_2718(&mut raw);

        let r = self
            .rpc(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw))]),
            )
            .await?;
        Ok(Self::result_hex(&r)?.to_string())
    }

    /// Send native BNB to an external address — withdraw the derived address's
    /// BNB (e.g. proceeds from a sell) to an exchange / another wallet.
    pub async fn send_bnb(&self, secret: &[u8; 32], to: &str, amount: U256) -> Result<String> {
        self.send_call_value(secret, parse_address(to)?, Vec::new(), amount)
            .await
    }

    /// `lock(hashlock, recipient, timeoutSec)` on the HTLC, sending `amount` wei
    /// of native BNB as the locked value.
    pub async fn htlc_lock(
        &self,
        secret: &[u8; 32],
        htlc: &str,
        hashlock: &str,
        recipient: &str,
        amount: U256,
        timeout_sec: u64,
    ) -> Result<String> {
        let data = lockCall {
            hashlock: parse_b256(hashlock)?,
            recipient: parse_address(recipient)?,
            timeoutSec: timeout_sec,
        }
        .abi_encode();
        self.send_call_value(secret, parse_address(htlc)?, data, amount)
            .await
    }

    /// `claim(preimage)` — reveal the preimage to receive the locked BNB.
    pub async fn htlc_claim(
        &self,
        secret: &[u8; 32],
        htlc: &str,
        preimage: &str,
    ) -> Result<String> {
        let data = claimCall {
            preimage: parse_b256(preimage)?,
        }
        .abi_encode();
        self.send_call(secret, parse_address(htlc)?, data).await
    }

    /// `refund(hashlock)` — reclaim our own expired lock (sender arm).
    pub async fn htlc_refund(
        &self,
        secret: &[u8; 32],
        htlc: &str,
        hashlock: &str,
    ) -> Result<String> {
        let data = refundCall {
            hashlock: parse_b256(hashlock)?,
        }
        .abi_encode();
        self.send_call(secret, parse_address(htlc)?, data).await
    }

    /// Receipt status: `Some(true)` = success, `Some(false)` = reverted,
    /// `None` = not yet mined.
    pub async fn receipt_status(&self, txhash: &str) -> Result<Option<bool>> {
        let r = self
            .rpc("eth_getTransactionReceipt", json!([txhash]))
            .await?;
        if r.is_null() {
            return Ok(None);
        }
        let status = r.get("status").and_then(Value::as_str).unwrap_or("0x0");
        Ok(Some(Self::hex_to_u64(status)? == 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known BIP-39 test vector → standard Ethereum address at m/44'/60'/0'/0/0.
    // Mnemonic: "test test test test test test test test test test test junk"
    // (the canonical Foundry/anvil default). Account 0 address:
    //   0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    // We assert our secp256k1 + EIP-55 path reproduces it, proving the BSC
    // address matches what MetaMask shows for the same mnemonic.
    #[test]
    fn evm_address_matches_known_vector() {
        let seed = bip39::Mnemonic::parse_normalized(
            "test test test test test test test test test test test junk",
        )
        .unwrap()
        .to_seed("");
        let path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse().unwrap();
        let xprv = bip32::XPrv::derive_from_path(&seed[..], &path).unwrap();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(xprv.private_key().to_bytes().as_slice());
        let addr = evm_address(&secret).unwrap();
        assert_eq!(addr, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    }

    #[test]
    fn htlc_state_decode() {
        assert_eq!(HtlcState::from_u8(0), HtlcState::None);
        assert_eq!(HtlcState::from_u8(1), HtlcState::Locked);
        assert_eq!(HtlcState::from_u8(2), HtlcState::Claimed);
        assert_eq!(HtlcState::from_u8(3), HtlcState::Refunded);
    }

    #[test]
    fn eip1559_sign_recovers_signer() {
        // Signing path is correct iff the recovered signer matches the key's
        // address — this exercises the EIP-1559 signature_hash (which binds
        // chain_id, EIP-155 replay protection) + secp256k1 sign.
        let secret = [0x11u8; 32];
        let signer = PrivateKeySigner::from_slice(&secret).unwrap();
        let tx = TxEip1559 {
            chain_id: 56,
            nonce: 7,
            gas_limit: 60_000,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(vec![0xde, 0xad]),
        };
        let h = tx.signature_hash();
        let sig = signer.sign_hash_sync(&h).unwrap();
        assert_eq!(
            sig.recover_address_from_prehash(&h).unwrap(),
            signer.address()
        );
    }

    #[test]
    fn abi_encode_lock_golden() {
        // Golden selector (keccak256(sig)[..4]) + ABI length for the native-BNB
        // lock call the engine signs. Catches any drift in the sol! ABI. The
        // locked amount is msg.value (native BNB), so it is NOT an ABI arg.
        let lock = lockCall {
            hashlock: B256::repeat_byte(0xAA),
            recipient: Address::repeat_byte(0x02),
            timeoutSec: 42u64,
        }
        .abi_encode();
        assert_eq!(
            &lock[..4],
            &alloy::primitives::keccak256("lock(bytes32,address,uint64)")[..4]
        );
        assert_eq!(lock.len(), 4 + 32 * 3);
    }

    #[test]
    fn abi_encode_claim_has_selector() {
        let data = claimCall {
            preimage: B256::repeat_byte(0xAB),
        }
        .abi_encode();
        // selector(claim(bytes32)) = keccak("claim(bytes32)")[..4]
        let sel = &alloy::primitives::keccak256("claim(bytes32)")[..4];
        assert_eq!(&data[..4], sel);
        assert_eq!(data.len(), 4 + 32);
    }

    #[test]
    fn locked_event_signature_matches_solidity() {
        // The getLogs topic[0] filter depends on this exact signature; a drift
        // from the deployed contract would silently return zero logs.
        let want = alloy::primitives::keccak256("Locked(bytes32,address,address,uint256,uint64)");
        assert_eq!(Locked::SIGNATURE_HASH, want);
    }

    #[test]
    fn hashlock_from_log_reads_topic_one() {
        // A real eth_getLogs entry shape: topic[1] is the indexed hashlock.
        let hl = format!("0x{}", "ab".repeat(32));
        let sender = format!("0x{}", "00".repeat(12) + &"11".repeat(20));
        let log = json!({
            "topics": [
                format!("0x{}", hex::encode(Locked::SIGNATURE_HASH)),
                hl,
                sender,
                format!("0x{}", "00".repeat(12) + &"22".repeat(20)),
            ],
            "data": "0x",
        });
        assert_eq!(hashlock_from_log(&log).as_deref(), Some(hl.as_str()));
    }

    #[test]
    fn hashlock_from_log_rejects_malformed() {
        // Missing topics, too-few topics, and a non-32-byte topic[1] all drop.
        assert_eq!(hashlock_from_log(&json!({})), None);
        assert_eq!(hashlock_from_log(&json!({ "topics": [] })), None);
        assert_eq!(
            hashlock_from_log(&json!({ "topics": ["0xsig", "0xdeadbeef"] })),
            None
        );
    }
}
