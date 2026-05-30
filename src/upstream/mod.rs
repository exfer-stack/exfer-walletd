//! Async client for the upstream Exfer node's JSON-RPC interface.
//!
//! Designed to be **decoupled from any specific node**. The client takes
//! one or more node URLs and, on each call, tries them in order — failing
//! over to the next on transport / 5xx error. JSON-RPC application errors
//! (e.g. `Block not found`) are surfaced immediately without retrying,
//! since they're not transport problems.
//!
//! On transport failure (connection refused, timeout, 5xx) the client
//! does a full pass over every configured node before considering the
//! whole *attempt* failed, then waits a linear backoff and starts another
//! attempt up to [`RetryPolicy::attempts`] times. This matters for any
//! transfer behind a flaky public RPC — `get_address_utxos` and
//! `send_raw_transaction` are sequential, so without retry the failure
//! probabilities compound.
//!
//! All wire types are strongly typed. The rest of the codebase never
//! touches raw JSON.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Retry behaviour for transport-level RPC failures. Application errors
/// (`{"error":{"code":...,"message":...}}`) are surfaced immediately and
/// never retried — they're not transient.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of total attempts per RPC call. `1` disables retry
    /// entirely. Each attempt rotates through every configured node
    /// before counting as failed.
    pub attempts: u32,
    /// Base backoff in milliseconds. The wait between attempt `k` and
    /// attempt `k + 1` is `backoff_ms * k`, so backoff grows linearly:
    /// `backoff_ms`, `2 * backoff_ms`, `3 * backoff_ms`, …
    pub backoff_ms: u64,
}

impl RetryPolicy {
    /// No retry — every call gets exactly one attempt across all nodes.
    /// The pre-retry-aware default for [`ExferNode::new`] and the
    /// recommended setting for tests.
    pub const fn none() -> Self {
        Self {
            attempts: 1,
            backoff_ms: 0,
        }
    }
}

impl Default for RetryPolicy {
    /// 4 attempts (= 3 retries after the first failure) with 500ms linear
    /// backoff. Worst-case extra wall-clock is 500 + 1000 + 1500 = 3s of
    /// sleep on top of the regular per-call timeout, in exchange for
    /// surviving a public RPC at ~80–90% reliability with several
    /// authenticated-output lookups per transfer.
    fn default() -> Self {
        Self {
            attempts: 4,
            backoff_ms: 500,
        }
    }
}

/// A client that fans out to one or more upstream Exfer nodes.
///
/// - With a single URL: behaves as a plain JSON-RPC client.
/// - With multiple URLs: rotates the starting node round-robin per call,
///   then tries the remaining nodes in order if the first one fails with
///   a transport-level error (connection refused, timeout, 5xx).
///   Application errors returned by the node (`{"error": {...}}`) are
///   surfaced immediately without trying the next node.
/// - When the full node sweep fails with only transport errors, the
///   call sleeps for the configured backoff and tries the whole sweep
///   again, up to [`RetryPolicy::attempts`] total times.
#[derive(Debug, Clone)]
pub struct ExferNode {
    nodes: Vec<String>,
    http: reqwest::Client,
    cursor: Arc<AtomicUsize>,
    retry: RetryPolicy,
}

impl ExferNode {
    /// Build a client with retries disabled. Accepts a comma-separated
    /// list of URLs (e.g. `"http://node-a:9334,http://node-b:9334"`) or
    /// a single URL. Use [`ExferNode::with_retry_policy`] to opt into
    /// retry on transient failures.
    pub fn new(urls: impl AsRef<str>, timeout: Duration) -> Result<Self> {
        Self::with_retry_policy(urls, timeout, RetryPolicy::none())
    }

    /// Like [`ExferNode::new`] but with an explicit retry policy. The
    /// daemon's `main` builds the node this way; tests typically want
    /// [`RetryPolicy::none`] to fail fast.
    pub fn with_retry_policy(
        urls: impl AsRef<str>,
        timeout: Duration,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let nodes: Vec<String> = urls
            .as_ref()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if nodes.is_empty() {
            return Err(Error::Internal("no upstream node URLs configured".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("exfer-walletd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Internal(format!("build http client: {e}")))?;
        Ok(Self {
            nodes,
            http,
            cursor: Arc::new(AtomicUsize::new(0)),
            retry,
        })
    }

    /// Inspect the retry policy this client was built with.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// The configured upstream URLs, in original order. Useful for
    /// health-check output.
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method":  method,
            "params":  params,
            "id":      1,
        });
        let n = self.nodes.len();
        // Rotate the starting node so load distributes across nodes.
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        let attempts = self.retry.attempts.max(1);

        let mut last_transport_err: Option<Error> = None;
        for attempt in 0..attempts {
            for offset in 0..n {
                let idx = (start + offset) % n;
                let url = &self.nodes[idx];
                match self.call_one(url, &body).await {
                    Ok(v) => return Ok(v),
                    Err(e @ Error::UpstreamUnreachable(_)) => {
                        tracing::warn!(
                            node    = %url,
                            attempt = attempt + 1,
                            of      = attempts,
                            error   = %e,
                            "upstream unreachable, trying next"
                        );
                        last_transport_err = Some(e);
                    }
                    Err(other) => return Err(other),
                }
            }
            // Whole node sweep failed with only transport errors.
            // Sleep linear backoff, then try the sweep again — unless
            // this was the last attempt.
            if attempt + 1 < attempts {
                let wait_ms = self.retry.backoff_ms.saturating_mul((attempt + 1) as u64);
                if wait_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                }
            }
        }
        Err(last_transport_err.unwrap_or_else(|| Error::Internal("no nodes tried".into())))
    }

    async fn call_one(&self, url: &str, body: &Value) -> Result<Value> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| Error::UpstreamUnreachable(format!("{url}: {e}")))?;
        let status = resp.status();
        // Check the status BEFORE decoding the body: a 5xx with an empty
        // or non-JSON body (common from load balancers and proxies) must
        // still be classified as a retryable transport failure, not as
        // a permanent malformed-response error.
        if status.is_server_error() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Error::UpstreamUnreachable(format!(
                "{url}: http {status}: {body_text}"
            )));
        }
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Error::UpstreamUnexpected(format!(
                "{url}: http {status}: {body_text}"
            )));
        }
        let payload: Value = resp
            .json()
            .await
            .map_err(|e| Error::UpstreamUnexpected(format!("{url}: decode: {e}")))?;
        if let Some(err) = payload.get("error") {
            let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("(no message)")
                .to_string();
            return Err(Error::UpstreamRpc { code, message });
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| Error::UpstreamUnexpected(format!("{url}: response missing `result`")))
    }

    // ====================================================================
    // Typed RPC methods
    // ====================================================================

    pub async fn get_block_height(&self) -> Result<BlockTip> {
        let v = self
            .call("get_block_height", Value::Object(Default::default()))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_block_by_height(&self, height: u64) -> Result<BlockSummary> {
        let v = self
            .call("get_block", serde_json::json!({ "height": height }))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_block_by_hash(&self, hash_hex: &str) -> Result<BlockSummary> {
        let v = self
            .call("get_block", serde_json::json!({ "hash": hash_hex }))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_transaction(&self, tx_id_hex: &str) -> Result<TxStatus> {
        let v = self
            .call("get_transaction", serde_json::json!({ "hash": tx_id_hex }))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_balance(&self, address_hex: &str) -> Result<BalanceResponse> {
        let v = self
            .call("get_balance", serde_json::json!({ "address": address_hex }))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_address_utxos(&self, address_hex: &str) -> Result<UtxoListResponse> {
        let v = self
            .call(
                "get_address_utxos",
                serde_json::json!({ "address": address_hex }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    pub async fn get_script_utxos(&self, script_hex: &str) -> Result<UtxoListResponse> {
        let v = self
            .call(
                "get_script_utxos",
                serde_json::json!({ "script_hex": script_hex }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    /// `get_address_mempool` — the unconfirmed (mempool) view of an
    /// address. Returns the txs currently in the node's mempool that
    /// credit (`received`) or debit (`spent`) this address, with
    /// amounts. This is the receiver-side "pending" signal that
    /// `get_balance` (confirmed-only) can't give: incoming funds show
    /// up here the moment the tx is admitted to the mempool, seconds
    /// ahead of confirmation. Node-side it counts toward the 30/min
    /// scan budget, so callers should treat it as opt-in.
    pub async fn get_address_mempool(&self, address_hex: &str) -> Result<AddressMempoolResponse> {
        let v = self
            .call(
                "get_address_mempool",
                serde_json::json!({ "address": address_hex }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    /// Like [`Self::get_address_mempool`] but tolerant of upstreams that
    /// predate the method (added node-side in v1.11.3). A node that
    /// doesn't know the method answers `-32601 Method not found`; since
    /// walletd fails over round-robin across several upstreams, a mixed
    /// fleet (some upgraded, some not) is the realistic state during a
    /// rollout. Mapping that one code to `Ok(None)` lets a pending-aware
    /// caller degrade to "no pending signal here" instead of failing the
    /// whole request. Every other error still propagates.
    pub async fn get_address_mempool_opt(
        &self,
        address_hex: &str,
    ) -> Result<Option<AddressMempoolResponse>> {
        match self.get_address_mempool(address_hex).await {
            Ok(r) => Ok(Some(r)),
            Err(Error::UpstreamRpc { code: -32601, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `get_balances` — confirmed balance for many addresses in ONE node
    /// call (and one scan-rate slot). Node v1.11.3+ (issue #15 Tier 1).
    pub async fn get_balances(&self, addresses: &[String]) -> Result<Vec<BalanceResponse>> {
        let v = self
            .call(
                "get_balances",
                serde_json::json!({ "addresses": addresses }),
            )
            .await?;
        let parsed: BalancesResponse =
            serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))?;
        Ok(parsed.balances)
    }

    /// Forward-compatible variant: `None` against a node predating the batch
    /// method (answers `-32601`), so the caller can fall back to per-address
    /// `get_balance`.
    pub async fn get_balances_opt(
        &self,
        addresses: &[String],
    ) -> Result<Option<Vec<BalanceResponse>>> {
        match self.get_balances(addresses).await {
            Ok(r) => Ok(Some(r)),
            Err(Error::UpstreamRpc { code: -32601, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `get_address_utxos_batch` — UTXOs for many addresses in ONE node call.
    /// Node v1.11.3+ (issue #15 Tier 1).
    pub async fn get_address_utxos_batch(
        &self,
        addresses: &[String],
    ) -> Result<UtxosBatchResponse> {
        let v = self
            .call(
                "get_address_utxos_batch",
                serde_json::json!({ "addresses": addresses }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }

    /// Forward-compatible variant: `None` against a node predating the batch
    /// method (`-32601`), so the caller can fall back to per-address
    /// `get_address_utxos`.
    pub async fn get_address_utxos_batch_opt(
        &self,
        addresses: &[String],
    ) -> Result<Option<UtxosBatchResponse>> {
        match self.get_address_utxos_batch(addresses).await {
            Ok(r) => Ok(Some(r)),
            Err(Error::UpstreamRpc { code: -32601, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn send_raw_transaction(&self, tx_hex: &str) -> Result<SendRawResponse> {
        let v = self
            .call(
                "send_raw_transaction",
                serde_json::json!({ "tx_hex": tx_hex }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::UpstreamUnexpected(e.to_string()))
    }
}

// ============================================================================
// Wire types — mirror the upstream JSON shapes exactly.
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTip {
    pub height: u64,
    pub block_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummary {
    /// Upstream returns this field as `"hash"`; walletd's outward
    /// surface normalises it to `block_id` so the same concept has the
    /// same name everywhere in our API.
    #[serde(rename(deserialize = "hash"))]
    pub block_id: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: u64,
    pub transactions: Vec<String>,
    pub prev_block_id: String,
    pub difficulty_target: String,
    pub nonce: u64,
    pub state_root: String,
    pub tx_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatus {
    pub tx_id: String,
    pub tx_hex: String,
    pub in_mempool: bool,
    /// Upstream sends `"block_hash"`; we normalise to `block_id`.
    #[serde(default, rename(deserialize = "block_hash"))]
    pub block_id: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub address: String,
    pub balance: u64,
}

/// `get_balances` response — one balance per requested address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancesResponse {
    pub balances: Vec<BalanceResponse>,
}

/// One address's UTXOs inside a `get_address_utxos_batch` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressUtxos {
    pub address: String,
    #[serde(default)]
    pub utxos: Vec<UtxoEntry>,
    #[serde(default)]
    pub truncated: bool,
}

/// `get_address_utxos_batch` response — UTXOs for many addresses, one tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxosBatchResponse {
    pub addresses: Vec<AddressUtxos>,
    pub tip_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub output_index: u32,
    pub value: u64,
    pub height: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoListResponse {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub script_hex: Option<String>,
    pub tip_height: u64,
    // `truncated` was added in a later node release; older nodes omit
    // it (observed in real-money testing against 89.127.232.155:9334
    // on 2026-05-20: walletd rejected the utxos response with
    // "missing field `truncated`" and the transfer engine couldn't
    // even read sender UTXOs). Defaulting to `false` matches the
    // semantics: if the node didn't tell us "this list was clipped,"
    // assume it's the full set.
    #[serde(default)]
    pub truncated: bool,
    pub utxos: Vec<UtxoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRawResponse {
    pub tx_id: String,
}

/// One mempool tx as seen through an address-scoped lens: the outputs
/// it creates that pay *this* address (`received`) and the prior
/// outputs of *this* address it spends (`spent`). Mirrors the node's
/// `get_address_mempool` per-tx shape exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolTx {
    pub tx_id: String,
    #[serde(default)]
    pub received: Vec<MempoolReceived>,
    #[serde(default)]
    pub spent: Vec<MempoolSpent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolReceived {
    pub output_index: u32,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSpent {
    pub tx_id: String,
    pub output_index: u32,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressMempoolResponse {
    pub address: String,
    pub tip_height: u64,
    #[serde(default)]
    pub mempool: Vec<MempoolTx>,
}

impl AddressMempoolResponse {
    /// Total value of mempool outputs paying this address (incoming,
    /// unconfirmed credit).
    pub fn pending_received(&self) -> u64 {
        self.mempool
            .iter()
            .flat_map(|t| t.received.iter())
            .map(|r| r.value)
            .sum()
    }

    /// Total value of this address's outputs being spent in the
    /// mempool (outgoing, unconfirmed debit).
    pub fn pending_spent(&self) -> u64 {
        self.mempool
            .iter()
            .flat_map(|t| t.spent.iter())
            .map(|s| s.value)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The node's `get_address_mempool` JSON, captured verbatim, must
    // round-trip into AddressMempoolResponse and the pending sums must
    // match: one tx crediting 0.1 + 0.05 and debiting 0.2.
    #[test]
    fn address_mempool_round_trips_and_sums() {
        let raw = serde_json::json!({
            "address": "ab".repeat(32),
            "tip_height": 12345,
            "mempool": [{
                "tx_id": "11".repeat(32),
                "received": [
                    {"output_index": 0, "value": 100_000},
                    {"output_index": 2, "value":  50_000}
                ],
                "spent": [
                    {"tx_id": "22".repeat(32), "output_index": 1, "value": 200_000}
                ]
            }]
        });
        let r: AddressMempoolResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(r.tip_height, 12345);
        assert_eq!(r.mempool.len(), 1);
        assert_eq!(r.pending_received(), 150_000);
        assert_eq!(r.pending_spent(), 200_000);
    }

    // Empty mempool (no pending tx touching the address) → zero sums,
    // and a tx with omitted `received`/`spent` arrays defaults clean.
    #[test]
    fn address_mempool_empty_and_partial_default() {
        let empty: AddressMempoolResponse = serde_json::from_value(serde_json::json!({
            "address": "cd".repeat(32),
            "tip_height": 1,
            "mempool": []
        }))
        .unwrap();
        assert_eq!(empty.pending_received(), 0);
        assert_eq!(empty.pending_spent(), 0);

        let partial: AddressMempoolResponse = serde_json::from_value(serde_json::json!({
            "address": "cd".repeat(32),
            "tip_height": 1,
            "mempool": [{ "tx_id": "33".repeat(32), "received": [{"output_index": 0, "value": 7}] }]
        }))
        .unwrap();
        assert_eq!(partial.pending_received(), 7);
        assert_eq!(partial.pending_spent(), 0);
    }
}
