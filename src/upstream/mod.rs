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
//! attempt up to [`RetryPolicy::attempts`] times. This matters most for
//! `transfer`, which fires 1 + N + 1 sequential calls during UTXO
//! authentication — without retry the per-call failure probability
//! compounds and a flaky public RPC becomes unusable.
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
    pub hash: String,
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
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub address: String,
    pub balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub output_index: u32,
    pub value: u64,
    pub height: u64,
    pub is_coinbase: bool,
    #[serde(default)]
    pub script_len: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoListResponse {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub script_hex: Option<String>,
    pub tip_height: u64,
    pub truncated: bool,
    pub utxos: Vec<UtxoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRawResponse {
    pub tx_id: String,
}
