//! Optional client for an upstream `exfer-indexer` service.
//!
//! Walletd's local index only covers HTLCs that pay one of its own
//! keys. For everything else — reputation lookups, atomic-swap
//! counterparty verification, "what's the track record of agent X" —
//! the wallet defers to a multi-tenant indexer. When the operator
//! sets `--indexer-rpc`, this client lights up and the new
//! delegating methods proxy through it.
//!
//! Wire shape is identical to the indexer's, which itself mirrors
//! walletd's owned-key surface, so an MCP server pointed at walletd
//! can't tell which side handled a query.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Defaults mirror the upstream-node client so an operator who tunes
/// one feels at home tuning the other.
const DEFAULT_RETRY_ATTEMPTS: u32 = 4;
const DEFAULT_BACKOFF_MS: u64 = 500;

#[derive(Clone)]
pub struct IndexerClient {
    http: Client,
    urls: Arc<Vec<String>>,
    token: Option<Arc<String>>,
    next: Arc<AtomicUsize>,
    attempts: u32,
    backoff_ms: u64,
}

impl IndexerClient {
    /// `urls` is a comma-separated list. Empty / whitespace-only
    /// segments are filtered out. Errors only on zero usable URLs.
    pub fn new(urls: &str, token: Option<&str>, timeout: Duration) -> Result<Self> {
        let url_list: Vec<String> = urls
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if url_list.is_empty() {
            return Err(Error::Internal(
                "indexer_rpc: at least one URL required".into(),
            ));
        }
        let http = Client::builder()
            .timeout(timeout)
            .user_agent(concat!("exfer-walletd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Internal(format!("reqwest build: {e}")))?;
        Ok(Self {
            http,
            urls: Arc::new(url_list),
            token: token.map(|s| Arc::new(s.to_string())),
            next: Arc::new(AtomicUsize::new(0)),
            attempts: DEFAULT_RETRY_ATTEMPTS,
            backoff_ms: DEFAULT_BACKOFF_MS,
        })
    }

    /// Configure retry behaviour. Mostly useful for tests.
    pub fn with_retry(mut self, attempts: u32, backoff_ms: u64) -> Self {
        self.attempts = attempts.max(1);
        self.backoff_ms = backoff_ms;
        self
    }

    fn next_url(&self) -> &str {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.urls.len();
        &self.urls[i]
    }

    /// Generic JSON-RPC call. Mirrors `ExferNode::call`'s contract:
    /// retry on transport errors, surface RPC errors immediately,
    /// returns the `result` field on success.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let mut last_err: Option<String> = None;
        for attempt in 0..self.attempts {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(
                    self.backoff_ms.saturating_mul(attempt as u64),
                ))
                .await;
            }
            let url = self.next_url();
            let mut req = self.http.post(url).json(&body);
            if let Some(tok) = &self.token {
                req = req.bearer_auth(tok.as_str());
            }
            match req.send().await {
                Ok(resp) => {
                    let v: Value = match resp.json().await {
                        Ok(v) => v,
                        Err(e) => {
                            last_err = Some(format!("decode: {e}"));
                            continue;
                        }
                    };
                    if let Some(err) = v.get("error") {
                        let code =
                            err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603) as i32;
                        let message = err
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("unspecified indexer error")
                            .to_string();
                        return Err(Error::UpstreamRpc { code, message });
                    }
                    if let Some(result) = v.get("result") {
                        return Ok(result.clone());
                    }
                    return Err(Error::UpstreamRpc {
                        code: -32603,
                        message: "indexer missing result field".into(),
                    });
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            }
        }
        Err(Error::UpstreamUnreachable(
            last_err.unwrap_or_else(|| "all attempts exhausted".into()),
        ))
    }

    // Typed thin wrappers used by the delegating handlers. They all
    // pass through the raw JSON so the wire shape is whatever the
    // indexer chose to return — keeping walletd as a transparent
    // proxy rather than an interpreter.

    pub async fn htlc_status(&self, params: Value) -> Result<Value> {
        self.call("htlc_status", params).await
    }
    pub async fn htlc_list(&self, params: Value) -> Result<Value> {
        self.call("htlc_list", params).await
    }
    pub async fn htlc_lookup_by_hashlock(&self, params: Value) -> Result<Value> {
        self.call("htlc_lookup_by_hashlock", params).await
    }
    pub async fn list_settlements(&self, params: Value) -> Result<Value> {
        self.call("list_settlements", params).await
    }
    pub async fn contract_stats(&self, params: Value) -> Result<Value> {
        self.call("contract_stats", params).await
    }
    pub async fn get_address_history(&self, params: Value) -> Result<Value> {
        self.call("get_address_history", params).await
    }
    pub async fn get_output_spent_by(&self, params: Value) -> Result<Value> {
        self.call("get_output_spent_by", params).await
    }
}

// Both `Serialize` and `Deserialize` are derived so tests can round-trip a
// configured client through serde_json fixtures without depending on real I/O.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct _MarkerForCompileCheck;
