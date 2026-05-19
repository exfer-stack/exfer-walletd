//! L5 — transaction cache. LRU-bounded.
//!
//! Two effective TTLs per cached entry, picked at write time based on
//! whether the transaction is in mempool or confirmed:
//!
//! - **Mempool** (`in_mempool=true`, `block_height=None`) → 5s TTL.
//!   The tx is one block away from changing state; we don't want to
//!   serve a "still in mempool" claim for too long.
//! - **Confirmed** (`block_height=Some(_)`) → long TTL (5 minutes).
//!   A confirmed tx is immutable absent a chain reorg. Reorgs trigger
//!   `invalidate_all` from the refresher; we don't try to be cleverer.
//!
//! The L5 cache is by far the biggest amortization win in the
//! `get_transaction` decode path: `decode_with_inputs` fans out one
//! parent-tx fetch per input, and a tx with N inputs becomes ~free on
//! cache hit. Wallets that scan their own history repeatedly (every
//! deposit-watcher pass) cache the parent transactions across passes.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::error::Result;
use crate::upstream::{ExferNode, TxStatus};

/// Confirmed transactions are effectively immutable (modulo reorg).
/// Pick a TTL long enough that a single dashboard pass doesn't re-fetch,
/// short enough that operator-driven invalidation flows still work.
const CONFIRMED_TTL: Duration = Duration::from_secs(300);

/// Mempool transactions are at most one block from confirming. Short
/// TTL so the cache reflects "now confirmed" promptly.
const MEMPOOL_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct Entry {
    value: TxStatus,
    fetched_at: Instant,
    ttl: Duration,
}

impl Entry {
    fn fresh(value: TxStatus) -> Self {
        let ttl = if value.block_height.is_some() {
            CONFIRMED_TTL
        } else {
            MEMPOOL_TTL
        };
        Self {
            value,
            fetched_at: Instant::now(),
            ttl,
        }
    }

    fn is_fresh(&self) -> bool {
        Instant::now().saturating_duration_since(self.fetched_at) < self.ttl
    }
}

pub struct TxCache {
    inner: Mutex<LruCache<String, Entry>>,
    enabled: bool,
}

impl TxCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            enabled: capacity > 0,
        }
    }

    /// Read-through. On hit, returns the cached value; on miss / stale,
    /// fetches upstream and inserts.
    pub async fn get_or_fetch(&self, tx_id: &str, node: &ExferNode) -> Result<TxStatus> {
        if !self.enabled {
            return node.get_transaction(tx_id).await;
        }
        // Fresh cache hit?
        if let Some(v) = self.peek_fresh(tx_id) {
            return Ok(v);
        }
        // Miss or stale → upstream.
        let value = node.get_transaction(tx_id).await?;
        self.insert(tx_id, value.clone());
        Ok(value)
    }

    fn peek_fresh(&self, tx_id: &str) -> Option<TxStatus> {
        let mut g = self.inner.lock().unwrap();
        // `get` bumps LRU position; only return if fresh.
        if let Some(entry) = g.get(tx_id) {
            if entry.is_fresh() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    fn insert(&self, tx_id: &str, value: TxStatus) {
        if !self.enabled {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        g.put(tx_id.to_string(), Entry::fresh(value));
    }

    /// Wipe everything. Refresher calls this on reorg.
    pub fn invalidate_all(&self) {
        if !self.enabled {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        g.clear();
    }

    pub fn len(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_node(server: &MockServer) -> ExferNode {
        ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap()
    }

    fn tx_body(tx_id: &str, in_mempool: bool, block_height: Option<u64>) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{
                "tx_id": tx_id,
                "tx_hex": "00",
                "in_mempool": in_mempool,
                "block_hash": block_height.map(|_| "abcd"),
                "block_height": block_height,
            }
        })
    }

    #[tokio::test]
    async fn confirmed_tx_caches_for_long_ttl() {
        let server = MockServer::start().await;
        let tx_id = "aa".repeat(32);
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_transaction",
                "params":{"hash": tx_id}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_body(
                &tx_id,
                false,
                Some(100),
            )))
            .up_to_n_times(1) // exactly one upstream hit
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = TxCache::new(100);
        for _ in 0..3 {
            let r = c.get_or_fetch(&tx_id, &node).await.unwrap();
            assert_eq!(r.block_height, Some(100));
        }
    }

    #[tokio::test]
    async fn mempool_tx_caches_briefly_then_refreshes() {
        let server = MockServer::start().await;
        let tx_id = "bb".repeat(32);
        // First call: mempool.
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method":"get_transaction",
                "params":{"hash": tx_id}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_body(&tx_id, true, None)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // After TTL, second call: confirmed.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_body(
                &tx_id,
                false,
                Some(50),
            )))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = TxCache::new(100);

        let r1 = c.get_or_fetch(&tx_id, &node).await.unwrap();
        assert!(r1.in_mempool);
        // Wait past mempool TTL.
        tokio::time::sleep(Duration::from_millis(5_100)).await;
        let r2 = c.get_or_fetch(&tx_id, &node).await.unwrap();
        assert!(!r2.in_mempool, "mempool TTL expiry must refresh");
        assert_eq!(r2.block_height, Some(50));
    }

    #[tokio::test]
    async fn invalidate_all_clears_cache() {
        let server = MockServer::start().await;
        let tx_id = "cc".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_body(
                &tx_id,
                false,
                Some(10),
            )))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = TxCache::new(100);
        c.get_or_fetch(&tx_id, &node).await.unwrap();
        assert_eq!(c.len(), 1);
        c.invalidate_all();
        assert_eq!(c.len(), 0);
    }

    #[tokio::test]
    async fn disabled_capacity_zero_bypasses() {
        let server = MockServer::start().await;
        let tx_id = "dd".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tx_body(
                &tx_id,
                false,
                Some(10),
            )))
            .expect(3) // disabled cache → three upstream calls
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = TxCache::new(0);
        for _ in 0..3 {
            c.get_or_fetch(&tx_id, &node).await.unwrap();
        }
    }
}
