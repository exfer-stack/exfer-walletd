//! L4 — block cache. LRU-bounded, two keyspaces.
//!
//! - **By hash** (`block_id`): permanent until LRU eviction. Block
//!   contents under a given hash are immutable: same SHA → same bytes
//!   (or it's a different block). A reorg doesn't change *what's at
//!   hash X*; it just changes whether X is on the main chain.
//!
//! - **By height**: short TTL within `reorg_depth` of the current tip,
//!   permanent beyond. A block at height H within reorg-depth could be
//!   replaced by a different block on a reorg; beyond reorg-depth it's
//!   stable in practice.
//!
//! Reorg detection (handled by the refresher) calls `invalidate_all`,
//! which is the lazy-correct path: rebuilding the cache from upstream
//! after a reorg is cheap, and we don't have to track which heights
//! were before vs after the divergence.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::error::Result;
use crate::upstream::{BlockSummary, ExferNode};

/// TTL for by-height entries within reorg-depth of tip. Beyond
/// reorg-depth, the entry is considered immutable and stored without
/// TTL.
const HEIGHT_WITHIN_REORG_TTL: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
struct ByHashEntry {
    value: BlockSummary,
}

#[derive(Debug, Clone)]
struct ByHeightEntry {
    value: BlockSummary,
    fetched_at: Instant,
    /// `None` means "stable, no TTL"; `Some(d)` means "TTL applies".
    ttl: Option<Duration>,
}

pub struct BlockCache {
    by_hash: Mutex<LruCache<String, ByHashEntry>>,
    by_height: Mutex<LruCache<u64, ByHeightEntry>>,
    reorg_depth: u64,
    enabled: bool,
}

impl BlockCache {
    pub fn new(capacity: usize, reorg_depth: u64) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            by_hash: Mutex::new(LruCache::new(cap)),
            by_height: Mutex::new(LruCache::new(cap)),
            reorg_depth,
            enabled: capacity > 0,
        }
    }

    /// Cache-aside by-hash read. Permanent cache (no TTL) once written.
    pub async fn get_by_hash(&self, hash: &str, node: &ExferNode) -> Result<BlockSummary> {
        if !self.enabled {
            return node.get_block_by_hash(hash).await;
        }
        if let Some(v) = self.peek_hash(hash) {
            return Ok(v);
        }
        let v = node.get_block_by_hash(hash).await?;
        self.insert_hash(hash, v.clone());
        Ok(v)
    }

    /// Cache-aside by-height read. Caller passes `current_tip_height`
    /// so the cache can decide TTL on insert: within reorg-depth →
    /// short TTL; beyond → permanent.
    pub async fn get_by_height(
        &self,
        height: u64,
        node: &ExferNode,
        current_tip_height: u64,
    ) -> Result<BlockSummary> {
        if !self.enabled {
            return node.get_block_by_height(height).await;
        }
        if let Some(v) = self.peek_height(height) {
            return Ok(v);
        }
        let v = node.get_block_by_height(height).await?;
        let within_reorg = current_tip_height.saturating_sub(height) < self.reorg_depth;
        let ttl = if within_reorg {
            Some(HEIGHT_WITHIN_REORG_TTL)
        } else {
            None
        };
        self.insert_height(height, v.clone(), ttl);
        // Also key by hash — same block, no extra upstream fetch needed.
        self.insert_hash(&v.hash, v.clone());
        Ok(v)
    }

    fn peek_hash(&self, hash: &str) -> Option<BlockSummary> {
        let mut g = self.by_hash.lock().unwrap();
        // By-hash entries are permanent — no TTL check.
        g.get(hash).map(|e| e.value.clone())
    }

    fn peek_height(&self, height: u64) -> Option<BlockSummary> {
        let mut g = self.by_height.lock().unwrap();
        let entry = g.get(&height)?;
        if let Some(ttl) = entry.ttl {
            let age = Instant::now().saturating_duration_since(entry.fetched_at);
            if age >= ttl {
                return None;
            }
        }
        Some(entry.value.clone())
    }

    fn insert_hash(&self, hash: &str, value: BlockSummary) {
        if !self.enabled {
            return;
        }
        let mut g = self.by_hash.lock().unwrap();
        g.put(hash.to_string(), ByHashEntry { value });
    }

    fn insert_height(&self, height: u64, value: BlockSummary, ttl: Option<Duration>) {
        if !self.enabled {
            return;
        }
        let mut g = self.by_height.lock().unwrap();
        g.put(
            height,
            ByHeightEntry {
                value,
                fetched_at: Instant::now(),
                ttl,
            },
        );
    }

    pub fn invalidate_all(&self) {
        if !self.enabled {
            return;
        }
        self.by_hash.lock().unwrap().clear();
        self.by_height.lock().unwrap().clear();
    }

    pub fn hash_len(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.by_hash.lock().unwrap().len()
    }
    pub fn height_len(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.by_height.lock().unwrap().len()
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

    fn block_body(hash: &str, height: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{
                "hash": hash,
                "height": height,
                "timestamp": 1,
                "tx_count": 0,
                "transactions": [],
                "prev_block_id": "00",
                "difficulty_target": "ff",
                "nonce": 0,
                "state_root": "00",
                "tx_root": "00",
            }
        })
    }

    #[tokio::test]
    async fn by_hash_is_permanent() {
        let server = MockServer::start().await;
        let h = "ab".repeat(32);
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({"params":{"hash": h}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(block_body(&h, 1)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = BlockCache::new(100, 6);
        for _ in 0..3 {
            let r = c.get_by_hash(&h, &node).await.unwrap();
            assert_eq!(r.height, 1);
        }
    }

    #[tokio::test]
    async fn by_height_within_reorg_depth_has_ttl() {
        let server = MockServer::start().await;
        let h = "cd".repeat(32);
        // Same response served indefinitely.
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"params":{"height": 5}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(block_body(&h, 5)))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        // Tip=6, height=5 → within reorg-depth=6 → short TTL.
        let c = BlockCache::new(100, 6);
        c.get_by_height(5, &node, 6).await.unwrap();
        // Cache populated.
        assert_eq!(c.height_len(), 1);
        // After TTL expires, peek returns None → next get_by_height re-fetches.
        tokio::time::sleep(Duration::from_millis(15_100)).await;
        c.get_by_height(5, &node, 6).await.unwrap();
        // Cache repopulated by second call — still one entry.
        assert_eq!(c.height_len(), 1);
    }

    #[tokio::test]
    async fn by_height_beyond_reorg_depth_is_permanent() {
        let server = MockServer::start().await;
        let h = "ef".repeat(32);
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"params":{"height": 1}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(block_body(&h, 1)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        // Tip=1000 vs height=1 → way beyond reorg-depth → permanent.
        let c = BlockCache::new(100, 6);
        for _ in 0..3 {
            c.get_by_height(1, &node, 1000).await.unwrap();
        }
    }

    #[tokio::test]
    async fn by_height_also_indexes_by_hash() {
        let server = MockServer::start().await;
        let h = "11".repeat(32);
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"params":{"height": 2}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(block_body(&h, 2)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = BlockCache::new(100, 6);
        let r = c.get_by_height(2, &node, 1000).await.unwrap();
        // Subsequent get_by_hash on the same block must hit cache.
        let r2 = c.get_by_hash(&r.hash, &node).await.unwrap();
        assert_eq!(r2.height, 2);
    }

    #[tokio::test]
    async fn invalidate_all_clears_both_keyspaces() {
        let server = MockServer::start().await;
        let h = "22".repeat(32);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(block_body(&h, 7)))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;
        let c = BlockCache::new(100, 6);
        c.get_by_height(7, &node, 1000).await.unwrap();
        assert!(c.hash_len() > 0 && c.height_len() > 0);
        c.invalidate_all();
        assert_eq!(c.hash_len(), 0);
        assert_eq!(c.height_len(), 0);
    }
}
