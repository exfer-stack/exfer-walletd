//! L1 — chain tip cache.
//!
//! All other caches store `tip_at_fetch` so they can declare themselves
//! stale relative to the current chain head. The refresher consults
//! tip on every wake-up to detect reorgs. So tip is **hot** — without
//! this cache, every `list_balances` call would re-fetch tip too.
//!
//! Semantics differ from L2/L3:
//!
//! - **No generation / CAS.** Tip is a single global value; "two
//!   refresher passes interleaved" is impossible because there is one
//!   refresher.
//! - **Force-fetch path for the refresher.** The refresher explicitly
//!   bypasses TTL each tick — it's the *source* of the cache, not a
//!   reader. TTL only applies to incidental callers (an inbound RPC
//!   that wants tip while the refresher hasn't run for >TTL).
//! - **Serves stale on upstream error.** Cache lookup against a dead
//!   upstream returns the last-known tip with a `stale=true` flag.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::upstream::{BlockTip, ExferNode};

/// Snapshot returned to callers. `stale=true` iff the value is older
/// than [`TipCache::ttl`] *or* the most recent refresh attempt failed.
#[derive(Debug, Clone)]
pub struct TipSnapshot {
    pub tip: BlockTip,
    pub fetched_at: Instant,
    pub stale: bool,
    pub last_error: Option<String>,
}

struct State {
    tip: Option<BlockTip>,
    fetched_at: Option<Instant>,
    last_error: Option<String>,
}

pub struct TipCache {
    state: RwLock<State>,
    ttl: Duration,
}

impl TipCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: RwLock::new(State {
                tip: None,
                fetched_at: None,
                last_error: None,
            }),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Cache-aside read. Returns `Some(snap)` if a value has ever been
    /// successfully fetched; `None` if the cache has never been primed.
    ///
    /// Does **not** trigger a refresh — that is the refresher's job.
    /// Callers who need a fresh value should use [`Self::get_or_fetch`].
    pub fn peek(&self) -> Option<TipSnapshot> {
        let g = self.state.read().unwrap();
        let tip = g.tip.clone()?;
        let fetched_at = g.fetched_at?;
        let age = Instant::now().saturating_duration_since(fetched_at);
        let stale = age >= self.ttl || g.last_error.is_some();
        Some(TipSnapshot {
            tip,
            fetched_at,
            stale,
            last_error: g.last_error.clone(),
        })
    }

    /// Read-through. If a fresh entry exists, return it; otherwise hit
    /// upstream and write back. On upstream failure: if a stale entry
    /// exists, return that with `stale=true`; otherwise propagate the
    /// upstream error.
    pub async fn get_or_fetch(&self, node: &ExferNode) -> Result<TipSnapshot> {
        if let Some(snap) = self.peek() {
            if !snap.stale {
                return Ok(snap);
            }
        }
        self.force_fetch(node).await
    }

    /// Refresher entry point — always hits upstream, updates cache,
    /// records error on failure without clobbering the prior tip.
    pub async fn force_fetch(&self, node: &ExferNode) -> Result<TipSnapshot> {
        match node.get_block_height().await {
            Ok(tip) => {
                let mut g = self.state.write().unwrap();
                g.tip = Some(tip.clone());
                g.fetched_at = Some(Instant::now());
                g.last_error = None;
                Ok(TipSnapshot {
                    tip,
                    fetched_at: g.fetched_at.unwrap(),
                    stale: false,
                    last_error: None,
                })
            }
            Err(e) => {
                let stale_snap = {
                    let mut g = self.state.write().unwrap();
                    g.last_error = Some(e.to_string());
                    g.tip.clone().map(|tip| TipSnapshot {
                        tip,
                        fetched_at: g.fetched_at.unwrap_or_else(Instant::now),
                        stale: true,
                        last_error: g.last_error.clone(),
                    })
                };
                match stale_snap {
                    Some(s) => Ok(s),
                    None => Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_node(server: &MockServer) -> ExferNode {
        ExferNode::new(server.uri(), Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn peek_returns_none_before_first_fetch() {
        let c = TipCache::new(Duration::from_millis(200));
        assert!(c.peek().is_none());
    }

    #[tokio::test]
    async fn force_fetch_populates_cache_and_returns_fresh() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(
                serde_json::json!({"method":"get_block_height"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":{"height":100,"block_id":"aa"}
            })))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = TipCache::new(Duration::from_secs(60));
        let snap = c.force_fetch(&node).await.unwrap();
        assert_eq!(snap.tip.height, 100);
        assert!(!snap.stale);

        // Peek returns the same value, still fresh.
        let p = c.peek().unwrap();
        assert_eq!(p.tip.height, 100);
        assert!(!p.stale);
    }

    #[tokio::test]
    async fn peek_marks_stale_after_ttl() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":{"height":7,"block_id":"bb"}
            })))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = TipCache::new(Duration::from_millis(50));
        c.force_fetch(&node).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(c.peek().unwrap().stale);
    }

    #[tokio::test]
    async fn force_fetch_serves_stale_on_upstream_failure_when_primed() {
        let server = MockServer::start().await;
        // First call succeeds.
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({"id":1})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":{"height":5,"block_id":"aa"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Subsequent calls 5xx.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = TipCache::new(Duration::from_millis(10));
        c.force_fetch(&node).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let snap = c.force_fetch(&node).await.unwrap();
        assert!(snap.stale);
        assert!(snap.last_error.is_some());
        assert_eq!(snap.tip.height, 5, "stale value preserved");
    }

    #[tokio::test]
    async fn force_fetch_propagates_error_when_cache_cold() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = TipCache::new(Duration::from_millis(10));
        let r = c.force_fetch(&node).await;
        assert!(r.is_err(), "no stale fallback available");
    }

    #[tokio::test]
    async fn get_or_fetch_returns_fresh_without_hitting_upstream() {
        let server = MockServer::start().await;
        // Respond only ONCE.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":{"height":42,"block_id":"cc"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let node = mock_node(&server).await;

        let c = Arc::new(TipCache::new(Duration::from_secs(60)));
        let first = c.get_or_fetch(&node).await.unwrap();
        assert_eq!(first.tip.height, 42);

        // Second call must come from cache; if it hit upstream, wiremock
        // would 404 and the call would fail.
        let second = c.get_or_fetch(&node).await.unwrap();
        assert_eq!(second.tip.height, 42);
        assert!(!second.stale);
    }
}
