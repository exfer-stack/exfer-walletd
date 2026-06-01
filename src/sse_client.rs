//! Client for the upstream node's Phase 2 SSE push endpoint
//! (exfer issue #15 Tier 2).
//!
//! Talks to `GET /sse?addresses=<hex>,<hex>,...` on the node and forwards
//! every event onto an in-process broadcast channel that walletd
//! consumers (the follower's tick wake-up, the desktop / mobile Tauri
//! supervisors, future API endpoints) subscribe to.
//!
//! Probe-and-fallback:
//!
//!   - On first connect attempt, if the node returns 404 / any non-200
//!     / closes the connection within 500ms, the client logs once and
//!     enters "fallback mode" — the broadcast channel stays empty, and
//!     downstream consumers continue with whatever polling cadence they
//!     already had. We retry the probe on a long interval so a node
//!     upgrade gets picked up automatically without a walletd restart.
//!   - On a successful stream, we forward every event. If the stream
//!     drops mid-flight we reconnect with exponential backoff.
//!   - When the owned-address set changes (a new address generated,
//!     an old one deleted) we tear down the current stream and reopen
//!     with the new set. Polled every `ADDRESS_RESCAN_INTERVAL` and on
//!     every reconnect.
//!
//! Wire format mirrors `exfer::rpc_sse` exactly:
//!
//!   event: script_changed     data: {"script":"<hex>"}
//!   event: tip                data: {"height":N}
//!   event: resync             data: {}
//!
//! Heartbeats (`: heartbeat`) are silently consumed; they exist only
//! to keep the TCP / proxy mappings warm.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use serde_json::Value;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

use crate::store::WalletStore;
use crate::upstream::ExferNode;

/// How often to re-probe an unreachable SSE endpoint. Long because the
/// follower's existing 2 s poll loop already covers the fallback case
/// and an aggressive retry would just waste CPU.
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Backoff for transient stream drops on a working endpoint. Capped so
/// we don't pile up while the node is restarting.
const STREAM_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const STREAM_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// How often we re-list the wallet store to pick up newly-generated
/// addresses. Cheap (one redb read); the actual reconnect is only
/// triggered on a real diff.
const ADDRESS_RESCAN_INTERVAL: Duration = Duration::from_secs(15);

/// Connect timeout for the probe phase. Anything longer is treated as
/// unreachable so we fall back fast.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Internal broadcast capacity. Sized for ~1 minute of bursty mempool
/// activity at one event per address change; slow consumers see
/// `RecvError::Lagged` and can resync via the wallet's normal
/// JSON-RPC calls.
const BROADCAST_CAPACITY: usize = 1024;

/// One nudge from the bus. Carries either a specific script that
/// changed (re-pull balance / mempool for that address), a tip
/// advancement (re-pull height-dependent state), or a resync flag
/// (re-pull everything).
#[derive(Clone, Debug)]
pub enum WalletNudge {
    /// 32-byte script bytes that changed. Walletd consumers should
    /// re-derive balance / utxos for the matching owned address.
    Script(Vec<u8>),
    /// Tip advanced.
    Tip(u64),
    /// Bus dropped events for this subscriber upstream. Consumers
    /// should re-pull every owned address's balance.
    Resync,
}

/// In-process push channel for walletd internal events. Embedders (the
/// Tauri supervisor, the follower) hold an `Arc<WalletEvents>` and call
/// `subscribe()` to get a `broadcast::Receiver<WalletNudge>`.
pub struct WalletEvents {
    inner: broadcast::Sender<WalletNudge>,
}

impl std::fmt::Debug for WalletEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletEvents")
            .field("subscribers", &self.inner.receiver_count())
            .finish()
    }
}

impl WalletEvents {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Arc::new(WalletEvents { inner: tx })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WalletNudge> {
        self.inner.subscribe()
    }

    /// Number of live subscribers (for observability).
    pub fn subscriber_count(&self) -> usize {
        self.inner.receiver_count()
    }

    fn emit(&self, nudge: WalletNudge) {
        // Best-effort. A zero-receiver channel returns Err — that's
        // fine, nothing's listening yet.
        let _ = self.inner.send(nudge);
    }
}

/// Status the supervisor can read for observability and for telling
/// users whether they're on push or poll.
#[derive(Clone, Debug)]
pub enum SseStatus {
    /// Have not yet attempted a probe.
    Init,
    /// Probe failed; periodically retrying. Downstream is on poll.
    Fallback { reason: String },
    /// Connected and forwarding events.
    Active { addresses: usize },
}

/// SSE client task handle. Constructed once at walletd boot, spawned via
/// [`SseClient::spawn`], cancelled by dropping the cancellation token.
pub struct SseClient {
    store: Arc<dyn WalletStore>,
    node: Arc<ExferNode>,
    events: Arc<WalletEvents>,
    status: Arc<RwLock<SseStatus>>,
}

impl SseClient {
    pub fn new(
        store: Arc<dyn WalletStore>,
        node: Arc<ExferNode>,
        events: Arc<WalletEvents>,
    ) -> Arc<Self> {
        Arc::new(SseClient {
            store,
            node,
            events,
            status: Arc::new(RwLock::new(SseStatus::Init)),
        })
    }

    pub fn status_handle(&self) -> Arc<RwLock<SseStatus>> {
        self.status.clone()
    }

    /// Spawn the client run loop. Returns a handle that the caller can
    /// use to wait for shutdown; cancel via the passed-in token.
    pub fn spawn(self: Arc<Self>, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run(shutdown).await })
    }

    async fn set_status(&self, s: SseStatus) {
        let mut g = self.status.write().await;
        *g = s;
    }

    async fn list_addresses(&self) -> HashSet<[u8; 32]> {
        let store = self.store.clone();
        let res = tokio::task::spawn_blocking(move || store.list()).await;
        let entries = match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "sse_client: store.list() failed");
                return HashSet::new();
            }
            Err(join) => {
                tracing::warn!(error = %join, "sse_client: store.list() panicked");
                return HashSet::new();
            }
        };
        entries
            .into_iter()
            .filter_map(|e| {
                let raw = match hex::decode(&e.address) {
                    Ok(v) => v,
                    Err(_) => return None,
                };
                if raw.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                Some(arr)
            })
            .collect()
    }

    /// Pick the first configured upstream URL as the SSE base — SSE
    /// is sticky-per-connection so multi-node load balancing doesn't
    /// add anything here.
    fn sse_url(&self, addresses: &HashSet<[u8; 32]>) -> Option<String> {
        let nodes = self.node.nodes();
        let base = nodes.first()?;
        let mut hex_addrs: Vec<String> = addresses.iter().map(hex::encode).collect();
        hex_addrs.sort(); // determinism for log scraping
        Some(format!(
            "{}/sse?addresses={}",
            base.trim_end_matches('/'),
            hex_addrs.join(",")
        ))
    }

    async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let mut backoff = STREAM_BACKOFF_INITIAL;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(300)) // long for the read; we hand-rolled the connect timeout below
            .build();
        let http = match http {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "sse_client: failed to build reqwest client; SSE disabled");
                self.set_status(SseStatus::Fallback {
                    reason: format!("reqwest build failed: {e}"),
                })
                .await;
                return;
            }
        };

        loop {
            if shutdown.is_cancelled() {
                return;
            }

            let addresses = self.list_addresses().await;
            if addresses.is_empty() {
                // Nothing to subscribe to. Wait, re-list, try again.
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(ADDRESS_RESCAN_INTERVAL) => continue,
                }
            }

            let url = match self.sse_url(&addresses) {
                Some(u) => u,
                None => {
                    self.set_status(SseStatus::Fallback {
                        reason: "no upstream URL configured".into(),
                    })
                    .await;
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(PROBE_RETRY_INTERVAL) => continue,
                    }
                }
            };

            // Probe: try to open the stream; if the connect fails or the
            // node refuses /sse, go to fallback and re-probe later.
            // Native SSE is a GET with addresses in the query string.
            let probe = tokio::time::timeout(
                PROBE_CONNECT_TIMEOUT,
                http.get(&url).header("Accept", "text/event-stream").send(),
            )
            .await;

            let response = match probe {
                Ok(Ok(r)) if r.status().is_success() => {
                    self.set_status(SseStatus::Active {
                        addresses: addresses.len(),
                    })
                    .await;
                    backoff = STREAM_BACKOFF_INITIAL;
                    tracing::info!(
                        url = %url,
                        addresses = addresses.len(),
                        "sse_client: stream open"
                    );
                    r
                }
                Ok(Ok(r)) => {
                    let reason = format!("HTTP {}", r.status());
                    tracing::info!(
                        url = %url,
                        status = %r.status(),
                        "sse_client: upstream does not support /sse (Phase 2); using poll fallback"
                    );
                    self.set_status(SseStatus::Fallback { reason }).await;
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(PROBE_RETRY_INTERVAL) => continue,
                    }
                }
                Ok(Err(e)) => {
                    let reason = format!("connect: {e}");
                    tracing::debug!(error = %e, "sse_client: connect failed; fallback");
                    self.set_status(SseStatus::Fallback { reason }).await;
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(PROBE_RETRY_INTERVAL) => continue,
                    }
                }
                Err(_) => {
                    self.set_status(SseStatus::Fallback {
                        reason: format!("connect timeout > {:?}", PROBE_CONNECT_TIMEOUT),
                    })
                    .await;
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(PROBE_RETRY_INTERVAL) => continue,
                    }
                }
            };

            // Stream loop. reqwest::Response::bytes_stream is itself
            // an `impl Stream<Item = Result<Bytes>>`; we accumulate bytes
            // into a line buffer and parse one event per blank line.
            let mut stream = response.bytes_stream();
            let mut line_buf = String::new();
            let mut current_event: Option<String> = None;
            let mut current_data: String = String::new();
            let mut rescan_tick = tokio::time::interval(ADDRESS_RESCAN_INTERVAL);
            rescan_tick.tick().await; // discard immediate

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    chunk = stream.next() => {
                        let chunk = match chunk {
                            Some(Ok(b)) => b,
                            Some(Err(e)) => {
                                tracing::warn!(error = %e, "sse_client: stream error; reconnecting");
                                break;
                            }
                            None => {
                                tracing::info!("sse_client: stream ended; reconnecting");
                                break;
                            }
                        };
                        let s = match std::str::from_utf8(&chunk) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(error = %e, "sse_client: non-utf8 chunk; reconnecting");
                                break;
                            }
                        };
                        for ch in s.chars() {
                            if ch == '\n' {
                                let line = std::mem::take(&mut line_buf);
                                if line.is_empty() {
                                    // Event delimiter — dispatch.
                                    if let Some(ev) = current_event.take() {
                                        dispatch_event(&self.events, &ev, &current_data);
                                    }
                                    current_data.clear();
                                } else if let Some(rest) = line.strip_prefix("event: ") {
                                    current_event = Some(rest.to_string());
                                } else if let Some(rest) = line.strip_prefix("data: ") {
                                    if !current_data.is_empty() {
                                        current_data.push('\n');
                                    }
                                    current_data.push_str(rest);
                                } else if line.starts_with(':') {
                                    // SSE comment — heartbeats. Ignore.
                                }
                            } else if ch != '\r' {
                                line_buf.push(ch);
                            }
                        }
                    }
                    _ = rescan_tick.tick() => {
                        // Did the address set change? If yes, reconnect.
                        let now = self.list_addresses().await;
                        if now != addresses {
                            tracing::info!(
                                old = addresses.len(),
                                new = now.len(),
                                "sse_client: address set changed; reconnecting"
                            );
                            break;
                        }
                    }
                }
            }

            // Stream broke. Back off and reconnect.
            self.set_status(SseStatus::Fallback {
                reason: "stream interrupted; reconnecting".into(),
            })
            .await;
            let sleep = backoff;
            backoff = std::cmp::min(backoff * 2, STREAM_BACKOFF_MAX);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(sleep) => {}
            }
        }
    }
}

fn dispatch_event(events: &Arc<WalletEvents>, name: &str, data: &str) {
    match name {
        "script_changed" => {
            let v: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, data = data, "sse_client: bad script_changed payload");
                    return;
                }
            };
            let s = match v.get("script").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    tracing::warn!(data = data, "sse_client: script_changed missing `script`");
                    return;
                }
            };
            let bytes = match hex::decode(s) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "sse_client: bad hex in script_changed");
                    return;
                }
            };
            events.emit(WalletNudge::Script(bytes));
        }
        "tip" => {
            let v: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(_) => return,
            };
            let h = match v.get("height").and_then(|v| v.as_u64()) {
                Some(h) => h,
                None => return,
            };
            events.emit(WalletNudge::Tip(h));
        }
        "resync" => events.emit(WalletNudge::Resync),
        other => {
            tracing::debug!(event = other, "sse_client: unknown event type, ignoring");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wallet_events_broadcasts_to_multiple_subscribers() {
        let ev = WalletEvents::new();
        let mut a = ev.subscribe();
        let mut b = ev.subscribe();
        ev.emit(WalletNudge::Tip(42));
        let recv_a = a.recv().await.unwrap();
        let recv_b = b.recv().await.unwrap();
        assert!(matches!(recv_a, WalletNudge::Tip(42)));
        assert!(matches!(recv_b, WalletNudge::Tip(42)));
    }

    #[tokio::test]
    async fn dispatch_script_changed_parses_hex() {
        let ev = WalletEvents::new();
        let mut rx = ev.subscribe();
        let data = format!("{{\"script\":\"{}\"}}", "aa".repeat(32));
        dispatch_event(&ev, "script_changed", &data);
        match rx.recv().await.unwrap() {
            WalletNudge::Script(s) => assert_eq!(s, vec![0xaa; 32]),
            other => panic!("expected Script, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn dispatch_tip_parses_height() {
        let ev = WalletEvents::new();
        let mut rx = ev.subscribe();
        dispatch_event(&ev, "tip", "{\"height\":99}");
        match rx.recv().await.unwrap() {
            WalletNudge::Tip(99) => {}
            other => panic!("expected Tip(99), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn dispatch_resync_emits_resync() {
        let ev = WalletEvents::new();
        let mut rx = ev.subscribe();
        dispatch_event(&ev, "resync", "{}");
        assert!(matches!(rx.recv().await.unwrap(), WalletNudge::Resync));
    }

    #[tokio::test]
    async fn dispatch_ignores_unknown_event_type() {
        let ev = WalletEvents::new();
        let mut rx = ev.subscribe();
        dispatch_event(&ev, "future_event_we_dont_know", "{}");
        // No emit should have happened.
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }
}
