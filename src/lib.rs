//! `exfer-walletd` — the **Exfer Wallet Daemon**.
//!
//! An independent HTTP service that manages wallet keypairs and exposes
//! higher-level RPC methods (`generate_address`, `transfer`, `balance`,
//! …) on top of one or more Exfer nodes. The daemon **does not require
//! a colocated node** — point it at any reachable Exfer JSON-RPC URL
//! (or several, for round-robin + failover) and it just works.
//!
//! Why this exists:
//! the Exfer node's own JSON-RPC interface is intentionally read-only
//! plus broadcast. It can't sign on your behalf, because nodes never
//! hold keys. `exfer-walletd` closes the gap by holding a pool of
//! wallet keypairs, building and signing transactions locally using
//! the same crypto primitives as the upstream `exfer` binary (via the
//! `exfer` crate), and broadcasting the signed bytes through the
//! node(s).
//!
//! Topology — any of:
//!
//! ```text
//!   ┌─ exchange / app backend ─┐
//!   │                          │
//!   │  POST / (JSON-RPC + auth)│
//!   │                          │
//!   └─────────────────────────▶│
//!                              │
//!                       exfer-walletd
//!                              │
//!                              │  one or more node URLs
//!                              │  (loopback, LAN, VPC, public RPC)
//!                              ▼
//!                ┌─── exfer node(s) ───┐
//! ```
//!
//! Keys never leave the host running the daemon. Upstream nodes never
//! see a private key.
//!
//! ## Architecture
//!
//! Modules in dependency order:
//!
//! - [`error`] — crate-wide error enum with JSON-RPC code mapping
//! - [`config`] — CLI / env config (clap + env vars)
//! - [`store`] — [`WalletStore`](store::WalletStore) trait; ships with
//!   [`FsWalletStore`](store::FsWalletStore). Future backends (redb,
//!   cloud KMS) drop in here.
//! - [`upstream`] — async client for the Exfer node JSON-RPC, with
//!   round-robin + failover across multiple node URLs.
//! - [`tx`] — transfer engine: authenticated UTXO fetch → local Ed25519
//!   sign → broadcast.
//! - [`api`] — JSON-RPC dispatch (wrapper-only methods + passthroughs).
//! - [`server`] — axum HTTP server, Bearer auth, health endpoint.

pub mod allowance;
pub mod api;
pub mod auth;
pub mod config;
pub mod embed;
pub mod error;
pub mod evm;
pub mod follower;
pub mod idempotency;
pub mod index;
pub mod indexer;
pub mod inflight;
pub mod payment_uri;
pub mod server;
pub mod sse_client;
pub mod store;
pub mod swap;
pub mod tls;
pub mod tx;
pub mod upstream;

pub use embed::{run_embedded, EmbeddedTokens, ServerHandle};
pub use error::{Error, Result};
