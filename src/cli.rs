//! Top-level CLI entry. Two modes:
//!
//! - **No subcommand** — run the daemon. All daemon flags / env vars
//!   are flattened in from [`crate::config::Config`] for backward
//!   compatibility (`exfer-walletd --bind … --node-rpc …` keeps
//!   working).
//! - **`init`** — one-shot scaffolder. Generates fresh tokens, writes
//!   the env file, creates the wallet directory. Idempotent: refuses
//!   to clobber an existing env file unless `--force` is set.
//! - **`uninstall`** — reverse of `init`. Dry-run by default; `--yes`
//!   executes. See [`crate::uninstall`] for the safety rails around
//!   wallet-directory deletion.

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::init::InitArgs;
use crate::uninstall::UninstallArgs;

#[derive(Parser)]
#[command(
    name = "exfer-walletd",
    about = "Exfer Wallet Daemon — independent wallet service that exposes generate_address / transfer / balance over JSON-RPC, talking to one or more Exfer nodes",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Daemon flags (consumed when no subcommand is given).
    #[command(flatten)]
    pub daemon: Config,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scaffold a fresh deployment: generate tokens, write the env
    /// file, create the wallet directory.
    Init(InitArgs),

    /// Reverse `init`. Dry-run by default; `--yes` executes. Wallet
    /// directory is preserved unless `--wallets` (plus
    /// `--i-understand-this-deletes-keys` if it contains keys) is set.
    Uninstall(UninstallArgs),
}

impl Cli {
    pub fn from_env() -> Self {
        Self::parse()
    }
}
