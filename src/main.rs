use std::io::IsTerminal;

use clap::Parser;

use exfer_walletd::config::Config;
use exfer_walletd::server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Suppress ANSI escapes when stderr isn't a TTY (systemd journal,
    // Docker logs, file redirects) so operators don't see `[2m...[0m`
    // litter in `journalctl -u exfer-walletd`.
    tracing_subscriber::fmt()
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn,exfer_walletd=debug".into()),
        )
        .init();

    let cfg = Config::parse();
    server::run(cfg).await
}
