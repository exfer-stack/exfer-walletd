use clap::Parser;

use exfer_walletd::config::Config;
use exfer_walletd::server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn,exfer_walletd=debug".into()),
        )
        .init();

    let cfg = Config::parse();
    server::run(cfg).await
}
