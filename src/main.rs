use exfer_walletd::cli::{Cli, Command};
use exfer_walletd::{init, server, uninstall};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::from_env();

    match cli.command {
        Some(Command::Init(args)) => {
            // Init writes a file and exits; quieter logger is enough.
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "warn".into()),
                )
                .init();
            init::run(args)
        }
        Some(Command::Uninstall(args)) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "warn".into()),
                )
                .init();
            uninstall::run(args)
        }
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info,tower_http=warn,exfer_walletd=debug".into()),
                )
                .init();
            server::run(cli.daemon).await
        }
    }
}
