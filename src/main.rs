use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use exfer_walletd::config::Config;
use exfer_walletd::server;
use exfer_walletd::store::{KeyringStore, WalletStore};

/// Top-level CLI. Default invocation (no subcommand) runs the daemon
/// with [`Config`]; subcommands provide one-shot utilities that share
/// the same `--datadir` / `--wallet-dir` resolution.
#[derive(Parser, Debug)]
#[command(name = "exfer-walletd", version)]
struct Cli {
    #[command(flatten)]
    config: Config,
    #[command(subcommand)]
    subcmd: Option<Subcmd>,
}

#[derive(Subcommand, Debug)]
enum Subcmd {
    /// Import legacy `.key` files from a v0.x walletd directory into
    /// the v1 HD keystore as non-derived (imported) addresses.
    ///
    /// Requires `WALLETD_KEYSTORE_PASSPHRASE` so we can seal each
    /// imported secret with the same KEK as the seed.
    Migrate {
        /// Directory containing legacy `<addr>.key` files (raw 32 bytes
        /// or upstream-encrypted format). Subdirectories are not
        /// recursed.
        #[arg(long)]
        from: PathBuf,

        /// Optional passphrase for upstream-encrypted (`EXFK`) `.key`
        /// files. Plaintext `.key` files don't need this. Reads from
        /// env `WALLETD_LEGACY_PASSPHRASE` if not supplied as a flag.
        #[arg(long, env = "WALLETD_LEGACY_PASSPHRASE")]
        legacy_passphrase: Option<String>,
    },

    /// Initialise a SEEDED keystore (writes `seed.enc`) from a 24-word phrase
    /// — required for the cross-chain swap engine, whose BSC key derives from
    /// the HD seed. Generates a fresh phrase if `--mnemonic` is omitted, makes
    /// one standard EXFER address, and prints the phrase + EXFER + BSC
    /// addresses. Needs `WALLETD_KEYSTORE_PASSPHRASE`.
    InitSeeded {
        /// 24-word recovery phrase to seed from. Omit to generate a fresh one.
        #[arg(long)]
        mnemonic: Option<String>,
    },
}

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

    let cli = Cli::parse();
    match cli.subcmd {
        None => server::run(cli.config).await,
        Some(Subcmd::Migrate {
            from,
            legacy_passphrase,
        }) => run_migrate(cli.config, &from, legacy_passphrase.as_deref()),
        Some(Subcmd::InitSeeded { mnemonic }) => run_init_seeded(cli.config, mnemonic),
    }
}

fn run_init_seeded(cfg: Config, mnemonic: Option<String>) -> anyhow::Result<()> {
    use bip39::{Language, Mnemonic};
    let passphrase = std::env::var("WALLETD_KEYSTORE_PASSPHRASE").unwrap_or_default();
    if passphrase.is_empty() {
        anyhow::bail!("WALLETD_KEYSTORE_PASSPHRASE is required to seed the keystore.");
    }
    let phrase = match mnemonic {
        Some(p) => p,
        None => {
            let mut rng = rand::thread_rng();
            Mnemonic::generate_in_with(&mut rng, Language::English, 24)
                .map_err(|e| anyhow::anyhow!("generate mnemonic: {e}"))?
                .to_string()
        }
    };
    let wallet_dir = cfg.resolved_wallet_dir();
    KeyringStore::init_from_mnemonic(&wallet_dir, passphrase.as_bytes(), &phrase)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let store = KeyringStore::open_keyring(&wallet_dir, passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let (exfer_addr, _pubkey) = store
        .create_standard(Some("primary".into()))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let secret = store
        .evm_secret()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let bsc_addr =
        exfer_walletd::evm::evm_address(&secret).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    println!(
        "{}",
        serde_json::json!({
            "mnemonic": phrase,
            "exfer_address": exfer_addr,
            "bsc_address": bsc_addr,
            "wallet_dir": wallet_dir.display().to_string(),
        })
    );
    Ok(())
}

fn run_migrate(
    cfg: Config,
    legacy_dir: &std::path::Path,
    legacy_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let passphrase = std::env::var("WALLETD_KEYSTORE_PASSPHRASE").unwrap_or_default();
    if passphrase.is_empty() {
        anyhow::bail!(
            "WALLETD_KEYSTORE_PASSPHRASE is required to open / initialise the v1 keystore."
        );
    }
    let wallet_dir = cfg.resolved_wallet_dir();
    std::fs::create_dir_all(&wallet_dir)?;
    // Standalone daemon stays seeded (operators may rely on the seed
    // mnemonic backup + first-run print). The desktop's embedded path
    // (embed.rs) opens seedless.
    let store = KeyringStore::open_or_init_fresh(&wallet_dir, passphrase.as_bytes())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // Don't print the mnemonic during migrate — operator may be
    // running this non-interactively; the words would otherwise leak
    // to a log file. If a fresh keystore was just created, print a
    // shorter notice instead.
    if store.take_fresh_mnemonic().is_some() {
        eprintln!(
            "note: initialised a fresh v1 keystore at {}; backup mnemonic was \
             generated but NOT printed under `migrate` to avoid log capture. \
             Start the daemon once with no subcommand to see and record it.",
            wallet_dir.display()
        );
        anyhow::bail!(
            "refusing to migrate into a brand-new keystore without the operator first \
             recording the mnemonic. Run `exfer-walletd` (no subcommand) once, copy the \
             24-word backup, then re-run `migrate`."
        );
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let entries = std::fs::read_dir(legacy_dir)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", legacy_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if path.extension().and_then(|s| s.to_str()) != Some("key") {
            continue;
        }
        if stem.len() != 64 || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let secret: [u8; 32] = if bytes.len() == 32 {
            // Plaintext legacy format.
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else if bytes.len() >= 4 && &bytes[0..4] == b"EXFK" {
            // Upstream-encrypted format — needs the legacy passphrase.
            let pw = match legacy_passphrase {
                Some(p) => p,
                None => {
                    eprintln!(
                        "skip {}: looks encrypted (EXFK magic) but no --legacy-passphrase given",
                        path.display()
                    );
                    skipped += 1;
                    continue;
                }
            };
            use exfer::wallet::wallet::Wallet;
            let w = Wallet::load_encrypted(&path, pw.as_bytes())
                .map_err(|e| anyhow::anyhow!("load_encrypted {}: {:?}", path.display(), e))?;
            w.signing_key_for_cli().to_bytes()
        } else {
            eprintln!(
                "skip {}: unrecognised legacy format ({} bytes)",
                path.display(),
                bytes.len()
            );
            skipped += 1;
            continue;
        };

        match store.import(&secret, None) {
            Ok(addr) => {
                if addr.eq_ignore_ascii_case(&stem) {
                    println!("imported {addr}");
                    imported += 1;
                } else {
                    eprintln!(
                        "skip {}: derived address {addr} ≠ filename {stem} (corrupted file?)",
                        path.display()
                    );
                    skipped += 1;
                }
            }
            Err(e) => {
                eprintln!("skip {}: {e}", path.display());
                skipped += 1;
            }
        }
    }
    println!(
        "migrate complete: {imported} imported, {skipped} skipped (from {})",
        legacy_dir.display()
    );
    Ok(())
}
