//! `exfer-walletd uninstall` — reverse the work of `init`.
//!
//! Mirror of [`crate::init`]. Default is conservative:
//!
//! - Always offered: delete the env file (tokens + config).
//! - `--systemd`: stop + disable + remove the systemd unit + daemon-reload.
//! - `--wallets`: also delete the wallet directory. If the directory is
//!   non-empty, additionally requires
//!   `--i-understand-this-deletes-keys` — losing a `.key` file means
//!   losing every penny that address holds, so we make the operator
//!   type out an unambiguous phrase rather than letting `--yes` carry
//!   the day.
//! - Dry-run by default: without `--yes`, prints the plan and exits 0
//!   without touching anything.
//!
//! Things `init` doesn't create are not touched here either —
//! `useradd`, Caddy config, the binary in `/usr/local/bin`. Those are
//! printed as "follow-up" suggestions at the end so the operator can
//! finish the cleanup deliberately.
//!
//! All steps are best-effort idempotent: missing paths / inactive
//! services are not errors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Env file written by `init`.
    #[arg(long, default_value = "/etc/exfer-walletd/env")]
    pub env_file: PathBuf,

    /// Wallet directory created by `init`. Only deleted if `--wallets`
    /// is also set.
    #[arg(long, default_value = "/var/lib/exfer-walletd")]
    pub wallet_dir: PathBuf,

    /// Also delete the wallet directory. Without this, the wallet
    /// directory is left in place — losing `.key` files loses every
    /// penny those addresses hold, so the default is to preserve them.
    #[arg(long)]
    pub wallets: bool,

    /// Explicit acknowledgement required when the wallet directory is
    /// non-empty. Even with `--wallets --yes`, walletd refuses to
    /// delete a directory that contains key files unless this flag is
    /// also set. The intent is to require an operator to type out an
    /// unambiguous phrase rather than letting habit + `--yes` do
    /// irreversible damage.
    #[arg(long)]
    pub i_understand_this_deletes_keys: bool,

    /// Also stop + disable + remove the systemd unit.
    #[arg(long)]
    pub systemd: bool,

    /// systemd service name (used for `systemctl stop/disable`).
    #[arg(long, default_value = "exfer-walletd")]
    pub service_name: String,

    /// Systemd unit file to remove.
    #[arg(long, default_value = "/etc/systemd/system/exfer-walletd.service")]
    pub unit_file: PathBuf,

    /// Actually perform the actions. Without this flag, uninstall prints
    /// what it *would* do and exits without touching anything.
    #[arg(long)]
    pub yes: bool,
}

/// One step in the uninstall plan. Captured as data so we can render
/// it both as a dry-run and as actual execution.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    SystemctlStop(String),
    SystemctlDisable(String),
    RemoveUnitFile(PathBuf),
    SystemctlDaemonReload,
    RemoveEnvFile(PathBuf),
    RemoveWalletDir { path: PathBuf, entry_count: usize },
}

impl Action {
    fn describe(&self) -> String {
        match self {
            Action::SystemctlStop(name) => {
                format!("systemctl stop {name}  (ignore failure if inactive)")
            }
            Action::SystemctlDisable(name) => {
                format!("systemctl disable {name}  (ignore failure if not enabled)")
            }
            Action::RemoveUnitFile(p) => format!("rm {}", p.display()),
            Action::SystemctlDaemonReload => "systemctl daemon-reload".to_string(),
            Action::RemoveEnvFile(p) => format!("rm {}  (env file with tokens)", p.display()),
            Action::RemoveWalletDir { path, entry_count } => {
                if *entry_count == 0 {
                    format!("rmdir {}  (empty)", path.display())
                } else {
                    let noun = if *entry_count == 1 {
                        "entry"
                    } else {
                        "entries"
                    };
                    format!(
                        "rm -rf {}  ({} {} — DESTROYS KEYS)",
                        path.display(),
                        entry_count,
                        noun
                    )
                }
            }
        }
    }
}

pub fn run(args: UninstallArgs) -> anyhow::Result<()> {
    // Refuse early if --wallets points at a non-empty directory and the
    // operator hasn't explicitly acknowledged what that means.
    let wallet_entries = if args.wallets {
        Some(count_entries(&args.wallet_dir)?)
    } else {
        None
    };
    if let Some(n) = wallet_entries {
        if n > 0 && !args.i_understand_this_deletes_keys {
            let noun = if n == 1 { "entry" } else { "entries" };
            anyhow::bail!(
                "{} contains {} {} — refusing to delete without --i-understand-this-deletes-keys. \
                 Losing a .key file loses every penny that address holds. \
                 If you really mean it, re-run with --i-understand-this-deletes-keys.",
                args.wallet_dir.display(),
                n,
                noun,
            );
        }
    }

    let plan = build_plan(&args, wallet_entries);

    if plan.is_empty() {
        eprintln!(
            "Nothing to do. (env file, unit file, and wallet dir are all absent or out of scope.)"
        );
        return Ok(());
    }

    eprintln!();
    eprintln!("uninstall plan:");
    for (i, action) in plan.iter().enumerate() {
        eprintln!("  {}. {}", i + 1, action.describe());
    }
    eprintln!();

    if !args.yes {
        eprintln!("Dry run. Re-run with --yes to execute.");
        print_followups(&args);
        return Ok(());
    }

    for action in &plan {
        execute(action)?;
    }

    eprintln!();
    eprintln!("Done.");
    print_followups(&args);
    Ok(())
}

fn build_plan(args: &UninstallArgs, wallet_entries: Option<usize>) -> Vec<Action> {
    let mut plan = Vec::new();

    if args.systemd {
        // We always *try* stop/disable — systemctl handles "not loaded"
        // gracefully and we tolerate non-zero exits in execute(). Skip
        // only the unit-file removal if the file is absent.
        plan.push(Action::SystemctlStop(args.service_name.clone()));
        plan.push(Action::SystemctlDisable(args.service_name.clone()));
        if args.unit_file.exists() {
            plan.push(Action::RemoveUnitFile(args.unit_file.clone()));
            plan.push(Action::SystemctlDaemonReload);
        }
    }

    if args.env_file.exists() {
        plan.push(Action::RemoveEnvFile(args.env_file.clone()));
    }

    if let Some(n) = wallet_entries {
        // wallet_entries is Some(_) iff --wallets was passed; n was
        // taken from a real stat above, so the dir exists.
        plan.push(Action::RemoveWalletDir {
            path: args.wallet_dir.clone(),
            entry_count: n,
        });
    }

    plan
}

fn execute(action: &Action) -> anyhow::Result<()> {
    match action {
        Action::SystemctlStop(name) => {
            // Tolerate "Unit ... not loaded" / "inactive" — uninstall
            // shouldn't fail just because the daemon wasn't running.
            let status = Command::new("systemctl").arg("stop").arg(name).status();
            log_systemctl("stop", name, status);
        }
        Action::SystemctlDisable(name) => {
            let status = Command::new("systemctl").arg("disable").arg(name).status();
            log_systemctl("disable", name, status);
        }
        Action::RemoveUnitFile(p) => {
            remove_file_if_exists(p)?;
            eprintln!("  removed {}", p.display());
        }
        Action::SystemctlDaemonReload => {
            let status = Command::new("systemctl").arg("daemon-reload").status();
            log_systemctl("daemon-reload", "", status);
        }
        Action::RemoveEnvFile(p) => {
            remove_file_if_exists(p)?;
            eprintln!("  removed {}", p.display());
        }
        Action::RemoveWalletDir { path, .. } => {
            if path.exists() {
                fs::remove_dir_all(path)?;
                eprintln!("  removed {}", path.display());
            }
        }
    }
    Ok(())
}

fn log_systemctl(verb: &str, name: &str, result: io::Result<std::process::ExitStatus>) {
    match result {
        Ok(s) if s.success() => eprintln!("  systemctl {verb} {name}"),
        Ok(s) => eprintln!("  systemctl {verb} {name} → exit {s} (ignored)"),
        Err(e) => eprintln!("  systemctl {verb} {name} → {e} (ignored — systemctl missing?)"),
    }
}

fn remove_file_if_exists(p: &Path) -> io::Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn count_entries(dir: &Path) -> anyhow::Result<usize> {
    match fs::read_dir(dir) {
        Ok(it) => Ok(it.count()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn print_followups(args: &UninstallArgs) {
    eprintln!();
    eprintln!("Not automated (clean up by hand if you want a complete teardown):");
    eprintln!("  - runtime user:   sudo userdel exfer-walletd");
    eprintln!("  - binary:         sudo rm /usr/local/bin/exfer-walletd");
    if let Some(parent) = args.env_file.parent() {
        // Only suggest removing the parent if it would now be empty.
        if parent.exists() && dir_is_empty(parent) {
            eprintln!("  - empty env dir:  sudo rmdir {}", parent.display());
        }
    }
    eprintln!("  - reverse proxy:  remove the walletd block from your Caddyfile / nginx conf");
    eprintln!();
}

fn dir_is_empty(p: &Path) -> bool {
    fs::read_dir(p)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn args_with(dir: &Path) -> UninstallArgs {
        UninstallArgs {
            env_file: dir.join("env"),
            wallet_dir: dir.join("wallets"),
            wallets: false,
            i_understand_this_deletes_keys: false,
            systemd: false,
            service_name: "exfer-walletd".into(),
            unit_file: dir.join("exfer-walletd.service"),
            yes: false,
        }
    }

    #[test]
    fn dry_run_does_not_remove_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        File::create(&args.env_file)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        args.yes = false;
        run(args).unwrap();
        assert!(dir.path().join("env").exists());
    }

    #[test]
    fn yes_removes_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        File::create(&args.env_file)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        args.yes = true;
        run(args).unwrap();
        assert!(!dir.path().join("env").exists());
    }

    #[test]
    fn missing_env_file_is_ok() {
        // Idempotent: re-running uninstall on a host that already had
        // it removed is a no-op, not an error.
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        args.yes = true;
        run(args).unwrap();
    }

    #[test]
    fn wallets_non_empty_refused_without_ack() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        fs::create_dir(&args.wallet_dir).unwrap();
        File::create(args.wallet_dir.join("aa.key"))
            .unwrap()
            .write_all(b"k")
            .unwrap();
        args.wallets = true;
        args.yes = true;
        // i_understand_this_deletes_keys deliberately false
        let err = run(args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--i-understand-this-deletes-keys"),
            "msg was: {msg}"
        );
        assert!(dir.path().join("wallets/aa.key").exists());
    }

    #[test]
    fn wallets_empty_dir_deletes_without_ack() {
        // An empty wallets dir is harmless; the irrevocability gate is
        // about destroying keys, and there are none.
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        fs::create_dir(&args.wallet_dir).unwrap();
        args.wallets = true;
        args.yes = true;
        run(args).unwrap();
        assert!(!dir.path().join("wallets").exists());
    }

    #[test]
    fn wallets_non_empty_with_ack_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        fs::create_dir(&args.wallet_dir).unwrap();
        File::create(args.wallet_dir.join("aa.key"))
            .unwrap()
            .write_all(b"k")
            .unwrap();
        args.wallets = true;
        args.i_understand_this_deletes_keys = true;
        args.yes = true;
        run(args).unwrap();
        assert!(!dir.path().join("wallets").exists());
    }

    #[test]
    fn plan_includes_unit_file_only_if_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_with(dir.path());
        args.systemd = true;
        // No unit file written
        let plan = build_plan(&args, None);
        assert!(plan.iter().any(|a| matches!(a, Action::SystemctlStop(_))));
        assert!(!plan.iter().any(|a| matches!(a, Action::RemoveUnitFile(_))));
        assert!(!plan
            .iter()
            .any(|a| matches!(a, Action::SystemctlDaemonReload)));

        // With unit file present, plan includes its removal + reload.
        File::create(&args.unit_file)
            .unwrap()
            .write_all(b"[Unit]")
            .unwrap();
        let plan = build_plan(&args, None);
        assert!(plan.iter().any(|a| matches!(a, Action::RemoveUnitFile(_))));
        assert!(plan
            .iter()
            .any(|a| matches!(a, Action::SystemctlDaemonReload)));
    }
}
