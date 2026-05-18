# Backup, upgrade, rotate

## Backup

Back up `~/.exfer-walletd/wallets/`. Losing it = losing every key =
losing every penny those addresses hold.

```bash
# Stop walletd briefly for a consistent snapshot
# (whatever supervisor you use — Ctrl-C, systemctl, docker stop …)
tar -C ~ -czf wallets-$(date +%F).tar.gz .exfer-walletd

# Encrypt before shipping off-box
gpg --symmetric --cipher-algo AES256 wallets-$(date +%F).tar.gz
# → wallets-YYYY-MM-DD.tar.gz.gpg — safe to store offsite
```

If you can't stop the daemon, snapshot the underlying volume (LVM,
ZFS, your cloud volume snapshot). Atomic copies of individual `.key`
files are fine — walletd writes them with `O_CREAT | O_EXCL` and never
modifies in-place.

## Upgrade

Walletd uses semver. Patches and minors are drop-in; majors will be
called out in the release notes.

```bash
# stop, replace binary, start — exactly how you started it the first time
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
# restart walletd via whatever supervisor you use
```

The `<datadir>` format is stable: any version of walletd can load any
wallet file written by any other version.

## Rotate tokens

Single-token (auto-generated) mode — delete the file, restart, copy
the fresh token from the startup output:

```bash
rm ~/.exfer-walletd/token
exfer-walletd        # generates + prints a new one
```

Two-token mode — change the env values / CLI flags and restart.

Either way, any in-flight request authenticated with the old token
will fail after the restart and need to retry with the new one. Plan
the window.

## Point at a different node

Change `--node-rpc` / `EXFER_NODE_RPC` and restart. Wallets and tokens
are unaffected.

```bash
EXFER_NODE_RPC=http://new-node-host:9334 exfer-walletd
```

Comma-separate URLs for round-robin + failover across several nodes:

```bash
EXFER_NODE_RPC='http://node-a:9334,http://node-b:9334' exfer-walletd
```

## Uninstall

There's no uninstall ceremony — walletd doesn't touch anything outside
its `--datadir`.

```bash
# Stop the daemon, then:
rm -rf ~/.exfer-walletd     # tokens + wallets — IRREVERSIBLE
sudo rm /usr/local/bin/exfer-walletd
```

If you back up `~/.exfer-walletd/wallets/` first, you can restore the
exact same address set later by dropping the directory back into
place.

## Next

- [FAQ & troubleshooting →](./faq.md)
