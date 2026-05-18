# Backup, upgrade, rotate

## Backup

Back up the wallet directory. Losing it = losing every key = losing
every penny those addresses hold.

```bash
# Stop walletd briefly for a consistent snapshot
sudo systemctl stop exfer-walletd
sudo tar -C /var/lib -czf wallets-$(date +%F).tar.gz exfer-walletd
sudo systemctl start exfer-walletd

# Encrypt before shipping off-box
gpg --symmetric --cipher-algo AES256 wallets-$(date +%F).tar.gz
# → wallets-YYYY-MM-DD.tar.gz.gpg — safe to store offsite
```

If you can't stop the daemon, snapshot the underlying volume (LVM,
ZFS, your cloud volume snapshot). Atomic copies of individual `.key`
files are fine — walletd writes them with `O_CREAT | O_EXCL` and
never modifies in-place.

## Upgrade

Walletd uses semver. Patches and minors are drop-in; majors will be
called out in the release notes.

```bash
sudo systemctl stop exfer-walletd
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
sudo systemctl start exfer-walletd
sudo journalctl -u exfer-walletd -n 20
```

The wallet directory format is stable: any version of walletd can
load any wallet file written by any other version.

## Rotate tokens

Tokens are stateless — just change them.

Single-token mode:

```bash
sudo sed -i "s|^WALLETD_AUTH_TOKEN=.*|WALLETD_AUTH_TOKEN=$(openssl rand -hex 32)|" \
    /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Two-token (`--scoped`) mode:

```bash
sudo sed -i \
  -e "s|^WALLETD_AUTH_TOKEN_READ=.*|WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32)|" \
  -e "s|^WALLETD_AUTH_TOKEN_SPEND=.*|WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)|" \
  /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Then update your client application. Any in-flight request
authenticated with the old token will fail after the restart and need
to retry with the new one. Plan the window.

## Point at a different node

The upstream node URL lives in `EXFER_NODE_RPC`. Edit, restart, done
— wallets and tokens are unaffected.

```bash
sudo sed -i "s|^EXFER_NODE_RPC=.*|EXFER_NODE_RPC=http://new-node-host:9334|" \
    /etc/exfer-walletd/env
sudo systemctl restart exfer-walletd
```

Comma-separate URLs for round-robin + failover across several nodes.

## Uninstall

`exfer-walletd uninstall` reverses `init`. Dry-run by default — it
prints the plan and exits without touching anything until you pass
`--yes`. The wallet directory is preserved by default; losing `.key`
files loses every penny those addresses hold.

```bash
# 1. See what would happen — no changes made.
sudo exfer-walletd uninstall --systemd
#   uninstall plan:
#     1. systemctl stop exfer-walletd  (ignore failure if inactive)
#     2. systemctl disable exfer-walletd
#     3. rm /etc/systemd/system/exfer-walletd.service
#     4. systemctl daemon-reload
#     5. rm /etc/exfer-walletd/env  (env file with tokens)
#   Dry run. Re-run with --yes to execute.

# 2. Execute. Wallet directory still untouched.
sudo exfer-walletd uninstall --systemd --yes

# 3. ONLY when you really want the keys gone (and have backups elsewhere):
sudo exfer-walletd uninstall \
    --systemd --wallets --i-understand-this-deletes-keys --yes
```

If the wallet directory contains key files, walletd refuses
`--wallets` unless you also pass `--i-understand-this-deletes-keys`
— the long flag exists precisely so that habit + `--yes` can't
accidentally destroy a treasury.

The runtime user, the binary in `/usr/local/bin`, and any
reverse-proxy block in your Caddyfile / nginx config are *not*
touched; uninstall prints the exact commands to clean them up by hand
at the end.

## Next

- [FAQ & troubleshooting →](./faq.md)
