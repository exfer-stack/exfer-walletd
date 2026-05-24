# Backup, upgrade, rotate

## Backup

Back up `~/.exfer-walletd/wallets/`. Losing it = losing every key =
losing every penny those addresses hold.

```bash
# Stop walletd briefly for a consistent snapshot, then:
tar -C ~ -czf wallets-$(date +%F).tar.gz .exfer-walletd

# Encrypt before shipping off-box
gpg --symmetric --cipher-algo AES256 wallets-$(date +%F).tar.gz
```

If you can't stop the daemon, snapshot the underlying volume (LVM,
ZFS, your cloud snapshot). Walletd writes `seed.enc`, `state.json`,
and `imported/*.key.enc` atomically (write-to-`.tmp` + rename), so
per-file copies during a quiet moment are fine too.

The 24-word mnemonic printed on first run is the canonical backup
of the HD seed — keep it offline. With the mnemonic you can rederive
every HD address; only the `imported/` directory holds non-HD
secrets that are not recoverable from the mnemonic.

## Upgrade

Semver. Patches and minors are drop-in; majors will be called out in
release notes.

```bash
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
# restart walletd via whatever supervisor you use
```

The `<datadir>` format is stable — any version can load any wallet
file written by any other version.

## Rotate tokens

Auto-generated mode — delete the file(s) for the scope(s) you want
to rotate and restart:

```bash
rm ~/.exfer-walletd/token-spend          # one scope
# or:
rm ~/.exfer-walletd/token-{read,manage,spend}   # all three
exfer-walletd      # regenerates + prints whatever's missing
```

Externally-supplied mode (any of `--auth-token-{read,manage,spend}`
or `WALLETD_AUTH_TOKEN_{READ,MANAGE,SPEND}` set) — walletd ignores
the on-disk file for that scope, so deleting it does nothing. Change
the env / CLI value and restart instead.

Any in-flight request still using the old token will fail after the
restart. Plan the window.

## Rotate the TLS cert

Same idea — delete the trio and restart:

```bash
rm ~/.exfer-walletd/cert.{pem,key,fingerprint}
exfer-walletd --tls    # generates a fresh cert + prints the new fingerprint
```

Clients pinning the old fingerprint will start raising
`FingerprintMismatchError` on the next request. Push the new
fingerprint to them before restarting if you can't tolerate the
window.

## Running under systemd

Minimal hardened unit. Adjust `User`, `WALLETD_DATADIR`, and flags
for your environment.

```ini
# /etc/systemd/system/exfer-walletd.service
[Unit]
Description=Exfer Wallet Daemon
After=network-online.target
Wants=network-online.target

[Service]
User=walletd
Group=walletd
Environment=WALLETD_DATADIR=/var/lib/walletd
Environment=EXFER_NODE_RPC=http://127.0.0.1:9334
ExecStart=/usr/local/bin/exfer-walletd --tls --bind 10.0.1.5:7448
Restart=on-failure
RestartSec=2s

# Hardening — walletd never needs anything outside its datadir.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/walletd
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --home /var/lib/walletd --shell /usr/sbin/nologin walletd
sudo install -d -o walletd -g walletd -m 0700 /var/lib/walletd
sudo systemctl daemon-reload
sudo systemctl enable --now exfer-walletd
journalctl -u exfer-walletd -f      # first-run token + fingerprint print here
```

For Kubernetes: same idea, but mount the datadir as a
`PersistentVolume` (token + wallet keys must persist across pod
restarts), set `runAsUser` to a non-root UID, and add a `readinessProbe`
hitting `GET /healthz`.

## Uninstall

No ceremony — walletd doesn't touch anything outside its `--datadir`.

```bash
# Stop the daemon, then:
rm -rf ~/.exfer-walletd     # tokens + wallets + certs — IRREVERSIBLE
sudo rm /usr/local/bin/exfer-walletd
```

If you back up `~/.exfer-walletd/wallets/` first, you can restore the
same address set later by dropping the directory back into place.

## Next

- [FAQ & troubleshooting →](./faq.md)
