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
ZFS, your cloud snapshot). Walletd writes `.key` files with
`O_CREAT | O_EXCL` and never modifies in place, so atomic per-file
copies are fine too.

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

Single-token (auto-generated) mode — delete the file and restart:

```bash
rm ~/.exfer-walletd/token
exfer-walletd      # generates + prints a fresh one
```

Two-token mode (`--auth-token-read` / `--auth-token-spend` set) —
walletd ignores `<datadir>/token`, so deleting it does nothing.
Change the env values / CLI flags and restart instead.

Either way, any in-flight request still using the old token will
fail after the restart. Plan the window.

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

## Cache profile

Since v0.13.0 walletd keeps an in-memory cache (per-address balance,
UTXOs, recent blocks, recent transactions) plus a background refresher
so dashboard reads — most notably [`list_balances`](./rpc-reference.md#list_balances)
— don't hit upstream per-call.

One flag tunes everything:

```bash
exfer-walletd --cache-profile balanced   # default
exfer-walletd --cache-profile aggressive # tighter TTLs, more refresher work
exfer-walletd --cache-profile off        # pre-0.13 behavior, no caching
```

| | off | balanced | aggressive |
|---|---|---|---|
| Tip TTL | — | 200 ms | 100 ms |
| Balance TTL | — | 30 s | 5 s |
| UTXO TTL | — | 30 s | 5 s |
| Block LRU | — | 1 000 | 5 000 |
| Tx LRU | — | 10 000 | 50 000 |
| Refresh interval | — | 5 s | 2 s |
| Per-tick concurrency | — | 8 | 16 |
| Max addresses / tick | — | 10 000 | 50 000 |

For deposit-watcher deployments that need fresher-than-default
latency without going to full `aggressive`, override just the refresh
interval:

```bash
exfer-walletd --cache-profile balanced --cache-refresh-secs 2
```

Every other knob stays profile-derived — this is the one parameter
operators actually want to tune in production.

### `GET /cache/stats`

Operator-facing dashboard endpoint. Unauthenticated by design (the
output is non-sensitive). Returns the live cache profile, refresh
interval, current tip view, and per-layer sizes:

```bash
curl -s $URL/cache/stats | jq
```

```json
{
  "profile": "on",
  "refresh_interval_ms": 5000,
  "concurrency": 8,
  "tip": { "height": 589354, "block_id": "f9c8a440...", "stale": false, "last_error": null },
  "sizes": { "balance": 12, "utxo_addr": 12, "block_hash": 0, "block_height": 0, "tx": 0 }
}
```

Gate it at your reverse proxy if you don't want it exposed publicly.

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
