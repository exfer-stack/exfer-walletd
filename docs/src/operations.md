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
UTXOs, recent blocks, recent transactions). Dashboard reads — most
notably [`list_balances`](./rpc-reference.md#list_balances) — don't
hit upstream per-call.

One flag tunes everything:

```bash
exfer-walletd --cache-profile balanced   # default — manual refresh
exfer-walletd --cache-profile aggressive # auto-poll every 2 s
exfer-walletd --cache-profile off        # pre-0.13 behavior, no caching
```

| | off | balanced (v0.14.0+) | aggressive |
|---|---|---|---|
| Tip TTL | — | 200 ms | 100 ms |
| Balance TTL | — | 30 s | 5 s |
| UTXO TTL | — | 30 s | 5 s |
| Block LRU | — | 1 000 | 5 000 |
| Tx LRU | — | 10 000 | 50 000 |
| Refresh interval | — | **0 (manual)** | 2 s |
| Per-tick concurrency | — | 8 | 16 |
| Max addresses / tick | — | 10 000 | 50 000 |

### Manual vs. automatic refresh (v0.14.0 breaking change)

**v0.14.0 made `balanced` manual-mode by default.** The background
refresher does not auto-poll. Applications drive the cadence via the
[`refresh_address`](./rpc-reference.md#refresh_address) and
[`refresh_addresses`](./rpc-reference.md#refresh_addresses) RPC
methods. Why this is the right primitive at scale: see "The 4N math"
below.

To opt back into the pre-v0.14.0 automatic 5-second polling:

```bash
exfer-walletd --cache-profile balanced --cache-refresh-secs 5
```

`--cache-refresh-secs N` for any `N >= 1` overrides the profile's
default and runs the refresher every N seconds. `0` is explicit
"manual mode" (same as default `balanced`).

### The 4N math — when auto-polling is safe

Automatic polling means the refresher fetches `balance + utxos` for
every managed address on every tick. The per-minute upstream cost is

  `quota_per_minute = 2 × N × (60 / refresh_interval_secs)`

To stay under an upstream's rate limit (call it `Q` per minute), the
unavoidable inequality is

  `refresh_interval_secs >= 2N × 60 / Q  ≈  4N`  (when Q ≈ 30/min)

Concrete numbers for `rpc.exfer.dev`'s 30 balance/utxo per minute:

| N (managed addresses) | min refresh_secs | deposit-detection latency |
|---|---|---|
| 1 | 4 s | ~6 s |
| 5 | 20 s | ~25 s |
| 10 | 40 s | ~50 s |
| 50 | 200 s (~3 min) | ~4 min |
| 100 | 400 s (~7 min) | ~7 min |
| 1 000 | 4 000 s (~67 min) | ~67 min |
| 10 000 | 40 000 s (~11 h) | ~11 h |

At more than a handful of addresses, **auto-polling against shared
public RPCs is impossible** — `balanced`'s manual default is the
only sensible behavior. Three ways out:

1. **Run your own node** — no rate limit, set `--cache-refresh-secs 5`
   and the refresher works as in pre-v0.14.0.
2. **Paid / private RPC** with much higher quota.
3. **Stay in manual mode** (default) and trigger refreshes from the
   application layer when an event actually warrants it (user
   clicked check deposit, internal sweep completed, etc.).

### `GET /cache/stats`

Operator-facing dashboard endpoint. Unauthenticated by design (the
output is non-sensitive). Returns the live cache profile, refresh
interval (0 = manual), current tip view, and per-layer sizes:

```bash
curl -s $URL/cache/stats | jq
```

```json
{
  "profile": "on",
  "refresh_interval_ms": 0,
  "concurrency": 8,
  "tip": { "height": 589912, "block_id": "...", "stale": false, "last_error": null },
  "sizes": { "balance": 12, "utxo_addr": 12, "block_hash": 0, "block_height": 0, "tx": 0 }
}
```

`refresh_interval_ms: 0` is the v0.14.0 default and signals "manual
mode — call `refresh_address` / `refresh_addresses` from the
application." Gate the endpoint at your reverse proxy if you don't
want it exposed publicly.

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
