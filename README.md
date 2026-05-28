# exfer-walletd

[![CI](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml/badge.svg)](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Exfer Wallet Daemon** — an independent HTTP service that manages
wallet keypairs and exposes higher-level RPC methods
(`generate_address`, `transfer`, `balance`, …) on top of one or more
[Exfer](https://exfer.org/) nodes.

> **v1.x release line.** Multi-output `transfer` with `fee_rate` +
> `max_fee` + idempotency keys; BIP-39 HD seed encrypted at rest with
> argon2id + ChaCha20-Poly1305; three scoped tokens (`read` /
> `manage` / `spend`); JSON-RPC 2.0 batch support; spec-correct
> `-32700` / `-32600` / `-32602` boundaries.
>
> **v1.9 adds HTLC observability.** A background block follower
> indexes every HTLC paying any owned key; new methods `htlc_status`
> / `htlc_list` / `htlc_forget` / `get_follower_status` expose the
> lifecycle, `wait_for_tx` async-waits for confirmations off the
> follower's tip channel, `simulate_transfer` / `simulate_htlc_lock`
> answer "what would this cost?" without broadcasting, and
> `payment_uri_encode` / `_decode` round-trip a BIP21-style
> `exfer:<address>?amount=...` string.

Same pattern as
[`cardano-wallet`](https://github.com/cardano-foundation/cardano-wallet)
for Cardano: a separate signing daemon, decoupled from the chain node.
Keys never leave the daemon's host; the node never sees a private key.

Docs, API reference, examples →
<https://exfer-stack.github.io/exfer-walletd/>

## Install

Pre-built binaries (Linux / macOS / Windows) on the
[Releases](https://github.com/exfer-stack/exfer-walletd/releases) page.
Or build from source (Rust 1.75+):

```bash
cargo build --release
# Binary at target/release/exfer-walletd
```

## Run

For most deployments — node, walletd, and backend on different hosts —
turn on TLS so the bearer token isn't on plaintext wire:

```bash
export WALLETD_KEYSTORE_PASSPHRASE='whatever-your-secret-manager-provides'
exfer-walletd --tls \
    --node-rpc http://<your-node-host>:<port> \
    --bind     <walletd-host-internal-ip>:7448
```

`WALLETD_KEYSTORE_PASSPHRASE` is **required** — walletd encrypts the
HD seed at rest and refuses to start without it.

On first run, walletd creates `~/.exfer-walletd/` (mode `0700`),
generates a 24-word BIP-39 mnemonic and a sealed HD seed
(`wallets/seed.enc`), three scoped bearer tokens
(`token-{read,manage,spend}`, mode `0600`), and — with `--tls` — a
self-signed cert trio (`cert.pem`, `cert.key`, `cert.fingerprint`).
The mnemonic, every token, and the cert fingerprint are each printed
once to stderr; capture the mnemonic offline (paper / password
manager) — it is the only seed backup.

**Dev shortcut**: if node, walletd, and the caller are all on one
host, every flag has a sensible default and `exfer-walletd` with no
args just works (defaults: `--bind 127.0.0.1:7448`, `--node-rpc
http://127.0.0.1:9334`, plain HTTP since loopback-only).

Public/non-loopback binds without `--tls` fail-close at startup; if
an external TLS terminator (nginx, Caddy, cloud LB) already sits in
front, pass `--allow-public-bind`.

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token-manage)
curl -s https://<walletd-host>:7448/ \
     --cacert /etc/walletd/cert.pem \
     -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
# → {"jsonrpc":"2.0","result":{"address":"…","pubkey":"…","index":0},"id":1}
```

Loopback-only dev: drop `--tls`, use `http://127.0.0.1:7448` and skip
`--cacert`.

Full method list, error codes, security notes, example clients —
all on the docs site: <https://exfer-stack.github.io/exfer-walletd/>

## License

MIT
