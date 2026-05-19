# exfer-walletd

[![CI](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml/badge.svg)](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Exfer Wallet Daemon** — an independent HTTP service that manages
wallet keypairs and exposes higher-level RPC methods
(`generate_address`, `transfer`, `balance`, `list_balances`, …) on
top of one or more [Exfer](https://exfer.org/) nodes. Built-in
five-layer cache + background refresher means dashboard reads
(`list_balances` over N addresses) cost one local call regardless of N.

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
exfer-walletd --tls \
    --node-rpc http://<your-node-host>:<port> \
    --bind     <walletd-host-internal-ip>:7448
```

On first run, walletd creates `~/.exfer-walletd/` (mode `0700`),
generates a 32-byte bearer token at `~/.exfer-walletd/token`
(mode `0600`), and — with `--tls` — a self-signed cert trio
(`cert.pem`, `cert.key`, `cert.fingerprint`). The token and the
cert fingerprint are each printed once to stderr; copy both to the
backend side. The SDK pins by fingerprint, no CA needed.

**Dev shortcut**: if node, walletd, and the caller are all on one
host, every flag has a sensible default and `exfer-walletd` with no
args just works (defaults: `--bind 127.0.0.1:7448`, `--node-rpc
http://127.0.0.1:9334`, plain HTTP since loopback-only).

Public/non-loopback binds without `--tls` fail-close at startup; if
an external TLS terminator (nginx, Caddy, cloud LB) already sits in
front, pass `--allow-public-bind`.

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -s https://<walletd-host>:7448/ \
     --cacert /etc/walletd/cert.pem \
     -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
# → {"jsonrpc":"2.0","result":{"address":"…","pubkey":"…"},"id":1}
```

Loopback-only dev: drop `--tls`, use `http://127.0.0.1:7448` and skip
`--cacert`.

Full method list, error codes, security notes, example clients —
all on the docs site: <https://exfer-stack.github.io/exfer-walletd/>

## License

MIT
