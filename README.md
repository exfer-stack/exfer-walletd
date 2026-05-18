# exfer-walletd

[![CI](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml/badge.svg)](https://github.com/exfer-stack/exfer-walletd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Exfer Wallet Daemon** — an independent HTTP service that manages
wallet keypairs and exposes higher-level RPC methods
(`generate_address`, `transfer`, `balance`, …) on top of one or more
[Exfer](https://exfer.org/) nodes.

Same architectural pattern as
[`cardano-wallet`](https://github.com/cardano-foundation/cardano-wallet)
for Cardano: a separate signing daemon, decoupled from the chain node.
Keys never leave the daemon's host; the node never sees a private key.

Docs, API reference, examples →
<https://exfer-stack.github.io/exfer-walletd/>

## Install

Pre-built binaries (Linux / macOS / Windows) on the
[Releases](https://github.com/exfer-stack/exfer-walletd/releases) page.
Or build from source:

```bash
cargo build --release
```

## Run

```bash
exfer-walletd \
    --bind        0.0.0.0:8080 \
    --node-rpc    http://127.0.0.1:9334 \
    --wallet-dir  /var/lib/exfer-wallets \
    --auth-token  "$(openssl rand -hex 32)"
```

## Call it

```bash
curl -s http://localhost:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
# → {"jsonrpc":"2.0","result":{"address":"…","pubkey":"…"},"id":1}
```

Full method list, error codes, deployment topologies, security notes,
example clients — all on the docs site:
<https://exfer-stack.github.io/exfer-walletd/>

## License

MIT
