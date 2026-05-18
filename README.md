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
Or build from source (Rust 1.75+):

```bash
cargo build --release
# Binary at target/release/exfer-walletd
```

## Quick start

Fastest path from zero to a running daemon — works against either a
local Exfer node on loopback or any reachable Exfer JSON-RPC URL
(LAN, VPC, public RPC provider).

```bash
# 1. Scaffold env file + wallet dir + fresh read/spend tokens.
#    Omit --node-rpc to default to http://127.0.0.1:9334, or point it
#    at any reachable Exfer JSON-RPC endpoint.
sudo exfer-walletd init --node-rpc http://your-node-host:9334

# 2. Start (reads /etc/exfer-walletd/env)
sudo exfer-walletd
```

For local dev without `sudo`, write the env file under your home dir:

```bash
exfer-walletd init \
    --env-file   ./walletd.env \
    --wallet-dir ./wallets \
    --node-rpc   http://127.0.0.1:9334    # or a remote URL
set -a; . ./walletd.env; set +a
exfer-walletd
```

## Call it

```bash
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $WALLETD_AUTH_TOKEN" \
     -d '{"jsonrpc":"2.0","method":"generate_address","id":1}'
# → {"jsonrpc":"2.0","result":{"address":"…","pubkey":"…"},"id":1}
```

Full method list, error codes, deployment topologies (systemd + Caddy,
docker-compose), security notes, example clients — all on the docs
site: <https://exfer-stack.github.io/exfer-walletd/>

## License

MIT
