# exfer-walletd

A JSON-RPC HTTP daemon that holds wallet keys and signs Exfer
transactions on behalf of a backend. Same pattern as
[`cardano-wallet`](https://github.com/cardano-foundation/cardano-wallet)
for Cardano: a separate signing service, decoupled from the chain node.

```
your backend ──► exfer-walletd ──► exfer node(s)
                 (holds keys,        (chain data, p2p,
                  signs locally)      broadcast — no keys)
```

The Exfer node's own JSON-RPC is intentionally read-only + broadcast:
it can't sign for you because nodes never hold keys. `exfer-walletd`
closes that gap. It manages a pool of Ed25519 keypairs, builds and
signs transactions locally, and broadcasts the signed bytes through
whatever node(s) you point it at — your own node on loopback, a node
on your LAN/VPC, or a third-party public RPC endpoint.

## Why this exists

The Exfer node was deliberately built without a wallet RPC: it doesn't
know what addresses are yours, doesn't hold keys, and won't sign for
you. That's a good default — it means the consensus layer never sees
a private key — but it leaves every integrator (exchange, payment
processor, custodian) reimplementing the same flow:
list UTXOs → build tx → Ed25519 sign → broadcast.

`exfer-walletd` is the canonical implementation of that flow, exposed
as an RPC service that's drop-in usable from any backend language.

## What this isn't

- **Not a custody solution.** Keys live on disk as plain Ed25519
  secret-bytes (mode `0600`). The threat model is "encrypted volume
  + filesystem permissions", not HSM. If you need HSM or MPC, plug a
  different `WalletStore` implementation in — the trait is small.
- **Not multi-tenant.** Any holder of the spend token can spend any
  wallet the daemon manages. For per-user authorisation, you sit a
  thin policy layer in front of walletd or run one daemon per tenant.
- **Not a node.** Walletd does not validate the chain, gossip blocks,
  or hold UTXO state for the world. It uses the upstream node for all
  of that — it's a "wallet" in the strict sense.

## How to read these docs

The shortest path:

1. [Install](./install.md) — one binary.
2. [Quick start](./quick-start.md) — `init` + run, two commands.
3. [RPC reference](./rpc-reference.md) — each method with params,
   returns, curl example.

If you're standing up a production deployment:

- [Picking a node](./picking-a-node.md) — local vs. remote vs. HA.
- [Production deploy](./production-deploy.md) — systemd + Caddy on
  a single VM.
- [Security model](./security-model.md) — what's protected and what
  isn't.

If something doesn't behave the way you expected:

- [Error codes](./errors.md) — every JSON-RPC code and what it means.
- [FAQ & troubleshooting](./faq.md) — the corners that trip people up.

## Source

[github.com/exfer-stack/exfer-walletd](https://github.com/exfer-stack/exfer-walletd) · [Releases](https://github.com/exfer-stack/exfer-walletd/releases) · MIT licensed.
