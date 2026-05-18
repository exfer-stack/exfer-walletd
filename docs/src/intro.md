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
closes that gap — Ed25519 keypair pool, local tx build + sign,
broadcast through whatever node(s) you point it at (loopback, LAN,
VPC, or a third-party public RPC).

One binary, one command:

```bash
exfer-walletd
```

No `init` step, no env file, no systemd unit. Token auto-generated
on first run.

## Where to go from here

- [Install](./install.md) → [Quick start](./quick-start.md) → [RPC reference](./rpc-reference.md) — the shortest path.
- [Picking a node](./picking-a-node.md) — local vs. remote vs. multi-URL.
- [Tokens and scopes](./tokens-and-scopes.md) — single-token default, optional read/spend split, bind safety.
- [Security model](./security-model.md) — what's protected, what's deliberately not.
- [FAQ & troubleshooting](./faq.md) — corners that trip people up.

[github.com/exfer-stack/exfer-walletd](https://github.com/exfer-stack/exfer-walletd) · [Releases](https://github.com/exfer-stack/exfer-walletd/releases) · MIT licensed.
