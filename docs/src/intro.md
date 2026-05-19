# exfer-walletd

A JSON-RPC daemon that holds Ed25519 wallet keys and signs Exfer
transactions on behalf of a backend. Same pattern as
[`cardano-wallet`](https://github.com/cardano-foundation/cardano-wallet)
for Cardano — a separate signing service, decoupled from the chain
node.

```
your backend ──► exfer-walletd ──► exfer node(s)
                 (holds keys,        (chain data, p2p,
                  signs locally)      broadcast — no keys)
```

The Exfer node's JSON-RPC is read-only + broadcast; it can't sign,
because nodes don't hold keys. Walletd closes that gap.

One binary, zero ceremony:

```bash
exfer-walletd
```

Token auto-generated on first run. Wallets persisted under
`~/.exfer-walletd/`. Optional in-process TLS via `--tls` (the SDK
pins by SHA-256 fingerprint, no CA required).

## Read next

[Install](./install.md) → [Quick start](./quick-start.md) →
[RPC reference](./rpc-reference.md). Everything else
([picking a node](./picking-a-node.md),
[tokens](./tokens-and-scopes.md),
[security](./security-model.md),
[operations](./operations.md),
[FAQ](./faq.md))
is for when something is unclear or you're going to production.

[github.com/exfer-stack/exfer-walletd](https://github.com/exfer-stack/exfer-walletd)
· [Releases](https://github.com/exfer-stack/exfer-walletd/releases)
· MIT licensed.
