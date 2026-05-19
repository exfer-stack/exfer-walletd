# FAQ & troubleshooting

For "where's my token / how do I rotate / how do I bind a public IP"
see [Quick start](./quick-start.md), [Tokens and scopes](./tokens-and-scopes.md),
and [Operations](./operations.md) first.

## `transfer` returns `-32031` but `get_balance` says I have money

The in-flight UTXO tracker. A previous `transfer` from the same
wallet hasn't confirmed yet, and walletd reserved its UTXOs in
memory so the new transfer can't race onto the same outpoints.

The error message has the detail:

```
insufficient balance: need 1100000 exfers (amount + fee), wallet
has 0 spendable across 0 UTXO(s) (1 more UTXO(s) worth 64800000
exfers reserved by pending transfers from this daemon; retry once
they confirm or use a different sending wallet)
```

Wait for the pending tx to confirm, or use a different sender wallet.
TTL on the in-flight claim is 10 minutes; after that, walletd
re-tries the outpoint (and would lose to a mempool double-spend
rejection if the original is still pending).

## I restarted walletd and now `transfer` fails with mempool double-spend

The in-flight tracker is in-memory only. A pre-restart pending tx is
invisible to the fresh process. If `get_address_utxos` on the
upstream still returns the (mempool-spent) UTXO as confirmed, the
fresh walletd will pick it and get rejected.

Wait for the pending tx to confirm — once it's in a block, the spent
UTXO stops appearing. Or: don't restart walletd while transfers are
unconfirmed.

## Why doesn't `get_address_utxos` see my mempool spends?

Common policy across UTXO-chain nodes: `get_address_utxos` returns
the **confirmed** UTXO set, not the mempool view. A mempool-spent
UTXO keeps appearing here until its consuming tx confirms.

This is why walletd has the in-flight tracker — to bridge that gap
locally without depending on a mempool-aware UTXO endpoint upstream.

## Balances look wrong / `get_block_height` is way behind

Almost always: your upstream node isn't fully synced. Walletd
returns whatever the node has — node at height 50k while the chain
is at 580k means balances reflect the 50k view.

The walletd-local methods (`generate_address`, `list_addresses`,
`healthz`, `ping`) are safe to call regardless of node sync state.

## How do I see what walletd is doing?

Daemon logs go to stdout/stderr. Bump verbosity with `RUST_LOG`:

```bash
RUST_LOG=debug,exfer_walletd=trace exfer-walletd
```

Spend-scope requests always emit an audit line at `INFO` with
method, client IP, request id, and outcome.

## Something else?

[Open an issue](https://github.com/exfer-stack/exfer-walletd/issues/new)
with the error message, surrounding log lines (with token values
redacted), and what you were trying to do.
