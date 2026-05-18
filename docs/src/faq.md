# FAQ & troubleshooting

## "Where's my token?"

```bash
cat ~/.exfer-walletd/token
```

That file is auto-generated on first run, mode `0600`, owned by
whichever user ran walletd. Override location with `--datadir`.

## "I deleted the token file by mistake"

Restart walletd. It generates and prints a fresh one. Any client
using the old token starts getting `401` immediately — update them.

## "The daemon won't bind 0.0.0.0:8080"

By design. See [Tokens and scopes → Bind safety](./tokens-and-scopes.md#bind-safety).
Either bind loopback (default), bind a private/internal IP, or set
`--allow-public-bind` to acknowledge that a TLS terminator is in front
of walletd.

## "My backend on a different server can't reach walletd"

Walletd defaults to `127.0.0.1:8080` (loopback only). Bind a
private/internal IP:

```bash
exfer-walletd --bind 10.0.1.5:8080
```

Then on the backend host, `curl http://10.0.1.5:8080/healthz` should
return `ok`. If it doesn't, check firewall / security group / cloud
network ACLs.

## "I'm seeing `-32020 upstream node unreachable` intermittently"

The walletd → upstream hop has no retry within a single URL. If
you're talking to a flaky public RPC, add a second URL:

```bash
EXFER_NODE_RPC=http://primary:9334,http://backup:9334 exfer-walletd
```

Walletd fails over to the next URL on transport errors. Application-
level errors (`-32xxx` in the body) are surfaced immediately without
retrying — those are not transport failures.

## "`transfer` returns `-32031` but `get_balance` says I have money"

The in-flight UTXO tracker. A previous `transfer` from the same
wallet hasn't confirmed yet, and walletd reserved its UTXOs in
memory so the new transfer can't race onto the same outpoints.

The error message has more detail:

```
insufficient balance: need 1100000 exfers (amount + fee), wallet
has 0 spendable across 0 UTXO(s) (1 more UTXO(s) worth 64800000
exfers reserved by pending transfers from this daemon; retry once
they confirm or use a different sending wallet)
```

Wait for the pending tx to confirm, or use a different sender wallet.
The TTL on the in-flight claim is 10 minutes — after that, walletd
re-tries selecting the outpoint (and would lose to a mempool
double-spend rejection if the original tx is still pending).

## "I restarted walletd and now `transfer` fails with mempool double-spend"

The in-flight tracker is **in-memory only**. A pre-restart pending
tx is invisible to the fresh process. If `get_address_utxos` on the
upstream still returns the (mempool-spent) UTXO as confirmed, the
fresh walletd will pick it and get rejected.

Workarounds:

- Wait for the pending tx to confirm. Once it's in a block,
  `get_address_utxos` stops returning the spent UTXO.
- Don't restart walletd while pending transfers are still
  unconfirmed.

## "Why doesn't the upstream's `get_address_utxos` see my mempool spends?"

It's a common policy across UTXO-chain nodes: `get_address_utxos`
returns the **confirmed UTXO set**, not the mempool view. A
mempool-spent UTXO will keep showing up here until its consuming tx
confirms.

This is why walletd has the in-flight tracker — to bridge that gap
locally without depending on a mempool-aware UTXO endpoint upstream.

## "Can I run two walletd processes against the same datadir?"

Technically yes — the on-disk format tolerates concurrent readers,
and key generation uses `O_CREAT | O_EXCL` so two `generate_address`
calls can't collide.

But: the in-flight UTXO tracker is per-process. Two walletds against
the same datadir can race onto the same outpoint. Don't.

## "Balances look wrong / `get_block_height` is way behind"

Almost always: your upstream node isn't fully synced yet. Walletd
returns whatever the node has locally — if the node is at height 50k
and the chain is at 580k, balances reflect the 50k view. Wait for the
node to catch up, then retry.

`generate_address` is always safe to call (no chain dependency).

## How do I see what walletd is doing?

Daemon logs go to stdout/stderr. Bump verbosity with `RUST_LOG`:

```bash
RUST_LOG=debug,exfer_walletd=trace exfer-walletd
```

Spend-scope requests always emit a structured audit line at `INFO`
level with method, client IP, request id, and outcome.

## Something else?

[Open an issue](https://github.com/exfer-stack/exfer-walletd/issues/new)
with the error message, the daemon log lines around it (with token
values redacted), and what you were trying to do.
