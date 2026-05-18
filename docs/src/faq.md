# FAQ & troubleshooting

## "The env vars I loaded with `set -a; . ./walletd.env; set +a` disappeared"

That command exports them into the **current shell** only. Each new
terminal / `tmux` pane / SSH session starts with a clean environment.

Options:

- Re-source the env file in each new shell: `set -a; . ./walletd.env; set +a`.
- For local dev only, add the source line to `~/.bashrc` or `~/.zshrc`
  — but remember `.env` may contain tokens, so don't commit any
  shell-rc that sources it from a world-readable path.
- For production, use systemd's `EnvironmentFile=` — which is what
  our shipped systemd unit does. No shell sourcing needed; the
  daemon receives the env vars directly.

## `init` printed the wrong "Next steps" for my path

If `--env-file` points to a system path (`/etc`, `/var`, `/usr`,
`/opt`), `init` prints the systemd-flow next-steps. Anywhere else
(your home dir, a relative path) you get the simpler local-dev
flow. If the heuristic guessed wrong, just ignore the printed steps
— the env file content is correct either way.

## "Tokens (also stored in the env file): TOKEN ..." is printed to my terminal

That's `init` showing you the freshly-generated token once so you
can copy it into your client app. The output goes to **stderr** so
it's not captured by `command-sub $()` pipelines, but it does land
in terminal scrollback. If that's a concern, either:

- Use `--print` mode — env contents go to stdout, you redirect or
  pipe to a vault tool.
- Generate tokens out-of-band and write your own env file.

## "I'm seeing `-32020 upstream node unreachable` intermittently"

The walletd → upstream hop has no retry within a single URL. If
you're talking to a flaky public RPC, add a second URL:

```bash
EXFER_NODE_RPC=http://primary:9334,http://backup:9334
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

## "Can I run two walletd processes against the same wallet directory?"

Technically yes — the on-disk format tolerates concurrent readers,
and key generation uses `O_CREAT | O_EXCL` so two `generate_address`
calls can't collide.

But: the in-flight UTXO tracker is per-process. Two walletds against
the same wallet directory can race onto the same outpoint. Don't.

## "`exfer-walletd` exits immediately after `init`"

`init` only writes the env file and creates the wallet directory.
It does **not** start the daemon. Run `exfer-walletd` (with env
loaded) to actually start the server.

## "The daemon won't bind 0.0.0.0:8080"

By design. See [Tokens and scopes → Bind safety](./tokens-and-scopes.md#bind-safety).
Either bind loopback (default), or set
`WALLETD_ALLOW_PUBLIC_BIND=1` to acknowledge that a TLS terminator
is in front of walletd.

## How do I see what walletd is doing?

Daemon logs go to stdout/stderr by default; systemd captures them.

```bash
sudo journalctl -u exfer-walletd -f
```

Bump verbosity by changing `RUST_LOG` in the env file:

```
RUST_LOG=debug,exfer_walletd=trace
```

Spend-scope requests always emit a structured audit line at `INFO`
level with method, client IP, request id, and outcome.

## Something else?

[Open an issue](https://github.com/exfer-stack/exfer-walletd/issues/new)
with the error message, the daemon log lines around it (with token
values redacted), and what you were trying to do.
