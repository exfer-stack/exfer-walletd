# Quick start

`exfer-walletd init` scaffolds an env file (with a fresh CSPRNG token),
creates the wallet directory, and prints the remaining steps. The
daemon then starts with **zero CLI flags** — all configuration comes
from the env file. This is the recommended path for both first-time
tries and production.

## Local dev (no sudo)

For trying it from your laptop without touching `/etc` or `/var/lib`.
The daemon refuses to bind a non-loopback interface without an
explicit opt-in, so loopback dev is safe by construction.

```bash
exfer-walletd init \
    --env-file   ./walletd.env \
    --wallet-dir ./wallets \
    --node-rpc   http://127.0.0.1:9334    # see "Picking a node"
```

`init` prints something like:

```
  wrote    ./walletd.env
  created  ./wallets

Tokens (also stored in the env file):
  TOKEN  fd096802e4d9061a3d8b7411fe168c663a81831cf906350dd78e00a05f790408

Next steps (local dev):
  1. Load the env into your shell:
       set -a; . ./walletd.env; set +a
  2. Start the daemon:
       exfer-walletd
```

Follow those:

```bash
set -a; . ./walletd.env; set +a   # exports tokens + bind + node URL
exfer-walletd                      # picks up everything from env
```

Then try it from another terminal — **but first**, that shell does not
share the env you just loaded; either load it again or pass the token
directly:

```bash
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer <paste-token>" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

The env file is mode `0600` and contains your tokens — don't commit it.

## System-wide (systemd)

See [Production deploy → systemd + Caddy](./production-deploy.md#recipe-a---systemd--caddy-on-a-single-vm-most-common).
The first step there is the same `init`, but writing to
`/etc/exfer-walletd/env` and `/var/lib/exfer-walletd`. When `init`
sees a system path (`/etc`, `/var`, `/usr`, `/opt`), the printed
next-steps automatically switch to the systemd recipe.

## `init` flag reference

| Flag             | Default                      | Effect                                                              |
| ---------------- | ---------------------------- | ------------------------------------------------------------------- |
| `--env-file`     | `/etc/exfer-walletd/env`     | Where to write the env file. Mode `0600`.                           |
| `--wallet-dir`   | `/var/lib/exfer-walletd`     | Wallet directory. Created mode `0700`.                              |
| `--bind`         | `127.0.0.1:8080`             | Recorded as `WALLETD_BIND` in the env file.                         |
| `--node-rpc`     | `http://127.0.0.1:9334`      | Recorded as `EXFER_NODE_RPC`. Comma-separated for HA.               |
| `--scoped`       | off                          | Generate two tokens (read + spend) instead of one all-scope token.  |
| `--print`        | off                          | Print env body to stdout instead of writing a file (vault flows).   |
| `--force`        | off                          | Overwrite an existing env file. Off by default — re-runs are safe.  |

`init` is **idempotent**: a pre-existing env file is left alone so a
re-run can't silently rotate tokens that are in use. `--force` to
deliberately regenerate.

## Two-token mode (`--scoped`)

By default `init` emits a single `WALLETD_AUTH_TOKEN` that grants every
method. If you want to split deposit-watch from withdrawal-spend
(so a leaked read-only token can't move funds):

```bash
exfer-walletd init --scoped --node-rpc http://127.0.0.1:9334
```

Output gains a second token, env file gains a second variable:

```
Tokens (also stored in the env file):
  READ   ab2deff010d70a5bdb564b2acf62e4ed994bc097a27cc6a75be1c0b626c2b920
  SPEND  a76be2c162732728704c579317d75b58c3efa7135e3a3b570ee25f7ab88b1189
```

```bash
WALLETD_AUTH_TOKEN_READ=...
WALLETD_AUTH_TOKEN_SPEND=...
```

See [Tokens and scopes](./tokens-and-scopes.md) for details on what
each scope can do.

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
