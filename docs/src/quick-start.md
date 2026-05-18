# Quick start

One command:

```bash
exfer-walletd
```

That's it. On first run, walletd:

1. Creates `~/.exfer-walletd/` (mode `0700`) for state.
2. Generates a 32-byte bearer token, saves it to
   `~/.exfer-walletd/token` (mode `0600`), and **prints it once** to
   stderr so you can copy it into your backend.
3. Binds `127.0.0.1:8080` and starts serving JSON-RPC.

What you'll see on first launch:

```
  ┌─ first run ───────────────────────────────────────────────────────────
  │ generated bearer token (saved to ~/.exfer-walletd/token):
  │
  │     f88ed61ed82b64d13d331e511fdefc2cacbfb344fff39204c7a5e24cfe872962
  │
  │ use as:  Authorization: Bearer f88ed61ed82b64d13d331e511fdefc2cacbfb344fff39204c7a5e24cfe872962
  └───────────────────────────────────────────────────────────────────────

  INFO exfer-walletd starting bind=127.0.0.1:8080 node_rpc=http://127.0.0.1:9334 …
```

Subsequent runs read the token silently from the file. If you lose
it, `cat ~/.exfer-walletd/token`.

## Hit the API

From any shell on the same host:

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

Full method list: [RPC reference](./rpc-reference.md).

## Pointing at a different node

Defaults to `http://127.0.0.1:9334` (a local Exfer node). Override with
`--node-rpc` or `EXFER_NODE_RPC`:

```bash
# remote / public RPC
exfer-walletd --node-rpc https://exfer-rpc.example.com

# multiple URLs, round-robin + failover
exfer-walletd --node-rpc 'http://node-a:9334,http://node-b:9334'
```

See [Picking a node](./picking-a-node.md) for the trade-offs.

## Reaching it from another host

By default walletd binds loopback only — your backend on a different
server **can't reach it**. Bind to the host's **private/internal IP**:

```bash
exfer-walletd --bind 10.0.1.5:8080      # walletd host's internal IP
```

Private/RFC1918 addresses are allowed without any extra flag.

Public IPs (`0.0.0.0`, any globally-routable IP) are refused at startup
unless you also pass `--allow-public-bind`. The opt-in is your
acknowledgement that "a TLS terminator (Caddy / nginx / cloud LB) sits
in front of me" — without TLS, the bearer token rides the wire as
plaintext. See [Tokens and scopes → Bind safety](./tokens-and-scopes.md#bind-safety).

## Running on boot

Walletd is a single foreground binary. Wire it up however you'd wire
up any other long-running process:

- `tmux` / `screen` for a quick always-on session.
- `systemd --user` or a system-wide unit (`ExecStart=/usr/local/bin/exfer-walletd`).
- A process supervisor (`supervisord`, `s6`, `runit`).
- Your container orchestrator (`docker run`, `kubectl run …`).

There's no opinionated "install" path beyond "put the binary
somewhere and run it." The daemon needs no root, no system user, no
env file — just a writable `--datadir`.

## All flags (each one optional)

| Flag                       | Default                       | Effect                                                       |
| -------------------------- | ----------------------------- | ------------------------------------------------------------ |
| `--datadir`                | `$HOME/.exfer-walletd`        | Where to keep state (`token` + `wallets/`).                  |
| `--bind`                   | `127.0.0.1:8080`              | HTTP listen address.                                         |
| `--node-rpc`               | `http://127.0.0.1:9334`       | Upstream Exfer JSON-RPC. Comma-separate for failover.        |
| `--allow-public-bind`      | off                           | Required to bind a public IP. See bind-safety section.       |
| `--wallet-dir`             | `<datadir>/wallets`           | Override wallet storage location.                            |
| `--auth-token`             | auto-generated in `<datadir>/token` | Use this exact token instead of the file.              |
| `--auth-token-read`        | unset                         | Optional read-scope token (for the split-token model).       |
| `--auth-token-spend`       | unset                         | Optional spend-scope token (for the split-token model).      |
| `--upstream-timeout-secs`  | `30`                          | HTTP timeout for walletd → node calls.                       |

Every flag also reads from the matching env var (`WALLETD_DATADIR`,
`WALLETD_BIND`, `EXFER_NODE_RPC`, …).

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
