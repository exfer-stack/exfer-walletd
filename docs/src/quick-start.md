# Quick start

```bash
exfer-walletd
```

That's it. On first run, walletd creates `~/.exfer-walletd/` (mode
`0700`), generates a 32-byte bearer token at `~/.exfer-walletd/token`
(mode `0600`) and **prints it once** to stderr, then serves JSON-RPC
on `127.0.0.1:8080` against `http://127.0.0.1:9334` upstream.

If you ever need the token again: `cat ~/.exfer-walletd/token`.

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -s http://127.0.0.1:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

Full method list: [RPC reference](./rpc-reference.md).

## Common overrides

```bash
exfer-walletd --node-rpc https://exfer-rpc.example.com   # remote node
exfer-walletd --bind 10.0.1.5:8080                       # private/internal IP
exfer-walletd --datadir /var/lib/walletd                 # different storage
```

Every flag also reads from a matching env var (`EXFER_NODE_RPC`,
`WALLETD_BIND`, `WALLETD_DATADIR`, …). Full list: `exfer-walletd --help`.

Two safety rails worth knowing:

- **Public bind requires `--allow-public-bind`.** Loopback and
  private/RFC1918 IPs are allowed without it. `0.0.0.0` or a globally
  routable IP fail-close unless you opt in — see
  [Tokens and scopes → Bind safety](./tokens-and-scopes.md#bind-safety).
- **Walletd is a single foreground binary.** No systemd unit, no env
  file, no install ceremony. Wire it up under whatever supervisor you
  already use (tmux / systemd / supervisord / docker / k8s).

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
