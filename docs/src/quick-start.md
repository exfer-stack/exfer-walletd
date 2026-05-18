# Quick start

For most real deployments — node, walletd, and backend on different
hosts — you'll set two flags:

```bash
exfer-walletd \
    --node-rpc http://<your-node-host>:<port> \
    --bind     <walletd-host-internal-ip>:8080
```

- `--node-rpc` — the upstream Exfer node's JSON-RPC URL. The default
  (`http://127.0.0.1:9334`) only works if a node is running on the
  same host on that exact port.
- `--bind` — the address walletd listens on. The default
  (`127.0.0.1:8080`) is loopback-only, so a backend on a different
  server can't reach it. Use the walletd host's private/internal IP.
  Private/RFC1918 addresses are allowed without any extra flag;
  public IPs require `--allow-public-bind` (and a TLS terminator).

On first run, walletd creates `~/.exfer-walletd/` (mode `0700`),
generates a 32-byte bearer token at `~/.exfer-walletd/token` (mode
`0600`) and **prints it once** to stderr, then starts serving JSON-RPC.

If you ever need the token again: `cat ~/.exfer-walletd/token`.

## Dev shortcut

If node, walletd, and the caller are all on one host (laptop dev,
single-VM smoke test), every flag has a sensible default and you can
just run:

```bash
exfer-walletd
```

(Defaults: `--bind 127.0.0.1:8080`, `--node-rpc http://127.0.0.1:9334`,
`--datadir ~/.exfer-walletd`.)

## Call it

```bash
TOKEN=$(cat ~/.exfer-walletd/token)
curl -s http://<walletd-host>:8080/ -H 'content-type: application/json' \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
# → {"jsonrpc":"2.0","result":{"ok":true},"id":1}
```

Full method list: [RPC reference](./rpc-reference.md).

## Other useful flags

```bash
exfer-walletd --node-rpc 'http://a:9334,http://b:9334'  # round-robin + failover
exfer-walletd --datadir  /var/lib/walletd               # different storage location
exfer-walletd --allow-public-bind --bind 0.0.0.0:8080   # public bind (TLS in front!)
```

Every flag also reads from a matching env var (`EXFER_NODE_RPC`,
`WALLETD_BIND`, `WALLETD_DATADIR`, …). Full list:
`exfer-walletd --help`.

## Running on boot

Walletd is a single foreground binary — no systemd unit, no env
file, no install ceremony. Wire it up under whatever supervisor you
already use (tmux / systemd / supervisord / docker / k8s).

## Next

- [Picking a node →](./picking-a-node.md)
- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
