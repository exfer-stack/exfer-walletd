# Picking a node

`exfer-walletd` is decoupled from any specific Exfer node. Anything
that speaks the Exfer JSON-RPC will do. Choose based on what you
already run.

## Same host (most common)

Default. Walletd uses `http://127.0.0.1:9334`. Start the node first,
then walletd — no flags needed.

```bash
# Terminal 1 — an Exfer node with RPC enabled
exfer node --datadir ~/.exfer --rpc-bind 127.0.0.1:9334

# Terminal 2 — walletd
exfer-walletd
```

The walletd → node hop is loopback HTTP, plaintext. That's fine —
loopback never leaves the kernel, no NIC, no wire.

## Different host (LAN, VPC, public RPC)

Pass `--node-rpc` (or set `EXFER_NODE_RPC`). Walletd treats the
upstream like any other HTTP service — no auth, just a URL.

```bash
exfer-walletd --node-rpc https://exfer-rpc.example.com
```

Caveats when the upstream isn't yours:

- The upstream sees every broadcast you submit (**signed bytes only**
  — no keys, no plaintext sensitive data). Treat the choice of RPC
  provider like any other trust decision.
- If the upstream is on the public internet, prefer HTTPS for the
  upstream URL too. Walletd uses `rustls` for outbound HTTPS, no
  extra config needed.
## Multiple nodes (round-robin + failover)

Comma-separate the URLs. Walletd rotates the starting node per call
and falls over to the next on transport / 5xx error. Application-level
errors (`Block not found`) are surfaced immediately without trying
the next node.

```bash
exfer-walletd --node-rpc \
  'http://node-a:9334,http://node-b:9334,https://public-rpc.example.com'
```

Failover only triggers on:

- Connection refused / timeout
- HTTP 5xx
- Response that doesn't decode as JSON-RPC

Failover does **not** trigger on:

- HTTP 4xx (treated as application error)
- JSON-RPC body with `error.code` set (the node knows the answer, it's
  just an error answer — retrying on a different node is unlikely to
  produce a better one and could even be wrong if nodes are out of sync)

## You don't have a node yet

Either:

- Run one with the upstream Exfer CLI (`exfer node --datadir ~/.exfer --rpc-bind 127.0.0.1:9334`).
  This is the right choice for production — you control the trust path.
- Or use a public RPC provider as a stop-gap. You can switch any time
  by restarting walletd with a different `--node-rpc`.

## Latency matters

Walletd's `transfer` makes 3 sequential round-trips to the upstream
plus N parallel parent-tx fetches (where N = number of input UTXOs):

```
list_utxos  ──► upstream                          1 RTT
get_transaction × N (parallel, cap 8)             ⌈N/8⌉ RTTs
send_raw_transaction ──► upstream                 1 RTT
```

Total submit time ≈ `(2 + ⌈N/8⌉) × RTT`.

- Local node (RTT ~5ms): single-UTXO transfer ~15ms
- LAN node (RTT ~50ms): ~150ms
- Public RPC (RTT ~750ms): ~2.3s

For an exchange hot wallet with many small UTXOs, run a local or VPC-
internal node — public RPC will be visibly slow.

## Next

- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
