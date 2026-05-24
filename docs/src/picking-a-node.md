# Picking a node

Walletd is decoupled from any specific Exfer node — anything that
speaks Exfer JSON-RPC works. Pass `--node-rpc` (or `EXFER_NODE_RPC`)
to point at it.

| Use case | Flag |
|---|---|
| Same host (default) | none — uses `http://127.0.0.1:9334` |
| LAN / VPC | `--node-rpc http://node:9334` |
| Public RPC | `--node-rpc https://exfer-rpc.example.com` |
| Multiple nodes | `--node-rpc 'http://a:9334,http://b:9334'` (round-robin + failover) |

The walletd → node hop carries **signed bytes only** — no private
keys. Walletd treats the upstream like any other HTTP service; no
upstream auth. Prefer HTTPS for upstreams outside your trust
boundary (`rustls` handles this transparently).

## Multi-URL failover

Walletd rotates the starting node per call and fails over to the next
on transport / 5xx error. Application-level errors (`Block not found`,
etc.) are surfaced immediately — retrying on a different node could
even be wrong if nodes are out of sync.

| Triggers failover | Does NOT trigger failover |
|---|---|
| Connection refused / timeout | HTTP 4xx |
| HTTP 5xx | JSON-RPC body with `error.code` set |
| Non-JSON-RPC response body | — |

## Latency math (why local nodes matter)

Walletd's `transfer` makes 2 sequential round-trips, regardless of how
many input UTXOs the tx consumes:

```
list_utxos                                    1 RTT
send_raw_transaction                          1 RTT
```

Submit time ≈ `2 × RTT`.

- Local node (RTT ~5ms): ~10ms
- LAN node (RTT ~50ms): ~100ms
- Public RPC (RTT ~750ms): ~1.5s

Input count doesn't enter the latency budget: walletd trusts the
`value` reported by `get_address_utxos` and does not pre-fetch each
funding tx. A node that returns wrong values can only cause the
broadcast to fail consensus — funds stay safe.

## Next

- [Tokens and scopes →](./tokens-and-scopes.md)
- [RPC reference →](./rpc-reference.md)
