# Production deploy

Two recipes. Pick the one that matches your environment.

## Recipe A — systemd + Caddy on a single VM (most common)

A single host running walletd (with the Exfer node either on the same
host or somewhere reachable), Caddy terminating TLS and reverse-
proxying to walletd on loopback.

Files used: [`deploy/systemd/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/systemd)
and [`deploy/caddy/`](https://github.com/exfer-stack/exfer-walletd/tree/main/deploy/caddy).

### 1. Install the binary

```bash
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
```

### 2. Run `init`

```bash
sudo exfer-walletd init --node-rpc http://your-node-host:9334
```

`init` writes `/etc/exfer-walletd/env` (mode `0600`) and creates
`/var/lib/exfer-walletd` (mode `0700`). Because the env path is a
system location, the printed next-steps automatically include the
systemd flow.

### 3. Create the runtime user

```bash
sudo useradd --system --home /var/lib/exfer-walletd --shell /usr/sbin/nologin exfer-walletd
sudo chown -R exfer-walletd:exfer-walletd /var/lib/exfer-walletd
sudo chown root:exfer-walletd /etc/exfer-walletd/env
sudo chmod 0640 /etc/exfer-walletd/env
```

### 4. Install the systemd unit

```bash
sudo curl -L -o /etc/systemd/system/exfer-walletd.service \
     https://raw.githubusercontent.com/exfer-stack/exfer-walletd/main/deploy/systemd/exfer-walletd.service
sudo systemctl daemon-reload
sudo systemctl enable --now exfer-walletd
sudo systemctl status exfer-walletd
```

### 5. Put Caddy in front for TLS

```Caddyfile
walletd.example.com {
    reverse_proxy 127.0.0.1:8080
    request_body { max_size 1MB }
}
```

Caddy fetches a LetsEncrypt cert on first request. The bearer token
never crosses the wire in plaintext.

> **Read the tokens out of the env file** when you need to hand them
> to your client application: `sudo cat /etc/exfer-walletd/env`.
> Don't paste them into shell history; copy them into your
> application's secret store (Vault, AWS Secrets Manager, 1Password,
> your platform's secret store, …).

---

## Recipe B — docker-compose (walletd in a container, node elsewhere)

Useful when the Exfer node already runs separately (bare-metal node,
managed RPC provider, sibling container).

### 1. Generate tokens

```bash
cat >.env <<EOF
WALLETD_AUTH_TOKEN=$(openssl rand -hex 32)
EXFER_NODE_RPC=http://your-node-host:9334
EOF
chmod 600 .env
```

For two-token mode replace the first line with:

```
WALLETD_AUTH_TOKEN_READ=$(openssl rand -hex 32)
WALLETD_AUTH_TOKEN_SPEND=$(openssl rand -hex 32)
```

### 2. `docker-compose.yml`

```yaml
services:
  exfer-walletd:
    image: ghcr.io/exfer-stack/exfer-walletd:latest  # or build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"     # loopback on the host; Caddy/nginx in front
    environment:
      # Bind 0.0.0.0 inside the container so the published port works.
      # The host port is 127.0.0.1 only. ALLOW_PUBLIC_BIND acknowledges
      # that arrangement — without it, walletd refuses 0.0.0.0 binds.
      WALLETD_BIND: "0.0.0.0:8080"
      WALLETD_ALLOW_PUBLIC_BIND: "1"
      WALLETD_WALLET_DIR: "/wallets"
      EXFER_NODE_RPC: "${EXFER_NODE_RPC}"
      WALLETD_AUTH_TOKEN: "${WALLETD_AUTH_TOKEN}"
    volumes:
      - walletd_data:/wallets
    entrypoint: ["/usr/local/bin/exfer-walletd"]
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  walletd_data:
```

### 3. Run

```bash
docker compose up -d
```

The image entrypoint defaults to a combined node + walletd supervisor;
we override it to run walletd only and talk to a node elsewhere
(loopback on the host via `host.docker.internal`, a sibling container,
or a public RPC URL — whatever `EXFER_NODE_RPC` points at).

### 4. Put Caddy / nginx in front

Same as Recipe A — the published port at `127.0.0.1:8080` is what
your reverse proxy targets.

---

## Choosing between A and B

|                                                  | Recipe A (systemd) | Recipe B (docker) |
| ------------------------------------------------ | :----------------: | :---------------: |
| You already run everything on bare-metal / VM    |        ✓           |                   |
| You already containerise other backend services  |                    |        ✓          |
| You want the simplest possible "one host, one daemon" |    ✓           |                   |
| You want kubernetes-style orchestration          |                    |        ✓          |
| Backup boundary is a tar of `/var/lib/exfer-walletd` |  ✓             |   (use named volumes + `docker volume export`) |

Either way, the daemon, the bearer-token flow, and the wallet on-disk
format are identical.

## Next

- [Security model →](./security-model.md)
- [Operations →](./operations.md)
