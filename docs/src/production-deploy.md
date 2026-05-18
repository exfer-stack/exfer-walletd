# Production deploy

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

## Next

- [Security model →](./security-model.md)
- [Operations →](./operations.md)
