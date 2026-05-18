# Deploy recipes

Ready-to-copy configuration for the two deployment topologies covered
in the [docs site](https://exfer-stack.github.io/exfer-walletd/#production-deploy).

| Directory | Topology | When to use |
| --------- | -------- | ----------- |
| [`systemd/`](systemd/) | Native binary under systemd, Caddy/nginx in front | Single VM, you own the host |
| [`docker/`](docker/)   | Walletd in a container, node anywhere reachable    | You already containerize, want clean isolation |

Read the [docs site](https://exfer-stack.github.io/exfer-walletd/#production-deploy)
for the step-by-step walkthrough of each.
