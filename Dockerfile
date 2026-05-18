# syntax=docker/dockerfile:1.7

# ----------------------------------------------------------------------------
# Stage 1: build the walletd binary from source.
# ----------------------------------------------------------------------------
# The `exfer` dependency is pulled from GitHub at build time (see
# Cargo.toml), so this image is self-contained — you don't need the
# exfer source tree on disk.

FROM rust:1-slim AS build
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src        ./src
COPY tests      ./tests

RUN cargo build --release \
 && cp /build/target/release/exfer-walletd /usr/local/bin/

# ----------------------------------------------------------------------------
# Stage 2: minimal runtime with both binaries.
# Ubuntu 24.04 ships GLIBC 2.39, which the upstream `exfer` binary needs.
# ----------------------------------------------------------------------------

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tini bash \
    && rm -rf /var/lib/apt/lists/*

# Pull the upstream exfer node binary.
RUN curl -L -o /usr/local/bin/exfer \
        https://github.com/ahuman-exfer/exfer/releases/latest/download/exfer-linux-x86_64 \
 && chmod +x /usr/local/bin/exfer

# Bring in the walletd binary built in stage 1.
COPY --from=build /usr/local/bin/exfer-walletd /usr/local/bin/exfer-walletd

# Optional combined-deployment supervisor — runs both `exfer node` and
# `exfer-walletd` in one container, sharing localhost. For walletd-only
# deployments (talking to a remote node), override ENTRYPOINT to
# /usr/local/bin/exfer-walletd directly.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Wallet directory — separate from chain data so backup boundaries stay
# clean. Permissions are tightened by WalletStore::open at runtime.
RUN mkdir -p /data /wallets

EXPOSE 9333 8080

# Force bash for the entrypoint regardless of shebang — Ubuntu's /bin/sh
# is dash which doesn't support `wait -n`.
ENTRYPOINT ["/usr/bin/tini", "--", "/bin/bash", "/usr/local/bin/entrypoint.sh"]
