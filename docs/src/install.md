# Install

## Pre-built binary

```bash
curl -L -o exfer-walletd \
    https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
chmod +x exfer-walletd
sudo install -m 0755 exfer-walletd /usr/local/bin/
```

Other platforms on the
[Releases page](https://github.com/exfer-stack/exfer-walletd/releases):
linux-x86_64, linux-arm64, macos-x86_64, macos-arm64, windows-x86_64.

## From source

```bash
git clone https://github.com/exfer-stack/exfer-walletd
cd exfer-walletd && cargo build --release
# Binary at target/release/exfer-walletd
```

Rust 1.75+. The `exfer` crate (tx crypto) is pulled from GitHub at
build time.

Next: [Quick start →](./quick-start.md)
