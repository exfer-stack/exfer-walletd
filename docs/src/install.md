# Install

## Pre-built binary

Linux, macOS, Windows builds are on the
[Releases page](https://github.com/exfer-stack/exfer-walletd/releases).

```bash
curl -L -o exfer-walletd \
    https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
chmod +x exfer-walletd
sudo install -m 0755 exfer-walletd /usr/local/bin/
exfer-walletd --version
```

Available platforms:

| OS      | Arch   | Asset name                              |
| ------- | ------ | --------------------------------------- |
| Linux   | x86_64 | `exfer-walletd-linux-x86_64`            |
| Linux   | arm64  | `exfer-walletd-linux-arm64`             |
| macOS   | x86_64 | `exfer-walletd-macos-x86_64`            |
| macOS   | arm64  | `exfer-walletd-macos-arm64`             |
| Windows | x86_64 | `exfer-walletd-windows-x86_64.exe`      |

## From source

Rust 1.75 or newer.

```bash
git clone https://github.com/exfer-stack/exfer-walletd
cd exfer-walletd
cargo build --release
# Binary at target/release/exfer-walletd
```

The `exfer` crate (transaction crypto) is pulled from GitHub at
build time; no parent-directory checkout needed.

## Verify

```bash
exfer-walletd --version
# exfer-walletd 0.3.x

exfer-walletd --help
```

Next: [Quick start →](./quick-start.md)
