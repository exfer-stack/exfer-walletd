# Backup, upgrade, rotate

## Backup

Back up `~/.exfer-walletd/wallets/`. Losing it = losing every key =
losing every penny those addresses hold.

```bash
# Stop walletd briefly for a consistent snapshot, then:
tar -C ~ -czf wallets-$(date +%F).tar.gz .exfer-walletd

# Encrypt before shipping off-box
gpg --symmetric --cipher-algo AES256 wallets-$(date +%F).tar.gz
```

If you can't stop the daemon, snapshot the underlying volume (LVM,
ZFS, your cloud snapshot). Walletd writes `.key` files with
`O_CREAT | O_EXCL` and never modifies in place, so atomic per-file
copies are fine too.

## Upgrade

Semver. Patches and minors are drop-in; majors will be called out in
release notes.

```bash
curl -L -o /tmp/exfer-walletd \
     https://github.com/exfer-stack/exfer-walletd/releases/latest/download/exfer-walletd-linux-x86_64
sudo install -m 0755 /tmp/exfer-walletd /usr/local/bin/
# restart walletd via whatever supervisor you use
```

The `<datadir>` format is stable — any version can load any wallet
file written by any other version.

## Rotate tokens

Single-token (auto-generated) mode — delete the file and restart:

```bash
rm ~/.exfer-walletd/token
exfer-walletd      # generates + prints a fresh one
```

Two-token mode — change the env values / CLI flags and restart.

Either way, any in-flight request still using the old token will
fail after the restart. Plan the window.

## Rotate the TLS cert

Same idea — delete the trio and restart:

```bash
rm ~/.exfer-walletd/cert.{pem,key,fingerprint}
exfer-walletd --tls    # generates a fresh cert + prints the new fingerprint
```

Clients pinning the old fingerprint will start raising
`FingerprintMismatchError` on the next request. Push the new
fingerprint to them before restarting if you can't tolerate the
window.

## Uninstall

No ceremony — walletd doesn't touch anything outside its `--datadir`.

```bash
# Stop the daemon, then:
rm -rf ~/.exfer-walletd     # tokens + wallets + certs — IRREVERSIBLE
sudo rm /usr/local/bin/exfer-walletd
```

If you back up `~/.exfer-walletd/wallets/` first, you can restore the
same address set later by dropping the directory back into place.

## Next

- [FAQ & troubleshooting →](./faq.md)
