# pki.pl — PKI Manager

Pure openssl + Perl. No easy-rsa dependency.

## Hierarchy

```
$pki_dir/                              ← pki.pl lives here ($RealBin)
  ca.key (RSA 4096, chmod 400)
  ca.crt                               ← Root CA (20 years)
  <subca>/                             ← Sub-CA directory
    ca.key (RSA 2048, chmod 400)
    cacert.pem                         ← Sub-CA cert (10 years)
    ca-chain.pem                       ← cacert.pem + ca.crt
    server.crt, server.key             ← server cert (10 years)
    dh2048.pem                         ← Diffie-Hellman
    ta.key                             ← TLS-Auth HMAC
    pki.pl -> ../pki.pl                ← symlink to master script
    clients/
      <name>.crt, <name>.key           ← client cert + key
      <name>.ovpn                      ← all-in-one config (from `conf`)
```

## Commands

```bash
pki.pl init                            # Root CA
pki.pl subca <name>                    # create Sub-CA (e.g. vpn, mail, web)
pki.pl server [CN]                     # server cert
pki.pl add <name> [name..]             # add client(s)
pki.pl conf <name> [name..]            # generate .ovpn all-in-one config
pki.pl dh                              # DH parameters
pki.pl takey                           # TLS-Auth key (requires openvpn)
pki.pl list                            # show all certs with dates
pki.pl revoke <name>                   # revoke client (.crt/.key → .revoked)
pki.pl status                          # short status

# Options:
pki.pl --subca <name> <command>        # select Sub-CA (default: vpn)
```

## Example

```bash
# Setup
pki.pl init
pki.pl subca vpn
pki.pl server myserver.example.com
pki.pl add client1 client2 client3
pki.pl dh
pki.pl takey
pki.pl conf client1 client2

# Multiple Sub-CAs
pki.pl subca mail
pki.pl --subca mail server mail.example.com
pki.pl --subca mail add postfix dovecot

# Management
pki.pl list
pki.pl status
pki.pl revoke client2
```

## Features

- **Portable**: uses `FindBin::$RealBin` — no hardcoded paths
- **Idempotent**: safe to re-run, skips existing files
- **Sub-CA isolation**: each Sub-CA in its own directory with own `cacert.pem`
- **All-in-one configs**: `conf` embeds ca-chain, cert, key, tls-auth into single `.ovpn`
- **Symlinks**: Sub-CA dirs get `pki.pl → ../pki.pl` for convenience

## Requirements

- Perl 5 (core modules only: `FindBin`, `File::Path`)
- openssl
- openvpn (only for `takey` command)

## License

GPL-3.0
