# pki.pl — PKI Manager (pure openssl, no easy-rsa)

## Synopsis

```
pki.pl init
pki.pl subca <name>
pki.pl server [CN]
pki.pl add <name> [name..]
pki.pl conf <name> [name..]
pki.pl p12 <name> [name..]
pki.pl card <name> [name..]
pki.pl dh
pki.pl takey
pki.pl list
pki.pl revoke <name>
pki.pl crl
pki.pl status

Options:
  --subca <name>    select Sub-CA (default: vpn)
  --remote <ip>     server IP/hostname for .ovpn (default: 127.0.0.1)
```

## Description

Generates and manages a PKI hierarchy using pure openssl:

```
Root CA (RSA 4096, 20 years)
  └── Sub-CA (RSA 2048, 10 years)
        ├── Server cert
        └── Client certs
```

Uses `FindBin::$RealBin` as PKI directory —
works from any location without hardcoded paths.

When running as root, automatically chroots to PKI directory
after copying openssl binary and its shared libraries (one-time).
Subsequent runs verify MD5 checksums from `.chroot_manifest`.
Set `PKI_NO_CHROOT=1` to disable. Non-root skips chroot.

## Commands

### init

Create Root CA. Idempotent — skips if already exists.

### subca *name*

Create a Sub-CA signed by Root CA. Creates symlink to `../pki.pl`
in the sub-CA directory for convenience.

### server [*CN*]

Generate server certificate signed by current Sub-CA.

### add *name* [*name* ...]

Add client certificates signed by current Sub-CA.

### conf *name* [*name* ...]

Generate all-in-one `.ovpn` configs with embedded
ca-chain, cert, key and tls-auth. Ready to copy to client.

### p12 *name* [*name* ...]

Generate PKCS12 bundles (`.p12`) containing client cert, key and
ca-chain. Empty passphrase by default. For Windows/macOS/mobile clients.

### card *name* [*name* ...]

Generate compact binary blob (48 bytes) for Mifare 4K smart cards.
Contains SHA-256 of client certificate (32 bytes) + client name (16 bytes,
null-padded). Intended for sector 2+ of Mifare 4K. Reader verifies
hash against PKI database.

### dh

Generate Diffie-Hellman parameters.

### takey

Generate TLS-Auth HMAC key (pure openssl, no openvpn dependency).

### list

Show all certificates (Root CA, Sub-CA, Server, Clients)
with CN, notBefore and notAfter dates.

### revoke *name*

Revoke client certificate using openssl ca, rename `.crt`/`.key` to
`.revoked`, delete `.ovpn`/`.p12`, regenerate CRL.

### crl

Regenerate CRL (`crl.pem`) from current revocation database.

### status

Short status: active/revoked client count, server, DH, ta.key, CRL presence.

## File Layout

```
$RealBin/
  ca.key, ca.crt                          Root CA
  .chroot_manifest                        MD5 checksums of copied binaries
  usr/bin/openssl                          Copied binary (chroot only)
  usr/lib64/, lib64/                       Copied shared libs (chroot only)
  <subca>/
    ca.key                                Sub-CA private key
    cacert.pem                            Sub-CA certificate
    ca-chain.pem                          cacert.pem + ca.crt
    server.crt, server.key                Server certificate
    dh2048.pem                            Diffie-Hellman parameters
    ta.key                                TLS-Auth HMAC key
    crl.pem                               Certificate Revocation List
    index.txt                             Revocation database
    ca.cnf                                Minimal openssl ca config
    pki.pl -> ../pki.pl                   Symlink to master script
    clients/
      <name>.crt, <name>.key              Client certificate + key
      <name>.ovpn                         All-in-one OpenVPN config
      <name>.p12                          PKCS12 bundle
      <name>.card                         Mifare card blob (48 bytes)
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
pki.pl p12 client3
pki.pl card client1 client2 client3

# Multiple Sub-CAs
pki.pl subca mail
pki.pl --subca mail server mail.example.com
pki.pl --subca mail add postfix dovecot

# Management
pki.pl list
pki.pl status
pki.pl revoke client2
pki.pl crl
```

## Requirements

- Perl 5 (core modules only: `FindBin`, `File::Path`)
- openssl

## Author

smooker <sc@smooker.org>

## License

GPL-3.0
