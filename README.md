# pki.pl — PKI Manager (pure openssl, no easy-rsa)

## Synopsis

```
pki.pl init
pki.pl subca <name>
pki.pl server [CN]
pki.pl add <name> [name..]
pki.pl conf <name> [name..]
pki.pl dh
pki.pl takey
pki.pl list
pki.pl revoke <name>
pki.pl status

Options:
  --subca <name>    select Sub-CA (default: vpn)
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

### dh

Generate Diffie-Hellman parameters.

### takey

Generate TLS-Auth HMAC key (pure openssl, no openvpn dependency).

### list

Show all certificates (Root CA, Sub-CA, Server, Clients)
with CN, notBefore and notAfter dates.

### revoke *name*

Revoke client certificate — renames `.crt`/`.key` to `.revoked`,
deletes `.ovpn` if exists.

### status

Short status: active/revoked client count, server, DH, ta.key presence.

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
    pki.pl -> ../pki.pl                   Symlink to master script
    clients/
      <name>.crt, <name>.key              Client certificate + key
      <name>.ovpn                         All-in-one OpenVPN config
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

## Requirements

- Perl 5 (core modules only: `FindBin`, `File::Path`)
- openssl

## Author

smooker <sc@smooker.org>

## License

GPL-3.0
