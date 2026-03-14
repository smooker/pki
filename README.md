# pki.pl — PKI Manager (pure openssl, no easy-rsa)

## Synopsis

```
pki.pl init
pki.pl subca <name>
pki.pl server [CN]
pki.pl add <name> [name..]
pki.pl conf <name> [name..]
pki.pl show_conf server|<name>
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
  --port <port>     server port for .ovpn (default: 1194)
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
Certificate is named by CN (e.g. `srv.vpn.smooker.org.crt`).

### add *name* [*name* ...]

Add client certificates signed by current Sub-CA.
Client names are auto-expanded to FQCN (e.g. `st` becomes `st.vpn.smooker.org`).

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

### show_conf server|*name*

Print OpenVPN config to stdout. `server` prints server config,
client name prints client config. All components inline (ca, cert,
key, dh, tls-auth). Use `--remote` and `--port` to set endpoint.

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
    <CN>.crt, <CN>.key                    Server certificate (named by CN)
    dh2048.pem                            Diffie-Hellman parameters
    ta.key                                TLS-Auth HMAC key
    crl.pem                               Certificate Revocation List
    index.txt                             Revocation database
    ca.cnf                                Minimal openssl ca config
    pki.pl -> ../pki.pl                   Symlink to master script
    clients/
      <name>.crt, <name>.key              Client cert + key (FQCN)
      <name>.ovpn                         All-in-one OpenVPN config
      <name>.p12                          PKCS12 bundle
      <name>.card                         Mifare card blob (48 bytes)
```

## Example

```bash
# Setup
pki.pl init
pki.pl subca vpn.example.com
pki.pl server srv.vpn.example.com
pki.pl add client1 client2        # -> client1.vpn.example.com etc.
pki.pl dh
pki.pl takey

# Generate client configs
pki.pl --remote 1.2.3.4 --port 65432 conf client1 client2
pki.pl p12 client3
pki.pl card client1 client2 client3

# Preview configs
pki.pl --port 65432 show_conf server
pki.pl --remote 1.2.3.4 --port 65432 show_conf client1

# Multiple Sub-CAs
pki.pl subca mail.example.com
pki.pl --subca mail.example.com server srv.mail.example.com
pki.pl --subca mail.example.com add postfix dovecot

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
