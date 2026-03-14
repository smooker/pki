#!/usr/bin/perl
# pki.pl — PKI Manager (чист openssl, без easy-rsa)
# Copyright (c) 2026 smooker <sc@smooker.org>
# License: GPL-3.0 (see LICENSE)
# Йерархия: Root CA → Sub-CA → certs
#
# Структура:
#   $pki_dir/ca.key, ca.crt                        — Root CA
#   $pki_dir/<subca>/cacert.pem, ca.key             — Sub-CA
#   $pki_dir/<subca>/ca-chain.pem                   — chain (sub-ca + root)
#   $pki_dir/<subca>/server.{crt,key}               — server
#   $pki_dir/<subca>/clients/<name>.{crt,key}       — clients
#   $pki_dir/<subca>/dh2048.pem, ta.key             — DH + TLS-Auth

use strict;
use warnings;
use File::Path qw(make_path);
use FindBin qw($RealBin);

# PKI dir = wherever this script lives
my $pki_dir   = $RealBin;
my $subca_name = 'vpn';  # default

# parse --subca option before command
if (@ARGV && $ARGV[0] eq '--subca') {
    shift @ARGV;
    $subca_name = shift @ARGV || die "--subca requires a name\n";
}

my $subca_dir = "$pki_dir/$subca_name";

my $days_ca    = 7300;    # 20 years root CA
my $days_subca = 3650;    # 10 years sub-CA
my $days_cert  = 3650;    # 10 years certs
my $key_size   = 2048;
my $ca_key_size = 4096;

my $server_cn = 'server';
my $server_ip = '127.0.0.1';
my $server_port = 1194;

my @default_clients = ();

# --- Helpers ---

sub usage {
    print <<EOF;
Usage:
  pki.pl init                    — Root CA
  pki.pl subca <name>            — create Sub-CA (e.g. vpn, mail, web)
  pki.pl server [CN]             — server cert
  pki.pl add <name> [name..]     — add client(s)
  pki.pl conf <name> [name..]    — generate .ovpn config (all-in-one)
  pki.pl dh                      — generate DH params
  pki.pl takey                   — generate TLS-Auth key
  pki.pl list                    — show all certificates
  pki.pl revoke <name>           — revoke client certificate
  pki.pl status                  — short PKI status

  Options:
    --subca <name>                   — select Sub-CA (default: vpn)
EOF
    exit 1;
}

sub run {
    my $cmd = shift;
    print ">>> $cmd\n";
    system($cmd) == 0 or die "FAILED: $cmd\n";
}

sub slurp {
    my $file = shift;
    open my $fh, '<', $file or die "Can't read $file: $!\n";
    local $/;
    my $data = <$fh>;
    close $fh;
    chomp $data;
    return $data;
}

sub check_ca {
    die "PKI not initialized — run: pki.pl init\n"
        unless -f "$pki_dir/ca.crt" && -f "$subca_dir/cacert.pem";
}

sub gen_client {
    my $client = shift;
    my $prefix = "$subca_dir/clients/$client";
    if (-f "$prefix.crt") {
        print "Client $client already exists, skipping.\n";
        return;
    }
    print "=== Generating client: $client ===\n";
    run("openssl genrsa -out $prefix.key $key_size");
    run("openssl req -new -key $prefix.key -out $prefix.csr -batch -subj '/CN=$client'");
    run("openssl x509 -req -in $prefix.csr -CA $subca_dir/cacert.pem -CAkey $subca_dir/ca.key -CAcreateserial -out $prefix.crt -days $days_cert");
    unlink("$prefix.csr");
}

# --- Commands ---
my $cmd = shift @ARGV || usage();

if ($cmd eq 'init') {
    make_path($pki_dir);

    # --- Root CA ---
    unless (-f "$pki_dir/ca.key") {
        print "=== Generating Root CA ===\n";
        run("openssl genrsa -out $pki_dir/ca.key $ca_key_size");
        run("openssl req -new -x509 -key $pki_dir/ca.key -out $pki_dir/ca.crt -days $days_ca -batch -subj '/CN=Root CA'");
        chmod 0400, "$pki_dir/ca.key";
        print "\n=== Root CA created ===\n";
        print "Root CA: $pki_dir/ca.crt\n";
        print "Next: pki.pl subca <name>\n";
    } else {
        print "Root CA already exists.\n";
        run("openssl x509 -in $pki_dir/ca.crt -noout -subject -dates");
    }

} elsif ($cmd eq 'subca') {
    my $name = shift @ARGV || die "Usage: pki.pl subca <name>\n";
    die "Root CA not found — run: pki.pl init\n" unless -f "$pki_dir/ca.key";

    my $sdir = "$pki_dir/$name";
    make_path("$sdir/clients");

    unless (-f "$sdir/ca.key") {
        print "=== Generating Sub-CA ($name) ===\n";
        run("openssl genrsa -out $sdir/ca.key $key_size");
        run("openssl req -new -key $sdir/ca.key -out $sdir/ca.csr -batch -subj '/CN=$name CA'");

        open my $fh, '>', "$sdir/ca.ext" or die;
        print $fh "basicConstraints=CA:TRUE,pathlen:0\nkeyUsage=keyCertSign,cRLSign\n";
        close $fh;

        run("openssl x509 -req -in $sdir/ca.csr -CA $pki_dir/ca.crt -CAkey $pki_dir/ca.key -CAcreateserial -out $sdir/cacert.pem -days $days_subca -extfile $sdir/ca.ext");
        unlink("$sdir/ca.csr", "$sdir/ca.ext");

        # chain: sub-ca + root
        run("cat $sdir/cacert.pem $pki_dir/ca.crt > $sdir/ca-chain.pem");
        chmod 0400, "$sdir/ca.key";
        # symlink for convenience
        symlink('../pki.pl', "$sdir/pki.pl") unless -e "$sdir/pki.pl";

        print "\n=== Sub-CA created: $name ===\n";
        print "Cert:  $sdir/cacert.pem\n";
        print "Chain: $sdir/ca-chain.pem\n";
    } else {
        print "Sub-CA $name already exists.\n";
        run("openssl x509 -in $sdir/cacert.pem -noout -subject -dates");
    }

} elsif ($cmd eq 'server') {
    check_ca();
    my $cn = shift @ARGV || $server_cn;

    unless (-f "$subca_dir/server.key") {
        print "=== Generating server cert ($cn) ===\n";
        run("openssl genrsa -out $subca_dir/server.key $key_size");
        run("openssl req -new -key $subca_dir/server.key -out $subca_dir/server.csr -batch -subj '/CN=$cn'");
        run("openssl x509 -req -in $subca_dir/server.csr -CA $subca_dir/cacert.pem -CAkey $subca_dir/ca.key -CAcreateserial -out $subca_dir/server.crt -days $days_cert");
        unlink("$subca_dir/server.csr");
        print "Server cert: $subca_dir/server.crt\n";
    } else {
        print "Server cert already exists, skipping.\n";
    }

} elsif ($cmd eq 'dh') {
    check_ca();
    unless (-f "$subca_dir/dh2048.pem") {
        print "=== Generating DH params ===\n";
        run("openssl dhparam -out $subca_dir/dh2048.pem $key_size");
    } else {
        print "DH already exists, skipping.\n";
    }

} elsif ($cmd eq 'takey') {
    check_ca();
    unless (-f "$subca_dir/ta.key") {
        print "=== Generating TLS-Auth key ===\n";
        run("openvpn --genkey secret $subca_dir/ta.key");
    } else {
        print "ta.key already exists, skipping.\n";
    }

} elsif ($cmd eq 'add') {
    usage() unless @ARGV;
    check_ca();
    make_path("$subca_dir/clients");
    gen_client($_) for @ARGV;

} elsif ($cmd eq 'conf') {
    usage() unless @ARGV;
    check_ca();

    for my $client (@ARGV) {
        my $crt_file = "$subca_dir/clients/$client.crt";
        my $key_file = "$subca_dir/clients/$client.key";
        die "Client $client not found (run: pki.pl add $client)\n"
            unless -f $crt_file && -f $key_file;

        my $ca_chain = slurp("$subca_dir/ca-chain.pem");
        my $crt      = slurp($crt_file);
        my $key      = slurp($key_file);
        my $ta       = slurp("$subca_dir/ta.key");

        my $ovpn = <<"OVPN";
client
dev tap
proto udp
remote $server_ip $server_port
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
verb 3
key-direction 1

<ca>
$ca_chain
</ca>

<cert>
$crt
</cert>

<key>
$key
</key>

<tls-auth>
$ta
</tls-auth>
OVPN

        my $out = "$subca_dir/clients/$client.ovpn";
        open my $fh, '>', $out or die "Can't write $out: $!\n";
        print $fh $ovpn;
        close $fh;
        chmod 0600, $out;
        print "Generated: $out\n";
    }

} elsif ($cmd eq 'list') {
    check_ca();
    print "=== Root CA ===\n";
    run("openssl x509 -in $pki_dir/ca.crt -noout -subject -dates");
    print "\n=== Sub-CA ($subca_name) ===\n";
    run("openssl x509 -in $subca_dir/cacert.pem -noout -subject -dates");
    print "\n=== Server ===\n";
    run("openssl x509 -in $subca_dir/server.crt -noout -subject -dates") if -f "$subca_dir/server.crt";
    print "\n=== Clients ===\n";
    for my $f (sort glob("$subca_dir/clients/*.crt")) {
        run("openssl x509 -in $f -noout -subject -dates");
        print "\n";
    }

} elsif ($cmd eq 'revoke') {
    usage() unless @ARGV;
    check_ca();
    for my $client (@ARGV) {
        my $crt = "$subca_dir/clients/$client.crt";
        die "Client $client not found\n" unless -f $crt;
        print "=== Revoking $client ===\n";
        rename $crt, "$crt.revoked";
        rename "$subca_dir/clients/$client.key", "$subca_dir/clients/$client.key.revoked";
        unlink "$subca_dir/clients/$client.ovpn" if -f "$subca_dir/clients/$client.ovpn";
        print "Revoked: $client (files renamed to .revoked)\n";
    }

} elsif ($cmd eq 'status') {
    if (-f "$pki_dir/ca.crt") {
        print "PKI: initialized\n";
        print "Root CA:  $pki_dir/ca.crt\n";
        if (-f "$subca_dir/cacert.pem") {
            my @crts = glob("$subca_dir/clients/*.crt");
            my @revoked = glob("$subca_dir/clients/*.crt.revoked");
            print "Sub-CA:   $subca_dir/cacert.pem\n";
            print "Clients:  " . scalar(@crts) . " active, " . scalar(@revoked) . " revoked\n";
            print "Server:   " . (-f "$subca_dir/server.crt" ? "yes" : "no") . "\n";
            print "DH:       " . (-f "$subca_dir/dh2048.pem" ? "yes" : "no") . "\n";
            print "ta.key:   " . (-f "$subca_dir/ta.key" ? "yes" : "no") . "\n";
        }
    } else {
        print "PKI: not initialized\n";
    }

} else {
    usage();
}

__END__

=head1 NAME

pki.pl — PKI Manager (pure openssl, no easy-rsa)

=head1 SYNOPSIS

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

=head1 DESCRIPTION

Generates and manages a PKI hierarchy using pure openssl:

    Root CA (RSA 4096, 20 years)
      └── Sub-CA (RSA 2048, 10 years)
            ├── Server cert
            └── Client certs

Uses C<FindBin::$RealBin> as PKI directory —
works from any location without hardcoded paths.

=head1 COMMANDS

=over 4

=item B<init>

Create Root CA. Idempotent — skips if already exists.

=item B<subca> I<name>

Create a Sub-CA signed by Root CA. Creates symlink to ../pki.pl
in the sub-CA directory for convenience.

=item B<server> [I<CN>]

Generate server certificate signed by current Sub-CA.

=item B<add> I<name> [I<name> ...]

Add client certificates signed by current Sub-CA.

=item B<conf> I<name> [I<name> ...]

Generate all-in-one C<.ovpn> configs with embedded
ca-chain, cert, key and tls-auth. Ready to copy to client.

=item B<dh>

Generate Diffie-Hellman parameters.

=item B<takey>

Generate TLS-Auth HMAC key (requires openvpn).

=item B<list>

Show all certificates (Root CA, Sub-CA, Server, Clients)
with CN, notBefore and notAfter dates.

=item B<revoke> I<name>

Revoke client certificate — renames C<.crt>/C<.key> to C<.revoked>,
deletes C<.ovpn> if exists.

=item B<status>

Short status: active/revoked client count, server, DH, ta.key presence.

=back

=head1 FILE LAYOUT

    $RealBin/
      ca.key, ca.crt                          Root CA
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

=head1 EXAMPLE

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

=head1 AUTHOR

smooker E<lt>sc@smooker.orgE<gt>

=head1 LICENSE

GPL-3.0

=cut
