# pki — PKI Manager (чист openssl + Perl)

## Йерархия

```
$pki_dir/                                ← pki.pl живее тук ($RealBin)
  ca.key (RSA 4096, chmod 400)
  ca.crt                                 ← Root CA (smooker.org, 20 години)
  vpn.smooker.org/                       ← Sub-CA
    ca.key (RSA 2048, chmod 400)
    cacert.pem                           ← Sub-CA cert (10 години)
    ca-chain.pem                         ← cacert.pem + ca.crt
    server.crt, server.key               ← ntr.smooker.org (10 години)
    dh2048.pem                           ← Diffie-Hellman
    ta.key                               ← TLS-Auth HMAC
    clients/
      st.crt, st.key                     ← client cert+key
      st.ovpn                            ← all-in-one конфиг (генериран от conf)
      ...
```

Sub-CA е с `pathlen:0` — не може да подписва други CA-та.

## Команди

```bash
perl pki.pl init                    # пълен setup: Root CA + Sub-CA + server + 7 клиента + DH + ta
perl pki.pl add phone laptop        # добави нови клиенти (подписани от Sub-CA)
perl pki.pl conf st sw2 shp         # генерирай .ovpn all-in-one конфиги (вградени ключове)
perl pki.pl list                    # покажи всички сертификати с CN + дати
perl pki.pl revoke sw1              # отмени клиент (преименува .crt/.key → .revoked)
perl pki.pl status                  # кратък статус: брой клиенти, server, DH, ta
```

## Портабилност

Скриптът ползва `FindBin::$RealBin` — PKI директорията е там, където живее `pki.pl`.
Няма hardcoded пътища. Копираш го където искаш и работи.

## Default клиенти

`st, sto, sw1, sw2, shp, sf1, lemyr` — генерират се при `init`.

## OpenVPN server.conf

`server.conf` сочи към `$pki_dir/vpn.smooker.org/` с абсолютни пътища:

```
ca      /etc/openvpn/pki/vpn.smooker.org/ca-chain.pem
cert    /etc/openvpn/pki/vpn.smooker.org/server.crt
key     /etc/openvpn/pki/vpn.smooker.org/server.key
dh      /etc/openvpn/pki/vpn.smooker.org/dh2048.pem
tls-auth /etc/openvpn/pki/vpn.smooker.org/ta.key 0
```

## VPN мрежа

| Параметър | Стойност |
|-----------|----------|
| Server IP | 87.121.112.43 |
| VPN subnet | 10.10.0.0/24 |
| Server bridge | 10.10.0.1 |
| Client pool | 10.10.0.100 — 10.10.0.200 |
| Proto | UDP |
| Port | 1194 |
| Dev | tap0 (layer 2 bridge) |
| Cipher | AES-256-GCM |

## Идемпотентност

Всички стъпки проверяват дали файловете съществуват. Безопасно е да пуснеш `init` повторно.

## Бъдещи Sub-CA

Нов sub-CA (напр. `mail.smooker.org`) — подписва се от същия Root CA:

```
$pki_dir/
  ca.key, ca.crt                     ← общ Root CA
  vpn.smooker.org/cacert.pem          ← VPN sub-CA
  mail.smooker.org/cacert.pem         ← Mail sub-CA (бъдещ)
  web.smooker.org/cacert.pem          ← Web sub-CA (бъдещ)
```

Скриптът поддържа само `vpn.smooker.org` засега. За нови sub-CA — нова стойност на `$subca_name` или CLI параметър.

## Deploy на ntr

```bash
scp -P 1022 pki/pki.pl root@87.121.112.43:/etc/openvpn/pki/
ssh -p 1022 root@87.121.112.43 'cd /etc/openvpn/pki && perl pki.pl init'
```
