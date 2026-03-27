# pki.pl — промени спрямо upstream (smooker/pki)

## 2026-03-16 — FQDN domain support

- Добавена `$domain = 'smooker.org'` глобална променлива
- `_fqcn()`: клиентските CN-и вече са `<name>.<subca>.<domain>` (напр. `clnt1.cm.smooker.org`) вместо `<name>.<subca>`
- Root CA CN: `smooker.org Root CA` вместо `Root CA`
- Sub-CA CN: `<name>.<domain> CA` (напр. `cm.smooker.org CA`) вместо `<name> CA`
