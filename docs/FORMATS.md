# Formats

This page documents the wallet formats `wallet2hash` can export, and how each is
detected and serialized. The full classification lives in
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

## Normalized model

Every parser produces a `PasswordVerifier` — a minimal, secret-free object:

- `kdf`, `cipher` — the construction.
- `salt`, `iterations`, `memory_cost`, `parallelism` — KDF parameters.
- `iv`, `mac`, `encrypted_check_material`, `public_check_material` — verification bytes.

The Hashcat exporter and the John exporter consume the same object. For most
wallet formats the two tools share one `$...$` hash-line syntax, so the John
exporter reuses the Hashcat line verbatim (John only adds a `filename:` prefix,
the same convention as the `*2john` scripts).

## Shared syntax (Hashcat + John)

| Wallet | Hash line | Hashcat mode | John format |
| --- | --- | --- | --- |
| Bitcoin Core | `$bitcoin$<len>$<hex>$<len>$<hex>$<rounds>$2$00$2$00` | 11300 | `bitcoin` |
| Electrum | `$electrum$<1..5>*…` | 16600 / 21700 / 21800 | `electrum` |
| Ethereum keystore | `$ethereum$p*…` / `$ethereum$s*…` | 15600 / 15700 | `ethereum` |
| Ethereum pre-sale | `$ethereum$w*…` | 16300 | `ethereum` |
| Blockchain.com V0.0/V1 raw | `$blockchain$<len>$<hex>` | 12700 | `blockchain` |
| Blockchain.com V1 JSON | `$blockchain$<len>$<hex>` | 12700 | `blockchain` |
| Blockchain.com V2/V3/V4 | `$blockchain$v2$<iter>$<len>$<hex>` | 15200 | `blockchain` |
| MultiBit Classic `.key` | `$multibit$1*…` | 22500 | `multibit` |
| MultiBit HD `.aes` | `$multibit$2*…` | 22700 | `multibit` |
| MultiBit Classic `.wallet` | `$multibit$3*<n>*<r>*<p>*<salt>*<data>` | 27700 | `multibit` |
| BitShares (LevelDB) | `<128 hex>` | 21000 | `dynamic_84` |
| Trust Wallet | `$ethereum$p*…` / `$ethereum$s*…` | 15600 / 15700 | `ethereum` |

> **Trust Wallet legacy note:** pre-2024 cloud backups may carry an *empty* salt
> (`"salt": ""` or the key omitted — wallet-core falls back to an empty salt).
> Hashcat's Ethereum modes require the salt to be **exactly 32 bytes** (64 hex
> chars), so for those files wallet2hash emits **no hash line** (it cannot be
> loaded by 15600/15700) and reports `verify-only`: `--verify` still works,
> because the MAC check needs no salt length. Standard backups with a 32-byte
> salt export the normal `$ethereum$…` line.

## Hashcat-only

| Wallet | Hash line | Mode |
| --- | --- | --- |
| MetaMask | `$metamask$[rounds=N$]<salt>$<iv>$<data>` | 26600 |
| MetaMask (short) | `$metamask-short$[rounds=N$]<salt>$<iv>$<data[:64]>` | 26610 |
| MetaMask Mobile | `$metamaskMobile$<salt>$<iv_hex>$<cipher[:32]>` | 31900 |
| Exodus | `EXODUS:<n>:<r>:<p>:<salt>:<iv>:<key>:<tag>` | 28200 |
| Bisq | `$bisq$3*<n>*<r>*<p>*<salt>*<data>` | 29800 |
| Dogechain (CBC) | `$dogechain$0*<iter>*<payload_b64>*<salt_b64>` | 32500 |
| Blockchain.com 2nd password | `<80-char base64 bs: blob>` (verbatim `dpasswordhash`) | 18800 |
| Terra Station | `hex(salt16)+hex(iv16)+b64(ct80)` concatenated (verbatim `encrypted`) | 29600 |

## John-only

| Wallet | Hash line | John format | Converter |
| --- | --- | --- | --- |
| Monero | `$monero$0*<hex>` | `monero` | monero2john.py |
| BitShares (wallet JSON) | `$BitShares$0*<key>` | `BitShares` | bitshares2john.py |
| Dogechain (GCM variant) | verify only — no mode in either tool | — | — |
| Cardano (planned) | `$cardano$1$<hex>` (John's format) | `cardano` | cardano2john.py |
| Coinomi (planned) | (Coinomi export, John's format) | `coinomi` | coinomi2john.py |

## Detection

Detection is evidence-based: magic bytes, container structure (Berkeley DB,
SQLite, protobuf, JSON keys), encryption/KDF fields, and known version markers.
The filename is used only as a weak hint for formats whose encrypted payload has
no readable magic (MultiBit HD `.aes`).

When more than one handler matches, the CLI reports every candidate with a
confidence score instead of picking one.
