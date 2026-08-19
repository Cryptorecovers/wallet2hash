# Support matrix

The authoritative map of which cryptocurrency wallet formats can be exported for
**Hashcat** and/or **John the Ripper Jumbo**. Every row marked `implemented` is
backed by a fixture-validated parser plus exporter tests — synthetic fixtures in
the test suite and, where noted, real wallets from public open-source test-wallet suites
(encrypted, no funds, documented passwords).

Sources used (current upstream, not blogs):

- Hashcat `src/modules/module_*.c`, `tools/test_modules/m*.pm`,
  `tools/*2hashcat.py`, official example hashes. The mode catalog below is
  enumerated from the current Hashcat source (`HASH_CATEGORY_CRYPTOCURRENCY_WALLET`).
- John the Ripper Jumbo `run/*2john.py` converters and their `$...$` hash lines.
- Public open-source test-wallet suites (encrypted sample wallets with
  documented passwords) used for real-file validation.

## Legend

**Status** is one of:

- `implemented` — parser + exporter + tests exist in this repository.
- `planned` — researched and confirmed upstream, not yet implemented here.
- `unsupported` — the target (Hashcat or John) cannot handle this wallet.
- `unknown` — upstream support is genuinely unclear without further verification.

**Detection Method** describes the evidence used, never the filename alone.

---

## The full Hashcat cryptocurrency-wallet mode catalog

Enumerated from current Hashcat source (`grep HASH_CATEGORY_CRYPTOCURRENCY_WALLET
src/modules/`). 35 modes exist; the table shows where each one stands here.

| Mode | Algorithm / Wallet | wallet2hash status |
| ---: | --- | --- |
| 11300 | Bitcoin/Litecoin/Dogecoin Core `wallet.dat` | implemented |
| 12700 | Blockchain, My Wallet (V0.0/V1) | implemented |
| 15200 | Blockchain, My Wallet, V2 (also V3/V4) | implemented |
| 15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256 | implemented |
| 15700 | Ethereum Wallet, scrypt | implemented |
| 16300 | Ethereum Pre-Sale Wallet | implemented |
| 16600 | Electrum Wallet (salt-type 1–3) | implemented |
| 18800 | Blockchain, My Wallet, Second Password | implemented — legacy `bs:` dpasswordhash blob, extracted verbatim from wallet JSON (self-validating CRC32); verified against Hashcat `m18800.pm` |
| 21000 | BitShares v0.x — sha512(sha512(pass)) | implemented (LevelDB `checksum` extraction) |
| 21700 | Electrum Wallet (salt-type 4, 2FA) | implemented |
| 21800 | Electrum Wallet (salt-type 5, 2FA) | implemented |
| 22500 | MultiBit Classic `.key` (MD5) | implemented |
| 22700 | MultiBit HD (scrypt) | implemented |
| 25500 | Stargazer Stellar Wallet XLM | not claimed — wallet source is unavailable (repos gone), schema cannot be fixture-validated |
| 26600 | MetaMask Wallet | implemented |
| 26610 | MetaMask Wallet (short) | implemented (large vaults, `$metamask-short$`) |
| 27700 | MultiBit Classic `.wallet` (scrypt, bitcoinj protobuf) | implemented |
| 28200 | Exodus Desktop Wallet (SECO) | implemented |
| 28501–28506 | Bitcoin raw private key (P2PKH/P2WPKH variants) | not a password format — needs WIF + address; key-cracking, out of scope |
| 29600 | Terra Station Wallet (AES-256-CBC(PBKDF2)) | implemented — verified against terra-money/key-utils `keystore.ts` + module_29600 |
| 29800 | Bisq `.wallet` (scrypt, bitcoinj protobuf) | implemented |
| 30901–30906 | Bitcoin raw private key (address-checked) | not a password format — out of scope |
| 31900 | MetaMask Mobile Wallet | implemented |
| 32500 | Dogechain.info Wallet | implemented (CBC); GCM variant is verify-only |
| 34700 | Blockchain, My Wallet, Legacy Wallets | implemented — legacy OFB/1-iteration scheme; same line syntax as 12700, emitted for non-CBC-shaped V0.0 payloads |

---

## Wallets supported by both Hashcat and John the Ripper

These share the same `$...$` hash-line format, so one parser feeds both exporters.

| Wallet / Format | Detection Method | Hashcat | Mode | John | John Format / Converter | Status | Notes |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| Bitcoin Core `wallet.dat` (BDB/SQLite) | BDB magic `0x00053162` / SQLite header + `mkey` | yes | 11300 | yes | `bitcoin` / bitcoin2john.py | implemented | `$bitcoin$…$2$00$2$00`; verified against public BDB + SQLite Core test wallets |
| Litecoin/Dogecoin Core `wallet.dat` | same Core structure | yes | 11300 | yes | `bitcoin` | implemented | verified against public litecoincore/dogecoincore test fixtures |
| Electrum wallet (salt-type 1–3) | JSON `seed`/`keystore` + `use_encryption` | yes | 16600 | yes | `electrum` / electrum2john.py | implemented | sha256d KDF, AES-256-CBC |
| Electrum wallet (salt-type 4) | `BIE1` ECIES blob | yes | 21700 | yes | `electrum` / electrum2john.py | implemented | secp256k1 ECDH; extract-only |
| Electrum wallet (salt-type 5) | `BIE1` blob, ciphertext > 16 KB | yes | 21800 | yes | `electrum` / electrum2john.py | implemented | ciphertext truncated to 1024 bytes |
| Ethereum keystore V3 (PBKDF2) | JSON `crypto.kdf=pbkdf2` | yes | 15600 | yes | `ethereum` / ethereum2john.py | implemented | `$ethereum$p*…` |
| Ethereum keystore V3 (scrypt) | JSON `crypto.kdf=scrypt` | yes | 15700 | yes | `ethereum` / ethereum2john.py | implemented | `$ethereum$s*…` |
| Ethereum pre-sale wallet | JSON `encseed`/`ethaddr`/`bkp` | yes | 16300 | yes | `ethereum` / ethereum2john.py | implemented | `$ethereum$w*…` |
| Trust Wallet cloud backup | JSON `crypto` (Web3 V3) | yes | 15600/15700 | yes | `ethereum` / ethereum2john.py | implemented | same construction as Ethereum V3 |
| Trust Wallet cloud backup (legacy) | same, but empty/missing `kdfparams.salt` | no | — | no | — | implemented (verify-only) | pre-2024 backups derive with an empty salt; Hashcat 15600/15700 lock the salt to 32 bytes so no line is emitted, but offline `--verify` works |
| Blockchain.com V0.0/V1 (raw base64) | whole file is a base64 blob | yes | 12700 | yes | `blockchain` / blockchain2john.py `--base64` | implemented | PBKDF2-HMAC-SHA1, 10 rounds; our line matches blockchain2john byte-for-byte |
| Blockchain.com V1 JSON | JSON `guid`/`sharedKey`/`payload` | yes | 12700 | yes | `blockchain` | implemented | 10-round HMAC-SHA1 KDF |
| Blockchain.com V2/V3/V4 | JSON `version`/`pbkdf2_iterations`/`payload` | yes | 15200 | yes | `blockchain` | implemented | per-wallet iteration count; 34700 also consumes legacy lines |
| MultiBit Classic `.key` | base64 `Salted__` | yes | 22500 | yes | `multibit` / multibit2john.py | implemented | `$multibit$1*…`; 3-round MD5 KDF |
| MultiBit HD `.aes` | raw IV + AES-CBC ciphertext | yes | 22700 | yes | `multibit` | implemented | `$multibit$2*…`; scrypt N=16384 r=8 p=1, fixed salt |
| MultiBit Classic `.wallet` (bitcoinj protobuf) | protobuf `org.bitcoin` + `org.multibit` marker | yes | 27700 | yes | `multibit` / multibit2john.py (v3) | implemented | `$multibit$3*…`; verified against a public `multibit.wallet.bitcoinj.encrypted` fixture |
| Dogechain.info wallet (CBC) | JSON `salt`/`payload`/`pbkdf2_iterations` | yes | 32500 | no | — | implemented | PBKDF2-SHA256(base64(sha256(pass))); verified against 2022 + 2024 fixtures |
| BitShares wallet (LevelDB `checksum`) | `checksum` marker + 128 hex | yes | 21000 | yes | `dynamic_84` / bitshares2john.py | implemented | sha512(sha512(pass)); verify supported |

---

## Wallets supported only by Hashcat

| Wallet / Format | Detection Method | Hashcat | Mode | John | Status | Notes |
| --- | --- | --- | ---: | --- | --- | --- |
| MetaMask extension vault | JSON `data`/`iv`/`salt` + `keyMetadata` | yes | 26600 / 26610 | no | implemented | AES-256-GCM; `rounds=` emitted for non-default iterations; short form for vaults > 3000 chars |
| MetaMask Mobile vault | persist-root `vault` with `lib: original` | yes | 31900 | no | implemented | PBKDF2-SHA512(5000); verified against iOS + Android persist-root fixtures |
| Exodus `exodus.seco` | SECO container JSON | yes | 28200 | no | implemented | scrypt + AES-256-GCM |
| Bisq `.wallet` (bitcoinj protobuf) | protobuf `org.bitcoin` + scrypt params | yes | 29800 | no | implemented | `$bisq$3*…` |
| Dogechain.info wallet (GCM) | JSON `cipher: AES-GCM` | no | — | no | implemented (verify only) | newer variant; no Hashcat mode yet |

---

## Wallets supported only by John the Ripper

| Wallet / Format | Detection Method | Hashcat | John | John Format / Converter | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Monero `wallet.keys` | `.keys` filename + high-entropy binary | no | yes | `monero` / monero2john.py | implemented | `$monero$0*<hex>`; CryptoNight + ChaCha8 (verify not feasible in pure Python) |
| BitShares wallet (JSON `encryption_key`) | `encryption_key` field | no | yes | `BitShares` / bitshares2john.py | implemented | `$BitShares$0*…` |
| Cardano `secret.key` | CBOR keystore | no | yes | `cardano` / cardano2john.py | planned | `$cardano$1$…`; needs cbor2 |
| Coinomi backup | Coinomi export JSON | no | yes | `coinomi` / coinomi2john.py | planned | needs format verification |

---

## Wallets supported by neither Hashcat nor John

| Wallet / Format | Hashcat | John | Status | Notes |
| --- | --- | --- | --- | --- |
| BIP-0038 encrypted key (`6P…`) | no | no | planned | offline-verifiable (scrypt+AES+secp256k1) but no mode in either tool; custom-module candidate |
| Descriptor wallets (Bitcoin Core ≥ 0.21) | no | no | documented | not password-encrypted in the relevant sense |

---

## Final classification

### Both Hashcat and John

- Bitcoin/Litecoin/Dogecoin Core `wallet.dat` (11300)
- Electrum salt-type 1–5 (16600/21700/21800)
- Ethereum keystore V3 + pre-sale (15600/15700/16300)
- Trust Wallet cloud backup (15600/15700)
- Blockchain.com V0.0–V4 (12700/15200/34700)
- MultiBit Classic `.key` (22500), MultiBit HD `.aes` (22700)
- MultiBit Classic `.wallet` bitcoinj protobuf (27700)
- BitShares LevelDB checksum (21000 / `dynamic_84`)

### Hashcat only

- MetaMask extension (26600/26610), MetaMask Mobile (31900)
- Exodus (28200)
- Bisq (29800)
- Dogechain CBC (32500) — GCM variant verify-only

### John only

- Monero `wallet.keys` (`monero`)
- BitShares `encryption_key` wallets (`BitShares`)
- Cardano (planned), Coinomi (planned)

### Neither

- BIP-0038 (offline-verifiable, no cracking mode in either tool)
- Unencrypted descriptor wallets

---

## Research backlog (unknown until verified)

These were listed for investigation but have not been confirmed against current
upstream. They stay `unknown`/`planned` rather than guessed:

- Stargazer Stellar (25500): the wallet source repositories are gone (404 on
  both known repos), so the on-disk schema cannot be verified. Per the
  no-guessing rule this format is **not claimed** — it is documented in
  HASHCAT_MODES.md as an upstream mode with no verified extractor.
- Terra Station (29600): implemented — see the table above.
- Cardano (John `cardano`): needs a CBOR parser + fixture.
- NEO wallets (possible John `neo` format — unverified)
- Keplr / Phantom / other browser-extension vaults (no Hashcat/John modes)
- geth/Mist keystore variants beyond the standard V3 schema
