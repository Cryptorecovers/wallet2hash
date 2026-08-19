# Tool coverage comparisons

This page compares wallet-file coverage across the recovery ecosystem:
Hashcat modes, John the Ripper formats, and the wallet formats proven verifiable
by CPU verifiers. It exists to answer one question: *for a given wallet, who can
prove the password offline, and who can crack it?*

## Verifiable by a CPU verifier but **not** by Hashcat

The highest-value gap: formats with a proven offline verifier but no Hashcat mode.

| Wallet | Verifier support | Hashcat status | Our classification |
| ------ | ---------------- | -------------- | ------------------ |
| BIP-0038 encrypted keys | yes (incl. altcoin forks) | no mode | **C** — custom module (scrypt+AES+secp256k1) |
| Bither | yes | no mode | **D/C** — standalone verifier; custom module possible |
| Bitcoin Wallet for Android (bitcoinj PIN/backup) | yes | no mode | **D/C** — bitcoinj protobuf |
| KnC Wallet for Android | yes | no mode | **D/C** |
| mSIGNA (CoinVault) | yes | no mode | **D** |
| block.io "Secret PIN" | yes | no mode | **D** |
| btc.com / blocktrail PDF password | yes | no mode | **D** |
| pywallet `--dumpwallet` (BU/Classic/XT/Core) | yes | 11300 | **A** — the BDB `wallet.dat` is handled; the pywallet *JSON dump* is a separate text artifact not yet parsed |
| Toast Wallet passphrase | yes | no mode | **D/C** |
| Yoroi (Cardano) master password | yes | no mode | **C** (see JTR_GAPS) |
| Coinomi (password-protected) | yes | no mode | **D/C** |
| imToken | yes | no mode | **D/C** |
| MultiDoge / Dogechain.info / Dogecoin Wallet Android | yes | no mode (Core/bitcoinj-derived) | **D/C** (Dogechain CBC now implemented: 32500) |
| Damaged raw Ethereum private keys | yes | n/a (missing-char brute force, not password) | **D** |

Brainwallets are the exception: sha256 and scrypt brainwallets are representable
by generic Hashcat modes (1400 / 8900) → class **B**.

## Supported by Hashcat but **not** by CPU verifiers

| Wallet | Hashcat mode | Verifier status |
| ------ | ------------ | --------------- |
| Electrum 2FA / salt-type 4-5 (ECIES) | 21700 / 21800 | no support for 2FA wallets |
| Exodus `exodus.seco` | 28200 | Exodus appears only under BIP39 seed recovery |

## Supported by neither (but technically recoverable)

| Wallet | Why neither | Classification |
| ------ | ----------- | -------------- |
| Monero `wallet.keys` | JtR only (see JTR_GAPS); extraction implemented here | **C** — CryptoNight KDF + ChaCha8 |
| Wasabi | Argon2 + ChaCha20; no converter | **C** |
| Trust Wallet / Phantom / Keplr / … | browser-extension AES-GCM vaults; no converter (MetaMask 26600 is the closest analogue) | **C/D** |

## What this means for the tool

`wallet2hash` is the interop layer: it extracts the *password-verification
material* from a wallet and serializes it in exactly the shape Hashcat or John
expects. For every "verifiable but no Hashcat mode" row above, the next step is
either

1. a standalone verifier, or
2. a custom Hashcat module write-up under `docs/hashcat-candidates/`.

Neither should be attempted without a synthetic fixture from the wallet's own
code or documented format.
