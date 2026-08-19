# John the Ripper gaps

Formats John the Ripper (jumbo) supports for wallet recovery that Hashcat does
**not**. These are the highest-value "no convenient wallet-to-Hashcat converter"
gaps. Converters were read from `openwall/john` `bleeding-jumbo` `run/*2john.py`.

## Monero `wallet.keys`

- **Wallet:** Monero GUI/CLI (and Monero-derived wallets).
- **Converter:** `run/monero2john.py`.
- **JtR formats:** `monero`, `monero Wallet [Pseudo-AES]`.
- **Underlying crypto:** CryptoNight (`cn_slow_hash`) key derivation + ChaCha8
  stream cipher; the `.keys` `password` field is the verification value
  (Keccak-based). Verify the exact salt/layout against
  `src/wallet/wallet2.cpp` (`wallet2::verify_password`) before implementing.
- **Conversion to Hashcat possible?** Not with an existing mode. Hashcat has
  CryptoNight *mining-hash* kernels, but none target the wallet-key verification
  construction.
- **New Hashcat module required?** Yes — a CryptoNight-KDF + ChaCha8 + Keccak
  module. Feasible but non-trivial (CryptoNight is memory-hard and needs the
  scratchpad per candidate).
- **Status here:** classified `C` (custom module possible). **Extraction is
  implemented in wallet2hash** (`$monero$0*<hex>`, John `monero` format — the
  same line monero2john.py emits); only the offline verifier is unavailable
  because it would require CryptoNight.

## Cardano (Daedalus / Yoroi)

- **Wallet:** Cardano wallets with an encrypted secret file.
- **Converter:** `run/cardano2john.py`.
- **JtR format:** Cardano wallet format(s).
- **Underlying crypto:** KDF + AEAD over the encrypted root key; confirm the exact
  construction against `cardano-wallet` / `cardano-crypto` source before
  implementing.
- **Conversion to Hashcat possible?** No existing mode.
- **New Hashcat module required?** Yes, pending confirmation of the KDF.
- **Status here:** classified `H` (research required); JtR proves offline
  verification is possible, which is the important part.

---

## Parity (JtR and Hashcat both support these)

These converters overlap with Hashcat modes and are *not* gaps — they are useful
cross-checks for our extraction logic:

| Converter | JtR format | Hashcat mode |
| --------- | ---------- | ------------ |
| `bitcoin2john.py` | Bitcoin/Litecoin wallet.dat | 11300 |
| `electrum2john.py` | Electrum salt 1-5 | 16600 / 21700 / 21800 |
| `ethereum2john.py` | Ethereum keystore / pre-sale | 15600 / 15700 / 16300 |
| `blockchain2john.py` | Blockchain.com V1/V2 | 12700 / 15200 |
| `multibit2john.py` | MultiBit `.key` / `.aes` / `.wallet` (v3) | 22500 / 22700 / 27700 |
| `bitshares2john.py` | BitShares LevelDB checksum | 21000 (`dynamic_84`) |

Where a wallet appears in both, `wallet2hash` extracts against the **Hashcat**
encoding (verified from `module_*.c`) and cites the JtR converter as a secondary
reference.
