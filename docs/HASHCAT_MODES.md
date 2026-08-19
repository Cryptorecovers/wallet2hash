# Hashcat modes

Every entry below was checked against the current Hashcat source
(`src/modules/module_*.c`) or the official example-hash list during research, not
from memory. `wallet2hash/hashcat/modes.py` is the machine-readable copy of this
table.

## Wallet-specific modes

### 11300 — Bitcoin/Litecoin wallet.dat

- **Algorithm:** SHA-512 based key derivation (Bitcoin Core `nDeriveMethod`) +
  AES-256-CBC.
- **Encoded format:**
  `$bitcoin$<cry_master_len>$<cry_master_hex>$<cry_salt_len>$<cry_salt_hex>$<n_deriv_iterations>$<ckey_len>$<ckey_hex>$<pubkey_len>$<pubkey_hex>`
- **Applicable wallets:** Bitcoin Core, Litecoin Core, Dogecoin Core, Dash Core
  and other Core-derived Berkeley DB `wallet.dat` files.
- **Source module:** `src/modules/module_11300.c`.
- **Limitations:** length fields are expressed in hex characters (2 × byte
  length). `wallet2hash` reaches the `mkey` record with no dependency (a pure-Python B-tree leaf scan, with `berkeleydb` tried
  first when installed); the emitted hash carries the final two AES blocks plus
  dummy `ckey`/`pubkey` placeholders (`$2$00$2$00`), exactly like `bitcoin2john.py`.

### 12700 — Blockchain, My Wallet (V1)

- **Algorithm:** HMAC-SHA1 key derivation (10 rounds) + AES-256-CBC.
- **Encoded format:** `$blockchain$<payload_len>$<payload_hex>`.
- **Applicable wallets:** Blockchain.com / blockchain.info "My Wallet" V1.
- **Source module:** `src/modules/module_12700.c`; `OpenCL/m12700-pure.cl`.
- **Limitations:** IV is the first 16 bytes of the payload.

### 15200 — Blockchain, My Wallet V2 (also V3/V4)

- **Algorithm:** HMAC-SHA1 key derivation (per-wallet `pbkdf2_iterations`) +
  AES-256-CBC.
- **Encoded format:** `$blockchain$v2$<pbkdf2_iterations>$<payload_len>$<payload_hex>`.
- **Source module:** `src/modules/module_15200.c`.
- **Limitations:** the V3/V4 field layout is accepted by the same mode.

### 18800 — Blockchain, My Wallet Second Password

- **Algorithm:** iterated SHA-256 over `UUID_string(password_salt) + password`
  (legacy `bs:` form of the double-encryption spending password).
- **Encoded format:** a single 80-char base64 string decoding to 59 bytes:
  `"bs:" (3) ‖ digest (32) ‖ salt (16) ‖ le32(iterations) (4) ‖ crc32(first 55) (4)`.
- **Source module:** `src/modules/module_18800.c`; `tools/test_modules/m18800.pm`
  (the module's own test generator).
- **Applicable wallets:** a directly-readable Blockchain.com wallet JSON whose
  `dpasswordhash` field is this `bs:` blob (old double-encrypted wallets). The
  blob is self-validating via its CRC32, and the field is the hash line verbatim.
- **Verification:** implemented in wallet2hash (see `formats/blockchain.py`),
  mirroring `module_generate_hash` exactly.

### 15600 — Ethereum Wallet, PBKDF2-HMAC-SHA256

- **Algorithm:** PBKDF2-HMAC-SHA256 (keystore `c`) → `keccak256(dk[16:32] ‖ ct)` MAC check.
- **Encoded format:** `$ethereum$p*<c>*<salt_hex>*<ciphertext_hex>*<mac_hex>`.
- **Applicable wallets:** Ethereum UTC/JSON keystore V3 and Trust Wallet cloud
  backups (same V3 `crypto` object), `kdf=pbkdf2`, `cipher=aes-128-ctr`.
- **Source module:** `src/modules/module_15600.c`.
- **Limitations:** only the MAC is checked (no AES needed) — correct by design.
  The salt token is locked to exactly 64 hex chars, so legacy Trust Wallet
  backups with an empty salt are rejected by this mode.

### 15700 — Ethereum Wallet, SCRYPT

- **Algorithm:** scrypt (`n`,`r`,`p`) → same keccak256 MAC check.
- **Encoded format:** `$ethereum$s*<n>*<r>*<p>*<salt_hex>*<ciphertext_hex>*<mac_hex>`.
- **Note:** also applies to Trust Wallet cloud backups; the module reads the
  three scrypt digits in the order `N`, `r`, `p`.
- **Source module:** `src/modules/module_15700.c`.
- **Limitations:** same fixed 32-byte salt requirement as 15600 — legacy
  empty-salt Trust Wallet backups are not loadable here either.

### 16300 — Ethereum Pre-Sale Wallet

- **Algorithm:** PBKDF2-HMAC-SHA256, fixed 2000 rounds, salt = `ethaddr`.
- **Encoded format:** `$ethereum$w*<encseed_hex>*<ethaddr_hex>*<bkp_hex(16 bytes)>`.
- **Source module:** `src/modules/module_16300.c`.

### 16600 — Electrum Wallet (Salt-Type 1–3)

- **Algorithm:** `key = sha256(sha256(pass))` + AES-256-CBC.
- **Encoded format:** `$electrum$<1|2|3>*<iv_hex(16 bytes)>*<ct_hex(16 bytes)>`.
- **Applicable wallets:** legacy Electrum seed / xprv / imported-key encryption.
- **Source module:** `src/modules/module_16600.c`; `run/electrum2john.py`.
- **Limitations:** salt 1/2 use `IV = blob[:16]`, block `blob[16:32]`; salt 3 uses
  `IV = blob[-32:-16]`, block `blob[-16:]`.

### 21700 — Electrum Wallet (Salt-Type 4)

- **Algorithm:** ECIES — secp256k1 ECDH → sha512 → AES-256-CBC + HMAC-SHA256.
- **Encoded format:** `$electrum$4*<ephemeral_pubkey_hex(33 bytes)>*<ct_hex>*<mac_hex(32 bytes)>`.
- **Source module:** `src/modules/module_21700.c`.

### 21800 — Electrum Wallet (Salt-Type 5)

- **Algorithm:** same ECIES as 21700, but the ciphertext is truncated to 1024
  bytes (matching `electrum2john.py`).
- **Encoded format:** `$electrum$5*<ephemeral_pubkey_hex(33 bytes)>*<ct_hex>*<mac_hex(32 bytes)>`.
- **Source module:** `src/modules/module_21800.c`.

### 22500 — MultiBit Classic .key (MD5)

- **Algorithm:** MD5-based key derivation variant + AES-256-CBC.
- **Encoded format:** `$multibit$1*<salt_hex(8 bytes)>*<ct_hex(32 bytes)>`.
- **Source module:** `src/modules/module_22500.c`.

### 22700 — MultiBit HD (scrypt)

- **Algorithm:** scrypt N=16384, r=8, p=1 + AES-256-CBC.
- **Encoded format:** `$multibit$2*<iv_hex(16 bytes)>*<block1_hex(16 bytes)>*<block2_hex(16 bytes)>`.
- **Source module:** `src/modules/module_22700.c`.

### 26600 — MetaMask Wallet

- **Algorithm:** PBKDF2-HMAC-SHA256 (default 10,000 rounds) + AES-256-GCM tag check.
- **Encoded format:** `$metamask$<salt_b64>$<iv_b64>$<data_b64>` (fields verbatim).
- **Source module:** `src/modules/module_26600.c`; `OpenCL/m26600-pure.cl`.

### 26610 — MetaMask Wallet (short data)

- **Algorithm:** same as 26600 for truncated-data vaults.
- **Encoded format:** `$metamask-short$<salt_b64>$<iv_b64>$<data_b64>`.
- **Source module:** `src/modules/module_26610.c`.

### 28200 — Exodus Wallet (scrypt)

- **Algorithm:** scrypt + AES-256-GCM over the `exodus.seco` seed container.
- **Encoded format:** `EXODUS:<n>:<r>:<p>:<salt_b64>:<iv_b64>:<key_b64>:<tag_b64>`.
- **Source module:** `src/modules/module_28200.c`; `tools/exodus2hashcat.py`.

### 29800 — Bisq .wallet (scrypt)

- **Algorithm:** scrypt + AES-256-CBC over a bitcoinj wallet container (Bisq).
- **Encoded format:** `$bisq$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32 bytes)>`.
- **Applicable wallets:** Bisq `.wallet` and other scrypt-encrypted bitcoinj wallets.
- **Source module:** `src/modules/module_29800.c`; `tools/bisq2hashcat.py`.
- **Limitations:** only the `3` (bitcoinj protobuf) variant is accepted; the
  extracted data is the final 32 bytes (2 AES blocks) of the encrypted key.

### 21000 — BitShares v0.x — sha512(sha512_bin(pass))

- **Algorithm:** double SHA-512 of the password (no salt).
- **Encoded format:** `<128 hex chars>` (raw hash line).
- **Applicable wallets:** BitShares LevelDB wallet `checksum` field
  (extracted by bitshares2john.py as `$dynamic_84$`).
- **Source module:** `src/modules/module_21000.c`.

### 25500 — Stargazer Stellar Wallet XLM

- **Algorithm:** PBKDF2-HMAC-SHA256 (4096) + AES-256-GCM.
- **Encoded format:** `$stellar$<salt_b64>$<iv_b64>$<ct+tag_b64>`.
- **Source module:** `src/modules/module_25500.c`; `tools/test_modules/m25500.pm`.
- **Limitations:** **not claimed by wallet2hash.** The wallet's source
  repositories are no longer reachable (404), so the on-disk schema that maps a
  real wallet file to this hash cannot be verified. Per the no-guessing rule we
  document the mode but ship no extractor for it.

### 27700 — MultiBit Classic .wallet (scrypt)

- **Algorithm:** scrypt + AES-256-CBC over a bitcoinj wallet container.
- **Encoded format:** `$multibit$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32 bytes)>`.
- **Applicable wallets:** MultiBit Classic `.wallet` files (bitcoinj protobuf).
- **Source module:** `src/modules/module_27700.c`; `tools/test_modules/m27700.pm`.
- **Limitations:** the 32 bytes are the last two AES blocks of the encrypted
  private key; the second block must decrypt to a full `0x10` padding block.

### 29600 — Terra Station Wallet (AES-256-CBC(PBKDF2))

- **Algorithm:** PBKDF2-HMAC-SHA1 (100 iterations) + AES-256-CBC, PKCS7.
- **Encoded format:** `hex(salt16) + hex(iv16) + base64(ct80)` **concatenated
  with no separators** (172 chars) — the module encoder does
  `snprintf("%s%s%s", salt, iv, data_b64)`.
- **Source module:** `src/modules/module_29600.c`; `tools/test_modules/m29600.pm`.
- **Applicable wallets:** Terra Station extension `keys` localStorage JSON array
  (each entry `{"name", "address", "encrypted"}`), where `encrypted` is the
  concatenated form above and the plaintext is a 64-char hex private key.
- **Verification:** implemented in wallet2hash; construction cross-checked
  against `terra-money/key-utils` `src/keystore.ts` (PBKDF2-SHA1, 100 iters,
  32-byte key, AES-256-CBC) and Hashcat issue #3285 (on-disk layout).

### 31900 — MetaMask Mobile Wallet

- **Algorithm:** PBKDF2-HMAC-SHA512 (5000) + AES-256-CBC; the base64 salt string
  is used verbatim as the PBKDF2 salt.
- **Encoded format:** `$metamaskMobile$<salt_b64>$<iv_hex>$<cipher_b64(32 bytes)>`.
- **Applicable wallets:** MetaMask mobile `persist-root` / LevelDB vaults
  (`lib: "original"`), verified against public iOS + Android fixtures.
- **Source module:** `src/modules/module_31900.c`; `tools/test_modules/m31900.pm`.

### 32500 — Dogechain.info Wallet

- **Algorithm:** PBKDF2-HMAC-SHA256(base64(sha256(pass))) + AES-256-CBC.
- **Encoded format:** `$dogechain$0*<iter>*<payload_b64(240 bytes)>*<salt_b64(16 bytes)>`.
- **Applicable wallets:** dogechain.info wallet JSON exports with an IV-prefixed
  payload; verified against public 2022 + 2024 fixtures. The AES-GCM variant
  has no mode yet.
- **Source module:** `src/modules/module_32500.c`.

### 34700 — Blockchain, My Wallet, Legacy Wallets

- **Algorithm:** PBKDF2-HMAC-SHA1 with **1 iteration** + **AES-256-OFB** — the
  earliest V0.0 wallet scheme (mode 12700 is the CBC/10-iteration scheme; the
  wallet code tries CBC/10, CBC/1, then OFB/1).
- **Encoded format:** `$blockchain$<len>$<hex>` — the same legacy line syntax
  12700 consumes; the mode decides the construction. wallet2hash emits the line
  for CBC-shaped payloads as 12700 and for non-CBC-shaped (OFB) payloads as
  34700.
- **Source module:** `src/modules/module_34700.c`;
  `tools/test_modules/m34700.pm` (the module's own test generator shows the
  OFB/1-iteration construction).

### 28501–28506 / 30901–30906 — Bitcoin raw private keys

- **Algorithm:** these modes check a raw private key against a known address
  (P2PKH / P2WPKH / P2SH variants, compressed/uncompressed).
- **Not a password format:** they require the WIF/raw key + the address, and
  attack the key itself. Out of scope for wallet2hash (which extracts
  password-verification material, never private keys). Documented here for
  completeness.
- **Source modules:** `src/modules/module_2850*.c`, `module_3090*.c`.

## Generic modes wallet converters frequently reuse

| Mode | Name | Encoded format | Typical wallet use |
| ---- | ---- | -------------- | ------------------ |
| 1400 | SHA2-256 | `<hex>` | brainwallets |
| 8900 | scrypt | `SCRYPT:<N>:<r>:<p>:<salt_b64>:<dk_b64>` | generic scrypt constructions |
| 10900 | PBKDF2-HMAC-SHA256 | `sha256:<iter>:<salt_b64>:<dk_b64>` | generic PBKDF2 constructions |
| 12000 | PBKDF2-HMAC-SHA1 | `sha1:<iter>:<salt_b64>:<dk_b64>` | generic PBKDF2-SHA1 |
| 12100 | PBKDF2-HMAC-SHA512 | `sha512:<iter>:<salt_b64>:<dk_b64>` | generic PBKDF2-SHA512 |

## Gap analysis (wallet → mode)

Where converters lag behind Hashcat, or Hashcat lags behind the wallets:

1. **Monero / Cake / Feather** — no Hashcat mode at all (see JTR_GAPS).
2. **Cardano (Daedalus/Yoroi)** — no Hashcat mode (see JTR_GAPS).
3. **BIP-0038** — no Hashcat mode; scrypt+AES+secp256k1 custom module is feasible.
4. **Wasabi** — Argon2 + ChaCha20 construction; no wallet-specific mode; the
   Argon2 generic mode (9100) could form the basis of a custom module.
