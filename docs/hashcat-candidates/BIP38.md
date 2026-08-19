# Custom Hashcat module candidate: BIP-0038

- **Classification:** `C` (CUSTOM_HASHCAT_MODULE_POSSIBLE).
- **Status:** offline verification is proven (independent implementations exist);
  Hashcat has no mode.

## Exact password-verification algorithm (non-EC-multiplied)

BIP-0038 ("6P…", 39 chars) stores an AES-encrypted private key and a 4-byte
address fingerprint. Verification is:

1. Base58Check-decode the 39-char string → 43-byte payload:
   - `payload[0]` = `0x01` (version),
   - `payload[1]` = `0x42` (compressed) or `0xC0` (uncompressed),
   - `payload[2:6]` = `addresshash`,
   - `payload[6:38]` = `encryptedhalf1` (32 bytes),
   - `payload[38:70]` = `encryptedhalf2` (32 bytes).
2. `derived = scrypt(passphrase, salt=addresshash, N=16384, r=8, p=8, dkLen=64)`.
3. `derivedhalf1 = derived[0:32]`, `derivedhalf2 = derived[32:64]`.
4. `firsthalf  = AES-256-ECB-decrypt(derivedhalf2, encryptedhalf1) XOR derivedhalf1[0:16]`
5. `secondhalf = AES-256-ECB-decrypt(derivedhalf2, encryptedhalf2) XOR derivedhalf1[16:32]`
6. `privkey = firsthalf ‖ secondhalf` (32 bytes).
7. Derive the address from `privkey` (secp256k1 pubkey → `hash160` → Base58Check)
   and check `SHA256(SHA256(address))[0:4] == addresshash`.

The EC-multiplied variant (58 chars) additionally multiplies an intermediate
point by the passphrase factor (`scrypt` over `ownersalt`) and validates against a
stored public key; it needs a separate kernel path.

## Verification material

| Field | Bytes | Hex chars |
| ----- | ----- | --------- |
| flag | 1 | 2 |
| addresshash (salt) | 4 | 8 |
| encryptedhalf1 | 32 | 64 |
| encryptedhalf2 | 32 | 64 |

**Minimum bytes required:** the 69-byte decoded payload (flag + salt + two
ciphertext halves) is sufficient; the version byte and checksum are fixed.

**Early rejection:** none cheap. The address check requires deriving the public
key, which is the whole point of the check. The `0x01` version byte is constant
and provides no discrimination. Rejections happen only at the final address
comparison (4 bytes), so a GPU kernel must pay one secp256k1 point multiplication
per candidate — the same cost Hashcat already pays for Electrum 21700/21800.

## Computational bottleneck

`scrypt(N=16384, r=8, p=8)` dominates and is identical for every candidate.
AES-256-ECB (two blocks) and one secp256k1 multiplication are negligible by
comparison.

## Proposed encoded hash syntax

```
$bip38$<flag_hex(2)>$<addresshash_hex(8)>$<encryptedhalf1_hex(64)>$<encryptedhalf2_hex(64)>
```

N/r/p are fixed by the spec, so they are not carried in the line.

## Reference implementations

- Spec: <https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki>
- `wallet2hash/formats/bip38.py` — detection + inspection (no verifier yet).

## Test vectors

Required before a module can be validated (generate with the BIP-38 reference
code, not by hand):

1. known passphrase + known compressed key → decodes and validates;
2. known passphrase + known uncompressed key → decodes and validates;
3. wrong passphrase → addresshash mismatch;
4. EC-multiplied vector → exercises the second kernel path.

## Notes

- Same construction applies to Litecoin/altcoin BIP-38 forks (address-hash
  versions differ; the scrypt+AES core does not).
- Independent CPU implementations already verify this, so a standalone
  verifier is possible without any new GPU code; the custom module is an
  optimization, not a prerequisite for offline recovery.
