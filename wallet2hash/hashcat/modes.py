"""Verified Hashcat modes relevant to cryptocurrency wallets.

Every entry here was checked against the current Hashcat source
(``src/modules/module_*.c``) or the official example-hash list during research.
Do not add a mode from memory — verify the number, the name, and the encoded
format against ``hashcat --example-hashes`` first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class HashcatMode:
    number: int
    name: str
    encoded_format: str
    source_module: str
    notes: str = ""


# mode number -> descriptor
WALLET_MODES = {
    11300: HashcatMode(
        11300, "Bitcoin/Litecoin wallet.dat",
        "$bitcoin$<cry_master_len>$<cry_master_hex>$<cry_salt_len>$<cry_salt_hex>"
        "$<n_deriv_iterations>$<ckey_len>$<ckey_hex>$<pubkey_len>$<pubkey_hex>",
        "src/modules/module_11300.c",
        "SHA512-based KDF + AES-256-CBC; also covers Dogecoin/Dash Core and other Core-derived BDB wallets.",
    ),
    12700: HashcatMode(
        12700, "Blockchain, My Wallet (V1)",
        "$blockchain$<payload_len>$<payload_hex>",
        "src/modules/module_12700.c",
        "HMAC-SHA1 (PBKDF2) KDF, 10 rounds; AES-256-CBC; IV is the first 16 bytes of the payload.",
    ),
    15200: HashcatMode(
        15200, "Blockchain, My Wallet, V2 (also V3/V4)",
        "$blockchain$v2$<pbkdf2_iterations>$<payload_len>$<payload_hex>",
        "src/modules/module_15200.c",
        "HMAC-SHA1 (PBKDF2) KDF with per-wallet rounds; AES-256-CBC; IV is the first 16 bytes of the payload.",
    ),
    15600: HashcatMode(
        15600, "Ethereum Wallet, PBKDF2-HMAC-SHA256",
        "$ethereum$p*<c>*<salt_hex>*<ciphertext_hex>*<mac_hex>",
        "src/modules/module_15600.c",
        "UTC/JSON keystore V3, kdf=pbkdf2, cipher=aes-128-ctr.",
    ),
    15700: HashcatMode(
        15700, "Ethereum Wallet, SCRYPT",
        "$ethereum$s*<n>*<r>*<p>*<salt_hex>*<ciphertext_hex>*<mac_hex>",
        "src/modules/module_15700.c",
        "UTC/JSON keystore V3, kdf=scrypt, cipher=aes-128-ctr.",
    ),
    16300: HashcatMode(
        16300, "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
        "$ethereum$w*<encseed_hex>*<ethaddr_hex>*<bkp_hex(16 bytes)>",
        "src/modules/module_16300.c",
        "Fixed 2000 PBKDF2-HMAC-SHA256 rounds; salt = ethaddr.",
    ),
    16600: HashcatMode(
        16600, "Electrum Wallet (Salt-Type 1-3)",
        "$electrum$<1|2|3>*<iv_hex(16 bytes)>*<ct_hex(16 bytes)>",
        "src/modules/module_16600.c",
        "key = sha256(sha256(pass)); AES-256-CBC.",
    ),
    18800: HashcatMode(
        18800, "Blockchain, My Wallet, Second Password",
        "<80-char base64: bs: blob (digest32+salt16+le32 iters+crc32)>",
        "src/modules/module_18800.c",
        "Iterated SHA-256 over UUID(salt)+password; the dpasswordhash bs: blob of a legacy double-encrypted wallet, extracted verbatim.",
    ),
    21000: HashcatMode(
        21000, "BitShares v0.x - sha512(sha512_bin(pass))",
        "<128 hex>",
        "src/modules/module_21000.c",
        "Double SHA-512 of the password; extracted from the BitShares LevelDB 'checksum' field.",
    ),
    21700: HashcatMode(
        21700, "Electrum Wallet (Salt-Type 4)",
        "$electrum$4*<ephemeral_pubkey_hex(33 bytes)>*<ct_hex>*<mac_hex(32 bytes)>",
        "src/modules/module_21700.c",
        "ECIES + secp256k1 ECDH; AES-256-CBC + HMAC-SHA256.",
    ),
    21800: HashcatMode(
        21800, "Electrum Wallet (Salt-Type 5)",
        "$electrum$5*<ephemeral_pubkey_hex(33 bytes)>*<ct_hex>*<mac_hex(32 bytes)>",
        "src/modules/module_21800.c",
        "Newer Electrum ECIES variant (segwit/2fa seed derivation).",
    ),
    22500: HashcatMode(
        22500, "MultiBit Classic .key (MD5)",
        "$multibit$1*<salt_hex(8 bytes)>*<ct_hex(32 bytes)>",
        "src/modules/module_22500.c",
        "MD5-based KDF variant of MultiBit Classic encrypted keys.",
    ),
    22700: HashcatMode(
        22700, "MultiBit HD (scrypt)",
        "$multibit$2*<iv_hex(16 bytes)>*<block1_hex(16 bytes)>*<block2_hex(16 bytes)>",
        "src/modules/module_22700.c",
        "scrypt N=16384, r=8, p=1 + AES-256-CBC.",
    ),
    26600: HashcatMode(
        26600, "MetaMask Wallet (scrypt + AES-GCM tag check)",
        "$metamask$<salt_b64>$<iv_b64>$<data_b64>",
        "src/modules/module_26600.c",
        "PBKDF2-HMAC-SHA256 (10000 rounds) + AES-256-GCM; extension vault.",
    ),
    26610: HashcatMode(
        26610, "MetaMask Wallet (short data)",
        "$metamask-short$<salt_b64>$<iv_b64>$<data_b64>",
        "src/modules/module_26610.c",
        "Truncated-data variant for MetaMask extension vaults.",
    ),
    27700: HashcatMode(
        27700, "MultiBit Classic .wallet (scrypt)",
        "$multibit$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32 bytes)>",
        "src/modules/module_27700.c",
        "bitcoinj wallet container (MultiBit Classic .wallet), scrypt + AES-256-CBC.",
    ),
    28200: HashcatMode(
        28200, "Exodus Wallet (scrypt)",
        "EXODUS:<n>:<r>:<p>:<salt_b64>:<iv_b64>:<key_b64>:<tag_b64>",
        "tools/exodus2hashcat.py",
        "Exodus 'SECO' seed container, scrypt + AES-256-GCM.",
    ),
    29600: HashcatMode(
        29600, "Terra Station Wallet (AES256-CBC(PBKDF2($pass)))",
        "hex(salt16)+hex(iv16)+b64(ct80) concatenated",
        "src/modules/module_29600.c",
        "PBKDF2-HMAC-SHA1 (100 iters) + AES-256-CBC; the encrypted field of a Terra Station keys JSON entry is the hash line verbatim.",
    ),
    29800: HashcatMode(
        29800, "Bisq .wallet (scrypt)",
        "$bisq$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32 bytes)>",
        "src/modules/module_29800.c",
        "bitcoinj wallet container (Bisq), scrypt + AES-256-CBC; uses the last 2 encrypted key blocks.",
    ),
    31900: HashcatMode(
        31900, "MetaMask Mobile Wallet",
        "$metamaskMobile$<salt_b64>$<iv_hex>$<cipher_b64(32 bytes)>",
        "src/modules/module_31900.c",
        "PBKDF2-HMAC-SHA512 (5000) + AES-256-CBC; base64 salt string is the PBKDF2 salt.",
    ),
    32500: HashcatMode(
        32500, "Dogechain.info Wallet",
        "$dogechain$0*<iter>*<payload_b64>*<salt_b64>",
        "src/modules/module_32500.c",
        "PBKDF2-HMAC-SHA256(base64(sha256(pass))) + AES-256-CBC; fixed 240-byte payload.",
    ),
    34700: HashcatMode(
        34700, "Blockchain, My Wallet, Legacy Wallets",
        "$blockchain$<len>$<hex>",
        "src/modules/module_34700.c",
        "Earliest V0.0 scheme: PBKDF2-HMAC-SHA1 x1 + AES-256-OFB (m34700.pm); emitted for non-CBC-shaped V0.0 payloads.",
    ),
}

# Bitcoin raw private key modes: not password formats (they need the key + a
# known address), documented here for completeness.
RAW_KEY_MODES = {
    n: HashcatMode(n, "Bitcoin raw private key", "<WIF + address>", "src/modules/module_%d.c" % n, "Out of scope.")
    for n in list(range(28501, 28507)) + list(range(30901, 30907))
}

# Generic modes that wallet converters frequently reuse.
GENERIC_MODES = {
    1400: HashcatMode(1400, "SHA2-256", "<hex>", "src/modules/module_01400.c", "sha256(pass) brainwallets."),
    8900: HashcatMode(8900, "scrypt", "SCRYPT:<N>:<r>:<p>:<salt_b64>:<dk_b64>", "src/modules/module_08900.c", "Generic scrypt."),
    10900: HashcatMode(10900, "PBKDF2-HMAC-SHA256", "sha256:<iter>:<salt_b64>:<dk_b64>", "src/modules/module_10900.c", "Generic PBKDF2-HMAC-SHA256."),
    12000: HashcatMode(12000, "PBKDF2-HMAC-SHA1", "sha1:<iter>:<salt_b64>:<dk_b64>", "src/modules/module_12000.c", "Generic PBKDF2-HMAC-SHA1."),
    12100: HashcatMode(12100, "PBKDF2-HMAC-SHA512", "sha512:<iter>:<salt_b64>:<dk_b64>", "src/modules/module_12100.c", "Generic PBKDF2-HMAC-SHA512."),
}


def wallet_modes() -> List[HashcatMode]:
    return [WALLET_MODES[n] for n in sorted(WALLET_MODES)]


def get_mode(number: int):
    if number in WALLET_MODES:
        return WALLET_MODES[number]
    return GENERIC_MODES.get(number)
