"""Terra Station wallet handler — Hashcat mode 29600.

Format facts, verified against two independent authoritative sources:

1. ``terra-money/key-utils`` ``src/keystore.ts`` (the wallet's own encryptor):
   - ``salt`` = 16 random bytes, hex-encoded in the output.
   - ``key``  = ``CryptoJS.PBKDF2(password, salt, {keySize: 8, iterations: 100})``
     — crypto-js PBKDF2 defaults to HMAC-SHA1, and ``keySize: 8`` means 8
     32-bit words = 32 bytes.
   - ``iv``   = 16 random bytes, hex-encoded in the output.
   - ``AES-256-CBC`` with PKCS7 padding.
   - ``transitmessage = hex(salt) + hex(iv) + base64(ciphertext)`` concatenated
     with no separators.

2. Hashcat ``src/modules/module_29600.c`` + ``tools/test_modules/m29600.pm``:
   - the hash line is exactly that concatenated form (the module's own encoder
     does ``snprintf("%s%s%s", salt_hex, iv_hex, data_b64)``);
   - the tokenizer requires salt = 32 hex, iv = 32 hex, ciphertext = 108 base64
     chars (80 bytes);
   - the kernel decrypts the 80 bytes and accepts when the final 16 bytes are
     ``0x10`` x 16 (the PKCS7 block of a 64-byte plaintext).

3. Hashcat issue #3285 (the mode's original request, with real wallet dumps):
   - the extension stores a ``keys`` localStorage item that is a JSON array of
     ``{"name", "address", "encrypted": "<transitmessage>"}`` objects;
   - the encrypted plaintext is a 64-character hex string (the private key), so
     the ciphertext is exactly 64 + 16 = 80 bytes.

Extraction therefore passes the ``encrypted`` field through verbatim — it *is*
the mode-29600 line. The file may contain several entries, each independently
encrypted; the first is exported (each entry is its own crackable line), and
``--verify`` accepts if any entry decrypts with the password.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import List, Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification.crypto import aes_decrypt

_ENC_RE = re.compile(r"^[0-9a-f]{64}[A-Za-z0-9+/]+={0,2}$")
_HEX64 = re.compile(rb"^[0-9a-fA-F]{64}$")

# terra-money/key-utils keystore.ts: iterations = 100, keySize = 256 bits.
ITERATIONS = 100
KEY_BYTES = 32


def _is_transitmessage(value: object) -> bool:
    """True if ``value`` is a Terra Station encrypted blob (salt_hex+iv_hex+b64)."""
    if not isinstance(value, str):
        return False
    if not _ENC_RE.match(value):
        return False
    try:
        ct = base64.b64decode(value[64:], validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(ct) == 80  # 64-byte plaintext + one PKCS7 block


def _load_json(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("not valid JSON") from exc


@register
class TerraStationFormat(WalletFormat):
    format_key = "terra-station"
    name = "Terra Station wallet"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [29600]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except FormatError:
            return None
        if not isinstance(doc, list):
            return None
        entries = [e for e in doc if isinstance(e, dict) and "encrypted" in e]
        if not entries:
            return None
        if not all(_is_transitmessage(e["encrypted"]) for e in entries):
            return None
        if not all(isinstance(e.get("address"), str) for e in entries):
            return None
        evidence = [f"JSON array with {len(entries)} encrypted wallet entries"]
        if any("address" in e and str(e["address"]).startswith("terra1") for e in entries):
            evidence.append("terra1… address fields")
        return Detection(cls.format_key, cls.name, 0.95, evidence)

    def parse(self) -> List[dict]:
        doc = _load_json(self.data)
        if not isinstance(doc, list):
            raise FormatError("not a Terra Station keys file (expected a JSON array)")
        entries = [e for e in doc if isinstance(e, dict) and "encrypted" in e]
        if not entries:
            raise FormatError("not a Terra Station keys file (no encrypted entries)")
        for e in entries:
            if not _is_transitmessage(e["encrypted"]):
                raise FormatError("Terra Station entry has an invalid encrypted field")
        return entries

    def inspect(self) -> Inspection:
        entries = self.parse()
        return Inspection(
            wallet="Terra Station",
            format=self.name,
            encrypted=True,
            kdf="PBKDF2-HMAC-SHA1 x 100",
            cipher="AES-256-CBC (PKCS7)",
            mac="PKCS7 padding block + 64-char hex plaintext check",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            notes=[f"{len(entries)} independently encrypted wallet entr"
                   + ("y" if len(entries) == 1 else "ies"),
                   "each entry is its own crackable mode-29600 line"],
            source_references=[
                SourceReference("terra-money/key-utils", "src/keystore.ts", "encrypt / decrypt"),
                SourceReference("Hashcat", "src/modules/module_29600.c", "module_hash_decode / module_hash_encode"),
                SourceReference("Hashcat issue #3285", "on-disk keys localStorage format"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        entries = self.parse()
        # The encrypted field is the concatenated salt_hex + iv_hex + b64(ct)
        # that module_29600 consumes — pass it through verbatim.
        return HashcatHash(29600, "Terra Station Wallet (AES256-CBC(PBKDF2($pass)))",
                           entries[0]["encrypted"])

    def verify_password(self, password: str) -> VerifyStatus:
        entries = self.parse()
        for entry in entries:
            status = self._verify_entry(entry["encrypted"], password)
            if status == VerifyStatus.VALID:
                return VerifyStatus.VALID
            if status == VerifyStatus.CORRUPTED:
                return VerifyStatus.CORRUPTED
        return VerifyStatus.INVALID

    def _verify_entry(self, transitmessage: str, password: str) -> VerifyStatus:
        salt = bytes.fromhex(transitmessage[:32])
        iv = bytes.fromhex(transitmessage[32:64])
        ct = base64.b64decode(transitmessage[64:], validate=True)
        key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, ITERATIONS, KEY_BYTES)
        try:
            plaintext = aes_decrypt("aes-256-cbc", key, iv, ct)
        except VerificationUnsupportedError:
            return VerifyStatus.UNSUPPORTED
        except Exception:
            return VerifyStatus.CORRUPTED
        if plaintext is None or len(plaintext) != 80:
            return VerifyStatus.INVALID
        # PKCS7 block of a 64-byte plaintext: the final 16 bytes are 0x10 x 16
        # (exactly what the mode-29600 kernel checks).
        if plaintext[-16:] != b"\x10" * 16:
            return VerifyStatus.INVALID
        if not _HEX64.match(plaintext[:-16]):
            return VerifyStatus.INVALID
        return VerifyStatus.VALID
