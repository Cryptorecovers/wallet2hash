"""MultiBit Classic and MultiBit HD handlers.

Two different artifacts, two different Hashcat modes:

* **MultiBit Classic ``.key`` backup** — mode 22500 (MD5 KDF)::

      $multibit$1*<salt_hex(8 bytes)>*<ct_hex(32 bytes)>

  The file is base64 text (possibly wrapped over several lines) of the OpenSSL
  ``Salted__`` envelope: ``"Salted__"`` + 8-byte salt + AES-256-CBC ciphertext.
  Only the first two ciphertext blocks are needed.

* **MultiBit HD ``.aes`` backup** — mode 22700 (scrypt, N=16384 r=8 p=1)::

      $multibit$2*<iv_hex(16 bytes)>*<block1_hex(16 bytes)>*<block2_hex(16 bytes)>

  The file is the raw scrypt-encrypted bitcoinj wallet: a 16-byte IV followed by
  the AES-256-CBC ciphertext. ``block1`` is the first ciphertext block (decrypted
  with the stored IV, MultiBit HD >= 0.5.0) and ``block2`` reuses the leading
  16 bytes (decrypted with the hardcoded legacy IV, MultiBit HD < 0.5.0). The
  22700 kernel tries both.

Sources
-------
* John the Ripper: ``run/multibit2john.py`` — exact extraction and encoding
  for both versions.
* Reference wallet-recovery implementation: ``WalletMultiBit`` (the ``Salted__``
  base64 layout and the 3-round MD5 key schedule).
* Hashcat: ``src/modules/module_22500.c`` / ``module_22700.c`` (tokenizers) and
  ``OpenCL/m22700-pure.cl`` (scrypt + AES with the two IV alternatives).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification.crypto import aes_decrypt, scrypt


@register
class MultiBitClassicFormat(WalletFormat):
    format_key = "multibit-classic"
    name = "MultiBit Classic (.key)"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [22500]
    john_formats = ["multibit"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        text = b"".join(data.split())
        if len(text) < 12:
            return None
        try:
            head = base64.b64decode(text[:12])
        except (ValueError, binascii.Error):
            return None
        if head.startswith(b"Salted__"):
            return Detection(
                cls.format_key, cls.name, 0.95,
                ["OpenSSL 'Salted__' base64 header (MultiBit/Android key backup)"],
            )
        return None

    def parse(self) -> dict:
        text = b"".join(self.data.split())
        try:
            decoded = base64.b64decode(text)
        except (ValueError, binascii.Error) as exc:
            raise FormatError(f"not a MultiBit Classic .key file (invalid base64: {exc})") from exc
        if not decoded.startswith(b"Salted__"):
            raise FormatError("not a MultiBit Classic .key file (missing 'Salted__' header)")
        if len(decoded) < 48:
            raise FormatError("MultiBit Classic .key file is too short (needs 2 AES blocks)")
        return {"salt": decoded[8:16], "encrypted_block": decoded[16:48]}

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="MultiBit",
            format=self.name,
            encrypted=True,
            kdf="3-round MD5 key schedule (OpenSSL EVP_BytesToKey-style)",
            cipher="AES-256-CBC",
            mac="base58 / bitcoinj structure check",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("Reference wallet-recovery implementation", "WalletMultiBit.load_from_filename", "Salted__ layout + MD5 schedule"),
                SourceReference("John the Ripper", "run/multibit2john.py", "process_file"),
                SourceReference("Hashcat", "src/modules/module_22500.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        salt = binascii.hexlify(m["salt"]).decode()
        ct = binascii.hexlify(m["encrypted_block"]).decode()
        return HashcatHash(22500, "MultiBit Classic .key (MD5)", f"$multibit$1*{salt}*{ct}")

    def verify_password(self, password: str) -> VerifyStatus:
        # Reference implementation WalletMultiBit: UTF-16LE password
        # (truncated to 8-bit), 3-round MD5 key schedule, AES-256-CBC,
        # base58 WIF check.
        m = self.parse()
        pw = password.encode("utf_16_le")[::2]
        salted = pw + m["salt"]
        key1 = hashlib.md5(salted).digest()
        key2 = hashlib.md5(key1 + salted).digest()
        iv = hashlib.md5(key2 + salted).digest()
        key = key1 + key2
        try:
            b1 = aes_decrypt("aes-256-cbc", key, iv, m["encrypted_block"][:16])
            b2 = aes_decrypt("aes-256-cbc", key, iv, m["encrypted_block"][16:32])
        except Exception:
            return VerifyStatus.CORRUPTED
        b58 = set(b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        # First block: WIF starts with L/K/5/Q followed by base58 (MultiBit/MultiDoge).
        if b1[:1] in (b"L", b"K", b"5", b"Q") and all(c in b58 for c in b1[1:]):
            return VerifyStatus.VALID
        # Second block: full base58 key material (older/edge-case layouts).
        if all(c in b58 for c in b2):
            return VerifyStatus.VALID
        return VerifyStatus.INVALID


@register
class MultiBitHDFormat(WalletFormat):
    format_key = "multibit-hd"
    name = "MultiBit HD (.aes)"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [22700]
    john_formats = ["multibit"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        # The .aes payload is an encrypted bitcoinj wallet with no readable magic,
        # so detection is filename-assisted (same limitation as the reference
        # tooling and JtR).
        name = (path or "").lower()
        if "multibit" in name and ("aes" in name or "mbhd" in name):
            return Detection(cls.format_key, cls.name, 0.85, ["filename contains 'multibit' and '.aes'"])
        if name.endswith(".aes") or name.endswith(".wallet.aes"):
            return Detection(cls.format_key, cls.name, 0.6, ["'.aes' extension (filename-only evidence)"])
        return None

    def parse(self) -> dict:
        if len(self.data) < 32:
            raise FormatError("MultiBit HD .aes file is too short (needs IV + one AES block)")
        iv = self.data[0:16]
        block1 = self.data[16:32]
        block2 = self.data[0:16]  # legacy: first block encrypted with a hardcoded IV
        return {"iv": iv, "block1": block1, "block2": block2}

    def inspect(self) -> Inspection:
        self.parse()
        return Inspection(
            wallet="MultiBit",
            format=self.name,
            encrypted=True,
            kdf="scrypt (N=16384, r=8, p=1, fixed salt)",
            cipher="AES-256-CBC",
            mac="decrypted bitcoinj structure check",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("John the Ripper", "run/multibit2john.py", "process_file"),
                SourceReference("Hashcat", "src/modules/module_22700.c", "module_hash_decode"),
                SourceReference("Hashcat", "OpenCL/m22700-pure.cl", "m22700_comp"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        iv = binascii.hexlify(m["iv"]).decode()
        b1 = binascii.hexlify(m["block1"]).decode()
        b2 = binascii.hexlify(m["block2"]).decode()
        return HashcatHash(22700, "MultiBit HD (scrypt)", f"$multibit$2*{iv}*{b1}*{b2}")

    def verify_password(self, password: str) -> VerifyStatus:
        # Reference implementation WalletMultiBitHD: UTF-16BE password, scrypt
        # with the fixed bitcoinj salt, AES-256-CBC under the stored IV
        # (v0.5.0+) or the hardcoded legacy IV (< 0.5.0); the plaintext starts
        # with a bitcoinj protobuf network identifier ("org.bitcoin...").
        m = self.parse()
        pw = password.encode("utf_16_be")
        try:
            key = scrypt(pw, bytes.fromhex("3551038075a3b0c5"), 16384, 8, 1, 32)
        except VerificationUnsupportedError:
            return VerifyStatus.UNSUPPORTED
        hardcoded_iv = bytes.fromhex("a344391f538311b329548616c489723e")
        try:
            blocks = (
                aes_decrypt("aes-256-cbc", key, m["iv"], m["block1"]),
                aes_decrypt("aes-256-cbc", key, hardcoded_iv, m["block2"]),
            )
        except Exception:
            return VerifyStatus.CORRUPTED
        for block in blocks:
            if len(block) >= 6 and block[0] == 10 and block[1] < 128 and block[2:6] == b"org.":
                return VerifyStatus.VALID
        return VerifyStatus.INVALID
