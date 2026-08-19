"""Blockchain.com (blockchain.info) wallet handler.

Format facts (verified against ``run/blockchain2john.py`` in John the Ripper,
the reference wallet-recovery implementation's ``WalletBlockchain`` class, and
the Hashcat module ``src/modules/module_12700.c`` / ``module_15200.c``):

* V0.0/V1 wallet: the file itself is a base64 blob (no JSON envelope).
  Decoded: ``IV/salt (16) || AES-256-CBC ciphertext``, key = PBKDF2-HMAC-SHA1
  (password, salt, iterations, 32 bytes). Hashcat 12700 assumes 10 iterations;
  the reference implementation additionally tries 1 iteration and an
  AES-256-OFB scheme for the earliest v0.0 wallets. The plaintext is a JSON
  document whose first block contains ``"guid"`` / ``"sharedKey"`` /
  ``"double_enc"`` etc.
* V1 JSON export: JSON with base64 ``payload`` field (no ``version``). The
  payload is ``IV(16) || ciphertext`` with the same 10-round construction.
  Hashcat 12700.
* V2/V3/V4 wallet: JSON with ``version`` in {2,3,4}, ``pbkdf2_iterations`` and
  a base64 ``payload``. Hashcat 15200 with the wallet's iteration count.

Encoded hashes:

* ``$blockchain$<payload_len>$<payload_hex>``          (12700)
* ``$blockchain$v2$<iter>$<payload_len>$<payload_hex>`` (15200)

Password verification implements the exact constructions (PBKDF2-HMAC-SHA1 +
AES-256-CBC, ISO 10126 padding, JSON plaintext check), validated against a
public test-wallet suite (real-format encrypted wallets, no funds).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import zlib
from typing import Optional

from ..errors import FormatError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification.crypto import aes_decrypt

# Strings that appear in the first decrypted block of a real wallet.
_MATCH = re.compile(rb'"guid"|"sharedKey"|"double_enc|"dpasswordh|"metadataHD|"options"|"address_bo|"tx_notes"|"tx_names"|"keys"|"hd_wallets|"paidTo"|"tag_names"')


def _load_json(data: bytes) -> dict:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("not valid JSON") from exc


def _parse_bs_blob(value: object) -> Optional[dict]:
    """Parse a legacy Blockchain.com second-password ``bs:`` blob (mode 18800).

    Layout (verified against Hashcat ``src/modules/module_18800.c`` and its own
    test module ``tools/test_modules/m18800.pm``): the field is a base64 string
    decoding to 59 bytes: ``"bs:"`` (3) + SHA-256 digest (32) + salt (16) +
    iteration count (4, little-endian) + CRC32 of the first 55 bytes (4).
    Returns the parsed fields, or None if the value is not such a blob.
    """
    if not isinstance(value, str):
        return None
    try:
        blob = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) != 59 or blob[:3] != b"bs:":
        return None
    if zlib.crc32(blob[:55]) & 0xFFFFFFFF != struct.unpack("<I", blob[55:59])[0]:
        return None  # CRC32 mismatch — not a genuine bs: blob
    return {
        "digest": blob[3:35],
        "salt": blob[35:51],
        "iterations": struct.unpack("<I", blob[51:55])[0],
    }


def _bs_verify(password: str, blob: dict) -> bool:
    """Mode-18800 check: iterated SHA-256 over ``UUID_string + password``.

    Mirrors Hashcat's ``module_generate_hash`` exactly: the 16-byte salt is
    formatted as a UUID string, the first hash is ``sha256(uuid + pass)``, then
    ``iterations - 1`` further SHA-256 rounds.
    """
    salt = blob["salt"]
    uuid_str = "%s-%s-%s-%s-%s" % (
        salt[0:4].hex(), salt[4:6].hex(), salt[6:8].hex(),
        salt[8:10].hex(), salt[10:16].hex(),
    )
    digest = hashlib.sha256(uuid_str.encode("ascii") + password.encode("utf-8")).digest()
    for _ in range(blob["iterations"] - 1):
        digest = hashlib.sha256(digest).digest()
    return digest == blob["digest"]


def _is_plausible_plaintext(plaintext: bytes) -> bool:
    """True if decrypted bytes look like a Blockchain wallet JSON document.

    Requires JSON-ish printable content plus a known wallet marker in the
    first block (the same heuristic the reference implementation and Hashcat
    use to validate
    the password).
    """
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text.lstrip().startswith("{"):
        return False
    return bool(_MATCH.search(plaintext[:4096]))


def _decrypt_cbc(password: str, salt_iv: bytes, ciphertext: bytes, iterations: int) -> Optional[bytes]:
    key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt_iv, iterations, 32)
    try:
        decrypted = aes_decrypt("aes-256-cbc", key, salt_iv, ciphertext)
    except Exception:
        return None
    if len(decrypted) == 0:
        return None
    padding = decrypted[-1]
    # ISO 10126: last byte is the pad length, 1..16
    if 1 <= padding <= 16:
        candidate = decrypted[:-padding]
        if _is_plausible_plaintext(candidate):
            return candidate
    # Some wallets have no/odd padding; accept a plaintext match anyway.
    if _is_plausible_plaintext(decrypted):
        return decrypted
    return None


def _decrypt_ofb(password: str, salt_iv: bytes, ciphertext: bytes) -> Optional[bytes]:
    key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt_iv, 1, 32)
    try:
        decrypted = aes_decrypt("aes-256-ofb", key, salt_iv, ciphertext)
    except Exception:
        return None
    if _is_plausible_plaintext(decrypted):
        return decrypted
    return None


@register
class BlockchainWalletFormat(WalletFormat):
    format_key = "blockchain"
    name = "Blockchain.com wallet"
    classification = Classification.EXISTING_HASHCAT
    # 34700 ("Blockchain, My Wallet, Legacy Wallets") consumes the same legacy
    # lines as 12700 — it is a kernel-side reimplementation of the same
    # construction — so the V0.0/V1 extraction below is valid for both modes.
    hashcat_modes = [12700, 15200, 18800, 34700]
    john_formats = ["blockchain"]

    def __init__(self, data: bytes, path: str = ""):
        super().__init__(data, path)
        self._parsed = None
        self._variant = None

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        # JSON variants
        try:
            doc = _load_json(data)
        except FormatError:
            doc = None
        if isinstance(doc, dict):
            # Legacy second-password wallet: a directly-readable JSON document
            # carrying a self-validating ``bs:`` blob (Hashcat 18800).
            if _parse_bs_blob(doc.get("dpasswordhash")) is not None:
                return Detection(cls.format_key, cls.name, 0.93,
                                 ["legacy dpasswordhash bs: blob (mode 18800)"])
            version = str(doc.get("version", ""))
            if version in ("2", "3", "4") and "pbkdf2_iterations" in doc and "payload" in doc:
                return Detection(cls.format_key, cls.name, 0.97,
                                 [f"version={version}", "pbkdf2_iterations + payload"])
            if "payload" in doc and ("guid" in doc or "sharedKey" in doc):
                return Detection(cls.format_key, cls.name, 0.9, ["V1 payload + guid/sharedKey"])
        # V0.0/V1 raw: a pure base64 blob (the pre-JSON "My Wallet" export).
        # Heuristics mirror the reference implementation: decodes cleanly,
        # >= 32 bytes, and the
        # decoded data is high-entropy (so plain .txt dumps don't false-positive).
        try:
            stripped = re.sub(rb"[ \t\r\n\x0b\x0c]", b"", data)
            payload = base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(payload) < 32:
            return None
        if not _high_entropy(payload):
            return None
        return Detection(cls.format_key, cls.name, 0.88,
                         ["raw base64 (V0.0/V1)", "high-entropy decoded payload"])

    def parse(self):
        if self._parsed is not None:
            return self._parsed, self._variant
        try:
            doc = _load_json(self.data)
        except FormatError:
            doc = None
        if isinstance(doc, dict):
            bs = _parse_bs_blob(doc.get("dpasswordhash"))
            if bs is not None:
                self._variant = "bs"
                self._bs = bs
                self._parsed = doc
                self._payload = b""
                return doc, "bs"
            version = str(doc.get("version", ""))
            if version in ("2", "3", "4") and "pbkdf2_iterations" in doc and "payload" in doc:
                self._variant = "v2"
            elif "payload" in doc:
                self._variant = "v1"
            else:
                raise FormatError("not a Blockchain.com wallet (missing payload)")
            try:
                payload = base64.b64decode(doc["payload"], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise FormatError("invalid base64 payload") from exc
            if len(payload) < 32:
                raise FormatError("payload too short (needs at least a 16-byte IV + one block)")
            self._parsed = doc
            self._payload = payload
            return doc, self._variant
        # V0.0 raw base64 blob
        stripped = re.sub(rb"[ \t\r\n\x0b\x0c]", b"", self.data)
        try:
            payload = base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FormatError("not a Blockchain.com wallet (base64 decode failed)") from exc
        if len(payload) < 32:
            raise FormatError("payload too short")
        self._parsed = {}
        self._variant = "v0"
        self._payload = payload
        return {}, "v0"

    def inspect(self) -> Inspection:
        doc, variant = self.parse()
        if variant == "bs":
            return Inspection(
                wallet="Blockchain.com",
                format=self.name,
                version="legacy second password (double_encryption)",
                encrypted=False,
                kdf=f"iterated SHA-256 x {self._bs['iterations']}",
                cipher="— (hash only; no wallet cipher involved)",
                mac="CRC32 over the bs: blob (self-validating)",
                offline_verification=True,
                classification=self.classification,
                hashcat=self.extract_hash(),
                source_references=[
                    SourceReference("Hashcat", "src/modules/module_18800.c", "module_hash_decode"),
                    SourceReference("Hashcat", "tools/test_modules/m18800.pm", "module_generate_hash"),
                ],
            )
        if variant == "v2":
            kdf = f"HMAC-SHA1 (PBKDF2), {doc.get('pbkdf2_iterations')} rounds"
            version = f"V{doc.get('version')}"
            mode = 15200
        elif variant == "v1":
            kdf = "HMAC-SHA1 (PBKDF2), 10 rounds"
            version = "V1"
            mode = 12700
        else:
            kdf = "HMAC-SHA1 (PBKDF2), 10 rounds (V0.0 may use 1 round or OFB)"
            version = "V0.0 (raw base64)"
            mode = 12700
        return Inspection(
            wallet="Blockchain.com",
            format=self.name,
            version=version,
            encrypted=True,
            kdf=kdf,
            cipher="AES-256-CBC (OFB in earliest V0.0)",
            mac="first ciphertext block (structural check)",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("John the Ripper", "run/blockchain2john.py", "main"),
                SourceReference("Hashcat", f"src/modules/module_{mode}.c", "module_hash_decode"),
                SourceReference("Reference wallet-recovery implementation", "WalletBlockchain", "decrypt_current/decrypt_old"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        doc, variant = self.parse()
        if variant == "bs":
            # The dpasswordhash field IS the mode-18800 line: pass it verbatim.
            return HashcatHash(18800, "Blockchain, My Wallet, Second Password",
                               doc["dpasswordhash"])
        payload_hex = binascii.hexlify(self._payload).decode()
        if variant == "v2":
            iter_ = doc.get("pbkdf2_iterations")
            return HashcatHash(15200, "Blockchain, My Wallet, V2",
                               f"$blockchain$v2${iter_}${len(self._payload)}${payload_hex}")
        # V0.0/V1 legacy: the $blockchain$ line is shared by two Hashcat modes
        # with the same syntax but different constructions:
        #   12700 = PBKDF2-HMAC-SHA1 x10 + AES-256-CBC (verified against the
        #           reference implementation and m12700.pm),
        #   34700 = PBKDF2-HMAC-SHA1 x1 + AES-256-OFB (m34700.pm).
        # CBC-shaped payloads go to 12700; a payload that is not CBC-shaped is
        # the OFB scheme of the earliest v0.0 wallets, so the identical line is
        # emitted for mode 34700 (the tokenizer and verify logic of m34700.pm
        # accept exactly this form).
        if (len(self._payload) - 16) % 16 != 0:
            return HashcatHash(34700, "Blockchain, My Wallet, Legacy Wallets (OFB)",
                               f"$blockchain${len(self._payload)}${payload_hex}")
        return HashcatHash(12700, "Blockchain, My Wallet",
                           f"$blockchain${len(self._payload)}${payload_hex}")

    def verify_password(self, password: str) -> VerifyStatus:
        doc, variant = self.parse()
        if variant == "bs":
            return VerifyStatus.VALID if _bs_verify(password, self._bs) else VerifyStatus.INVALID
        salt_iv = self._payload[:16]
        ciphertext = self._payload[16:]
        if variant == "v2":
            iterations = int(doc.get("pbkdf2_iterations", 0))
            if iterations < 1:
                return VerifyStatus.CORRUPTED
            if _decrypt_cbc(password, salt_iv, ciphertext, iterations):
                return VerifyStatus.VALID
            return VerifyStatus.INVALID
        # V0.0/V1: try the three documented schemes in order: CBC/10, CBC/1,
        # OFB/1.
        if _decrypt_cbc(password, salt_iv, ciphertext, 10):
            return VerifyStatus.VALID
        if _decrypt_cbc(password, salt_iv, ciphertext, 1):
            return VerifyStatus.VALID
        if _decrypt_ofb(password, salt_iv, ciphertext):
            return VerifyStatus.VALID
        return VerifyStatus.INVALID


def _high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """Shannon entropy in bits per byte (the v0.0 sanity check)."""
    if not data:
        return False
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = -sum((c / total) * (c / total and __import__("math").log2(c / total)) for c in counts if c)
    return entropy >= threshold
