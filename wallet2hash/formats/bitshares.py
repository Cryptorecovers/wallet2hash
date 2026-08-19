"""BitShares wallet handler — Hashcat mode 21000 plus John formats.

BitShares v0.x stored its wallet in browser storage (Chrome IndexedDB/LevelDB,
``https_wallet.bitshares.org_0``) or SQLite. Verified against
``run/bitshares2john.py`` in John the Ripper:

* LevelDB path — a ``checksum`` marker followed by the hex of
  ``sha512(sha512(password))`` (128 hex chars). Hashcat 21000 is exactly
  ``sha512(sha512_bin(pass))``, and JtR's ``$dynamic_84$`` is the same hash:
  both consume the raw 128-hex line.
* SQLite path — the ``wallet`` table's JSON ``value`` carries an
  ``encryption_key``; the last 64 hex chars identify the wallet for John's
  ``$BitShares$0`` format.
* Backup ``.bin`` files are the whole-file hex, John ``$BitShares$1``.

Offline password verification: the 21000 hash is a plain iterated SHA-512 of
the password, so verification is a direct recompute.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

from ..errors import FormatError
from ..models import (
    Classification,
    Detection,
    HashcatHash,
    Inspection,
    JohnHash,
    SourceReference,
    VerifyStatus,
)
from ..registry import WalletFormat, register


def _sha512_sha512(password: str) -> str:
    return hashlib.sha512(hashlib.sha512(password.encode("utf-8")).digest()).hexdigest()


@register
class BitSharesFormat(WalletFormat):
    format_key = "bitshares"
    name = "BitShares wallet"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [21000]
    john_formats = ["dynamic_84", "BitShares"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        text = data.decode("utf-8", "ignore")
        if "checksum" in text.lower():
            m = re.search(rb"checksum.{0,4}([0-9a-fA-F]{128})", data)
            if m:
                return Detection(cls.format_key, cls.name, 0.9,
                                 ["'checksum' marker + 128-hex password hash"])
        if "encryption_key" in text:
            return Detection(cls.format_key, cls.name, 0.7, ["encryption_key field"])
        return None

    def _checksum_hex(self) -> Optional[str]:
        m = re.search(rb"checksum.{0,4}([0-9a-fA-F]{128})", self.data)
        return m.group(1).decode("ascii").lower() if m else None

    def _encryption_key(self) -> Optional[str]:
        text = self.data.decode("utf-8", "ignore")
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        if isinstance(doc, dict) and isinstance(doc.get("encryption_key"), str):
            return doc["encryption_key"]
        return None

    def parse(self) -> dict:
        checksum = self._checksum_hex()
        if checksum:
            return {"kind": "checksum", "hash": checksum}
        enc_key = self._encryption_key()
        if enc_key:
            return {"kind": "encryption_key", "key": enc_key[-64:]}
        raise FormatError("not a BitShares wallet (no checksum or encryption_key)")

    def inspect(self) -> Inspection:
        m = self.parse()
        if m["kind"] == "checksum":
            notes = ["21000 = sha512(sha512(pass)); John format is dynamic_84"]
        else:
            notes = ["encryption_key wallet — John $BitShares$0 only"]
        return Inspection(
            wallet="BitShares",
            format=self.name,
            encrypted=True,
            kdf="sha512(sha512(password))" if m["kind"] == "checksum" else "AES (encryption_key)",
            cipher="n/a (hash of password)" if m["kind"] == "checksum" else "AES-256",
            mac="n/a",
            offline_verification=m["kind"] == "checksum",
            classification=self.classification,
            hashcat=self.extract_hash(),
            notes=notes,
            source_references=[
                SourceReference("John the Ripper", "run/bitshares2john.py", "process_leveldb / process_file"),
                SourceReference("Hashcat", "src/modules/module_21000.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        if m["kind"] != "checksum":
            return None
        return HashcatHash(21000, "BitShares v0.x - sha512(sha512_bin(pass))", m["hash"])

    def extract_john(self) -> Optional[JohnHash]:
        m = self.parse()
        if m["kind"] == "checksum":
            return JohnHash(format_name="dynamic_84", hash=f"$dynamic_84${m['hash']}")
        return JohnHash(format_name="BitShares", hash=f"$BitShares$0*{m['key']}")

    def verify_password(self, password: str) -> VerifyStatus:
        m = self.parse()
        if m["kind"] != "checksum":
            return VerifyStatus.UNSUPPORTED
        return VerifyStatus.VALID if _sha512_sha512(password) == m["hash"] else VerifyStatus.INVALID
