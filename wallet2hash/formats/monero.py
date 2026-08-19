"""Monero ``wallet.keys`` handler — John the Ripper only.

Monero wallet files (``wallet.keys``, produced by the official GUI/CLI and
Feather) are a binary container: a 16-byte salt followed by the ChaCha8 /
CryptoNight-encrypted spend key and checksum. There is **no Hashcat mode** for
Monero; John the Ripper Jumbo cracks it with its ``monero`` format.

Format facts (verified against ``run/monero2john.py`` in JtR and
``src/monero_fmt_plug.c``):

* ``monero2john.py`` hexlifies the *entire* file::

      <filename>:$monero$0*<hex of whole file>

* John's ``monero`` format derives the wallet key with CryptoNight (``cn_slow_hash``)
  and decrypts with ChaCha8, checking the stored checksum.

Extraction is a pure function of the file bytes; offline password verification
would require implementing CryptoNight, which is intentionally out of scope —
the hash line is what John consumes.
"""

from __future__ import annotations

import binascii
import math
from typing import Optional

from ..models import (
    Classification,
    Detection,
    Inspection,
    JohnHash,
    SourceReference,
    VerifyStatus,
)
from ..registry import WalletFormat, register


@register
class MoneroFormat(WalletFormat):
    format_key = "monero"
    name = "Monero wallet (.keys)"
    classification = Classification.STANDALONE_VERIFIER_ONLY
    hashcat_modes = []
    john_formats = ["monero"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        name = (path or "").lower()
        if not name.endswith(".keys"):
            return None
        # Real wallet.keys files are 512 bytes+ of high-entropy data.
        if len(data) < 512 or len(data) > 16 * 1024 * 1024:
            return None
        if not _high_entropy(data):
            return None
        return Detection(cls.format_key, cls.name, 0.85,
                         ["filename ends .keys", "high-entropy binary payload"])

    def parse(self) -> dict:
        if len(self.data) < 512:
            raise ValueError("Monero wallet.keys file is implausibly small")
        return {"hex": binascii.hexlify(self.data).decode("ascii")}

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="Monero",
            format=self.name,
            encrypted=True,
            kdf="CryptoNight (cn_slow_hash)",
            cipher="ChaCha8 (wallet keys encryption)",
            mac="stored wallet checksum",
            offline_verification=True,
            classification=self.classification,
            hashcat=None,
            notes=["No Hashcat mode exists; John the Ripper's 'monero' format cracks this line."],
            source_references=[
                SourceReference("John the Ripper", "run/monero2john.py", "process_file"),
                SourceReference("John the Ripper", "src/monero_fmt_plug.c", "monero_fmt"),
                SourceReference("Monero", "src/wallet/wallet2.cpp", "wallet_keys encryption"),
            ],
        )

    def extract_john(self) -> Optional[JohnHash]:
        m = self.parse()
        return JohnHash(format_name="monero", hash=f"$monero$0*{m['hex']}")

    def extract_hash(self):
        return None

    def verify_password(self, password: str) -> VerifyStatus:
        # CryptoNight is a memory-hard PoW hash; not implemented in pure Python.
        return VerifyStatus.UNSUPPORTED


def _high_entropy(data: bytes, threshold: float = 7.5) -> bool:
    if not data:
        return False
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts if c)
    return entropy >= threshold
