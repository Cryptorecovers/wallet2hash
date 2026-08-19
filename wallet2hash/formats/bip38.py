"""BIP-0038 encrypted private keys.

BIP-0038 (https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) defines
passphrase-protected private keys. Two variants exist, both base58 strings
beginning with ``6P``:

* non-EC-multiplied (39 chars): ``scrypt(pass, addresshash, N=16384, r=8, p=8, 64)``
  then AES-256-ECB; correctness is confirmed by the 4-byte ``addresshash`` check.
* EC-multiplied (58 chars): additionally multiplies an intermediate point by the
  passphrase factor and validates against a stored public key.

Hashcat has no BIP-0038 mode. The reference recovery tooling verifies both
variants on the CPU, so a
standalone verifier is possible today and a custom Hashcat module (scrypt + AES +
secp256k1) is technically feasible. See ``docs/hashcat-candidates/BIP38.md``.
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import Classification, Detection, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register

_BIP38_RE = re.compile(r"6P[1-9A-HJ-NP-Za-km-z]{37,56}")


@register
class Bip38Format(WalletFormat):
    format_key = "bip38"
    name = "BIP-0038 encrypted private key"
    classification = Classification.CUSTOM_HASHCAT_MODULE_POSSIBLE
    hashcat_modes = []

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return None
        match = _BIP38_RE.search(text)
        if not match:
            return None
        token = match.group(0)
        evidence = ["base58 '6P' prefix", f"{len(token)} chars"]
        if len(token) == 39:
            evidence.append("non-EC-multiplied")
        elif len(token) == 58:
            evidence.append("EC-multiplied")
        return Detection(cls.format_key, cls.name, 0.92, evidence)

    def parse(self) -> str:
        text = self.data.decode("utf-8", errors="ignore")
        match = _BIP38_RE.search(text)
        if not match:
            from ..errors import FormatError
            raise FormatError("no BIP-0038 key found")
        return match.group(0)

    def inspect(self) -> Inspection:
        token = self.parse()
        ec_multiplied = len(token) == 58
        return Inspection(
            wallet="BIP-0038",
            format=self.name,
            version="EC-multiplied" if ec_multiplied else "non-EC-multiplied",
            encrypted=True,
            kdf="scrypt (N=16384, r=8, p=8, dkLen=64) + AES-256-ECB",
            cipher="AES-256-ECB",
            mac="4-byte addresshash / EC point validation",
            offline_verification=True,
            classification=self.classification,
            hashcat=None,
            notes=[
                "no Hashcat mode exists; a CPU verifier supports this format",
                "standalone verifier needs scrypt + AES + secp256k1",
            ],
            source_references=[
                SourceReference("BIP", "bip-0038.mediawiki", "Passphrase-protected private key"),
                SourceReference("BIP-0038", "bips/bip-0038.mediawiki", "EC-multiply + non-EC variants"),
            ],
        )

    def extract_hash(self):
        return None

    def verify_password(self, password: str) -> VerifyStatus:
        # Requires scrypt (hashlib.scrypt), AES-256-ECB and a secp256k1 point
        # multiplication. Not bundled; documented in docs/hashcat-candidates/BIP38.md.
        return VerifyStatus.UNSUPPORTED
