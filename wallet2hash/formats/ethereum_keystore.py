"""Ethereum UTC/JSON keystore V3 and the pre-sale wallet JSON.

Format facts
------------
* Web3 Secret Storage Definition V3:
  https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/
* ``crypto.kdf`` is ``pbkdf2`` (Hashcat 15600) or ``scrypt`` (Hashcat 15700).
* ``crypto.cipher`` is ``aes-128-ctr``.
* The MAC authenticates the *password* without decryption:
  ``mac = keccak256(derived_key[16:32] || ciphertext)`` — this is exactly what
  Hashcat checks, so offline verification needs no AES.

Hashcat encodings (verified against ``src/modules/module_15600.c`` /
``module_15700.c`` / ``module_16300.c``):

* ``$ethereum$p*<c>*<salt>*<ciphertext>*<mac>``
* ``$ethereum$s*<n>*<r>*<p>*<salt>*<ciphertext>*<mac>``
* ``$ethereum$w*<encseed>*<ethaddr>*<bkp[:16 bytes]>``
"""

from __future__ import annotations

import json
from typing import Optional

from ..errors import FormatError, UnsupportedFormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification import keccak256, pbkdf2_hmac_sha256, scrypt


def _load_json(data: bytes) -> dict:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("not valid JSON") from exc


def _require_hex(value: str, field: str, length: Optional[int] = None) -> str:
    v = value
    if v.startswith("0x") or v.startswith("0X"):
        v = v[2:]
    if not v or any(c not in "0123456789abcdefABCDEF" for c in v):
        raise FormatError(f"field '{field}' is not hex")
    if length is not None and len(v) != length:
        raise FormatError(f"field '{field}' must be {length} hex chars")
    return v.lower()


@register
class EthereumKeystoreFormat(WalletFormat):
    format_key = "ethereum-keystore-v3"
    name = "Ethereum UTC/JSON keystore V3"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [15600, 15700]
    john_formats = ["ethereum"]

    def __init__(self, data: bytes, path: str = ""):
        super().__init__(data, path)
        self._json: Optional[dict] = None

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except FormatError:
            return None
        # Trust Wallet cloud backups carry the same V3 crypto object plus
        # Trust-Wallet-specific fields; let the dedicated handler claim them.
        if doc.get("type") in ("mnemonic", "private-key") or "activeAccounts" in doc:
            return None
        crypto = doc.get("crypto") or doc.get("Crypto")
        if not isinstance(crypto, dict):
            return None
        if crypto.get("cipher") != "aes-128-ctr":
            return None
        kdf = crypto.get("kdf")
        if kdf not in ("pbkdf2", "scrypt"):
            return None
        evidence = [
            f"crypto.cipher={crypto.get('cipher')}",
            f"crypto.kdf={kdf}",
        ]
        if crypto.get("mac"):
            evidence.append("crypto.mac present")
        return Detection(cls.format_key, cls.name, 0.98, evidence)

    def parse(self) -> dict:
        if self._json is not None:
            return self._json
        doc = _load_json(self.data)
        self._validate_v3(doc)
        self._json = doc
        return doc

    @staticmethod
    def _validate_v3(doc: dict) -> None:
        """Validate a Web3 Secret Storage V3 document (shared with subclasses
        such as the Trust Wallet handler, which normalizes before validating)."""
        crypto = doc.get("crypto")
        if not isinstance(crypto, dict) or crypto.get("cipher") != "aes-128-ctr":
            raise FormatError("not an Ethereum keystore V3 (missing crypto.aes-128-ctr)")
        kdf = crypto.get("kdf")
        if kdf not in ("pbkdf2", "scrypt"):
            raise FormatError(f"unsupported Ethereum KDF '{kdf}'")
        if "mac" not in crypto or "ciphertext" not in crypto:
            raise FormatError("keystore is missing crypto.mac or crypto.ciphertext")
        params = crypto.get("kdfparams") or {}
        if kdf == "pbkdf2" and ("c" not in params or "salt" not in params):
            raise FormatError("pbkdf2 kdfparams must contain c and salt")
        if kdf == "scrypt" and not all(k in params for k in ("n", "r", "p", "salt")):
            raise FormatError("scrypt kdfparams must contain n, r, p and salt")

    def inspect(self) -> Inspection:
        doc = self.parse()
        crypto = doc["crypto"]
        kdf = crypto["kdf"]
        params = crypto.get("kdfparams") or {}
        if kdf == "pbkdf2":
            kdf_desc = f"PBKDF2-HMAC-SHA256 ({params.get('c')} rounds)"
        else:
            kdf_desc = f"scrypt (N={params.get('n')}, r={params.get('r')}, p={params.get('p')})"
        mode = 15600 if kdf == "pbkdf2" else 15700
        hashcat = None
        try:
            hashcat = self.extract_hash()
        except FormatError:
            pass
        return Inspection(
            wallet="Ethereum",
            format=self.name,
            version=str(doc.get("version", "3")),
            encrypted=True,
            kdf=kdf_desc,
            cipher="AES-128-CTR",
            mac="keccak256(derived_key[16:32] || ciphertext)",
            offline_verification=True,
            classification=self.classification,
            hashcat=hashcat,
            source_references=[
                SourceReference("Ethereum", "web3-secret-storage", "Web3 Secret Storage Definition"),
                SourceReference("Hashcat", f"src/modules/module_{mode}.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        doc = self.parse()
        crypto = doc["crypto"]
        kdf = crypto["kdf"]
        params = crypto.get("kdfparams") or {}
        salt = _require_hex(str(params.get("salt", "")), "kdfparams.salt")
        ct = _require_hex(str(crypto.get("ciphertext", "")), "crypto.ciphertext")
        mac = _require_hex(str(crypto.get("mac", "")), "crypto.mac")
        if kdf == "pbkdf2":
            c = params.get("c")
            return HashcatHash(15600, "Ethereum Wallet, PBKDF2-HMAC-SHA256",
                               f"$ethereum$p*{c}*{salt}*{ct}*{mac}")
        n, r, p = params.get("n"), params.get("r"), params.get("p")
        return HashcatHash(15700, "Ethereum Wallet, SCRYPT",
                           f"$ethereum$s*{n}*{r}*{p}*{salt}*{ct}*{mac}")

    def verify_password(self, password: str) -> VerifyStatus:
        doc = self.parse()
        crypto = doc["crypto"]
        kdf = crypto["kdf"]
        params = crypto.get("kdfparams") or {}
        salt = bytes.fromhex(_require_hex(str(params.get("salt", "")), "kdfparams.salt"))
        ct = bytes.fromhex(_require_hex(str(crypto.get("ciphertext", "")), "crypto.ciphertext"))
        mac = bytes.fromhex(_require_hex(str(crypto.get("mac", "")), "crypto.mac"))
        pw = password.encode("utf-8")
        try:
            if kdf == "pbkdf2":
                derived = pbkdf2_hmac_sha256(pw, salt, int(params["c"]), 32)
            else:
                derived = scrypt(pw, salt, int(params["n"]), int(params["r"]), int(params["p"]), 32)
        except (VerificationUnsupportedError, ValueError) as exc:
            raise VerificationUnsupportedError(str(exc)) from exc
        if keccak256(derived[16:32] + ct) == mac:
            return VerifyStatus.VALID
        return VerifyStatus.INVALID

    def source_references(self):
        return [
            {"project": "Ethereum", "file": "Web3 Secret Storage Definition", "function": "crypto.mac"},
            {"project": "Hashcat", "file": "src/modules/module_15600.c", "function": "module_hash_decode"},
            {"project": "Hashcat", "file": "src/modules/module_15700.c", "function": "module_hash_decode"},
        ]


@register
class EthereumPresaleFormat(WalletFormat):
    format_key = "ethereum-presale"
    name = "Ethereum Pre-Sale Wallet JSON"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [16300]
    john_formats = ["ethereum"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except FormatError:
            return None
        if not all(k in doc for k in ("encseed", "ethaddr", "bkp")):
            return None
        return Detection(cls.format_key, cls.name, 0.95, ["encseed/ethaddr/bkp fields present"])

    def parse(self) -> dict:
        doc = _load_json(self.data)
        if not all(k in doc for k in ("encseed", "ethaddr", "bkp")):
            raise FormatError("not an Ethereum pre-sale wallet JSON")
        return doc

    def inspect(self) -> Inspection:
        doc = self.parse()
        return Inspection(
            wallet="Ethereum",
            format=self.name,
            encrypted=True,
            kdf="PBKDF2-HMAC-SHA256 (2000 rounds, salt=ethaddr)",
            cipher="AES-256-CBC",
            mac="bkp field (16 bytes used as check)",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("Hashcat", "src/modules/module_16300.c", "module_hash_decode"),
                SourceReference("John the Ripper", "run/ethereum2john.py", "process_presale_wallet"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        doc = self.parse()
        encseed = _require_hex(str(doc.get("encseed", "")), "encseed")
        ethaddr = _require_hex(str(doc.get("ethaddr", "")), "ethaddr", 40)
        bkp = _require_hex(str(doc.get("bkp", "")), "bkp")
        if len(bkp) < 32:
            raise FormatError("bkp must be at least 16 bytes (32 hex chars)")
        return HashcatHash(16300, "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
                           f"$ethereum$w*{encseed}*{ethaddr}*{bkp[:32]}")

    def verify_password(self, password: str) -> VerifyStatus:
        # Verification requires AES-256-CBC decryption of the encrypted seed and
        # validation of its structure; supported once an AES backend is present.
        return VerifyStatus.UNSUPPORTED
