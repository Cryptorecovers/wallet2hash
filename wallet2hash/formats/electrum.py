"""Electrum wallet handler.

Salt types (the naming Hashcat uses):
    * 1/2/3  -> ``key = sha256(sha256(password))`` + AES-256-CBC (mode 16600).
    * 4/5    -> ECIES: secp256k1 ECDH + AES-256-CBC + HMAC-SHA256 (21700/21800).

Extraction follows ``run/electrum2john.py`` (John the Ripper) and the Hashcat
module parsers, which were the reference converters the modes were built for:

* salt 1: wallet (JSON or Python-literal) with ``seed_version == 4``, ``seed`` is
  base64 of a 64-byte blob; IV = blob[:16], first ciphertext block = blob[16:32].
* salt 2: ``keystore.type == 'bip32'`` with ``xprv`` (or legacy
  ``master_private_keys``); blob is 128 bytes; IV = blob[:16], block = blob[16:32].
* salt 3: imported private keys; blob is 80 bytes; IV = blob[-32:-16],
  last ciphertext block = blob[-16:].
* salt 4/5: an ``xprv``/``x1``/``x2``/``x3`` field whose base64 payload begins with
  the ECIES magic ``BIE1``: ephemeral_pubkey = blob[4:37], ciphertext = blob[37:-32],
  MAC = blob[-32:]. (salt 5 is emitted when the ciphertext is truncated, as
  electrum2john does.)

Verification of salt 1/2/3 needs only sha256d + AES-256-CBC (bundled fallback).
Verification of salt 4/5 needs secp256k1 and is reported UNSUPPORTED without a
secp256k1 backend.
"""

from __future__ import annotations

import ast
import base64
import binascii
import json
from typing import Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification import aes_decrypt, sha256d
from ..verification._aes import strip_pkcs7


def _try_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8-sig"))
    except Exception:
        return None


def _try_literal(data: bytes):
    try:
        return ast.literal_eval(data.decode("utf-8-sig"))
    except Exception:
        return None


def _decode_blob(value: str) -> Optional[bytes]:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


@register
class ElectrumFormat(WalletFormat):
    format_key = "electrum"
    name = "Electrum"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [16600, 21700, 21800]
    john_formats = ["electrum"]

    def __init__(self, data: bytes, path: str = ""):
        super().__init__(data, path)
        self._parsed = None
        self._extract: Optional[dict] = None

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        # Bare base64 ECIES blob (someone extracted just the xprv string).
        try:
            if base64.b64decode(data, validate=True).startswith(b"BIE1"):
                return Detection(cls.format_key, cls.name, 0.97, ["base64 BIE1 ECIES magic"])
        except Exception:
            pass

        doc = _try_json(data)
        if doc is None:
            doc = _try_literal(data)
        if not isinstance(doc, dict):
            return None

        evidence = []
        if "use_encryption" in doc:
            evidence.append("use_encryption field")
        if isinstance(doc.get("keystore"), dict):
            evidence.append("keystore object")
        if "seed_version" in doc:
            evidence.append("seed_version field")
        if isinstance(doc.get("master_private_keys"), dict):
            evidence.append("master_private_keys object")
        if "wallet_type" in doc:
            evidence.append("wallet_type field")
        if not evidence:
            return None
        return Detection(cls.format_key, cls.name, 0.9, evidence)

    # -- parsing -----------------------------------------------------------

    def parse(self):
        if self._extract is not None:
            return self._parsed, self._extract

        doc: Optional[dict] = None
        # Case A: bare ECIES blob.
        try:
            decoded = base64.b64decode(self.data, validate=True)
            if decoded.startswith(b"BIE1"):
                self._parsed = {}
                self._extract = self._ecies_extract(decoded)
                return self._parsed, self._extract
        except Exception:
            pass

        doc = _try_json(self.data)
        if doc is None:
            doc = _try_literal(self.data)
        if not isinstance(doc, dict):
            raise FormatError("not an Electrum wallet (unparseable JSON/literal)")
        self._parsed = doc

        extract = {"kind": None}

        if doc.get("use_encryption") is False:
            self._extract = {"kind": "plain"}
            return self._parsed, self._extract

        # Legacy / old-style encrypted seed.
        if isinstance(doc.get("seed"), str):
            blob = _decode_blob(doc["seed"])
            if blob is not None and len(blob) == 64:
                extract = {"kind": "aes", "salt_type": 1, "iv": blob[:16],
                           "ct": blob[16:32], "full_ct": blob[16:]}

        keystore = doc.get("keystore") if isinstance(doc.get("keystore"), dict) else None
        if keystore is not None and extract["kind"] is None:
            ks_type = keystore.get("type")
            if ks_type == "old" and isinstance(keystore.get("seed"), str):
                blob = _decode_blob(keystore["seed"])
                if blob is not None and len(blob) == 64:
                    extract = {"kind": "aes", "salt_type": 1, "iv": blob[:16],
                               "ct": blob[16:32], "full_ct": blob[16:]}
            elif ks_type == "bip32" and isinstance(keystore.get("xprv"), str):
                extract = self._blob_extract(keystore["xprv"], default_salt_type=2, blob_len=128)
            elif ks_type == "imported":
                for privkey in keystore.get("keypairs", {}).values():
                    if not privkey:
                        continue
                    blob = _decode_blob(privkey)
                    if blob is not None and len(blob) == 80:
                        extract = {"kind": "aes", "salt_type": 3, "iv": blob[-32:-16],
                                   "ct": blob[-16:], "full_ct": blob}
                        break

        # Multisig / 2fa cosigner slots (x1/x2/x3...).
        if extract["kind"] is None:
            for i in range(1, 10):
                slot = doc.get(f"x{i}/")
                if not isinstance(slot, dict):
                    continue
                if slot.get("type") == "bip32" and isinstance(slot.get("xprv"), str):
                    extract = self._blob_extract(slot["xprv"], default_salt_type=4, blob_len=128)
                    if extract["kind"] is not None:
                        break

        # Electrum 2.0 - 2.6.4 master private keys.
        if extract["kind"] is None:
            mpks = doc.get("master_private_keys")
            if isinstance(mpks, dict) and mpks:
                xprv = next(iter(mpks.values()))
                if isinstance(xprv, str):
                    extract = self._blob_extract(xprv, default_salt_type=2, blob_len=128)

        if extract["kind"] is None:
            raise FormatError("no encrypted seed/keystore found in Electrum wallet")

        self._extract = extract
        return self._parsed, self._extract

    def _blob_extract(self, value: str, default_salt_type: int, blob_len: int) -> dict:
        blob = _decode_blob(value)
        if blob is None:
            return {"kind": None}
        if blob.startswith(b"BIE1"):
            return self._ecies_extract(blob)
        if len(blob) == blob_len:
            return {"kind": "aes", "salt_type": default_salt_type, "iv": blob[:16],
                    "ct": blob[16:32], "full_ct": blob[16:]}
        return {"kind": None}

    @staticmethod
    def _ecies_extract(blob: bytes) -> dict:
        if len(blob) < 37 + 32 + 16:
            raise FormatError("ECIES blob too short")
        ct = blob[37:-32]
        salt_type = 4
        if len(ct) > 16384:
            ct = ct[:1024]
            salt_type = 5
        return {
            "kind": "ecies",
            "salt_type": salt_type,
            "ephemeral_pubkey": blob[4:37],
            "ciphertext": ct,
            "mac": blob[-32:],
        }

    # -- reporting ---------------------------------------------------------

    def inspect(self) -> Inspection:
        doc, extract = self.parse()
        if extract.get("kind") == "plain":
            return Inspection(
                wallet="Electrum",
                format=self.name,
                encrypted=False,
                offline_verification=False,
                classification=Classification.NOT_PASSWORD_ENCRYPTED,
                notes=["use_encryption is false; this wallet has no password"],
            )
        salt_type = extract["salt_type"]
        mode = {1: 16600, 2: 16600, 3: 16600, 4: 21700, 5: 21800}.get(salt_type)
        if salt_type in (1, 2, 3):
            kdf = "sha256(sha256(password))"
            cipher = "AES-256-CBC"
            mac = "PKCS7 padding"
        else:
            kdf = "ECDH(secp256k1) -> sha512 -> iv/enc/mac keys"
            cipher = "AES-256-CBC + HMAC-SHA256"
            mac = "HMAC-SHA256"
        return Inspection(
            wallet="Electrum",
            format=self.name,
            version=f"salt-type {salt_type}",
            encrypted=True,
            kdf=kdf,
            cipher=cipher,
            mac=mac,
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            notes=[] if salt_type != 5 else ["ciphertext truncated to 1024 bytes (electrum2john behaviour)"],
            source_references=[
                SourceReference("Electrum", "electrum/crypto.py", "ecies_encrypt_message / EncodeAES_bytes"),
                SourceReference("John the Ripper", "run/electrum2john.py", "process_file"),
                SourceReference("Hashcat", f"src/modules/module_{mode}.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        _, extract = self.parse()
        if extract.get("kind") == "plain":
            return None
        if extract.get("kind") == "ecies":
            pub = binascii.hexlify(extract["ephemeral_pubkey"]).decode()
            ct = binascii.hexlify(extract["ciphertext"]).decode()
            mac = binascii.hexlify(extract["mac"]).decode()
            if extract["salt_type"] == 5:
                return HashcatHash(21800, "Electrum Wallet (Salt-Type 5)", f"$electrum$5*{pub}*{ct}*{mac}")
            return HashcatHash(21700, "Electrum Wallet (Salt-Type 4)", f"$electrum$4*{pub}*{ct}*{mac}")
        salt_type = extract["salt_type"]
        iv = binascii.hexlify(extract["iv"]).decode()
        ct = binascii.hexlify(extract["ct"]).decode()
        return HashcatHash(16600, "Electrum Wallet (Salt-Type 1-3)", f"$electrum${salt_type}*{iv}*{ct}")

    def verify_password(self, password: str) -> VerifyStatus:
        _, extract = self.parse()
        if extract.get("kind") == "plain":
            return VerifyStatus.UNSUPPORTED
        if extract.get("kind") == "ecies":
            raise VerificationUnsupportedError(
                "Electrum salt-type 4/5 verification requires a secp256k1 backend "
                "(not bundled); use Hashcat mode 21700/21800 instead"
            )
        key = sha256d(password.encode("utf-8"))
        if extract["salt_type"] == 3:
            # Only the final 16-byte block is available; the preceding ciphertext
            # block is the CBC IV for that block.
            try:
                pt = aes_decrypt("aes-256-cbc", key, extract["iv"], extract["ct"])
                strip_pkcs7(pt)
                return VerifyStatus.VALID
            except ValueError:
                return VerifyStatus.INVALID
        try:
            pt = aes_decrypt("aes-256-cbc", key, extract["iv"], extract["full_ct"])
            strip_pkcs7(pt)
            return VerifyStatus.VALID
        except ValueError:
            return VerifyStatus.INVALID
