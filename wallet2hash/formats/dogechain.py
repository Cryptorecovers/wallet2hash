"""Dogechain.info wallet handler — Hashcat mode 32500.

Format facts (verified against ``src/modules/module_32500.c`` in Hashcat and
the reference wallet-recovery implementation's ``WalletDogechain`` class,
including the ``dogechain.wallet.aes.json.2024-*`` test wallets):

* Wallet JSON: ``guid``, ``salt`` (base64, 16 bytes), ``payload`` (base64),
  ``pbkdf2_iterations`` and optionally ``cipher`` ("AES-CBC" / "AES-GCM").
* KDF: ``PBKDF2-HMAC-SHA256(base64(sha256(password)), salt, iterations, 32)`` —
  note the password is the base64 encoding of sha256(password).
* AES-CBC: ``payload = iv(16) || ciphertext``; plaintext is the wallet JSON.
  Encoded hash (32500): ``$dogechain$0*<iter>*<payload_b64>*<salt_b64>``.
* AES-GCM: ``payload = iv(12) || tag(16) || ciphertext`` — the newer variant;
  no Hashcat mode exists for it yet, so verification only.

The older (pre-2024) dogechain wallets use a legacy payload layout without the
IV prefix; those are detected but not hash-extractable.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification.crypto import aes_decrypt, verify_aes_gcm

_MATCH = re.compile(rb'"guid"|"sharedKey"|"keys"')


def _load_json(data: bytes) -> dict:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("not valid JSON") from exc


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    pw_sha256 = hashlib.sha256(password.encode("utf-8")).digest()
    pw_b64 = base64.b64encode(pw_sha256)
    return hashlib.pbkdf2_hmac("sha256", pw_b64, salt, iterations, 32)


@register
class DogechainFormat(WalletFormat):
    format_key = "dogechain"
    name = "Dogechain.info wallet"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [32500]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except FormatError:
            return None
        if not isinstance(doc, dict):
            return None
        if all(k in doc for k in ("salt", "payload", "pbkdf2_iterations")):
            evidence = ["salt + payload + pbkdf2_iterations"]
            if "guid" in doc:
                evidence.append("guid")
            return Detection(cls.format_key, cls.name, 0.93, evidence)
        return None

    def parse(self) -> dict:
        doc = _load_json(self.data)
        if not all(k in doc for k in ("salt", "payload", "pbkdf2_iterations")):
            raise FormatError("not a Dogechain wallet (missing salt/payload/pbkdf2_iterations)")
        if ";" in str(doc.get("payload", "")):
            # Payloads containing ';' are RSA-encrypted (never downloaded in a
            # password-recoverable form); the reference tooling refuses them
            # the same way.
            raise FormatError("RSA-encrypted Dogechain payload — password recovery not possible")
        try:
            salt = base64.b64decode(doc["salt"], validate=True)
            payload = base64.b64decode(doc["payload"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FormatError("invalid base64 in Dogechain wallet") from exc
        if len(salt) != 16 or len(payload) < 28:
            raise FormatError("Dogechain wallet fields are the wrong size")
        iterations = int(doc.get("pbkdf2_iterations", 0))
        if iterations < 1:
            raise FormatError("invalid pbkdf2_iterations")
        cipher = str(doc.get("cipher", "AES-CBC")).upper()
        return {"salt": salt, "payload": payload, "iterations": iterations,
                "cipher": cipher, "doc": doc}

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="Dogechain.info",
            format=self.name,
            encrypted=True,
            kdf=f"PBKDF2-HMAC-SHA256(base64(sha256(pass))) x {m['iterations']}",
            cipher=m["cipher"],
            mac="wallet JSON structure check / GCM tag",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("Reference wallet-recovery implementation", "WalletDogechain", "CBC/GCM key derivation"),
                SourceReference("Hashcat", "src/modules/module_32500.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        if m["cipher"] != "AES-CBC":
            # The GCM payload layout (iv+tag+ct) has no matching Hashcat mode.
            return None
        # 32500 expects payload = iv(16) + CBC ciphertext in the tokenizer's
        # fixed 320-char base64 field; refuse anything that doesn't fit.
        if len(m["payload"]) != 240:
            return None
        payload_b64 = base64.b64encode(m["payload"]).decode()
        salt_b64 = base64.b64encode(m["salt"]).decode()
        return HashcatHash(32500, "Dogechain.info Wallet",
                           f"$dogechain$0*{m['iterations']}*{payload_b64}*{salt_b64}")

    def verify_password(self, password: str) -> VerifyStatus:
        m = self.parse()
        key = _derive_key(password, m["salt"], m["iterations"])
        payload = m["payload"]
        try:
            if m["cipher"] == "AES-GCM":
                iv, tag, ct = payload[:12], payload[12:28], payload[28:]
                try:
                    return VerifyStatus.VALID if verify_aes_gcm(key, iv, ct + tag) else VerifyStatus.INVALID
                except VerificationUnsupportedError:
                    raise
            # AES-CBC (ISO 10126 padding + wallet JSON markers)
            decrypted = aes_decrypt("aes-256-cbc", key, payload[:16], payload[16:])
        except VerificationUnsupportedError:
            return VerifyStatus.UNSUPPORTED
        except Exception:
            return VerifyStatus.CORRUPTED
        if not decrypted:
            return VerifyStatus.INVALID
        padding = decrypted[-1]
        candidate = decrypted[:-padding] if 1 <= padding <= 16 else decrypted
        if _is_plausible(candidate):
            return VerifyStatus.VALID
        return VerifyStatus.INVALID


def _is_plausible(plaintext: bytes) -> bool:
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text.lstrip().startswith("{"):
        return False
    return bool(_MATCH.search(plaintext[:4096]))
