"""MetaMask vault handlers: extension (26600/26610) and mobile (31900).

Format facts (verified against ``src/modules/module_26600.c`` / ``module_26610.c``
/ ``module_31900.c``, ``tools/metamask2hashcat.py``, and the public test
wallets):

Extension vault (``data``/``iv``/``salt`` + ``keyMetadata.params.iterations``):

* KDF: ``PBKDF2-HMAC-SHA256(password, salt, iterations, 32)``; cipher
  AES-256-GCM with the last 16 bytes of ``data`` as the tag.
* The module tokenizers require a 16-byte IV (24 base64 chars); vaults with a
  12-byte IV are refused because Hashcat would reject the line.
* Encoded hash (26600): ``$metamask$[rounds=N$]<salt>$<iv>$<data>``. The
  ``rounds=`` option is mandatory when iterations != 10000 (module default).
* When ``data`` exceeds 3000 chars, Hashcat's own converter emits the 26610
  short form: ``$metamask-short$[rounds=N$]<salt>$<iv>$<b64(data[:64])>``.

Mobile vault (found inside the ``vault`` field of a MetaMask mobile
``persist-root`` / LevelDB export, or as a bare JSON):

* ``salt`` (base64 string), ``iv`` (hex), ``cipher`` (base64), ``lib:
  "original"``; iterations fixed at 5000.
* KDF: ``PBKDF2-HMAC-SHA512(password, salt-string-bytes, 5000, 32)`` (the
  base64 salt string is used verbatim as the PBKDF2 salt), AES-256-CBC.
* Encoded hash (31900): ``$metamaskMobile$<salt>$<iv_hex>$<b64(cipher[:32])>``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification import pbkdf2_hmac_sha256, verify_aes_gcm
from ..verification.crypto import aes_decrypt

_IV_B64_LEN = 24  # 16-byte IV, the length the 26600/26610 tokenizers require


def _load_json(data: bytes) -> dict:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("not valid JSON") from exc


def _rounds_prefix(iterations: int) -> str:
    return f"rounds={iterations}$" if iterations != 10000 else ""


@register
class MetaMaskFormat(WalletFormat):
    format_key = "metamask"
    name = "MetaMask browser extension vault"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [26600, 26610]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except FormatError:
            return None
        if not isinstance(doc, dict):
            return None
        if all(k in doc for k in ("data", "iv", "salt")) and "crypto" not in doc and "cipher" not in doc:
            evidence = ["data/iv/salt fields", "no crypto object"]
            if isinstance(doc.get("keyMetadata"), dict):
                evidence.append("keyMetadata present")
            return Detection(cls.format_key, cls.name, 0.95, evidence)
        return None

    def parse(self) -> dict:
        doc = _load_json(self.data)
        if not all(k in doc for k in ("data", "iv", "salt")):
            raise FormatError("not a MetaMask vault (missing data/iv/salt)")
        return doc

    def _iterations(self, doc: dict) -> int:
        try:
            return int(doc["keyMetadata"]["params"]["iterations"])
        except (KeyError, TypeError, ValueError):
            return 10000

    def _module_compatible(self, doc: dict) -> bool:
        """The 26600/26610 tokenizers pin the IV at 16 bytes."""
        try:
            return len(base64.b64decode(doc["iv"], validate=True)) == 16
        except (binascii.Error, ValueError):
            return False

    def inspect(self) -> Inspection:
        doc = self.parse()
        iterations = self._iterations(doc)
        notes = []
        if iterations != 10000:
            notes.append(f"iterations={iterations} (needs rounds= prefix)")
        if not self._module_compatible(doc):
            notes.append("IV is not 16 bytes — no Hashcat mode accepts this vault")
        return Inspection(
            wallet="MetaMask",
            format=self.name,
            encrypted=True,
            kdf=f"PBKDF2-HMAC-SHA256 ({iterations} rounds)",
            cipher="AES-256-GCM",
            mac="GCM tag (last 16 bytes of data)",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            notes=notes,
            source_references=[
                SourceReference("MetaMask", "browser-passworder", "vault JSON schema"),
                SourceReference("Hashcat", "src/modules/module_26600.c", "module_hash_decode"),
                SourceReference("Hashcat", "src/modules/module_26610.c", "module_hash_decode"),
                SourceReference("Hashcat", "tools/metamask2hashcat.py", "metamask_parser"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        doc = self.parse()
        if not self._module_compatible(doc):
            return None
        salt = doc["salt"]
        iv = doc["iv"]
        data = doc["data"]
        iterations = self._iterations(doc)
        rounds = _rounds_prefix(iterations)
        if len(data) > 3000:
            # Hashcat's own converter switches to the 26610 short form here.
            data_bin = base64.b64decode(data)
            data = base64.b64encode(data_bin[:64]).decode("ascii")
            return HashcatHash(26610, "MetaMask Wallet (short)",
                               f"$metamask-short${rounds}{salt}${iv}${data}")
        return HashcatHash(26600, "MetaMask Wallet (scrypt + AES-GCM tag check)",
                           f"$metamask${rounds}{salt}${iv}${data}")

    def verify_password(self, password: str) -> VerifyStatus:
        doc = self.parse()
        try:
            salt = base64.b64decode(doc["salt"], validate=True)
            iv = base64.b64decode(doc["iv"], validate=True)
            data = base64.b64decode(doc["data"], validate=True)
        except (binascii.Error, ValueError):
            return VerifyStatus.CORRUPTED
        key = pbkdf2_hmac_sha256(password.encode("utf-8"), salt, self._iterations(doc), 32)
        try:
            if verify_aes_gcm(key, iv, data):
                return VerifyStatus.VALID
            return VerifyStatus.INVALID
        except VerificationUnsupportedError as exc:
            raise VerificationUnsupportedError(str(exc)) from exc


_MOBILE_VAULT_RE = re.compile(rb'"vault"\s*:\s*"(.*?)"\s*[,}]', re.S)


def _extract_mobile_vault(data: bytes) -> Optional[dict]:
    """Find the MetaMask mobile vault JSON inside a persist-root / LevelDB dump."""
    text = data.decode("utf-8", "ignore").replace("\\", "")
    # Directly-pasted bare mobile vault
    try:
        doc = json.loads(text)
        if isinstance(doc, dict) and "cipher" in doc and "lib" in doc:
            return doc
    except (ValueError, json.JSONDecodeError):
        pass
    m = _MOBILE_VAULT_RE.search(data)
    if m:
        try:
            doc = json.loads('{"vault": "' + m.group(1).decode("utf-8", "ignore") + '"}')["vault"]
            if isinstance(doc, dict) and "cipher" in doc:
                return doc
        except (ValueError, json.JSONDecodeError):
            pass
    # Fallback (same approach as the reference tooling): locate the JSON
    # object that holds "cipher"
    idx = text.lower().find("cipher")
    if idx >= 0:
        start = text.rfind("{", 0, idx)
        end = text.find("}", idx)
        if start >= 0 and end > start:
            try:
                doc = json.loads(text[start:end + 1])
                if isinstance(doc, dict) and "cipher" in doc:
                    return doc
            except (ValueError, json.JSONDecodeError):
                pass
    return None


@register
class MetaMaskMobileFormat(WalletFormat):
    format_key = "metamask-mobile"
    name = "MetaMask Mobile Wallet vault"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [31900]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        doc = _extract_mobile_vault(data)
        if doc is None:
            return None
        if not all(k in doc for k in ("salt", "iv", "cipher")):
            return None
        if "original" not in str(doc.get("lib", "")):
            return None
        return Detection(cls.format_key, cls.name, 0.9,
                         ["mobile vault (lib=original) with salt/iv/cipher"])

    def parse(self) -> dict:
        doc = _extract_mobile_vault(self.data)
        if doc is None:
            raise FormatError("not a MetaMask mobile vault")
        if not all(k in doc for k in ("salt", "iv", "cipher")):
            raise FormatError("MetaMask mobile vault missing salt/iv/cipher")
        if "original" not in str(doc.get("lib", "")):
            raise FormatError("MetaMask mobile vault missing lib=original")
        try:
            cipher = base64.b64decode(doc["cipher"], validate=True)
            iv = bytes.fromhex(doc["iv"])
        except (binascii.Error, ValueError) as exc:
            raise FormatError("invalid mobile vault cipher/iv") from exc
        if len(iv) != 16 or len(cipher) < 16:
            raise FormatError("mobile vault iv/cipher are the wrong size")
        return {"salt": doc["salt"], "iv": doc["iv"], "cipher": cipher}

    def inspect(self) -> Inspection:
        self.parse()
        return Inspection(
            wallet="MetaMask",
            format=self.name,
            encrypted=True,
            kdf="PBKDF2-HMAC-SHA512 (5000 rounds)",
            cipher="AES-256-CBC",
            mac="decrypted first block must be printable",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("MetaMask", "react-native-keychain / vault schema", "mobile persist-root"),
                SourceReference("Hashcat", "src/modules/module_31900.c", "module_hash_decode"),
                SourceReference("Hashcat", "tools/test_modules/m31900.pm", "module_generate_hash"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        cipher_b64 = base64.b64encode(m["cipher"][:32]).decode()
        return HashcatHash(31900, "MetaMask Mobile Wallet",
                           f"$metamaskMobile${m['salt']}${m['iv']}${cipher_b64}")

    def verify_password(self, password: str) -> VerifyStatus:
        m = self.parse()
        # The base64 salt *string* is the PBKDF2 salt (m31900.pm).
        key = __import__("hashlib").pbkdf2_hmac(
            "sha512", password.encode("utf-8"), m["salt"].encode("utf-8"), 5000, 32)
        try:
            pt = aes_decrypt("aes-256-cbc", key, bytes.fromhex(m["iv"]), m["cipher"][:32])
        except Exception:
            return VerifyStatus.CORRUPTED
        # Plaintext is the start of the HD Key Tree JSON: printable ASCII.
        try:
            pt.decode("ascii")
            if all(32 <= b < 127 or b in (9, 10, 13) for b in pt):
                return VerifyStatus.VALID
        except UnicodeDecodeError:
            pass
        return VerifyStatus.INVALID
