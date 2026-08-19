"""Trust Wallet cloud backup handler (StoredKey JSON, all variants).

Trust Wallet's cloud backup (Google Drive / iCloud) is the wallet-core
``StoredKey`` JSON. Its ``crypto`` object is byte-for-byte the Web3 Secret
Storage Definition V3 construction — ``aes-128-ctr`` + ``scrypt``/``pbkdf2`` +
``keccak256(derived[16:32] || ciphertext)`` — so it cracks with the same Hashcat
modes as an Ethereum keystore (15600 / 15700).

Evidence: ``trustwallet/wallet-core`` ``src/Keystore/StoredKey.cpp`` writes a V3
keystore (``version: 3``, lowercase ``crypto``), and ``loadJson`` contains a
"Workaround for myEtherWallet files" that accepts the uppercase ``Crypto`` key.
The only Trust-Wallet-specific fields are ``type`` (``mnemonic``/``private-key``),
``name``, and ``activeAccounts``.

Legacy variants: pre-2024 backups may carry an EMPTY salt (``"salt": ""``) or
omit the ``salt`` key entirely — wallet-core treats both as an empty salt for
backward compatibility (``StoredKey.cpp`` ``loadJson``). Hashcat's Ethereum
modes lock the salt token to exactly 64 hex chars (``TOKEN_ATTR_FIXED_LENGTH``
in ``module_15600.c`` / ``module_15700.c``), so those files cannot be loaded by
Hashcat; wallet2hash still verifies them offline (scrypt/pbkdf2 with an empty
salt + MAC check) and says so instead of emitting a line Hashcat would reject.

This handler reuses the Ethereum V3 parser and only overrides detection,
legacy-salt normalization, and labelling. It never duplicates the crypto logic.
"""

from __future__ import annotations

from typing import Optional

from ..errors import VerificationUnsupportedError
from ..models import Detection, VerifyStatus
from ..registry import register
from ..verification import keccak256, pbkdf2_hmac_sha256, scrypt
from .ethereum_keystore import EthereumKeystoreFormat, _load_json, _require_hex

_TRUSTWALLET_TYPES = ("mnemonic", "private-key")
_HASHCAT_SALT_HEX = 64  # hashcat 15600/15700 require exactly 32 salt bytes (64 hex)


@register
class TrustWalletFormat(EthereumKeystoreFormat):
    format_key = "trustwallet"
    name = "Trust Wallet cloud backup"
    classification = EthereumKeystoreFormat.classification
    hashcat_modes = [15600, 15700]

    @classmethod
    def is_trust_wallet_doc(cls, doc: dict) -> bool:
        return (
            doc.get("type") in _TRUSTWALLET_TYPES
            or "activeAccounts" in doc
        )

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        try:
            doc = _load_json(data)
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None
        if not cls.is_trust_wallet_doc(doc):
            return None
        crypto = doc.get("crypto")
        if not isinstance(crypto, dict):
            return None
        if crypto.get("cipher") != "aes-128-ctr" or crypto.get("kdf") not in ("pbkdf2", "scrypt"):
            return None
        evidence = ["Trust Wallet type/activeAccounts fields", f"crypto.kdf={crypto.get('kdf')}"]
        if doc.get("type") in _TRUSTWALLET_TYPES:
            evidence.insert(0, f"type={doc['type']}")
        salt = (crypto.get("kdfparams") or {}).get("salt")
        if salt in (None, ""):
            evidence.append("legacy empty-salt backup")
        return Detection(cls.format_key, cls.name, 0.99, evidence)

    def parse(self) -> dict:
        doc = _load_json(self.data)
        crypto = doc.get("crypto")
        if isinstance(crypto, dict):
            params = crypto.get("kdfparams")
            if isinstance(params, dict) and params.get("salt") in (None, ""):
                # Legacy Trust Wallet backups: a missing/empty salt means the
                # key was derived with an empty salt (wallet-core behavior).
                params["salt"] = ""
        EthereumKeystoreFormat._validate_v3(doc)
        self._json = doc
        return doc

    def _salt(self) -> bytes:
        doc = self.parse()
        salt_hex = str((doc.get("crypto") or {}).get("kdfparams", {}).get("salt", ""))
        if not salt_hex:
            return b""
        return bytes.fromhex(_require_hex(salt_hex, "kdfparams.salt"))

    def extract_hash(self):
        doc = self.parse()
        salt_hex = str((doc.get("crypto") or {}).get("kdfparams", {}).get("salt", ""))
        if len(salt_hex) != _HASHCAT_SALT_HEX:
            # Hashcat's Ethereum Wallet modes lock the salt field to exactly
            # 64 hex chars; legacy empty-salt backups cannot be loaded there,
            # so no line is emitted (see inspect() for the explanation).
            return None
        return super().extract_hash()

    def verify_password(self, password: str) -> VerifyStatus:
        doc = self.parse()
        crypto = doc["crypto"]
        kdf = crypto["kdf"]
        params = crypto.get("kdfparams") or {}
        salt = self._salt()
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

    def inspect(self):
        inspection = super().inspect()
        inspection.wallet = "Trust Wallet"
        inspection.format = self.name
        inspection.notes = list(inspection.notes)
        if len(self._salt()) != 32:
            inspection.notes.append(
                "Legacy Trust Wallet backup with an empty salt: Hashcat modes "
                "15600/15700 require a 32-byte salt, so no hash line can be emitted "
                "for this file. Offline password verification still works via --verify."
            )
        return inspection
