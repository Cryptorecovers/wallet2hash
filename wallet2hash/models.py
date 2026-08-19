"""Shared data model for wallet2hash.

These dataclasses are the single source of truth for everything the CLI prints:
detection candidates, inspection reports, extracted Hashcat hashes, and the
password-verification result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Classification(str, Enum):
    """The master-matrix classification of a wallet format."""

    EXISTING_HASHCAT = "A_EXISTING_HASHCAT"
    CONVERTIBLE_TO_GENERIC_HASHCAT = "B_CONVERTIBLE_TO_GENERIC_HASHCAT"
    CUSTOM_HASHCAT_MODULE_POSSIBLE = "C_CUSTOM_HASHCAT_MODULE_POSSIBLE"
    STANDALONE_VERIFIER_ONLY = "D_STANDALONE_VERIFIER_ONLY"
    NO_OFFLINE_VERIFIER = "E_NO_OFFLINE_VERIFIER"
    NOT_PASSWORD_ENCRYPTED = "F_NOT_PASSWORD_ENCRYPTED"
    HARDWARE_OR_REMOTE_VERIFICATION = "G_HARDWARE_OR_REMOTE_VERIFICATION"
    UNKNOWN = "H_UNKNOWN"


class VerifyStatus(str, Enum):
    """Result of an offline password check."""

    VALID = "VALID"
    INVALID = "INVALID"
    CORRUPTED = "CORRUPTED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class Detection:
    """A single candidate from auto-detection."""

    format_key: str
    name: str
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "format": self.format_key,
            "name": self.name,
            "confidence": round(self.confidence, 2),
            "evidence": list(self.evidence),
        }


@dataclass
class HashcatHash:
    """An encoded hash plus the Hashcat mode that consumes it."""

    mode: int
    mode_name: str
    hash: str

    def to_dict(self) -> Dict[str, object]:
        return {"mode": self.mode, "mode_name": self.mode_name, "hash": self.hash}


@dataclass
class JohnHash:
    """An encoded John the Ripper hash line plus the JtR format that consumes it."""

    format_name: str
    hash: str

    def to_dict(self) -> Dict[str, object]:
        return {"format": self.format_name, "hash": self.hash}


@dataclass
class PasswordVerifier:
    """The normalized, minimal password-verification material extracted from a wallet.

    This is the intermediate object between the parsers and the Hashcat/John
    exporters. It deliberately contains no private keys, seeds, or decrypted
    wallet contents — only the bytes needed to construct a crackable hash line.
    """

    wallet_type: str
    wallet_version: Optional[str] = None
    source_filename: Optional[str] = None

    kdf: Optional[str] = None
    cipher: Optional[str] = None

    salt: Optional[bytes] = None
    iterations: Optional[int] = None
    memory_cost: Optional[int] = None
    parallelism: Optional[int] = None

    iv: Optional[bytes] = None
    mac: Optional[bytes] = None
    encrypted_check_material: Optional[bytes] = None
    public_check_material: Optional[bytes] = None

    metadata: Dict[str, object] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    supported_exports: List[str] = field(default_factory=list)

    def redacted_summary(self) -> Dict[str, object]:
        """A log-safe summary: types and lengths, never the secret bytes themselves."""
        def _hex_len(v):
            return len(v) if isinstance(v, (bytes, bytearray)) else None

        return {
            "wallet_type": self.wallet_type,
            "wallet_version": self.wallet_version,
            "kdf": self.kdf,
            "cipher": self.cipher,
            "salt_bytes": _hex_len(self.salt),
            "iterations": self.iterations,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "iv_bytes": _hex_len(self.iv),
            "mac_bytes": _hex_len(self.mac),
            "encrypted_check_material_bytes": _hex_len(self.encrypted_check_material),
            "public_check_material_bytes": _hex_len(self.public_check_material),
            "warnings": list(self.warnings),
            "supported_exports": list(self.supported_exports),
        }


@dataclass
class SourceReference:
    """Traceability record for a piece of format knowledge."""

    project: str
    file: str
    function: str = ""
    commit: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "project": self.project,
            "file": self.file,
            "function": self.function,
            "commit": self.commit,
        }


@dataclass
class Inspection:
    """Everything wallet2hash knows about an artifact, without secret material."""

    wallet: str
    format: str
    version: Optional[str] = None
    encrypted: bool = False
    kdf: Optional[str] = None
    cipher: Optional[str] = None
    mac: Optional[str] = None
    offline_verification: bool = False
    classification: Classification = Classification.UNKNOWN
    hashcat: Optional[HashcatHash] = None
    notes: List[str] = field(default_factory=list)
    source_references: List[SourceReference] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "wallet": self.wallet,
            "format": self.format,
            "version": self.version,
            "encrypted": self.encrypted,
            "kdf": self.kdf,
            "cipher": self.cipher,
            "mac": self.mac,
            "offline_verification": self.offline_verification,
            "classification": self.classification.value,
            "hashcat": self.hashcat.to_dict() if self.hashcat else None,
            "notes": list(self.notes),
            "source_references": [r.to_dict() for r in self.source_references],
        }
