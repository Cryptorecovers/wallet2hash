"""The format registry and the common ``WalletFormat`` interface.

Every wallet handler subclasses :class:`WalletFormat` and registers itself in
``ALL_FORMATS``. The detector iterates the registry; the CLI asks the registry
for a specific ``--format`` handler. Parsing, Hashcat extraction and password
verification all live in one handler so they can never drift apart.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from .errors import FormatError, UnreadableFileError
from .models import Classification, Detection, HashcatHash, Inspection, JohnHash, VerifyStatus


class WalletFormat:
    """Common interface for a wallet format handler.

    Subclasses must set ``format_key``, ``name`` and ``classification``, and
    implement :meth:`parse`, :meth:`inspect`, and (when applicable)
    :meth:`extract_hash` / :meth:`verify_password`.

    ``hashcat_modes`` and ``john_formats`` declare which export targets the
    format can produce. Most wallet formats share one ``$...$`` hash-line syntax
    between Hashcat and John, so :meth:`extract_john` reuses the Hashcat line by
    default and only needs overriding when the John serialization differs.
    """

    format_key: str = ""
    name: str = ""
    classification: Classification = Classification.UNKNOWN
    hashcat_modes: List[int] = []
    john_formats: List[str] = []

    def __init__(self, data: bytes, path: str = ""):
        self.data = data
        self.path = path

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        """Return a Detection if *data* looks like this format, else ``None``."""
        raise NotImplementedError

    # -- parsing -----------------------------------------------------------

    def parse(self) -> None:
        """Validate the artifact and raise :class:`FormatError` on mismatch."""
        raise NotImplementedError

    # -- reporting ---------------------------------------------------------

    def inspect(self) -> Inspection:
        raise NotImplementedError

    def extract_hash(self) -> Optional[HashcatHash]:
        """Return the Hashcat hash, or ``None`` if no mode applies."""
        return None

    def extract_john(self) -> Optional[JohnHash]:
        """Return the John hash line, or ``None`` if no JtR format applies.

        For the common case where Hashcat and John share the same ``$...$``
        serialization, this reuses the Hashcat hash verbatim.
        """
        if not self.john_formats:
            return None
        h = self.extract_hash()
        if h is None:
            return None
        return JohnHash(format_name=self.john_formats[0], hash=h.hash)

    def supported_exports(self) -> List[str]:
        """Return the export targets this format can produce ('hashcat'/'john')."""
        exports: List[str] = []
        if self.hashcat_modes:
            exports.append("hashcat")
        if self.john_formats:
            exports.append("john")
        return exports

    def verify_password(self, password: str) -> VerifyStatus:
        """Return VALID/INVALID/CORRUPTED/UNSUPPORTED for *password*."""
        return VerifyStatus.UNSUPPORTED

    def source_references(self) -> List[dict]:
        return []


_REGISTRY: Dict[str, Type[WalletFormat]] = {}


def register(cls: Type[WalletFormat]) -> Type[WalletFormat]:
    if not cls.format_key:
        raise ValueError(f"{cls.__name__} must set a format_key")
    _REGISTRY[cls.format_key] = cls
    return cls


def get_format(format_key: str) -> Type[WalletFormat]:
    try:
        return _REGISTRY[format_key]
    except KeyError:
        raise KeyError(f"unknown format '{format_key}' (run --list-formats)")


def all_formats() -> List[Type[WalletFormat]]:
    return list(_REGISTRY.values())


def list_formats() -> List[Dict[str, object]]:
    rows = []
    for cls in sorted(_REGISTRY.values(), key=lambda c: c.format_key):
        rows.append({
            "format": cls.format_key,
            "name": cls.name,
            "classification": cls.classification.value,
            "hashcat_modes": list(cls.hashcat_modes),
            "john_formats": list(cls.john_formats),
        })
    return rows
