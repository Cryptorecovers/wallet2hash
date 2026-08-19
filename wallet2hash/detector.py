"""Format auto-detection.

Detection is evidence-based, never filename-based. Each handler's ``detect``
inspects magic bytes, JSON keys, container structures, etc. and returns a
confidence in [0, 1]. When several handlers claim the same file, every candidate
is reported so the user — not the tool — decides.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .errors import FormatError, UnreadableFileError, UnsupportedFormatError
from .models import Detection, HashcatHash, Inspection, VerifyStatus
from .registry import WalletFormat, all_formats, get_format


def detect(data: bytes, path: str = "") -> List[Detection]:
    """Return all format candidates, sorted by confidence (highest first)."""
    results: List[Detection] = []
    for cls in all_formats():
        try:
            d = cls.detect(data, path)
        except Exception:
            continue
        if d is not None:
            results.append(d)
    results.sort(key=lambda d: d.confidence, reverse=True)
    return results


def detect_top(data: bytes, path: str = "") -> Optional[Detection]:
    results = detect(data, path)
    return results[0] if results else None


def load_file(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise UnreadableFileError(f"cannot read '{path}': {exc}") from exc


def resolve_handler(
    data: bytes,
    path: str = "",
    format_key: Optional[str] = None,
) -> Tuple[WalletFormat, Optional[List[Detection]]]:
    """Instantiate the best (or explicitly requested) handler for *data*."""
    candidates: Optional[List[Detection]] = None
    if format_key:
        cls = get_format(format_key)
        d = cls.detect(data, path)
        return cls(data, path), ([d] if d else [])
    candidates = detect(data, path)
    if not candidates:
        raise UnsupportedFormatError(
            "unrecognized file: no registered wallet format matched"
        )
    top = candidates[0]
    cls = get_format(top.format_key)
    return cls(data, path), candidates
