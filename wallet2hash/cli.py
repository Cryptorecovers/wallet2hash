"""The ``wallet2hash`` command-line interface.

``--format`` selects the *export target* (``auto``/``hashcat``/``john``/``all``);
``--type`` forces a specific wallet-format handler. The subcommand spellings
(``inspect``, ``list-formats``, ``list-targets``, ``self-test``) are accepted as
aliases for their flag forms.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .detector import load_file, resolve_handler
from .errors import (
    FormatError,
    UnreadableFileError,
    UnsupportedFormatError,
    VerificationUnsupportedError,
    Wallet2HashError,
)
from .hashcat import wallet_modes
from .models import Detection, Inspection, VerifyStatus
from .registry import list_formats

_TARGETS = ("auto", "hashcat", "john", "all")
_COMMANDS = {
    "inspect": "--inspect",
    "list-formats": "--list-formats",
    "list-hashcat-modes": "--list-hashcat-modes",
    "list-targets": "--list-targets",
    "self-test": "--self-test",
}


def _normalize_argv(argv: List[str]) -> List[str]:
    """Map ``wallet2hash <subcommand> …`` onto the equivalent flag form."""
    if argv and argv[0] in _COMMANDS:
        mapped = [_COMMANDS[argv[0]]]
        # `inspect` takes a file; the list/self-test commands take none.
        mapped.extend(argv[1:])
        return mapped
    return argv


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wallet2hash",
        description="Identify a cryptocurrency wallet file and export its offline "
                    "password-verification material as a Hashcat-compatible or "
                    "John-the-Ripper-compatible hash line.",
    )
    p.add_argument("file", nargs="?", help="path to the wallet artifact")
    p.add_argument("--format", dest="target", metavar="TARGET", default="auto",
                   choices=_TARGETS,
                   help="export target: auto, hashcat, john, or all (default: auto)")
    p.add_argument("--type", dest="format_key", metavar="FORMAT",
                   help="force a specific wallet format handler (see --list-formats)")
    p.add_argument("--json", action="store_true", help="emit structured JSON")
    p.add_argument("--inspect", action="store_true", help="show format metadata (default action)")
    p.add_argument("--hashcat", action="store_true", dest="hashcat_only",
                   help="alias for --format hashcat")
    p.add_argument("--hashcat-with-mode", action="store_true",
                   help="print 'mode:hash' for the Hashcat export")
    p.add_argument("--verify", action="store_true", help="prompt for a password and verify it")
    p.add_argument("--password", metavar="PASSWORD", dest="password",
                   help="password for --verify (use with care; prefer the prompt)")
    p.add_argument("--list-formats", action="store_true", help="list registered wallet formats")
    p.add_argument("--list-hashcat-modes", action="store_true", help="list known Hashcat wallet modes")
    p.add_argument("--list-targets", action="store_true", help="list export targets")
    p.add_argument("--self-test", action="store_true", help="run the built-in self-test")
    p.add_argument("--support-matrix", action="store_true", help="print a classification summary")
    p.add_argument("--redact", action="store_true", help="redact hash material in human output")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="store_true", help="print the version")
    return p


def _read_password(args) -> str:
    if args.password is not None:
        return args.password
    if sys.stdin.isatty():
        return getpass.getpass("Password: ")
    return sys.stdin.readline().rstrip("\n")


def _redact(hash_line: str) -> str:
    if len(hash_line) <= 12:
        return hash_line[:3] + "…"
    return hash_line[:12] + "… (redacted)"


def _john_line(handler, file: str) -> Optional[str]:
    jh = handler.extract_john()
    if jh is None:
        return None
    return f"{os.path.basename(file) or 'wallet'}:{jh.hash}"


def _detect_line(handler) -> str:
    return f"Detected wallet: {handler.name}"


def _hashcat_example(h) -> str:
    return f"hashcat -m {h.mode} hash.txt wordlist.txt"


def _john_example(jh) -> str:
    return f"john --format={jh.format_name} hash.txt"


def _emit_hashcat(handler, file: str, args, json_payload: Optional[dict] = None) -> int:
    h = handler.extract_hash()
    if h is None:
        return _fail_hashcat_unavailable(handler, file, args)
    if args.json:
        if json_payload is not None:
            json_payload["hashcat"] = h.to_dict()
            json_payload["hashcat"]["example_command"] = _hashcat_example(h)
            json_payload["suitable_for"] = ["hashcat"]
        _print_json(json_payload or {})
    else:
        print(_detect_line(handler))
        print("Suitable for: Hashcat")
        print()
        print(_redact(h.hash) if args.redact else h.hash)
        print()
        print(f"Example:\n  {_hashcat_example(h)}")
    return 0


def _emit_john(handler, file: str, args, json_payload: Optional[dict] = None) -> int:
    jh = handler.extract_john()
    if jh is None:
        return _fail_john_unavailable(handler, file, args)
    line = _john_line(handler, file)
    if args.json:
        if json_payload is not None:
            json_payload["john"] = jh.to_dict()
            json_payload["john"]["line"] = line
            json_payload["john"]["example_command"] = _john_example(jh)
            json_payload["suitable_for"] = ["john"]
        _print_json(json_payload or {})
    else:
        print(_detect_line(handler))
        print("Suitable for: John the Ripper")
        print()
        print(_redact(line) if args.redact else line)
        print()
        print(f"Example:\n  {_john_example(jh)}")
    return 0


def _fail_hashcat_unavailable(handler, file: str, args) -> int:
    if args.json:
        _print_json({"error": "Hashcat export is not supported for this wallet format.",
                     "suitable_for": handler.supported_exports()})
    else:
        print(_detect_line(handler), file=sys.stderr)
        print("Hashcat export is not supported for this wallet format.", file=sys.stderr)
        if "john" in handler.supported_exports():
            print("John the Ripper export is available.", file=sys.stderr)
            print(file=sys.stderr)
            print(f"  wallet2hash {file} --format john", file=sys.stderr)
    return 1


def _fail_john_unavailable(handler, file: str, args) -> int:
    if args.json:
        _print_json({"error": "John the Ripper export is not supported for this wallet format.",
                     "suitable_for": handler.supported_exports()})
    else:
        print(_detect_line(handler), file=sys.stderr)
        print("John the Ripper export is not supported for this wallet format.", file=sys.stderr)
        if "hashcat" in handler.supported_exports():
            print("Hashcat export is available.", file=sys.stderr)
            print(file=sys.stderr)
            print(f"  wallet2hash {file} --format hashcat", file=sys.stderr)
    return 1


def _emit_all(handler, file: str, args) -> int:
    exports = handler.supported_exports()
    if args.json:
        payload = {"file": file, "wallet": handler.name, "suitable_for": exports}
        if "hashcat" in exports:
            h = handler.extract_hash()
            payload["hashcat"] = h.to_dict() if h else None
        if "john" in exports:
            jh = handler.extract_john()
            if jh is not None:
                payload["john"] = jh.to_dict()
                payload["john"]["line"] = _john_line(handler, file)
            else:
                payload["john"] = None
        _print_json(payload)
        return 0

    if "hashcat" in exports:
        print("HASHCAT:")
        h = handler.extract_hash()
        if h is None:
            print("(no hashcat line for this variant - see --inspect for why)")
        else:
            print(_redact(h.hash) if args.redact else h.hash)
            print(f"Example: {_hashcat_example(h)}")
        print()
    if "john" in exports:
        jh = handler.extract_john()
        if jh is None:
            print("JOHN THE RIPPER:")
            print("(no john line for this variant - see --inspect for why)")
            print()
        else:
            print("JOHN THE RIPPER:")
            print(_redact(_john_line(handler, file)) if args.redact else _john_line(handler, file))
            print(f"Example: {_john_example(jh)}")
            print()
    for target in ("hashcat", "john"):
        if target not in exports:
            label = "Hashcat" if target == "hashcat" else "John the Ripper"
            print(f"{label}: unsupported for this wallet format.")
    return 0


def _print_human(inspection: Inspection, candidates: Optional[List[Detection]] = None,
                 redact: bool = False):
    print("Wallet detected")
    print("===============")
    print(f"Wallet:          {inspection.wallet}")
    print(f"Format:          {inspection.format}")
    if inspection.version:
        print(f"Version:         {inspection.version}")
    print(f"Encrypted:       {'Yes' if inspection.encrypted else 'No'}")
    if inspection.kdf:
        print(f"KDF:             {inspection.kdf}")
    if inspection.cipher:
        print(f"Cipher:          {inspection.cipher}")
    if inspection.mac:
        print(f"Authentication:  {inspection.mac}")
    print()
    print(f"Offline password verification: {'YES' if inspection.offline_verification else 'NO'}")
    print(f"Classification:  {inspection.classification.value}")
    print()
    if candidates and len(candidates) > 1:
        print("Other candidates:")
        for c in candidates[1:]:
            print(f"  - {c.name} ({c.format_key}) — confidence {c.confidence:.0%}")
        print()
    print("Hashcat")
    print("=======")
    if inspection.hashcat:
        h = inspection.hashcat
        print(f"Supported:       Yes")
        print(f"Mode:            {h.mode} ({h.mode_name})")
        print()
        print("Hash:")
        print()
        print(_redact(h.hash) if redact else h.hash)
    else:
        print("Supported:       No")
        if inspection.notes:
            print()
            for n in inspection.notes:
                print(f"Note:            {n}")
    if inspection.source_references:
        print()
        print("Source verification:")
        for r in inspection.source_references:
            loc = f"{r.project}: {r.file}" + (f" ({r.function})" if r.function else "")
            print(f"  {loc}")


def _print_json(payload: dict):
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def _self_test() -> int:
    """Run a minimal end-to-end check of the detect→parse→export pipeline.

    The fixture is built inline (no test-package import) so this works from an
    installed wheel as well as a source checkout.
    """
    import base64
    import hashlib
    import json
    import os

    from .detector import detect_top
    from .registry import get_format

    salt = os.urandom(32)
    derived = hashlib.pbkdf2_hmac("sha256", b"self-test-password", salt, 1024, 32)
    ciphertext = os.urandom(32)
    from .verification import keccak256

    doc = {
        "version": 3,
        "id": "00000000-0000-0000-0000-000000000000",
        "address": "00" * 20,
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": os.urandom(16).hex()},
            "cipher": "aes-128-ctr",
            "kdf": "pbkdf2",
            "kdfparams": {"c": 1024, "dklen": 32, "prf": "hmac-sha256", "salt": salt.hex()},
            "mac": keccak256(derived[16:32] + ciphertext).hex(),
        },
    }
    data = json.dumps(doc).encode()
    top = detect_top(data)
    if top is None or top.format_key != "ethereum-keystore-v3":
        print("FAIL: synthetic Ethereum keystore was not detected")
        return 1
    handler = get_format(top.format_key)(data)
    if handler.extract_hash() is None or handler.extract_john() is None:
        print("FAIL: Ethereum keystore did not export to both Hashcat and John")
        return 1
    print("self-test OK: detect + Hashcat export + John export all work")
    return 0


def _list_targets(args) -> int:
    targets = {
        "hashcat": "Hashcat-compatible hash line (numeric mode, e.g. 11300, 15600)",
        "john": "John the Ripper compatible hash line (named format, e.g. bitcoin, electrum)",
    }
    if args.json:
        _print_json({"targets": [{"name": k, "description": v} for k, v in targets.items()]})
    else:
        print("Export targets")
        print("--------------")
        for k, v in targets.items():
            print(f"  {k:<10} {v}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = _normalize_argv(list(sys.argv[1:] if argv is None else argv))
    args = _build_parser().parse_args(argv)

    if args.version:
        print(f"wallet2hash {__version__}")
        return 0

    if args.list_formats:
        rows = list_formats()
        if args.json:
            _print_json({"formats": rows})
        else:
            print(f"{'Wallet / Format':<34} {'Hashcat modes':<24} {'John formats'}")
            print("-" * 90)
            for r in rows:
                hc = ",".join(str(m) for m in r.get("hashcat_modes", [])) or "-"
                jr = ",".join(r.get("john_formats", [])) or "-"
                print(f"{r['name']:<34} {hc:<24} {jr}")
        return 0

    if args.list_hashcat_modes:
        modes = wallet_modes()
        if args.json:
            _print_json({"hashcat_modes": [m.__dict__ for m in modes]})
        else:
            print(f"{'Mode':<8} {'Name':<42} {'Encoded format'}")
            print("-" * 110)
            for m in modes:
                print(f"{m.number:<8} {m.name:<42} {m.encoded_format}")
        return 0

    if args.list_targets:
        return _list_targets(args)

    if args.self_test:
        return _self_test()

    if args.support_matrix:
        rows = list_formats()
        if args.json:
            _print_json({"classifications": rows})
        else:
            print("Classification summary (full matrix: docs/SUPPORT_MATRIX.md)")
            print("-" * 70)
            counts = {}
            for r in rows:
                counts[r["classification"]] = counts.get(r["classification"], 0) + 1
            for k in sorted(counts):
                print(f"  {k}: {counts[k]}")
            print()
            for r in rows:
                print(f"  [{r['classification'][0]}] {r['name']}")
        return 0

    if not args.file:
        _build_parser().print_help()
        return 2

    try:
        data = load_file(args.file)
        handler, candidates = resolve_handler(data, args.file, args.format_key)

        if args.verify:
            password = _read_password(args)
            try:
                status = handler.verify_password(password)
            except VerificationUnsupportedError as exc:
                status = VerifyStatus.UNSUPPORTED
                reason = str(exc)
            except FormatError:
                status = VerifyStatus.CORRUPTED
                reason = "file is corrupted or not the expected format"
            else:
                reason = ""
            if args.json:
                _print_json({"file": args.file, "status": status.value,
                             "format": handler.format_key, "reason": reason})
            else:
                print(status.value)
                if reason:
                    print(reason)
            return 0 if status == VerifyStatus.VALID else 1

        # Explicit inspect action.
        if args.inspect:
            inspection = handler.inspect()
            if args.json:
                _print_json({"file": args.file, **inspection.to_dict(),
                             "candidates": [c.to_dict() for c in (candidates or [])],
                             "suitable_for": handler.supported_exports()})
            else:
                _print_human(inspection, candidates, redact=args.redact)
            return 0

        # Bare-hash conveniences (kept for piping straight into Hashcat).
        if args.hashcat_with_mode:
            h = handler.extract_hash()
            if h is None:
                print("UNSUPPORTED", file=sys.stderr)
                return 1
            print(f"{h.mode}:{h.hash}")
            return 0

        if args.hashcat_only:
            h = handler.extract_hash()
            if h is None:
                print("UNSUPPORTED", file=sys.stderr)
                return 1
            print(h.hash)
            return 0

        # Export target selection.
        target = args.target or "auto"
        exports = handler.supported_exports()

        if target == "hashcat":
            return _emit_hashcat(handler, args.file, args)
        if target == "john":
            return _emit_john(handler, args.file, args)
        if target == "all":
            return _emit_all(handler, args.file, args)

        # target == "auto"
        if len(exports) == 0:
            if args.json:
                _print_json({"file": args.file, "wallet": handler.name,
                             "suitable_for": [], "supported": False})
            else:
                print(_detect_line(handler))
                print("Suitable for: none")
                print()
                print("No Hashcat or John the Ripper hash can currently be generated "
                      "for this wallet format.")
            return 1

        if len(exports) == 1:
            return _emit_hashcat(handler, args.file, args) if exports == ["hashcat"] \
                else _emit_john(handler, args.file, args)

        # Both supported: do not silently choose.
        if args.json:
            _print_json({"file": args.file, "wallet": handler.name,
                         "suitable_for": ["hashcat", "john"], "supported": True})
        else:
            print(_detect_line(handler))
            print("Suitable for:")
            print("  - Hashcat")
            print("  - John the Ripper")
            print()
            print("This wallet can be exported for both Hashcat and John the Ripper.")
            print("Please choose an output format:")
            print()
            print(f"  wallet2hash {args.file} --format hashcat")
            print(f"  wallet2hash {args.file} --format john")
            print(f"  wallet2hash {args.file} --format all")
        return 0

    except (Wallet2HashError, KeyError) as exc:
        if args.json:
            _print_json({"error": str(exc)})
        else:
            print(f"wallet2hash: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
