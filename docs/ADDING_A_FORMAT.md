# Adding a format

A new wallet is one file under `wallet2hash/formats/` plus a registration line.
Follow this checklist in order.

## 1. Research first

Verify the format against an authoritative source before writing a parser:

1. official wallet source code or documentation;
2. Hashcat `src/modules/module_*.c` and `tools/*2hashcat.py`;
3. John the Ripper Jumbo `run/*2john.py` converters.

Never guess field layouts. Record the source file, function, and (ideally) commit
in the handler's docstring and `source_references()`.

## 2. Write the handler

Subclass `WalletFormat` and set the class attributes:

```python
from ..registry import WalletFormat, register

@register
class ExampleFormat(WalletFormat):
    format_key = "example"          # unique, used by --type and list-formats
    name = "Example wallet"         # human display name
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [12345]         # [] if no Hashcat mode
    john_formats = ["example"]      # [] if no John format
```

Implement, as appropriate:

- `detect(data, path)` — return a `Detection` or `None`; use content evidence.
- `parse()` — validate and raise `FormatError` on mismatch.
- `extract_hash()` — return a `HashcatHash` (mode, name, line) or `None`.
- `extract_john()` — only override if the John line differs from the Hashcat line.
- `inspect()` — return an `Inspection` with `source_references`.
- `verify_password()` — optional; return `UNSUPPORTED` if the crypto path is not
  yet fixture-validated.

## 3. Register it

Add `from . import example  # noqa: F401` to `wallet2hash/formats/__init__.py`.
Importing the package registers the handler; that is what populates the registry.

## 4. Add a synthetic fixture and tests

Use the wallet's own code or the documented format to build a fixture with a
known password (never a real wallet with funds). Cover at minimum:

- detection;
- the exact Hashcat/John hash line;
- a wrong-password / malformed-file case.

The compatibility contract in `tests/test_compat.py` enforces that a handler
never emits a hash for a mode it does not declare.

## 5. Update the matrix

Mark the row `implemented` in `docs/SUPPORT_MATRIX.md` only after the parser,
exporters, and tests all pass.

## Template

```text
Wallet name:
Artifact:
Versions:
Detection:
Container:
KDF:
Cipher:
Authentication:
Hashcat mode(s):
John format(s):
Source references:
Test fixture generation:
Limitations:
```
