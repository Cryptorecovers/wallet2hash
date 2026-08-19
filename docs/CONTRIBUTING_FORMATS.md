# Contributing a wallet format

A contributor normally only needs to add one file under `wallet2hash/formats/`
and it is registered automatically by `wallet2hash/formats/__init__.py`.

## The rules that cannot be relaxed

1. **No guessing.** Every field in the template below must cite an authoritative
   source (official wallet source, official docs, Hashcat `module_*.c`, JtR
   `*2john.py`, or another reputable recovery tool) — never a blog post or
   memory.
2. **No false support.** `extract_hash()` must raise or return `None` until the
   extracted value has been checked byte-for-byte against a synthetic fixture.
   `UNSUPPORTED` is always an acceptable answer.
3. **No secret material in output.** `inspect()` and `--json` must not include
   private keys, seeds, or decrypted contents.
4. **A fixture.** Every supported format needs a synthetic wallet generated with
   the wallet's own code or documented format — never a real funded wallet.

## The handler skeleton

```python
from ..models import Classification, Detection, Inspection, VerifyStatus
from ..registry import WalletFormat, register

@register
class MyWalletFormat(WalletFormat):
    format_key = "mywallet-v2"
    name = "My Wallet v2"
    classification = Classification.EXISTING_HASHCAT   # or another A–H class
    hashcat_modes = [12345]                            # [] if none

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        # evidence-based: magic bytes / JSON keys / schema / protobuf, not filename
        ...

    def parse(self): ...        # validate + cache parsed structure; raise FormatError

    def inspect(self) -> Inspection: ...   # metadata only

    def extract_hash(self): ...            # HashcatHash or None / raise UnsupportedFormatError

    def verify_password(self, password: str) -> VerifyStatus: ...
```

`detect()` returns a `Detection(format_key, name, confidence, evidence)`. If
several handlers match, the detector reports all of them sorted by confidence —
never silently picks one.

## Format template

Fill this out (it is also the basis for the SUPPORT_MATRIX row):

```
Wallet name:
Product:
Artifact:
Platform:
Versions:
Detection signature:
Container:
Encryption:
KDF:
Iterations:
Salt:
IV/nonce:
Ciphertext:
Authentication:
Offline verifier:
Hashcat compatibility:
Hashcat mode (if any):
John mode (if any):
Existing converter:
Source references:
Test fixture generation:
Limitations:
```

## Where things go

| Concern | Location |
| ------- | -------- |
| Handler | `wallet2hash/formats/<wallet>.py` |
| Registration | import the module in `wallet2hash/formats/__init__.py` |
| Mode catalogue | `wallet2hash/hashcat/modes.py` (only after verifying against `hashcat --example-hashes`) |
| Custom-module candidate | `docs/hashcat-candidates/<WALLET>.md` |
| Matrix row | `docs/SUPPORT_MATRIX.md` |
| Tests | `tests/test_formats.py` (or a new `tests/test_<wallet>.py`) |

## Verification conventions

`verify_password` returns one of:

- `VALID` / `INVALID` — the candidate was checked against the artifact's
  authentication data.
- `CORRUPTED` — the artifact is not well-formed for this format.
- `UNSUPPORTED` — the check is possible but needs an optional backend
  (AES-GCM/secp256k1/berkeleydb), or is documented but not implemented.

Raise `VerificationUnsupportedError` (from `wallet2hash.errors`) when a backend is
missing, so the CLI can explain the dependency instead of failing silently.

## Adding a new Hashcat mode to the catalogue

Never add a mode from memory. Steps:

1. `git clone https://github.com/hashcat/hashcat` and read
   `src/modules/module_<N>.c`.
2. Confirm the number, name and encoded format against
   `hashcat --example-hashes`.
3. Add a `HashcatMode` entry in `wallet2hash/hashcat/modes.py`.
4. Add a test that extracts a synthetic wallet and asserts the exact encoded
   string.
