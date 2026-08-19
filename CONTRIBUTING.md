# Contributing

The one rule that overrides everything else: **don't guess wallet formats or
cryptography.** A format is only marked supported once a synthetic fixture
proves the extraction byte-for-byte, and every handler cites the source it was
derived from.

That said, adding a wallet is small — usually a single file:

1. Create `wallet2hash/formats/<wallet>.py` with a handler subclassing
   `WalletFormat`.
2. Import it in `wallet2hash/formats/__init__.py` to register it.
3. Add a synthetic fixture and tests.
4. Add a row to `docs/SUPPORT_MATRIX.md`.

The full template (detection, KDF, cipher, authentication, source references,
fixture generation, limitations) is in
[docs/CONTRIBUTING_FORMATS.md](docs/CONTRIBUTING_FORMATS.md).

Run the suite with either:

```bash
python -m unittest discover -s tests -t .
# or
pytest
```

Custom Hashcat module proposals go under `docs/hashcat-candidates/`.
