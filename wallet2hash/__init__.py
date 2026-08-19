"""wallet2hash — offline wallet format inspector and password-verification hash extractor.

The public surface is intentionally small:

* :func:`wallet2hash.detector.detect` — identify a wallet file.
* :func:`wallet2hash.registry.get_format` / ``registry.ALL_FORMATS`` — format handlers.
* :mod:`wallet2hash.cli` — the command line interface.

Everything is offline. Nothing here ever transmits wallet data, contacts a remote
service, or writes decrypted wallet contents to disk.
"""

__version__ = "0.1.0"

# Importing the package registers every built-in wallet format handler. This is
# what populates the registry used by the detector and the CLI.
from . import formats  # noqa: F401,E402

__all__ = ["__version__", "formats"]
