"""CLI behavior for export targets (hashcat / john / all / auto)."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from wallet2hash.cli import main
from tests.test_formats import make_eth_pbkdf2
from tests.test_core_multibit import make_bitcoin_core_bdb, make_multibit_classic


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ExportTargetTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, name, data):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    # -- Ethereum: supported by both ------------------------------------------

    def test_auto_prompts_when_both(self):
        path = self._write("keystore.json", make_eth_pbkdf2())
        code, out, _ = run_main([path])
        self.assertEqual(code, 0)
        self.assertIn("Suitable for:", out)
        self.assertIn("Hashcat", out)
        self.assertIn("John the Ripper", out)
        self.assertIn("--format hashcat", out)
        self.assertIn("--format john", out)
        self.assertIn("--format all", out)
        # Must not print a hash before the user chooses.
        self.assertNotIn("$ethereum$", out)

    def test_format_hashcat(self):
        path = self._write("keystore.json", make_eth_pbkdf2())
        code, out, _ = run_main([path, "--format", "hashcat"])
        self.assertEqual(code, 0)
        self.assertIn("Suitable for: Hashcat", out)
        self.assertIn("$ethereum$p*", out)

    def test_format_john(self):
        path = self._write("keystore.json", make_eth_pbkdf2())
        code, out, _ = run_main([path, "--format", "john"])
        self.assertEqual(code, 0)
        self.assertIn("Suitable for: John the Ripper", out)
        # John lines carry the filename prefix, like the *2john scripts.
        self.assertIn("keystore.json:$ethereum$p*", out)

    def test_format_all(self):
        path = self._write("keystore.json", make_eth_pbkdf2())
        code, out, _ = run_main([path, "--format", "all"])
        self.assertEqual(code, 0)
        self.assertIn("HASHCAT:", out)
        self.assertIn("JOHN THE RIPPER:", out)
        self.assertIn("$ethereum$p*", out)

    # -- MultiBit Classic .key: also supported by both ------------------------

    def test_multibit_john_export(self):
        path = self._write("mywallet.key", make_multibit_classic())
        code, out, _ = run_main([path, "--format", "john"])
        self.assertEqual(code, 0)
        self.assertIn("mywallet.key:$multibit$1*", out)

    # -- Bitcoin Core: both ----------------------------------------------------

    def test_bitcoin_core_all(self):
        path = self._write("wallet.dat", make_bitcoin_core_bdb())
        code, out, _ = run_main([path, "--format", "all"])
        self.assertEqual(code, 0)
        self.assertIn("HASHCAT:", out)
        self.assertIn("$bitcoin$", out)
        self.assertIn("JOHN THE RIPPER:", out)
        self.assertIn("wallet.dat:$bitcoin$", out)

    # -- MetaMask: Hashcat only ------------------------------------------------

    def _metamask(self):
        import base64 as b64
        return json.dumps({
            "data": b64.b64encode(os.urandom(64)).decode(),
            "iv": b64.b64encode(os.urandom(16)).decode(),
            "salt": b64.b64encode(os.urandom(32)).decode(),
            "keyMetadata": {"params": {"iterations": 10000}},
        }).encode()

    def test_hashcat_only_auto(self):
        path = self._write("vault.json", self._metamask())
        code, out, _ = run_main([path])
        self.assertEqual(code, 0)
        self.assertIn("Suitable for: Hashcat", out)
        self.assertIn("$metamask$", out)

    def test_john_fails_cleanly_for_hashcat_only(self):
        path = self._write("vault.json", self._metamask())
        code, out, err = run_main([path, "--format", "john"])
        self.assertEqual(code, 1)
        self.assertIn("not supported", err)
        self.assertIn("--format hashcat", err)

    # -- BIP-38: neither --------------------------------------------------------

    def test_unsupported_neither(self):
        path = self._write("bip38.txt", b"note: 6P" + b"1" * 37 + b"\n")
        code, out, _ = run_main([path])
        self.assertEqual(code, 1)
        self.assertIn("Suitable for: none", out)
        self.assertIn("No Hashcat or John the Ripper hash", out)

    # -- commands ---------------------------------------------------------------

    def test_list_targets(self):
        code, out, _ = run_main(["list-targets"])
        self.assertEqual(code, 0)
        self.assertIn("hashcat", out)
        self.assertIn("john", out)

    def test_self_test(self):
        code, out, _ = run_main(["self-test"])
        self.assertEqual(code, 0)
        self.assertIn("self-test OK", out)

    def test_list_formats_shows_john(self):
        code, out, _ = run_main(["list-formats"])
        self.assertEqual(code, 0)
        self.assertIn("John formats", out)
        self.assertIn("bitcoin", out)
        self.assertIn("electrum", out)


if __name__ == "__main__":
    unittest.main()
