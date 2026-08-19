import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from wallet2hash.cli import main
from tests.test_formats import PASSWORD, make_eth_pbkdf2


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "keystore.json")
        with open(self.path, "wb") as fh:
            fh.write(make_eth_pbkdf2())

    def test_hashcat(self):
        code, out, _ = run_main([self.path, "--hashcat"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip().startswith("$ethereum$p*"))

    def test_hashcat_with_mode(self):
        code, out, _ = run_main([self.path, "--hashcat-with-mode"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip().startswith("15600:$ethereum$p*"))

    def test_json(self):
        code, out, _ = run_main(["inspect", self.path, "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["wallet"], "Ethereum")
        self.assertEqual(doc["classification"], "A_EXISTING_HASHCAT")
        self.assertEqual(doc["hashcat"]["mode"], 15600)

    def test_verify_valid(self):
        code, out, _ = run_main([self.path, "--verify", "--password", PASSWORD])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip().startswith("VALID"))

    def test_verify_invalid(self):
        code, out, _ = run_main([self.path, "--verify", "--password", "wrong"])
        self.assertEqual(code, 1)
        self.assertTrue(out.strip().startswith("INVALID"))

    def test_list_formats(self):
        code, out, _ = run_main(["--list-formats"])
        self.assertEqual(code, 0)
        self.assertIn("Ethereum", out)
        self.assertIn("Electrum", out)

    def test_list_hashcat_modes(self):
        code, out, _ = run_main(["--list-hashcat-modes"])
        self.assertEqual(code, 0)
        self.assertIn("11300", out)
        self.assertIn("15600", out)

    def test_unknown_file(self):
        p = os.path.join(self._tmp.name, "junk.bin")
        with open(p, "wb") as fh:
            fh.write(b"definitely not a wallet")
        code, _, err = run_main([p])
        self.assertEqual(code, 1)
        self.assertIn("unrecognized", err.lower())


if __name__ == "__main__":
    unittest.main()
