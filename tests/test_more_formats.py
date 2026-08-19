import base64
import hashlib
import json
import os
import struct
import unittest

from wallet2hash.detector import detect_top
from wallet2hash.models import VerifyStatus
from wallet2hash.registry import get_format
from wallet2hash.verification import keccak256
from tests.test_formats import PASSWORD, make_eth_pbkdf2, make_eth_scrypt

PASSWORD_BYTES = PASSWORD.encode()


def _scrypt_or_skip():
    """Return the scrypt function, or skip the test when no backend is available
    (stdlib-only Python without hashlib.scrypt / cryptography)."""
    try:
        from wallet2hash.verification import scrypt as _scrypt

        _scrypt(b"probe", b"salt", 2, 1, 1, 32)  # cheap smoke call
        return _scrypt
    except Exception as exc:  # noqa: BLE001 - any backend failure => skip
        raise unittest.SkipTest(f"scrypt backend unavailable: {exc}") from exc


def make_trustwallet_pbkdf2():
    doc = json.loads(make_eth_pbkdf2())
    doc["type"] = "mnemonic"
    doc["name"] = "My Wallet"
    doc["activeAccounts"] = [{"address": "0x" + "11" * 20, "coin": 60, "derivationPath": "m/44'/60'/0'/0/0"}]
    return json.dumps(doc).encode()


def make_trustwallet_scrypt():
    doc = json.loads(make_eth_scrypt())
    doc["type"] = "private-key"
    doc["name"] = "My Wallet"
    doc["activeAccounts"] = []
    return json.dumps(doc).encode()


def make_trustwallet_legacy_emptysalt(password=PASSWORD):
    """Legacy pre-2024 Trust Wallet cloud backup: scrypt n=16384 r=8 p=4 with an
    EMPTY salt ("salt": "") - a real documented variant of the StoredKey format."""
    salt = b""
    n, r, p = 16384, 8, 4
    derived = _scrypt_or_skip()(password.encode(), salt, n, r, p, 32)
    ciphertext = os.urandom(32)
    mac = keccak256(derived[16:32] + ciphertext)
    doc = {
        "version": 3,
        "type": "mnemonic",
        "id": "6b5b2c8d-19ef-4281-a70a-b88045107cff",
        "name": "Trust Wallet",
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": os.urandom(16).hex()},
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {"dklen": 32, "n": n, "r": r, "p": p, "salt": ""},
            "mac": mac.hex(),
        },
        "activeAccounts": [
            {"address": "0x" + "11" * 20, "coin": 60, "derivationPath": "m/44'/60'/0'/0/0"}
        ],
    }
    return json.dumps(doc).encode()


def make_trustwallet_legacy_nosalt(password=PASSWORD):
    """The same legacy backup, but with the 'salt' key missing entirely
    (wallet-core falls back to an empty salt). The MAC is identical because the
    key was derived with an empty salt either way."""
    doc = json.loads(make_trustwallet_legacy_emptysalt(password))
    del doc["crypto"]["kdfparams"]["salt"]
    return json.dumps(doc).encode()


def make_exodus():
    salt = os.urandom(32)
    n, r, p = 16384, 8, 1
    cipher = b"aes-256-gcm"
    blob_key_iv = os.urandom(12)
    blob_key_auth_tag = os.urandom(16)
    blob_key_key = os.urandom(32)
    blob_iv = os.urandom(12)
    blob_auth_tag = os.urandom(16)
    blob = os.urandom(96)
    blob_len = len(blob)

    metadata_size = 32 + 12 + 32 + 12 + 16 + 32 + 12 + 16  # 164
    digest = hashlib.sha256()
    digest.update(salt)
    digest.update(struct.pack(">LLL", n, r, p))
    digest.update(cipher.ljust(32, b"\x00"))
    digest.update(blob_key_iv)
    digest.update(blob_key_auth_tag)
    digest.update(blob_key_key)
    digest.update(blob_iv)
    digest.update(blob_auth_tag)
    digest.update(bytes(256 - metadata_size))
    digest.update(struct.pack(">L", blob_len))
    digest.update(blob)
    checksum = digest.digest()

    version_tag = b"seco-v0-scrypt-aes"
    app_name = b"Exodus"
    app_version = b"24.1.1"
    header = struct.pack(">4sL4x", b"SECO", 0)
    header += struct.pack(">B", len(version_tag)) + version_tag
    header += struct.pack(">B", len(app_name)) + app_name
    header += struct.pack(">B", len(app_version)) + app_version
    header = header.ljust(224, b"\x00")

    metadata = salt + struct.pack(">LLL", n, r, p) + cipher.ljust(32, b"\x00")
    metadata += blob_key_iv + blob_key_auth_tag + blob_key_key
    metadata += blob_iv + blob_auth_tag
    metadata = metadata.ljust(256, b"\x00")

    return (
        header
        + checksum
        + metadata
        + struct.pack(">L", blob_len)
        + blob
    )


class TrustWalletTests(unittest.TestCase):
    def test_detect_extract_pbkdf2(self):
        data = make_trustwallet_pbkdf2()
        self.assertEqual(detect_top(data).format_key, "trustwallet")
        h = get_format("trustwallet")(data).extract_hash()
        self.assertEqual(h.mode, 15600)
        self.assertTrue(h.hash.startswith("$ethereum$p*"))

    def test_detect_extract_scrypt(self):
        data = make_trustwallet_scrypt()
        self.assertEqual(detect_top(data).format_key, "trustwallet")
        h = get_format("trustwallet")(data).extract_hash()
        self.assertEqual(h.mode, 15700)
        self.assertTrue(h.hash.startswith("$ethereum$s*"))

    def test_verify(self):
        handler = get_format("trustwallet")(make_trustwallet_pbkdf2())
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("nope"), VerifyStatus.INVALID)

    def test_does_not_collide_with_ethereum(self):
        # A Trust Wallet backup must route to trustwallet, not ethereum-keystore-v3.
        data = make_trustwallet_pbkdf2()
        self.assertEqual(detect_top(data).format_key, "trustwallet")
        self.assertNotEqual(detect_top(data).format_key, "ethereum-keystore-v3")

    def test_legacy_emptysalt_verify(self):
        data = make_trustwallet_legacy_emptysalt()
        self.assertEqual(detect_top(data).format_key, "trustwallet")
        handler = get_format("trustwallet")(data)
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("wrong password"), VerifyStatus.INVALID)

    def test_legacy_nosalt_verify(self):
        data = make_trustwallet_legacy_nosalt()
        self.assertEqual(detect_top(data).format_key, "trustwallet")
        handler = get_format("trustwallet")(data)
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("wrong password"), VerifyStatus.INVALID)

    def test_legacy_empty_salt_refuses_hashcat_line(self):
        # Hashcat 15600/15700 lock the salt to exactly 64 hex chars, so a legacy
        # empty-salt backup must NOT emit a line (Hashcat would reject it), and
        # the inspection must explain why instead of guessing.
        data = make_trustwallet_legacy_emptysalt()
        handler = get_format("trustwallet")(data)
        self.assertIsNone(handler.extract_hash())
        inspection = handler.inspect()
        self.assertIsNone(inspection.hashcat)
        self.assertTrue(any("empty salt" in n for n in inspection.notes))


class ExodusTests(unittest.TestCase):
    def test_detect_extract(self):
        data = make_exodus()
        self.assertEqual(detect_top(data).format_key, "exodus")
        handler = get_format("exodus")(data)
        h = handler.extract_hash()
        self.assertEqual(h.mode, 28200)
        # exact line, matching exodus2hashcat.py
        m = handler.parse()
        b64 = base64.b64encode
        expected = ":".join([
            "EXODUS", "16384", "8", "1",
            b64(m["salt"]).decode(),
            b64(m["blob_key_iv"]).decode(),
            b64(m["blob_key_key"]).decode(),
            b64(m["blob_key_auth_tag"]).decode(),
        ])
        self.assertEqual(h.hash, expected)
        self.assertTrue(h.hash.startswith("EXODUS:16384:8:1:"))

    def test_corrupted_checksum(self):
        data = bytearray(make_exodus())
        # flip a byte inside the blob
        data[-1] ^= 0xFF
        with self.assertRaises(Exception):
            get_format("exodus")(bytes(data)).parse()

    def test_not_exodus(self):
        from wallet2hash.errors import FormatError
        with self.assertRaises(FormatError):
            get_format("exodus")(b"not a seco file").parse()


if __name__ == "__main__":
    unittest.main()
