"""Synthetic fixtures and tests for Bitcoin Core (11300) and MultiBit (22500/22700).

Fixture builders are shared with test_compat.py so the compatibility contract and
these format tests use the same bytes.
"""

import base64
import hashlib
import os
import sqlite3
import struct
import tempfile
import unittest

from wallet2hash.detector import detect
from wallet2hash.models import VerifyStatus
from wallet2hash.registry import get_format

_BDB_MAGIC = b"\x62\x31\x05\x00\x09\x00\x00\x00"
_MKEY_KEY = b"\x04mkey\x01\x00\x00\x00"


def _align32(i):
    m = i % 4
    return i if m == 0 else i + 4 - m


def make_mkey_value(cry_master, salt, iterations=25000, method=0):
    """Serialize a Bitcoin Core CMasterKey value (crypter.h)."""
    return (
        bytes([len(cry_master)]) + cry_master
        + bytes([len(salt)]) + salt
        + struct.pack("<II", method, iterations)
    )


def build_bdb_with_mkey(mkey_value, page_size=4096):
    """Build a minimal Berkeley DB file containing one mkey record on a leaf page."""
    key = _MKEY_KEY

    def item(data):
        return struct.pack("<HB", len(data), 1) + data

    value_item = item(mkey_value)
    key_item = item(key)

    header = bytearray(page_size)          # page 0 (metadata)
    header[12:20] = _BDB_MAGIC
    struct.pack_into("<I", header, 20, page_size)

    leaf = bytearray(page_size)            # page 1 (leaf)
    struct.pack_into("<I", leaf, 8, 1)     # pgno
    first_item_pos = 28
    struct.pack_into("<HHBB", leaf, 20, 2, first_item_pos, 1, 5)
    pos = first_item_pos
    leaf[pos:pos + len(value_item)] = value_item
    pos = _align32(pos + len(value_item))
    leaf[pos:pos + len(key_item)] = key_item

    return bytes(header + leaf)


def make_bitcoin_core_bdb(cry_master=None, salt=None, iterations=25000):
    cry_master = cry_master if cry_master is not None else bytes(range(48))
    salt = salt if salt is not None else bytes(range(8))
    mkey_value = make_mkey_value(cry_master, salt, iterations)
    return build_bdb_with_mkey(mkey_value)


def make_bitcoin_core_encrypted(password=b"correct horse", salt=None, iterations=500):
    """A Bitcoin Core wallet whose master key is genuinely encrypted with *password*."""
    salt = salt if salt is not None else bytes(range(8))
    derived = password + salt
    for _ in range(iterations):
        derived = hashlib.sha512(derived).digest()
    from wallet2hash.verification._aes import AesCipher

    master_key = os.urandom(32)
    plaintext = master_key + b"\x10" * 16  # 32-byte key + full padding block
    cry_master = AesCipher(derived[:32]).cbc_encrypt(derived[32:48], plaintext)
    return make_bitcoin_core_bdb(cry_master, salt, iterations)


def make_multibit_classic(salt=None, encrypted_block=None):
    salt = salt if salt is not None else bytes(range(8))
    encrypted_block = encrypted_block if encrypted_block is not None else bytes(range(32))
    raw = b"Salted__" + salt + encrypted_block
    return base64.b64encode(raw)


def make_multibit_hd(iv=None, block1=None):
    iv = iv if iv is not None else bytes(range(16))
    block1 = block1 if block1 is not None else bytes(range(16, 32))
    return iv + block1


class BitcoinCoreTests(unittest.TestCase):
    def test_detect_bdb(self):
        data = make_bitcoin_core_bdb()
        keys = [d.format_key for d in detect(data)]
        self.assertIn("bitcoin-core", keys)

    def test_extract_11300(self):
        cry_master = bytes(range(48))
        salt = bytes(range(8))
        iterations = 100000
        data = make_bitcoin_core_bdb(cry_master, salt, iterations)
        h = get_format("bitcoin-core")(data).extract_hash()
        self.assertEqual(h.mode, 11300)
        expected = (
            f"$bitcoin$64${cry_master[-32:].hex()}"
            f"$16${salt.hex()}${iterations}$2$00$2$00"
        )
        self.assertEqual(h.hash, expected)

    def test_verify_round_trip(self):
        data = make_bitcoin_core_encrypted(b"correct horse", iterations=500)
        handler = get_format("bitcoin-core")(data)
        from wallet2hash.models import VerifyStatus
        self.assertEqual(handler.verify_password("correct horse"), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("wrong"), VerifyStatus.INVALID)

    def test_missing_mkey_refuses(self):
        # A BDB file with the right magic but no mkey record must refuse cleanly.
        from wallet2hash.errors import UnsupportedFormatError
        header = bytearray(4096)
        header[12:20] = _BDB_MAGIC
        struct.pack_into("<I", header, 20, 4096)
        leaf = bytearray(4096)
        struct.pack_into("<I", leaf, 8, 1)
        struct.pack_into("<HHBB", leaf, 20, 0, 28, 1, 5)  # zero items
        with self.assertRaises(UnsupportedFormatError):
            get_format("bitcoin-core")(bytes(header + leaf)).extract_hash()

    def test_extract_from_sqlite(self):
        cry_master = bytes(range(48))
        salt = bytes(range(8))
        iterations = 50000
        mkey_value = make_mkey_value(cry_master, salt, iterations)
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            path = f.name
        try:
            con = sqlite3.connect(path)
            con.execute("CREATE TABLE main (key BLOB, value BLOB)")
            con.execute("INSERT INTO main VALUES (?, ?)", (_MKEY_KEY, mkey_value))
            con.commit()
            con.close()
            with open(path, "rb") as f:
                data = f.read()
            h = get_format("bitcoin-core")(data, path).extract_hash()
            self.assertEqual(h.mode, 11300)
            self.assertEqual(
                h.hash,
                f"$bitcoin$64${cry_master[-32:].hex()}$16${salt.hex()}${iterations}$2$00$2$00",
            )
        finally:
            os.unlink(path)


class MultiBitClassicTests(unittest.TestCase):
    def test_detect(self):
        data = make_multibit_classic()
        keys = [d.format_key for d in detect(data)]
        self.assertIn("multibit-classic", keys)

    def test_extract_22500(self):
        salt = bytes(range(8))
        block = bytes(range(32))
        data = make_multibit_classic(salt, block)
        h = get_format("multibit-classic")(data).extract_hash()
        self.assertEqual(h.mode, 22500)
        self.assertEqual(h.hash, f"$multibit$1*{salt.hex()}*{block.hex()}")

    def test_multiline_base64(self):
        salt = bytes(range(8))
        block = bytes(range(32))
        raw = base64.b64encode(b"Salted__" + salt + block)
        # wrap across two lines like the original MultiBit backup files
        data = raw[:20] + b"\n" + raw[20:40] + b"\n" + raw[40:]
        h = get_format("multibit-classic")(data).extract_hash()
        self.assertEqual(h.hash, f"$multibit$1*{salt.hex()}*{block.hex()}")

    def test_not_salted_refuses(self):
        from wallet2hash.errors import FormatError
        with self.assertRaises(FormatError):
            get_format("multibit-classic")(base64.b64encode(os.urandom(48))).extract_hash()

    def test_verify_round_trip(self):
        # Reference WalletMultiBit: UTF-16LE password, 3-round MD5 key schedule,
        # AES-256-CBC; plaintext is a base58 WIF.
        from wallet2hash.verification._aes import AesCipher

        password = "btcr-test-password"
        pw = password.encode("utf_16_le")[::2]
        salt = bytes(range(8))
        salted = pw + salt
        key1 = hashlib.md5(salted).digest()
        key2 = hashlib.md5(key1 + salted).digest()
        iv = hashlib.md5(key2 + salted).digest()
        wif = b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        padded = wif + b"\x10" * (16 - len(wif) % 16) + b"\x10" * 16  # two full blocks
        ct = AesCipher(key1 + key2).cbc_encrypt(iv, padded)
        data = base64.b64encode(b"Salted__" + salt + ct)
        fmt = get_format("multibit-classic")(data)
        self.assertEqual(fmt.verify_password(password), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong-password"), VerifyStatus.INVALID)


class MultiBitHDTests(unittest.TestCase):
    def test_detect_by_filename(self):
        data = make_multibit_hd()
        d = get_format("multibit-hd").detect(data, "mbhd.wallet.aes")
        self.assertIsNotNone(d)

    def test_extract_22700(self):
        iv = bytes(range(16))
        block1 = bytes(range(16, 32))
        data = make_multibit_hd(iv, block1)
        h = get_format("multibit-hd")(data).extract_hash()
        self.assertEqual(h.mode, 22700)
        # block2 reuses the leading 16 bytes (the IV) for the legacy alternative
        self.assertEqual(h.hash, f"$multibit$2*{iv.hex()}*{block1.hex()}*{iv.hex()}")

    def test_too_short_refuses(self):
        from wallet2hash.errors import FormatError
        with self.assertRaises(FormatError):
            get_format("multibit-hd")(os.urandom(16)).extract_hash()

    def test_verify_round_trip(self):
        # Reference WalletMultiBitHD: UTF-16BE password, scrypt (N=16384, r=8,
        # p=1) with the fixed bitcoinj salt, AES-256-CBC under the stored IV;
        # plaintext starts with a bitcoinj protobuf network identifier.
        try:
            from wallet2hash.verification.crypto import scrypt
            from wallet2hash.verification._aes import AesCipher
            key = scrypt("correct horse".encode("utf_16_be"), bytes.fromhex("3551038075a3b0c5"), 16384, 8, 1, 32)
        except Exception:
            self.skipTest("scrypt unavailable in this Python build")

        iv = os.urandom(16)
        plain = b"\x0a\x09org.bitcoin.production\x12\x08testwallet"
        padded = plain + b"\x00" * (16 - len(plain) % 16)
        ct = AesCipher(key).cbc_encrypt(iv, padded)
        blob = iv + ct
        fmt = get_format("multibit-hd")(blob)
        self.assertEqual(fmt.verify_password("correct horse"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong-password"), VerifyStatus.INVALID)


if __name__ == "__main__":
    unittest.main()
