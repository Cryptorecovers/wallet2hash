"""Round-trip verification tests for the newer supported formats.

Each test builds a genuinely encrypted artifact with the documented construction
(the same bytes JtR / Hashcat modules expect), then asserts the
handler verifies the known password and rejects a wrong one.
"""

import base64
import binascii
import hashlib
import json
import os
import unittest

from wallet2hash.detector import detect_top
from wallet2hash.models import VerifyStatus
from wallet2hash.registry import get_format
from tests.test_bisq import _field_bytes, _field_varint
from tests.test_compat import _multibit_wallet


def _cbc_encrypt(key, iv, plain):
    from wallet2hash.verification._aes import AesCipher
    c = AesCipher(key)
    prev = iv
    out = b""
    for i in range(0, len(plain), 16):
        block = bytes(a ^ b for a, b in zip(plain[i:i + 16], prev))
        enc = c.encrypt_block(block)
        out += enc
        prev = enc
    return out


class DogechainTests(unittest.TestCase):
    def test_verify_round_trip(self):
        pw = "btcr-test-password"
        salt = os.urandom(16)
        iterations = 5000
        pw_sha256 = hashlib.sha256(pw.encode()).digest()
        key = hashlib.pbkdf2_hmac("sha256", base64.b64encode(pw_sha256), salt, iterations, 32)
        iv = os.urandom(16)
        # 32500's tokenizer fixes the payload at 240 bytes (iv 16 + ct 224).
        # The plaintext must be a valid JSON document (trailing spaces are fine).
        doc = {"guid": "g", "sharedKey": "k", "keys": [],
               "tx_notes": {}, "options": {"pbkdf2_iterations": 5000}}
        plain = json.dumps(doc).encode()
        plain = plain + b" " * (224 - len(plain))
        ct = _cbc_encrypt(key, iv, plain)
        doc = json.dumps({
            "guid": "g", "salt": base64.b64encode(salt).decode(),
            "payload": base64.b64encode(iv + ct).decode(),
            "pbkdf2_iterations": iterations, "cipher": "AES-CBC",
        }).encode()
        fmt = get_format("dogechain")(doc)
        self.assertEqual(fmt.verify_password(pw), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 32500)
        self.assertTrue(h.hash.startswith("$dogechain$0*"))


class MetaMaskMobileTests(unittest.TestCase):
    def _build(self):
        pw = "btcr-test-password"
        salt = base64.b64encode(os.urandom(16)).decode()
        iv = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha512", pw.encode(), salt.encode(), 5000, 32)
        plain = b'[{"type":"HD Key Tree","data":{"mnemonic":"test test test"}}]'
        pad = 16 - len(plain) % 16
        ct = _cbc_encrypt(key, iv, plain + bytes([pad]) * pad)
        vault = {"cipher": base64.b64encode(ct).decode(), "iv": iv.hex(),
                 "salt": salt, "lib": "original"}
        engine = json.dumps({"backgroundState": {"vault": json.dumps(vault)}})
        return json.dumps({"engine": engine}).encode(), pw

    def test_detect_and_verify_round_trip(self):
        data, pw = self._build()
        self.assertEqual(detect_top(data).format_key, "metamask-mobile")
        fmt = get_format("metamask-mobile")(data)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 31900)
        self.assertTrue(h.hash.startswith("$metamaskMobile$"))
        self.assertEqual(fmt.verify_password(pw), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)


class BitSharesTests(unittest.TestCase):
    def test_checksum_extraction_and_verify(self):
        pw = "testpassword"
        digest = hashlib.sha512(hashlib.sha512(pw.encode()).digest()).hexdigest()
        data = b"leveldb-prefix ... checksum" + digest.encode()
        self.assertEqual(detect_top(data).format_key, "bitshares")
        fmt = get_format("bitshares")(data)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 21000)
        self.assertEqual(h.hash, digest)
        j = fmt.extract_john()
        self.assertEqual(j.format_name, "dynamic_84")
        self.assertEqual(j.hash, f"$dynamic_84${digest}")
        self.assertEqual(fmt.verify_password(pw), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)

    def test_encryption_key_wallet(self):
        doc = json.dumps({"encryption_key": "aa" * 64}).encode()
        fmt = get_format("bitshares")(doc)
        self.assertIsNone(fmt.extract_hash())  # no Hashcat hash for this variant
        j = fmt.extract_john()
        self.assertEqual(j.format_name, "BitShares")
        self.assertTrue(j.hash.startswith("$BitShares$0*"))


class MultiBitWalletTests(unittest.TestCase):
    def test_extract_27700(self):
        data = _multibit_wallet()
        self.assertEqual(detect_top(data).format_key, "multibit-wallet")
        h = get_format("multibit-wallet")(data).extract_hash()
        self.assertEqual(h.mode, 27700)
        self.assertTrue(h.hash.startswith("$multibit$3*"))

    def test_verify_round_trip(self):
        try:
            from wallet2hash.verification.crypto import scrypt
            key = scrypt("btcr-test-password".encode("utf_16_be"), bytes(range(8)), 16384, 8, 1, 32)
        except Exception:
            self.skipTest("scrypt unavailable in this Python build")
        from wallet2hash.verification._aes import AesCipher
        # Encrypt a private key so the final AES block is pure 0x10 padding:
        # plaintext = 32-byte key + 16 bytes of 0x10.
        plain = os.urandom(32) + b"\x10" * 16
        iv = os.urandom(16)
        ct = AesCipher(key).cbc_encrypt(iv, plain)
        # Wallet: salt + scrypt params + a key carrying the 48-byte encrypted private key
        params = _field_bytes(1, bytes(range(8))) + _field_varint(2, 16384) + \
                 _field_varint(3, 8) + _field_varint(4, 1)
        enc_data = _field_bytes(1, iv) + _field_bytes(2, ct)
        key_msg = _field_varint(1, 2) + _field_bytes(6, enc_data)
        wallet = _field_bytes(1, b"org.bitcoin.production") + _field_bytes(3, key_msg) + \
                 _field_varint(5, 2) + _field_bytes(6, params)
        wallet += _field_bytes(10, b"org.multibit.walletProtect.2")
        fmt = get_format("multibit-wallet")(wallet)
        self.assertEqual(fmt.verify_password("btcr-test-password"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)


class BlockchainSecondPasswordTests(unittest.TestCase):
    """Mode 18800: the legacy ``bs:`` dpasswordhash blob.

    The blob is built exactly per Hashcat's own ``tools/test_modules/m18800.pm``:
    base64 of ``"bs:" + sha256-iterated digest + salt16 + le32(iterations) +
    crc32`` — 59 bytes, 80 base64 chars.
    """

    def _blob(self, password="hashcat", salt=b"0123456789abcdef", iterations=10000):
        import struct
        import zlib

        uuid_str = "%s-%s-%s-%s-%s" % (
            salt[0:4].hex(), salt[4:6].hex(), salt[6:8].hex(),
            salt[8:10].hex(), salt[10:16].hex(),
        )
        digest = hashlib.sha256(uuid_str.encode() + password.encode()).digest()
        for _ in range(iterations - 1):
            digest = hashlib.sha256(digest).digest()
        data = b"bs:" + digest + salt + struct.pack("<I", iterations)
        data += struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
        return base64.b64encode(data).decode()

    def test_detect_extract_and_verify(self):
        blob = self._blob()
        data = json.dumps({"guid": "g", "double_encryption": True,
                           "dpasswordhash": blob}).encode()
        self.assertEqual(detect_top(data).format_key, "blockchain")
        fmt = get_format("blockchain")(data)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 18800)
        self.assertEqual(h.hash, blob)  # verbatim pass-through
        self.assertEqual(len(blob), 80)
        self.assertEqual(fmt.verify_password("hashcat"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)

    def test_corrupt_blob_is_not_detected(self):
        blob = self._blob()
        data = json.dumps({"guid": "g", "double_encryption": True,
                           "dpasswordhash": blob[:-1] + ("A" if blob[-1] != "A" else "B")}).encode()
        from wallet2hash.detector import detect
        detected = [d.format_key for d in detect(data)]
        self.assertNotIn("blockchain", detected)  # CRC32/parse failure -> refuse


class TerraStationTests(unittest.TestCase):
    def _build(self, pw="testpassword"):
        salt = bytes(range(16))
        iv = bytes(range(16, 32))
        key = hashlib.pbkdf2_hmac("sha1", pw.encode(), salt, 100, 32)
        plain = "0" * 64  # 64-char hex private key, per Hashcat issue #3285
        ct = _cbc_encrypt(key, iv, plain.encode() + b"\x10" * 16)
        tm = salt.hex() + iv.hex() + base64.b64encode(ct).decode()
        return json.dumps([{"name": "t1", "address": "terra1abc", "encrypted": tm}]).encode()

    def test_detect_and_extract_pass_through(self):
        data = self._build()
        self.assertEqual(detect_top(data).format_key, "terra-station")
        fmt = get_format("terra-station")(data)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 29600)
        # The encrypted field IS the mode-29600 line: hex(salt)+hex(iv)+b64(ct),
        # 32+32+108 = 172 chars, no separators.
        self.assertEqual(len(h.hash), 172)
        self.assertTrue(h.hash.startswith("000102030405060708090a0b0c0d0e0f"))

    def test_verify_round_trip(self):
        data = self._build("correct horse battery staple")
        fmt = get_format("terra-station")(data)
        self.assertEqual(fmt.verify_password("correct horse battery staple"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)

    def test_damaged_entry_refused(self):
        from wallet2hash.errors import FormatError
        data = self._build()
        doc = json.loads(data)
        doc[0]["encrypted"] = "zz" + doc[0]["encrypted"][2:]  # non-hex salt
        fmt = get_format("terra-station")(json.dumps(doc).encode())
        with self.assertRaises(FormatError):
            fmt.verify_password("testpassword")


class MoneroTests(unittest.TestCase):
    def test_extract_john_line(self):
        data = os.urandom(2048)
        fmt = get_format("monero")(data)
        self.assertEqual(detect_top(data, "wallet.keys").format_key, "monero")
        j = fmt.extract_john()
        self.assertEqual(j.format_name, "monero")
        self.assertEqual(j.hash, f"$monero$0*{data.hex()}")
        self.assertIsNone(fmt.extract_hash())  # no Hashcat mode


if __name__ == "__main__":
    unittest.main()
