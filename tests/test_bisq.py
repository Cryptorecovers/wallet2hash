import os
import unittest

from wallet2hash.detector import detect_top
from wallet2hash.errors import FormatError
from wallet2hash.registry import get_format


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field_varint(num, val):
    return _varint((num << 3) | 0) + _varint(val)


def _field_bytes(num, data):
    return _varint((num << 3) | 2) + _varint(len(data)) + data


def make_bisq_wallet(n=32768, r=8, p=6):
    salt = bytes(range(8))

    # ScryptParameters { salt=1, n=2, r=3, p=4 }
    params = b""
    params += _field_bytes(1, salt)
    params += _field_varint(2, n)
    params += _field_varint(3, r)
    params += _field_varint(4, p)

    # EncryptedData { initialisation_vector=1, encrypted_private_key=2 }
    iv = os.urandom(16)
    encrypted_private_key = os.urandom(48)
    enc_data = _field_bytes(1, iv) + _field_bytes(2, encrypted_private_key)

    # Key { type=1 (varint), encrypted_data=6 }
    key = _field_varint(1, 2) + _field_bytes(6, enc_data)

    # Wallet { network_identifier=1, key=3 (repeated), encryption_type=5, encryption_parameters=6 }
    wallet = b""
    wallet += _field_bytes(1, b"org.bitcoin.production")
    wallet += _field_bytes(3, key)
    wallet += _field_varint(5, 2)  # ENCRYPTED_SCRYPT_AES
    wallet += _field_bytes(6, params)

    return wallet, salt, encrypted_private_key


class BisqTests(unittest.TestCase):
    def test_detect_and_extract(self):
        data, salt, encrypted_private_key = make_bisq_wallet()
        self.assertEqual(detect_top(data).format_key, "bisq")
        handler = get_format("bisq")(data)
        h = handler.extract_hash()
        self.assertEqual(h.mode, 29800)
        expected = f"$bisq$3*32768*8*6*{salt.hex()}*{encrypted_private_key[-32:].hex()}"
        self.assertEqual(h.hash, expected)

    def test_inspect(self):
        data, _, _ = make_bisq_wallet()
        insp = get_format("bisq")(data).inspect()
        self.assertEqual(insp.wallet, "Bisq")
        self.assertEqual(insp.hashcat.mode, 29800)

    def test_rejects_unencrypted(self):
        # network_identifier only, no encryption_type -> not scrypt-encrypted
        wallet = _field_bytes(1, b"org.bitcoin.production")
        with self.assertRaises(FormatError):
            get_format("bisq")(wallet).parse()

    def test_not_bisq(self):
        with self.assertRaises(FormatError):
            get_format("bisq")(b"definitely not a wallet").parse()


if __name__ == "__main__":
    unittest.main()
