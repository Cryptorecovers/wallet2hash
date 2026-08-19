import unittest

from wallet2hash.verification._aes import AesCipher, pkcs7_pad, strip_pkcs7


class AesTests(unittest.TestCase):
    def test_fips197_aes128(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(AesCipher(key).encrypt_block(pt), ct)
        self.assertEqual(AesCipher(key).decrypt_block(ct), pt)

    def test_fips197_aes192(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        self.assertEqual(AesCipher(key).encrypt_block(pt), ct)

    def test_fips197_aes256(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(AesCipher(key).encrypt_block(pt), ct)

    def test_cbc_roundtrip(self):
        key = bytes(range(32))
        iv = bytes(range(16))
        data = pkcs7_pad(b"hello wallet" * 8)
        cipher = AesCipher(key)
        ct = cipher.cbc_encrypt(iv, data)
        self.assertEqual(strip_pkcs7(cipher.cbc_decrypt(iv, ct)), b"hello wallet" * 8)

    def test_pkcs7_strictness(self):
        with self.assertRaises(ValueError):
            strip_pkcs7(b"\x00" * 16)


if __name__ == "__main__":
    unittest.main()
