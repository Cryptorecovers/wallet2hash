import hashlib
import unittest

from wallet2hash.verification.crypto import keccak256


class KeccakTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc(self):
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_not_sha3(self):
        self.assertNotEqual(keccak256(b""), hashlib.sha3_256(b"").digest())


if __name__ == "__main__":
    unittest.main()
