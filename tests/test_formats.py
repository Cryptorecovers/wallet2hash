import base64
import json
import os
import unittest

from wallet2hash.detector import detect_top
from wallet2hash.errors import UnsupportedFormatError, VerificationUnsupportedError
from wallet2hash.formats import (  # noqa: F401  (registers handlers)
    bip38,
    bitcoin_core,
    blockchain,
    electrum,
    ethereum_keystore,
    metamask,
    multibit,
)
from wallet2hash.models import VerifyStatus
from wallet2hash.registry import get_format
from wallet2hash.verification import keccak256, pbkdf2_hmac_sha256, sha256d
from wallet2hash.verification._aes import AesCipher, pkcs7_pad
from tests.test_core_multibit import make_bitcoin_core_bdb, make_multibit_classic, make_multibit_hd

PASSWORD = "correct horse battery staple"


def make_eth_pbkdf2(password=PASSWORD, c=1024):
    salt = os.urandom(32)
    derived = pbkdf2_hmac_sha256(password.encode(), salt, c, 32)
    ciphertext = os.urandom(32)
    mac = keccak256(derived[16:32] + ciphertext)
    return json.dumps({
        "version": 3,
        "id": "00000000-0000-0000-0000-000000000000",
        "address": "00112233445566778899aabbccddeeff00112233",
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": os.urandom(16).hex()},
            "cipher": "aes-128-ctr",
            "kdf": "pbkdf2",
            "kdfparams": {"c": c, "dklen": 32, "prf": "hmac-sha256", "salt": salt.hex()},
            "mac": mac.hex(),
        },
    }).encode()


def make_eth_scrypt():
    return json.dumps({
        "version": 3,
        "crypto": {
            "ciphertext": os.urandom(32).hex(),
            "cipherparams": {"iv": os.urandom(16).hex()},
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {"n": 262144, "r": 8, "p": 1, "dklen": 32, "salt": os.urandom(32).hex()},
            "mac": os.urandom(32).hex(),
        },
    }).encode()


def make_electrum_salt1():
    key = sha256d(PASSWORD.encode())
    iv = os.urandom(16)
    pt = pkcs7_pad(b"S" * 32)
    ct = AesCipher(key).cbc_encrypt(iv, pt)
    blob = iv + ct
    return json.dumps({"seed_version": 4, "seed": base64.b64encode(blob).decode(),
                       "use_encryption": True}).encode()


def make_electrum_salt2():
    key = sha256d(PASSWORD.encode())
    iv = os.urandom(16)
    pt = pkcs7_pad(b"M" * 96)
    ct = AesCipher(key).cbc_encrypt(iv, pt)
    blob = iv + ct
    return json.dumps({"wallet_type": "standard", "seed_version": 13,
                       "keystore": {"type": "bip32", "xprv": base64.b64encode(blob).decode()},
                       "use_encryption": True}).encode()


def make_electrum_salt3():
    key = sha256d(PASSWORD.encode())
    ct_prev = os.urandom(16)
    pt_last = b"\x10" * 16
    ct_last = AesCipher(key).encrypt_block(bytes(a ^ b for a, b in zip(pt_last, ct_prev)))
    blob = os.urandom(48) + ct_prev + ct_last
    return json.dumps({"wallet_type": "imported", "seed_version": 13,
                       "keystore": {"type": "imported",
                                    "keypairs": {"addr": base64.b64encode(blob).decode()}},
                       "use_encryption": True}).encode()


def make_electrum_salt4():
    blob = b"BIE1" + os.urandom(33) + os.urandom(64) + os.urandom(32)
    return json.dumps({"wallet_type": "standard", "seed_version": 13,
                       "keystore": {"type": "bip32", "xprv": base64.b64encode(blob).decode()},
                       "use_encryption": True}).encode()


def make_electrum_salt5():
    # ciphertext longer than 16384 bytes -> electrum2john truncates to 1024 (21800)
    blob = b"BIE1" + os.urandom(33) + os.urandom(17000) + os.urandom(32)
    return json.dumps({"wallet_type": "standard", "seed_version": 13,
                       "keystore": {"type": "bip32", "xprv": base64.b64encode(blob).decode()},
                       "use_encryption": True}).encode()


class EthereumKeystoreTests(unittest.TestCase):
    def test_pbkdf2_detect_extract_verify(self):
        data = make_eth_pbkdf2()
        self.assertEqual(detect_top(data).format_key, "ethereum-keystore-v3")
        h = get_format("ethereum-keystore-v3")(data).extract_hash()
        self.assertEqual(h.mode, 15600)
        self.assertTrue(h.hash.startswith("$ethereum$p*1024*"))
        handler = get_format("ethereum-keystore-v3")(data)
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("wrong password"), VerifyStatus.INVALID)

    def test_scrypt_extract(self):
        h = get_format("ethereum-keystore-v3")(make_eth_scrypt()).extract_hash()
        self.assertEqual(h.mode, 15700)
        self.assertTrue(h.hash.startswith("$ethereum$s*262144*8*1*"))

    def test_corrupted_mac(self):
        data = make_eth_pbkdf2()
        doc = json.loads(data)
        doc["crypto"]["mac"] = "00" * 32
        handler = get_format("ethereum-keystore-v3")(json.dumps(doc).encode())
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.INVALID)


class EthereumPresaleTests(unittest.TestCase):
    def test_presale(self):
        data = json.dumps({
            "encseed": "00" * 100,
            "ethaddr": "aabbccddeeff00112233445566778899aabbccdd",
            "bkp": "11" * 32,
        }).encode()
        self.assertEqual(detect_top(data).format_key, "ethereum-presale")
        h = get_format("ethereum-presale")(data).extract_hash()
        self.assertEqual(h.mode, 16300)
        self.assertTrue(h.hash.startswith("$ethereum$w*"))


class ElectrumTests(unittest.TestCase):
    def test_detect_extract_salt1(self):
        h = get_format("electrum")(make_electrum_salt1()).extract_hash()
        self.assertEqual(h.mode, 16600)
        self.assertTrue(h.hash.startswith("$electrum$1*"))

    def test_detect_extract_salt2(self):
        h = get_format("electrum")(make_electrum_salt2()).extract_hash()
        self.assertEqual(h.mode, 16600)
        self.assertTrue(h.hash.startswith("$electrum$2*"))

    def test_detect_extract_salt3(self):
        h = get_format("electrum")(make_electrum_salt3()).extract_hash()
        self.assertEqual(h.mode, 16600)
        self.assertTrue(h.hash.startswith("$electrum$3*"))

    def test_detect_extract_salt4(self):
        h = get_format("electrum")(make_electrum_salt4()).extract_hash()
        self.assertEqual(h.mode, 21700)
        self.assertTrue(h.hash.startswith("$electrum$4*"))

    def test_detect_extract_salt5(self):
        h = get_format("electrum")(make_electrum_salt5()).extract_hash()
        self.assertEqual(h.mode, 21800)
        self.assertTrue(h.hash.startswith("$electrum$5*"))

    def test_salt1_verify(self):
        handler = get_format("electrum")(make_electrum_salt1())
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)
        self.assertEqual(handler.verify_password("nope"), VerifyStatus.INVALID)

    def test_salt2_verify(self):
        handler = get_format("electrum")(make_electrum_salt2())
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)

    def test_salt3_verify(self):
        handler = get_format("electrum")(make_electrum_salt3())
        self.assertEqual(handler.verify_password(PASSWORD), VerifyStatus.VALID)

    def test_salt4_verify_unsupported(self):
        handler = get_format("electrum")(make_electrum_salt4())
        with self.assertRaises(VerificationUnsupportedError):
            handler.verify_password(PASSWORD)

    def test_unencrypted(self):
        data = json.dumps({"use_encryption": False, "seed_version": 4}).encode()
        insp = get_format("electrum")(data).inspect()
        self.assertFalse(insp.encrypted)
        self.assertTrue(insp.classification.value.startswith("F_"))


class MetaMaskTests(unittest.TestCase):
    def test_detect_extract(self):
        data = json.dumps({
            "data": base64.b64encode(os.urandom(64)).decode(),
            "iv": base64.b64encode(os.urandom(16)).decode(),  # 16-byte IV, as Hashcat 26600 requires
            "salt": base64.b64encode(os.urandom(32)).decode(),
            "keyMetadata": {"params": {"iterations": 10000}},
        }).encode()
        self.assertEqual(detect_top(data).format_key, "metamask")
        h = get_format("metamask")(data).extract_hash()
        self.assertEqual(h.mode, 26600)
        self.assertTrue(h.hash.startswith("$metamask$"))


class BlockchainTests(unittest.TestCase):
    def test_v1(self):
        payload = os.urandom(48)
        data = json.dumps({"guid": "g", "sharedKey": "k",
                           "payload": base64.b64encode(payload).decode()}).encode()
        self.assertEqual(detect_top(data).format_key, "blockchain")
        h = get_format("blockchain")(data).extract_hash()
        self.assertEqual(h.mode, 12700)
        self.assertEqual(h.hash, f"$blockchain${len(payload)}${payload.hex()}")

    def test_v2(self):
        payload = os.urandom(48)
        data = json.dumps({"version": 2, "pbkdf2_iterations": 5000,
                           "payload": base64.b64encode(payload).decode()}).encode()
        self.assertEqual(detect_top(data).format_key, "blockchain")
        h = get_format("blockchain")(data).extract_hash()
        self.assertEqual(h.mode, 15200)
        self.assertEqual(h.hash, f"$blockchain$v2$5000${len(payload)}${payload.hex()}")

    def test_v00_raw_base64(self):
        # V0.0: the whole file is a base64 blob (no JSON envelope). Real v0.0
        # wallets are ~500+ bytes; the entropy check mirrors the reference parser.
        payload = os.urandom(512)
        data = base64.b64encode(payload)
        self.assertEqual(detect_top(data).format_key, "blockchain")
        h = get_format("blockchain")(data).extract_hash()
        self.assertEqual(h.mode, 12700)
        self.assertEqual(h.hash, f"$blockchain${len(payload)}${payload.hex()}")

    def test_v00_rejects_low_entropy_base64(self):
        # A base64 blob that isn't random (e.g. a MultiBit key or plain dump)
        # must not be classified as a Blockchain wallet.
        data = base64.b64encode(b"A" * 512)
        self.assertIsNone(detect_top(data))

    def _cbc_encrypt(self, key, iv, plain):
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

    def test_v00_verify_round_trip(self):
        # Real construction (reference WalletBlockchain decrypt):
        # PBKDF2-HMAC-SHA1(pw, salt, 10, 32) + AES-256-CBC, ISO 10126 padding.
        import hashlib
        pw = b"btcr-test-password"
        salt_iv = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha1", pw, salt_iv, 10, 32)
        plain = b'{\n\t"guid" : "9bb4c672-563e-4806-9012-a3e8f86a0eca",\n\t"sharedKey" : "k"}'
        pad = 16 - len(plain) % 16
        padded = plain + bytes([pad]) * pad
        ct = self._cbc_encrypt(key, salt_iv, padded)
        data = base64.b64encode(salt_iv + ct)
        fmt = get_format("blockchain")(data)
        self.assertEqual(fmt.verify_password("btcr-test-password"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 12700)

    def test_v2_verify_round_trip(self):
        import hashlib
        pw = b"btcr-test-password"
        salt_iv = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha1", pw, salt_iv, 5000, 32)
        plain = b'{"guid":"g","sharedKey":"k","tx_notes":{},"keys":[]}'
        pad = 16 - len(plain) % 16
        ct = self._cbc_encrypt(key, salt_iv, plain + bytes([pad]) * pad)
        data = json.dumps({"version": 2, "pbkdf2_iterations": 5000,
                           "payload": base64.b64encode(salt_iv + ct).decode()}).encode()
        fmt = get_format("blockchain")(data)
        self.assertEqual(fmt.verify_password("btcr-test-password"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)

    def test_v00_ofb_emits_34700(self):
        # The earliest V0.0 wallets used AES-256-OFB with 1 PBKDF2 iteration
        # (m34700.pm). The payload is not CBC-shaped, so the same $blockchain$
        # line must be emitted for mode 34700, and verify must still work.
        import hashlib
        from wallet2hash.verification._aes import AesCipher
        pw = b"testpassword"
        salt_iv = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha1", pw, salt_iv, 1, 32)
        plain = b'{"guid":"g","sharedKey":"k","tx_notes":{},"keys":[]}'
        a = AesCipher(key)
        keystream = b""
        prev = salt_iv
        while len(keystream) < len(plain):
            prev = a.encrypt_block(prev)
            keystream += prev
        ct = bytes(p ^ c for p, c in zip(keystream[:len(plain)], plain))
        data = base64.b64encode(salt_iv + ct)
        fmt = get_format("blockchain")(data)
        h = fmt.extract_hash()
        self.assertEqual(h.mode, 34700)
        self.assertTrue(h.hash.startswith("$blockchain$"))
        self.assertEqual(fmt.verify_password("testpassword"), VerifyStatus.VALID)
        self.assertEqual(fmt.verify_password("wrong"), VerifyStatus.INVALID)


class DetectionOnlyTests(unittest.TestCase):
    def test_bitcoin_core_bdb(self):
        self.assertEqual(detect_top(make_bitcoin_core_bdb()).format_key, "bitcoin-core")
        h = get_format("bitcoin-core")(make_bitcoin_core_bdb()).extract_hash()
        self.assertEqual(h.mode, 11300)

    def test_bitcoin_core_sqlite(self):
        blob = b"SQLite format 3\x00" + os.urandom(32)
        self.assertEqual(detect_top(blob).format_key, "bitcoin-core")

    def test_bip38(self):
        token = "6P" + "1" * 37
        self.assertEqual(detect_top(f"note: {token}\n".encode()).format_key, "bip38")

    def test_multibit_classic(self):
        self.assertEqual(detect_top(make_multibit_classic()).format_key, "multibit-classic")

    def test_multibit_hd(self):
        blob = make_multibit_hd()
        self.assertEqual(detect_top(blob, "mbhd.wallet.aes").format_key, "multibit-hd")

    def test_unknown(self):
        self.assertIsNone(detect_top(b"this is not a wallet at all"))


if __name__ == "__main__":
    unittest.main()
