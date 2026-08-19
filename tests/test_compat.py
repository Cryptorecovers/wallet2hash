"""Compatibility contract for every registered format.

One rule drives this suite: a handler must either produce a *valid* Hashcat hash
whose mode is one of the handler's declared ``hashcat_modes``, or cleanly refuse
(``None`` / ``UnsupportedFormatError`` / an explanatory note). A handler must
never emit a hash for a format whose extraction has not been fixture-validated.
"""

import base64
import json
import os
import unittest

from wallet2hash.detector import detect
from wallet2hash.errors import FormatError, UnsupportedFormatError
from wallet2hash.models import HashcatHash
from wallet2hash.registry import all_formats, get_format
from tests.test_formats import (
    make_eth_pbkdf2,
    make_electrum_salt1,
    make_electrum_salt5,
)
from tests.test_more_formats import make_exodus, make_trustwallet_pbkdf2
from tests.test_bisq import _field_bytes, make_bisq_wallet
from tests.test_core_multibit import (
    make_bitcoin_core_bdb,
    make_multibit_classic,
    make_multibit_hd,
)


def _bip38():
    return b"note: 6P" + b"1" * 37 + b"\n"


def _multibit_wallet():
    data, _, _ = make_bisq_wallet()
    return data + _field_bytes(10, b"org.multibit.walletProtect.2")


def _dogechain():
    return json.dumps({
        "guid": "52500558-b3fa-4318-b6a3-3c55835c6575",
        "salt": base64.b64encode(os.urandom(16)).decode(),
        "payload": base64.b64encode(os.urandom(240)).decode(),
        "pbkdf2_iterations": 5000,
        "cipher": "AES-CBC",
        "version": 1,
    }).encode()


def _metamask_mobile():
    # Same shape as MetaMask's iOS/Android persist-root: the engine state is a
    # JSON-encoded string whose "vault" value is itself a JSON-encoded string.
    vault = {
        "cipher": base64.b64encode(os.urandom(48)).decode(),
        "iv": os.urandom(16).hex(),
        "salt": base64.b64encode(os.urandom(16)).decode(),
        "lib": "original",
    }
    engine = json.dumps({"backgroundState": {"vault": json.dumps(vault)}})
    return json.dumps({"engine": engine}).encode()


def _monero():
    return os.urandom(2048)


def _bitshares():
    import hashlib
    digest = hashlib.sha512(hashlib.sha512(b"testpassword").digest()).hexdigest()
    return b"some leveldb data ... checksum" + digest.encode()


def _terra():
    """A Terra Station `keys` localStorage export (one encrypted entry)."""
    import base64
    import hashlib

    from tests.test_new_formats import _cbc_encrypt

    pw = b"testpassword"
    salt = bytes(range(16))
    iv = bytes(range(16, 32))
    key = hashlib.pbkdf2_hmac("sha1", pw, salt, 100, 32)
    plain = "0" * 64  # 64-char hex private key
    ct = _cbc_encrypt(key, iv, plain.encode() + b"\x10" * 16)
    tm = salt.hex() + iv.hex() + base64.b64encode(ct).decode()
    return json.dumps([{"name": "t1", "address": "terra1abc", "encrypted": tm}]).encode()


def _metamask():
    return json.dumps({
        "data": base64.b64encode(os.urandom(64)).decode(),
        "iv": base64.b64encode(os.urandom(16)).decode(),  # 16-byte IV, as Hashcat 26600 requires
        "salt": base64.b64encode(os.urandom(32)).decode(),
        "keyMetadata": {"params": {"iterations": 10000}},
    }).encode()


def _blockchain_v1():
    payload = os.urandom(48)
    return json.dumps({"guid": "g", "sharedKey": "k",
                       "payload": base64.b64encode(payload).decode()}).encode()


def _ethereum_presale():
    return json.dumps({
        "encseed": "00" * 100,
        "ethaddr": "aabbccddeeff00112233445566778899aabbccdd",
        "bkp": "11" * 32,
    }).encode()


# format_key -> fixture builder. Extraction is fixture-validated for every format
# whose builder lives here.
FIXTURES = {
    "ethereum-keystore-v3": make_eth_pbkdf2,
    "ethereum-presale": _ethereum_presale,
    "electrum": make_electrum_salt1,
    "metamask": _metamask,
    "metamask-mobile": _metamask_mobile,
    "blockchain": _blockchain_v1,
    "bitcoin-core": make_bitcoin_core_bdb,
    "bip38": _bip38,
    "multibit-classic": make_multibit_classic,
    "multibit-hd": make_multibit_hd,
    "multibit-wallet": _multibit_wallet,
    "trustwallet": make_trustwallet_pbkdf2,
    "exodus": make_exodus,
    "bisq": lambda: make_bisq_wallet()[0],
    "dogechain": _dogechain,
    "monero": _monero,
    "bitshares": _bitshares,
    "terra-station": _terra,
}

# Formats whose detection needs a filename hint (the artifact has no magic bytes).
FIXTURE_PATHS = {"multibit-hd": "mbhd.wallet.aes", "monero": "wallet.keys"}

# Formats where extraction is *deliberately* not emitted until a real fixture
# validates the container parsing (BDB / protobuf / secp256k1). These must refuse,
# never guess.
REFUSE_FORMATS = {"bip38"}


class RegistryCompatibilityTests(unittest.TestCase):
    def test_registry_metadata_complete(self):
        keys = {cls.format_key for cls in all_formats()}
        self.assertEqual(keys, set(FIXTURES))
        for cls in all_formats():
            self.assertTrue(cls.name, f"{cls.format_key} has no display name")
            self.assertIsInstance(cls.hashcat_modes, list)
            for m in cls.hashcat_modes:
                self.assertIsInstance(m, int)

    def test_every_format_detects_and_inspects(self):
        for key, builder in FIXTURES.items():
            data = builder()
            detected = [d.format_key for d in detect(data, FIXTURE_PATHS.get(key, ""))]
            self.assertIn(key, detected, f"{key} did not detect its own fixture")
            inspection = get_format(key)(data).inspect()
            self.assertIsNotNone(inspection.wallet)
            self.assertIsNotNone(inspection.format)

    def test_no_handler_emits_an_undeclared_hash(self):
        """Every produced hash must use a mode the handler itself declares."""
        for key, builder in FIXTURES.items():
            cls = get_format(key)
            data = builder()
            inspection = cls(data).inspect()
            h = inspection.hashcat
            if h is not None:
                self.assertIsInstance(h, HashcatHash, key)
                self.assertTrue(h.hash and h.mode, f"{key} returned an empty hash")
                self.assertIn(
                    h.mode,
                    cls.hashcat_modes,
                    f"{key} emitted mode {h.mode} not in {cls.hashcat_modes}",
                )

    def test_unvalidated_formats_refuse_to_guess(self):
        """Formats without fixture-validated extraction must not emit a hash."""
        for key in REFUSE_FORMATS:
            cls = get_format(key)
            data = FIXTURES[key]()
            inspection = cls(data).inspect()
            self.assertIsNone(
                inspection.hashcat,
                f"{key} must not emit a hash until its extraction is fixture-validated",
            )
            # A refusal should explain itself.
            self.assertTrue(
                inspection.notes or inspection.classification.value != "A_EXISTING_HASHCAT",
                f"{key} refused without explaining why",
            )

    def test_extract_never_returns_a_wrong_type(self):
        """extract_hash may refuse (None / FormatError / UnsupportedFormatError),
        but when it does return a value it must be a HashcatHash with a declared mode."""
        for key, builder in FIXTURES.items():
            cls = get_format(key)
            try:
                result = cls(builder()).extract_hash()
            except (FormatError, UnsupportedFormatError):
                continue
            if result is None:
                continue
            self.assertIsInstance(result, HashcatHash, key)
            self.assertIn(result.mode, cls.hashcat_modes, key)

    def test_electrum_salt5_uses_21800(self):
        h = get_format("electrum")(make_electrum_salt5()).extract_hash()
        self.assertEqual(h.mode, 21800)
        self.assertTrue(h.hash.startswith("$electrum$5*"))


if __name__ == "__main__":
    unittest.main()
