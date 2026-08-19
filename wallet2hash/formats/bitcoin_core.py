"""Bitcoin Core (and Core-derived) ``wallet.dat`` handler — Hashcat mode 11300.

Container: Berkeley DB (legacy encrypted wallets) or SQLite (newer builds that
still carry legacy ``mkey``/``ckey`` records). Encrypted wallets store an
``mkey`` record whose value is Bitcoin Core's ``CMasterKey`` serialization
(``src/wallet/crypter.h``)::

    compact_size(len(vchCryptedKey)) + vchCryptedKey   (48 bytes)
    compact_size(len(vchSalt))       + vchSalt          (8 bytes)
    nDerivationMethod (uint32 LE)                        (0 == SHA512)
    nDerivationIterations (uint32 LE)

Hashcat mode 11300 consumes (verified against ``src/modules/module_11300.c``)::

    $bitcoin$<cry_master_len>$<cry_master_hex>$<cry_salt_len>$<cry_salt_hex>
             $<rounds>$<ckey_len>$<ckey_hex>$<pubkey_len>$<pubkey_hex>

The 11300 kernel only verifies the master-key decryption (AES-256-CBC padding of
the final block); the ``ckey``/``pubkey`` fields are parsed but unused. We
therefore emit the exact form produced by JtR's ``bitcoin2john.py``: the final
two AES blocks of the master key plus dummy ``ckey``/``pubkey`` placeholders.

BDB reading first tries the optional ``berkeleydb`` package, then falls back to a
pure-Python B-tree leaf-page scan (ported from the reference wallet-recovery
implementation's ``WalletBitcoinCore.load_from_filename``, which does the same).
SQLite wallets are read with the standard library.

Sources
-------
* Bitcoin Core: ``src/wallet/crypter.h`` (``CMasterKey``), ``src/wallet/walletdb.cpp``
  (``mkey`` record), ``src/wallet/db.cpp`` (BDB magic ``0x00053162``).
* Reference wallet-recovery implementation: ``WalletBitcoinCore`` (record layout
  and BDB leaf-page scan).
* John the Ripper: ``run/bitcoin2john.py`` (the exact ``$bitcoin$…$2$00$2$00`` form).
* Hashcat: ``src/modules/module_11300.c`` (tokenizer).
"""

from __future__ import annotations

import binascii
import hashlib
import struct
from typing import Optional

from ..errors import FormatError, UnsupportedFormatError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register
from ..verification.crypto import aes_decrypt

# Bitcoin Core's BDB file header at offset 12: magic 0x00053162 ("b1") followed by
# version 9. The reference recovery tooling checks these eight bytes to
# identify a legacy wallet.dat.
_BDB_MAGIC = b"\x62\x31\x05\x00\x09\x00\x00\x00"
_SQLITE_MAGIC = b"SQLite format 3\x00"
# The BDB key for master key #1: compact-size "mkey" + uint32 nID == 1.
_MKEY_KEY = b"\x04mkey\x01\x00\x00\x00"


def _read_varint(data: bytes, pos: int):
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        return int.from_bytes(data[pos + 1:pos + 3], "little"), pos + 3
    if first == 0xFE:
        return int.from_bytes(data[pos + 1:pos + 5], "little"), pos + 5
    return int.from_bytes(data[pos + 1:pos + 9], "little"), pos + 9


def _align32(i: int) -> int:
    m = i % 4
    return i if m == 0 else i + 4 - m


def _scan_bdb_leaf_pages(data: bytes) -> Optional[bytes]:
    """Pure-Python BDB leaf-page scan for the ``mkey`` value.

    This is a byte-for-byte port of the reference implementation's
    ``force_purepython`` reader: it
    does not walk the B-tree, it scans every leaf page for the value/key pair
    (stored value-first on BDB leaf pages) and returns the value of the first
    ``mkey`` record it finds.
    """
    if len(data) < 24 or data[12:20] != _BDB_MAGIC:
        return None
    page_size = struct.unpack_from("<I", data, 20)[0]
    if page_size <= 0 or page_size > len(data):
        return None
    for page_base in range(page_size, len(data), page_size):
        if page_base + 26 > len(data):
            break
        item_count, first_item_pos, level, page_type = struct.unpack_from(
            "<HHBB", data, page_base + 20
        )
        if page_type != 5 or level != 1:  # leaf pages only
            continue
        pos = _align32(page_base + first_item_pos)
        value_pos = None
        value_len = None
        for i in range(item_count):
            if pos + 3 > len(data):
                break
            item_len, item_type = struct.unpack_from("<HB", data, pos)
            if item_type & ~0x80 == 1:  # variable-length key or value
                if item_type == 1:  # not deleted
                    if i % 2 == 0:  # value comes before its key
                        value_pos, value_len = pos + 3, item_len
                    elif item_len == len(_MKEY_KEY) and data[pos + 3:pos + 3 + item_len] == _MKEY_KEY:
                        if value_pos is not None and value_len is not None:
                            end = value_pos + value_len
                            if end <= len(data):
                                return data[value_pos:end]
                        return None
                pos = _align32(pos + 3 + item_len)
            else:
                pos += 12  # fixed-length item types
    return None


def _read_mkey_from_bdb(data: bytes, path: str) -> Optional[bytes]:
    """Read the raw ``mkey`` value, preferring berkeleydb then the pure-Python scan."""
    for name in ("berkeleydb", "bsddb3"):
        try:
            mod = __import__(name)
        except ImportError:
            continue
        dbmod = getattr(mod, "db", None)
        if dbmod is None or not path:
            continue
        try:
            db = dbmod.DB()
            db.open(path, "main", dbmod.DB_BTREE, dbmod.DB_RDONLY)
            try:
                return db.get(_MKEY_KEY)
            finally:
                db.close()
        except Exception:
            continue
    return _scan_bdb_leaf_pages(data)


def _read_mkey_from_sqlite(path: str) -> Optional[bytes]:
    if not path:
        return None
    import sqlite3

    try:
        con = sqlite3.connect(path)
    except sqlite3.Error:
        return None
    try:
        try:
            rows = con.execute("SELECT key, value FROM main").fetchall()
        except sqlite3.Error:
            return None
        for key, value in rows:
            if isinstance(key, bytes) and _MKEY_KEY in key:
                return value
        return None
    finally:
        con.close()


@register
class BitcoinCoreFormat(WalletFormat):
    format_key = "bitcoin-core"
    name = "Bitcoin Core wallet.dat"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [11300]
    john_formats = ["bitcoin"]

    def __init__(self, data: bytes, path: str = ""):
        super().__init__(data, path)
        self._records = None

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        if len(data) >= 20 and data[12:20] == _BDB_MAGIC:
            return Detection(cls.format_key, cls.name, 0.96, ["Berkeley DB magic 0x00053162 (Btree v9)"])
        if data.startswith(_SQLITE_MAGIC):
            return Detection(cls.format_key, cls.name, 0.9, ["SQLite 3 header"])
        return None

    def _read_mkey(self) -> bytes:
        if self.data.startswith(_SQLITE_MAGIC):
            mkey = _read_mkey_from_sqlite(self.path)
        else:
            mkey = _read_mkey_from_bdb(self.data, self.path)
        if not mkey:
            container = "SQLite" if self.data.startswith(_SQLITE_MAGIC) else "Berkeley DB"
            raise UnsupportedFormatError(
                f"no encrypted master key (mkey) record found in this {container} wallet.dat; "
                "is the wallet encrypted with a password?"
            )
        return mkey

    @staticmethod
    def _parse_mkey_value(mkey: bytes) -> dict:
        try:
            pos = 0
            cry_master_len, pos = _read_varint(mkey, pos)
            cry_master = mkey[pos:pos + cry_master_len]
            pos += cry_master_len
            salt_len, pos = _read_varint(mkey, pos)
            salt = mkey[pos:pos + salt_len]
            pos += salt_len
            method = int.from_bytes(mkey[pos:pos + 4], "little")
            iterations = int.from_bytes(mkey[pos + 4:pos + 8], "little")
        except (IndexError, struct.error):
            raise FormatError("truncated Bitcoin Core mkey record")

        if len(cry_master) != cry_master_len:
            raise FormatError("truncated Bitcoin Core encrypted master key")
        if method != 0:
            raise UnsupportedFormatError(
                f"Bitcoin Core nDerivationMethod {method} is not supported (only method 0 / SHA512)"
            )
        if cry_master_len < 32:
            raise FormatError("Bitcoin Core encrypted master key is too short")
        if salt_len not in (8, 18):
            raise UnsupportedFormatError(f"unexpected Bitcoin Core salt length {salt_len}")
        return {"cry_master": cry_master, "salt": salt, "iterations": iterations}

    def _extract_records(self) -> dict:
        if self._records is not None:
            return self._records
        mkey = self._read_mkey()
        self._records = self._parse_mkey_value(mkey)
        return self._records

    def inspect(self) -> Inspection:
        container = "SQLite" if self.data.startswith(_SQLITE_MAGIC) else "Berkeley DB"
        notes = []
        hashcat = None
        try:
            records = self._extract_records()
            hashcat = self._encode(records)
        except UnsupportedFormatError as exc:
            notes.append(str(exc))
        return Inspection(
            wallet="Bitcoin Core",
            format=f"Bitcoin Core wallet.dat ({container})",
            encrypted=True,
            kdf="SHA-512 based derivation (method 0)",
            cipher="AES-256-CBC",
            mac="final AES block PKCS#7 padding",
            offline_verification=True,
            classification=self.classification,
            hashcat=hashcat,
            notes=notes,
            source_references=[
                SourceReference("Bitcoin Core", "src/wallet/crypter.h", "CMasterKey"),
                SourceReference("Bitcoin Core", "src/wallet/walletdb.cpp", "WriteMasterKey"),
                SourceReference("Reference wallet-recovery implementation", "WalletBitcoinCore.load_from_filename", "BDB record layout"),
                SourceReference("John the Ripper", "run/bitcoin2john.py", "read_wallet"),
                SourceReference("Hashcat", "src/modules/module_11300.c", "module_hash_decode"),
            ],
        )

    def _encode(self, records: dict) -> HashcatHash:
        # Only the final two AES blocks are needed (the last is padding); this is
        # exactly what bitcoin2john.py emits and what module_11300.c accepts.
        part = records["cry_master"][-32:]
        cm = binascii.hexlify(part).decode()
        salt = binascii.hexlify(records["salt"]).decode()
        line = (
            f"$bitcoin${len(part) * 2}${cm}"
            f"${len(records['salt']) * 2}${salt}"
            f"${records['iterations']}"
            f"$2$00$2$00"
        )
        return HashcatHash(11300, "Bitcoin/Litecoin wallet.dat", line)

    def extract_hash(self) -> Optional[HashcatHash]:
        return self._encode(self._extract_records())

    def verify_password(self, password: str) -> VerifyStatus:
        records = self._extract_records()
        derived = password.encode("utf-8", "ignore") + records["salt"]
        for _ in range(records["iterations"]):
            derived = hashlib.sha512(derived).digest()
        part = records["cry_master"][-32:]
        plaintext = aes_decrypt("aes-256-cbc", derived[:32], part[:16], part[16:])
        if plaintext == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
            return VerifyStatus.VALID
        return VerifyStatus.INVALID
