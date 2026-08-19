"""Exodus wallet (``exodus.seco``) handler — Hashcat mode 28200.

Format facts verified against Hashcat's own converter
``tools/exodus2hashcat.py``, which is the reference implementation for mode 28200:

* Container header starts with the magic ``SECO``, version 0, and the version
  tag ``seco-v0-scrypt-aes`` (224-byte header).
* A 256-byte metadata block holds the scrypt salt (32 bytes), ``n``/``r``/``p``
  (big-endian), the cipher name ``aes-256-gcm`` (32 bytes, null-padded), and two
  AES-256-GCM envelopes: a ``blob_key`` (iv, auth_tag, key) that wraps the data
  key, and a ``blob`` (iv, auth_tag) for the ciphertext itself.
* Encoded hash::

      EXODUS:<n>:<r>:<p>:<salt_b64>:<blob_key_iv_b64>:<blob_key_key_b64>:<blob_key_auth_tag_b64>

The extraction below replicates ``exodus2hashcat.py`` field-for-field, including
the checksum validation, so the emitted line is exactly what Hashcat 28200
expects.
"""

from __future__ import annotations

import base64
import hashlib
import io
import struct
from typing import Optional

from ..errors import FormatError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register

_MAGIC = b"SECO"
_VERSION_TAG = b"seco-v0-scrypt-aes"
_HEADER_SIZE = 224
_METADATA_SIZE = 256
_CHECKSUM_SIZE = 32

_SALT_SIZE = 32
_CIPHER_SIZE = 32
_BLOB_KEY_IV_SIZE = 12
_BLOB_KEY_AUTH_TAG_SIZE = 16
_BLOB_KEY_KEY_SIZE = 32
_BLOB_IV_SIZE = 12
_BLOB_AUTH_TAG_SIZE = 16


@register
class ExodusFormat(WalletFormat):
    format_key = "exodus"
    name = "Exodus wallet (SECO)"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [28200]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        if not data.startswith(_MAGIC):
            return None
        evidence = ["SECO magic"]
        if _VERSION_TAG in data[:_HEADER_SIZE]:
            evidence.append("seco-v0-scrypt-aes version tag")
        return Detection(cls.format_key, cls.name, 0.98, evidence)

    def parse(self) -> dict:
        data = self.data
        if not data.startswith(_MAGIC):
            raise FormatError("not an Exodus SECO file (missing magic)")

        buf = io.BytesIO(data)

        header = buf.read(_HEADER_SIZE)
        if len(header) < _HEADER_SIZE:
            raise FormatError("Exodus SECO file is truncated (header)")
        hb = io.BytesIO(header)
        magic, version = struct.unpack(">4sL4x", hb.read(12))
        if magic != _MAGIC:
            raise FormatError("not an Exodus SECO file")
        if version != 0:
            raise FormatError(f"unsupported Exodus SECO version {version}")

        (vtlen,) = struct.unpack(">B", hb.read(1))
        version_tag = hb.read(vtlen)
        (namelen,) = struct.unpack(">B", hb.read(1))
        app_name = hb.read(namelen)
        (verlen,) = struct.unpack(">B", hb.read(1))
        app_version = hb.read(verlen)
        if version_tag != _VERSION_TAG:
            raise FormatError(f"unsupported Exodus version tag {version_tag!r}")

        checksum = buf.read(_CHECKSUM_SIZE)
        if len(checksum) < _CHECKSUM_SIZE:
            raise FormatError("Exodus SECO file is truncated (checksum)")

        metadata = buf.read(_METADATA_SIZE)
        if len(metadata) < _METADATA_SIZE:
            raise FormatError("Exodus SECO file is truncated (metadata)")
        mb = io.BytesIO(metadata)
        salt = mb.read(_SALT_SIZE)
        n, r, p = struct.unpack(">LLL", mb.read(12))
        cipher_raw = mb.read(_CIPHER_SIZE)
        cipher = cipher_raw.rstrip(b"\x00")
        blob_key_iv = mb.read(_BLOB_KEY_IV_SIZE)
        blob_key_auth_tag = mb.read(_BLOB_KEY_AUTH_TAG_SIZE)
        blob_key_key = mb.read(_BLOB_KEY_KEY_SIZE)
        blob_iv = mb.read(_BLOB_IV_SIZE)
        blob_auth_tag = mb.read(_BLOB_AUTH_TAG_SIZE)

        (blob_len,) = struct.unpack(">L", buf.read(4))
        blob = buf.read(blob_len)
        if len(blob) < blob_len:
            raise FormatError("Exodus SECO file is truncated (blob)")

        # Recompute the file checksum exactly as exodus2hashcat.py does.
        digest = hashlib.sha256()
        digest.update(salt)
        digest.update(struct.pack(">LLL", n, r, p))
        digest.update(cipher.ljust(_CIPHER_SIZE, b"\x00"))
        digest.update(blob_key_iv)
        digest.update(blob_key_auth_tag)
        digest.update(blob_key_key)
        digest.update(blob_iv)
        digest.update(blob_auth_tag)
        metadata_size = (
            _SALT_SIZE + 12 + _CIPHER_SIZE
            + _BLOB_KEY_IV_SIZE + _BLOB_KEY_AUTH_TAG_SIZE + _BLOB_KEY_KEY_SIZE
            + _BLOB_IV_SIZE + _BLOB_AUTH_TAG_SIZE
        )
        digest.update(bytes(_METADATA_SIZE - metadata_size))
        digest.update(struct.pack(">L", blob_len))
        digest.update(blob)
        if checksum != digest.digest():
            raise FormatError("Exodus SECO file is corrupted (checksum mismatch)")

        return {
            "salt": salt,
            "n": n,
            "r": r,
            "p": p,
            "cipher": cipher,
            "blob_key_iv": blob_key_iv,
            "blob_key_auth_tag": blob_key_auth_tag,
            "blob_key_key": blob_key_key,
            "blob_iv": blob_iv,
            "blob_auth_tag": blob_auth_tag,
            "app_name": app_name,
            "app_version": app_version,
        }

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="Exodus",
            format=self.name,
            version=m["app_version"].decode(errors="replace") or None,
            encrypted=True,
            kdf=f"scrypt (N={m['n']}, r={m['r']}, p={m['p']})",
            cipher="AES-256-GCM",
            mac="GCM tag on the encrypted blob key",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("Hashcat", "tools/exodus2hashcat.py", "read_file"),
                SourceReference("Hashcat", "src/modules/module_28200.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        b64 = base64.b64encode
        line = ":".join([
            "EXODUS",
            str(m["n"]),
            str(m["r"]),
            str(m["p"]),
            b64(m["salt"]).decode(),
            b64(m["blob_key_iv"]).decode(),
            b64(m["blob_key_key"]).decode(),
            b64(m["blob_key_auth_tag"]).decode(),
        ])
        return HashcatHash(28200, "Exodus Wallet (scrypt)", line)

    def verify_password(self, password: str) -> VerifyStatus:
        # scrypt + AES-256-GCM over the blob key. The exact scrypt output length
        # has not been independently confirmed against an Exodus fixture, so this
        # refuses rather than guess; use Hashcat 28200 with the extracted hash.
        return VerifyStatus.UNSUPPORTED

    def source_references(self):
        return [
            {"project": "Hashcat", "file": "tools/exodus2hashcat.py", "function": "read_file"},
            {"project": "Hashcat", "file": "src/modules/module_28200.c", "function": "module_hash_decode"},
        ]
