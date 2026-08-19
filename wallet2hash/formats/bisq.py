"""Bisq wallet (``.wallet``) handler — Hashcat mode 29800.

Bisq uses a bitcoinj wallet container (protobuf) with scrypt + AES key
encryption. Hashcat mode 29800 ("Bisq .wallet (scrypt)") consumes::

    $bisq$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32 bytes)>

Extraction is verified against Hashcat's own converter ``tools/bisq2hashcat.py``
and ``src/modules/module_29800.c``, and the protobuf field numbers against
bitcoinj's ``core/src/main/proto/wallet.proto``:

* ``Wallet.network_identifier``   = field 1 (string)
* ``Wallet.key``                  = field 3 (repeated ``Key``)
* ``Wallet.encryption_type``      = field 5 (varint; ``ENCRYPTED_SCRYPT_AES`` = 2)
* ``Wallet.encryption_parameters`` = field 6 (``ScryptParameters``)
* ``ScryptParameters.salt``       = field 1 (8 bytes)
* ``ScryptParameters.n/r/p``      = fields 2/3/4 (varint)
* ``Key.type``                    = field 1 (``ENCRYPTED_SCRYPT_AES``=2, ``DETERMINISTIC_KEY``=4)
* ``Key.encrypted_data``          = field 6 (``EncryptedData``)
* ``EncryptedData.encrypted_private_key`` = field 2 (bytes; last 32 used)

Only the scrypt-encrypted bitcoinj wallet is supported here (the ``version 3``
path of ``bisq2hashcat.py``); that is the only variant mode 29800 accepts.
"""

from __future__ import annotations

import binascii
from typing import List, Optional

from ..errors import FormatError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import WalletFormat, register

_BISQ_VERSION = 3


def _read_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise FormatError("truncated protobuf varint")
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise FormatError("protobuf varint too long")


def parse_message(data: bytes) -> dict:
    """Parse a protobuf message into ``{field_number: [values]}``.

    varint/fixed fields become ``int``; length-delimited fields stay ``bytes``.
    Nested messages are left as raw bytes and re-parsed by the caller.
    """
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            val, pos = _read_varint(data, pos)
        elif wire_type == 1:  # 64-bit
            val = int.from_bytes(data[pos:pos + 8], "little")
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            val = data[pos:pos + length]
            pos += length
        elif wire_type == 5:  # 32-bit
            val = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
        else:
            # Unknown wire types 3/4 (groups) are legacy; skip would be unsafe,
            # so refuse rather than mis-parse.
            raise FormatError(f"unsupported protobuf wire type {wire_type}")
        fields.setdefault(field_num, []).append(val)
    return fields


def _first_int(fields: dict, number: int):
    values = fields.get(number)
    if not values:
        return None
    return values[0]


@register
class BisqFormat(WalletFormat):
    format_key = "bisq"
    name = "Bisq wallet"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [29800]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        if b"org.bitcoin" not in data:
            return None
        # MultiBit Classic .wallet files are also bitcoinj containers but carry
        # their own "org.multibit" extension; that is 27700's territory.
        if b"org.multibit" in data:
            return None
        try:
            wallet = parse_message(data)
        except FormatError:
            return None
        net = _first_int(wallet, 1)  # field 1 is network_identifier (bytes)
        if not (isinstance(net, bytes) and b"org.bitcoin" in net):
            return None
        enc_type = _first_int(wallet, 5)
        if enc_type != 2:  # ENCRYPTED_SCRYPT_AES
            return None
        evidence = [f"network={net[:40]!r}", "bitcoinj scrypt encryption"]
        return Detection(cls.format_key, cls.name, 0.95, evidence)

    def parse(self) -> dict:
        data = self.data
        try:
            wallet = parse_message(data)
        except FormatError as exc:
            raise FormatError(f"not a bitcoinj/Bisq wallet: {exc}") from exc

        net = _first_int(wallet, 1)
        if not isinstance(net, bytes) or b"org.bitcoin" not in net:
            raise FormatError("not a bitcoinj/Bisq wallet (network identifier)")

        enc_type = _first_int(wallet, 5)
        if enc_type is None:
            raise FormatError("wallet is not encrypted")
        if enc_type != 2:
            raise FormatError(f"unsupported bitcoinj encryption type {enc_type}")

        params_raw = wallet.get(6)
        if not params_raw:
            raise FormatError("wallet is missing scrypt encryption parameters")
        params = parse_message(params_raw[0])
        salt = params.get(1, [b""])[0]
        # ScryptParameters declares defaults in wallet.proto; old bitcoinj
        # wallets omit n/r/p and rely on them.
        n = _first_int(params, 2) or 16384
        r = _first_int(params, 3) or 8
        p = _first_int(params, 4) or 1
        if not isinstance(salt, bytes) or n is None or r is None or p is None:
            raise FormatError("incomplete scrypt parameters")

        part_encrypted_key = None
        for key_raw in wallet.get(3, []):
            try:
                key = parse_message(key_raw)
            except FormatError:
                continue
            key_type = _first_int(key, 1)
            if key_type not in (2, 4):  # ENCRYPTED_SCRYPT_AES / DETERMINISTIC_KEY
                continue
            enc_data_raw = key.get(6)
            if not enc_data_raw:
                continue
            enc_data = parse_message(enc_data_raw[0])
            encrypted_key = enc_data.get(2, [b""])[0]
            if isinstance(encrypted_key, bytes) and len(encrypted_key) == 48:
                part_encrypted_key = encrypted_key[-32:]
                break

        if part_encrypted_key is None:
            raise FormatError("no encrypted scrypt-AES key found in wallet")

        return {
            "network": net,
            "salt": salt,
            "n": n,
            "r": r,
            "p": p,
            "encrypted_key": part_encrypted_key,
        }

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="Bisq",
            format=self.name,
            encrypted=True,
            kdf=f"scrypt (N={m['n']}, r={m['r']}, p={m['p']})",
            cipher="AES-256-CBC",
            mac="decrypted key structure / padding",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("bitcoinj", "core/src/main/proto/wallet.proto", "Wallet/Key/ScryptParameters"),
                SourceReference("Hashcat", "tools/bisq2hashcat.py", "process_file"),
                SourceReference("Hashcat", "src/modules/module_29800.c", "module_hash_decode"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        salt_hex = binascii.hexlify(m["salt"]).decode()
        data_hex = binascii.hexlify(m["encrypted_key"]).decode()
        line = f"$bisq${_BISQ_VERSION}*{m['n']}*{m['r']}*{m['p']}*{salt_hex}*{data_hex}"
        return HashcatHash(29800, "Bisq .wallet (scrypt)", line)

    def verify_password(self, password: str) -> VerifyStatus:
        # scrypt + AES-256-CBC over the encrypted key; the full KDF/decryption
        # chain is not yet fixture-validated, so refuse rather than guess.
        return VerifyStatus.UNSUPPORTED

    def source_references(self) -> List[dict]:
        return [
            {"project": "bitcoinj", "file": "core/src/main/proto/wallet.proto", "function": "Wallet/Key/ScryptParameters"},
            {"project": "Hashcat", "file": "tools/bisq2hashcat.py", "function": "process_file"},
            {"project": "Hashcat", "file": "src/modules/module_29800.c", "function": "module_hash_decode"},
        ]
