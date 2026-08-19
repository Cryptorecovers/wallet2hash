"""MultiBit Classic ``.wallet`` (bitcoinj protobuf) handler — Hashcat mode 27700.

MultiBit Classic stores its wallet as a bitcoinj ``Wallet`` protobuf with
scrypt + AES-256-CBC key encryption — the same container Bisq uses, which is why
this handler reuses ``formats/bisq.py``'s protobuf parser.

Format facts (verified against ``run/multibit2john.py`` in John the Ripper,
``src/modules/module_27700.c`` and ``tools/test_modules/m27700.pm`` in Hashcat,
and the reference wallet-recovery implementation's ``WalletBitcoinj``):

* The scrypt parameters (salt, n, r, p) live on the wallet message; the last 32
  bytes of an ``encrypted_private_key`` (48 bytes) provide the two AES blocks
  that decrypt to a full padding block.
* Encoded hash: ``$multibit$3*<n>*<r>*<p>*<salt_hex(8 bytes)>*<data_hex(32)>``
  — the same line multibit2john.py emits (``version 3`` path).
* Password check (m27700): key = scrypt(pass UTF-16BE, salt, n, r, p, 32);
  AES-256-CBC-decrypt the second 16-byte block with the first as IV; the result
  must be 16 bytes of ``0x10`` (PKCS7 padding of the private key).

There is no Hashcat mode for this file's JtR ``$multibit$3`` output — 27700 is
Hashcat's own mode for it.
"""

from __future__ import annotations

import binascii
from typing import List, Optional

from ..errors import FormatError, VerificationUnsupportedError
from ..models import Classification, Detection, HashcatHash, Inspection, SourceReference, VerifyStatus
from ..registry import register
from ..verification.crypto import aes_decrypt, scrypt
from .bisq import BisqFormat, parse_message, _first_int


@register
class MultiBitWalletFormat(BisqFormat):
    format_key = "multibit-wallet"
    name = "MultiBit Classic (.wallet, bitcoinj protobuf)"
    classification = Classification.EXISTING_HASHCAT
    hashcat_modes = [27700]
    john_formats = ["multibit"]

    @classmethod
    def detect(cls, data: bytes, path: str = "") -> Optional[Detection]:
        # MultiBit Classic .wallet files carry the "org.multibit.walletProtect"
        # extension in a wallet-level field (see the public test wallets).
        if b"org.multibit" not in data or b"org.bitcoin" not in data:
            return None
        try:
            wallet = parse_message(data)
        except FormatError:
            return None
        if _first_int(wallet, 5) != 2:  # ENCRYPTED_SCRYPT_AES
            return None
        return Detection(cls.format_key, cls.name, 0.98,
                         ["bitcoinj protobuf + org.multibit marker", "scrypt-AES encryption"])

    def inspect(self) -> Inspection:
        m = self.parse()
        return Inspection(
            wallet="MultiBit",
            format=self.name,
            encrypted=True,
            kdf=f"scrypt (N={m['n']}, r={m['r']}, p={m['p']})",
            cipher="AES-256-CBC",
            mac="decrypted block must be full PKCS7 padding",
            offline_verification=True,
            classification=self.classification,
            hashcat=self.extract_hash(),
            source_references=[
                SourceReference("bitcoinj", "core/src/main/proto/wallet.proto", "Wallet/Key/ScryptParameters"),
                SourceReference("John the Ripper", "run/multibit2john.py", "process_file (version 3)"),
                SourceReference("Hashcat", "src/modules/module_27700.c", "module_hash_decode"),
                SourceReference("Hashcat", "tools/test_modules/m27700.pm", "module_generate_hash"),
            ],
        )

    def extract_hash(self) -> Optional[HashcatHash]:
        m = self.parse()
        salt_hex = binascii.hexlify(m["salt"]).decode()
        data_hex = binascii.hexlify(m["encrypted_key"]).decode()
        line = f"$multibit$3*{m['n']}*{m['r']}*{m['p']}*{salt_hex}*{data_hex}"
        return HashcatHash(27700, "MultiBit Classic .wallet (scrypt)", line)

    def verify_password(self, password: str) -> VerifyStatus:
        # m27700: scrypt(pass UTF-16BE, salt) -> AES-256-CBC; the second block
        # of the extracted data must decrypt to 16 bytes of 0x10.
        m = self.parse()
        try:
            key = scrypt(password.encode("utf_16_be"), m["salt"], m["n"], m["r"], m["p"], 32)
        except VerificationUnsupportedError:
            return VerifyStatus.UNSUPPORTED
        data = m["encrypted_key"]  # 32 bytes: [prev-ct block][padding block]
        try:
            block = aes_decrypt("aes-256-cbc", key, data[:16], data[16:32])
        except Exception:
            return VerifyStatus.CORRUPTED
        if block == b"\x10" * 16:
            return VerifyStatus.VALID
        return VerifyStatus.INVALID
