"""Compact reference AES-128/192/256 (decrypt-focused) for offline verification.

Used only as a fallback when no external AES backend is installed. The block
cipher follows FIPS-197 exactly; the S-box and inverse S-box are generated from
the GF(2^8) field arithmetic rather than pasted as tables. Tested against the
NIST FIPS-197 test vectors in ``tests/test_aes.py``.

This module is deliberately decryption-oriented and is *not* a general purpose
crypto library.
"""

from __future__ import annotations


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    if a == 0:
        return 0
    for b in range(1, 256):
        if _gf_mul(a, b) == 1:
            return b
    raise ArithmeticError("unreachable: GF(2^8) is a field")


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    s = [0] * 256
    for i in range(256):
        inv = _gf_inv(i)
        s[i] = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
    return s


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(x: int) -> int:
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def _mul4(a: int, b: int) -> int:
    """Multiply in GF(2^8) using the AES polynomial 0x11B."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


class AesCipher:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.key = key
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes):
        nk, nr = self.nk, self.nr
        w = [0] * (4 * (nr + 1))
        for i in range(nk):
            w[i] = int.from_bytes(key[4 * i:4 * i + 4], "big")
        for i in range(nk, 4 * (nr + 1)):
            temp = w[i - 1]
            if i % nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ (_RCON[i // nk - 1] << 24)
            elif nk > 6 and i % nk == 4:
                temp = self._sub_word(temp)
            w[i] = w[i - nk] ^ temp
        return w

    @staticmethod
    def _rot_word(w: int) -> int:
        return ((w << 8) & 0xFFFFFFFF) | (w >> 24)

    @staticmethod
    def _sub_word(w: int) -> int:
        return (
            (_SBOX[(w >> 24) & 0xFF] << 24)
            | (_SBOX[(w >> 16) & 0xFF] << 16)
            | (_SBOX[(w >> 8) & 0xFF] << 8)
            | _SBOX[w & 0xFF]
        )

    def encrypt_block(self, block: bytes) -> bytes:
        s = [block[i] for i in range(16)]
        self._add_round_key(s, 0)
        for rnd in range(1, self.nr):
            self._sub_bytes(s)
            self._shift_rows(s)
            self._mix_columns(s)
            self._add_round_key(s, rnd)
        self._sub_bytes(s)
        self._shift_rows(s)
        self._add_round_key(s, self.nr)
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = [block[i] for i in range(16)]
        self._add_round_key(s, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            self._inv_shift_rows(s)
            self._inv_sub_bytes(s)
            self._add_round_key(s, rnd)
            self._inv_mix_columns(s)
        self._inv_shift_rows(s)
        self._inv_sub_bytes(s)
        self._add_round_key(s, 0)
        return bytes(s)

    def _add_round_key(self, s, rnd: int):
        rk = self.round_keys[rnd * 4:(rnd + 1) * 4]
        for i in range(4):
            word = rk[i]
            s[4 * i] ^= (word >> 24) & 0xFF
            s[4 * i + 1] ^= (word >> 16) & 0xFF
            s[4 * i + 2] ^= (word >> 8) & 0xFF
            s[4 * i + 3] ^= word & 0xFF

    @staticmethod
    def _sub_bytes(s):
        for i in range(16):
            s[i] = _SBOX[s[i]]

    @staticmethod
    def _inv_sub_bytes(s):
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    @staticmethod
    def _shift_rows(s):
        # rows 1..3 left-rotate by 1..3
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    @staticmethod
    def _inv_shift_rows(s):
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]

    @staticmethod
    def _mix_columns(s):
        # State is column-major: column c is the four consecutive bytes
        # s[4c], s[4c+1], s[4c+2], s[4c+3] (rows 0..3).
        for c in range(4):
            b = 4 * c
            a0, a1, a2, a3 = s[b], s[b + 1], s[b + 2], s[b + 3]
            s[b] = _mul4(a0, 2) ^ _mul4(a1, 3) ^ a2 ^ a3
            s[b + 1] = a0 ^ _mul4(a1, 2) ^ _mul4(a2, 3) ^ a3
            s[b + 2] = a0 ^ a1 ^ _mul4(a2, 2) ^ _mul4(a3, 3)
            s[b + 3] = _mul4(a0, 3) ^ a1 ^ a2 ^ _mul4(a3, 2)

    @staticmethod
    def _inv_mix_columns(s):
        for c in range(4):
            b = 4 * c
            a0, a1, a2, a3 = s[b], s[b + 1], s[b + 2], s[b + 3]
            s[b] = _mul4(a0, 14) ^ _mul4(a1, 11) ^ _mul4(a2, 13) ^ _mul4(a3, 9)
            s[b + 1] = _mul4(a0, 9) ^ _mul4(a1, 14) ^ _mul4(a2, 11) ^ _mul4(a3, 13)
            s[b + 2] = _mul4(a0, 13) ^ _mul4(a1, 9) ^ _mul4(a2, 14) ^ _mul4(a3, 11)
            s[b + 3] = _mul4(a0, 11) ^ _mul4(a1, 13) ^ _mul4(a2, 9) ^ _mul4(a3, 14)

    # -- modes -------------------------------------------------------------

    def ecb_decrypt(self, ct: bytes) -> bytes:
        if len(ct) % 16:
            raise ValueError("ECB ciphertext length must be a multiple of 16")
        return b"".join(self.decrypt_block(ct[i:i + 16]) for i in range(0, len(ct), 16))

    def cbc_encrypt(self, iv: bytes, pt: bytes) -> bytes:
        if len(iv) != 16 or len(pt) % 16:
            raise ValueError("bad CBC parameters")
        out = bytearray()
        prev = iv
        for i in range(0, len(pt), 16):
            block = bytes(a ^ b for a, b in zip(pt[i:i + 16], prev))
            enc = self.encrypt_block(block)
            out += enc
            prev = enc
        return bytes(out)

    def cbc_decrypt(self, iv: bytes, ct: bytes) -> bytes:
        if len(iv) != 16 or len(ct) % 16:
            raise ValueError("bad CBC parameters")
        out = bytearray()
        prev = iv
        for i in range(0, len(ct), 16):
            block = ct[i:i + 16]
            pt = self.decrypt_block(block)
            out += bytes(a ^ b for a, b in zip(pt, prev))
            prev = block
        return bytes(out)

    def ctr(self, iv: bytes, data: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("CTR IV must be 16 bytes")
        out = bytearray()
        counter = int.from_bytes(iv, "big")
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            keystream = self.encrypt_block(counter.to_bytes(16, "big"))
            out += bytes(a ^ b for a, b in zip(block, keystream))
            counter = (counter + 1) & ((1 << 128) - 1)
        return bytes(out)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padlen = block_size - (len(data) % block_size)
    return data + bytes([padlen]) * padlen


def strip_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("invalid padded length")
    padlen = data[-1]
    if not 0 < padlen <= 16:
        raise ValueError("invalid padding byte")
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("invalid padding")
    return data[:-padlen]
