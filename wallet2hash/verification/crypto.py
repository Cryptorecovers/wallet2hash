"""Cryptographic primitives used by the verifier.

Policy
------
wallet2hash prefers established cryptographic libraries, but its core must run
air-gapped on a bare Python installation. Two consequences follow:

* :func:`keccak256` is implemented here because the Python standard library does
  not ship Keccak (the *original* Keccak, as used by Ethereum — not NIST SHA3).
* A compact, decrypt-only AES-128/192/256 reference (CBC/CTR/ECB) is bundled as a
  fallback so common wallets can be verified with zero dependencies. It is only
  used when ``pycryptodome``/``cryptography`` are absent, and is exercised against
  the NIST FIPS-197 vectors in the test suite.

AEAD (AES-GCM, ChaCha20-Poly1305) and secp256k1 are *not* reimplemented; those
verification paths require an optional backend and raise a clear error otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Tuple

from ..errors import VerificationUnsupportedError


# ---------------------------------------------------------------------------
# Keccak-256 (original Keccak, Ethereum flavour)
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# r[x][y], flattened as index = y * 5 + x (x = column, y = row).
_ROT = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]

_MASK = 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f1600(state):
    """Keccak-f[1600] on a 25-lane state, flattened x-major.

    ``state[x + 5*y]`` holds lane ``A[x][y]`` (x = column, y = row), the
    canonical layout used by the Keccak team's reference and by FIPS 202.
    """
    for rc in _RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi: B[y, (2x + 3y) mod 5] = ROT(A[x, y], r[x, y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _ROT[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]) & _MASK
        # iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (Ethereum) digest of *data* (32 bytes, big-endian)."""
    rate = 136  # 1088-bit rate for a 256-bit output
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [0] * 25
    for i in range(0, len(padded), rate):
        block = padded[i:i + rate]
        for j in range(0, rate, 8):
            state[j // 8] ^= int.from_bytes(block[j:j + 8], "little")
        _keccak_f1600(state)

    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------
# KDF helpers with graceful degradation
# ---------------------------------------------------------------------------

def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, dklen: int = 32) -> bytes:
    try:
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    except (AttributeError, ValueError, NotImplementedError):
        pass
    # Fall back to the `cryptography` package when this Python's hashlib was
    # built without OpenSSL scrypt support.
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _Scrypt  # type: ignore
        kdf = _Scrypt(salt=salt, length=dklen, n=n, r=r, p=p)
        return kdf.derive(password)
    except Exception:
        raise VerificationUnsupportedError(
            "scrypt is unavailable in this Python build (hashlib.scrypt missing); "
            "install a Python built against OpenSSL 1.1+ or the 'cryptography' package "
            "to verify scrypt wallets"
        ) from None


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Optional AES backends
# ---------------------------------------------------------------------------

_AES_BACKEND = None
_BACKEND_NAME = None


def _detect_backend() -> Tuple[Optional[object], Optional[str]]:
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES, "pycryptodome"
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes  # type: ignore
        from cryptography.hazmat.backends import default_backend  # type: ignore
        return (algorithms, Cipher, modes, default_backend), "cryptography"
    except Exception:
        pass
    return None, None


def aes_backend_name() -> Optional[str]:
    return _BACKEND_NAME


def _backend_decrypt(algorithm: str, key: bytes, iv: bytes, ct: bytes) -> bytes:
    global _AES_BACKEND, _BACKEND_NAME
    if _AES_BACKEND is None and _BACKEND_NAME is None:
        _AES_BACKEND, _BACKEND_NAME = _detect_backend()

    if _BACKEND_NAME == "pycryptodome":
        AES = _AES_BACKEND
        if algorithm == "aes-128-ctr":
            from Crypto.Cipher import AES as _A  # noqa: F401
            return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).decrypt(ct)
        if algorithm == "aes-256-cbc":
            return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        if algorithm == "aes-256-ofb":
            return AES.new(key, AES.MODE_OFB, iv).decrypt(ct)
        if algorithm == "aes-256-ecb":
            return AES.new(key, AES.MODE_ECB).decrypt(ct)
        if algorithm == "aes-256-gcm":
            from Crypto.Cipher import AES as _A  # noqa: F401
            return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct[:-16], ct[-16:])
    if _BACKEND_NAME == "cryptography":
        algorithms, Cipher, modes, default_backend = _AES_BACKEND
        if algorithm == "aes-128-ctr":
            dec = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend()).decryptor()
            return dec.update(ct) + dec.finalize()
        if algorithm == "aes-256-cbc":
            dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
            return dec.update(ct) + dec.finalize()
        if algorithm == "aes-256-ofb":
            dec = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend()).decryptor()
            return dec.update(ct) + dec.finalize()
        if algorithm == "aes-256-ecb":
            dec = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
            return dec.update(ct) + dec.finalize()
        if algorithm == "aes-256-gcm":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
            from cryptography import exceptions
            try:
                return AESGCM(key).decrypt(iv, ct, None)
            except exceptions.InvalidTag:
                raise ValueError("invalid tag")
    return _reference_aes_decrypt(algorithm, key, iv, ct)


def _reference_aes_decrypt(algorithm: str, key: bytes, iv: bytes, ct: bytes) -> bytes:
    from ._aes import AesCipher  # deferred import

    if algorithm == "aes-128-ctr":
        return AesCipher(key).ctr(iv, ct)
    if algorithm == "aes-256-cbc":
        return AesCipher(key).cbc_decrypt(iv, ct)
    if algorithm == "aes-256-ecb":
        return AesCipher(key).ecb_decrypt(ct)
    raise VerificationUnsupportedError(f"no AES backend available for {algorithm}")


def aes_decrypt(algorithm: str, key: bytes, iv: bytes, ct: bytes) -> bytes:
    """Decrypt with a preferred backend, falling back to the bundled reference AES."""
    try:
        return _backend_decrypt(algorithm, key, iv, ct)
    except VerificationUnsupportedError:
        return _reference_aes_decrypt(algorithm, key, iv, ct)


def verify_aes_gcm(key: bytes, nonce: bytes, ct_with_tag: bytes) -> bool:
    """True if the AES-256-GCM ciphertext authenticates under *key*/*nonce*."""
    global _AES_BACKEND, _BACKEND_NAME
    if _AES_BACKEND is None and _BACKEND_NAME is None:
        _AES_BACKEND, _BACKEND_NAME = _detect_backend()
    if _BACKEND_NAME is None:
        raise VerificationUnsupportedError(
            "AES-GCM verification requires pycryptodome or cryptography; "
            "install 'pycryptodome' to verify MetaMask vaults offline"
        )
    try:
        _backend_decrypt("aes-256-gcm", key, nonce, ct_with_tag)
        return True
    except ValueError:
        return False
