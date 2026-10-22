"""Encrypt local data for the current user on macOS (v0.10.22, Mac build).

The Mac counterpart of Windows DPAPI, used for configuration backups and the backup fingerprint
key. A random 512-bit key is created once and kept in the user's login keychain
(app.core.macos_keychain); data is encrypted with AES-256-CBC (CommonCrypto, part of macOS) and
authenticated with HMAC-SHA256 over the whole message (encrypt-then-MAC), so a changed or
truncated file is refused before it is decrypted.

Format: b"NWMK1" | iv (16 bytes) | ciphertext | tag (32 bytes)
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import secrets
import sys
import threading
from ctypes import POINTER, c_int32, c_size_t, c_uint32, c_void_p

MAGIC = b"NWMK1"
KEY_SERVICE = "NodeWatch:LocalDataKey"
_IV = 16
_TAG = 32
_LOCK = threading.Lock()
_KEY: bytes | None = None


class ProtectError(RuntimeError):
    pass


def available() -> bool:
    return sys.platform == "darwin"


# --------------------------------------------------------------------------- AES (CommonCrypto)
_CC = None


def _commoncrypto():
    global _CC
    if _CC is None:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")  # CommonCrypto lives in libSystem
        fn = lib.CCCrypt
        # CCCryptorStatus CCCrypt(CCOperation, CCAlgorithm, CCOptions, const void *key, size_t keyLength,
        #     const void *iv, const void *dataIn, size_t dataInLength, void *dataOut,
        #     size_t dataOutAvailable, size_t *dataOutMoved)
        fn.argtypes = [
            c_uint32,
            c_uint32,
            c_uint32,
            c_void_p,
            c_size_t,
            c_void_p,
            c_void_p,
            c_size_t,
            c_void_p,
            c_size_t,
            POINTER(c_size_t),
        ]
        fn.restype = c_int32
        _CC = fn
    return _CC


_K_CC_ENCRYPT, _K_CC_DECRYPT = 0, 1
_K_CC_ALGORITHM_AES = 0
_K_CC_OPTION_PKCS7 = 1


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    fn = _commoncrypto()
    out = ctypes.create_string_buffer(len(data) + 16)
    moved = c_size_t(0)
    status = fn(
        _K_CC_ENCRYPT if encrypt else _K_CC_DECRYPT,
        _K_CC_ALGORITHM_AES,
        _K_CC_OPTION_PKCS7,
        key,
        len(key),
        iv,
        data,
        len(data),
        out,
        len(out),
        ctypes.byref(moved),
    )
    if status != 0:
        raise ProtectError(f"CommonCrypto error {status}")
    return out.raw[: moved.value]


# --------------------------------------------------------------------------- key
def _keychain():
    from app.core import macos_keychain

    return macos_keychain


def _key() -> bytes:
    """The per-user data key, created on first use. Never replaced when it exists but cannot be
    read (locked keychain, denied prompt): a new key would make every existing backup unreadable."""
    global _KEY
    with _LOCK:
        if _KEY is None:
            kc = _keychain()
            key = kc.get_password(KEY_SERVICE)
            if key is None:
                key = secrets.token_bytes(64)
                kc.set_password(KEY_SERVICE, key, label="NodeWatch local data key")
                if kc.get_password(KEY_SERVICE) != key:
                    raise ProtectError("the new data key could not be read back from the Keychain")
            if len(key) != 64:
                raise ProtectError("the NodeWatch data key in the Keychain is damaged")
            _KEY = key
        return _KEY


# --------------------------------------------------------------------------- public
def protect(raw: bytes) -> bytes:
    key = _key()
    iv = os.urandom(_IV)
    body = MAGIC + iv + _aes_cbc(key[:32], iv, raw, True)
    return body + hmac.new(key[32:], body, hashlib.sha256).digest()


def is_protected(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def unprotect(blob: bytes) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + _IV + 16 + _TAG:
        raise ProtectError("not NodeWatch-encrypted data")
    key = _key()
    body, tag = blob[:-_TAG], blob[-_TAG:]
    if not hmac.compare_digest(hmac.new(key[32:], body, hashlib.sha256).digest(), tag):
        raise ProtectError("the encrypted data was changed or belongs to another user or Mac")
    iv = body[len(MAGIC) : len(MAGIC) + _IV]
    return _aes_cbc(key[:32], iv, body[len(MAGIC) + _IV :], False)
