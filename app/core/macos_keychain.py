"""macOS Keychain access for NodeWatch (v0.10.22, Mac build).

Generic-password items in the user's login keychain through Security.framework's SecItem API,
with the standard library only (ctypes). This is the Mac counterpart of Windows Credential
Manager: secrets are encrypted by macOS with the user's login keychain, and only programs the
item's access list trusts (the NodeWatch Python runtime that created it) read them without asking.

Each item is identified by (service, account). NodeWatch uses the credential target name
("NodeWatch:MistApiToken", ...) as the service and "NodeWatch" as the account, so the entries
appear under those names in the Keychain Access app.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import POINTER, byref, c_char_p, c_int32, c_long, c_uint32, c_void_p

ACCOUNT = "NodeWatch"

ERR_SEC_SUCCESS = 0
ERR_SEC_ITEM_NOT_FOUND = -25300
ERR_SEC_DUPLICATE_ITEM = -25299
ERR_SEC_AUTH_FAILED = -25293
ERR_SEC_INTERACTION_NOT_ALLOWED = -25308
ERR_SEC_PARAM = -50
ERR_SEC_NO_SUCH_ATTR = -25303
ERR_USER_CANCELED = -128

_UTF8 = 0x08000100  # kCFStringEncodingUTF8

_SECURITY = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"


class KeychainError(RuntimeError):
    def __init__(self, action: str, status: int):
        hint = {
            ERR_USER_CANCELED: "access was denied in the Keychain prompt",
            ERR_SEC_AUTH_FAILED: "the login keychain is locked or the password was wrong",
            ERR_SEC_INTERACTION_NOT_ALLOWED: "the login keychain is locked",
        }.get(status, "")
        super().__init__(f"macOS Keychain {action} failed (OSStatus {status}{': ' + hint if hint else ''})")
        self.status = status


class _Api:
    """Function prototypes and constants, loaded once on first use (macOS only)."""

    def __init__(self) -> None:
        sec = ctypes.CDLL(_SECURITY)
        cf = ctypes.CDLL(_CORE_FOUNDATION)

        cf.CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_uint32]
        cf.CFStringCreateWithCString.restype = c_void_p
        cf.CFDataCreate.argtypes = [c_void_p, c_char_p, c_long]
        cf.CFDataCreate.restype = c_void_p
        cf.CFDataGetBytePtr.argtypes = [c_void_p]
        cf.CFDataGetBytePtr.restype = c_void_p
        cf.CFDataGetLength.argtypes = [c_void_p]
        cf.CFDataGetLength.restype = c_long
        cf.CFDictionaryCreate.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_void_p), c_long, c_void_p, c_void_p]
        cf.CFDictionaryCreate.restype = c_void_p
        cf.CFRelease.argtypes = [c_void_p]
        cf.CFRelease.restype = None

        sec.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]
        sec.SecItemCopyMatching.restype = c_int32
        sec.SecItemAdd.argtypes = [c_void_p, POINTER(c_void_p)]
        sec.SecItemAdd.restype = c_int32
        sec.SecItemUpdate.argtypes = [c_void_p, c_void_p]
        sec.SecItemUpdate.restype = c_int32
        sec.SecItemDelete.argtypes = [c_void_p]
        sec.SecItemDelete.restype = c_int32

        def const(lib, name: str) -> int:
            return c_void_p.in_dll(lib, name).value  # a CFStringRef / CFBooleanRef global

        self.sec, self.cf = sec, cf
        self.kSecClass = const(sec, "kSecClass")
        self.kSecClassGenericPassword = const(sec, "kSecClassGenericPassword")
        self.kSecAttrService = const(sec, "kSecAttrService")
        self.kSecAttrAccount = const(sec, "kSecAttrAccount")
        self.kSecAttrLabel = const(sec, "kSecAttrLabel")
        self.kSecAttrAccessible = const(sec, "kSecAttrAccessible")
        # Readable once the Mac has been unlocked after boot; never migrates to another device via backup.
        self.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = const(sec, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")
        self.kSecValueData = const(sec, "kSecValueData")
        self.kSecReturnData = const(sec, "kSecReturnData")
        self.kSecMatchLimit = const(sec, "kSecMatchLimit")
        self.kSecMatchLimitOne = const(sec, "kSecMatchLimitOne")
        self.kCFBooleanTrue = const(cf, "kCFBooleanTrue")
        # The callback structs themselves are the globals: pass their addresses.
        self.key_callbacks = ctypes.addressof(c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks"))
        self.value_callbacks = ctypes.addressof(c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks"))

    # -- CoreFoundation helpers (every object created here is released by the caller)
    def string(self, text: str) -> int:
        ref = self.cf.CFStringCreateWithCString(None, text.encode("utf-8"), _UTF8)
        if not ref:
            raise KeychainError("string conversion", -1)
        return ref

    def data(self, raw: bytes) -> int:
        ref = self.cf.CFDataCreate(None, raw, len(raw))
        if not ref:
            raise KeychainError("data conversion", -1)
        return ref

    def dictionary(self, pairs: list[tuple[int, int]]) -> int:
        n = len(pairs)
        keys = (c_void_p * n)(*[k for k, _ in pairs])
        values = (c_void_p * n)(*[v for _, v in pairs])
        ref = self.cf.CFDictionaryCreate(None, keys, values, n, self.key_callbacks, self.value_callbacks)
        if not ref:
            raise KeychainError("query construction", -1)
        return ref  # the dictionary retains its keys and values

    def release(self, *refs: int | None) -> None:
        for ref in refs:
            if ref:
                self.cf.CFRelease(ref)


_API: _Api | None = None
_LOCK = threading.Lock()


def available() -> bool:
    return sys.platform == "darwin"


def _api() -> _Api:
    global _API
    if not available():
        raise KeychainError("access (not macOS)", -1)
    with _LOCK:
        if _API is None:
            _API = _Api()
        return _API


def _item_query(api: _Api, service: str, account: str) -> tuple[list[tuple[int, int]], list[int]]:
    svc, acct = api.string(service), api.string(account)
    pairs = [
        (api.kSecClass, api.kSecClassGenericPassword),
        (api.kSecAttrService, svc),
        (api.kSecAttrAccount, acct),
    ]
    return pairs, [svc, acct]


def get_password(service: str, account: str = ACCOUNT) -> bytes | None:
    """The stored bytes, or None when there is no such item."""
    api = _api()
    pairs, owned = _item_query(api, service, account)
    query = result = None
    try:
        query = api.dictionary(
            pairs + [(api.kSecReturnData, api.kCFBooleanTrue), (api.kSecMatchLimit, api.kSecMatchLimitOne)]
        )
        out = c_void_p()
        status = api.sec.SecItemCopyMatching(query, byref(out))
        result = out.value
        if status == ERR_SEC_ITEM_NOT_FOUND:
            return None
        if status != ERR_SEC_SUCCESS:
            raise KeychainError("read", status)
        if not result:
            return b""
        length = api.cf.CFDataGetLength(result)
        ptr = api.cf.CFDataGetBytePtr(result)
        return ctypes.string_at(ptr, length) if ptr and length > 0 else b""
    finally:
        api.release(result, query, *owned)


def set_password(service: str, secret: bytes, account: str = ACCOUNT, label: str | None = None) -> None:
    """Create the item, or replace its value when it already exists."""
    api = _api()
    pairs, owned = _item_query(api, service, account)
    value = api.data(secret)
    owned.append(value)
    query = update = add = None
    try:
        query = api.dictionary(pairs)
        update = api.dictionary([(api.kSecValueData, value)])
        status = api.sec.SecItemUpdate(query, update)
        if status == ERR_SEC_SUCCESS:
            return
        if status != ERR_SEC_ITEM_NOT_FOUND:
            raise KeychainError("update", status)
        lbl = api.string(label or service)
        owned.append(lbl)
        base = pairs + [(api.kSecValueData, value), (api.kSecAttrLabel, lbl)]
        add = api.dictionary(base + [(api.kSecAttrAccessible, api.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)])
        status = api.sec.SecItemAdd(add, None)
        if status in (ERR_SEC_PARAM, ERR_SEC_NO_SUCH_ATTR):
            # A keychain that does not take the attribute: store the item as v0.10.42 did.
            api.release(add)
            add = api.dictionary(base)
            status = api.sec.SecItemAdd(add, None)
        if status == ERR_SEC_DUPLICATE_ITEM:  # created concurrently: update it instead
            status = api.sec.SecItemUpdate(query, update)
        if status != ERR_SEC_SUCCESS:
            raise KeychainError("write", status)
    finally:
        api.release(add, update, query, *owned)


def delete_password(service: str, account: str = ACCOUNT) -> bool:
    """Delete the item; False when it did not exist."""
    api = _api()
    pairs, owned = _item_query(api, service, account)
    query = None
    try:
        query = api.dictionary(pairs)
        status = api.sec.SecItemDelete(query)
        if status == ERR_SEC_ITEM_NOT_FOUND:
            return False
        if status != ERR_SEC_SUCCESS:
            raise KeychainError("delete", status)
        return True
    finally:
        api.release(query, *owned)
