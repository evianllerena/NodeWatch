from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

from app.core.file_utils import write_private_text

CREDENTIAL_TARGET = "NodeWatch:MistApiToken"
LEGACY_TARGETS = {
    "NodeWatch:MistApiToken": "MistNetworkTools:MistApiToken",
    "NodeWatch:SplunkHecToken": "MistNetworkTools:SplunkHecToken",
    "NodeWatch:AlertWebhookUrl": "MistNetworkTools:AlertWebhookUrl",
    "NodeWatch:PlatformOverviewPin": "MistNetworkTools:PlatformOverviewPin",
}


class CredentialStoreError(RuntimeError):
    pass


# v0.10.22: macOS keeps secrets in the user's login keychain (the Mac counterpart of Windows
# Credential Manager). The plain-file fallback below is for Linux development and tests only.
IS_MAC = sys.platform == "darwin"


def store_label() -> str:
    if os.name == "nt":
        return "Windows Credential Manager"
    if IS_MAC:
        return "macOS Keychain"
    return "Development file fallback"


def _keychain():
    from app.core import macos_keychain

    return macos_keychain


def _fallback_path(data_root: Path) -> Path:
    return data_root / "credentials.dev.json"


def _load_dev_payload(data_root: Path) -> dict:
    path = _fallback_path(data_root)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        if "token" in payload and CREDENTIAL_TARGET not in payload:
            payload[CREDENTIAL_TARGET] = payload.get("token")
        return payload
    except Exception:
        return {}


def _write_dev_payload(data_root: Path, payload: dict) -> None:
    path = _fallback_path(data_root)
    write_private_text(path, json.dumps(payload))


if os.name == "nt":
    LPBYTE = ctypes.POINTER(ctypes.c_ubyte)

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", LPBYTE),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    PCREDENTIALW = ctypes.POINTER(CREDENTIALW)
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    advapi32.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
    advapi32.CredWriteW.restype = wintypes.BOOL
    advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIALW)]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi32.CredDeleteW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2
    ERROR_NOT_FOUND = 1168


def save_secret(data_root: Path, target: str, secret: str, *, username: str = "NodeWatch Secret") -> None:
    secret = (secret or "").strip()
    target = (target or "").strip()
    if not target:
        raise CredentialStoreError("Credential target cannot be empty")
    if not secret:
        raise CredentialStoreError("Credential value cannot be empty")
    if IS_MAC:
        try:
            _keychain().set_password(target, secret.encode("utf-8"), label=target)
        except Exception as exc:  # noqa: BLE001
            raise CredentialStoreError(str(exc)) from None
        return
    if os.name != "nt":
        payload = _load_dev_payload(data_root)
        payload[target] = secret
        payload.pop("token", None)
        _write_dev_payload(data_root, payload)
        return

    blob = secret.encode("utf-16-le")
    blob_buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    cred = CREDENTIALW()
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(blob_buffer, LPBYTE)
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.UserName = username
    if not advapi32.CredWriteW(ctypes.byref(cred), 0):
        err = ctypes.get_last_error()
        raise CredentialStoreError(f"Windows Credential Manager write failed (error {err})")


def _load_secret_exact(data_root: Path, target: str) -> str:
    if IS_MAC:
        try:
            raw = _keychain().get_password(target)
        except Exception as exc:  # noqa: BLE001
            raise CredentialStoreError(str(exc)) from None
        return raw.decode("utf-8", errors="replace") if raw else ""
    if os.name != "nt":
        return str(_load_dev_payload(data_root).get(target) or "")

    pcred = PCREDENTIALW()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        err = ctypes.get_last_error()
        if err == ERROR_NOT_FOUND:
            return ""
        raise CredentialStoreError(f"Windows Credential Manager read failed (error {err})")
    try:
        cred = pcred.contents
        if not cred.CredentialBlob or not cred.CredentialBlobSize:
            return ""
        raw = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        return raw.decode("utf-16-le").rstrip("\x00")
    finally:
        advapi32.CredFree(pcred)


def _delete_secret_exact(data_root: Path, target: str) -> None:
    if IS_MAC:
        try:
            _keychain().delete_password(target)
        except Exception as exc:  # noqa: BLE001
            raise CredentialStoreError(str(exc)) from None
        return
    if os.name != "nt":
        payload = _load_dev_payload(data_root)
        payload.pop(target, None)
        payload.pop("token", None)
        if payload:
            _write_dev_payload(data_root, payload)
        else:
            try:
                _fallback_path(data_root).unlink(missing_ok=True)
            except OSError:
                pass
        return
    if advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        return
    err = ctypes.get_last_error()
    if err != ERROR_NOT_FOUND:
        raise CredentialStoreError(f"Windows Credential Manager delete failed (error {err})")


def load_secret(data_root: Path, target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    value = _load_secret_exact(data_root, target)
    if value:
        return value

    legacy_target = LEGACY_TARGETS.get(target)
    if not legacy_target:
        return ""
    legacy_value = _load_secret_exact(data_root, legacy_target)
    if not legacy_value:
        return ""

    # Copy -> read-back verify -> delete old. If migration fails, return the
    # legacy secret so the user is not locked out of an existing configuration.
    try:
        save_secret(data_root, target, legacy_value)
        if _load_secret_exact(data_root, target) == legacy_value:
            _delete_secret_exact(data_root, legacy_target)
    except Exception:
        pass
    return legacy_value


def delete_secret(data_root: Path, target: str) -> None:
    target = (target or "").strip()
    if not target:
        return
    _delete_secret_exact(data_root, target)
    legacy_target = LEGACY_TARGETS.get(target)
    if legacy_target:
        try:
            _delete_secret_exact(data_root, legacy_target)
        except CredentialStoreError:
            pass


def migrate_known_credentials(data_root: Path) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for target in LEGACY_TARGETS:
        try:
            result[target] = bool(load_secret(data_root, target))
        except Exception:
            result[target] = False
    return result


def save_token(data_root: Path, token: str) -> None:
    save_secret(data_root, CREDENTIAL_TARGET, token, username="Mist API Token")


def load_token(data_root: Path) -> str:
    return load_secret(data_root, CREDENTIAL_TARGET)


def delete_token(data_root: Path) -> None:
    delete_secret(data_root, CREDENTIAL_TARGET)
