"""Who owns a log file on the share (v0.10.22): binds a triage writer to a Windows account.

Before v0.10.22 a writer was identified only by its file name (``<machine>~<user>``). Anyone with
write access to the share could create ``hq-pc~alice.0001.jsonl`` and act as Alice, and the
"CREATOR OWNER" ACL the docs recommended did not stop it, because the forger only *creates* files.
Windows records the creating account as the file's owner, and changing the owner to someone else
needs administrator rights, so the owner is what proves who wrote a file.

``file_owner(path)`` returns the owning account's name (without the domain), ``""`` when the owner
cannot be determined or is not a single person (the Administrators group, which owns files an
elevated administrator creates), or ``None`` where ownership is not available at all (non-Windows
development). ``current_account()`` is the account this NodeWatch runs as.
"""

from __future__ import annotations

import os
from pathlib import Path

_ADMINISTRATORS_SID = "S-1-5-32-544"


def _windows_owner(path: str) -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    se_file_object, owner_security_information = 1, 1
    rc = advapi32.GetNamedSecurityInfoW(
        ctypes.c_wchar_p(path),
        se_file_object,
        owner_security_information,
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(sd),
    )
    if rc != 0 or not owner:
        return ""
    try:
        sid_text = ctypes.c_wchar_p()
        if advapi32.ConvertSidToStringSidW(owner, ctypes.byref(sid_text)):
            try:
                if sid_text.value == _ADMINISTRATORS_SID:
                    return ""
            finally:
                kernel32.LocalFree(sid_text)
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_len, domain_len = wintypes.DWORD(256), wintypes.DWORD(256)
        use = wintypes.DWORD()
        if not advapi32.LookupAccountSidW(
            None, owner, name, ctypes.byref(name_len), domain, ctypes.byref(domain_len), ctypes.byref(use)
        ):
            return ""
        return name.value
    finally:
        kernel32.LocalFree(sd)


def file_owner(path: Path | str) -> str | None:
    if os.name != "nt":
        return None
    try:
        return _windows_owner(str(path))
    except Exception:  # noqa: BLE001 - an unreadable owner is "unknown", never a crash
        return ""


def current_account() -> str:
    """The signed-in Windows account (GetUserNameW via os.getlogin), not the %USERNAME% variable."""
    try:
        return os.getlogin()
    except OSError:
        import getpass

        return getpass.getuser()
