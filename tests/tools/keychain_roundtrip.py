"""macOS only: exercise app/core/macos_keychain.py against the real login keychain (CI macOS runner).

Creates, reads, replaces and deletes one throw-away item, and reports whether the Keychain accepted the
explicit accessibility attribute or the v0.10.42 fallback was used. Exit 0 = every step worked.
"""

from __future__ import annotations

import importlib.util
import secrets
import sys
from ctypes import byref, c_void_p
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
spec = importlib.util.spec_from_file_location("macos_keychain", ROOT / "app" / "core" / "macos_keychain.py")
kc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kc)

service = f"NodeWatch CI test {secrets.token_hex(4)}"
one, two = secrets.token_bytes(24), secrets.token_bytes(24)

api = kc._api()
pairs, owned = kc._item_query(api, service, kc.ACCOUNT)
probe = api.dictionary(pairs + [(api.kSecValueData, api.data(b"x")),
                                (api.kSecAttrAccessible, api.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)])
status = api.sec.SecItemAdd(probe, None)
print(f"SecItemAdd with kSecAttrAccessible: status {status}")
api.release(probe, *owned)
kc.delete_password(service)

kc.set_password(service, one, label="NodeWatch CI test")
assert kc.get_password(service) == one, "read after create"
kc.set_password(service, two)
assert kc.get_password(service) == two, "read after replace"
assert kc.delete_password(service) is True, "delete"
assert kc.get_password(service) is None, "gone after delete"
print("create / read / replace / delete: ok")
print("accessibility attribute:", "accepted" if status == 0 else f"not accepted ({status}); fallback path used")
