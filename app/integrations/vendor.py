from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class VendorManifest:
    vendor_id: str
    display_name: str
    adapter_version: str
    provider_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    internal: bool = True

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


class VendorCatalog:
    """Internal adapter catalog; intentionally not a dynamic third-party plugin loader."""

    def __init__(self) -> None:
        self._manifests: dict[str, VendorManifest] = {}

    def register(self, manifest: VendorManifest) -> None:
        if not manifest.vendor_id:
            raise ValueError("vendor_id cannot be empty")
        existing = self._manifests.get(manifest.vendor_id)
        if existing and existing != manifest:
            raise ValueError(f"Conflicting vendor manifest: {manifest.vendor_id}")
        self._manifests[manifest.vendor_id] = manifest

    def catalog(self) -> list[dict[str, Any]]:
        return [x.public_dict for x in sorted(self._manifests.values(), key=lambda m: m.vendor_id)]


VENDORS = VendorCatalog()
