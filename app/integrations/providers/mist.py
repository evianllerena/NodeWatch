from __future__ import annotations

from app.integrations.base import ProviderAdapter, ProviderDescriptor, ProviderHealth, registry
from app.services.mist_client import get_mist_client

PROVIDER_ID = "mist"
DESCRIPTOR = ProviderDescriptor(
    PROVIDER_ID,
    "Juniper Mist",
    (
        "device_by_mac",
        "device_by_ip",
        "device_search",
        "physical_attachment",
        "wireless_attachment",
        "nac_context",
        "client_history",
        "device.by_mac",
        "device.by_ip",
        "device.search",
        "network.attachment.physical",
        "network.attachment.wireless",
        "nac.context",
        "client.history",
    ),
    read_only=False,
    vendor="juniper",
)


class MistProviderAdapter(ProviderAdapter):
    descriptor = DESCRIPTOR
    """Compatibility adapter around the existing proven Mist service layer.

    NodeWatch deliberately does not rewrite the working Mist implementation. New
    consumers can discover its capabilities through the same provider registry.
    """

    @property
    def client(self):
        return get_mist_client()

    @property
    def configured(self) -> bool:
        return self.client.configured

    def health_state(self) -> ProviderHealth:
        health = ProviderHealth(configured=self.configured)
        health.state = "unknown" if self.configured else "disabled"
        return health

    def test_connection(self) -> dict:
        if not self.configured:
            return {"ok": False, "provider": PROVIDER_ID, "configured": False}
        rows = self.client.list_sites()
        return {"ok": True, "provider": PROVIDER_ID, "configured": True, "site_count": len(rows)}


registry.register(DESCRIPTOR, MistProviderAdapter)
