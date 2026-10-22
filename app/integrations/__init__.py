"""NodeWatch vendor-neutral integration and canonical-data framework."""

from app.integrations.base import registry
from app.integrations.vendor import VENDORS, VendorManifest

# Import providers for registry side effects. Keep imports network-free.
from app.integrations.providers import mist as _mist  # noqa: F401
from app.integrations.providers import palo_alto_device_security as _pa_ds  # noqa: F401
from app.integrations.providers import strata_logging as _strata_logging  # noqa: F401
from app.integrations.providers import traffic as _traffic  # noqa: F401

VENDORS.register(
    VendorManifest(
        vendor_id="juniper",
        display_name="Juniper",
        adapter_version="1",
        provider_ids=("mist",),
        capabilities=tuple(registry.descriptor("mist").capabilities if registry.descriptor("mist") else ()),
    )
)
_pa_capabilities = set()
for _provider_id in ("palo_alto_device_security", "strata_logging_service"):
    _descriptor = registry.descriptor(_provider_id)
    if _descriptor:
        _pa_capabilities.update(_descriptor.capabilities)
VENDORS.register(
    VendorManifest(
        vendor_id="palo_alto",
        display_name="Palo Alto Networks",
        adapter_version="1",
        provider_ids=("palo_alto_device_security", "strata_logging_service"),
        capabilities=tuple(sorted(_pa_capabilities)),
    )
)
VENDORS.register(
    VendorManifest(
        vendor_id="nodewatch",
        display_name="NodeWatch",
        adapter_version="1",
        provider_ids=("traffic_framework",),
        capabilities=("traffic.framework",),
    )
)
