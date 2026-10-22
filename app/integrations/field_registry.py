from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FieldDefinition:
    field_id: str
    label: str
    group: str
    default_visible: bool = False
    searchable: bool = False
    filterable: bool = False
    sensitive: bool = False
    order: int = 100
    data_type: str = "string"
    indexed: bool = False
    retention_class: str = "warm"
    provider_sources: tuple[str, ...] = ()

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


FIELDS: tuple[FieldDefinition, ...] = (
    FieldDefinition("device.hostname", "Hostname", "Device", True, True, order=10),
    FieldDefinition("device.ip", "IP Address", "Device", True, True, order=20),
    FieldDefinition("device.mac", "MAC Address", "Device", True, True, order=30),
    FieldDefinition("device.vendor", "Vendor", "Device", True, True, order=40),
    FieldDefinition("device.model", "Model", "Device", True, True, order=50),
    FieldDefinition("device.serial", "Serial Number", "Device", False, True, sensitive=True, order=60),
    FieldDefinition("device.category", "Device Category", "Device", False, True, order=70),
    FieldDefinition("device.profile", "Device Profile", "Device", False, True, order=80),
    FieldDefinition("device.profile_type", "Profile Type", "Device", False, order=90),
    FieldDefinition("device.profile_vertical", "Profile Vertical", "Device", False, order=100),
    FieldDefinition("device.os", "Operating System", "Device", False, True, order=110),
    FieldDefinition("device.firmware", "OS / Firmware Version", "Device", False, True, order=120),
    FieldDefinition("network.site", "Site", "Network", True, True, order=10),
    FieldDefinition("network.connection_type", "Connection", "Network", True, True, order=20),
    FieldDefinition("network.switch", "Switch", "Network", True, True, order=30),
    FieldDefinition("network.switch_member", "Switch Member", "Network", False, order=40),
    FieldDefinition("network.port", "Port", "Network", True, True, order=50),
    FieldDefinition("network.vlan", "VLAN", "Network", True, True, filterable=True, order=60),
    FieldDefinition("network.subnet", "Subnet", "Network", False, True, order=70),
    FieldDefinition("network.zone", "Security Zone", "Network", False, True, filterable=True, order=80),
    FieldDefinition("network.ssid", "SSID", "Network", False, True, order=90),
    FieldDefinition("network.ap", "Access Point", "Network", False, True, order=100),
    FieldDefinition("network.band", "Band", "Network", False, order=110),
    FieldDefinition("network.channel", "Channel", "Network", False, order=120),
    FieldDefinition("network.rssi", "RSSI", "Network", False, order=130),
    FieldDefinition(
        "security.risk_level", "Risk Level", "Security / Device Intelligence", True, True, filterable=True, order=10
    ),
    FieldDefinition(
        "security.confidence", "Classification Confidence", "Security / Device Intelligence", True, order=20
    ),
    FieldDefinition("security.risk_score", "Risk Score", "Security / Device Intelligence", False, order=30),
    FieldDefinition(
        "security.endpoint_protection",
        "Endpoint Protection",
        "Security / Device Intelligence",
        False,
        True,
        filterable=True,
        order=40,
    ),
    FieldDefinition(
        "security.internet_access",
        "Internet Access",
        "Security / Device Intelligence",
        False,
        filterable=True,
        order=50,
    ),
    FieldDefinition(
        "security.status", "Device Status", "Security / Device Intelligence", False, filterable=True, order=60
    ),
    FieldDefinition(
        "security.critical_alerts",
        "Critical Alerts",
        "Security / Device Intelligence",
        False,
        filterable=True,
        order=70,
    ),
    FieldDefinition(
        "security.warning_alerts", "Warning Alerts", "Security / Device Intelligence", False, filterable=True, order=80
    ),
    FieldDefinition(
        "security.caution_alerts", "Caution Alerts", "Security / Device Intelligence", False, filterable=True, order=90
    ),
    FieldDefinition("security.info_alerts", "Info Alerts", "Security / Device Intelligence", False, order=100),
    FieldDefinition("security.first_seen", "First Seen", "Security / Device Intelligence", False, order=110),
    FieldDefinition("security.last_activity", "Last Activity", "Security / Device Intelligence", False, order=120),
    FieldDefinition("identity.username", "Username", "Identity / Access", False, True, sensitive=True, order=10),
    FieldDefinition("identity.domain", "Domain", "Identity / Access", False, True, sensitive=True, order=20),
    FieldDefinition(
        "identity.auth_method", "Authentication Method", "Identity / Access", False, filterable=True, order=30
    ),
    FieldDefinition("identity.eap_method", "EAP Method", "Identity / Access", False, filterable=True, order=40),
    FieldDefinition("identity.nac_profile", "NAC Profile", "Identity / Access", False, filterable=True, order=50),
    FieldDefinition("identity.nac_state", "NAC State", "Identity / Access", False, filterable=True, order=60),
    # Canonical traffic/session fields. These are provider-neutral even though the
    # first production adapter is Strata Logging Service.
    FieldDefinition(
        "traffic.rule",
        "Security Rule",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=10,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.rule_uuid",
        "Rule UUID",
        "Traffic / Sessions",
        False,
        True,
        order=15,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.action",
        "Action",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=20,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.receive_time",
        "Receive Time",
        "Traffic / Sessions",
        False,
        order=30,
        data_type="datetime",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.from_zone",
        "From Zone",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=40,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.to_zone",
        "To Zone",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=50,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.source",
        "Source",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=60,
        data_type="ip",
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.destination",
        "Destination",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=70,
        data_type="ip",
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.source_user",
        "Source User",
        "Traffic / Sessions",
        False,
        True,
        True,
        sensitive=True,
        order=80,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.destination_user",
        "Destination User",
        "Traffic / Sessions",
        False,
        True,
        True,
        sensitive=True,
        order=85,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.destination_port",
        "Destination Port",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=90,
        data_type="integer",
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.application",
        "Application",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=100,
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.application_category",
        "Application Category",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=102,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.application_subcategory",
        "Application Subcategory",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=104,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.application_risk",
        "Application Risk",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=106,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.bytes_sent",
        "Bytes Sent",
        "Traffic / Sessions",
        False,
        order=110,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.bytes_received",
        "Bytes Received",
        "Traffic / Sessions",
        False,
        order=120,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.session_end_reason",
        "Session End Reason",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=130,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.source_port",
        "Source Port",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=140,
        data_type="integer",
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.protocol",
        "Protocol",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=150,
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.bytes_total",
        "Total Bytes",
        "Traffic / Sessions",
        False,
        order=160,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.packets_total",
        "Total Packets",
        "Traffic / Sessions",
        False,
        order=170,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.packets_sent",
        "Packets Sent",
        "Traffic / Sessions",
        False,
        order=172,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.packets_received",
        "Packets Received",
        "Traffic / Sessions",
        False,
        order=174,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.session_id",
        "Session ID",
        "Traffic / Sessions",
        False,
        True,
        order=180,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.session_start_time",
        "Session Start",
        "Traffic / Sessions",
        False,
        order=182,
        data_type="datetime",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.elapsed_time",
        "Duration",
        "Traffic / Sessions",
        False,
        order=184,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.nat_source",
        "NAT Source",
        "Traffic / Sessions",
        False,
        True,
        order=190,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.nat_source_port",
        "NAT Source Port",
        "Traffic / Sessions",
        False,
        True,
        order=192,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.nat_destination",
        "NAT Destination",
        "Traffic / Sessions",
        False,
        True,
        order=200,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.nat_destination_port",
        "NAT Destination Port",
        "Traffic / Sessions",
        False,
        True,
        order=202,
        data_type="integer",
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.firewall",
        "Firewall",
        "Traffic / Sessions",
        False,
        True,
        order=210,
        indexed=True,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.firewall_serial",
        "Firewall Serial",
        "Traffic / Sessions",
        False,
        True,
        sensitive=True,
        order=212,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.vsys",
        "VSYS",
        "Traffic / Sessions",
        False,
        True,
        order=214,
        provider_sources=("strata_logging_service",),
    ),
    FieldDefinition(
        "traffic.url_category",
        "URL Category",
        "Traffic / Sessions",
        False,
        True,
        True,
        order=216,
        provider_sources=("strata_logging_service",),
    ),
)


class FieldRegistry:
    """Extensible normalized field registry used by Device Finder and future modules."""

    def __init__(self, fields: tuple[FieldDefinition, ...] = ()) -> None:
        self._fields: dict[str, FieldDefinition] = {}
        self.register(*fields)

    def register(self, *fields: FieldDefinition, replace: bool = False) -> None:
        for field_def in fields:
            if not field_def.field_id:
                raise ValueError("Field ID cannot be empty")
            if field_def.field_id in self._fields and not replace:
                # Idempotent provider imports are allowed only for the exact same
                # definition. Conflicting registrations require an explicit replace.
                if self._fields[field_def.field_id] != field_def:
                    raise ValueError(f"Field is already registered: {field_def.field_id}")
                continue
            self._fields[field_def.field_id] = field_def

    def get(self, field_id: str) -> FieldDefinition | None:
        return self._fields.get(field_id)

    def catalog(self) -> list[dict[str, Any]]:
        values = sorted(self._fields.values(), key=lambda x: (x.group, x.order, x.label))
        return [f.public_dict for f in values]

    def preset(self, name: str) -> list[str]:
        fields = list(self._fields.values())
        name = (name or "standard").lower()
        if name == "full":
            return [f.field_id for f in fields]
        if name == "network":
            return [f.field_id for f in fields if f.default_visible or f.group == "Network"]
        if name == "security":
            return [f.field_id for f in fields if f.default_visible or f.group == "Security / Device Intelligence"]
        if name == "identity":
            return [f.field_id for f in fields if f.default_visible or f.group == "Identity / Access"]
        return [f.field_id for f in fields if f.default_visible]


FIELD_REGISTRY = FieldRegistry(FIELDS)
FIELD_MAP = {f.field_id: f for f in FIELDS}  # compatibility for existing imports


def register_fields(*fields: FieldDefinition, replace: bool = False) -> None:
    FIELD_REGISTRY.register(*fields, replace=replace)


def public_field_catalog() -> list[dict[str, Any]]:
    return FIELD_REGISTRY.catalog()


def preset_fields(name: str) -> list[str]:
    return FIELD_REGISTRY.preset(name)
