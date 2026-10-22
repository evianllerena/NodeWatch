"""Standard-MIB object identifiers and parsers for the generic SNMP connector (v0.10.17).

Only IETF/IEEE standard MIBs are read (plus the optional, widely implemented CISCO-CDP-MIB cache),
so the same code works on any vendor's agent. Every parser takes the flat ``{oid: value}`` dict a
:class:`~app.integrations.connectors.snmp.transport.SnmpTransport` returns and produces plain dicts;
the connector turns those into domain records.

Value model (what transports return, what fixtures encode):

* INTEGER / Counter32 / Counter64 / Gauge32 / TimeTicks / Unsigned32 → ``int``
* OCTET STRING (DisplayString, PhysAddress, MacAddress, BITS, InetAddress …) → ``bytes``
* IpAddress → ``str`` dotted quad;  OBJECT IDENTIFIER → ``str`` dotted ("1.3.6.1.4.1.32473.1")

References (all public):
* SNMPv2-MIB (RFC 3418) system group · IF-MIB (RFC 2863) · IP-MIB (RFC 4293, RFC 1213 ipAddrTable)
* ENTITY-MIB (RFC 6933 / 4133) entPhysicalTable · HOST-RESOURCES-MIB (RFC 2790)
* LLDP-MIB (IEEE 802.1AB-2005, 1.0.8802.1.1.2) · BRIDGE-MIB (RFC 4188) · Q-BRIDGE-MIB (RFC 4363)
* IEEE8023-LAG-MIB (802.3ad) dot3adAggPortAttachedAggID
* IP-FORWARD-MIB (RFC 4292 inetCidrRouteTable, RFC 2096 ipCidrRouteTable) and RFC 1213 ipRouteTable
* CISCO-CDP-MIB cdpCacheTable (optional; empty on agents that do not implement it)
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.integrations.domain import normalize_mac

# --------------------------------------------------------------------------- OIDs

# SNMPv2-MIB system group (scalars, ".0" instances)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
# LLDP-MIB local system
LLDP_LOC_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_SYS_CAP_ENABLED = "1.0.8802.1.1.2.1.3.6.0"
# BRIDGE-MIB base bridge MAC
DOT1D_BASE_BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"

SYSTEM_GETS = (
    SYS_DESCR,
    SYS_OBJECT_ID,
    SYS_UPTIME,
    SYS_NAME,
    SYS_LOCATION,
    SYS_SERVICES,
    LLDP_LOC_CHASSIS_SUBTYPE,
    LLDP_LOC_CHASSIS_ID,
    LLDP_LOC_SYS_CAP_ENABLED,
    DOT1D_BASE_BRIDGE_ADDRESS,
)

# ENTITY-MIB entPhysicalEntry columns
ENT_PHYSICAL = "1.3.6.1.2.1.47.1.1.1.1"
ENT_CLASS = ENT_PHYSICAL + ".5"
ENT_SOFTWARE_REV = ENT_PHYSICAL + ".10"
ENT_SERIAL = ENT_PHYSICAL + ".11"
ENT_MFG_NAME = ENT_PHYSICAL + ".12"
ENT_MODEL_NAME = ENT_PHYSICAL + ".13"
ENTITY_WALKS = (ENT_CLASS, ENT_SOFTWARE_REV, ENT_SERIAL, ENT_MFG_NAME, ENT_MODEL_NAME)

# IF-MIB ifTable / ifXTable columns
IF_ENTRY = "1.3.6.1.2.1.2.2.1"
IF_DESCR = IF_ENTRY + ".2"
IF_TYPE = IF_ENTRY + ".3"
IF_SPEED = IF_ENTRY + ".5"
IF_PHYS_ADDRESS = IF_ENTRY + ".6"
IF_ADMIN_STATUS = IF_ENTRY + ".7"
IF_OPER_STATUS = IF_ENTRY + ".8"
IF_IN_ERRORS = IF_ENTRY + ".14"
IF_OUT_ERRORS = IF_ENTRY + ".20"
IFX_ENTRY = "1.3.6.1.2.1.31.1.1.1"
IFX_NAME = IFX_ENTRY + ".1"
IFX_HC_IN_OCTETS = IFX_ENTRY + ".6"
IFX_HC_OUT_OCTETS = IFX_ENTRY + ".10"
IFX_HIGH_SPEED = IFX_ENTRY + ".15"
IFX_ALIAS = IFX_ENTRY + ".18"
# IP-MIB addresses: RFC 1213 ipAddrTable (IPv4) and RFC 4293 ipAddressTable (IPv4 + IPv6)
IP_ADDR_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_ADDR_NETMASK = "1.3.6.1.2.1.4.20.1.3"
IP_ADDRESS_IFINDEX = "1.3.6.1.2.1.4.34.1.3"
IP_ADDRESS_PREFIX = "1.3.6.1.2.1.4.34.1.5"
# IEEE8023-LAG-MIB: aggregator a port is attached to
LAG_PORT_ATTACHED_AGG = "1.2.840.10006.300.43.1.2.1.1.13"

INTERFACE_WALKS = (
    IF_DESCR,
    IF_TYPE,
    IF_SPEED,
    IF_PHYS_ADDRESS,
    IF_ADMIN_STATUS,
    IF_OPER_STATUS,
    IF_IN_ERRORS,
    IF_OUT_ERRORS,
    IFX_NAME,
    IFX_HC_IN_OCTETS,
    IFX_HC_OUT_OCTETS,
    IFX_HIGH_SPEED,
    IFX_ALIAS,
    IP_ADDR_IFINDEX,
    IP_ADDR_NETMASK,
    IP_ADDRESS_IFINDEX,
    IP_ADDRESS_PREFIX,
    LAG_PORT_ATTACHED_AGG,
)

# LLDP-MIB local ports and remote systems
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"
LLDP_LOC_PORT_ID_SUBTYPE = LLDP_LOC_PORT + ".2"
LLDP_LOC_PORT_ID = LLDP_LOC_PORT + ".3"
LLDP_LOC_PORT_DESC = LLDP_LOC_PORT + ".4"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_CHASSIS_SUBTYPE = LLDP_REM + ".4"
LLDP_REM_CHASSIS_ID = LLDP_REM + ".5"
LLDP_REM_PORT_SUBTYPE = LLDP_REM + ".6"
LLDP_REM_PORT_ID = LLDP_REM + ".7"
LLDP_REM_PORT_DESC = LLDP_REM + ".8"
LLDP_REM_SYS_NAME = LLDP_REM + ".9"
LLDP_REM_SYS_DESC = LLDP_REM + ".10"
LLDP_REM_SYS_CAP_ENABLED = LLDP_REM + ".12"
LLDP_REM_MAN_ADDR_IF_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"
# CISCO-CDP-MIB cdpCacheEntry (optional)
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
CDP_ADDRESS_TYPE = CDP_CACHE + ".3"
CDP_ADDRESS = CDP_CACHE + ".4"
CDP_DEVICE_ID = CDP_CACHE + ".6"
CDP_DEVICE_PORT = CDP_CACHE + ".7"
CDP_PLATFORM = CDP_CACHE + ".8"
CDP_CAPABILITIES = CDP_CACHE + ".9"

NEIGHBOR_WALKS = (
    LLDP_LOC_PORT_ID_SUBTYPE,
    LLDP_LOC_PORT_ID,
    LLDP_LOC_PORT_DESC,
    LLDP_REM_CHASSIS_SUBTYPE,
    LLDP_REM_CHASSIS_ID,
    LLDP_REM_PORT_SUBTYPE,
    LLDP_REM_PORT_ID,
    LLDP_REM_PORT_DESC,
    LLDP_REM_SYS_NAME,
    LLDP_REM_SYS_DESC,
    LLDP_REM_SYS_CAP_ENABLED,
    LLDP_REM_MAN_ADDR_IF_SUBTYPE,
    CDP_ADDRESS_TYPE,
    CDP_ADDRESS,
    CDP_DEVICE_ID,
    CDP_DEVICE_PORT,
    CDP_PLATFORM,
    CDP_CAPABILITIES,
)

# IP-MIB ARP: ipNetToPhysicalTable (RFC 4293), then ipNetToMediaTable (RFC 1213) as fallback
IP_NET_TO_PHYS_ADDRESS = "1.3.6.1.2.1.4.35.1.4"
IP_NET_TO_PHYS_TYPE = "1.3.6.1.2.1.4.35.1.6"
IP_NET_TO_MEDIA_ADDRESS = "1.3.6.1.2.1.4.22.1.2"
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"
ARP_WALKS = ((IP_NET_TO_PHYS_ADDRESS, IP_NET_TO_PHYS_TYPE), (IP_NET_TO_MEDIA_ADDRESS, IP_NET_TO_MEDIA_TYPE))

# Q-BRIDGE-MIB forwarding database, then BRIDGE-MIB as fallback; bridge port → ifIndex
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_TP_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
DOT1Q_VLAN_FDB_ID = "1.3.6.1.2.1.17.7.1.4.2.1.3"
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
FDB_WALKS = (
    (DOT1Q_TP_FDB_PORT, DOT1Q_TP_FDB_STATUS, DOT1Q_VLAN_FDB_ID, DOT1D_BASE_PORT_IFINDEX),
    (DOT1D_TP_FDB_PORT, DOT1D_TP_FDB_STATUS, DOT1D_BASE_PORT_IFINDEX),
)

# IP-FORWARD-MIB inetCidrRouteTable, then ipCidrRouteTable, then RFC 1213 ipRouteTable
INET_CIDR_ROUTE_IFINDEX = "1.3.6.1.2.1.4.24.7.1.7"
INET_CIDR_ROUTE_TYPE = "1.3.6.1.2.1.4.24.7.1.8"
INET_CIDR_ROUTE_PROTO = "1.3.6.1.2.1.4.24.7.1.9"
IP_CIDR_ROUTE_IFINDEX = "1.3.6.1.2.1.4.24.4.1.5"
IP_CIDR_ROUTE_TYPE = "1.3.6.1.2.1.4.24.4.1.6"
IP_CIDR_ROUTE_PROTO = "1.3.6.1.2.1.4.24.4.1.7"
IP_ROUTE_IFINDEX = "1.3.6.1.2.1.4.21.1.2"
IP_ROUTE_NEXT_HOP = "1.3.6.1.2.1.4.21.1.7"
IP_ROUTE_TYPE = "1.3.6.1.2.1.4.21.1.8"
IP_ROUTE_PROTO = "1.3.6.1.2.1.4.21.1.9"
IP_ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"
ROUTE_WALKS = (
    (INET_CIDR_ROUTE_IFINDEX, INET_CIDR_ROUTE_TYPE, INET_CIDR_ROUTE_PROTO),
    (IP_CIDR_ROUTE_IFINDEX, IP_CIDR_ROUTE_TYPE, IP_CIDR_ROUTE_PROTO),
    (IP_ROUTE_IFINDEX, IP_ROUTE_NEXT_HOP, IP_ROUTE_TYPE, IP_ROUTE_PROTO, IP_ROUTE_MASK),
)

# HOST-RESOURCES-MIB processor load and storage
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"
HR_STORAGE_TYPE = HR_STORAGE + ".2"
HR_STORAGE_UNITS = HR_STORAGE + ".4"
HR_STORAGE_SIZE = HR_STORAGE + ".5"
HR_STORAGE_USED = HR_STORAGE + ".6"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HEALTH_WALKS = (HR_PROCESSOR_LOAD, HR_STORAGE_TYPE, HR_STORAGE_UNITS, HR_STORAGE_SIZE, HR_STORAGE_USED)

# --------------------------------------------------------------------------- value helpers


def oid_key(oid: str) -> tuple[int, ...]:
    """Sort key: numeric OID order (what GETNEXT/GETBULK walks follow)."""
    try:
        return tuple(int(x) for x in str(oid).strip(".").split("."))
    except ValueError:
        return ()


def column(data: dict[str, Any], base: str) -> dict[str, Any]:
    """{index suffix: value} for every instance under ``base`` (a table column OID)."""
    prefix = base + "."
    return {oid[len(prefix) :]: value for oid, value in data.items() if oid.startswith(prefix)}


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    return str(value).replace("\x00", "").strip()


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(text(value))
    except (TypeError, ValueError):
        return None


def mac(value: Any) -> str:
    """PhysAddress / MacAddress (6 raw octets) or a textual MAC → 12 hex digits ('' otherwise)."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 6:
            result = raw.hex()
            return "" if result in ("000000000000", "ffffffffffff") else result
        value = raw.decode("ascii", errors="ignore")
    result = normalize_mac(value)
    return "" if result in ("000000000000", "ffffffffffff") else result


def ip_text(value: Any) -> str:
    """IpAddress (dotted str) or InetAddress octets (4 / 16) → printable address ('' otherwise)."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) in (4, 16):
            return str(ipaddress.ip_address(raw))
        value = raw.decode("ascii", errors="ignore")
    try:
        return str(ipaddress.ip_address(text(value)))
    except ValueError:
        return ""


def _index_parts(index: str) -> list[int]:
    try:
        return [int(x) for x in index.split(".") if x != ""]
    except ValueError:
        return []


def inet_from_index(parts: list[int], pos: int) -> tuple[str, int]:
    """Decode an InetAddressType + InetAddress pair from a table index starting at ``pos``.

    Per SMIv2 the address is length-prefixed; some agents omit the length for IPv4. Returns
    (address, next position) or ("", -1) when the index cannot be decoded.
    """
    if pos >= len(parts):
        return "", -1
    addr_type = parts[pos]
    pos += 1
    sizes = {1: 4, 2: 16, 3: 8, 4: 20}  # ipv4, ipv6, ipv4z, ipv6z
    want = sizes.get(addr_type)
    if want is None:
        if addr_type == 0 and pos < len(parts) and parts[pos] == 0:  # unknown, empty address
            return "", pos + 1
        return "", -1
    if pos < len(parts) and parts[pos] == want and len(parts) - pos - 1 >= want:
        raw = parts[pos + 1 : pos + 1 + want]
        nxt = pos + 1 + want
    elif len(parts) - pos >= want:  # length omitted (seen on some IPv4 agents)
        raw = parts[pos : pos + want]
        nxt = pos + want
    else:
        return "", -1
    if any(b > 255 for b in raw):
        return "", -1
    raw = raw[:16] if addr_type in (2, 4) else raw[:4]  # drop the zone index of ipv4z/ipv6z
    return str(ipaddress.ip_address(bytes(raw))), nxt


def _octets(parts: list[int]) -> bytes:
    """Index sub-identifiers → bytes; b"" when any is not an octet (malformed row, skipped by callers)."""
    if any(not 0 <= p <= 255 for p in parts):
        return b""
    return bytes(parts)


def _ip_octets(parts: list[int]) -> str:
    """4 or 16 index sub-identifiers → address text; '' for a malformed index."""
    raw = _octets(parts)
    return str(ipaddress.ip_address(raw)) if len(raw) in (4, 16) and len(raw) == len(parts) else ""


# --------------------------------------------------------------------------- system / entity

LLDP_CAPS = ("other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station")


def lldp_caps(value: Any) -> list[str]:
    """LLDP BITS (first octet, MSB = bit 0) → capability names the topology fingerprints know."""
    raw = bytes(value) if isinstance(value, (bytes, bytearray)) else b""
    if not raw:
        return []
    return [name for bit, name in enumerate(LLDP_CAPS) if raw[0] & (0x80 >> bit)]


def cdp_caps(value: Any) -> list[str]:
    """CISCO-CDP-MIB capability bitmap (32-bit, Router=0x01, Trans-bridge=0x02, Switch=0x08, Phone=0x80)."""
    raw = bytes(value) if isinstance(value, (bytes, bytearray)) else b""
    number = int.from_bytes(raw[-4:], "big") if raw else (integer(value) or 0)
    names = []
    for mask, name in ((0x01, "router"), (0x02, "bridge"), (0x04, "bridge"), (0x08, "bridge"), (0x80, "telephone")):
        if number & mask and name not in names:
            names.append(name)
    return names


def sys_services_caps(value: Any) -> list[str]:
    """sysServices layer bits: 2 = datalink (bridge), 4 = internet (router)."""
    number = integer(value) or 0
    caps = []
    if number & 0x02:
        caps.append("bridge")
    if number & 0x04:
        caps.append("router")
    return caps


def parse_system(data: dict[str, Any]) -> dict[str, Any]:
    """System group + LLDP local chassis + ENTITY-MIB chassis row → identity facts."""
    chassis_subtype = integer(data.get(LLDP_LOC_CHASSIS_SUBTYPE))
    chassis_raw = data.get(LLDP_LOC_CHASSIS_ID)
    lldp_mac = mac(chassis_raw) if chassis_subtype == 4 else ""
    classes = column(data, ENT_CLASS)
    serials = column(data, ENT_SERIAL)
    models = column(data, ENT_MODEL_NAME)
    mfgs = column(data, ENT_MFG_NAME)
    softs = column(data, ENT_SOFTWARE_REV)
    chassis = [i for i, c in sorted(classes.items(), key=lambda kv: oid_key(kv[0])) if integer(c) == 3]
    # Prefer the first chassis that carries a serial (stacks list one chassis per member).
    members = []
    for idx in chassis:
        serial = text(serials.get(idx))
        if serial:
            members.append({"serial": serial, "model": text(models.get(idx)), "index": idx})
    first = chassis[0] if chassis else ""
    serial_idx = members[0]["index"] if members else first
    uptime = integer(data.get(SYS_UPTIME))
    return {
        "name": text(data.get(SYS_NAME)),
        "description": text(data.get(SYS_DESCR)),
        "object_id": text(data.get(SYS_OBJECT_ID)).lstrip("."),
        "location": text(data.get(SYS_LOCATION)),
        "uptime_s": uptime / 100.0 if isinstance(uptime, int) and uptime >= 0 else None,
        "services": integer(data.get(SYS_SERVICES)),
        "lldp_mac": lldp_mac,
        "lldp_chassis_subtype": chassis_subtype,
        "lldp_caps": lldp_caps(data.get(LLDP_LOC_SYS_CAP_ENABLED)),
        "bridge_mac": mac(data.get(DOT1D_BASE_BRIDGE_ADDRESS)),
        "serial": text(serials.get(serial_idx)) if serial_idx else "",
        "model": text(models.get(serial_idx)) if serial_idx else "",
        "manufacturer": text(mfgs.get(serial_idx)) if serial_idx else "",
        "software": text(softs.get(serial_idx)) if serial_idx else "",
        "members": [{"serial": m["serial"], "model": m["model"]} for m in members] if len(members) > 1 else [],
    }


# IANA private enterprise numbers → vendor display name (sysObjectID 1.3.6.1.4.1.<n>…). Data only.
ENTERPRISES = {
    9: "Cisco",
    11: "HPE",
    43: "3Com",
    171: "D-Link",
    674: "Dell",
    1916: "Extreme Networks",
    1991: "Brocade",
    2011: "Huawei",
    2636: "Juniper Networks",
    3375: "F5",
    4526: "Netgear",
    6527: "Nokia",
    6876: "VMware",
    8072: "Net-SNMP",
    12356: "Fortinet",
    14823: "HPE Aruba Networking",
    14988: "MikroTik",
    23867: "HPE Aruba Networking (Silver Peak)",
    25461: "Palo Alto Networks",
    25506: "H3C",
    29671: "Cisco Meraki",
    30065: "Arista Networks",
    32473: "Example (documentation)",
    41112: "Ubiquiti",
    47196: "HPE Aruba Networking",
}


def enterprise_vendor(object_id: str) -> str:
    parts = _index_parts(object_id)
    if len(parts) > 6 and parts[:6] == [1, 3, 6, 1, 4, 1]:
        return ENTERPRISES.get(parts[6], "")
    return ""


_VERSION = re.compile(r"\b(?:version|software|firmware|release|ver\.?)[\s:]*v?([0-9][\w.()\-]*)", re.I)


def os_version_from_descr(descr: str) -> str:
    m = _VERSION.search(descr or "")
    return m.group(1).rstrip(".,)") if m else ""


# --------------------------------------------------------------------------- interfaces

IF_KIND = {
    6: "physical",  # ethernetCsmacd
    62: "physical",  # fastEther
    69: "physical",  # fastEtherFX
    117: "physical",  # gigabitEthernet
    71: "physical",  # ieee80211
    161: "lag",  # ieee8023adLag
    135: "vlan",  # l2vlan
    136: "vlan",  # l3ipvlan
    53: "vlan",  # propVirtual (VLAN interfaces on many switches)
    24: "loopback",  # softwareLoopback
    131: "tunnel",  # tunnel
    150: "tunnel",  # mplsTunnel
    166: "tunnel",  # mpls
    1: "logical",  # other
}
_MGMT_NAME = re.compile(r"^(me\d|fxp\d|em\d|mgmt|management|vme|eth-?mgmt|ma\d)", re.I)


def if_names(data: dict[str, Any]) -> dict[str, str]:
    """{ifIndex: best name} — ifName, then ifDescr."""
    names = {i: text(v) for i, v in column(data, IF_DESCR).items()}
    for i, v in column(data, IFX_NAME).items():
        if text(v):
            names[i] = text(v)
    return {i: n for i, n in names.items() if n}


def parse_interfaces(data: dict[str, Any]) -> list[dict[str, Any]]:
    names = if_names(data)
    descr = column(data, IF_DESCR)
    types = column(data, IF_TYPE)
    speed = column(data, IF_SPEED)
    high = column(data, IFX_HIGH_SPEED)
    phys = column(data, IF_PHYS_ADDRESS)
    admin = column(data, IF_ADMIN_STATUS)
    oper = column(data, IF_OPER_STATUS)
    in_err = column(data, IF_IN_ERRORS)
    out_err = column(data, IF_OUT_ERRORS)
    hc_in = column(data, IFX_HC_IN_OCTETS)
    hc_out = column(data, IFX_HC_OUT_OCTETS)
    alias = column(data, IFX_ALIAS)
    lag_of = {i: str(integer(v)) for i, v in column(data, LAG_PORT_ATTACHED_AGG).items() if integer(v)}
    ips: dict[str, list[str]] = {}
    masks = column(data, IP_ADDR_NETMASK)
    for addr_idx, if_idx in column(data, IP_ADDR_IFINDEX).items():
        addr = ip_text(addr_idx)
        if not addr or integer(if_idx) is None:
            continue
        mask = ip_text(masks.get(addr_idx))
        try:
            cidr = str(ipaddress.ip_interface(f"{addr}/{mask}")) if mask else addr
        except ValueError:
            cidr = addr
        ips.setdefault(str(integer(if_idx)), []).append(cidr)
    prefixes = column(data, IP_ADDRESS_PREFIX)
    for idx, if_idx in column(data, IP_ADDRESS_IFINDEX).items():
        parts = _index_parts(idx)
        addr, nxt = inet_from_index(parts, 0)
        if not addr or nxt != len(parts) or integer(if_idx) is None:
            continue
        known = ips.setdefault(str(integer(if_idx)), [])
        if any(c.split("/")[0] == addr for c in known):
            continue  # already listed by ipAddrTable
        pointer = _index_parts(text(prefixes.get(idx)))
        length = pointer[-1] if pointer and pointer[:9] == [1, 3, 6, 1, 2, 1, 4, 32, 1] else None
        try:
            known.append(str(ipaddress.ip_interface(f"{addr}/{length}")) if length is not None else addr)
        except ValueError:
            known.append(addr)
    rows = []
    for idx in sorted(set(names) | set(types) | set(oper), key=oid_key):
        if_type = integer(types.get(idx))
        name = names.get(idx) or f"ifIndex {idx}"
        kind = IF_KIND.get(if_type or 0, "logical")
        if _MGMT_NAME.match(name):
            kind = "mgmt"
        high_speed = integer(high.get(idx))
        low_speed = integer(speed.get(idx))
        if high_speed:
            speed_mbps: float | None = float(high_speed)
        elif low_speed and low_speed < 4294967295:
            speed_mbps = low_speed / 1_000_000
        else:
            speed_mbps = None
        admin_status = integer(admin.get(idx))
        oper_status = integer(oper.get(idx))
        parent = lag_of.get(idx, "")
        rows.append(
            {
                "index": idx,
                "name": name,
                "descr": text(descr.get(idx)),
                "kind": kind,
                "if_type": if_type,
                "admin_up": None if admin_status is None else admin_status == 1,
                "oper_up": None if oper_status in (None, 4) else oper_status == 1,  # 4 = unknown
                "oper_status": oper_status,
                "speed_mbps": speed_mbps,
                "mac": mac(phys.get(idx)),
                "ips": ips.get(idx, []),
                "alias": text(alias.get(idx)),
                "rx_errors": integer(in_err.get(idx)),
                "tx_errors": integer(out_err.get(idx)),
                "hc_in": integer(hc_in.get(idx)),
                "hc_out": integer(hc_out.get(idx)),
                "lag_parent": names.get(parent, "") if parent and parent != idx else "",
            }
        )
    return rows


# --------------------------------------------------------------------------- neighbors

PORT_SUBTYPE_MAC = 3


def _local_port_names(data: dict[str, Any], names: dict[str, str]) -> dict[str, str]:
    """lldpLocPortNum → interface name. The port number is NOT guaranteed to be the ifIndex."""
    ids = column(data, LLDP_LOC_PORT_ID)
    subtypes = column(data, LLDP_LOC_PORT_ID_SUBTYPE)
    descs = column(data, LLDP_LOC_PORT_DESC)
    known = {n.lower(): n for n in names.values()}
    out: dict[str, str] = {}
    for num in set(ids) | set(descs):
        port_id = "" if integer(subtypes.get(num)) == PORT_SUBTYPE_MAC else text(ids.get(num))
        desc = text(descs.get(num))
        for candidate in (port_id, desc):
            if candidate and candidate.lower() in known:
                out[num] = known[candidate.lower()]
                break
        else:
            out[num] = names.get(num) or port_id or desc or f"port {num}"
    for num, name in names.items():  # no lldpLocPortTable: most agents number LLDP ports by ifIndex
        out.setdefault(num, name)
    return out


def parse_neighbors(data: dict[str, Any], names: dict[str, str]) -> list[dict[str, Any]]:
    local = _local_port_names(data, names)
    rem = {
        "chassis_subtype": column(data, LLDP_REM_CHASSIS_SUBTYPE),
        "chassis": column(data, LLDP_REM_CHASSIS_ID),
        "port_subtype": column(data, LLDP_REM_PORT_SUBTYPE),
        "port": column(data, LLDP_REM_PORT_ID),
        "port_desc": column(data, LLDP_REM_PORT_DESC),
        "name": column(data, LLDP_REM_SYS_NAME),
        "desc": column(data, LLDP_REM_SYS_DESC),
        "caps": column(data, LLDP_REM_SYS_CAP_ENABLED),
    }
    mgmt: dict[str, str] = {}
    for idx in column(data, LLDP_REM_MAN_ADDR_IF_SUBTYPE):
        parts = _index_parts(idx)
        if len(parts) < 5:
            continue
        key = ".".join(str(p) for p in parts[:3])
        subtype, length = parts[3], parts[4]
        raw = parts[5 : 5 + length]
        if subtype in (1, 2) and len(raw) == length and length in (4, 16):
            address = _ip_octets(raw)
            if not address:
                continue  # malformed index: skip this row only
            if subtype == 1 or key not in mgmt:  # prefer IPv4 over IPv6
                mgmt[key] = address
    out = []
    rows = set()
    for col in rem.values():
        rows |= set(col)
    for idx in sorted(rows, key=oid_key):
        parts = _index_parts(idx)
        if len(parts) != 3:
            continue
        port_num = str(parts[1])
        chassis_subtype = integer(rem["chassis_subtype"].get(idx))
        chassis = rem["chassis"].get(idx)
        port_subtype = integer(rem["port_subtype"].get(idx))
        port_raw = rem["port"].get(idx)
        port_desc = text(rem["port_desc"].get(idx))
        if port_subtype == PORT_SUBTYPE_MAC:
            remote_port = port_desc or mac(port_raw)
        else:
            remote_port = text(port_raw) or port_desc
        remote_mgmt = mgmt.get(idx, "")
        if (
            not remote_mgmt
            and chassis_subtype == 5
            and isinstance(chassis, (bytes, bytearray))
            and len(chassis) in (5, 17)
        ):
            remote_mgmt = ip_text(bytes(chassis)[1:])  # networkAddress: IANA family octet + address
        out.append(
            {
                "local_port": local.get(port_num, f"port {port_num}"),
                "remote_name": text(rem["name"].get(idx)),
                "remote_port": remote_port,
                "remote_mac": mac(chassis) if chassis_subtype == 4 else "",
                "remote_mgmt_ip": remote_mgmt,
                "remote_description": text(rem["desc"].get(idx)),
                "remote_caps": lldp_caps(rem["caps"].get(idx)),
                "protocol": "lldp",
            }
        )
    cdp = {
        "type": column(data, CDP_ADDRESS_TYPE),
        "addr": column(data, CDP_ADDRESS),
        "id": column(data, CDP_DEVICE_ID),
        "port": column(data, CDP_DEVICE_PORT),
        "platform": column(data, CDP_PLATFORM),
        "caps": column(data, CDP_CAPABILITIES),
    }
    seen = {(n["local_port"], n["remote_name"].lower()) for n in out}
    for idx in sorted(set(cdp["id"]), key=oid_key):
        parts = _index_parts(idx)
        if len(parts) != 2:
            continue
        local_port = names.get(str(parts[0]), f"ifIndex {parts[0]}")
        remote = text(cdp["id"].get(idx))
        if (local_port, remote.lower()) in seen:
            continue  # the same neighbor already seen through LLDP
        address = cdp["addr"].get(idx)
        out.append(
            {
                "local_port": local_port,
                "remote_name": remote,
                "remote_port": text(cdp["port"].get(idx)),
                "remote_mac": "",
                "remote_mgmt_ip": ip_text(address) if integer(cdp["type"].get(idx)) in (1, None) else "",
                "remote_description": text(cdp["platform"].get(idx)),
                "remote_caps": cdp_caps(cdp["caps"].get(idx)),
                "protocol": "cdp",
            }
        )
    return out


# --------------------------------------------------------------------------- ARP

ARP_INVALID = 2


def parse_arp(data: dict[str, Any], names: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    types = column(data, IP_NET_TO_PHYS_TYPE)
    for idx, phys in column(data, IP_NET_TO_PHYS_ADDRESS).items():
        parts = _index_parts(idx)
        if len(parts) < 3 or integer(types.get(idx)) == ARP_INVALID:
            continue
        address, nxt = inet_from_index(parts, 1)
        if not address or nxt != len(parts):
            continue
        if ipaddress.ip_address(address).version != 4:
            continue  # IPv6 neighbor-discovery entries are not ARP; keep the table comparable
        out.append({"ip": address, "mac": mac(phys), "interface": names.get(str(parts[0]), "")})
    if out:
        return [r for r in out if r["mac"]]
    types = column(data, IP_NET_TO_MEDIA_TYPE)
    for idx, phys in column(data, IP_NET_TO_MEDIA_ADDRESS).items():
        parts = _index_parts(idx)
        if len(parts) != 5 or integer(types.get(idx)) == ARP_INVALID or not _ip_octets(parts[1:]):
            continue  # invalid entry or malformed index: skip this row only
        out.append(
            {
                "ip": _ip_octets(parts[1:]),
                "mac": mac(phys),
                "interface": names.get(str(parts[0]), ""),
            }
        )
    return [r for r in out if r["mac"]]


# --------------------------------------------------------------------------- MAC table

FDB_STATUS_INVALID, FDB_STATUS_SELF = 2, 4


def parse_fdb(data: dict[str, Any], names: dict[str, str]) -> list[dict[str, Any]]:
    port_if = {p: str(integer(v)) for p, v in column(data, DOT1D_BASE_PORT_IFINDEX).items() if integer(v)}

    def port_name(port: Any) -> str:
        number = integer(port)
        if not number:
            return ""
        if_index = port_if.get(str(number), str(number))
        return names.get(if_index, f"port {number}")

    fdb_vlan: dict[int, int] = {}
    for idx, fdb in column(data, DOT1Q_VLAN_FDB_ID).items():
        parts = _index_parts(idx)
        if len(parts) == 2 and integer(fdb) is not None:
            fdb_vlan.setdefault(int(integer(fdb) or 0), parts[1])
    out = []
    status = column(data, DOT1Q_TP_FDB_STATUS)
    for idx, port in column(data, DOT1Q_TP_FDB_PORT).items():
        parts = _index_parts(idx)
        if len(parts) != 7 or integer(status.get(idx)) in (FDB_STATUS_INVALID, FDB_STATUS_SELF):
            continue
        fdb_id = parts[0]
        if fdb_vlan:
            vlan = fdb_vlan.get(fdb_id)
        else:  # no VLAN ↔ FDB map published: most agents use the VLAN ID as the FDB ID
            vlan = fdb_id if 1 <= fdb_id <= 4094 else None
        address = mac(_octets(parts[1:]))
        name = port_name(port)
        if address and name:
            out.append({"mac": address, "interface": name, "vlan": vlan})
    if out:
        return out
    status = column(data, DOT1D_TP_FDB_STATUS)
    for idx, port in column(data, DOT1D_TP_FDB_PORT).items():
        parts = _index_parts(idx)
        if len(parts) != 6 or integer(status.get(idx)) in (FDB_STATUS_INVALID, FDB_STATUS_SELF):
            continue
        address = mac(_octets(parts))
        name = port_name(port)
        if address and name:
            out.append({"mac": address, "interface": name, "vlan": None})
    return out


# --------------------------------------------------------------------------- routes

# IANAipRouteProtocol → domain words
ROUTE_PROTO = {
    1: "other",
    2: "connected",  # local
    3: "static",  # netmgmt
    4: "icmp",
    8: "rip",
    9: "isis",
    11: "igrp",
    13: "ospf",
    14: "bgp",
    16: "eigrp",
}
ROUTE_TYPE_REJECT, ROUTE_TYPE_BLACKHOLE = 2, 5


def _nh(address: str) -> str:
    return "" if address in ("0.0.0.0", "::", "") else address


def parse_routes(data: dict[str, Any], names: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    proto = column(data, INET_CIDR_ROUTE_PROTO)
    rtype = column(data, INET_CIDR_ROUTE_TYPE)
    for idx, if_index in column(data, INET_CIDR_ROUTE_IFINDEX).items():
        parts = _index_parts(idx)
        dest, pos = inet_from_index(parts, 0)
        if not dest or pos < 0 or pos >= len(parts):
            continue
        prefix_len = parts[pos]
        pos += 1
        if pos >= len(parts):
            continue
        policy_len = parts[pos]  # RouteFirstHopPolicy OID, length-prefixed
        pos += 1 + policy_len
        next_hop, end = inet_from_index(parts, pos)
        if end != len(parts):
            next_hop = ""
        try:
            prefix = str(ipaddress.ip_network(f"{dest}/{prefix_len}", strict=False))
        except ValueError:
            continue
        kind = integer(rtype.get(idx))
        out.append(
            {
                "prefix": prefix,
                "next_hop": _nh(next_hop),
                "interface": names.get(str(integer(if_index) or ""), ""),
                "protocol": ROUTE_PROTO.get(integer(proto.get(idx)) or 0, ""),
                "blackhole": kind in (ROUTE_TYPE_REJECT, ROUTE_TYPE_BLACKHOLE),
            }
        )
    if out:
        return out
    proto = column(data, IP_CIDR_ROUTE_PROTO)
    rtype = column(data, IP_CIDR_ROUTE_TYPE)
    for idx, if_index in column(data, IP_CIDR_ROUTE_IFINDEX).items():
        parts = _index_parts(idx)
        if len(parts) != 13:
            continue
        try:
            network = ipaddress.ip_network(f"{_dotted(parts[0:4])}/{_dotted(parts[4:8])}", strict=False)
        except ValueError:
            continue
        kind = integer(rtype.get(idx))
        out.append(
            {
                "prefix": str(network),
                "next_hop": _nh(_dotted(parts[9:13])),
                "interface": names.get(str(integer(if_index) or ""), ""),
                "protocol": ROUTE_PROTO.get(integer(proto.get(idx)) or 0, ""),
                "blackhole": kind == ROUTE_TYPE_REJECT,
            }
        )
    if out:
        return out
    proto = column(data, IP_ROUTE_PROTO)
    masks = column(data, IP_ROUTE_MASK)
    hops = column(data, IP_ROUTE_NEXT_HOP)
    rtype = column(data, IP_ROUTE_TYPE)
    for idx, if_index in column(data, IP_ROUTE_IFINDEX).items():
        dest, mask = ip_text(idx), ip_text(masks.get(idx))
        if not dest or not mask:
            continue
        try:
            network = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
        except ValueError:
            continue
        out.append(
            {
                "prefix": str(network),
                "next_hop": "" if integer(rtype.get(idx)) == 3 else _nh(ip_text(hops.get(idx))),  # 3 = direct
                "interface": names.get(str(integer(if_index) or ""), ""),
                "protocol": ROUTE_PROTO.get(integer(proto.get(idx)) or 0, ""),
                "blackhole": integer(rtype.get(idx)) == ARP_INVALID,
            }
        )
    return out


def _dotted(parts: list[int]) -> str:
    try:
        return str(ipaddress.IPv4Address(_octets(parts))) if len(parts) == 4 else ""
    except ValueError:
        return ""


# --------------------------------------------------------------------------- health


def parse_health(data: dict[str, Any]) -> dict[str, float | None]:
    loads = [integer(v) for v in column(data, HR_PROCESSOR_LOAD).values()]
    loads = [v for v in loads if v is not None and 0 <= v <= 100]
    cpu = round(sum(loads) / len(loads), 1) if loads else None
    memory = None
    types = column(data, HR_STORAGE_TYPE)
    units = column(data, HR_STORAGE_UNITS)
    sizes = column(data, HR_STORAGE_SIZE)
    used = column(data, HR_STORAGE_USED)
    total_size = total_used = 0
    for idx, kind in types.items():
        if text(kind).lstrip(".") != HR_STORAGE_RAM:
            continue
        unit, size, use = integer(units.get(idx)) or 1, integer(sizes.get(idx)), integer(used.get(idx))
        if size and use is not None and size > 0:
            total_size += size * unit
            total_used += use * unit
    if total_size:
        memory = round(100.0 * total_used / total_size, 1)
    return {"cpu_pct": cpu, "memory_pct": memory}
