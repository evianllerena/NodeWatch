"""LLDP/CDP fingerprints: guess what an unmanaged neighbor is from what it advertises (v0.10.16).

The topology engine is vendor-neutral; the only vendor knowledge it uses lives here, as data. When a
switch reports an LLDP neighbor that no connected source describes ("discovered" node), we look at
the advertised system description, system name and capabilities to guess its role, vendor and model
so it can be placed in the right tier. Adding a vendor = adding a row.

Each rule: (pattern on "system description + system name", role, vendor display name).
First match wins, so put specific products before generic ones.
"""

from __future__ import annotations

import re
from typing import Any

FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    # SD-WAN edges
    (
        r"silver ?peak|edgeconnect|\bec-?(v|xs|s|m|l|xl|us)\b|\becos\b",
        "sdwan_edge",
        "HPE Aruba Networking (Silver Peak)",
    ),
    (r"velocloud", "sdwan_edge", "VMware VeloCloud"),
    (r"viptela|vedge|catalyst sd-?wan|c8\d{3}v?-?\w*.*sd-?wan", "sdwan_edge", "Cisco"),
    (r"meraki mx|\bmx\d{2,3}w?\b.*meraki", "sdwan_edge", "Cisco Meraki"),
    (r"versa", "sdwan_edge", "Versa Networks"),
    # Firewalls
    (r"palo ?alto|pan-?os|\bpa-\d{3,4}", "firewall", "Palo Alto Networks"),
    (r"fortiswitch|\bfs-\d{3}", "switch", "Fortinet"),
    (r"fortiap|\bfap-", "wireless_ap", "Fortinet"),
    (r"fortigate|fortios|\bfgt|\bfg-\d", "firewall", "Fortinet"),
    (r"check ?point|gaia", "firewall", "Check Point"),
    (r"sonicwall|sonicos", "firewall", "SonicWall"),
    (r"adaptive security appliance|\basa\s?\d{4}|firepower|\bftd\b", "firewall", "Cisco"),
    (r"juniper.*\bsrx|\bsrx\d{3,4}", "firewall", "Juniper Networks"),
    # Wireless
    (r"mist ap|juniper.*\bap\d{2}|^ap\d{2}\b", "wireless_ap", "Juniper Networks"),
    (r"meraki mr|\bmr\d{2}\b", "wireless_ap", "Cisco Meraki"),
    (r"aruba.*\b(ap|iap)-?\d|arubaos.*instant", "wireless_ap", "HPE Aruba Networking"),
    (r"cisco.*(aironet|\bc9\d{2,3}ax?i?\b.*access point|\bap\b)", "wireless_ap", "Cisco"),
    (r"wireless lan controller|\bwlc\b|c98\d0", "wireless_controller", "Cisco"),
    # Routers
    (r"juniper.*\b(mx|ptx|acx)\d|\bmx\d{2,4}\b", "router", "Juniper Networks"),
    (r"cisco ios xr|\b(isr|asr)\s?\d{3,4}", "router", "Cisco"),
    # Switches
    (r"juniper|junos|\bex\d{4}|\bqfx\d{4}", "switch", "Juniper Networks"),
    (r"aruba.*(cx|os-cx)|arubaos-switch|procurve", "switch", "HPE Aruba Networking"),
    (r"arista|\beos\b", "switch", "Arista Networks"),
    (r"meraki ms|\bms\d{3}\b", "switch", "Cisco Meraki"),
    (r"nx-os|nexus", "switch", "Cisco"),
    (r"cisco ios|catalyst|\bc9[23]\d{2}|ios-xe", "switch", "Cisco"),  # refined by capabilities below
    (r"dell|force10|os10", "switch", "Dell"),
    (r"hpe? .*comware|h3c", "switch", "HPE"),
    # Servers / endpoints
    (r"vmware|esxi", "server", "VMware"),
    (r"windows|linux|ubuntu|debian|red hat|freebsd", "server", ""),
    (r"phone|polycom|yealink|avaya|mitel", "endpoint", ""),
)

_COMPILED = tuple((re.compile(p, re.I), role, vendor) for p, role, vendor in FINGERPRINTS)

_MODEL = re.compile(
    r"\b(PA-\d{3,4}\w*|FG-?\d+\w*|FortiGate-\d+\w*|EX\d{4}[\w-]*|QFX\d{4}[\w-]*|SRX\d{3,4}\w*|EC-[A-Z]+[\w-]*|"
    r"C9\d{3}[\w-]*|AP\d{2}\w*|MX\d{2,4}\w*|MS\d{3}[\w-]*|MR\d{2}\w*|ISR\d{4}\w*|ASR\d{3,4}\w*|"
    r"N[3579]K-[\w-]+|CX\s?\d{4}\w*)\b",
    re.I,
)


def fingerprint(description: str = "", name: str = "", capabilities: list[str] | None = None) -> dict[str, Any]:
    """{role, vendor_name, model, matched} guessed from advertised LLDP/CDP fields."""
    text = f"{description or ''} {name or ''}".strip()
    caps = {str(c).lower() for c in capabilities or []}
    role, vendor, matched = "unknown", "", ""
    for rx, r, v in _COMPILED:
        if text and rx.search(text):
            role, vendor, matched = r, v, rx.pattern
            break
    if role == "switch" and "router" in caps and "bridge" not in caps:
        role = "router"
    if role == "unknown":
        if caps & {"wlan", "wlan-ap", "wlan access point", "wlanaccesspoint"}:
            role = "wireless_ap"
        elif "router" in caps and "bridge" not in caps:
            role = "router"
        elif "bridge" in caps:
            role = "switch"
        elif caps & {"telephone", "station", "station-only"}:
            role = "endpoint"
    m = _MODEL.search(description or "") or _MODEL.search(name or "")
    return {"role": role, "vendor_name": vendor, "model": m.group(1) if m else "", "matched": matched}
