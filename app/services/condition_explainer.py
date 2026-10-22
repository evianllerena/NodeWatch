from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _epoch(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    try:
        n = float(value)
        if n > 1e12:
            n /= 1000.0
        return n
    except (TypeError, ValueError):
        return 0.0


def _when(value: Any) -> str:
    ts = _epoch(value)
    if not ts:
        return "Not reported"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%b %d, %Y %I:%M:%S %p %Z")
    except (OverflowError, OSError, ValueError):
        return str(value)


def _entities(row: dict) -> list[dict]:
    value = row.get("impacted_entities") or row.get("entities") or []
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "type": str(item.get("entity_type") or item.get("type") or "device"),
                "name": str(item.get("entity_name") or item.get("name") or item.get("entity_mac") or "Unknown device"),
                "mac": str(item.get("entity_mac") or item.get("mac") or ""),
                "port": str(item.get("port_id") or item.get("port") or ""),
            }
        )
    return output


# Plain-English explanations for the Mist alarm types engineers see most (v0.10.16). Matched on
# substrings of the lower-case type, first rule wins. Sources: Mist alarm definitions
# (/api/v1/const/alarm_defs), Juniper Mist "Alerts" and "Marvis Actions" documentation.
_RULES: list[tuple[tuple[str, ...], tuple[str, ...], dict]] = [
    (
        ("port_flap", "sw_port_flap", "flap"),
        (),
        {
            "headline": "Switch port flapping",
            "summary": "A switch port on {where} keeps going down and up.",
            "impact": "Whatever is plugged into the port (AP, phone, camera, uplink) repeatedly loses its link; on an uplink this disconnects everything behind it.",
            "causes": (
                "Damaged/loose cable or patch panel jack, or a failing transceiver/optic.",
                "The connected device rebooting or power-cycling (PoE budget, crash loop).",
                "Speed/duplex or EEE negotiation problems.",
            ),
            "steps": (
                "Open the port in Port Toolkit: check errors, speed and how often the link changed.",
                "Check whether the attached device rebooted (PoE draw, uptime) before touching the cable.",
                "Re-seat or replace the patch cable/optic; move the device to another port to isolate the fault.",
            ),
        },
    ),
    (
        ("bad_cable", "cable"),
        (),
        {
            "headline": "Bad cable detected",
            "summary": "Marvis flagged a port on {where} whose errors or negotiation pattern point to a faulty cable.",
            "impact": "Expect CRC errors, low negotiated speed, intermittent link loss or PoE drop-outs for the attached device.",
            "causes": ("Damaged, too long or poorly terminated copper run.", "Faulty patch panel jack or patch cord."),
            "steps": (
                "Check the port's error counters and negotiated speed in Port Toolkit.",
                "Replace the patch cord first, then test/certify the horizontal run.",
                "If the cable tests good, try another switch port to rule out the port.",
            ),
        },
    ),
    (
        ("stp", "loop", "bpdu"),
        (),
        {
            "headline": "Spanning-tree / loop protection event",
            "summary": "Spanning tree or BPDU protection reported a problem on {where}.",
            "impact": "A loop can flood the VLAN and take down every client on it; BPDU guard may have err-disabled a port.",
            "causes": (
                "Someone connected a switch/hub or looped a cable on an edge port.",
                "Redundant links without STP/LAG agreement.",
            ),
            "steps": (
                "Find the port that received BPDUs or changed state repeatedly (Port Toolkit, recent events).",
                "Remove the loop/unauthorised switch, then clear the err-disabled port.",
            ),
        },
    ),
    (
        ("vc_", "virtual_chassis"),
        (),
        {
            "headline": "Virtual Chassis membership change",
            "summary": "The Virtual Chassis on {where} reported a member or role change.",
            "impact": "Ports on a missing member are down; a primary/backup switch-over briefly interrupts control-plane traffic.",
            "causes": (
                "A member lost power or rebooted.",
                "A VC port/cable between members failed.",
                "Firmware mismatch between members.",
            ),
            "steps": (
                "Open Chassis Manager to see which member is missing and the current primary/backup roles.",
                "Check power and the VC cabling of the missing member.",
                "Confirm all members run the same Junos version.",
            ),
        },
    ),
    (
        ("restart", "reboot", "rebooted"),
        (),
        {
            "headline": "Device restarted",
            "summary": "{where} restarted.",
            "impact": "Clients/ports on the device were offline during the reboot; repeated restarts point to a crash loop or power problem.",
            "causes": (
                "Power interruption or PoE budget problem (APs).",
                "Firmware upgrade or crash.",
                "Someone rebooted it from Mist.",
            ),
            "steps": (
                "Check uptime and whether this repeats (count, timeline below).",
                "For APs, check the switch port's PoE draw and class in Power Guard / Port Toolkit.",
                "Review Mist's audit log for a manual reboot or upgrade.",
            ),
        },
    ),
    (
        ("chassis_poe", "poe"),
        (),
        {
            "headline": "PoE problem",
            "summary": "The switch {where} reported a Power-over-Ethernet controller or budget alarm.",
            "impact": "Powered devices (APs, phones, cameras) can lose power or fail to come up.",
            "causes": (
                "PoE budget exceeded.",
                "PoE controller fault or firmware issue.",
                "A powered device drawing more than its class.",
            ),
            "steps": (
                "Open Power Guard / Port Toolkit to see PoE draw per port and the remaining budget.",
                "Check whether APs on this switch restarted around the same time.",
                "If the controller faulted, a PoE firmware upgrade or switch reboot may be needed (plan a window).",
            ),
        },
    ),
    (
        ("psu", "pem"),
        (),
        {
            "headline": "Power supply problem",
            "summary": "A power supply on {where} is failed, missing or not receiving input power.",
            "impact": "The device lost power redundancy; a second failure takes it down.",
            "causes": ("Unplugged power cord / tripped PDU circuit.", "Failed power supply unit."),
            "steps": (
                "Check the PSU LEDs and the feed/PDU it is plugged into.",
                "RMA the PSU if input power is present.",
            ),
        },
    ),
    (
        ("fan",),
        (),
        {
            "headline": "Fan failure",
            "summary": "A fan on {where} has failed or is missing.",
            "impact": "The device may overheat and shut down ports or itself.",
            "causes": ("Failed fan tray.", "Blocked airflow."),
            "steps": (
                "Check the fan tray status and airflow in the closet.",
                "Replace the fan tray (most are hot-swappable).",
            ),
        },
    ),
    (
        ("hot", "temp"),
        (),
        {
            "headline": "Over-temperature",
            "summary": "{where} is running hotter than its limit.",
            "impact": "Hardware may throttle or shut down to protect itself.",
            "causes": ("Closet cooling failure or blocked vents.", "Fan failure."),
            "steps": ("Check closet HVAC and airflow.", "Look for a fan alarm on the same device."),
        },
    ),
    (
        ("rogue", "honeypot", "spoof"),
        (),
        {
            "headline": "Rogue / unauthorised wireless",
            "summary": "Mist sees an access point at {site} that is not yours but is either on your wired network (rogue) or imitating your SSID (honeypot).",
            "impact": "Clients may connect to an untrusted AP, and a rogue on the LAN bypasses your security controls.",
            "causes": (
                "Personal hotspot or consumer router plugged into a wall jack.",
                "Neighbouring network (often harmless) or a spoofing attack.",
            ),
            "steps": (
                "Check the BSSID/SSID and RSSI below; strong signal + seen on wired = act now.",
                "Locate it with Mist location and find its switch port with Device Finder (search the BSSID MAC).",
                "If harmless (neighbour), mute this alert type for the site.",
            ),
        },
    ),
    (
        ("bgp",),
        (),
        {
            "headline": "BGP neighbor down",
            "summary": "A BGP session on WAN edge {where} is down.",
            "impact": "Routes learned from that neighbor are gone; traffic may fail over or blackhole.",
            "causes": (
                "WAN/underlay circuit down.",
                "Peer device down or reconfigured.",
                "Authentication/timer mismatch.",
            ),
            "steps": (
                "Check the WAN interface/circuit to the peer.",
                "Confirm the peer is up and its config matches (AS, password).",
            ),
        },
    ),
    (
        ("tunnel", "vpn", "path_down", "peer"),
        (),
        {
            "headline": "VPN / tunnel down",
            "summary": "An overlay tunnel or VPN path on {where} is down.",
            "impact": "Site-to-site or cloud-security traffic over this path fails or takes a backup path.",
            "causes": (
                "Underlay WAN link down or lossy.",
                "IKE/IPsec mismatch or expired certificate.",
                "Remote hub down.",
            ),
            "steps": ("Check the underlay WAN link health.", "Check the remote end and IKE/IPsec logs."),
        },
    ),
    (
        ("dhcp",),
        (),
        {
            "headline": "DHCP problem",
            "summary": "Clients at {site} are failing to get an address, or a DHCP pool on {where} is exhausted.",
            "impact": "New or roaming clients cannot get online.",
            "causes": (
                "Pool exhausted / lease time too long.",
                "DHCP server or relay unreachable.",
                "Missing VLAN on a trunk.",
            ),
            "steps": (
                "Check pool utilisation and the DHCP server.",
                "Verify the VLAN is allowed on the uplink trunks.",
            ),
        },
    ),
    (
        ("dns",),
        (),
        {
            "headline": "DNS failures",
            "summary": "Clients at {site} are failing DNS lookups.",
            "impact": "Users see 'no internet' even when connected.",
            "causes": ("DNS server down or unreachable.", "Firewall/filtering blocking DNS."),
            "steps": ("Test the configured DNS servers from the site.", "Check firewall policy for DNS."),
        },
    ),
    (
        ("missing_vlan",),
        (),
        {
            "headline": "Missing VLAN",
            "summary": "Traffic for a VLAN is seen on {where} but the VLAN is not allowed on the switch port.",
            "impact": "Clients on that VLAN behind the port cannot reach their gateway.",
            "causes": ("Trunk/port profile is missing the VLAN.",),
            "steps": ("Compare the port profile with the AP/WLAN VLANs in Port Toolkit.",),
        },
    ),
    (
        ("negotiation", "duplex", "mismatch"),
        (),
        {
            "headline": "Speed/duplex mismatch",
            "summary": "A port on {where} negotiated badly with its neighbor.",
            "impact": "Throughput collapses and errors climb.",
            "causes": ("Hard-coded speed/duplex on one side.", "Bad cable."),
            "steps": ("Set both sides to auto-negotiation.", "Check the cable if it persists."),
        },
    ),
    (
        ("cpu", "memory"),
        (),
        {
            "headline": "High CPU / memory",
            "summary": "{where} is reporting sustained high CPU or memory use.",
            "impact": "Control-plane protocols (STP, LACP, routing) may time out and the device may become unresponsive.",
            "causes": ("Broadcast storm or loop.", "Software bug / runaway process.", "Too many routes or MACs."),
            "steps": (
                "Check for an STP/loop alarm at the same site.",
                "Review processes on the device; open a case if it persists.",
            ),
        },
    ),
]


def _match_rule(atype: str) -> dict | None:
    for tokens, excluded, rule in _RULES:
        if any(t in atype for t in tokens) and not any(x in atype for x in excluded):
            return rule
    return None


def explain_condition(
    row: dict, definition: dict | None, *, site: str, device: str, evidence: list[dict] | None = None
) -> dict:
    """Engineer summary for a condition, with ``evidence`` (what Mist actually reported) attached."""
    result = _explain(row, definition, site=site, device=device)
    result["evidence"] = list(evidence or [])
    return result


def _explain(row: dict, definition: dict | None, *, site: str, device: str) -> dict:
    definition = definition or {}
    atype = str(row.get("type") or row.get("key") or row.get("alarm_type") or "").lower()
    impacted = _entities(row)
    detected = _when(row.get("timestamp") or row.get("created_time"))
    last_seen = _when(row.get("last_seen") or row.get("timestamp"))
    def_text = str(definition.get("description") or definition.get("desc") or "").strip()

    if atype == "switch_stp_loop" or ("stp" in atype and "loop" in atype):
        count = len(impacted)
        names = [x["name"] for x in impacted if x.get("name")]
        entity_text = ", ".join(names[:5]) + (f" and {count - 5} more" if count > 5 else "")
        summary = f"Marvis detected Spanning Tree behavior consistent with a Layer 2 loop at {site}. " + (
            f"{count} switch{'es' if count != 1 else ''} are identified as impacted."
            if count
            else "Mist did not include the exact switch list in this alert payload."
        )
        impact = "An STP loop can cause rapid topology changes, broadcast or multicast storms, MAC-table instability, high switch CPU, packet loss, and widespread client connectivity problems."
        next_steps = [
            "Start with the impacted switches below and review their recent STP topology-change and port-flap events.",
            "Check trunk, LAG/LACP, and redundant inter-switch links for an unintended second active Layer 2 path.",
            "Review STP state/role on uplinks and verify BPDU/STP settings have not been disabled or filtered on an intermediate device.",
            "Use Device Finder / Port Toolkit to inspect LLDP neighbors and identify ports that recently changed state repeatedly.",
            "If Marvis self-driving Loop Detected is enabled, verify whether Mist disabled a port automatically before manually re-enabling anything.",
        ]
        if not any(x.get("port") for x in impacted):
            next_steps.append(
                "This alarm payload does not identify the exact looping port. Correlate the impacted switches with recent switch/port events before changing a port."
            )
        return {
            "headline": "Layer 2 / STP loop detected",
            "summary": summary,
            "impact": impact,
            "likely_causes": [
                "Redundant links are forwarding simultaneously without the expected STP/LAG protection.",
                "A cabling or unmanaged-switch loop was introduced.",
                "STP, trunk, VLAN, or LACP configuration is inconsistent across connected switches.",
            ],
            "next_steps": next_steps,
            "entities": impacted,
            "detected": detected,
            "last_seen": last_seen,
            "mist_definition": def_text,
            "context": entity_text,
        }

    # "*_currently_down" is what the dashboard synthesises for devices Mist reports as down.
    if any(
        token in atype
        for token in (
            "offline",
            "disconnected",
            "device_down",
            "switch_down",
            "gateway_down",
            "ap_down",
            "currently_down",
        )
    ):
        return {
            "headline": "Infrastructure connectivity lost",
            "summary": f"Mist reports that {device or 'a managed device'} at {site} is currently disconnected or has recently lost cloud connectivity.",
            "impact": "Clients behind the device may lose network service. A device-down condition can be caused by power loss, an upstream switch/uplink failure, WAN/cloud reachability loss, reboot, or physical failure.",
            "likely_causes": [
                "Power loss or device reboot.",
                "Upstream switch/uplink failure.",
                "WAN/DNS/cloud reachability issue.",
                "Physical device or cabling failure.",
            ],
            "next_steps": [
                "Check “Also down at this site” above: several devices dropping together points to site power, core switching or WAN rather than this device.",
                "If multiple devices dropped together, investigate site power, UPS, core switching, and WAN before treating them as independent failures.",
                "Review the recent events above for a restart, upgrade or port-down event before dispatching.",
            ],
            "entities": impacted,
            "detected": detected,
            "last_seen": last_seen,
            "mist_definition": def_text,
            "context": "",
        }

    rule = _match_rule(atype)
    if rule is not None:
        where = f"{device} at {site}" if device and device != "Unknown device" else site
        return {
            "headline": rule["headline"],
            "summary": rule["summary"].format(where=where, site=site, device=device or "the device")
            + (f" Mist: {def_text}" if def_text else ""),
            "impact": rule["impact"],
            "likely_causes": list(rule["causes"]),
            "next_steps": list(rule["steps"]),
            "entities": impacted,
            "detected": detected,
            "last_seen": last_seen,
            "mist_definition": def_text,
            "context": "",
        }

    if any(token in atype for token in ("psu", "pem", "power", "poe", "low_power")):
        return {
            "headline": "Power / hardware condition",
            "summary": f"Mist reports a power-related condition affecting {device or 'infrastructure'} at {site}.",
            "impact": "Power-supply and PoE conditions can lead to device restarts, powered-endpoint outages, or reduced redundancy.",
            "likely_causes": [
                "Power supply or feed issue.",
                "Insufficient PoE budget or negotiation problem.",
                "Hardware component alarm.",
            ],
            "next_steps": [
                "Check the affected device power/PoE telemetry and recent restart events.",
                "Verify UPS/PDU/feed health if multiple devices at the site show power symptoms.",
                "Use Power Guard for switch-port power context where applicable.",
            ],
            "entities": impacted,
            "detected": detected,
            "last_seen": last_seen,
            "mist_definition": def_text,
            "context": "",
        }

    if any(token in atype for token in ("rogue", "spoof", "attack", "security", "ddos", "idp")):
        return {
            "headline": "Security condition",
            "summary": f"Mist reports a security-related condition at {site}"
            + (f" involving {device}." if device and device != "Unknown device" else ".")
            + (f" {def_text}" if def_text else ""),
            "impact": "Review the affected identities/devices and determine whether this is expected activity or a security event requiring containment.",
            "likely_causes": [],
            "next_steps": [
                "Review the impacted entities and the details Mist reported below (SSID, BSSID, MACs, how often it was seen).",
                "Check Security Operations and Event Relay for related activity before taking containment action.",
            ],
            "entities": impacted,
            "detected": detected,
            "last_seen": last_seen,
            "mist_definition": def_text,
            "context": "",
        }

    return {
        "headline": str(
            definition.get("display")
            or definition.get("name")
            or row.get("title")
            or atype.replace("_", " ").title()
            or "Mist condition"
        ),
        "summary": def_text or f"Mist reports an active condition affecting {device or site}.",
        "impact": "Review the impacted device/site context and correlate with recent Mist events before making a configuration change.",
        "likely_causes": [],
        "next_steps": [
            "Review the impacted entities and the details Mist reported below.",
            "Use Device Finder for the affected MAC/device when deeper attachment and alarm context is needed.",
        ],
        "entities": impacted,
        "detected": detected,
        "last_seen": last_seen,
        "mist_definition": def_text,
        "context": "",
    }
