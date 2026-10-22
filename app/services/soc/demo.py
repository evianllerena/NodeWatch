"""Sample detections for previewing the Security Operations page before a source is connected (v0.10.30).

Clearly labelled as sample data wherever it is shown; never stored, never mixed with real detections, never
sent anywhere. The organisation is fictitious (sites, hosts, addresses from documentation ranges where
public); attacker addresses use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and a
few others only as labels. It exercises exactly the same engine as real data.
"""

from __future__ import annotations

import random
import time
from typing import Any

from app.integrations.domain import SecurityEvent, stable_key
from app.services.soc.context import Context

SOURCE_A = "sample_firewalls"
SOURCE_B = "sample_wireless"
PRODUCTS = {SOURCE_A: ("Sample firewalls", "Sample vendor"), SOURCE_B: ("Sample wireless", "Sample vendor")}

SITES = {
    "hq": "Headquarters",
    "dc1": "Data Center East",
    "north": "North Clinic",
    "south": "South Clinic",
    "west": "West Campus",
}
SENSORS = [  # name, site, key
    ("FW-HQ1", "hq", "s-hq1"),
    ("FW-DC1", "dc1", "s-dc1"),
    ("FW-NORTH1", "north", "s-no1"),
    ("FW-SOUTH1", "south", "s-so1"),
    ("FW-WEST1", "west", "s-we1"),
]
ASSETS = [  # ip, name, role, site
    ("10.10.1.20", "HQ-WEB-01", "server", "hq"),
    ("10.10.1.25", "HQ-MAIL-01", "server", "hq"),
    ("10.20.5.10", "DC-VPN-GW", "firewall", "dc1"),
    ("10.20.8.40", "DC-EHR-APP", "server", "dc1"),
    ("10.20.8.41", "DC-EHR-DB", "server", "dc1"),
    ("10.30.2.77", "10.30.2.77", "endpoint", "north"),
    ("10.30.2.91", "10.30.2.91", "endpoint", "north"),
    ("10.40.4.12", "10.40.4.12", "endpoint", "south"),
    ("10.50.3.5", "WEST-PRINT-01", "server", "west"),
    ("10.50.9.33", "10.50.9.33", "endpoint", "west"),
]
# country, weight, attacker addresses
ORIGINS = [
    ("CN", 30, ["203.0.113.14", "203.0.113.77", "203.0.113.90"]),
    ("RU", 22, ["198.51.100.23", "198.51.100.61"]),
    ("US", 18, ["192.0.2.45", "192.0.2.88", "192.0.2.130"]),
    ("NL", 9, ["198.51.100.140"]),
    ("BR", 8, ["203.0.113.150"]),
    ("IN", 7, ["203.0.113.201"]),
    ("IR", 6, ["198.51.100.199"]),
    ("KP", 3, ["198.51.100.250"]),
    ("VN", 5, ["192.0.2.201"]),
    ("DE", 4, ["192.0.2.220"]),
    ("RO", 4, ["198.51.100.31"]),
    ("UA", 3, ["203.0.113.33"]),
    ("TR", 3, ["192.0.2.9"]),
    ("NG", 2, ["203.0.113.5"]),
    ("KR", 3, ["192.0.2.17"]),
]
INBOUND = [  # kind, name, severity, cves, weight, port
    ("reconnaissance", "TCP port sweep", "info", [], 40, 0),
    ("reconnaissance", "SSH brute-force probe", "warning", [], 18, 22),
    ("credential", "Repeated VPN sign-in failures", "major", [], 9, 443),
    ("exploit", "Log4j remote code execution attempt", "critical", ["CVE-2021-44228"], 8, 443),
    ("exploit", "VPN gateway command injection attempt", "critical", ["CVE-2024-3400"], 6, 443),
    ("exploit", "Mail server request forgery attempt", "critical", ["CVE-2021-26855"], 4, 443),
    ("exploit", "Web framework path traversal attempt", "major", ["CVE-2021-41773"], 7, 80),
    ("exploit", "SQL injection attempt", "major", [], 9, 443),
    ("flood", "SYN flood", "warning", [], 6, 443),
    ("malware", "Malicious document download", "major", [], 3, 443),
]
OUTBOUND = [
    ("command_control", "Beacon to known command server", "critical"),
    ("command_control", "DNS tunnel to suspicious domain", "major"),
    ("web", "Phishing page blocked", "warning"),
    ("web", "Newly registered malicious domain", "warning"),
    ("data_loss", "Large upload to file-sharing site", "major"),
]


class DemoContext(Context):
    def __init__(self) -> None:
        super().__init__()
        for ip, name, role, site in ASSETS:
            managed = role != "endpoint"
            node = {"node_id": f"demo:{name}" if managed else "", "name": name, "role": role, "site_key": site, "site_name": SITES[site], "model": ""}
            self.by_ip[ip] = node
        for name, site, key in SENSORS:
            node = {"node_id": f"demo:{name}", "name": name, "role": "firewall", "site_key": site, "site_name": SITES[site], "model": ""}
            self.by_record[f"{SOURCE_A}:{key}"] = node
        self.sites = dict(SITES)
        self.ready = True

    def asset(self, ip: str) -> dict[str, Any] | None:
        hit = self.by_ip.get(ip)
        if hit:
            return {**hit, "ip": ip, "managed": hit["role"] != "endpoint"}
        if ip.startswith("10."):
            site = {"10": "hq", "20": "dc1", "30": "north", "40": "south", "50": "west"}.get(ip.split(".")[1], "")
            return {"node_id": "", "name": ip, "role": "endpoint", "site_key": site, "site_name": SITES.get(site, ""), "ip": ip, "managed": False}
        return None


def _pick(rng: random.Random, rows: list, weight_index: int) -> Any:
    total = sum(r[weight_index] for r in rows)
    x = rng.uniform(0, total)
    for r in rows:
        x -= r[weight_index]
        if x <= 0:
            return r
    return rows[-1]


def events(hours: float = 168.0, now: float | None = None) -> list[dict[str, Any]]:
    """A deterministic week of sample detections (the same every time within one hour)."""
    now = now or time.time()
    anchor = int(now // 3600) * 3600
    rng = random.Random(anchor // 86400)
    out: list[SecurityEvent] = []
    span = hours * 3600
    sensor_of = {s[1]: s for s in SENSORS}
    n = int(1800 * hours / 168) + 60
    for i in range(n):
        ts = anchor - rng.random() ** 1.3 * span + (now - anchor)
        country, _w, ips = _pick(rng, ORIGINS, 1)
        kind, name, sev, cves, _w2, port = _pick(rng, INBOUND, 4)
        ip, aname, role, site = rng.choice(ASSETS[:5] + ASSETS[8:9]) if kind != "reconnaissance" else rng.choice(ASSETS)
        sensor = sensor_of[site]
        attacker = rng.choice(ips)
        outcome = "blocked"
        # the story: one attacker's Log4j attempts slip past an alert-only profile on the DMZ rule
        if kind == "exploit" and attacker == "203.0.113.90" and "Log4j" in name and rng.random() < 0.5:
            outcome = "alerted"
        if kind == "credential" and attacker == "198.51.100.23" and rng.random() < 0.25:
            outcome = "alerted"
        if kind == "reconnaissance" and rng.random() < 0.3:
            outcome = "alerted"
        out.append(
            SecurityEvent(
                key=stable_key("demo", i, anchor),
                source=SOURCE_A,
                timestamp=ts,
                kind=kind,
                severity=sev,
                outcome=outcome,
                direction="inbound",
                name=name,
                signature_id=str(30000 + INBOUND.index((kind, name, sev, cves, _w2, port))),
                cves=list(cves),
                category=kind,
                src_ip=attacker,
                src_country=country,
                dst_ip=ip,
                dst_port=port or rng.choice([80, 443, 3389, 8443]),
                sensor_key=sensor[2],
                sensor_name=sensor[0],
                rule="inbound-dmz" if site in ("hq", "dc1") else "inbound-branch",
                count=rng.choice([1, 1, 1, 2, 3, 6]) if kind in ("reconnaissance", "flood") else 1,
                application="web-browsing" if port in (80, 443) else "ssh" if port == 22 else "",
            )
        )
    # an infected laptop at North Clinic calling out (Reach 4), partly blocked
    for j in range(46):
        ts = now - 5.5 * 3600 + j * 420 + rng.uniform(-60, 60)
        kind, name, sev = OUTBOUND[0] if j % 3 else OUTBOUND[1]
        out.append(
            SecurityEvent(
                key=stable_key("demo-c2", j, anchor),
                source=SOURCE_A,
                timestamp=ts,
                kind=kind,
                severity=sev,
                outcome="blocked" if j % 4 else "alerted",
                direction="outbound",
                name=name,
                src_ip="10.30.2.77",
                dst_ip="198.51.100.66" if j % 3 else "203.0.113.120",
                dst_country="RU" if j % 3 else "CN",
                dst_host="update-check.example.net" if j % 3 else "cdn-sync.example.org",
                sensor_key="s-no1",
                sensor_name="FW-NORTH1",
                rule="outbound-internet",
                src_user="north\\nurse.station4",
            )
        )
    # the same laptop probing neighbours (Reach 5)
    for j in range(9):
        out.append(
            SecurityEvent(
                key=stable_key("demo-lat", j, anchor),
                source=SOURCE_A,
                timestamp=now - 2.4 * 3600 + j * 300,
                kind="exploit" if j % 3 == 0 else "reconnaissance",
                severity="major" if j % 3 == 0 else "warning",
                outcome="blocked",
                direction="internal",
                name="SMB remote code execution attempt" if j % 3 == 0 else "Internal port scan",
                cves=["CVE-2017-0144"] if j % 3 == 0 else [],
                src_ip="10.30.2.77",
                dst_ip=rng.choice(["10.30.2.91", "10.30.2.12", "10.30.2.40"]),
                dst_port=445,
                sensor_key="s-no1",
                sensor_name="FW-NORTH1",
                rule="clinic-segmentation",
            )
        )
    # web threats from users
    for j in range(70):
        kind, name, sev = OUTBOUND[2 + j % 3]
        src = rng.choice(["10.40.4.12", "10.50.9.33", "10.30.2.91", "10.10.4.50"])
        out.append(
            SecurityEvent(
                key=stable_key("demo-web", j, anchor),
                source=SOURCE_A,
                timestamp=now - rng.random() * span,
                kind=kind,
                severity=sev,
                outcome="blocked" if rng.random() < 0.92 else "allowed",
                direction="outbound",
                name=name,
                src_ip=src,
                dst_ip=f"192.0.2.{rng.randint(1, 250)}",
                dst_country=rng.choice(["US", "NL", "DE", "SG", "RU"]),
                dst_host=rng.choice(["login-verify.example.com", "invoice-share.example.net", "free-tools.example.org"]),
                sensor_key={"10.40": "s-so1", "10.50": "s-we1", "10.30": "s-no1"}.get(src[:5], "s-hq1"),
                sensor_name={"10.40": "FW-SOUTH1", "10.50": "FW-WEST1", "10.30": "FW-NORTH1"}.get(src[:5], "FW-HQ1"),
            )
        )
    # rogue access point at West Campus, from the wireless system
    for j in range(5):
        out.append(
            SecurityEvent(
                key=stable_key("demo-wifi", j, anchor),
                source=SOURCE_B,
                timestamp=now - (30 - j * 5) * 3600,
                kind="wireless",
                severity="major" if j == 4 else "warning",
                outcome="alerted",
                direction="internal",
                name="Rogue access point imitating a staff network" if j == 4 else "Rogue access point",
                category="rogue_ap",
                site_key="west",
                sensor_name="WEST-AP-2F-07",
                vendor={"site_name": SITES["west"]},
            )
        )
    return [e.to_dict() for e in out if now - e.timestamp <= span]


def software() -> list[dict[str, Any]]:
    return [
        {"vendor": "Sample vendor", "model": "FW-3200", "role": "firewall", "devices": 5, "versions": [{"version": "11.1.4", "count": 3}, {"version": "11.0.2", "count": 2}], "targeted": 3},
        {"vendor": "Sample vendor", "model": "SW-48P", "role": "switch", "devices": 41, "versions": [{"version": "23.4R2", "count": 38}, {"version": "22.2R3", "count": 3}], "targeted": 0},
        {"vendor": "Sample vendor", "model": "AP-45", "role": "wireless_ap", "devices": 120, "versions": [{"version": "0.14.2", "count": 120}], "targeted": 0},
    ]
