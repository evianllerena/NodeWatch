"""Strict parsing of the SNMP target list (hosts, IP addresses and small private ranges).

Rules (security: the connector must never become a scanner of other people's networks):
* entries are separated by commas, semicolons, spaces or new lines; at most 64 entries;
* an entry is an IP address, a DNS host name, or a CIDR range;
* ranges must be private (RFC 1918 / IPv6 ULA) and no larger than /24 (IPv6 /120);
  the network and broadcast addresses of a range are never polled;
* multicast, broadcast, unspecified, reserved and link-local addresses are refused;
* at most 256 hosts in total after expanding ranges.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

MAX_HOSTS = 256
MAX_ENTRIES = 64
_SPLIT = re.compile(r"[\s,;]+")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$", re.I)


def _address_problem(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if addr.is_multicast:
        return "is a multicast address"
    if addr.is_unspecified:
        return "is the unspecified address"
    if isinstance(addr, ipaddress.IPv4Address) and addr == ipaddress.IPv4Address("255.255.255.255"):
        return "is the broadcast address"
    if addr.is_link_local:
        return "is a link-local address"
    if addr.is_reserved:
        return "is a reserved address"
    return ""


def check_address(value: Any) -> str:
    """'' when ``value`` is an address the connector may poll, else the reason it may not."""
    try:
        addr = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return "is not an IP address"
    return _address_problem(addr)


def parse_targets(value: Any) -> list[str]:
    """Target text → ordered, de-duplicated host list. Raises ValueError with a readable message."""
    entries = [e for e in _SPLIT.split(str(value or "").strip()) if e]
    if not entries:
        raise ValueError("Enter at least one SNMP target (IP address, host name or private /24-or-smaller range)")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"Too many SNMP target entries (at most {MAX_ENTRIES})")
    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        if host not in seen:
            seen.add(host)
            hosts.append(host)
        if len(hosts) > MAX_HOSTS:
            raise ValueError(f"The SNMP targets expand to more than {MAX_HOSTS} hosts; use smaller ranges")

    for entry in entries:
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"SNMP target {entry!r} is not a valid range") from None
            limit = 24 if network.version == 4 else 120
            if network.prefixlen < limit:
                raise ValueError(f"SNMP range {entry} is too large (at most /{limit})")
            if not network.is_private or network.is_link_local or network.is_loopback or network.is_multicast:
                raise ValueError(
                    f"SNMP range {entry} must be a private network (10/8, 172.16/12, 192.168/16, fc00::/7)"
                )
            for addr in network.hosts() if network.num_addresses > 2 else network:
                if not _address_problem(addr):
                    add(str(addr))
            continue
        try:
            addr = ipaddress.ip_address(entry)
        except ValueError:
            if not _HOSTNAME.match(entry) or entry.replace(".", "").isdigit():
                raise ValueError(f"SNMP target {entry!r} is not an IP address, host name or range") from None
            add(entry.lower().rstrip("."))
            continue
        problem = _address_problem(addr)
        if problem:
            raise ValueError(f"SNMP target {entry} {problem}")
        add(str(addr))
    return hosts


def resolve(host: str) -> str:
    """Host name → one pollable IP address (IPv4 preferred). Raises ValueError when it cannot be used."""
    if not check_address(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except OSError:
        raise ValueError(f"cannot resolve {host}") from None
    addresses = sorted({info[4][0] for info in infos}, key=lambda a: (":" in a, a))
    for address in addresses:
        if not check_address(address):
            return address
    raise ValueError(f"{host} resolves only to addresses that cannot be polled")
