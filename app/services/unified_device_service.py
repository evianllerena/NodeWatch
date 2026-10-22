from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.integrations.base import IntegrationError, registry
from app.integrations.correlation import CORRELATION_ENGINE, Observation
from app.integrations.field_registry import public_field_catalog
from app.integrations.providers.palo_alto_device_security import get_palo_alto_device_security_provider
from app.services.detective_service import clean_mac, detective_detail, display_mac, search_detective


def _query_type(value: str) -> str:
    raw = (value or "").strip()
    mac = clean_mac(raw)
    if len(mac) == 12:
        return "mac"
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        return "text"


def _pa_lookup(query: str, *, fresh: bool = False) -> tuple[dict[str, Any], str]:
    provider = get_palo_alto_device_security_provider()
    if not provider.configured:
        return {}, ""
    try:
        kind = _query_type(query)
        if kind == "ip":
            return provider.lookup_by_ip(query.strip(), fresh=fresh), ""
        if kind == "mac":
            return provider.lookup_by_mac(display_mac(clean_mac(query)), fresh=fresh), ""
    except IntegrationError as exc:
        if exc.code == "NOT_FOUND":
            return {}, ""
        return {}, exc.code
    except Exception:
        return {}, "PROVIDER_UNAVAILABLE"
    return {}, ""


def _merge_search_result(item: dict[str, Any], intel: dict[str, Any]) -> dict[str, Any]:
    if not intel:
        return item
    item_mac = clean_mac(item.get("mac"))
    intel_mac = clean_mac(intel.get("mac"))
    if item_mac and intel_mac and item_mac != intel_mac:
        return item
    merged = dict(item)
    if intel.get("ip") and not merged.get("ip"):
        merged["ip"] = str(intel["ip"])
    if intel.get("hostname"):
        current_title = str(merged.get("title") or "")
        if not current_title or clean_mac(current_title) == item_mac:
            merged["title"] = str(intel["hostname"])
        if not merged.get("hostname"):
            merged["hostname"] = str(intel["hostname"])
    vendor_model = " ".join(str(x) for x in (intel.get("vendor"), intel.get("model")) if x).strip()
    if vendor_model and (
        not merged.get("subtitle")
        or merged.get("subtitle") in {merged.get("display_mac"), "Wired client", "Wireless client"}
    ):
        merged["subtitle"] = vendor_model
    if intel.get("vendor"):
        merged["vendor"] = str(intel.get("vendor") or "")
    if intel.get("model"):
        merged["model"] = str(intel.get("model") or "")
    if intel.get("category"):
        merged["intelligence_category"] = intel.get("category")
        merged["device_type"] = str(intel.get("category") or "")
    if intel.get("confidence") not in (None, ""):
        merged["intelligence_confidence"] = intel.get("confidence")
    return merged


def _palo_only_result(intel: dict[str, Any], query: str) -> dict[str, Any]:
    mac = clean_mac(intel.get("mac"))
    title = str(intel.get("hostname") or display_mac(mac) or intel.get("ip") or query)
    subtitle = " ".join(str(x) for x in (intel.get("vendor"), intel.get("model")) if x).strip() or str(
        intel.get("profile") or "Endpoint"
    )
    return {
        "kind": "endpoint",
        "kind_label": "Endpoint",
        "client_profile": {"icon": "PC", "label": str(intel.get("category") or "Endpoint"), "family": "endpoint"},
        "mac": mac,
        "display_mac": display_mac(mac),
        "title": title,
        "subtitle": subtitle,
        "ip": str(intel.get("ip") or ""),
        "site_id": "",
        "site": "",
        "attachment": "",
        "attachment_mac": "",
        "port_id": "",
        "network": "",
        "vlan": str(intel.get("vlan") or ""),
        "username": str(intel.get("username") or ""),
        "hostname": str(intel.get("hostname") or ""),
        "last_seen": str(intel.get("last_activity") or ""),
        "sort_time": 0,
        "score": 120,
        "intelligence_category": intel.get("category", ""),
        "intelligence_confidence": intel.get("confidence", ""),
        "device_type": str(intel.get("category") or "Endpoint"),
        "vendor": str(intel.get("vendor") or ""),
        "model": str(intel.get("model") or ""),
    }


def _dedupe_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("kind") or ""), clean_mac(row.get("mac")), str(row.get("site_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def unified_search_detective(query: str, site_id: str | None = None) -> dict[str, Any]:
    query = (query or "").strip()
    provider = get_palo_alto_device_security_provider()
    use_intelligence = bool(query) and provider.configured and _query_type(query) in {"ip", "mac"}

    if not use_intelligence:
        data = search_detective(query, site_id=site_id)
        if site_id:
            scoped = [row for row in (data.get("results") or []) if str(row.get("site_id") or "") == str(site_id)]
            data["results"] = scoped
            data["total"] = len(scoped)
        # Provider/source counts are correlation internals, not Device Finder UI data.
        data.pop("sources", None)
        data["provider_partial"] = False
        data["field_catalog_version"] = 1
        return data

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_core = pool.submit(search_detective, query, site_id)
        f_intel = pool.submit(_pa_lookup, query)
        data = f_core.result()
        intel, provider_error = f_intel.result()

    rows = list(data.get("results") or [])
    intel_mac = clean_mac(intel.get("mac")) if intel else ""

    # IP searches are where L2-only visibility used to stop. If device intelligence
    # resolves IP -> MAC and the original network search did not find that MAC, run a
    # second network lookup by MAC and fold those results into the same search.
    if intel_mac and not any(clean_mac(row.get("mac")) == intel_mac for row in rows):
        try:
            by_mac = search_detective(display_mac(intel_mac), site_id=site_id)
            rows.extend(by_mac.get("results") or [])
        except Exception:
            pass

    if intel_mac:
        rows = [_merge_search_result(row, intel) if clean_mac(row.get("mac")) == intel_mac else row for row in rows]
        if not any(clean_mac(row.get("mac")) == intel_mac for row in rows):
            rows.append(_palo_only_result(intel, query))
    elif intel and not rows:
        rows.append(_palo_only_result(intel, query))

    rows = _dedupe_results(rows)

    # A selected site is a hard investigation boundary. Provider-only records that
    # cannot be correlated to that Mist site are intentionally excluded rather than
    # leaking organization-wide intelligence into a site-scoped result set.
    if site_id:
        rows = [row for row in rows if str(row.get("site_id") or "") == str(site_id)]

    rows.sort(key=lambda x: (int(x.get("score") or 0), float(x.get("sort_time") or 0)), reverse=True)
    data["results"] = rows
    data["total"] = len(rows)
    data.pop("sources", None)
    data["provider_partial"] = bool(provider_error)
    data["field_catalog_version"] = 1
    # Provider/source details are deliberately not rendered in Device Finder.
    return data


def _empty_endpoint_detail(mac: str, intel: dict[str, Any]) -> dict[str, Any]:
    title = str(intel.get("hostname") or display_mac(mac) or intel.get("ip") or "Endpoint")
    return {
        "mode": "live",
        "kind": "endpoint",
        "identity": {
            "title": title,
            "mac": display_mac(mac),
            "ip": str(intel.get("ip") or ""),
            "username": str(intel.get("username") or ""),
            "hostname": str(intel.get("hostname") or ""),
            "site": "",
            "site_id": "",
        },
        "path": [],
        "connection": {"type": "Endpoint", "status": str(intel.get("status") or "Seen")},
        "authentication": {},
        "device": {},
        "port": {},
        "alarms": [],
        "nac_events": [],
        "troubleshoot": {"available": False, "pending": False, "data": {}, "error": ""},
    }


def _resolve_endpoint_to_core(mac: str, site_id: str | None, fresh: bool) -> dict[str, Any] | None:
    try:
        found = search_detective(display_mac(mac), site_id=site_id)
    except Exception:
        return None
    candidates = [
        x
        for x in found.get("results") or []
        if clean_mac(x.get("mac")) == mac
        and x.get("kind") in {"wired_client", "wireless_client", "nac_client", "infrastructure"}
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda x: (1 if x.get("kind") in {"wired_client", "wireless_client"} else 0, int(x.get("score") or 0)),
        reverse=True,
    )
    chosen = candidates[0]
    try:
        return detective_detail(
            str(chosen.get("kind")), mac, site_id=str(chosen.get("site_id") or site_id or "") or None, fresh=fresh
        )
    except Exception:
        return None


def _field_values(detail: dict[str, Any], intel: dict[str, Any]) -> dict[str, Any]:
    """Resolve provider observations into the vendor-neutral Device Finder field model.

    Provider identities and conflicts intentionally stay inside this backend step.  The
    browser receives only resolved values, while the correlation engine remains ready
    for future providers and explicit authority/freshness rules.
    """
    identity = detail.get("identity") if isinstance(detail.get("identity"), dict) else {}
    connection = detail.get("connection") if isinstance(detail.get("connection"), dict) else {}
    auth = detail.get("authentication") if isinstance(detail.get("authentication"), dict) else {}
    device = detail.get("device") if isinstance(detail.get("device"), dict) else {}
    port = detail.get("port") if isinstance(detail.get("port"), dict) else {}

    switch_member = port.get("node") or port.get("member") or ""
    if not switch_member:
        port_id = str(connection.get("port_id") or "")
        if port_id.startswith(("ge-", "xe-", "et-")) and "/" in port_id:
            try:
                switch_member = str(int(port_id.split("-", 1)[1].split("/", 1)[0]))
            except Exception:
                switch_member = ""

    observations: list[Observation] = []

    def add(
        field_id: str,
        value: Any,
        provider_id: str,
        authority: int,
        *,
        observed_at: str = "",
        confidence: float | None = None,
    ) -> None:
        if value is None or value == "":
            return
        observations.append(
            Observation(
                field_id=field_id,
                value=value,
                provider_id=provider_id,
                authority=authority,
                observed_at=observed_at,
                confidence=confidence,
            )
        )

    mist_seen = str(connection.get("last_seen") or "")
    pa_seen = str(intel.get("last_activity") or "")
    try:
        pa_confidence = float(intel.get("confidence")) if intel.get("confidence") not in (None, "") else None
    except (TypeError, ValueError):
        pa_confidence = None

    # Existing network telemetry is authoritative for physical attachment.
    add("device.hostname", identity.get("hostname"), "mist", 65, observed_at=mist_seen)
    add("device.ip", identity.get("ip") or connection.get("ip"), "mist", 65, observed_at=mist_seen)
    add("device.mac", identity.get("mac"), "mist", 95, observed_at=mist_seen)
    if detail.get("kind") == "infrastructure":
        add("device.model", device.get("model"), "mist", 90, observed_at=mist_seen)
        add("device.serial", device.get("serial"), "mist", 90, observed_at=mist_seen)

    add("network.site", identity.get("site"), "mist", 100, observed_at=mist_seen)
    add("network.connection_type", connection.get("type"), "mist", 100, observed_at=mist_seen)
    add("network.switch", connection.get("switch"), "mist", 100, observed_at=mist_seen)
    add("network.switch_member", switch_member, "mist", 100, observed_at=mist_seen)
    add("network.port", connection.get("port_id"), "mist", 100, observed_at=mist_seen)
    add("network.vlan", connection.get("vlan"), "mist", 100, observed_at=mist_seen)
    add("network.ssid", connection.get("ssid"), "mist", 100, observed_at=mist_seen)
    add("network.ap", connection.get("ap"), "mist", 100, observed_at=mist_seen)
    add("network.band", connection.get("band"), "mist", 100, observed_at=mist_seen)
    add("network.channel", connection.get("channel"), "mist", 100, observed_at=mist_seen)
    add("network.rssi", connection.get("rssi"), "mist", 100, observed_at=mist_seen)
    add("security.last_activity", connection.get("last_seen"), "mist", 55, observed_at=mist_seen)
    add("identity.username", auth.get("username") or identity.get("username"), "mist", 90, observed_at=mist_seen)
    add("identity.auth_method", auth.get("method"), "mist", 90, observed_at=mist_seen)
    add("identity.nac_profile", auth.get("nac_rule"), "mist", 90, observed_at=mist_seen)
    add("identity.nac_state", auth.get("state"), "mist", 90, observed_at=mist_seen)

    # Device Security is preferred for L3 identity/classification/security posture.
    add(
        "device.hostname",
        intel.get("hostname"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add("device.ip", intel.get("ip"), "palo_alto_device_security", 100, observed_at=pa_seen, confidence=pa_confidence)
    add("device.mac", intel.get("mac"), "palo_alto_device_security", 100, observed_at=pa_seen, confidence=pa_confidence)
    add(
        "device.vendor",
        intel.get("vendor"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.model",
        intel.get("model"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.serial",
        intel.get("serial"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.category",
        intel.get("category"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.profile",
        intel.get("profile"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.profile_type",
        intel.get("profile_type"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "device.profile_vertical",
        intel.get("profile_vertical"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add("device.os", intel.get("os"), "palo_alto_device_security", 100, observed_at=pa_seen, confidence=pa_confidence)
    add(
        "device.firmware",
        intel.get("firmware"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )

    # Keep physical VLAN from network telemetry when both exist, but retain the PA
    # observation internally so disagreement can be detected by the correlation layer.
    add(
        "network.vlan",
        intel.get("vlan"),
        "palo_alto_device_security",
        80,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "network.subnet",
        intel.get("subnet"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "network.zone",
        intel.get("zone"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )

    add(
        "security.risk_level",
        intel.get("risk_level"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.confidence",
        intel.get("confidence"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.risk_score",
        intel.get("risk_score"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.endpoint_protection",
        intel.get("endpoint_protection"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.internet_access",
        intel.get("internet_access"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.status",
        intel.get("status"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.critical_alerts",
        intel.get("critical_alerts"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.warning_alerts",
        intel.get("warning_alerts"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.caution_alerts",
        intel.get("caution_alerts"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.info_alerts",
        intel.get("info_alerts"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.first_seen",
        intel.get("first_seen"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "security.last_activity",
        intel.get("last_activity"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )

    add(
        "identity.username",
        intel.get("username"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "identity.domain",
        intel.get("domain"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "identity.auth_method",
        intel.get("auth_method"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "identity.eap_method",
        intel.get("eap_method"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "identity.nac_profile",
        intel.get("nac_profile"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )
    add(
        "identity.nac_state",
        intel.get("nac_state"),
        "palo_alto_device_security",
        100,
        observed_at=pa_seen,
        confidence=pa_confidence,
    )

    return CORRELATION_ENGINE.resolve(observations).values


def unified_detective_detail(kind: str, mac: str, site_id: str | None = None, *, fresh: bool = False) -> dict[str, Any]:
    normalized_mac = clean_mac(mac)
    provider = get_palo_alto_device_security_provider()

    def core_detail() -> dict[str, Any]:
        if kind == "endpoint":
            resolved = _resolve_endpoint_to_core(normalized_mac, site_id, fresh)
            if resolved:
                return resolved
            return _empty_endpoint_detail(normalized_mac, {})
        return detective_detail(kind, normalized_mac, site_id=site_id, fresh=fresh)

    if provider.configured:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_core = pool.submit(core_detail)
            f_intel = pool.submit(_pa_lookup, display_mac(normalized_mac), fresh=fresh)
            detail = f_core.result()
            intel, provider_error = f_intel.result()
    else:
        detail = core_detail()
        intel, provider_error = {}, ""

    if site_id:
        resolved_detail_site = str((detail.get("identity") or {}).get("site_id") or "")
        if resolved_detail_site and resolved_detail_site != str(site_id):
            raise ValueError("Resolved device does not belong to the selected site")

    resolved_fields = _field_values(detail, intel)

    identity = detail.setdefault("identity", {})
    if intel:
        if intel.get("hostname"):
            identity["hostname"] = str(intel["hostname"])
            if not identity.get("title") or clean_mac(identity.get("title")) == normalized_mac:
                identity["title"] = str(intel["hostname"])
        if intel.get("ip"):
            identity["ip"] = str(intel["ip"])
        if intel.get("mac"):
            identity["mac"] = display_mac(intel["mac"])
        if intel.get("username") and not identity.get("username"):
            identity["username"] = str(intel["username"])

    detail["fields"] = resolved_fields
    detail["provider_partial"] = bool(provider_error)
    detail["traffic_sessions_available"] = False
    detail["traffic_sessions"] = []
    # Provider provenance stays inside backend correlation logic; do not surface it
    # as normal Device Finder UI data.
    detail.pop("raw_sources", None)
    return detail


def detective_field_catalog() -> dict[str, Any]:
    fields = public_field_catalog()
    traffic_provider = registry.get("traffic_sessions")
    if not traffic_provider or not bool(getattr(traffic_provider, "configured", False)):
        # Do not advertise controls that cannot return data yet. The traffic fields
        # are already registered internally and will appear automatically once the
        # validated provider is enabled in a later phase.
        fields = [field for field in fields if field.get("group") != "Traffic / Sessions"]
    return {
        "version": 1,
        "fields": fields,
        "presets": ["standard", "network", "security", "identity", "full", "custom"],
    }
