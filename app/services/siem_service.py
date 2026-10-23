from __future__ import annotations

from app.core.errors import NotConfiguredError
from app.core.version import APP_VERSION

import hashlib
import json
import re
import socket
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener, getproxies, proxy_bypass, urlopen

from app.core.config import AUTOMATION_ROOT, DATA_ROOT, EXPORT_ROOT, get_settings
from app.core.credential_store import delete_secret, load_secret, save_secret
from app.core.file_utils import write_private_text
from app.core.security import redact_sensitive, redact_text, validate_http_url
from app.modules.history.activity import (
    action_phrase,
    device_type_from,
    diff_changes,
    field_rows,
    humanize_type,
    mist_device_url,
    parse_audit_message,
)
from app.services.mist_client import MistApiError, get_mist_client

SIEM_SETTINGS_FILE = AUTOMATION_ROOT / "siem-forwarder.json"
SIEM_STATE_FILE = AUTOMATION_ROOT / "siem-forwarder-state.json"
SPLUNK_CREDENTIAL_TARGET = "NodeWatch:SplunkHecToken"
_FORWARDER_STOP = threading.Event()
_FORWARDER_THREAD: threading.Thread | None = None
_FORWARDER_LOCK = threading.Lock()


def _ts(item: dict):
    return item.get("timestamp") or item.get("last_seen") or item.get("created_time") or item.get("time") or ""


_SEVERITY_MAP = {
    "critical": "critical",
    "major": "critical",
    "minor": "warning",
    "warn": "warning",
    "warning": "warning",
}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


def normalize_severity(value, event_type: str = "") -> str:
    """Mist critical/major/minor/warn/warning/info → critical | warning | info."""
    text = str(value or "").strip().lower()
    if not text:
        return "warning" if "fail" in str(event_type or "").lower() else "info"
    return _SEVERITY_MAP.get(text, "info")


# Keys already shown as headline rows (or meaningless to people) in the event dialog.
_DETAIL_SKIP = {
    "type",
    "type_code",
    "severity",
    "timestamp",
    "message",
    "text",
    "detail",
    "site_id",
    "device_mac",
    "mac",
    "client_mac",
    "before",
    "after",
    "user_agent",
    "admin_name",
    "category",
    "group",
    "device_type",
    "device_name",
}


class _Lookups:
    """Names used to label events: sites, devices and the Mist portal host."""

    def __init__(self, sites: dict | None = None, devices: dict | None = None, api_host: str = "", org_id: str = ""):
        self.sites = sites or {}
        self.devices = devices or {}
        self.api_host = api_host
        self.org_id = org_id

    @classmethod
    def load(cls, client) -> "_Lookups":
        try:
            settings = get_settings()
            api_host, org_id = settings.api_host, settings.org_id
        except Exception:
            api_host, org_id = "", ""
        sites = client.site_name_map() if hasattr(client, "site_name_map") else {}
        devices = client.device_directory() if hasattr(client, "device_directory") else {}
        return cls(sites, devices, api_host, org_id)


def _first_mac(item: dict) -> str:
    mac = item.get("device_mac") or item.get("mac") or ""
    if not mac:
        macs = item.get("macs") or item.get("switches") or item.get("aps") or item.get("gateways")
        if isinstance(macs, list) and macs and isinstance(macs[0], str):
            mac = macs[0]
    return str(mac or "")


def _event(source: str, item: dict, lookups: _Lookups | None = None) -> dict:
    lookups = lookups or _Lookups()
    code = str(item.get("type") or item.get("type_code") or item.get("action") or "")
    severity_raw = str(item.get("severity") or "")
    severity = normalize_severity(severity_raw, code)
    site_id = str(item.get("site_id") or "")
    device_mac = _first_mac(item)
    bare_mac = re.sub(r"[^0-9a-f]", "", device_mac.lower())
    device = lookups.devices.get(str(item.get("device_id") or "")) or lookups.devices.get(bare_mac) or {}
    device_type = device_type_from(code, item.get("device_type") or device.get("type"))
    device_id = str(item.get("device_id") or device.get("id") or "")
    message = redact_text(item.get("message") or item.get("detail") or item.get("text") or item.get("type") or "")
    event_type = code
    title = humanize_type(code)
    admin = ""
    changes: list[dict] = []
    if source == "audit":
        parsed = parse_audit_message(message)
        event_type = " ".join(x for x in (parsed["action"], parsed["object_type"]) if x)[:80]
        admin = str(item.get("admin_name") or item.get("email") or "")
        title = f"{admin or 'An admin'} {action_phrase(parsed)}"
        changes = diff_changes(item.get("before"), item.get("after"))
    hostname = item.get("hostnames")
    device_name = str(
        item.get("device_name")
        or device.get("name")
        or (hostname[0] if isinstance(hostname, list) and hostname and isinstance(hostname[0], str) else "")
        or ""
    )
    ts = _epoch(_ts(item))
    return {
        "timestamp": _ts(item),
        "epoch_ms": int(ts * 1000) if ts else 0,
        "source": source,
        "severity": severity,
        "severity_raw": severity_raw,
        "category": item.get("category") or item.get("group") or source,
        "event_type": event_type,
        "code": code,
        "title": title or humanize_type(source),
        "site_id": site_id,
        "site_name": lookups.sites.get(site_id, "") if site_id else "",
        "device_mac": device_mac,
        "device_name": device_name,
        "device_type": device_type,
        "device_id": device_id,
        "client_mac": item.get("client_mac") or "",
        "admin": admin,
        "message": message,
        "mist_url": mist_device_url(
            lookups.api_host,
            lookups.org_id,
            site_id=site_id,
            device_type=device_type,
            device_id=device_id,
            mac=bare_mac,
        )
        if (device_mac or device_id or site_id)
        else "",
        "details": field_rows(item, skip=_DETAIL_SKIP),
        "changes": changes,
        "raw": redact_sensitive(item),
    }


def build_events(limit: int = 500) -> list[dict]:
    """Build the normalized event stream without serially waiting on each Mist source."""
    c = get_mist_client()
    rows: list[dict] = []
    sources = {
        "alarm": c.search_org_alarms,
        "device_event": c.search_org_device_events,
        "audit": lambda: c.search_audit_logs("1d"),
    }
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="siem-read") as pool:
        futures = {pool.submit(fn): name for name, fn in sources.items()}
        lookups = _Lookups.load(c)
        for future in as_completed(futures):
            name = futures[future]
            try:
                items = future.result()
            except MistApiError:
                items = []
            for item in items:
                if isinstance(item, dict):
                    rows.append(_event(name, item, lookups))
    rows.sort(key=lambda x: x.get("epoch_ms") or 0, reverse=True)
    return rows[: max(1, min(limit, 5000))]


def display_events(limit: int = 200) -> list[dict]:
    """Events for the UI: labelled fields only (the raw provider payload stays server-side)."""
    return [{k: v for k, v in e.items() if k != "raw"} for e in build_events(limit)]


def _cef_header(value) -> str:
    """CEF header fields: escape backslash and pipe only (ArcSight CEF spec)."""
    return str(value or "").replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value) -> str:
    """CEF extension values: escape backslash and '='; newlines become \\n."""
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def _cef_line(e: dict, *, product_version: str = APP_VERSION) -> str:
    sev = {"critical": 9, "warning": 5, "info": 2}[normalize_severity(e.get("severity"), e.get("event_type") or "")]
    return (
        f"CEF:0|Juniper Mist|NodeWatch|{_cef_header(product_version)}|{_cef_header(e.get('event_type') or e.get('source'))}|"
        f"{_cef_header(e.get('category'))}|{sev}|msg={_cef_ext(e.get('message'))} siteId={_cef_ext(e.get('site_id'))} "
        f"deviceMac={_cef_ext(e.get('device_mac'))} clientMac={_cef_ext(e.get('client_mac'))} sourceType={_cef_ext(e.get('source'))}"
    )


def export_events(fmt: str = "jsonl", limit: int = 1000) -> Path:
    events = build_events(limit)
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if fmt == "cef":
        path = EXPORT_ROOT / f"NodeWatch-SIEM-{stamp}.cef"
        write_private_text(path, "\n".join(_cef_line(e) for e in events))
    else:
        path = EXPORT_ROOT / f"NodeWatch-SIEM-{stamp}.jsonl"
        write_private_text(path, "\n".join(json.dumps(e, separators=(",", ":"), default=str) for e in events))
    return path


def _load_json(path: Path, default: dict) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else dict(default)
    except Exception:
        return dict(default)


def _save_json(path: Path, payload: dict) -> None:
    write_private_text(path, json.dumps(payload, indent=2, default=str))


def _defaults() -> dict:
    return {
        "enabled": False,
        "provider": "splunk_hec",
        "splunk_url": "",
        "splunk_index": "",
        "splunk_sourcetype": "nodewatch:network:events",
        "verify_tls": True,
        "proxy_url": "",
        "syslog_host": "",
        "syslog_port": 514,
        "syslog_protocol": "udp",
        "interval_seconds": 60,
        "batch_limit": 500,
    }


def get_forwarder_config() -> dict:
    cfg = _defaults()
    cfg.update(_load_json(SIEM_SETTINGS_FILE, {}))
    cfg["token_present"] = bool(load_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET))
    state = _load_json(SIEM_STATE_FILE, {})
    cfg["status"] = {
        "last_attempt": state.get("last_attempt"),
        "last_success": state.get("last_success"),
        "last_error": state.get("last_error"),
        "last_sent": state.get("last_sent", 0),
        "total_sent": state.get("total_sent", 0),
    }
    return cfg


def save_forwarder_config(payload: dict) -> dict:
    cfg = _defaults()
    cfg.update(_load_json(SIEM_SETTINGS_FILE, {}))
    for key in cfg:
        if key in payload:
            cfg[key] = payload[key]
    cfg["provider"] = str(cfg.get("provider") or "splunk_hec")
    if cfg["provider"] not in {"splunk_hec", "syslog_cef"}:
        raise ValueError("Provider must be Splunk HEC or CEF syslog")
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["verify_tls"] = bool(cfg.get("verify_tls", True))
    cfg["interval_seconds"] = max(30, min(3600, int(cfg.get("interval_seconds") or 60)))
    cfg["batch_limit"] = max(25, min(2000, int(cfg.get("batch_limit") or 500)))
    cfg["syslog_port"] = max(1, min(65535, int(cfg.get("syslog_port") or 514)))
    cfg["syslog_protocol"] = str(cfg.get("syslog_protocol") or "udp").lower()
    if cfg["syslog_protocol"] not in {"udp", "tcp"}:
        raise ValueError("Syslog protocol must be udp or tcp")
    cfg["splunk_url"] = str(cfg.get("splunk_url") or "").strip().rstrip("/")
    cfg["proxy_url"] = _normalize_proxy_url(cfg.get("proxy_url"))
    cfg["syslog_host"] = str(cfg.get("syslog_host") or "").strip()
    cfg["splunk_index"] = str(cfg.get("splunk_index") or "").strip()
    cfg["splunk_sourcetype"] = str(cfg.get("splunk_sourcetype") or "mist:network:tools").strip()
    secret = str(payload.get("splunk_token") or "").strip()
    existing_secret = load_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET)
    if cfg["provider"] == "splunk_hec" and cfg["splunk_url"]:
        _normalize_splunk_endpoint(cfg["splunk_url"])
    if cfg["enabled"]:
        if cfg["provider"] == "splunk_hec":
            if not cfg["splunk_url"]:
                raise ValueError("Splunk HEC URL is required when auto-forwarding is enabled")
            if not (secret or existing_secret):
                raise ValueError("Splunk HEC token is required when auto-forwarding is enabled")
        if cfg["provider"] == "syslog_cef" and not cfg["syslog_host"]:
            raise ValueError("Syslog host is required when auto-forwarding is enabled")
    if secret:
        save_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET, secret, username="Splunk HEC Token")
    if payload.get("clear_splunk_token"):
        delete_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET)
    _save_json(SIEM_SETTINGS_FILE, cfg)
    _reset_backoff()  # new destination settings: try again on the next cycle
    return get_forwarder_config()


_SPLUNK_CLOUD_DOMAINS = ("splunkcloud.com", "splunkcloudgc.com")
HEC_TIMEOUT_SECONDS = 15
HEC_MAX_POST_BYTES = 512 * 1024


def _cloud_domain(host: str) -> str:
    for domain in _SPLUNK_CLOUD_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return domain
    return ""


def _is_hec_cloud_host(host: str) -> bool:
    """http-inputs-<stack>.splunkcloud.com (AWS/Azure) or http-inputs.<stack>.splunkcloud.com (GCP)."""
    return host.startswith("http-inputs-") or host.startswith("http-inputs.")


def suggest_hec_url(url: str) -> str:
    """Best-guess HEC event endpoint for a Splunk Cloud *web* URL, or "" when not applicable."""
    text = (url or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else "https://" + text)
    host = (parsed.hostname or "").lower()
    domain = _cloud_domain(host)
    if not domain or _is_hec_cloud_host(host) or parsed.port not in (None, 443):
        return ""
    stack = host[: -(len(domain) + 1)] if host != domain else ""
    if not stack:
        return ""
    return f"https://http-inputs-{stack}.{domain}/services/collector/event"


def _normalize_splunk_endpoint(url: str) -> str:
    value = (url or "").strip().rstrip("/")
    if not value:
        raise ValueError("Splunk HEC URL is required")
    if urlparse(value).scheme.lower() == "http":
        # v0.10.22: the HEC token is a bearer secret; plain HTTP would send it in clear text.
        raise ValueError(
            "Splunk HEC must use https://. Plain http:// would send the HEC token and every event unencrypted; "
            "enable SSL on the HEC input (Splunk default) and use https://."
        )
    value = validate_http_url(value, require_https=True)
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if _cloud_domain(host) and not _is_hec_cloud_host(host) and (parsed.port in (None, 443)):
        suggestion = suggest_hec_url(value)
        hint = f" For this stack use {suggestion} (port 443)." if suggestion else ""
        raise ValueError(
            "This is the Splunk Web URL, not the HTTP Event Collector endpoint." + hint + " Splunk Cloud on GCP "
            "uses https://http-inputs.<stack>.splunkcloud.com/services/collector/event instead."
        )
    if "/services/collector/raw" in path.lower():
        raise ValueError(
            "NodeWatch sends JSON event envelopes, which the /services/collector/raw endpoint would store as "
            "plain text. Use /services/collector/event instead."
        )
    if "/services/collector" in path:
        return value
    if path.startswith(("/en-", "/app/", "/account/")) or "/app/" in path:
        raise ValueError(
            "This looks like a Splunk Web page address. Use the HEC endpoint, e.g. "
            "https://<host>:8088/services/collector/event."
        )
    return value + "/services/collector/event"


def _epoch(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        numeric = float(value)
        if numeric > 1e12:
            numeric /= 1000.0
        return numeric
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _hec_envelopes(events: list[dict], cfg: dict) -> list[bytes]:
    out = []
    for event in events:
        envelope = {
            "host": "NodeWatch",
            "source": "nodewatch",
            "sourcetype": cfg.get("splunk_sourcetype") or "mist:network:tools",
            "event": event,
        }
        ts = _epoch(event.get("timestamp"))
        if ts is not None:
            envelope["time"] = ts
        if cfg.get("splunk_index"):
            envelope["index"] = cfg["splunk_index"]
        out.append(json.dumps(envelope, separators=(",", ":"), default=str).encode("utf-8"))
    return out


def _chunk_payloads(lines: list[bytes], max_bytes: int | None = None) -> list[bytes]:
    """Group JSON envelopes into POST bodies of at most ``max_bytes`` (one oversize event goes alone)."""
    max_bytes = max_bytes or HEC_MAX_POST_BYTES
    chunks: list[bytes] = []
    current: list[bytes] = []
    size = 0
    for line in lines:
        if current and size + len(line) > max_bytes:
            chunks.append(b"".join(current))
            current, size = [], 0
        current.append(line)
        size += len(line)
    if current:
        chunks.append(b"".join(current))
    return chunks


def _host_port(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname}:{port}"


def _unreachable(endpoint: str) -> str:
    return (
        f"Could not reach {_host_port(endpoint)} within {HEC_TIMEOUT_SECONDS} s. Click “Diagnose connection” to "
        "see which step fails (DNS, proxy/firewall, TLS, or the Splunk Cloud HEC IP allow list)."
    )


def _normalize_proxy_url(value) -> str:
    """Optional explicit proxy for HEC ("http://proxy.corp:8080"). Credentials are refused (they would be
    stored in plain settings); an authenticating proxy must allow this PC, or use the system proxy."""
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Proxy must look like http://proxy.example.com:8080")
    if parsed.username or parsed.password:
        raise ValueError("Don't put a username/password in the proxy address; NodeWatch stores settings unencrypted")
    if parsed.path not in ("", "/") or parsed.query:
        raise ValueError("Proxy must be just scheme://host:port (a PAC script address can't be used here)")
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 8080)}"


def _windows_proxy_settings() -> dict:
    """Internet Options proxy settings (Windows only): a PAC script or auto-detect is not followed by Python."""
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return {}
    out: dict = {}
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        ) as key:
            for name in ("AutoConfigURL", "ProxyServer", "ProxyEnable", "AutoDetect"):
                try:
                    out[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except OSError:
        return {}
    return out


def _proxy_for(endpoint: str, cfg: dict) -> tuple[str, str]:
    """(proxy URL or "", where it came from) for the HEC endpoint."""
    explicit = str(cfg.get("proxy_url") or "").strip()
    if explicit:
        return explicit, "NodeWatch setting"
    host = urlparse(endpoint).hostname or ""
    proxies = getproxies()
    proxy = proxies.get("https") or proxies.get("all") or ""
    if proxy and not proxy_bypass(host):
        return proxy, "system proxy"
    return "", ""


def _hec_opener(endpoint: str, cfg: dict, context):
    proxy, _source = _proxy_for(endpoint, cfg)
    handlers = [HTTPSHandler(context=context)]
    handlers.insert(0, ProxyHandler({"https": proxy, "http": proxy} if proxy else {}))
    return build_opener(*handlers)


def _post_hec(endpoint: str, body: bytes, token: str, channel: str, context, opener=None) -> None:
    req = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
            "User-Agent": f"NodeWatch/{APP_VERSION}",
            "X-Splunk-Request-Channel": channel,
        },
    )
    try:
        opened = (
            opener.open(req, timeout=HEC_TIMEOUT_SECONDS)
            if opener is not None
            else urlopen(req, timeout=HEC_TIMEOUT_SECONDS, context=context)
        )
        with opened as response:
            text = response.read().decode("utf-8", errors="replace")
            if response.status >= 300:
                raise RuntimeError(f"Splunk HEC returned HTTP {response.status}: {redact_text(text[:300], token)}")
            try:
                result = json.loads(text or "{}")
            except json.JSONDecodeError:
                return
            if isinstance(result, dict) and result.get("code") not in (None, 0):
                raise RuntimeError(f"Splunk HEC rejected the batch: {result.get('text') or result.get('code')}")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict) and parsed.get("text"):
                detail = f"{parsed.get('text')} (code {parsed.get('code')})"
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"Splunk HEC HTTP {exc.code}: {redact_text(detail, token)}") from exc
    except ssl.SSLError as exc:
        raise RuntimeError(
            f"TLS handshake with {_host_port(endpoint)} failed ({exc.reason or exc}). Check the HEC URL/port, "
            "proxy TLS inspection, or the Verify TLS setting."
        ) from exc
    except (TimeoutError, socket.timeout, ConnectionError) as exc:
        raise RuntimeError(_unreachable(endpoint)) from exc
    except URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            raise RuntimeError(
                f"TLS handshake with {_host_port(endpoint)} failed ({reason.reason or reason}). Check the HEC "
                "URL/port, proxy TLS inspection, or the Verify TLS setting."
            ) from exc
        if isinstance(reason, (TimeoutError, socket.timeout, ConnectionError)) or "timed out" in str(reason).lower():
            raise RuntimeError(_unreachable(endpoint)) from exc
        if isinstance(reason, socket.gaierror):
            raise RuntimeError(
                f"Could not resolve {urlparse(endpoint).hostname} — check the HEC hostname and DNS/proxy settings."
            ) from exc
        raise RuntimeError(f"Unable to reach Splunk HEC endpoint {_host_port(endpoint)}: {reason}") from exc


_DIAG_TIMEOUT = 8


def _step(
    steps: list, key: str, label: str, ok: bool | None, detail: str, started: float | None = None, **extra
) -> bool:
    row = {"key": key, "label": label, "ok": ok, "detail": detail}
    if started is not None:
        row["ms"] = round((time.monotonic() - started) * 1000)
    row.update(extra)
    steps.append(row)
    return bool(ok) or ok is None


def _http_over(
    sock, method: str, host: str, path: str, headers: dict | None = None, body: bytes = b""
) -> tuple[int, str]:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"User-Agent: NodeWatch/{APP_VERSION}", "Connection: close"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(body)}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    data = b""
    while len(data) < 65536:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
        if method == "CONNECT" and b"\r\n\r\n" in data:
            break
    head, _, rest = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return status, rest.decode("utf-8", errors="replace")[:600]


SIEM_LAST_DIAGNOSE_FILE = AUTOMATION_ROOT / "siem-last-diagnose.json"


def last_diagnose() -> dict:
    """The most recent "Diagnose connection" result (for Support diagnostics)."""
    return _load_json(SIEM_LAST_DIAGNOSE_FILE, {})


def diagnose_hec(cfg: dict | None = None) -> dict:
    """Run the step-by-step HEC check and remember the result for Support diagnostics."""
    result = _diagnose_hec(cfg)
    try:
        record = {"at": datetime.now(timezone.utc).isoformat(), **result}
        token = load_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET)
        _save_json(SIEM_LAST_DIAGNOSE_FILE, json.loads(redact_text(json.dumps(record, default=str), token or "")))
    except Exception:  # noqa: BLE001 - remembering the result must never break the check
        pass
    return result


def _diagnose_hec(cfg: dict | None = None) -> dict:
    """Step-by-step reachability check for the Splunk HEC endpoint. Read-only: sends no events.

    URL → proxy → DNS → TCP → (proxy CONNECT) → TLS → HEC health → token. Stops at the first failing
    step and explains the likely causes in plain English.
    """
    cfg = cfg or get_forwarder_config()
    steps: list[dict] = []
    result = {"ok": False, "steps": steps, "endpoint": "", "advice": []}
    try:
        endpoint = _normalize_splunk_endpoint(cfg.get("splunk_url") or "")
    except ValueError as exc:
        _step(steps, "url", "HEC URL", False, str(exc))
        return result
    if not endpoint:
        _step(steps, "url", "HEC URL", False, "No Splunk HEC URL is saved yet.")
        return result
    parsed = urlparse(endpoint)
    host, port = parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)
    result["endpoint"] = f"{host}:{port}"
    _step(steps, "url", "HEC URL", True, endpoint.split("?", 1)[0].split("#", 1)[0])  # never echo query-string tokens

    proxy, source = _proxy_for(endpoint, cfg)
    win = _windows_proxy_settings()
    pac = str(win.get("AutoConfigURL") or "")
    if proxy:
        shown = urlparse(proxy)
        shown_text = (
            f"{shown.scheme}://{shown.hostname}{f':{shown.port}' if shown.port else ''}"  # never echo credentials
        )
        _step(steps, "proxy", "Proxy", True, f"Using {shown_text} ({source}).")
    elif pac or win.get("AutoDetect"):
        _step(
            steps,
            "proxy",
            "Proxy",
            None,
            "Windows uses "
            + (f"a proxy script (PAC) {pac}" if pac else "automatic proxy detection")
            + ". Browsers follow it but NodeWatch connects directly. If this PC needs a proxy for the internet, "
            "enter it under Proxy (ask your network team which proxy the script returns for *.splunkcloud.com).",
            pac=pac,
        )
    else:
        _step(steps, "proxy", "Proxy", True, "No proxy configured: connecting directly.")

    target_host, target_port = host, port
    if proxy:
        pp = urlparse(proxy)
        target_host, target_port = pp.hostname or "", pp.port or 8080

    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        _step(steps, "dns", "DNS", True, f"{target_host} → {', '.join(addrs[:4])}", started)
    except socket.gaierror as exc:
        _step(steps, "dns", "DNS", False, f"{target_host} does not resolve ({exc.strerror or exc}).", started)
        result["advice"] = [
            "Check the stack name: Splunk Cloud on AWS uses http-inputs-<stack>.splunkcloud.com, on GCP "
            "http-inputs.<stack>.splunkcloud.com.",
            "If your DNS only resolves internet names through the proxy, set the Proxy field.",
        ]
        return result

    started = time.monotonic()
    try:
        sock = socket.create_connection((target_host, target_port), timeout=_DIAG_TIMEOUT)
    except (TimeoutError, socket.timeout):
        _step(
            steps,
            "tcp",
            "TCP connect",
            False,
            f"No answer from {target_host}:{target_port} within {_DIAG_TIMEOUT} s — the connection is being dropped silently.",
            started,
        )
        result["advice"] = (
            ["The proxy did not answer: check its address/port."]
            if proxy
            else [
                "Most common: this network only reaches the internet through a proxy. Set the Proxy field"
                + (f" (Windows uses the proxy script {pac})." if pac else "."),
                f"A firewall blocks outbound TCP {port} from this PC to {host} — ask the network/firewall team to "
                "allow *.splunkcloud.com on 443.",
                "Splunk Cloud's HEC IP allow list (Admin Config Service feature “hec”) is open to everyone by default, "
                "but once your Splunk admin adds any subnet, only those IPs can send. Ask them to add your site's "
                "public egress IP.",
            ]
        )
        if not proxy:
            _firewall_evidence(steps, result, addrs if "addrs" in locals() else [], target_port, host=host)
        return result
    except OSError as exc:
        _step(
            steps,
            "tcp",
            "TCP connect",
            False,
            f"{target_host}:{target_port} refused or unreachable ({exc.strerror or exc}).",
            started,
        )
        result["advice"] = ["Check the port: Splunk Cloud HEC uses 443, on-prem HEC usually 8088."]
        return result
    _step(steps, "tcp", "TCP connect", True, f"Connected to {target_host}:{target_port}.", started)

    try:
        sock.settimeout(_DIAG_TIMEOUT)
        if proxy:
            started = time.monotonic()
            try:
                status, _body = _http_over(sock, "CONNECT", f"{host}:{port}", f"{host}:{port}")
            except OSError as exc:
                _step(steps, "proxy_connect", "Proxy tunnel", False, f"The proxy stopped answering ({exc}).", started)
                result["advice"] = [
                    "The proxy accepted the connection but did not open the tunnel: check its address/port."
                ]
                return result
            if status != 200:
                why = {
                    407: "the proxy requires authentication, which NodeWatch can't do. Ask the network team to allow "
                    "this PC (or *.splunkcloud.com) without a login.",
                    403: "the proxy blocks this destination. Ask the network team to allow *.splunkcloud.com on 443.",
                }.get(status, "the proxy refused the tunnel.")
                _step(steps, "proxy_connect", "Proxy tunnel", False, f"HTTP {status or '?'}: {why}", started)
                return result
            _step(steps, "proxy_connect", "Proxy tunnel", True, f"Tunnel to {host}:{port} open.", started)

        context = ssl.create_default_context() if cfg.get("verify_tls", True) else ssl._create_unverified_context()  # noqa: SLF001
        if parsed.scheme != "https":
            _step(steps, "tls", "TLS", None, "Plain HTTP endpoint: events travel unencrypted.")
        else:
            started = time.monotonic()
            try:
                tls = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError as exc:
                _step(steps, "tls", "TLS", False, f"Certificate not trusted: {exc.verify_message or exc}.", started)
                result["advice"] = [
                    "A firewall/proxy doing TLS inspection replaces Splunk's certificate. Install the inspection root "
                    "certificate in Windows (Trusted Root Certification Authorities) or ask for *.splunkcloud.com to be "
                    "excluded from inspection.",
                ]
                return result
            except (ssl.SSLError, OSError) as exc:
                _step(steps, "tls", "TLS", False, f"TLS handshake failed ({exc}).", started)
                result["advice"] = [
                    "Something on the path is not speaking TLS on this port (wrong port, or a block page)."
                ]
                return result
            sock = tls
            cert = tls.getpeercert() or {}
            subject = dict(x[0] for x in cert.get("subject", ()) if x)
            issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
            _step(
                steps,
                "tls",
                "TLS",
                True,
                f"{tls.version()} · certificate {subject.get('commonName', '?')} issued by "
                f"{issuer.get('organizationName') or issuer.get('commonName', '?')}",
                started,
            )

        started = time.monotonic()
        try:
            status, body = _http_over(sock, "GET", host, "/services/collector/health")
        except OSError as exc:
            _step(
                steps,
                "health",
                "HEC health",
                False,
                f"Connection dropped while asking HEC for its health ({exc}).",
                started,
            )
            result["advice"] = [
                "Something on the path (firewall, proxy or TLS inspection) cut the connection after it was opened."
            ]
            return result
        healthy = status == 200
        _step(steps, "health", "HEC health", healthy, f"HTTP {status}: {body.strip()[:160] or '(empty)'}", started)
        if not healthy:
            result["advice"] = [
                "HEC answered but is not healthy: 503 usually means HEC is disabled or overloaded; 404 means the URL "
                "is not an HEC endpoint."
            ]
            return result
    finally:
        try:
            sock.close()
        except OSError:
            pass

    token = load_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET)
    if not token:
        _step(steps, "token", "HEC token", False, "No HEC token is saved.")
        return result
    started = time.monotonic()
    try:
        opener = _hec_opener(endpoint, cfg, context)
        req = Request(endpoint, data=b"", method="POST", headers={"Authorization": f"Splunk {token}"})
        try:
            with opener.open(req, timeout=HEC_TIMEOUT_SECONDS) as response:
                code, text = response.status, response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            code, text = exc.code, exc.read().decode("utf-8", errors="replace")
        try:
            hec_code = json.loads(text).get("code")
        except (json.JSONDecodeError, AttributeError):
            hec_code = None
        # An empty POST returns "No data" (code 5) when the token is accepted; 4/1 mean invalid/disabled.
        if hec_code == 5 or code < 300:
            _step(steps, "token", "HEC token", True, "Token accepted (no event was sent).", started)
        else:
            _step(steps, "token", "HEC token", False, f"HTTP {code}: {redact_text(text[:200], token)}", started)
            result["advice"] = ["Check the token is correct and enabled, and that it may write to the chosen index."]
            return result
    except (URLError, OSError) as exc:
        _step(steps, "token", "HEC token", False, f"{exc}", started)
        return result
    result["ok"] = True
    return result


# ---- "Which side is the issue?" (v0.10.24) -------------------------------------------------------------
_DIAG_EVIDENCE_BUDGET_S = 25.0
_CHECKIP_URL = "https://checkip.amazonaws.com"
_INCOMPLETE_END = ("aged-out", "aged_out", "incomplete", "tcp-rst-from-server", "resources-unavailable")
SPLUNK_ALLOWLIST_PATH = "Splunk Cloud › Settings › Server settings › IP allow list › HEC access"


def _local_ip(remote: str, port: int) -> str:
    """This PC's own address on the route to ``remote`` (UDP connect: no packet is sent)."""
    try:
        family = socket.AF_INET6 if ":" in remote else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((remote, port or 443))
            return str(s.getsockname()[0])
    except OSError:
        return ""


def _is_public_ip(value: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _checkip(timeout: float = 5.0) -> str:
    """Best-effort public egress IP from one plain-text HTTPS GET; "" when blocked or not an IP."""
    try:
        req = Request(_CHECKIP_URL, headers={"User-Agent": f"NodeWatch/{APP_VERSION}"})
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:  # noqa: S310 - fixed https URL
            text = resp.read(64).decode("ascii", errors="ignore").strip()
    except Exception:  # noqa: BLE001 - silently skipped (blocked, offline, proxy-only)
        return ""
    return text if _is_public_ip(text) else ""


def _row_bytes_received(row: dict) -> float | None:
    try:
        return float(row.get("bytes_received"))
    except (TypeError, ValueError):
        return None


def _named(row: dict) -> str:
    return f" {row['firewall']}" if row.get("firewall") else ""


def hec_verdict(
    splunk_rows: list[dict], pc_rows: list[dict], *, has_logs: bool, port: int, egress_ip: str = ""
) -> dict:
    """Pure decision: which side blocks the HEC connection, from firewall log rows (vendor-neutral fields).

    ``splunk_rows``: logged sessions from this PC to the HEC addresses; ``pc_rows``: any other logged
    traffic of this PC in the same window. Returns ``{side: splunk|network|unknown, headline, detail,
    rule, firewall, egress_ip}``."""
    egress = egress_ip or ""
    add_ip = f" Add {egress} there." if egress else " Add your site's public egress IP there."
    denied = [r for r in splunk_rows if str(r.get("action") or "").lower() not in ("allow", "")]
    if denied:
        r = denied[0]
        rule = str(r.get("rule") or "?")
        return {
            "side": "network",
            "headline": "Your network",
            "detail": f"Your firewall{_named(r)} blocks it: rule “{rule}” (action {r.get('action')}, "
            f"{r.get('from_zone') or '?'} → {r.get('to_zone') or '?'}). Ask the firewall team to allow this PC to "
            f"*.splunkcloud.com on TCP {port}.",
            "rule": rule,
            "firewall": str(r.get("firewall") or ""),
            "egress_ip": egress,
        }
    if splunk_rows:
        r = splunk_rows[0]
        silent = [
            x
            for x in splunk_rows
            if (_row_bytes_received(x) in (None, 0.0))
            or any(t in str(x.get("session_end_reason") or "").lower() for t in _INCOMPLETE_END)
        ]
        if silent:
            return {
                "side": "splunk",
                "headline": "Splunk Cloud's side",
                "detail": f"Your firewall{_named(r)} let the connection out (rule “{r.get('rule') or '?'}”"
                f"{', as ' + egress if egress else ''}) but Splunk never answered ({len(silent)} of {len(splunk_rows)} "
                f"sessions got no reply). Splunk Cloud's HEC IP allow list most likely does not include your address: "
                f"{SPLUNK_ALLOWLIST_PATH}.{add_ip}",
                "rule": str(r.get("rule") or ""),
                "firewall": str(r.get("firewall") or ""),
                "egress_ip": egress,
            }
        return {
            "side": "unknown",
            "headline": "Can't tell yet",
            "detail": "Your firewall shows Splunk answering on some connections, so the path worked at that time. "
            "Run Diagnose again; if it keeps failing, check the proxy and TLS inspection settings.",
            "rule": str(r.get("rule") or ""),
            "firewall": str(r.get("firewall") or ""),
            "egress_ip": egress,
        }
    if pc_rows:
        fw = sorted({str(x.get("firewall") or "") for x in pc_rows} - {""})
        return {
            "side": "network",
            "headline": "Your network",
            "detail": f"This PC's other traffic passes your firewall{(' ' + ', '.join(fw[:2])) if fw else ''} and is "
            "logged, but nothing to Splunk is: the firewall drops it silently with a rule that does not log - "
            f"typically the default interzone deny, which does not log by default. Ask the firewall team to allow "
            f"this PC to *.splunkcloud.com on TCP {port} (or enable logging on that rule to confirm).",
            "rule": "",
            "firewall": ", ".join(fw[:2]),
            "egress_ip": egress,
        }
    why = (
        "Your firewall logs show no traffic from this PC at all, so it leaves through a path without a logging "
        "firewall - for example an SD-WAN local internet breakout or a VPN."
        if has_logs
        else "No firewall logs are connected, so NodeWatch cannot see where the connection stops."
    )
    return {
        "side": "unknown",
        "headline": "Can't tell yet",
        "detail": f"{why} Two likely causes: (1) a firewall or SD-WAN breakout policy on that path drops TCP {port} "
        f"to Splunk; (2) Splunk Cloud's HEC IP allow list ({SPLUNK_ALLOWLIST_PATH}) does not include "
        f"{egress or 'your public egress IP'}. Test from a network you know is allowlisted, or check the SD-WAN "
        "breakout policy for this site.",
        "rule": "",
        "firewall": "",
        "egress_ip": egress,
    }


def _tcp_ok(host: str, port: int, timeout: float = 6.0) -> bool | None:
    """True when a TCP connection opens, False on timeout / refusal, None when the name does not resolve."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except socket.gaierror:
        return None
    except OSError:
        return False


def _splunk_web_host(hec_host: str) -> str:
    """The same stack's web address: http-inputs-<stack>.splunkcloud.com → <stack>.splunkcloud.com (AWS),
    http-inputs.<stack>.splunkcloud.com → <stack>.splunkcloud.com (GCP); '' when not Splunk Cloud."""
    h = str(hec_host or "").lower()
    if not h.endswith(".splunkcloud.com"):
        return ""
    for prefix in ("http-inputs-", "http-inputs."):
        if h.startswith(prefix):
            return h[len(prefix) :]
    return ""


def _control_verdict(verdict: dict, host: str, port: int, egress: str, egress_from: str, steps: list) -> dict:
    """v0.10.32: when the firewall logs cannot say where the HEC connection stops ("Can't tell yet"), two
    control connections from this PC decide it: the internet in general (the HTTPS lookup of the egress IP,
    else a TCP connect to it) and the same Splunk Cloud stack's web address. A TCP connection that is never
    answered is an address/port block - URL or application filtering on a firewall or SD-WAN edge lets the
    handshake complete and resets later - so when other HTTPS works, only Splunk's addresses stay silent."""
    started = time.monotonic()
    internet = True if egress_from == "checkip.amazonaws.com" else _tcp_ok("checkip.amazonaws.com", 443, 5.0)
    web = _splunk_web_host(host)
    web_ok = _tcp_ok(web, 443, 6.0) if web else None
    bits = [f"internet on TCP 443: {'answers' if internet else 'no answer'}"]
    if web:
        bits.append(f"{web}:443 (your Splunk Cloud web address): {'answers' if web_ok else 'no answer' if web_ok is False else 'does not resolve'}")
    bits.append(f"{host}:{port} (HEC): no answer")
    _step(steps, "control", "Control connections", None, "; ".join(bits) + ".", started)
    ip = egress or "your public egress IP"
    add = (
        f"Ask your Splunk Cloud admin to add {ip}/32 under {SPLUNK_ALLOWLIST_PATH} "
        f"(or with the ACS CLI: acs ip-allowlist create hec --subnets {ip}/32). It takes effect in a few minutes."
    )
    if internet is False:
        return {
            **verdict,
            "side": "network",
            "headline": "Your network",
            "detail": "This PC cannot open any HTTPS connection to the internet directly, not only to Splunk: it needs a "
            "proxy or VPN to get out. Set the Proxy field (ask the network team which proxy this site uses), or run "
            "NodeWatch on a PC with direct internet access.",
        }
    if web_ok:
        return {
            **verdict,
            "side": "splunk",
            "headline": "Splunk Cloud's side",
            "detail": f"From this PC the internet and your Splunk Cloud web address ({web}) both answer on 443, but HEC "
            f"({host}) silently drops every connection. Only HEC is closed to this address, which is exactly what "
            f"Splunk Cloud's HEC IP allow list does when {ip} is not on it. {add}",
        }
    if internet and web_ok is False:
        return {
            **verdict,
            "side": "splunk",
            "headline": "Most likely Splunk Cloud's allow lists",
            "detail": f"Other HTTPS sites answer from this PC, but both Splunk addresses ({web} and {host}) never answer. "
            f"A silent TCP drop of only Splunk's addresses is what Splunk Cloud's IP allow lists do (they restrict "
            f"HEC and the web interface separately): {ip} is probably not on them. {add} If your Splunk admin "
            "confirms it is listed, the remaining cause is an address-based block of Splunk Cloud on this site's "
            "internet path (SD-WAN breakout or upstream firewall).",
        }
    return verdict


def _firewall_evidence(steps: list, result: dict, addrs: list[str], port: int, host: str = "") -> None:
    """Silent drop: answer WHERE using the connected firewall log sources (TRAFFIC_LOGS, any vendor).

    Read-only and bounded (≤ 25 s in total): sessions from this PC to the HEC addresses, this PC's other
    traffic, its public egress IP (NAT source in the logs, else one HTTPS GET to checkip). Sets
    ``result["verdict"]`` and adds the evidence steps."""
    started = time.monotonic()
    local = _local_ip(addrs[0], port) if addrs else ""
    try:
        from app.integrations.connectors import sdk
        from app.integrations.contracts import TRAFFIC_LOGS

        sources = sdk.sources(TRAFFIC_LOGS)
    except Exception:  # noqa: BLE001
        sources = []
    seen: list[dict] = []
    pc_rows: list[dict] = []
    errors: list[str] = []

    def search(ip: str, limit: int) -> list[dict]:
        rows: list[dict] = []
        for src in sources:
            if time.monotonic() - started > _DIAG_EVIDENCE_BUDGET_S - 6:
                break
            try:
                payload = src.search_traffic(ip, window="1h", limit=limit) or {}
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{src.manifest.product}: {type(exc).__name__}")
                continue
            rows.extend(r for r in payload.get("sessions") or [] if isinstance(r, dict))
        return rows

    products = ", ".join(sorted({s.manifest.product for s in sources}))
    if sources:
        for ip in addrs[:3]:
            seen.extend(
                r
                for r in search(ip, 50)
                if str(r.get("destination") or "") == ip and int(r.get("destination_port") or port) == port
            )
        if seen:
            _step(
                steps,
                "firewall",
                "Firewall logs",
                not any(str(r.get("action") or "").lower() not in ("allow", "") for r in seen),
                f"{len(seen)} logged connection(s) from this PC to Splunk ({products}).",
                started,
            )
        else:
            detail = f"The firewall logs ({products}) show no connections to {', '.join(addrs[:3])} in the last hour."
            if errors:
                detail += " (Some log queries failed: " + "; ".join(errors[:3]) + ")"
            _step(steps, "firewall", "Firewall logs", None, detail, started)

        if local:
            step_started = time.monotonic()
            pc_rows = [r for r in search(local, 50) if str(r.get("source") or "") == local]
            if pc_rows:
                fw = sorted({str(r.get("firewall") or "") for r in pc_rows} - {""})
                rules = sorted({str(r.get("rule") or "") for r in pc_rows} - {""})
                nats = sorted({str(r.get("nat_source") or "") for r in pc_rows} - {""})
                _step(
                    steps,
                    "pc_logs",
                    "This PC in the firewall logs",
                    True,
                    f"{len(pc_rows)} other session(s) from {local} in the last hour"
                    + (f" through {', '.join(fw[:2])}" if fw else "")
                    + (f", rule {', '.join(rules[:2])}" if rules else "")
                    + (f", leaving as {', '.join(nats[:2])}" if nats else "")
                    + ".",
                    step_started,
                )
            else:
                _step(
                    steps,
                    "pc_logs",
                    "This PC in the firewall logs",
                    None,
                    f"No traffic from {local} in the firewall logs ({products}) in the last hour.",
                    step_started,
                )
    # Public egress IP: NAT source of this PC's logged traffic, else one plain-text HTTPS lookup.
    nat_candidates = [str(r.get("nat_source") or "") for r in seen + pc_rows]
    egress = next((ip for ip in nat_candidates if _is_public_ip(ip)), "")
    egress_from = "firewall logs (NAT source)" if egress else ""
    remaining = _DIAG_EVIDENCE_BUDGET_S - (time.monotonic() - started)
    if not egress and remaining > 1:
        egress = _checkip(timeout=min(5.0, remaining))
        egress_from = "checkip.amazonaws.com" if egress else ""
    if local or egress:
        _step(
            steps,
            "egress",
            "This PC's addresses",
            None,
            f"LAN address {local or 'unknown'}; public egress IP {egress or 'unknown'}"
            + (f" (from {egress_from})" if egress_from else "")
            + ".",
        )
    verdict = hec_verdict(seen, pc_rows, has_logs=bool(sources), port=port, egress_ip=egress)
    if verdict.get("side") == "unknown" and host:
        verdict = _control_verdict(verdict, host, port, egress, egress_from, steps)
    verdict.update(local_ip=local, egress_from=egress_from)
    result["verdict"] = verdict
    result["advice"] = [verdict["detail"]] + [a for a in result.get("advice") or [] if a != verdict["detail"]]


def _send_splunk(events: list[dict], cfg: dict, on_delivered=None) -> None:
    token = load_secret(DATA_ROOT, SPLUNK_CREDENTIAL_TARGET)
    if not token:
        raise NotConfiguredError("Splunk HEC token is not configured")
    endpoint = _normalize_splunk_endpoint(cfg.get("splunk_url") or "")
    context = ssl.create_default_context() if cfg.get("verify_tls", True) else ssl._create_unverified_context()  # noqa: SLF001
    channel = str(uuid.uuid4())
    opener = _hec_opener(endpoint, cfg, context)
    lines = _hec_envelopes(events, cfg)
    start = 0
    for body in _chunk_payloads(lines):
        # Work out which events this body carries so delivered chunks are recorded even if a later
        # chunk fails (otherwise the next cycle would send them to Splunk a second time).
        size, end = 0, start
        while end < len(lines) and size + len(lines[end]) <= len(body):
            size += len(lines[end])
            end += 1
        _post_hec(endpoint, body, token, channel, context, opener)
        if on_delivered:
            on_delivered(events[start:end])
        start = end


def _send_syslog(events: list[dict], cfg: dict) -> None:
    host = str(cfg.get("syslog_host") or "").strip()
    port = int(cfg.get("syslog_port") or 514)
    protocol = str(cfg.get("syslog_protocol") or "udp").lower()
    if not host:
        raise NotConfiguredError("Syslog destination is not configured")
    lines = [("<134>" + _cef_line(e) + "\n").encode("utf-8", errors="replace") for e in events]
    sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.settimeout(8)
        if protocol == "tcp":
            sock.connect((host, port))
            for line in lines:
                sock.sendall(line)
        else:
            for line in lines:
                sock.sendto(line, (host, port))


def send_events(events: list[dict], cfg: dict | None = None, on_delivered=None) -> None:
    if not events:
        return
    config = cfg or get_forwarder_config()
    if config.get("provider") == "syslog_cef":
        _send_syslog(events, config)
        if on_delivered:
            on_delivered(events)
    else:
        _send_splunk(events, config, on_delivered)


def _event_key(event: dict) -> str:
    # "code" is the provider's own type (stable across releases); event_type is the display form.
    basis = "|".join(
        str(event.get(k if k != "event_type" or "code" not in event else "code") or "")
        for k in ("timestamp", "source", "event_type", "site_id", "device_mac", "client_mac", "message")
    )
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:24]


# Mist search results can surface an event slightly after its own timestamp, so the
# high-water mark keeps a grace window that the dedupe key set still covers.
HIGH_WATER_GRACE_SECONDS = 600


def _high_water(state: dict) -> float:
    value = state.get("last_ts")
    if value in (None, "") and state.get("sent_keys") and state.get("last_success"):
        # Upgrade from a release without last_ts: everything before the last successful
        # cycle was already delivered, so do not resend that backlog.
        value = _epoch(state.get("last_success"))
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def select_fresh_events(events: list[dict], state: dict) -> list[dict]:
    """Oldest-first events not yet delivered (dedupe keys + last_ts high-water mark)."""
    seen = set(state.get("sent_keys") or [])
    floor = _high_water(state) - HIGH_WATER_GRACE_SECONDS
    fresh = []
    for event in reversed(events):
        if _event_key(event) in seen:
            continue
        ts = _epoch(event.get("timestamp"))
        if ts is not None and floor > 0 and ts < floor:
            continue
        fresh.append(event)
    return fresh


def mark_sent(events: list[dict], state: dict) -> None:
    keys = list(state.get("sent_keys") or []) + [_event_key(e) for e in events]
    state["sent_keys"] = keys[-5000:]
    newest = max((t for t in (_epoch(e.get("timestamp")) for e in events) if t is not None), default=None)
    if newest is not None:
        state["last_ts"] = max(_high_water(state), newest)


def forward_once(*, force_sample: bool = False) -> dict:
    with _FORWARDER_LOCK:
        cfg = get_forwarder_config()
        state = _load_json(SIEM_STATE_FILE, {})
        state["last_attempt"] = datetime.now(timezone.utc).isoformat()
        try:
            if force_sample:
                sample = {
                    "timestamp": time.time(),
                    "source": "nodewatch",
                    "severity": "info",
                    "category": "SIEM Forwarder",
                    "event_type": "NODEWATCH_SIEM_TEST",
                    "site_id": "",
                    "device_mac": "",
                    "client_mac": "",
                    "message": "NodeWatch event relay destination test",
                    "raw": {"test": True},
                }
                send_events([sample], cfg)
                sent = 1
            else:
                events = build_events(int(cfg.get("batch_limit") or 500))
                fresh = select_fresh_events(events, state)
                if not fresh:
                    sent = 0
                else:
                    delivered: list[dict] = []

                    def record(batch: list[dict]) -> None:
                        delivered.extend(batch)
                        mark_sent(batch, state)

                    try:
                        send_events(fresh, cfg, on_delivered=record)
                    finally:
                        state["total_sent"] = int(state.get("total_sent") or 0) + len(delivered)
                    sent = len(fresh)
            state["last_success"] = datetime.now(timezone.utc).isoformat()
            state["last_error"] = ""
            state["last_sent"] = sent
            if force_sample:
                state["total_sent"] = int(state.get("total_sent") or 0) + sent
        except Exception as exc:
            state["last_error"] = str(exc)[:1000]
            state["last_sent"] = 0
            _save_json(SIEM_STATE_FILE, state)
            raise
        _save_json(SIEM_STATE_FILE, state)
        return {"ok": True, "sent": sent, "status": get_forwarder_config().get("status")}


# ---- automatic forwarding back-off (v0.10.23) -----------------------------------------------------
# Every cycle builds the full event set (Mist alarms, device events, audit logs and lookups: several
# paged searches) before it sends. With an unreachable destination that was pure waste every 30-60 s
# (field diagnostics: Splunk unreachable for 8 days, alarms + audit-log searches every cycle). Now a
# cheap TCP check runs first, and failures back off exponentially up to 30 minutes. Settings are not
# touched; saving them, or a successful send, resets the back-off.
BACKOFF_MAX_SECONDS = 1800
REACH_TIMEOUT_SECONDS = 5.0
_BACKOFF_LOCK = threading.Lock()
_BACKOFF = {"failures": 0, "next_at": 0.0}


def _reset_backoff() -> None:
    with _BACKOFF_LOCK:
        _BACKOFF["failures"] = 0
        _BACKOFF["next_at"] = 0.0


def _note_failure(interval: int) -> float:
    with _BACKOFF_LOCK:
        _BACKOFF["failures"] += 1
        wait = min(BACKOFF_MAX_SECONDS, max(30, interval) * (2 ** min(_BACKOFF["failures"], 10)))
        _BACKOFF["next_at"] = time.monotonic() + wait
        return wait


def _destination_reachable(cfg: dict) -> str:
    """'' when a TCP connection to the destination (or its proxy) opens, else a short reason.

    Only proves the network path; TLS, token and HEC errors still surface from the real send."""
    if cfg.get("provider") == "syslog_cef":
        if str(cfg.get("syslog_protocol") or "udp").lower() != "tcp":
            return ""  # UDP has nothing to check
        host, port = str(cfg.get("syslog_host") or "").strip(), int(cfg.get("syslog_port") or 514)
    else:
        try:
            endpoint = _normalize_splunk_endpoint(cfg.get("splunk_url") or "")
        except ValueError as exc:
            return str(exc)
        proxy, _source = _proxy_for(endpoint, cfg)
        target = urlparse(proxy if "://" in (proxy or "") else f"http://{proxy}") if proxy else urlparse(endpoint)
        host = target.hostname or ""
        port = target.port or (443 if target.scheme == "https" or not proxy else 8080)
    if not host:
        return "destination is not configured"
    try:
        with socket.create_connection((host, port), timeout=REACH_TIMEOUT_SECONDS):
            return ""
    except OSError as exc:
        return f"cannot reach {host}:{port} ({type(exc).__name__})"


STARTUP_DELAY_SECONDS = 30.0  # v0.10.24: let the first page load before the first forwarding cycle


def _forwarder_loop() -> None:
    _FORWARDER_STOP.wait(STARTUP_DELAY_SECONDS)
    while not _FORWARDER_STOP.is_set():
        cfg = get_forwarder_config()
        interval = int(cfg.get("interval_seconds") or 60)
        with _BACKOFF_LOCK:
            waiting = time.monotonic() < _BACKOFF["next_at"]
        if cfg.get("enabled") and not waiting:
            problem = _destination_reachable(cfg)
            if problem:
                wait = _note_failure(interval)
                try:
                    with _FORWARDER_LOCK:
                        state = _load_json(SIEM_STATE_FILE, {})
                        state["last_attempt"] = datetime.now(timezone.utc).isoformat()
                        state["last_error"] = (
                            f"Destination unreachable: {problem}. No Mist data was read; "
                            f"next automatic try in {int(wait)} s."
                        )
                        state["last_sent"] = 0
                        _save_json(SIEM_STATE_FILE, state)
                except Exception:  # noqa: BLE001
                    pass
            else:
                try:
                    forward_once()
                    _reset_backoff()
                except Exception:
                    _note_failure(interval)
        _FORWARDER_STOP.wait(max(30, interval))


def start_siem_forwarder() -> None:
    global _FORWARDER_THREAD
    if _FORWARDER_THREAD and _FORWARDER_THREAD.is_alive():
        return
    _FORWARDER_STOP.clear()
    _FORWARDER_THREAD = threading.Thread(target=_forwarder_loop, name="mist-siem-forwarder", daemon=True)
    _FORWARDER_THREAD.start()


def stop_siem_forwarder() -> None:
    _FORWARDER_STOP.set()
