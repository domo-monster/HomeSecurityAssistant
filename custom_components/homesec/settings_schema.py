"""Settings schema and validation for the Security Assistant Settings page.

The panel edits the config-entry options through ``POST
/api/homesec/settings/save``.  Every submitted value is validated here
(type, range and format) before it reaches the config entry, so a bad value
can never stop the integration from loading.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any
from urllib.parse import urlparse

from . import const as _const
from .const import (
    CONF_ABUSEIPDB_API_KEY,
    CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_BASELINE_EGRESS_MULTIPLIER,
    CONF_BASELINE_ENABLED,
    CONF_BASELINE_MIN_OBSERVATIONS,
    CONF_BASELINE_TRAINING_HOURS,
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_BLACKLIST_URLS,
    CONF_DNS_BLOCKED_CATEGORIES,
    CONF_DNS_LOG_RETENTION_HOURS,
    CONF_DNS_OVERRIDES,
    CONF_DNS_PROXY_BIND_HOST,
    CONF_DNS_PROXY_ENABLED,
    CONF_DNS_PROXY_PORT,
    CONF_DNS_PROXY_UPSTREAM,
    CONF_DNS_WARN_BLOCKED_LOGS,
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_IP_GEOLOCATION,
    CONF_ENABLE_NETFLOW_LISTENER,
    CONF_ENABLE_SCANNER,
    CONF_ENRICHMENT_TTL_MINUTES,
    CONF_EXTERNAL_IP_RETENTION,
    CONF_HIGH_EGRESS_THRESHOLD,
    CONF_INTERNAL_NETWORKS,
    CONF_NETFLOW_ALLOWED_EXPORTERS,
    CONF_NVD_API_KEY,
    CONF_NVD_API_URL,
    CONF_NVD_KEYWORDS,
    CONF_NVD_MIN_YEAR,
    CONF_NVD_TTL_HOURS,
    CONF_RETENTION_MALICIOUS_HOURS,
    CONF_RETENTION_SUSPICIOUS_HOURS,
    CONF_SCAN_EXCEPTIONS,
    CONF_SCAN_INTERVAL,
    CONF_SCAN_PORT_THRESHOLD,
    CONF_SCAN_PORTS,
    CONF_SCAN_WINDOW_SECONDS,
    CONF_STATS_TOP_N,
    CONF_SURICATA_ALLOWED_SOURCES,
    CONF_SURICATA_AUTH_TOKEN,
    CONF_SURICATA_LISTENER_ENABLED,
    CONF_SURICATA_LISTENER_HOST,
    CONF_SURICATA_LISTENER_PORT,
    CONF_SURICATA_LOG_RETENTION_HOURS,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    CONF_VT_ABUSEIPDB_THRESHOLD,
    CONF_WEBUI_REQUIRE_ADMIN,
)
from .scanner import parse_scan_ports

REDACTED_SECRET_VALUE = "********"
SECRET_SETTINGS_KEYS = frozenset(
    {CONF_VIRUSTOTAL_API_KEY, CONF_ABUSEIPDB_API_KEY, CONF_SURICATA_AUTH_TOKEN, CONF_NVD_API_KEY}
)

# Settings that HomeSecCollector.async_apply_entry_update can change without a
# reload.  Changing anything else reloads the config entry (internal networks
# also feed the DNS proxy ACL, so they need a reload).
IN_PLACE_KEYS = frozenset(
    {
        CONF_BIND_HOST,
        CONF_BIND_PORT,
        CONF_ENABLE_NETFLOW_LISTENER,
        CONF_NETFLOW_ALLOWED_EXPORTERS,
        CONF_ENABLE_SCANNER,
        CONF_DNS_LOG_RETENTION_HOURS,
        CONF_SURICATA_LOG_RETENTION_HOURS,
        CONF_ENABLE_DNS_RESOLUTION,
        CONF_STATS_TOP_N,
    }
)

# Map each settings key (e.g. "nvd_api_url") to its DEFAULT_* value by
# matching CONF_* and DEFAULT_* symbol pairs from const.py.
SETTINGS_DEFAULTS: dict[str, Any] = {
    conf_value: getattr(_const, f"DEFAULT_{conf_name[5:]}")
    for conf_name, conf_value in vars(_const).items()
    if conf_name.startswith("CONF_")
    and isinstance(conf_value, str)
    and hasattr(_const, f"DEFAULT_{conf_name[5:]}")
}

SETTINGS_SCHEMA: list[dict[str, Any]] = [
    {
        "section": "Network & NetFlow",
        "fields": [
            {"key": CONF_BIND_HOST, "label": "NetFlow Bind Host", "type": "text", "help": "IP address to bind the NetFlow UDP listener (use 0.0.0.0 for all interfaces)"},
            {"key": CONF_BIND_PORT, "label": "NetFlow Bind Port", "type": "number", "min": 1, "max": 65535, "help": "UDP port for NetFlow v5/v9/IPFIX datagrams (default 2055)"},
            {"key": CONF_ENABLE_NETFLOW_LISTENER, "label": "Enable NetFlow Listener", "type": "boolean", "help": "Enable UDP NetFlow/IPFIX listener and flow ingestion"},
            {"key": CONF_NETFLOW_ALLOWED_EXPORTERS, "label": "Allowed NetFlow Exporters", "type": "text", "help": "Comma-separated IPs or CIDRs allowed to send flows (e.g. your router). Empty accepts any sender — recommended to set."},
            {"key": CONF_INTERNAL_NETWORKS, "label": "Internal Networks", "type": "text", "help": "Comma-separated CIDR ranges that are considered internal (e.g. 192.168.0.0/16,10.0.0.0/8)"},
        ],
    },
    {
        "section": "Threat Detection",
        "fields": [
            {"key": CONF_SCAN_WINDOW_SECONDS, "label": "Port Scan Window (s)", "type": "number", "min": 10, "max": 3600, "help": "Time window in seconds for port-scan detection"},
            {"key": CONF_SCAN_PORT_THRESHOLD, "label": "Port Scan Threshold", "type": "number", "min": 1, "max": 10000, "help": "Number of distinct ports contacted within the window to trigger a port-scan alert"},
            {"key": CONF_HIGH_EGRESS_THRESHOLD, "label": "High Egress Threshold (bytes)", "type": "number", "min": 100000, "help": "Bytes sent outbound to trigger a high-egress alert"},
        ],
    },
    {
        "section": "Active Scanner",
        "fields": [
            {"key": CONF_ENABLE_SCANNER, "label": "Enable Scanner", "type": "boolean", "help": "Periodically ping, port-scan and banner-grab internal hosts (Home Assistant's own addresses are always skipped). Off by default: scanning can trip other intrusion detection and upset fragile IoT devices."},
            {"key": CONF_SCAN_INTERVAL, "label": "Scan Interval (s)", "type": "number", "min": 60, "max": 604800, "help": "Seconds between active scan cycles"},
            {"key": CONF_SCAN_PORTS, "label": "Scan Ports", "type": "text", "help": "Ports to scan (ranges and commas allowed, e.g. 22,80,443,8080-8090)"},
            {"key": CONF_SCAN_EXCEPTIONS, "label": "Scan Exceptions", "type": "text", "help": "Comma-separated IPs to exclude from active scanning"},
        ],
    },
    {
        "section": "DNS & Threat Intelligence",
        "fields": [
            {"key": CONF_ENABLE_DNS_RESOLUTION, "label": "Enable DNS Resolution", "type": "boolean", "help": "Resolve hostnames for external IPs and check them against blacklists"},
            {"key": CONF_BLACKLIST_URLS, "label": "Blacklist URLs", "type": "text", "help": "Comma or newline-separated HTTPS URLs of threat-intel blocklists to download"},
        ],
    },
    {
        "section": "DNS Proxy",
        "fields": [
            {"key": CONF_DNS_PROXY_ENABLED, "label": "Enable DNS Proxy", "type": "boolean", "help": "Run a DNS proxy that logs and optionally blocks queries"},
            {"key": CONF_DNS_PROXY_BIND_HOST, "label": "DNS Proxy Bind Host", "type": "text", "help": "Listener bind address for DNS proxy (recommended: 127.0.0.1 or a specific LAN IP)"},
            {"key": CONF_DNS_PROXY_PORT, "label": "DNS Proxy Port", "type": "number", "min": 1, "max": 65535, "help": "UDP/TCP port for the DNS proxy listener (default 53 — requires root/CAP_NET_BIND_SERVICE)"},
            {"key": CONF_DNS_PROXY_UPSTREAM, "label": "Upstream DNS Server", "type": "text", "help": "Upstream DNS resolver IP (e.g. 1.1.1.1); several may be comma-separated"},
            {"key": CONF_DNS_LOG_RETENTION_HOURS, "label": "DNS Log Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "How many hours to keep DNS query log entries (0 = until the 10,000-entry cap)"},
            {"key": CONF_DNS_WARN_BLOCKED_LOGS, "label": "Warn Logs for Blocked Domains", "type": "boolean", "help": "Write warning logs for each blocked DNS query (disabled by default to reduce log noise)"},
            {"key": CONF_DNS_BLOCKED_CATEGORIES, "label": "Blocked DNS Categories", "type": "text", "help": "Comma or newline-separated category names to block (e.g. ads,malware,tracking)"},
            {"key": CONF_DNS_OVERRIDES, "label": "DNS Local Overrides", "type": "text", "help": "Local DNS overrides, one per line: hostname=IP (e.g. myhost.local=192.168.1.5)"},
        ],
    },
    {
        "section": "External IP Enrichment",
        "fields": [
            {"key": CONF_ENABLE_IP_GEOLOCATION, "label": "IP Geolocation (ipwho.is)", "type": "boolean", "help": "Look up country and network owner of contacted public IPs at ipwho.is. Off by default: every public IP your devices contact is sent to that third-party service."},
            {"key": CONF_VIRUSTOTAL_API_KEY, "label": "VirusTotal API Key", "type": "password", "help": "Optional VirusTotal API key for external IP reputation lookup"},
            {"key": CONF_ABUSEIPDB_API_KEY, "label": "AbuseIPDB API Key", "type": "password", "help": "Optional AbuseIPDB API key for external IP reputation lookup"},
            {"key": CONF_VT_ABUSEIPDB_THRESHOLD, "label": "Threat Score Threshold (%)", "type": "number", "min": 0, "max": 100, "help": "Minimum abuse confidence score (0-100) to flag an IP as suspicious"},
            {"key": CONF_VIRUSTOTAL_DAILY_BUDGET, "label": "VirusTotal Daily Budget", "type": "number", "min": 0, "max": 1000000, "help": "Max VirusTotal API lookups per day"},
            {"key": CONF_ABUSEIPDB_DAILY_BUDGET, "label": "AbuseIPDB Daily Budget", "type": "number", "min": 0, "max": 1000000, "help": "Max AbuseIPDB API lookups per day"},
            {"key": CONF_ENRICHMENT_TTL_MINUTES, "label": "Enrichment Cache TTL (min)", "type": "number", "min": 1, "max": 525600, "help": "Minutes before re-querying enrichment APIs for a known IP"},
            {"key": CONF_EXTERNAL_IP_RETENTION, "label": "External IP Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "Hours to retain clean external IPs in the dashboard"},
            {"key": CONF_RETENTION_SUSPICIOUS_HOURS, "label": "Suspicious IP Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "Hours to retain suspicious IPs"},
            {"key": CONF_RETENTION_MALICIOUS_HOURS, "label": "Malicious IP Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "Hours to retain malicious IPs"},
        ],
    },
    {
        "section": "NVD Vulnerability Intelligence",
        "fields": [
            {"key": CONF_NVD_API_KEY, "label": "NVD API Key", "type": "password", "help": "Optional free key from nvd.nist.gov/developers/request-an-api-key. Speeds CVE downloads up about 10x (0.6 s instead of 6.5 s between requests)."},
            {"key": CONF_NVD_API_URL, "label": "NVD API URL", "type": "text", "help": "NVD CVE API endpoint URL (HTTPS)"},
            {"key": CONF_NVD_TTL_HOURS, "label": "NVD Cache TTL (h)", "type": "number", "min": 1, "max": 8760, "help": "Hours before refreshing the NVD CVE cache"},
            {"key": CONF_NVD_MIN_YEAR, "label": "CVE Min Year", "type": "number", "min": 1999, "max": 2100, "help": "Only show CVEs published on or after this year"},
            {"key": CONF_NVD_KEYWORDS, "label": "NVD Keywords", "type": "text", "help": "Comma-separated product keywords to pre-fetch from NVD (e.g. OpenSSH,nginx,Samba)"},
        ],
    },
    {
        "section": "Baseline & Behaviour Analysis",
        "fields": [
            {"key": CONF_BASELINE_ENABLED, "label": "Enable Baseline", "type": "boolean", "help": "Enable behavioural baseline learning and anomaly detection"},
            {"key": CONF_BASELINE_TRAINING_HOURS, "label": "Training Duration (h)", "type": "number", "min": 1, "max": 168, "help": "Hours of traffic to observe before the baseline is considered trained"},
            {"key": CONF_BASELINE_MIN_OBSERVATIONS, "label": "Min Observations", "type": "number", "min": 1, "max": 50, "help": "Minimum number of flow observations before treating a pattern as normal"},
            {"key": CONF_BASELINE_EGRESS_MULTIPLIER, "label": "Egress Anomaly Multiplier", "type": "number", "min": 1.0, "max": 100.0, "float": True, "help": "How many times the baseline egress a device must exceed before it is flagged"},
        ],
    },
    {
        "section": "Display",
        "fields": [
            {"key": CONF_WEBUI_REQUIRE_ADMIN, "label": "Sidebar panel requires admin", "type": "boolean", "help": "When enabled, only Home Assistant admin users can see the Security Assistant sidebar panel and read its data. Changing data always requires an admin."},
            {"key": CONF_STATS_TOP_N, "label": "Statistics Top N", "type": "number", "min": 3, "max": 25, "help": "How many top entries to show in statistics charts"},
        ],
    },
    {
        "section": "Suricata Alert Listener",
        "fields": [
            {"key": CONF_SURICATA_LISTENER_ENABLED, "label": "Enable Suricata Listener", "type": "boolean", "help": "Accept Suricata EVE JSON alerts over TCP from suricata_pusher.py"},
            {"key": CONF_SURICATA_LISTENER_HOST, "label": "Listener Bind Host", "type": "text", "help": "IP address to bind the TCP listener (0.0.0.0 for all interfaces)"},
            {"key": CONF_SURICATA_LISTENER_PORT, "label": "Listener TCP Port", "type": "number", "min": 1, "max": 65535, "help": "TCP port for the Suricata pusher to connect to (default 6343)"},
            {"key": CONF_SURICATA_AUTH_TOKEN, "label": "Listener Auth Token", "type": "password", "help": "Shared secret the pusher must send first (suricata_pusher.py --token or HSA_SURICATA_TOKEN). Strongly recommended."},
            {"key": CONF_SURICATA_ALLOWED_SOURCES, "label": "Allowed Pusher Sources", "type": "text", "help": "Comma-separated IPs or CIDRs allowed to connect (e.g. the Suricata host). Empty accepts any source."},
            {"key": CONF_SURICATA_LOG_RETENTION_HOURS, "label": "Alert Log Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "Hours to keep Suricata alert log entries (0 = until the 10,000-entry cap)"},
        ],
    },
]

SETTINGS_FIELDS: dict[str, dict[str, Any]] = {
    field["key"]: field for section in SETTINGS_SCHEMA for field in section["fields"]
}
SETTINGS_KEYS: tuple[str, ...] = tuple(SETTINGS_FIELDS)

_MAX_TEXT = 4096
_MAX_SECRET = 256
_SPLIT_RE = re.compile(r"[\n\r,]+")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$"
)


def _split(raw: str) -> list[str]:
    return [token.strip() for token in _SPLIT_RE.split(raw) if token.strip()]


def _check_ip(raw: str) -> None:
    ipaddress.ip_address(raw.strip())


def _check_network_list(raw: str, *, allow_empty: bool) -> None:
    tokens = _split(raw)
    if not tokens and not allow_empty:
        raise ValueError("at least one network is required")
    for token in tokens:
        ipaddress.ip_network(token, strict=False)


def _check_ip_list(raw: str) -> None:
    for token in _split(raw):
        ipaddress.ip_address(token)


def _check_https_url(raw: str) -> None:
    parsed = urlparse(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"not an https:// URL: {raw.strip()[:80]}")


def _check_url_list(raw: str) -> None:
    for token in _split(raw):
        _check_https_url(token)


def _check_upstreams(raw: str) -> None:
    tokens = _split(raw)
    if not tokens:
        raise ValueError("at least one upstream resolver is required")
    for token in tokens:
        host, port = token, "53"
        if token.startswith("["):
            end = token.find("]")
            if end == -1:
                raise ValueError(f"invalid upstream: {token}")
            host = token[1:end]
            rest = token[end + 1:]
            if rest:
                if not rest.startswith(":"):
                    raise ValueError(f"invalid upstream: {token}")
                port = rest[1:]
            _check_ip(host)
        elif token.count(":") == 1:
            host, port = token.split(":")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f"invalid upstream port: {token}")
        try:
            _check_ip(host)
        except ValueError:
            if not _HOSTNAME_RE.match(host):
                raise ValueError(f"invalid upstream host: {token}") from None


def _check_overrides(raw: str) -> None:
    for line in raw.replace(",", "\n").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain, sep, ip = line.partition("=")
        if not sep or not domain.strip() or not _HOSTNAME_RE.match(domain.strip()):
            raise ValueError(f"expected hostname=IP, got: {line[:80]}")
        _check_ip(ip)


def _check_scan_ports(raw: str) -> None:
    parse_scan_ports(raw)


_TEXT_VALIDATORS = {
    CONF_BIND_HOST: _check_ip,
    CONF_DNS_PROXY_BIND_HOST: _check_ip,
    CONF_SURICATA_LISTENER_HOST: _check_ip,
    CONF_INTERNAL_NETWORKS: lambda raw: _check_network_list(raw, allow_empty=False),
    CONF_NETFLOW_ALLOWED_EXPORTERS: lambda raw: _check_network_list(raw, allow_empty=True),
    CONF_SURICATA_ALLOWED_SOURCES: lambda raw: _check_network_list(raw, allow_empty=True),
    CONF_SCAN_EXCEPTIONS: _check_ip_list,
    CONF_SCAN_PORTS: _check_scan_ports,
    CONF_BLACKLIST_URLS: _check_url_list,
    CONF_NVD_API_URL: _check_https_url,
    CONF_DNS_PROXY_UPSTREAM: _check_upstreams,
    CONF_DNS_OVERRIDES: _check_overrides,
}


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false", "1", "0", "on", "off", "yes", "no"):
        return value.strip().lower() in ("true", "1", "on", "yes")
    raise ValueError("expected true or false")


def _coerce_number(field: dict[str, Any], value: Any) -> int | float:
    if isinstance(value, bool):
        raise ValueError("expected a number")
    if isinstance(value, str):
        value = value.strip()
        if not value:
            raise ValueError("expected a number")
        try:
            value = float(value)
        except ValueError:
            raise ValueError("expected a number") from None
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("expected a number")
    if field.get("float"):
        number: int | float = float(value)
    else:
        if float(value) != int(value):
            raise ValueError("expected a whole number")
        number = int(value)
    if "min" in field and number < field["min"]:
        raise ValueError(f"must be at least {field['min']}")
    if "max" in field and number > field["max"]:
        raise ValueError(f"must be at most {field['max']}")
    return number


def validate_setting(key: str, value: Any) -> Any:
    """Return the normalised value for *key*, or raise ``ValueError``."""
    field = SETTINGS_FIELDS[key]
    kind = field["type"]
    if kind == "boolean":
        return _coerce_bool(value)
    if kind == "number":
        return _coerce_number(field, value)
    if not isinstance(value, str):
        raise ValueError("expected text")
    if kind == "password":
        if len(value) > _MAX_SECRET or any(ord(ch) < 32 for ch in value):
            raise ValueError("invalid secret")
        return value.strip()
    if len(value) > _MAX_TEXT:
        raise ValueError(f"must be at most {_MAX_TEXT} characters")
    value = value.strip()
    validator = _TEXT_VALIDATORS.get(key)
    if validator is not None:
        validator(value)
    return value


def validate_settings(
    data: dict[str, Any], current: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, str]]:
    """Validate a settings submission.

    Returns ``(updates, errors)``.  ``updates`` maps keys to normalised values
    (``None`` means "reset to default").  Unknown keys are ignored.  A secret
    submitted as the redacted placeholder keeps its stored value.
    """
    updates: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key in SETTINGS_KEYS:
        if key not in data:
            continue
        value = data[key]
        if key in SECRET_SETTINGS_KEYS and value == REDACTED_SECRET_VALUE:
            continue
        if value is None:
            updates[key] = None
            continue
        try:
            updates[key] = validate_setting(key, value)
        except ValueError as err:
            errors[key] = str(err) or "invalid value"
    return updates, errors
