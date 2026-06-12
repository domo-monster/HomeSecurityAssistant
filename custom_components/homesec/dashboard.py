from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
import logging
from aiohttp import web

def _read_version() -> str:
    return _VERSION

try:
    _VERSION: str = json.loads((Path(__file__).parent / "manifest.json").read_text())["version"]
except Exception:
    _VERSION = "?"

from homeassistant.components import panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.core import HomeAssistant

from . import const as _const
from .const import (
    CONF_BASELINE_ENABLED,
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_BLACKLIST_URLS,
    CONF_BASELINE_EGRESS_MULTIPLIER,
    CONF_BASELINE_MIN_OBSERVATIONS,
    CONF_BASELINE_TRAINING_HOURS,
    CONF_DNS_BLOCKED_CATEGORIES,
    CONF_DNS_PROXY_BIND_HOST,
    CONF_DNS_LOG_RETENTION_HOURS,
    CONF_DNS_OVERRIDES,
    CONF_DNS_PROXY_ENABLED,
    CONF_DNS_PROXY_PORT,
    CONF_DNS_PROXY_UPSTREAM,
    CONF_DNS_WARN_BLOCKED_LOGS,
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_NETFLOW_LISTENER,
    CONF_ENABLE_SCANNER,
    CONF_ENRICHMENT_TTL_MINUTES,
    CONF_EXTERNAL_IP_RETENTION,
    CONF_HIGH_EGRESS_THRESHOLD,
    CONF_INTERNAL_NETWORKS,
    CONF_NVD_API_URL,
    CONF_NVD_KEYWORDS,
    CONF_NVD_MIN_YEAR,
    CONF_NVD_TTL_HOURS,
    CONF_RETENTION_MALICIOUS_HOURS,
    CONF_RETENTION_SUSPICIOUS_HOURS,
    CONF_ABUSEIPDB_API_KEY,
    CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_SCAN_EXCEPTIONS,
    CONF_SCAN_INTERVAL,
    CONF_SCAN_PORT_THRESHOLD,
    CONF_SCAN_PORTS,
    CONF_SCAN_WINDOW_SECONDS,
    CONF_STATS_TOP_N,
    CONF_SURICATA_LISTENER_ENABLED,
    CONF_SURICATA_LISTENER_HOST,
    CONF_SURICATA_LISTENER_PORT,
    CONF_SURICATA_LOG_RETENTION_HOURS,
    CONF_VT_ABUSEIPDB_THRESHOLD,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    CONF_WEBUI_REQUIRE_ADMIN,
    DEFAULT_BASELINE_ENABLED,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STATS_TOP_N,
    DEFAULT_WEBUI_REQUIRE_ADMIN,
    DOMAIN,
    get_entry_value,
)
from .storage import (
    load_chart_state,
    load_name_overrides,
    load_role_overrides,
    save_chart_state,
    save_name_overrides,
    save_role_overrides,
)

BUILT_IN_ROLES = (
    "unknown", "camera", "printer", "media_device", "mobile_device",
    "nas_or_desktop", "dns_or_gateway", "linux_host", "web_service", "iot_device",
)

import re as _re
_ROLE_RE = _re.compile(r'^[a-z0-9_]{1,40}$')
_REDACTED_SECRET_VALUE = "********"
_SECRET_SETTINGS_KEYS = {CONF_VIRUSTOTAL_API_KEY, CONF_ABUSEIPDB_API_KEY}

_LOGGER = logging.getLogger(__name__)

# Map each settings key (e.g. "nvd_api_url") to its DEFAULT_* value by
# matching CONF_* and DEFAULT_* symbol pairs from const.py.
SETTINGS_DEFAULTS: dict[str, Any] = {
    conf_value: getattr(_const, f"DEFAULT_{conf_name[5:]}")
    for conf_name, conf_value in vars(_const).items()
    if conf_name.startswith("CONF_")
    and isinstance(conf_value, str)
    and hasattr(_const, f"DEFAULT_{conf_name[5:]}")
}

SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4, "info": 5}

# ── Settings schema (mirrors standalone config.py — used by the Settings UI) ──
SETTINGS_KEYS: tuple[str, ...] = (
    CONF_BIND_HOST, CONF_BIND_PORT, CONF_ENABLE_NETFLOW_LISTENER,
    CONF_INTERNAL_NETWORKS, CONF_SCAN_WINDOW_SECONDS, CONF_SCAN_PORT_THRESHOLD,
    CONF_HIGH_EGRESS_THRESHOLD, CONF_ENABLE_SCANNER, CONF_SCAN_INTERVAL,
    CONF_SCAN_PORTS, CONF_SCAN_EXCEPTIONS, CONF_ENABLE_DNS_RESOLUTION,
    CONF_BLACKLIST_URLS, CONF_DNS_PROXY_ENABLED, CONF_DNS_PROXY_PORT,
    CONF_DNS_PROXY_BIND_HOST,
    CONF_DNS_PROXY_UPSTREAM, CONF_DNS_LOG_RETENTION_HOURS,
    CONF_DNS_WARN_BLOCKED_LOGS, CONF_DNS_BLOCKED_CATEGORIES, CONF_DNS_OVERRIDES,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_ABUSEIPDB_API_KEY, CONF_VT_ABUSEIPDB_THRESHOLD,
    CONF_VIRUSTOTAL_DAILY_BUDGET, CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_ENRICHMENT_TTL_MINUTES, CONF_EXTERNAL_IP_RETENTION,
    CONF_RETENTION_SUSPICIOUS_HOURS, CONF_RETENTION_MALICIOUS_HOURS,
    CONF_BASELINE_ENABLED, CONF_BASELINE_TRAINING_HOURS,
    CONF_BASELINE_MIN_OBSERVATIONS, CONF_BASELINE_EGRESS_MULTIPLIER,
    CONF_NVD_API_URL, CONF_NVD_TTL_HOURS, CONF_NVD_MIN_YEAR, CONF_NVD_KEYWORDS,
    CONF_STATS_TOP_N, CONF_WEBUI_REQUIRE_ADMIN,
    CONF_SURICATA_LISTENER_ENABLED, CONF_SURICATA_LISTENER_HOST,
    CONF_SURICATA_LISTENER_PORT, CONF_SURICATA_LOG_RETENTION_HOURS,
)

SETTINGS_SCHEMA: list[dict[str, Any]] = [
    {
        "section": "Network & NetFlow",
        "fields": [
            {"key": CONF_BIND_HOST, "label": "NetFlow Bind Host", "type": "text", "help": "IP address to bind the NetFlow UDP listener (use 0.0.0.0 for all interfaces)"},
            {"key": CONF_BIND_PORT, "label": "NetFlow Bind Port", "type": "number", "min": 1, "max": 65535, "help": "UDP port for NetFlow v5/v9/IPFIX datagrams (default 2055)"},
            {"key": CONF_ENABLE_NETFLOW_LISTENER, "label": "Enable NetFlow Listener", "type": "boolean", "help": "Enable UDP NetFlow/IPFIX listener and flow ingestion"},
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
            {"key": CONF_ENABLE_SCANNER, "label": "Enable Scanner", "type": "boolean", "help": "Enable periodic active port scanning of internal hosts"},
            {"key": CONF_SCAN_INTERVAL, "label": "Scan Interval (s)", "type": "number", "min": 60, "help": "Seconds between active scan cycles"},
            {"key": CONF_SCAN_PORTS, "label": "Scan Ports", "type": "text", "help": "Ports to scan (ranges and commas allowed, e.g. 22,80,443,8080-8090)"},
            {"key": CONF_SCAN_EXCEPTIONS, "label": "Scan Exceptions", "type": "text", "help": "Comma-separated IPs to exclude from active scanning"},
        ],
    },
    {
        "section": "DNS & Threat Intelligence",
        "fields": [
            {"key": CONF_ENABLE_DNS_RESOLUTION, "label": "Enable DNS Resolution", "type": "boolean", "help": "Resolve hostnames for external IPs and check them against blacklists"},
            {"key": CONF_BLACKLIST_URLS, "label": "Blacklist URLs", "type": "text", "help": "Comma or newline-separated URLs of threat-intel blocklists to download"},
        ],
    },
    {
        "section": "DNS Proxy",
        "fields": [
            {"key": CONF_DNS_PROXY_ENABLED, "label": "Enable DNS Proxy", "type": "boolean", "help": "Run a DNS proxy that logs and optionally blocks queries"},
            {"key": CONF_DNS_PROXY_BIND_HOST, "label": "DNS Proxy Bind Host", "type": "text", "help": "Listener bind address for DNS proxy (recommended: 127.0.0.1 or a specific LAN IP)"},
            {"key": CONF_DNS_PROXY_PORT, "label": "DNS Proxy Port", "type": "number", "min": 1, "max": 65535, "help": "UDP port for the DNS proxy listener (default 53 — requires root/CAP_NET_BIND_SERVICE)"},
            {"key": CONF_DNS_PROXY_UPSTREAM, "label": "Upstream DNS Server", "type": "text", "help": "Upstream DNS resolver IP (e.g. 1.1.1.1)"},
            {"key": CONF_DNS_LOG_RETENTION_HOURS, "label": "DNS Log Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "How many hours to keep DNS query log entries (0 = unlimited)"},
            {"key": CONF_DNS_WARN_BLOCKED_LOGS, "label": "Warn Logs for Blocked Domains", "type": "boolean", "help": "Write warning logs for each blocked DNS query (disabled by default to reduce log noise)"},
            {"key": CONF_DNS_BLOCKED_CATEGORIES, "label": "Blocked DNS Categories", "type": "text", "help": "Comma or newline-separated category names to block (e.g. ads,malware,tracking)"},
            {"key": CONF_DNS_OVERRIDES, "label": "DNS Local Overrides", "type": "text", "help": "Local DNS overrides, one per line: hostname=IP (e.g. myhost.local=192.168.1.5)"},
        ],
    },
    {
        "section": "External IP Enrichment",
        "fields": [
            {"key": CONF_VIRUSTOTAL_API_KEY, "label": "VirusTotal API Key", "type": "password", "help": "Optional VirusTotal API key for external IP reputation lookup"},
            {"key": CONF_ABUSEIPDB_API_KEY, "label": "AbuseIPDB API Key", "type": "password", "help": "Optional AbuseIPDB API key for external IP reputation lookup"},
            {"key": CONF_VT_ABUSEIPDB_THRESHOLD, "label": "Threat Score Threshold (%)", "type": "number", "min": 0, "max": 100, "help": "Minimum abuse confidence score (0-100) to flag an IP as suspicious"},
            {"key": CONF_VIRUSTOTAL_DAILY_BUDGET, "label": "VirusTotal Daily Budget", "type": "number", "min": 0, "help": "Max VirusTotal API lookups per day"},
            {"key": CONF_ABUSEIPDB_DAILY_BUDGET, "label": "AbuseIPDB Daily Budget", "type": "number", "min": 0, "help": "Max AbuseIPDB API lookups per day"},
            {"key": CONF_ENRICHMENT_TTL_MINUTES, "label": "Enrichment Cache TTL (min)", "type": "number", "min": 1, "help": "Minutes before re-querying enrichment APIs for a known IP"},
            {"key": CONF_EXTERNAL_IP_RETENTION, "label": "External IP Retention (h)", "type": "number", "min": 0, "help": "Hours to retain clean external IPs in the dashboard"},
            {"key": CONF_RETENTION_SUSPICIOUS_HOURS, "label": "Suspicious IP Retention (h)", "type": "number", "min": 0, "help": "Hours to retain suspicious IPs"},
            {"key": CONF_RETENTION_MALICIOUS_HOURS, "label": "Malicious IP Retention (h)", "type": "number", "min": 0, "help": "Hours to retain malicious IPs"},
        ],
    },
    {
        "section": "NVD Vulnerability Intelligence",
        "fields": [
            {"key": CONF_NVD_API_URL, "label": "NVD API URL", "type": "text", "help": "NVD CVE API endpoint URL"},
            {"key": CONF_NVD_TTL_HOURS, "label": "NVD Cache TTL (h)", "type": "number", "min": 1, "help": "Hours before refreshing the NVD CVE cache"},
            {"key": CONF_NVD_MIN_YEAR, "label": "CVE Min Year", "type": "number", "min": 1999, "help": "Only show CVEs published on or after this year"},
            {"key": CONF_NVD_KEYWORDS, "label": "NVD Keywords", "type": "text", "help": "Comma-separated product keywords to pre-fetch from NVD (e.g. OpenSSH,nginx,Samba)"},
        ],
    },
    {
        "section": "Baseline & Behaviour Analysis",
        "fields": [
            {"key": CONF_BASELINE_ENABLED, "label": "Enable Baseline", "type": "boolean", "help": "Enable behavioural baseline learning and anomaly detection"},
            {"key": CONF_BASELINE_TRAINING_HOURS, "label": "Training Duration (h)", "type": "number", "min": 1, "max": 168, "help": "Hours of traffic to observe before the baseline is considered trained"},
            {"key": CONF_BASELINE_MIN_OBSERVATIONS, "label": "Min Observations", "type": "number", "min": 1, "max": 50, "help": "Minimum number of flow observations before treating a pattern as normal"},
            {"key": CONF_BASELINE_EGRESS_MULTIPLIER, "label": "Egress Anomaly Multiplier", "type": "number", "min": 1.0, "help": "How many times the baseline egress a device must exceed before it is flagged"},
        ],
    },
    {
        "section": "Display",
        "fields": [
            {"key": CONF_WEBUI_REQUIRE_ADMIN, "label": "Sidebar panel requires admin", "type": "boolean", "help": "When enabled, only Home Assistant admin users can see the Security Assistant sidebar panel"},
            {"key": CONF_STATS_TOP_N, "label": "Statistics Top N", "type": "number", "min": 3, "max": 25, "help": "How many top entries to show in statistics charts"},
        ],
    },
    {
        "section": "Suricata Alert Listener",
        "fields": [
            {"key": CONF_SURICATA_LISTENER_ENABLED, "label": "Enable Suricata Listener", "type": "boolean", "help": "Accept Suricata EVE JSON alerts over TCP from suricata_pusher.py"},
            {"key": CONF_SURICATA_LISTENER_HOST, "label": "Listener Bind Host", "type": "text", "help": "IP address to bind the TCP listener (0.0.0.0 for all interfaces)"},
            {"key": CONF_SURICATA_LISTENER_PORT, "label": "Listener TCP Port", "type": "number", "min": 1, "max": 65535, "help": "TCP port for the Suricata pusher to connect to (default 6343)"},
            {"key": CONF_SURICATA_LOG_RETENTION_HOURS, "label": "Alert Log Retention (h)", "type": "number", "min": 0, "max": 8760, "help": "Hours to keep Suricata alert log entries (0 = unlimited)"},
        ],
    },
]

PANEL_URL_PATH = "homesec"
PANEL_COMPONENT = "homesec-panel"
STATIC_PANEL_URL = "/api/homesec/frontend/homesec-panel.js"
STATIC_PANEL_PATH = Path(__file__).parent / "frontend" / "homesec-panel.js"
STATIC_LOGO_URL = "/api/homesec/frontend/hsa-logo.svg"
STATIC_LOGO_PATH = Path(__file__).parent / "frontend" / "hsa-logo.svg"


async def async_setup_dashboard(hass: HomeAssistant, require_admin: bool = True) -> None:
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data.setdefault("entries", {})
    domain_data.setdefault("panel_registered", False)
    if domain_data["panel_registered"]:
        return

    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                STATIC_PANEL_URL,
                str(STATIC_PANEL_PATH),
                cache_headers=False,
            ),
            StaticPathConfig(
                STATIC_LOGO_URL,
                str(STATIC_LOGO_PATH),
                cache_headers=True,
            ),
        ]
    )
    # Load persisted role overrides
    role_overrides = await hass.async_add_executor_job(
        load_role_overrides, hass.config.config_dir
    )
    name_overrides = await hass.async_add_executor_job(
        load_name_overrides, hass.config.config_dir
    )
    domain_data["role_overrides"] = role_overrides
    domain_data["name_overrides"] = name_overrides

    hass.http.register_view(HomeSecDashboardView())
    hass.http.register_view(HomeSecPanelFallbackView())
    hass.http.register_view(HomeSecLookupView())
    hass.http.register_view(HomeSecDismissFindingView())
    hass.http.register_view(HomeSecDismissByPatternView())
    hass.http.register_view(HomeSecUndismissFindingView())
    hass.http.register_view(HomeSecRoleOverrideView())
    hass.http.register_view(HomeSecNameOverrideView())
    hass.http.register_view(HomeSecVulnBrowserView())
    hass.http.register_view(HomeSecDnsLogView())
    hass.http.register_view(HomeSecClearBlockedDnsView())
    hass.http.register_view(HomeSecSettingsView())
    hass.http.register_view(HomeSecSettingsSaveView())
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name=PANEL_COMPONENT,
        frontend_url_path=PANEL_URL_PATH,
        module_url=STATIC_PANEL_URL,
        sidebar_title="Security Assistant",
        sidebar_icon="mdi:shield-search",
        require_admin=require_admin,
        config={"domain": DOMAIN},
    )
    _LOGGER.info("Security Assistant panel registered at /%s and fallback at /api/homesec/panel", PANEL_URL_PATH)
    domain_data["panel_registered"] = True


def build_dashboard_payload(
    hass: HomeAssistant,
    persisted_chart_state: dict[str, Any] | None = None,
    dns_offset: int = 0,
    dns_limit: int | None = None,
) -> dict[str, Any]:
    domain_data = hass.data.get(DOMAIN, {})
    entries = domain_data.get("entries", {})
    persisted_chart_state = persisted_chart_state or {}

    entry_payloads: list[dict[str, Any]] = []
    all_devices: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    all_dismissed_findings: list[dict[str, Any]] = []
    all_connections: list[dict[str, Any]] = []
    all_external_ips: dict[str, dict[str, Any]] = {}
    all_multicast_ips: dict[str, dict[str, Any]] = {}
    all_versions: set[str] = set()
    all_exporters: set[str] = set()
    all_alive_hosts: list[str] = []
    dropped_datagrams = 0
    total_datagrams = 0
    parsed_datagrams = 0
    data_sets_without_template = 0
    active_templates = 0
    tracker_enriched_devices = 0
    scanned_devices = 0
    vulnerability_count = 0
    total_flows = 0
    last_flow_at: str | None = None
    last_parser_error: str | None = None
    collector_started_at: str | None = None
    nvd_last_updated: str | None = None
    nvd_ttl_hours: int | None = None
    nvd_total_cves: int = 0
    nvd_min_year: int | None = None
    nvd_keywords: list[dict[str, Any]] = []
    kev_total: int = 0
    kev_ttl_hours: int | None = None
    kev_last_updated: str | None = None
    scan_last_at: str | None = None
    scan_duration: float | None = None
    scan_hosts_found: int | None = None
    scan_last_status: str | None = None
    scan_last_targets: int | None = None

    baseline_anomalies: list[dict[str, Any]] = []
    baseline_status: dict[str, Any] = {}
    baseline_graph: dict[str, Any] = {}
    for entry_id, runtime in entries.items():
        coordinator = runtime["coordinator"]
        snapshot = coordinator.data or {}
        dismissed = getattr(coordinator.collector, "_dismissed_findings", {})
        listener = snapshot.get("listener", {})
        payload = {
            "entry_id": entry_id,
            "title": runtime["entry"].title,
            "snapshot": snapshot,
        }
        entry_payloads.append(payload)

        # Recompute at_risk per device using the live dismissed set
        devices_from_snapshot = snapshot.get("devices", [])
        for device in devices_from_snapshot:
            ip = device.get("ip", "")
            device["at_risk"] = any(
                v.get("severity") in ("critical", "high")
                for v in device.get("vulnerabilities", [])
                if f"vuln:{ip}:{v.get('port', 0)}:{v.get('cve_id', '')}" not in dismissed
            )
        all_devices.extend(devices_from_snapshot)

        # Split findings using the live dismissed dict (snapshot may be stale)
        stale_active = snapshot.get("findings", [])
        stale_dismissed = snapshot.get("dismissed_findings", [])
        # Merge both lists and re-partition against the live dismissed dict
        # so that dismiss/undismiss actions are reflected immediately
        # without waiting for the next coordinator refresh.
        combined_findings = list(stale_active) + list(stale_dismissed)
        seen_keys: set[str] = set()
        for f in combined_findings:
            fkey = f.get("key", "")
            if fkey in seen_keys:
                continue
            seen_keys.add(fkey)
            if fkey in dismissed:
                f = dict(f)
                f["dismiss_note"] = dismissed.get(fkey, "")
                all_dismissed_findings.append(f)
            else:
                all_findings.append(f)
        all_connections.extend(snapshot.get("connections", []))
        all_versions.update(listener.get("versions_seen", []))
        all_exporters.update(listener.get("exporters", []))
        all_alive_hosts.extend(snapshot.get("alive_hosts", []))
        for ext_entry in snapshot.get("external_ips", []):
            ip_key = ext_entry.get("ip", "")
            if ip_key and ip_key not in all_external_ips:
                all_external_ips[ip_key] = ext_entry
        for mc_entry in snapshot.get("multicast_ips", []):
            ip_key = mc_entry.get("ip", "")
            if ip_key and ip_key not in all_multicast_ips:
                all_multicast_ips[ip_key] = mc_entry
        dropped_datagrams += int(listener.get("dropped_datagrams", 0) or 0)
        total_datagrams += int(listener.get("total_datagrams", 0) or 0)
        parsed_datagrams += int(listener.get("parsed_datagrams", 0) or 0)
        data_sets_without_template += int(listener.get("data_sets_without_template", 0) or 0)
        active_templates += int(listener.get("active_templates", 0) or 0)
        tracker_enriched_devices += int(snapshot.get("tracker_enriched_devices", 0) or 0)
        scanned_devices += int(snapshot.get("scanned_devices", 0) or 0)
        vulnerability_count += int(snapshot.get("vulnerability_count", 0) or 0)
        total_flows += int(snapshot.get("total_flows", 0) or 0)

        # Collect baseline anomalies if present, excluding dismissed keys
        for anomaly in snapshot.get("baseline_anomalies", []):
            akey = anomaly.get("key", "")
            if not akey or akey not in dismissed:
                baseline_anomalies.append(anomaly)
        # Collect baseline status (last entry wins — single-entry setups)
        if snapshot.get("baseline"):
            baseline_status = snapshot["baseline"]
        # Collect baseline graph (last entry wins — single-entry setups)
        if snapshot.get("baseline_graph"):
            baseline_graph = snapshot["baseline_graph"]

        entry_last_flow = snapshot.get("last_flow_at")
        if isinstance(entry_last_flow, str) and (last_flow_at is None or entry_last_flow > last_flow_at):
            last_flow_at = entry_last_flow

        parser_error = listener.get("last_error")
        if isinstance(parser_error, str) and parser_error:
            last_parser_error = parser_error

        entry_started = snapshot.get("collector_started_at")
        if isinstance(entry_started, str) and entry_started:
            if collector_started_at is None or entry_started < collector_started_at:
                collector_started_at = entry_started

        entry_nvd_ts = snapshot.get("nvd_last_updated")
        if isinstance(entry_nvd_ts, str) and entry_nvd_ts:
            if nvd_last_updated is None or entry_nvd_ts > nvd_last_updated:
                nvd_last_updated = entry_nvd_ts
        entry_nvd_ttl = snapshot.get("nvd_ttl_hours")
        if entry_nvd_ttl is not None:
            nvd_ttl_hours = int(entry_nvd_ttl)
        # Read live NVD stats directly from the collector rather than from
        # the coordinator snapshot — the snapshot may be up to 30 s stale
        # and misses cache updates made by the NVD background loop.
        collector = runtime["collector"]
        nvd_total_cves += collector._nvd_client.total_cached_cves
        # Merge keyword info from the live NVD client (deduplicated by keyword)
        seen_kws = {k["keyword"] for k in nvd_keywords}
        for kw_info in collector._nvd_client.cached_keywords:
            if kw_info["keyword"] not in seen_kws:
                seen_kws.add(kw_info["keyword"])
                nvd_keywords.append(kw_info)
        entry_nvd_min = snapshot.get("nvd_min_year")
        if entry_nvd_min is not None:
            nvd_min_year = int(entry_nvd_min)
        kev_total = max(kev_total, collector._kev_client.total)
        entry_kev_ttl = snapshot.get("kev_ttl_hours")
        if entry_kev_ttl is not None:
            kev_ttl_hours = int(entry_kev_ttl)
        kev_ts = collector._kev_client.fetched_at
        if kev_ts:
            kev_ts_str = kev_ts.isoformat()
            if kev_last_updated is None or kev_ts_str > kev_last_updated:
                kev_last_updated = kev_ts_str
        scanner = collector._scanner
        s_at = scanner.last_scan_at
        if s_at:
            s_at_str = s_at.isoformat()
            if scan_last_at is None or s_at_str > scan_last_at:
                scan_last_at = s_at_str
        if scanner.last_scan_duration is not None:
            scan_duration = scanner.last_scan_duration
        if scanner.last_scan_hosts is not None:
            scan_hosts_found = scanner.last_scan_hosts
        if scanner.last_scan_status is not None:
            scan_last_status = scanner.last_scan_status
        if scanner.last_scan_targets is not None:
            scan_last_targets = scanner.last_scan_targets
        nvd_ts = collector._nvd_last_fetch_at
        if nvd_ts:
            nvd_ts_str = nvd_ts.isoformat()
            if nvd_last_updated is None or nvd_ts_str > nvd_last_updated:
                nvd_last_updated = nvd_ts_str

    # Apply persisted role overrides
    role_overrides = domain_data.get("role_overrides", {})
    name_overrides = domain_data.get("name_overrides", {})
    for device in all_devices:
        ip = device.get("ip", "")
        if ip in role_overrides:
            device["probable_role"] = role_overrides[ip]
            device["confidence"] = "manual"
        if ip in name_overrides:
            device["display_name"] = name_overrides[ip]

    recommendations = _build_recommendations(
        all_devices,
        all_findings,
        dropped_datagrams,
        all_exporters,
        total_datagrams,
        parsed_datagrams,
    )
    connections = sorted(all_connections, key=lambda connection: connection.get("octets", 0), reverse=True)[:120]

    # ── New aggregate statistics ─────────────────────────────────────────
    TOP_N = int(get_entry_value(
        list(entries.values())[0]["entry"], CONF_STATS_TOP_N, DEFAULT_STATS_TOP_N
    )) if entries else DEFAULT_STATS_TOP_N

    # Top public IPs by number of distinct internal sources contacting them
    ext_ip_connection_count: dict[str, int] = {}
    ext_ip_octets: dict[str, int] = {}
    for conn in all_connections:
        if conn.get("target_kind") == "external":
            ip = str(conn.get("target", ""))
            if ip:
                ext_ip_connection_count[ip] = ext_ip_connection_count.get(ip, 0) + int(conn.get("flows", 1))
                ext_ip_octets[ip] = ext_ip_octets.get(ip, 0) + int(conn.get("octets", 0) or 0)
    top_public_ips: list[dict[str, Any]] = []
    for ip, flow_count in sorted(ext_ip_connection_count.items(), key=lambda kv: kv[1], reverse=True)[:TOP_N]:
        ext_info = all_external_ips.get(ip, {})
        top_public_ips.append({
            "ip": ip,
            "flows": flow_count,
            "total_octets": ext_ip_octets.get(ip, 0),
            "hostname": ext_info.get("hostname") or "",
            "org": ext_info.get("org") or "",
            "country": ext_info.get("country") or "",
            "country_name": ext_info.get("country_name") or "",
            "blacklisted": ext_info.get("blacklisted", False),
            "rating": ext_info.get("rating") or "",
        })

    # Top countries contacted (by number of external IPs seen from that country)
    country_ip_count: dict[str, dict[str, Any]] = {}
    for ext_entry in all_external_ips.values():
        cc = str(ext_entry.get("country") or "")
        cn = str(ext_entry.get("country_name") or cc)
        if not cc:
            continue
        if cc not in country_ip_count:
            country_ip_count[cc] = {"country": cc, "country_name": cn, "ip_count": 0, "flow_count": 0}
        country_ip_count[cc]["ip_count"] = country_ip_count[cc]["ip_count"] + 1
        country_ip_count[cc]["flow_count"] = country_ip_count[cc]["flow_count"] + ext_ip_connection_count.get(str(ext_entry.get("ip", "")), 0)
    top_countries: list[dict[str, Any]] = sorted(
        country_ip_count.values(), key=lambda c: c["flow_count"], reverse=True
    )[:TOP_N]

    # Top internal talkers by total_octets
    top_internal_talkers: list[dict[str, Any]] = []
    for device in sorted(all_devices, key=lambda d: d.get("total_octets", 0), reverse=True)[:TOP_N]:
        top_internal_talkers.append({
            "ip": device.get("ip", ""),
            "display_name": device.get("display_name") or device.get("hostname") or device.get("ip", ""),
            "probable_role": device.get("probable_role", "unknown"),
            "total_octets": device.get("total_octets", 0),
        })

    # Enrichment budget stats — aggregate across all entries
    enrichment_stats_merged: dict[str, dict[str, Any]] = {}
    for entry_id, runtime in entries.items():
        for stat in runtime["collector"]._enricher.enrichment_stats():
            prov = stat["provider"]
            if prov not in enrichment_stats_merged:
                enrichment_stats_merged[prov] = dict(stat)
            else:
                enrichment_stats_merged[prov]["used"] = enrichment_stats_merged[prov]["used"] + stat["used"]
                # configured = True if any entry has it configured
                enrichment_stats_merged[prov]["configured"] = enrichment_stats_merged[prov]["configured"] or stat["configured"]
                enrichment_stats_merged[prov]["exhausted"] = enrichment_stats_merged[prov]["used"] >= enrichment_stats_merged[prov]["budget"]
    enrichment_stats: list[dict[str, Any]] = list(enrichment_stats_merged.values())

    # Timeseries — merge points from all collectors, deduplicated by timestamp
    timeseries_merged: dict[str, dict[str, Any]] = {}
    for entry_id, runtime in entries.items():
        for pt in runtime["collector"]._timeseries:
            ts_key = str(pt.get("ts", ""))
            if ts_key and ts_key not in timeseries_merged:
                timeseries_merged[ts_key] = pt
    timeseries: list[dict[str, Any]] = sorted(timeseries_merged.values(), key=lambda p: p["ts"])

    # Top suspicious/malicious external IPs — ranked by severity then flow count
    _THREAT_RATINGS = {"malicious": 0, "suspicious": 1}
    threat_candidates: list[dict[str, Any]] = []
    for ext_entry in all_external_ips.values():
        is_blacklisted = ext_entry.get("blacklisted", False)
        rating = str(ext_entry.get("rating") or "")
        if not is_blacklisted and rating not in _THREAT_RATINGS:
            continue
        ip = str(ext_entry.get("ip", ""))
        effective_rating = "malicious" if is_blacklisted else rating
        threat_candidates.append({
            "ip": ip,
            "flows": ext_ip_connection_count.get(ip, 0),
            "total_octets": ext_ip_octets.get(ip, 0),
            "hostname": ext_entry.get("hostname") or "",
            "org": ext_entry.get("org") or "",
            "country": ext_entry.get("country") or "",
            "country_name": ext_entry.get("country_name") or "",
            "blacklisted": bool(is_blacklisted),
            "rating": effective_rating,
            "blacklist_info": ext_entry.get("blacklist_info"),
            "vt_malicious": ext_entry.get("vt_malicious"),
            "abuse_confidence": ext_entry.get("abuse_confidence"),
            "internal_sources": ext_entry.get("internal_sources", []),
        })
    top_threat_ips: list[dict[str, Any]] = sorted(
        threat_candidates,
        key=lambda e: (_THREAT_RATINGS.get(e["rating"], 2), -e["flows"]),
    )[:TOP_N]

    if not all_connections:
        top_public_ips = list(persisted_chart_state.get("top_public_ips", []))[:TOP_N]
        top_countries = list(persisted_chart_state.get("top_countries", []))[:TOP_N]
        top_threat_ips = list(persisted_chart_state.get("top_threat_ips", []))[:TOP_N]
    if not any(int(device.get("total_octets", 0) or 0) > 0 for device in all_devices):
        top_internal_talkers = list(persisted_chart_state.get("top_internal_talkers", []))[:TOP_N]

    external_ips_payload: list[dict[str, Any]] = []
    for ext_entry in sorted(all_external_ips.values(), key=lambda e: e.get("ip", "")):
        ip = str(ext_entry.get("ip", ""))
        octets = ext_ip_octets.get(ip, 0)
        external_ips_payload.append({
            **ext_entry,
            "total_octets": octets,
            "total_kb": round(octets / 1024.0, 1),
        })
    # ─────────────────────────────────────────────────────────────────────

    full_dns_log = _build_dns_log(entries)
    dns_offset = max(0, int(dns_offset))
    if dns_limit is None:
        dns_limit = 0
    else:
        dns_limit = max(0, int(dns_limit))
    dns_log = full_dns_log[dns_offset:] if dns_limit == 0 else full_dns_log[dns_offset:dns_offset + dns_limit]

    return {
        "summary": {
            "entries": len(entries),
            "devices": len(all_devices),
            "findings": len(all_findings),
            "recommendations": len(recommendations),
            "tracker_enriched_devices": tracker_enriched_devices,
            "scanned_devices": scanned_devices,
            "vulnerability_count": vulnerability_count,
            "total_flows": total_flows,
            "versions_seen": sorted(all_versions),
            "exporters": sorted(all_exporters),
            "total_datagrams": total_datagrams,
            "parsed_datagrams": parsed_datagrams,
            "dropped_datagrams": dropped_datagrams,
            "data_sets_without_template": data_sets_without_template,
            "active_templates": active_templates,
            "last_parser_error": last_parser_error,
            "last_flow_at": last_flow_at,
            "collector_started_at": collector_started_at,
            "version": _read_version(),
        },
        "role_overrides": domain_data.get("role_overrides", {}),
        "name_overrides": domain_data.get("name_overrides", {}),
        "devices": sorted(all_devices, key=lambda device: device.get("total_octets", 0), reverse=True),
        "findings": sorted(all_findings, key=lambda finding: (SEVERITY_SORT.get(finding.get("severity", ""), 99), -finding.get("count", 0))),
        "baseline_anomalies": sorted(baseline_anomalies, key=lambda finding: (SEVERITY_SORT.get(finding.get("severity", ""), 99), -finding.get("count", 0))),
        "baseline": baseline_status,
        "baseline_graph": baseline_graph,
        "dismissed_findings": sorted(all_dismissed_findings, key=lambda finding: (SEVERITY_SORT.get(finding.get("severity", ""), 99), -finding.get("count", 0))),
        "recommendations": recommendations,
        "connections": connections,
        "external_ips": external_ips_payload,
        "multicast_ips": sorted(all_multicast_ips.values(), key=lambda e: e.get("ip", "")),
        "alive_hosts": sorted(set(all_alive_hosts)),
        "nvd_last_updated": nvd_last_updated,
        "nvd_ttl_hours": nvd_ttl_hours,
        "nvd_total_cves": nvd_total_cves,
        "nvd_min_year": nvd_min_year,
        "nvd_keywords": nvd_keywords,
        "kev_total": kev_total,
        "kev_ttl_hours": kev_ttl_hours,
        "kev_last_updated": kev_last_updated,
        "scan_last_at": scan_last_at,
        "scan_duration": scan_duration,
        "scan_hosts_found": scan_hosts_found,
        "scan_last_status": scan_last_status,
        "scan_last_targets": scan_last_targets,
        "scan_interval": int(get_entry_value(
            list(entries.values())[0]["entry"], CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )) if entries else None,
        "netflow_listener_enabled": bool(get_entry_value(
            list(entries.values())[0]["entry"], CONF_ENABLE_NETFLOW_LISTENER, False
        )) if entries else False,
        "baseline_enabled": bool(get_entry_value(
            list(entries.values())[0]["entry"], CONF_BASELINE_ENABLED, DEFAULT_BASELINE_ENABLED
        )) if entries else False,
        "dns_proxy_enabled": bool(get_entry_value(
            list(entries.values())[0]["entry"], CONF_DNS_PROXY_ENABLED, False
        )) if entries else False,
        "entries": entry_payloads,
        "stats_top_n": TOP_N,
        "top_public_ips": top_public_ips,
        "top_countries": top_countries,
        "top_internal_talkers": top_internal_talkers,
        "top_threat_ips": top_threat_ips,
        "enrichment_stats": enrichment_stats,
        "timeseries": timeseries,
        "dns_log": dns_log,
        "dns_log_total": len(full_dns_log),
        "dns_log_offset": dns_offset,
        "dns_log_limit": dns_limit,
        "dns_proxy_stats": _build_dns_proxy_stats(entries),
        "blacklist_stats": _build_blacklist_stats(entries),
        "suricata_stats": _build_suricata_stats(entries),
        "suricata_log": _build_suricata_log(entries),
    }


def _build_dns_log(entries: dict) -> list[dict[str, Any]]:
    """Merge and sort DNS log entries from all collectors (newest first)."""
    merged: list[dict[str, Any]] = []
    for runtime in entries.values():
        merged.extend(runtime["collector"].dns_log_snapshot())
    merged.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return merged


def _build_blacklist_stats(entries: dict) -> dict[str, Any]:
    """Return live threat-intel stats from the resolver (always fresh, never stale)."""
    for runtime in entries.values():
        resolver = getattr(runtime["collector"], "_resolver", None)
        if resolver is not None:
            return resolver.stats()
    return {"bad_ips": 0, "bad_domains": 0, "last_refresh": None, "sources": 0}


def _build_dns_proxy_stats(entries: dict) -> dict[str, Any]:
    """Return DNS proxy stats from the first collector that has one running."""
    for runtime in entries.values():
        stats = runtime["collector"].dns_proxy_stats()
        if stats.get("running"):
            return stats
    # Return the first available stats (may be running=False) or a default
    for runtime in entries.values():
        return runtime["collector"].dns_proxy_stats()
    return {"running": False}


def _build_suricata_stats(entries: dict) -> dict[str, Any]:
    """Return Suricata listener stats from the first collector that has one running."""
    for runtime in entries.values():
        stats = runtime["collector"].suricata_stats()
        if stats.get("running"):
            return stats
    for runtime in entries.values():
        return runtime["collector"].suricata_stats()
    return {"running": False}


def _build_suricata_log(entries: dict) -> list[dict[str, Any]]:
    """Return merged Suricata alert log across all entries, newest-first."""
    merged: list[dict[str, Any]] = []
    for runtime in entries.values():
        merged.extend(runtime["collector"].suricata_log_snapshot())
    return sorted(merged, key=lambda e: e.get("timestamp", ""), reverse=True)


def _build_recommendations(
    devices: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    dropped_datagrams: int,
    exporters: set[str],
    total_datagrams: int,
    parsed_datagrams: int,
) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []
    finding_categories = {finding.get("category") for finding in findings}
    # Use only alive devices for role/enrichment counts so the numbers match
    # the Hosts table, which also filters to alive=True only.
    alive_devices = [d for d in devices if d.get("alive")]
    unknown_devices = sum(1 for device in alive_devices if device.get("probable_role") == "unknown")
    tracker_enriched = sum(1 for device in alive_devices if device.get("enriched"))
    at_risk_count = sum(1 for device in devices if device.get("at_risk"))

    # ── helpers ──────────────────────────────────────────────────────────
    def _device_ref(d: dict[str, Any]) -> dict[str, Any]:
        """Compact device reference for the detail panel."""
        cves = [
            v.get("cve_id") for v in d.get("vulnerabilities", [])
            if v.get("severity") in ("critical", "high") and v.get("cve_id")
        ]
        return {
            "ip": d.get("ip", ""),
            "name": d.get("display_name") or d.get("hostname") or d.get("ip", ""),
            "role": d.get("probable_role", "unknown"),
            "vuln_count": len(d.get("vulnerabilities", [])),
            "cves": cves[:6],
        }

    def _finding_ref(f: dict[str, Any]) -> dict[str, Any]:
        """Compact finding reference for the detail panel."""
        return {
            "source_ip": f.get("source_ip", ""),
            "summary": f.get("summary", ""),
            "severity": f.get("severity", ""),
            "count": f.get("count", 1),
            "last_seen": f.get("last_seen", ""),
            "detail": f.get("detail") or {},
        }

    if at_risk_count > 0:
        at_risk_refs = [_device_ref(d) for d in devices if d.get("at_risk")]
        recommendations.append(
            {
                "title": "Patch vulnerable devices",
                "priority": "critical",
                "category": "patch_vulnerable",
                "detail": f"{at_risk_count} device(s) have known high or critical CVE vulnerabilities. Update firmware/software or restrict network access immediately.",
                "hosts": at_risk_refs,
                "findings_refs": [],
            }
        )
    if "vulnerability" in finding_categories:
        vuln_findings = [_finding_ref(f) for f in findings if f.get("category") == "vulnerability"]
        recommendations.append(
            {
                "title": "Review vulnerability findings",
                "priority": "high",
                "category": "vulnerability",
                "detail": "Active scanning found services with known security issues. Check the findings tab for CVE details and remediation steps.",
                "hosts": [],
                "findings_refs": vuln_findings,
            }
        )

    if not exporters:
        recommendations.append(
            {
                "title": "Connect a flow exporter",
                "priority": "high",
                "category": "no_exporter",
                "detail": "No NetFlow or IPFIX exporters have been observed yet. Configure your gateway, firewall, or switch to export flows to HomeSec.",
                "hosts": [],
                "findings_refs": [],
            }
        )
    if exporters and total_datagrams == 0:
        recommendations.append(
            {
                "title": "Verify exporter reachability",
                "priority": "high",
                "category": "exporter_unreachable",
                "detail": "Exporters are configured but HomeSec has not received any datagrams yet. Check exporter target IP/port, firewall rules, and container networking.",
                "hosts": [],
                "findings_refs": [],
            }
        )
    if total_datagrams > 0 and parsed_datagrams == 0:
        recommendations.append(
            {
                "title": "Check flow export format",
                "priority": "high",
                "category": "bad_flow_format",
                "detail": "Datagrams are arriving but none produced records. Confirm exporter uses NetFlow v5/v9/IPFIX with IPv4 fields and valid templates.",
                "hosts": [],
                "findings_refs": [],
            }
        )
    if "suspicious_port" in finding_categories:
        sp_findings = [_finding_ref(f) for f in findings if f.get("category") == "suspicious_port"]
        sp_hosts = [_device_ref(d) for d in alive_devices if d.get("ip") in {f["source_ip"] for f in sp_findings}]
        recommendations.append(
            {
                "title": "Restrict risky outbound ports",
                "priority": "high",
                "category": "suspicious_port",
                "detail": "At least one device reached a commonly abused external port such as Telnet or RDP. Block or alert on these ports at the gateway and patch the source device.",
                "hosts": sp_hosts,
                "findings_refs": sp_findings,
            }
        )
    if "port_scan" in finding_categories:
        ps_findings = [_finding_ref(f) for f in findings if f.get("category") == "port_scan"]
        ps_hosts = [_device_ref(d) for d in alive_devices if d.get("ip") in {f["source_ip"] for f in ps_findings}]
        recommendations.append(
            {
                "title": "Isolate scanning hosts",
                "priority": "high",
                "category": "port_scan",
                "detail": "A device is touching many ports in a short time window. Move it to an isolated VLAN or guest network until you confirm the behavior is expected.",
                "hosts": ps_hosts,
                "findings_refs": ps_findings,
            }
        )
    if "high_egress" in finding_categories:
        he_findings = [_finding_ref(f) for f in findings if f.get("category") == "high_egress"]
        he_hosts = [_device_ref(d) for d in alive_devices if d.get("ip") in {f["source_ip"] for f in he_findings}]
        recommendations.append(
            {
                "title": "Review high egress devices",
                "priority": "medium",
                "category": "high_egress",
                "detail": "One or more devices exceeded the outbound data threshold. Confirm whether the traffic matches backups, cameras, or media uploads instead of malware or exfiltration.",
                "hosts": he_hosts,
                "findings_refs": he_findings,
            }
        )
    if unknown_devices > 0:
        unknown_refs = [_device_ref(d) for d in alive_devices if d.get("probable_role") == "unknown"]
        recommendations.append(
            {
                "title": "Improve device identity coverage",
                "priority": "medium",
                "category": "unknown_roles",
                "detail": f"{unknown_devices} devices still have unknown roles. Add router, DHCP, or tracker integrations so HomeSec can correlate names, MAC addresses, and hostnames.",
                "hosts": unknown_refs,
                "findings_refs": [],
            }
        )
    if alive_devices and tracker_enriched == 0:
        unenriched = [_device_ref(d) for d in alive_devices if not d.get("enriched")]
        recommendations.append(
            {
                "title": "Enable device tracker enrichment",
                "priority": "medium",
                "category": "no_tracker",
                "detail": "HomeSec is seeing devices but none were enriched from Home Assistant trackers. Adding router or presence integrations will make the dashboard much more readable.",
                "hosts": unenriched,
                "findings_refs": [],
            }
        )
    if dropped_datagrams > 0:
        recommendations.append(
            {
                "title": "Stabilize exporter templates",
                "priority": "medium",
                "detail": "Some flow datagrams were dropped or arrived before their templates. Reduce exporter restarts or shorten template refresh intervals on the exporter.",
                "category": "dropped_datagrams",
                "hosts": [],
                "findings_refs": [],
            }
        )

    return recommendations[:8]


class HomeSecDashboardView(HomeAssistantView):
    url = "/api/homesec/dashboard"
    name = "api:homesec:dashboard"
    requires_auth = True

    async def get(self, request):
        hass = request.app["hass"]
        entries = hass.data.get(DOMAIN, {}).get("entries", {})
        entry = list(entries.values())[0]["entry"] if entries else None

        try:
            dns_offset = max(0, int(request.query.get("dns_offset", 0)))
        except (TypeError, ValueError):
            dns_offset = 0
        raw_dns_limit = request.query.get("dns_limit")
        if raw_dns_limit is None or raw_dns_limit == "":
            dns_limit = 0
        else:
            try:
                dns_limit = max(0, int(raw_dns_limit))
            except (TypeError, ValueError):
                dns_limit = 0

        persisted_chart_state = await hass.async_add_executor_job(
            load_chart_state, hass.config.config_dir
        )
        payload = build_dashboard_payload(
            hass,
            persisted_chart_state,
            dns_offset=dns_offset,
            dns_limit=dns_limit,
        )
        payload["panel_require_admin"] = bool(
            get_entry_value(entry, CONF_WEBUI_REQUIRE_ADMIN, DEFAULT_WEBUI_REQUIRE_ADMIN)
        ) if entry is not None else DEFAULT_WEBUI_REQUIRE_ADMIN
        await hass.async_add_executor_job(
            save_chart_state,
            hass.config.config_dir,
            {
                "top_public_ips": payload.get("top_public_ips", []),
                "top_countries": payload.get("top_countries", []),
                "top_internal_talkers": payload.get("top_internal_talkers", []),
                "top_threat_ips": payload.get("top_threat_ips", []),
            },
        )
        return self.json(payload)


class HomeSecPanelFallbackView(HomeAssistantView):
    url = "/api/homesec/panel"
    name = "api:homesec:panel"
    requires_auth = True

    async def get(self, request):
        html = f"""
<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Home Security Assistant</title>
    <style>
        html, body {{ margin: 0; padding: 0; background: #070b12; min-height: 100%; }}
    </style>
</head>
<body>
    <homesec-panel></homesec-panel>
    <script type=\"module\" src=\"{STATIC_PANEL_URL}\"></script>
</body>
</html>
"""
        return web.Response(text=html, content_type="text/html")


class HomeSecLookupView(HomeAssistantView):
    """On-demand IP enrichment + DNS + blacklist endpoint.

    GET /api/homesec/lookup?ip=1.2.3.4
    Returns enrichment data for the given IP address.
    """

    url = "/api/homesec/lookup"
    name = "api:homesec:lookup"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        ip_param = request.query.get("ip", "").strip()
        if not ip_param:
            return self.json({"error": "missing 'ip' query parameter"}, status_code=400)
        try:
            ipaddress.ip_address(ip_param)
        except ValueError:
            return self.json({"error": "invalid IP address"}, status_code=400)

        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)

        collector = next(iter(entries.values()))["collector"]
        result = await collector.lookup_ip(ip_param)
        return self.json(result)


class HomeSecDismissFindingView(HomeAssistantView):
    """Dismiss a finding by key, with an optional note."""

    url = "/api/homesec/findings/dismiss"
    name = "api:homesec:findings:dismiss"
    requires_auth = True

    async def post(self, request):
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        key = data.get("key")
        if not key:
            return self.json({"error": "Missing key"}, status_code=400)
        note = str(data.get("note") or "")[:500]  # cap note length
        hass = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        for runtime in entries.values():
            collector = getattr(runtime.get("coordinator"), "collector", None)
            if collector:
                collector.dismiss_finding(key, note)
        return self.json({"result": "ok"})


class HomeSecDismissByPatternView(HomeAssistantView):
    """Dismiss all active findings whose summary or key matches a regex pattern."""

    url = "/api/homesec/findings/dismiss_by_pattern"
    name = "api:homesec:findings:dismiss_by_pattern"
    requires_auth = True

    async def post(self, request):
        import re as _re

        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        pattern = str(data.get("pattern") or "").strip()
        if not pattern:
            return self.json({"error": "Missing pattern"}, status_code=400)
        if len(pattern) > 200:
            return self.json({"error": "Pattern too long (max 200 chars)"}, status_code=400)
        note = str(data.get("note") or "")[:500]
        try:
            rx = _re.compile(pattern, _re.IGNORECASE)
        except _re.error as exc:
            return self.json({"error": f"Invalid regex: {exc}"}, status_code=400)
        hass = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        seen_keys: set[str] = set()
        dismissed_count = 0
        for runtime in entries.values():
            coordinator = runtime.get("coordinator")
            collector = getattr(coordinator, "collector", None)
            if not collector or not coordinator:
                continue
            for f in (coordinator.data or {}).get("findings", []):
                key = str(f.get("key") or "")
                summary = str(f.get("summary") or "")
                if not key or key in seen_keys:
                    continue
                if rx.search(key) or rx.search(summary):
                    seen_keys.add(key)
                    collector.dismiss_finding(key, note or f"Regex dismiss: {pattern}")
                    dismissed_count += 1
        return self.json({"result": "ok", "dismissed": dismissed_count})


class HomeSecUndismissFindingView(HomeAssistantView):
    """Restore a previously dismissed finding."""

    url = "/api/homesec/findings/undismiss"
    name = "api:homesec:findings:undismiss"
    requires_auth = True

    async def post(self, request):
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        key = data.get("key")
        if not key:
            return self.json({"error": "Missing key"}, status_code=400)
        hass = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        for runtime in entries.values():
            collector = getattr(runtime.get("coordinator"), "collector", None)
            if collector:
                collector.undismiss_finding(key)
        return self.json({"result": "ok"})


class HomeSecRoleOverrideView(HomeAssistantView):
    """Set or clear a device role override."""

    url = "/api/homesec/device/role"
    name = "api:homesec:device:role"
    requires_auth = True

    async def post(self, request):
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        ip = data.get("ip", "").strip()
        role = data.get("role", "").strip()
        if not ip:
            return self.json({"error": "Missing ip"}, status_code=400)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self.json({"error": "Invalid IP address"}, status_code=400)
        if role and not _ROLE_RE.match(role):
            return self.json({"error": "Role must be 1-40 lowercase letters, digits, or underscores"}, status_code=400)

        hass = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        overrides = domain_data.get("role_overrides", {})
        if role:
            overrides[ip] = role
        else:
            overrides.pop(ip, None)
        domain_data["role_overrides"] = overrides
        await hass.async_add_executor_job(
            save_role_overrides, hass.config.config_dir, overrides
        )
        return self.json({"result": "ok"})


class HomeSecNameOverrideView(HomeAssistantView):
    """Set or clear a device name override."""

    url = "/api/homesec/device/name"
    name = "api:homesec:device:name"
    requires_auth = True

    async def post(self, request):
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        ip = data.get("ip", "").strip()
        custom_name = data.get("name", "").strip()
        if not ip:
            return self.json({"error": "Missing ip"}, status_code=400)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self.json({"error": "Invalid IP address"}, status_code=400)
        if custom_name and len(custom_name) > 64:
            return self.json({"error": "Name too long (max 64 chars)"}, status_code=400)

        hass = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        overrides = domain_data.get("name_overrides", {})
        if custom_name:
            overrides[ip] = custom_name
        else:
            overrides.pop(ip, None)
        domain_data["name_overrides"] = overrides
        await hass.async_add_executor_job(
            save_name_overrides, hass.config.config_dir, overrides
        )
        return self.json({"result": "ok"})


class HomeSecVulnBrowserView(HomeAssistantView):
    """Vulnerability browser API — returns all known CVEs for search/filter."""

    url = "/api/homesec/vulnerabilities"
    name = "api:homesec:vulnerabilities"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"vulnerabilities": [], "total": 0, "kev_matches": 0, "kev_total": 0})

        all_vulns: dict[str, dict] = {}
        kev_client = None

        for runtime in entries.values():
            collector = runtime["collector"]
            nvd_client = collector._nvd_client
            kev = collector._kev_client
            if kev.total > 0:
                kev_client = kev

            # Only include CVEs that actually matched a detected service
            # version via CPE validation — raw NVD keyword-search results
            # are NOT shown because they contain unrelated products.
            for ip, vulns in collector._nvd_results.items():
                for v in vulns:
                    cid = v.get("cve_id", "")
                    if not cid:
                        continue
                    if cid not in all_vulns:
                        # Look up CPE criteria from the NVD cache entry
                        cpe_list: list[str] = []
                        cached = nvd_client.get_cached_cve(cid)
                        if cached:
                            for cfg in cached.get("configurations", []):
                                for node in cfg.get("nodes", []):
                                    for m in node.get("cpeMatch", []):
                                        c = m.get("criteria", "")
                                        if c and c not in cpe_list:
                                            cpe_list.append(c)
                        all_vulns[cid] = {
                            "cve_id": cid,
                            "cvss": v.get("cvss", 0),
                            "severity": v.get("severity", ""),
                            "summary": v.get("summary", ""),
                            "published": v.get("published", ""),
                            "source": "nvd",
                            "in_kev": False,
                            "affected_hosts": [],
                            "ports": [],
                            "services": [],
                            "cpe_criteria": cpe_list,
                        }
                    entry = all_vulns[cid]
                    host_ip = v.get("host_ip", ip)
                    if host_ip and host_ip not in entry["affected_hosts"]:
                        entry["affected_hosts"].append(host_ip)
                    port = v.get("port")
                    if port and port not in entry["ports"]:
                        entry["ports"].append(port)
                    svc = v.get("service", "")
                    if svc and svc not in entry["services"]:
                        entry["services"].append(svc)

            # Static rule findings (include dismissed ones so the browser
            # stays complete — dismissal only hides from the findings view)
            coordinator = runtime["coordinator"]
            snapshot = coordinator.data or {}
            all_rule_findings = list(snapshot.get("findings", [])) + list(snapshot.get("dismissed_findings", []))
            for finding in all_rule_findings:
                if finding.get("category") != "vulnerability":
                    continue
                details = finding.get("details", {})
                cid = details.get("cve_id", "")
                if not cid:
                    continue
                if cid not in all_vulns:
                    all_vulns[cid] = {
                        "cve_id": cid,
                        "cvss": details.get("cvss", 0),
                        "severity": finding.get("severity", ""),
                        "summary": finding.get("summary", ""),
                        "source": "static_rules",
                        "in_kev": False,
                        "affected_hosts": [],
                        "ports": [],
                        "services": [],
                        "cpe_criteria": [],
                    }
                entry = all_vulns[cid]
                host_ip = finding.get("source_ip", "")
                if host_ip and host_ip not in entry["affected_hosts"]:
                    entry["affected_hosts"].append(host_ip)
                port = details.get("port")
                if port and port not in entry["ports"]:
                    entry["ports"].append(port)
                svc = details.get("service", "")
                if svc and svc not in entry["services"]:
                    entry["services"].append(svc)

        # Include ALL cached NVD CVEs (even those not matching a network
        # host) so the vulnerability browser doubles as a keyword-based
        # CVE database rather than duplicating the findings view.
        detected_cves = len(all_vulns)
        for runtime in entries.values():
            nvd_client = runtime["collector"]._nvd_client
            for cve in nvd_client.all_cached_cves:
                cid = cve.get("cve_id", "")
                if not cid or cid in all_vulns:
                    continue
                cpe_list: list[str] = []
                for cfg in cve.get("configurations", []):
                    for node in cfg.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            c = m.get("criteria", "")
                            if c and c not in cpe_list:
                                cpe_list.append(c)
                all_vulns[cid] = {
                    "cve_id": cid,
                    "cvss": cve.get("cvss", 0),
                    "severity": cve.get("severity", ""),
                    "summary": cve.get("summary", ""),
                    "published": cve.get("published", ""),
                    "source": "nvd",
                    "in_kev": False,
                    "affected_hosts": [],
                    "ports": [],
                    "services": [],
                    "cpe_criteria": cpe_list,
                }

        # Cross-reference with CISA KEV
        kev_matches = 0
        if kev_client:
            for cid, entry in all_vulns.items():
                kev_entry = kev_client.lookup(cid)
                if kev_entry:
                    entry["in_kev"] = True
                    entry["kev_vendor"] = kev_entry.get("vendor", "")
                    entry["kev_product"] = kev_entry.get("product", "")
                    entry["kev_name"] = kev_entry.get("name", "")
                    entry["kev_date_added"] = kev_entry.get("date_added", "")
                    entry["kev_action"] = kev_entry.get("action", "")
                    kev_matches += 1

        vuln_list = sorted(
            all_vulns.values(),
            key=lambda v: (-v.get("cvss", 0), v.get("cve_id", "")),
        )
        return self.json({
            "vulnerabilities": vuln_list,
            "total": len(vuln_list),
            "detected_cves": detected_cves,
            "kev_matches": kev_matches,
            "kev_total": kev_client.total if kev_client else 0,
        })


class HomeSecDnsLogView(HomeAssistantView):
    """Return recent DNS proxy query log entries.

    GET /api/homesec/dns/log?limit=200&malicious_only=true
    limit is optional; omit or set to 0 to return all entries.
    """

    url = "/api/homesec/dns/log"
    name = "api:homesec:dns:log"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"entries": [], "total": 0})

        raw_limit = request.query.get("limit")
        if raw_limit is None or raw_limit == "":
            limit = 0
        else:
            try:
                limit = max(0, int(raw_limit))
            except (ValueError, TypeError):
                limit = 0
        malicious_only = request.query.get("malicious_only", "").lower() in ("1", "true", "yes")

        merged: list[dict] = []
        for runtime in entries.values():
            merged.extend(runtime["collector"].dns_log_snapshot())
        merged.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        if malicious_only:
            merged = [e for e in merged if e.get("malicious")]
        if limit > 0:
            merged = merged[:limit]

        return self.json({"entries": merged, "total": len(merged)})


class HomeSecClearBlockedDnsView(HomeAssistantView):
    """Clear all blocked/malicious entries from the DNS log.

    POST /api/homesec/dns/log/clear_blocked
    """

    url = "/api/homesec/dns/log/clear_blocked"
    name = "api:homesec:dns:log:clear_blocked"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"removed": 0})
        total_removed = 0
        for runtime in entries.values():
            collector = runtime.get("collector")
            if collector is not None:
                total_removed += collector.clear_blocked_dns_log()
        return self.json({"removed": total_removed})


class HomeSecSettingsView(HomeAssistantView):
    """Return current integration settings and schema for the Settings UI.

    GET /api/homesec/settings
    Returns the current config entry values and the settings schema so
    the frontend can render an editable form.
    """

    url = "/api/homesec/settings"
    name = "api:homesec:settings"
    requires_auth = True

    @staticmethod
    def _require_admin(request: web.Request) -> web.Response | None:
        user = request.get("hass_user")
        if user is None or not getattr(user, "is_admin", False):
            return web.json_response({"error": "Admin privileges required"}, status=403)
        return None

    async def get(self, request: web.Request) -> web.Response:
        denied = self._require_admin(request)
        if denied is not None:
            return denied
        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)
        entry = next(iter(entries.values()))["entry"]
        config: dict[str, Any] = {}
        for key in SETTINGS_KEYS:
            value = get_entry_value(entry, key, SETTINGS_DEFAULTS.get(key))
            if key in _SECRET_SETTINGS_KEYS:
                config[key] = _REDACTED_SECRET_VALUE if value else ""
            else:
                config[key] = value
        return self.json({"config": config, "schema": SETTINGS_SCHEMA})


class HomeSecSettingsSaveView(HomeAssistantView):
    """Save updated settings via the HA config entry options.

    POST /api/homesec/settings
    Accepts a JSON object with one or more settings keys and merges them
    into the config entry options, then schedules a reload of the entry.
    """

    url = "/api/homesec/settings/save"
    name = "api:homesec:settings:save"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        denied = HomeSecSettingsView._require_admin(request)
        if denied is not None:
            return denied
        try:
            data = await request.json()
        except Exception:
            return self.json({"error": "Invalid or non-JSON request body"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)

        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.get(DOMAIN, {})
        entries = domain_data.get("entries", {})
        if not entries:
            return self.json({"error": "No active Home Security Assistant entry found. Is the integration set up?"}, status_code=404)

        runtime = next(iter(entries.values()))
        entry = runtime["entry"]

        # Merge submitted keys into existing options (only known keys accepted)
        new_options = dict(entry.options)
        for key in SETTINGS_KEYS:
            if key in data:
                if (
                    key in _SECRET_SETTINGS_KEYS
                    and isinstance(data[key], str)
                    and data[key] == _REDACTED_SECRET_VALUE
                ):
                    # Keep existing stored secret when UI posts redacted placeholder.
                    continue
                if data[key] is None:
                    new_options.pop(key, None)
                else:
                    new_options[key] = data[key]

        hass.config_entries.async_update_entry(entry, options=new_options)
        _LOGGER.info("HomeSec settings updated via Settings UI; scheduling reload")
        # Delay reload slightly so the HTTP response is sent before teardown begins
        hass.loop.call_later(0.5, lambda: hass.async_create_task(hass.config_entries.async_reload(entry.entry_id)))
        return self.json({"result": "ok", "restart_required": False})