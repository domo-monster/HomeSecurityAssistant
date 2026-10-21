from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
import re as _re
from typing import Any

from aiohttp import web
import voluptuous as vol

from homeassistant.components import panel_custom, websocket_api
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect, async_dispatcher_send

from .const import (
    CONF_BASELINE_ENABLED,
    CONF_DNS_PROXY_ENABLED,
    CONF_ENABLE_NETFLOW_LISTENER,
    CONF_SCAN_INTERVAL,
    CONF_STATS_TOP_N,
    CONF_WEBUI_REQUIRE_ADMIN,
    DASHBOARD_LOG_LIMIT,
    DEFAULT_BASELINE_ENABLED,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STATS_TOP_N,
    DEFAULT_WEBUI_REQUIRE_ADMIN,
    DOMAIN,
    SIGNAL_DASHBOARD_UPDATED,
    get_entry_value,
)
from .settings_schema import (
    REDACTED_SECRET_VALUE,
    SECRET_SETTINGS_KEYS,
    SETTINGS_DEFAULTS,
    SETTINGS_KEYS,
    SETTINGS_SCHEMA,
    validate_settings,
)

try:
    _VERSION: str = json.loads((Path(__file__).parent / "manifest.json").read_text())["version"]
except Exception:  # noqa: BLE001
    _VERSION = "?"


def _read_version() -> str:
    return _VERSION


BUILT_IN_ROLES = (
    "unknown", "camera", "printer", "media_device", "mobile_device",
    "nas_or_desktop", "dns_or_gateway", "linux_host", "web_service", "iot_device",
)

_ROLE_RE = _re.compile(r'^[a-z0-9_]{1,40}$')
_MAX_REGEX_LENGTH = 200
# Largest page of log entries one dashboard request may ask for
_MAX_LOG_PAGE = 10_000

_LOGGER = logging.getLogger(__name__)

SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4, "info": 5}

PANEL_URL_PATH = "homesec"
PANEL_COMPONENT = "homesec-panel"
STATIC_FRONTEND_URL = "/api/homesec/frontend"
STATIC_FRONTEND_PATH = Path(__file__).parent / "frontend"
STATIC_PANEL_URL = f"{STATIC_FRONTEND_URL}/homesec-panel.js"
STATIC_PANEL_PATH = STATIC_FRONTEND_PATH / "homesec-panel.js"


def _panel_version() -> str:
    """Short content hash of the panel bundle (cache-busting query parameter)."""
    import hashlib  # noqa: PLC0415

    return hashlib.sha256(STATIC_PANEL_PATH.read_bytes()).hexdigest()[:12]


def _runtimes(hass: HomeAssistant) -> dict[str, dict[str, Any]]:
    """Loaded entries keyed by entry id, as the dicts the payload builders use."""
    from . import loaded_entries  # local import: __init__ imports this module

    return {
        entry.entry_id: {
            "collector": entry.runtime_data.collector,
            "coordinator": entry.runtime_data.coordinator,
            "entry": entry,
            "runtime": entry.runtime_data,
        }
        for entry in loaded_entries(hass)
    }


def _first_runtime(hass: HomeAssistant) -> dict[str, Any] | None:
    return next(iter(_runtimes(hass).values()), None)


def _user_allowed(hass: HomeAssistant, user: Any, *, write: bool) -> bool:
    """Changing state needs an admin; reading too, unless the panel is open to all users."""
    if user is not None and getattr(user, "is_admin", False):
        return True
    if user is None or write:
        return False
    runtime = _first_runtime(hass)
    require_admin = DEFAULT_WEBUI_REQUIRE_ADMIN
    if runtime is not None:
        require_admin = bool(
            get_entry_value(runtime["entry"], CONF_WEBUI_REQUIRE_ADMIN, DEFAULT_WEBUI_REQUIRE_ADMIN)
        )
    return not require_admin


def _access_denied(request: web.Request, *, write: bool) -> web.Response | None:
    """Return a 403 response unless the user may perform this request."""
    if _user_allowed(request.app["hass"], request.get("hass_user"), write=write):
        return None
    return web.json_response({"error": "Admin privileges required"}, status=403)


def _parse_limit(raw: str | None, default: int) -> int:
    """Parse a page-size query parameter (0 = default, capped at _MAX_LOG_PAGE)."""
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        value = default
    if value <= 0:
        value = default
    return min(value, _MAX_LOG_PAGE)


def _parse_offset(raw: str | None) -> int:
    try:
        return max(0, int(raw or 0))
    except (TypeError, ValueError):
        return 0


async def async_setup_dashboard(hass: HomeAssistant, require_admin: bool = True) -> None:
    domain_data = hass.data.setdefault(DOMAIN, {})
    # Static paths and API views can only be registered once per HA run.
    if not domain_data.get("views_registered"):
        # The whole frontend folder (bundle, logo, hashed translation files) is
        # served with long-lived cache headers; the bundle URL carries a
        # content hash so a new version is fetched as soon as it changes.
        await hass.http.async_register_static_paths(
            [StaticPathConfig(STATIC_FRONTEND_URL, str(STATIC_FRONTEND_PATH), cache_headers=True)]
        )
        domain_data["panel_version"] = await hass.async_add_executor_job(_panel_version)
        for view in (
            HomeSecDashboardView(),
            HomeSecPanelFallbackView(),
            HomeSecLookupView(),
            HomeSecDismissFindingView(),
            HomeSecDismissByPatternView(),
            HomeSecUndismissFindingView(),
            HomeSecRoleOverrideView(),
            HomeSecNameOverrideView(),
            HomeSecVulnBrowserView(),
            HomeSecDnsLogView(),
            HomeSecClearBlockedDnsView(),
            HomeSecSettingsView(),
            HomeSecSettingsSaveView(),
        ):
            hass.http.register_view(view)
        websocket_api.async_register_command(hass, ws_subscribe_dashboard)
        websocket_api.async_register_command(hass, ws_refresh_dashboard)
        domain_data["views_registered"] = True

    if domain_data.get("panel_registered"):
        return
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name=PANEL_COMPONENT,
        frontend_url_path=PANEL_URL_PATH,
        module_url=f"{STATIC_PANEL_URL}?v={domain_data.get('panel_version', '0')}",
        sidebar_title="Security Assistant",
        sidebar_icon="mdi:shield-search",
        require_admin=require_admin,
        config={"domain": DOMAIN},
    )
    _LOGGER.debug("Security Assistant panel registered at /%s", PANEL_URL_PATH)
    domain_data["panel_registered"] = True


def build_dashboard_payload(
    hass: HomeAssistant,
    persisted_chart_state: dict[str, Any] | None = None,
    dns_offset: int = 0,
    dns_limit: int | None = None,
    suricata_limit: int | None = None,
) -> dict[str, Any]:
    entries = _runtimes(hass)
    persisted_chart_state = persisted_chart_state or {}

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
    for runtime in entries.values():
        coordinator = runtime["coordinator"]
        snapshot = coordinator.data or {}
        dismissed = getattr(coordinator.collector, "_dismissed_findings", {})
        listener = snapshot.get("listener", {})

        # Recompute at_risk per device using the live dismissed set (on copies:
        # the snapshot is shared with the sensor entities)
        devices_from_snapshot = [dict(device) for device in snapshot.get("devices", [])]
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
    first = next(iter(entries.values()), None)
    role_overrides = first["runtime"].role_overrides if first else {}
    name_overrides = first["runtime"].name_overrides if first else {}
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
    for runtime in entries.values():
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
    for runtime in entries.values():
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
    dns_limit = _parse_limit(str(dns_limit) if dns_limit is not None else None, DASHBOARD_LOG_LIMIT)
    dns_log = full_dns_log[dns_offset:dns_offset + dns_limit]
    full_suricata_log = _build_suricata_log(entries)
    suricata_limit = _parse_limit(
        str(suricata_limit) if suricata_limit is not None else None, DASHBOARD_LOG_LIMIT
    )

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
        "role_overrides": role_overrides,
        "name_overrides": name_overrides,
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
        "suricata_log": full_suricata_log[:suricata_limit],
        **build_log_stats(full_dns_log, full_suricata_log, TOP_N),
        "suricata_log_total": len(full_suricata_log),
    }


def build_log_stats(
    dns_log: list[dict[str, Any]], suricata_log: list[dict[str, Any]], top_n: int
) -> dict[str, Any]:
    """Aggregate the full DNS and Suricata logs for the panel's charts.

    Both logs are newest-first.  Ties keep first-seen order (as the panel's
    own counting did), and a domain's category is taken from its newest entry.
    """
    dns_total = dns_malicious = dns_blocked = 0
    by_category: dict[str, int] = {}
    by_client: dict[str, int] = {}
    by_domain: dict[str, int] = {}
    domain_category: dict[str, str] = {}
    for e in dns_log:
        dns_total += 1
        malicious = bool(e.get("malicious"))
        blocked = e.get("status") == "blocked"
        if malicious:
            dns_malicious += 1
        if blocked:
            dns_blocked += 1
        if not (malicious or blocked):
            continue
        category = str(e.get("category") or "other").lower()
        by_category[category] = by_category.get(category, 0) + 1
        client = str(e.get("src_ip") or "").strip()
        if client:
            by_client[client] = by_client.get(client, 0) + 1
        domain = e.get("domain")
        if domain:
            by_domain[domain] = by_domain.get(domain, 0) + 1
    for e in dns_log:
        domain = e.get("domain")
        if domain in by_domain and domain not in domain_category:
            domain_category[domain] = str(e.get("category") or "other")

    sev_counts: dict[int, int] = {}
    sur_category: dict[str, int] = {}
    sur_source: dict[str, int] = {}
    for e in suricata_log:
        severity = e.get("severity")
        if isinstance(severity, int):
            sev_counts[severity] = sev_counts.get(severity, 0) + 1
        category = str(e.get("category") or "Other")
        sur_category[category] = sur_category.get(category, 0) + 1
        source = str(e.get("src_ip") or "unknown")
        sur_source[source] = sur_source.get(source, 0) + 1

    def ranked(counts: dict[str, int], limit: int | None = None) -> list[tuple[str, int]]:
        items = sorted(counts.items(), key=lambda kv: -kv[1])  # stable: ties keep first-seen order
        return items[:limit] if limit else items

    return {
        "dns_log_stats": {
            "total": dns_total,
            "malicious": dns_malicious,
            "blocked": dns_blocked,
            "blocked_by_category": [{"cat": k, "count": v} for k, v in ranked(by_category)],
            "blocked_by_client": [{"ip": k, "count": v} for k, v in ranked(by_client, top_n)],
            "top_blocked_domains": [
                {"domain": k, "count": v, "category": domain_category.get(k, "other")}
                for k, v in ranked(by_domain, top_n)
            ],
        },
        "suricata_log_stats": {
            "total": len(suricata_log),
            "by_severity": {str(k): v for k, v in sorted(sev_counts.items())},
            "by_category": [{"category": k, "count": v} for k, v in ranked(sur_category)],
            "top_sources": [{"ip": k, "count": v} for k, v in ranked(sur_source, top_n)],
        },
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
    recommendations: list[dict[str, Any]] = []
    finding_categories = {finding.get("category") for finding in findings}
    # Use devices that are alive or enriched from HA trackers to match
    # the Hosts view filtering.
    active_devices = [d for d in devices if d.get("alive") or d.get("enriched")]
    unknown_devices = sum(1 for device in active_devices if device.get("probable_role") == "unknown")
    tracker_enriched = sum(1 for device in active_devices if device.get("enriched"))
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
        sp_hosts = [_device_ref(d) for d in active_devices if d.get("ip") in {f["source_ip"] for f in sp_findings}]
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
        ps_hosts = [_device_ref(d) for d in active_devices if d.get("ip") in {f["source_ip"] for f in ps_findings}]
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
        he_hosts = [_device_ref(d) for d in active_devices if d.get("ip") in {f["source_ip"] for f in he_findings}]
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
        unknown_refs = [_device_ref(d) for d in active_devices if d.get("probable_role") == "unknown"]
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
    if active_devices and tracker_enriched == 0:
        unenriched = [_device_ref(d) for d in active_devices if not d.get("enriched")]
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


async def async_dashboard_payload(
    hass: HomeAssistant,
    dns_offset: int = 0,
    dns_limit: int = DASHBOARD_LOG_LIMIT,
    suricata_limit: int = DASHBOARD_LOG_LIMIT,
) -> dict[str, Any]:
    """Dashboard payload shared by the HTTP endpoint and the websocket push."""
    first = _first_runtime(hass)
    runtime = first["runtime"] if first else None
    if runtime is not None and runtime.chart_state is None:
        runtime.chart_state = await runtime.collector.storage.async_load("chart_state", {})
    payload = build_dashboard_payload(
        hass,
        runtime.chart_state if runtime is not None else {},
        dns_offset=dns_offset,
        dns_limit=dns_limit,
        suricata_limit=suricata_limit,
    )
    payload["panel_require_admin"] = bool(
        get_entry_value(first["entry"], CONF_WEBUI_REQUIRE_ADMIN, DEFAULT_WEBUI_REQUIRE_ADMIN)
    ) if first is not None else DEFAULT_WEBUI_REQUIRE_ADMIN
    if runtime is not None:
        chart_state = {
            "top_public_ips": payload.get("top_public_ips", []),
            "top_countries": payload.get("top_countries", []),
            "top_internal_talkers": payload.get("top_internal_talkers", []),
            "top_threat_ips": payload.get("top_threat_ips", []),
        }
        # Only write when the top lists actually changed (not on every update)
        if chart_state != runtime.chart_state:
            runtime.chart_state = chart_state
            runtime.collector.storage.async_delay_save("chart_state", lambda: chart_state, 60)
    return payload


class HomeSecDashboardView(HomeAssistantView):
    url = "/api/homesec/dashboard"
    name = "api:homesec:dashboard"
    requires_auth = True

    async def get(self, request):
        if (denied := _access_denied(request, write=False)) is not None:
            return denied
        payload = await async_dashboard_payload(
            request.app["hass"],
            dns_offset=_parse_offset(request.query.get("dns_offset")),
            dns_limit=_parse_limit(request.query.get("dns_limit"), DASHBOARD_LOG_LIMIT),
            suricata_limit=_parse_limit(request.query.get("suricata_limit"), DASHBOARD_LOG_LIMIT),
        )
        return self.json(payload)


@websocket_api.websocket_command(
    {
        vol.Required("type"): "homesec/subscribe_dashboard",
        vol.Optional("dns_limit"): vol.All(vol.Coerce(int), vol.Range(min=0)),
        vol.Optional("suricata_limit"): vol.All(vol.Coerce(int), vol.Range(min=0)),
    }
)
@websocket_api.async_response
async def ws_subscribe_dashboard(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Push the dashboard: everything once, then only sections that changed.

    Events are ``{"full": payload}`` first, then ``{"changed": {key: value}}``
    after each coordinator refresh where at least one top-level key changed.
    """
    if not _user_allowed(hass, connection.user, write=False):
        connection.send_error(msg["id"], websocket_api.ERR_UNAUTHORIZED, "Admin privileges required")
        return
    dns_limit = _parse_limit(str(msg.get("dns_limit", "")), DASHBOARD_LOG_LIMIT)
    suricata_limit = _parse_limit(str(msg.get("suricata_limit", "")), DASHBOARD_LOG_LIMIT)
    sent: dict[str, str] = {}
    state = {"busy": False, "again": False}

    def _encode(value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str)

    async def _push(full: bool) -> None:
        payload = await async_dashboard_payload(hass, dns_limit=dns_limit, suricata_limit=suricata_limit)
        if full:
            sent.update({key: _encode(value) for key, value in payload.items()})
            connection.send_message(websocket_api.event_message(msg["id"], {"full": payload}))
            return
        changed = {}
        for key, value in payload.items():
            encoded = _encode(value)
            if sent.get(key) != encoded:
                sent[key] = encoded
                changed[key] = value
        if changed:
            connection.send_message(websocket_api.event_message(msg["id"], {"changed": changed}))

    async def _push_changes() -> None:
        # Coalesce refreshes that arrive while a push is being built
        if state["busy"]:
            state["again"] = True
            return
        state["busy"] = True
        try:
            while True:
                state["again"] = False
                await _push(full=False)
                if not state["again"]:
                    break
        finally:
            state["busy"] = False

    @callback
    def _on_update() -> None:
        hass.async_create_task(_push_changes(), "homesec dashboard push")

    connection.subscriptions[msg["id"]] = async_dispatcher_connect(hass, SIGNAL_DASHBOARD_UPDATED, _on_update)
    connection.send_result(msg["id"])
    await _push(full=True)


@websocket_api.websocket_command({vol.Required("type"): "homesec/refresh_dashboard"})
@callback
def ws_refresh_dashboard(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Ask open subscriptions to push changes now (after a user action)."""
    if not _user_allowed(hass, connection.user, write=False):
        connection.send_error(msg["id"], websocket_api.ERR_UNAUTHORIZED, "Admin privileges required")
        return
    async_dispatcher_send(hass, SIGNAL_DASHBOARD_UPDATED)
    connection.send_result(msg["id"])


class HomeSecPanelFallbackView(HomeAssistantView):
    url = "/api/homesec/panel"
    name = "api:homesec:panel"
    requires_auth = True

    async def get(self, request):
        version = request.app["hass"].data.get(DOMAIN, {}).get("panel_version", "0")
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
    <script type=\"module\" src=\"{STATIC_PANEL_URL}?v={version}\"></script>
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
        # Lookups spend third-party API quota: admin only.
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        ip_param = request.query.get("ip", "").strip()
        if not ip_param:
            return self.json({"error": "missing 'ip' query parameter"}, status_code=400)
        try:
            ipaddress.ip_address(ip_param)
        except ValueError:
            return self.json({"error": "invalid IP address"}, status_code=400)

        hass: HomeAssistant = request.app["hass"]
        first = _first_runtime(hass)
        if first is None:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)

        result = await first["collector"].lookup_ip(ip_param)
        return self.json(result)


class HomeSecDismissFindingView(HomeAssistantView):
    """Dismiss a finding by key, with an optional note."""

    url = "/api/homesec/findings/dismiss"
    name = "api:homesec:findings:dismiss"
    requires_auth = True

    async def post(self, request):
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)
        key = str(data.get("key") or "")[:512]
        if not key:
            return self.json({"error": "Missing key"}, status_code=400)
        note = str(data.get("note") or "")[:500]  # cap note length
        hass = request.app["hass"]
        entries = _runtimes(hass)
        for runtime in entries.values():
            collector = getattr(runtime.get("coordinator"), "collector", None)
            if collector:
                collector.dismiss_finding(key, note)
        return self.json({"result": "ok"})


def _match_findings(pattern: str, findings: list[tuple[str, str]]) -> list[str]:
    """Return keys whose key or summary matches *pattern* (runs in an executor)."""
    rx = _re.compile(pattern, _re.IGNORECASE)
    return [key for key, summary in findings if rx.search(key) or rx.search(summary)]


class HomeSecDismissByPatternView(HomeAssistantView):
    """Dismiss all active findings whose summary or key matches a regex pattern."""

    url = "/api/homesec/findings/dismiss_by_pattern"
    name = "api:homesec:findings:dismiss_by_pattern"
    requires_auth = True

    async def post(self, request):
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)
        pattern = str(data.get("pattern") or "").strip()
        if not pattern:
            return self.json({"error": "Missing pattern"}, status_code=400)
        if len(pattern) > _MAX_REGEX_LENGTH:
            return self.json({"error": f"Pattern too long (max {_MAX_REGEX_LENGTH} chars)"}, status_code=400)
        note = str(data.get("note") or "")[:500]
        try:
            _re.compile(pattern, _re.IGNORECASE)
        except _re.error as exc:
            return self.json({"error": f"Invalid regex: {exc}"}, status_code=400)
        hass = request.app["hass"]
        dismissed_count = 0
        for runtime in _runtimes(hass).values():
            coordinator = runtime["coordinator"]
            collector = runtime["collector"]
            candidates: dict[str, str] = {}
            for f in (coordinator.data or {}).get("findings", []):
                key = str(f.get("key") or "")
                if key:
                    candidates.setdefault(key, str(f.get("summary") or ""))
            # Regex matching runs in the executor: a pathological pattern can
            # tie up one worker thread but never the event loop.
            matched = await hass.async_add_executor_job(
                _match_findings, pattern, list(candidates.items())
            )
            for key in matched:
                collector.dismiss_finding(key, note or f"Regex dismiss: {pattern}")
                dismissed_count += 1
        return self.json({"result": "ok", "dismissed": dismissed_count})


class HomeSecUndismissFindingView(HomeAssistantView):
    """Restore a previously dismissed finding."""

    url = "/api/homesec/findings/undismiss"
    name = "api:homesec:findings:undismiss"
    requires_auth = True

    async def post(self, request):
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)
        key = str(data.get("key") or "")
        if not key:
            return self.json({"error": "Missing key"}, status_code=400)
        hass = request.app["hass"]
        entries = _runtimes(hass)
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
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)
        ip = str(data.get("ip") or "").strip()
        role = str(data.get("role") or "").strip()
        if not ip:
            return self.json({"error": "Missing ip"}, status_code=400)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self.json({"error": "Invalid IP address"}, status_code=400)
        if role and not _ROLE_RE.match(role):
            return self.json({"error": "Role must be 1-40 lowercase letters, digits, or underscores"}, status_code=400)

        first = _first_runtime(request.app["hass"])
        if first is None:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)
        overrides = first["runtime"].role_overrides
        if role:
            overrides[ip] = role
        else:
            overrides.pop(ip, None)
        await first["collector"].storage.async_save("role_overrides", dict(overrides))
        return self.json({"result": "ok"})


class HomeSecNameOverrideView(HomeAssistantView):
    """Set or clear a device name override."""

    url = "/api/homesec/device/name"
    name = "api:homesec:device:name"
    requires_auth = True

    async def post(self, request):
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except ValueError:
            return self.json({"error": "Invalid JSON"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)
        ip = str(data.get("ip") or "").strip()
        custom_name = str(data.get("name") or "").strip()
        if not ip:
            return self.json({"error": "Missing ip"}, status_code=400)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self.json({"error": "Invalid IP address"}, status_code=400)
        if custom_name and len(custom_name) > 64:
            return self.json({"error": "Name too long (max 64 chars)"}, status_code=400)

        first = _first_runtime(request.app["hass"])
        if first is None:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)
        overrides = first["runtime"].name_overrides
        if custom_name:
            overrides[ip] = custom_name
        else:
            overrides.pop(ip, None)
        await first["collector"].storage.async_save("name_overrides", dict(overrides))
        return self.json({"result": "ok"})


class HomeSecVulnBrowserView(HomeAssistantView):
    """Vulnerability browser API — returns all known CVEs for search/filter."""

    url = "/api/homesec/vulnerabilities"
    name = "api:homesec:vulnerabilities"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        if (denied := _access_denied(request, write=False)) is not None:
            return denied
        hass: HomeAssistant = request.app["hass"]
        entries = _runtimes(hass)
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
                cpe_list = []
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
        if (denied := _access_denied(request, write=False)) is not None:
            return denied
        hass: HomeAssistant = request.app["hass"]
        entries = _runtimes(hass)
        if not entries:
            return self.json({"entries": [], "total": 0})

        limit = _parse_limit(request.query.get("limit"), DASHBOARD_LOG_LIMIT)
        offset = _parse_offset(request.query.get("offset"))
        malicious_only = request.query.get("malicious_only", "").lower() in ("1", "true", "yes")

        merged: list[dict] = []
        for runtime in entries.values():
            merged.extend(runtime["collector"].dns_log_snapshot())
        merged.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        if malicious_only:
            merged = [e for e in merged if e.get("malicious")]
        total = len(merged)
        return self.json({"entries": merged[offset:offset + limit], "total": total, "offset": offset})


class HomeSecClearBlockedDnsView(HomeAssistantView):
    """Clear all blocked/malicious entries from the DNS log.

    POST /api/homesec/dns/log/clear_blocked
    """

    url = "/api/homesec/dns/log/clear_blocked"
    name = "api:homesec:dns:log:clear_blocked"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        hass: HomeAssistant = request.app["hass"]
        entries = _runtimes(hass)
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
    the frontend can render an editable form.  Secrets are redacted.
    """

    url = "/api/homesec/settings"
    name = "api:homesec:settings"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        first = _first_runtime(request.app["hass"])
        if first is None:
            return self.json({"error": "no active HomeSec entries"}, status_code=404)
        entry = first["entry"]
        config: dict[str, Any] = {}
        for key in SETTINGS_KEYS:
            value = get_entry_value(entry, key, SETTINGS_DEFAULTS.get(key))
            if key in SECRET_SETTINGS_KEYS:
                config[key] = REDACTED_SECRET_VALUE if value else ""
            else:
                config[key] = value
        return self.json({"config": config, "schema": SETTINGS_SCHEMA})


class HomeSecSettingsSaveView(HomeAssistantView):
    """Validate and save settings into the config entry options.

    POST /api/homesec/settings/save
    Accepts a JSON object with one or more settings keys.  Invalid values are
    rejected with HTTP 400 and a per-field ``errors`` map; nothing is saved
    in that case.  The entry's update listener then applies the change in
    place or reloads the entry.
    """

    url = "/api/homesec/settings/save"
    name = "api:homesec:settings:save"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if (denied := _access_denied(request, write=True)) is not None:
            return denied
        try:
            data = await request.json()
        except Exception:  # noqa: BLE001
            return self.json({"error": "Invalid or non-JSON request body"}, status_code=400)
        if not isinstance(data, dict):
            return self.json({"error": "Expected JSON object"}, status_code=400)

        hass: HomeAssistant = request.app["hass"]
        first = _first_runtime(hass)
        if first is None:
            return self.json({"error": "No active Home Security Assistant entry found. Is the integration set up?"}, status_code=404)
        entry = first["entry"]

        updates, errors = validate_settings(data)
        if errors:
            return self.json(
                {
                    "error": "Invalid settings: " + "; ".join(f"{k}: {v}" for k, v in errors.items()),
                    "errors": errors,
                },
                status_code=400,
            )

        new_options = dict(entry.options)
        for key, value in updates.items():
            if value is None:
                new_options.pop(key, None)
            else:
                new_options[key] = value
        if new_options != dict(entry.options):
            hass.config_entries.async_update_entry(entry, options=new_options)
            _LOGGER.info("HomeSec settings updated via Settings UI")
        return self.json({"result": "ok"})
