from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any
import logging
from aiohttp import web

from homeassistant.components import panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import (
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    get_entry_value,
)
from .storage import (
    load_name_overrides,
    load_role_overrides,
    save_name_overrides,
    save_role_overrides,
)

BUILT_IN_ROLES = (
    "unknown", "camera", "printer", "media_device", "mobile_device",
    "nas_or_desktop", "dns_or_gateway", "linux_host", "web_service", "iot_device",
)

import re as _re
_ROLE_RE = _re.compile(r'^[a-z0-9_]{1,40}$')

_LOGGER = logging.getLogger(__name__)

SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4, "info": 5}

PANEL_URL_PATH = "homesec"
PANEL_COMPONENT = "homesec-panel"
STATIC_PANEL_URL = "/api/homesec/frontend/homesec-panel.js"
STATIC_PANEL_PATH = Path(__file__).parent / "frontend" / "homesec-panel.js"
STATIC_LOGO_URL = "/api/homesec/frontend/hsa-logo.svg"
STATIC_LOGO_PATH = Path(__file__).parent / "frontend" / "hsa-logo.svg"

BRAND_DIR = Path(__file__).parent
BRAND_FILES = [
    "icon.png", "icon@2x.png",
    "dark_icon.png", "dark_icon@2x.png",
    "logo.png", "logo@2x.png",
    "dark_logo.png", "dark_logo@2x.png",
]


def _register_brand_route(hass: HomeAssistant, fname: str, fpath: Path) -> None:
    """Register a plain GET route for a single brand icon file.

    Plain routes take precedence over HA's dynamic
    /api/brands/{type}/{domain}/{file} handler in aiohttp.
    """
    _path = fpath  # capture for closure

    async def _serve(request: web.Request) -> web.StreamResponse:
        return web.FileResponse(_path)

    try:
        hass.http.app.router.add_get(
            f"/api/brands/integration/{DOMAIN}/{fname}", _serve
        )
    except Exception:  # noqa: BLE001
        _LOGGER.debug("Could not register brand route for %s", fname)


async def async_setup_dashboard(hass: HomeAssistant) -> None:
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
    # Register exact plain routes for brand icons — plain routes take
    # precedence over HA's dynamic /api/brands/{type}/{domain}/{file} handler.
    for fname in BRAND_FILES:
        fpath = BRAND_DIR / fname
        if fpath.is_file():
            _register_brand_route(hass, fname, fpath)

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
    hass.http.register_view(HomeSecUndismissFindingView())
    hass.http.register_view(HomeSecRoleOverrideView())
    hass.http.register_view(HomeSecNameOverrideView())
    hass.http.register_view(HomeSecVulnBrowserView())
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name=PANEL_COMPONENT,
        frontend_url_path=PANEL_URL_PATH,
        module_url=STATIC_PANEL_URL,
        sidebar_title="Home Security Assistant",
        sidebar_icon="mdi:shield-search",
        require_admin=False,
        config={"domain": DOMAIN},
    )
    _LOGGER.info("Home Security Assistant panel registered at /%s and fallback at /api/homesec/panel", PANEL_URL_PATH)
    domain_data["panel_registered"] = True


def build_dashboard_payload(hass: HomeAssistant) -> dict[str, Any]:
    domain_data = hass.data.get(DOMAIN, {})
    entries = domain_data.get("entries", {})

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
    TOP_N = 10

    # Top public IPs by number of distinct internal sources contacting them
    ext_ip_connection_count: dict[str, int] = {}
    for conn in all_connections:
        if conn.get("target_kind") == "external":
            ip = str(conn.get("target", ""))
            if ip:
                ext_ip_connection_count[ip] = ext_ip_connection_count.get(ip, 0) + int(conn.get("flows", 1))
    top_public_ips: list[dict[str, Any]] = []
    for ip, flow_count in sorted(ext_ip_connection_count.items(), key=lambda kv: kv[1], reverse=True)[:TOP_N]:
        ext_info = all_external_ips.get(ip, {})
        top_public_ips.append({
            "ip": ip,
            "flows": flow_count,
            "hostname": ext_info.get("hostname") or ext_info.get("hostname_ipinfo") or "",
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
    # ─────────────────────────────────────────────────────────────────────

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
        },
        "role_overrides": domain_data.get("role_overrides", {}),
        "name_overrides": domain_data.get("name_overrides", {}),
        "devices": sorted(all_devices, key=lambda device: device.get("total_octets", 0), reverse=True),
        "findings": sorted(all_findings, key=lambda finding: (SEVERITY_SORT.get(finding.get("severity", ""), 99), -finding.get("count", 0))),
        "dismissed_findings": sorted(all_dismissed_findings, key=lambda finding: (SEVERITY_SORT.get(finding.get("severity", ""), 99), -finding.get("count", 0))),
        "recommendations": recommendations,
        "connections": connections,
        "external_ips": sorted(all_external_ips.values(), key=lambda e: e.get("ip", "")),
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
        "scan_interval": int(get_entry_value(
            list(entries.values())[0]["entry"], CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )) if entries else None,
        "entries": entry_payloads,
        "top_public_ips": top_public_ips,
        "top_countries": top_countries,
        "top_internal_talkers": top_internal_talkers,
        "enrichment_stats": enrichment_stats,
    }


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
    unknown_devices = sum(1 for device in devices if device.get("probable_role") == "unknown")
    tracker_enriched = sum(1 for device in devices if device.get("enriched"))
    at_risk_count = sum(1 for device in devices if device.get("at_risk"))

    if at_risk_count > 0:
        recommendations.append(
            {
                "title": "Patch vulnerable devices",
                "priority": "critical",
                "detail": f"{at_risk_count} device(s) have known high or critical CVE vulnerabilities. Update firmware/software or restrict network access immediately.",
            }
        )
    if "vulnerability" in finding_categories:
        recommendations.append(
            {
                "title": "Review vulnerability findings",
                "priority": "high",
                "detail": "Active scanning found services with known security issues. Check the findings tab for CVE details and remediation steps.",
            }
        )

    if not exporters:
        recommendations.append(
            {
                "title": "Connect a flow exporter",
                "priority": "high",
                "detail": "No NetFlow or IPFIX exporters have been observed yet. Configure your gateway, firewall, or switch to export flows to HomeSec.",
            }
        )
    if exporters and total_datagrams == 0:
        recommendations.append(
            {
                "title": "Verify exporter reachability",
                "priority": "high",
                "detail": "Exporters are configured but HomeSec has not received any datagrams yet. Check exporter target IP/port, firewall rules, and container networking.",
            }
        )
    if total_datagrams > 0 and parsed_datagrams == 0:
        recommendations.append(
            {
                "title": "Check flow export format",
                "priority": "high",
                "detail": "Datagrams are arriving but none produced records. Confirm exporter uses NetFlow v5/v9/IPFIX with IPv4 fields and valid templates.",
            }
        )
    if "suspicious_port" in finding_categories:
        recommendations.append(
            {
                "title": "Restrict risky outbound ports",
                "priority": "high",
                "detail": "At least one device reached a commonly abused external port such as Telnet or RDP. Block or alert on these ports at the gateway and patch the source device.",
            }
        )
    if "port_scan" in finding_categories:
        recommendations.append(
            {
                "title": "Isolate scanning hosts",
                "priority": "high",
                "detail": "A device is touching many ports in a short time window. Move it to an isolated VLAN or guest network until you confirm the behavior is expected.",
            }
        )
    if "high_egress" in finding_categories:
        recommendations.append(
            {
                "title": "Review high egress devices",
                "priority": "medium",
                "detail": "One or more devices exceeded the outbound data threshold. Confirm whether the traffic matches backups, cameras, or media uploads instead of malware or exfiltration.",
            }
        )
    if unknown_devices > 0:
        recommendations.append(
            {
                "title": "Improve device identity coverage",
                "priority": "medium",
                "detail": f"{unknown_devices} devices still have unknown roles. Add router, DHCP, or tracker integrations so HomeSec can correlate names, MAC addresses, and hostnames.",
            }
        )
    if devices and tracker_enriched == 0:
        recommendations.append(
            {
                "title": "Enable device tracker enrichment",
                "priority": "medium",
                "detail": "HomeSec is seeing devices but none were enriched from Home Assistant trackers. Adding router or presence integrations will make the dashboard much more readable.",
            }
        )
    if dropped_datagrams > 0:
        recommendations.append(
            {
                "title": "Stabilize exporter templates",
                "priority": "medium",
                "detail": "Some flow datagrams were dropped or arrived before their templates. Reduce exporter restarts or shorten template refresh intervals on the exporter.",
            }
        )

    return recommendations[:8]


class HomeSecDashboardView(HomeAssistantView):
    url = "/api/homesec/dashboard"
    name = "api:homesec:dashboard"
    requires_auth = True

    async def get(self, request):
        return self.json(build_dashboard_payload(request.app["hass"]))


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