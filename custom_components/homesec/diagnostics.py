"""Diagnostics download for Home Security Assistant.

Contains configuration (secrets redacted) and runtime health counters only.
Device lists, logs and external IPs are deliberately left out so the file can
be attached to a public bug report.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .dashboard import _read_version
from .settings_schema import SECRET_SETTINGS_KEYS

TO_REDACT = set(SECRET_SETTINGS_KEYS) | {"nvd_api_key"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime = entry.runtime_data
    collector = runtime.collector
    data = runtime.coordinator.data or {}
    listener = dict(data.get("listener", {}) or {})
    # Exporter addresses identify the user's network equipment
    listener["exporters"] = len(listener.get("exporters", []) or [])
    suricata = dict(collector.suricata_stats())
    suricata["exporter_ips"] = len(suricata.get("exporter_ips", []) or [])

    return {
        "version": _read_version(),
        "entry": {
            "version": f"{entry.version}.{entry.minor_version}",
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": async_redact_data(dict(entry.options), TO_REDACT),
        },
        "collector": {
            "netflow_listener_enabled": collector._netflow_listener_enabled,
            "netflow_exporter_allowlist_size": len(collector._netflow_allowed_exporters),
            "netflow": listener,
            "scanner": {
                "enabled": collector._scanner_enabled,
                "last_scan_at": collector._scanner.last_scan_at.isoformat()
                if collector._scanner.last_scan_at
                else None,
                "last_scan_status": collector._scanner.last_scan_status,
                "last_scan_targets": collector._scanner.last_scan_targets,
                "last_scan_duration": collector._scanner.last_scan_duration,
            },
            "dns_proxy": collector.dns_proxy_stats(),
            "suricata": suricata,
            "blocklists": collector._resolver.stats(),
            "enrichment": collector._enricher.enrichment_stats(),
            "nvd": {
                "cached_cves": collector._nvd_client.total_cached_cves,
                "keywords": len(collector._nvd_client.cached_keywords),
                "kev_entries": collector._kev_client.total,
            },
            "baseline": data.get("baseline", {}),
        },
        "counts": {
            "devices": len(data.get("devices", []) or []),
            "findings": len(data.get("findings", []) or []),
            "dismissed_findings": len(data.get("dismissed_findings", []) or []),
            "external_ips": len(data.get("external_ips", []) or []),
            "connections": len(data.get("connections", []) or []),
            "dns_log": data.get("dns_log_size", 0),
            "suricata_log": data.get("suricata_log_size", 0),
            "device_updates_dropped": data.get("device_updates_dropped", 0),
        },
    }
