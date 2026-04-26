"""Persistent file-based storage for Home Security Assistant.

Four YAML files are written to the Home Assistant config directory
(alongside ``configuration.yaml``).  All I/O is done synchronously and
should be dispatched via ``hass.async_add_executor_job`` from async code.

Files
-----
homesec.yaml
    Integration settings (ports, thresholds, API keys, …).  Written on
    every reload and read back at startup so that component updates never
    lose user settings.  ``merge_file_config`` is used to fill in *only*
    keys that are missing or empty from the config-entry data — the UI
    (config entry) always wins over the file for keys that are present in
    both.  Only keys listed in ``PERSISTED_KEYS`` are stored; all others
    are silently ignored.

homesec_roles.yaml
    Manual device-role overrides, keyed by IP address.  Written whenever
    the user changes a role in the Hosts dashboard view; read at startup
    and passed to ``HomeSecurityAnalyzer`` so overrides survive restarts
    and component updates.  Structure: ``{ip: role}``.

homesec_names.yaml
    Manual device-name overrides, keyed by IP address.  Written whenever
    the user renames a host in the Hosts dashboard view; read at startup
    so custom names survive restarts and component updates.  Structure:
    ``{ip: custom_name}``.

homesec_hosts.yaml
    Active-scanner host-discovery results, keyed by IP address.  Written
    after each scan cycle by ``NetworkScanner`` (via the
    ``on_scan_complete`` callback) and reloaded at startup so that the
    Hosts view is immediately populated without waiting for the first full
    scan to complete.  Structure: ``{ip: {alive, open_ports, os_guess, …}}``.

Merge semantics
---------------
``merge_file_config`` applies *file-wins-on-missing* logic: a file value
is copied into the merged dict only when the corresponding key is absent,
``None``, or an empty string in the config-entry data.  This allows users
to bootstrap the integration from a pre-written YAML file without
conflicting with subsequent UI changes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

_LOGGER = logging.getLogger(__name__)

STORAGE_FILENAME = "homesec.yaml"
ROLE_OVERRIDES_FILENAME = "homesec_roles.yaml"
NAME_OVERRIDES_FILENAME = "homesec_names.yaml"

# Keys that are persisted to file
PERSISTED_KEYS = (
    "bind_host",
    "bind_port",
    "internal_networks",
    "scan_window_seconds",
    "scan_port_threshold",
    "high_egress_threshold",
    "enable_webui",
    "webui_require_admin",
    "enable_scanner",
    "scan_interval",
    "scan_exceptions",
    "external_ip_retention_hours",
    "retention_suspicious_hours",
    "retention_malicious_hours",
    "enable_dns_resolution",
    "blacklist_urls",
    "dns_proxy_enabled",
    "dns_proxy_port",
    "dns_proxy_upstream",
    "dns_log_retention_hours",
    "dns_proxy_check_sources",
    "dns_blocked_categories",
    "dns_overrides",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "vt_abuseipdb_threshold",
)


def _config_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / STORAGE_FILENAME


def load_config(hass_config_dir: str) -> dict[str, Any]:
    """Load persisted configuration from YAML file. Returns empty dict if missing."""
    path = _config_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return {}
        _LOGGER.info("Loaded HomeSec config from %s", path)
        return {k: v for k, v in data.items() if k in PERSISTED_KEYS}
    except Exception:
        _LOGGER.warning("Failed to read %s, using defaults", path, exc_info=True)
        return {}


def save_config(hass_config_dir: str, data: dict[str, Any]) -> None:
    """Persist current configuration to YAML file."""
    path = _config_path(hass_config_dir)
    filtered = {k: v for k, v in data.items() if k in PERSISTED_KEYS and v is not None}
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — persistent configuration\n")
            fh.write("# This file is auto-managed. Edit via the HA integration UI.\n\n")
            yaml.safe_dump(filtered, fh, default_flow_style=False, sort_keys=True)
        _LOGGER.debug("Saved HomeSec config to %s", path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


def merge_file_config(entry_data: dict[str, Any], file_data: dict[str, Any]) -> dict[str, Any]:
    """Merge file-based config under entry data. File values fill in missing keys only."""
    merged = dict(entry_data)
    for key in PERSISTED_KEYS:
        if key not in merged or merged[key] is None or merged[key] == "":
            if key in file_data and file_data[key] is not None:
                merged[key] = file_data[key]
    return merged


def _role_overrides_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / ROLE_OVERRIDES_FILENAME


def load_role_overrides(hass_config_dir: str) -> dict[str, str]:
    """Load IP -> role overrides from YAML. Returns empty dict if missing."""
    path = _role_overrides_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_role_overrides(hass_config_dir: str, overrides: dict[str, str]) -> None:
    """Persist IP -> role overrides to YAML."""
    path = _role_overrides_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — device role overrides\n")
            fh.write("# IP: role (auto-managed, edit via the dashboard)\n\n")
            yaml.safe_dump(dict(overrides), fh, default_flow_style=False, sort_keys=True)
        _LOGGER.debug("Saved role overrides to %s", path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


def _name_overrides_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / NAME_OVERRIDES_FILENAME


def load_name_overrides(hass_config_dir: str) -> dict[str, str]:
    """Load IP -> custom display name overrides from YAML. Returns empty dict if missing."""
    path = _name_overrides_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if v is not None and str(v).strip()}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_name_overrides(hass_config_dir: str, overrides: dict[str, str]) -> None:
    """Persist IP -> custom display name overrides to YAML."""
    path = _name_overrides_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — device name overrides\n")
            fh.write("# IP: custom display name (auto-managed, edit via the dashboard)\n\n")
            yaml.safe_dump(dict(overrides), fh, default_flow_style=False, sort_keys=True)
        _LOGGER.debug("Saved name overrides to %s", path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


HOSTS_FILENAME = "homesec_hosts.yaml"

DISMISSED_FILENAME = "homesec_dismissed.yaml"


def _dismissed_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / DISMISSED_FILENAME


def load_dismissed_findings(hass_config_dir: str) -> dict[str, str]:
    """Load persisted dismissed finding keys with optional notes.

    Returns a dict mapping key → note (note may be empty string).
    Supports the legacy list format (no notes) transparently.
    """
    path = _dismissed_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        # Legacy format: plain list of keys
        if isinstance(data, list):
            _LOGGER.info("Loaded %d dismissed findings (legacy) from %s", len(data), path)
            return {str(k): "" for k in data if k}
        # Current format: dict of {key: note}
        if isinstance(data, dict):
            _LOGGER.info("Loaded %d dismissed findings from %s", len(data), path)
            return {str(k): str(v or "") for k, v in data.items() if k}
        return {}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_dismissed_findings(hass_config_dir: str, dismissed: dict[str, str]) -> None:
    """Persist dismissed findings (key → note) to YAML."""
    path = _dismissed_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — dismissed findings\n")
            fh.write("# Auto-managed. Remove an entry here to restore a finding.\n\n")
            yaml.safe_dump(dismissed, fh, default_flow_style=False, allow_unicode=True)
        _LOGGER.debug("Saved %d dismissed findings to %s", len(dismissed), path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


def _hosts_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / HOSTS_FILENAME


def load_discovered_hosts(hass_config_dir: str) -> dict[str, dict]:
    """Load previously discovered host scan results from YAML. Returns empty dict if missing."""
    path = _hosts_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return {}
        _LOGGER.info("Loaded %d discovered hosts from %s", len(data), path)
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_discovered_hosts(hass_config_dir: str, hosts: dict[str, dict]) -> None:
    """Persist discovered host scan results to YAML."""
    path = _hosts_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — discovered hosts\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(hosts, fh, default_flow_style=False, sort_keys=True)
        _LOGGER.debug("Saved %d discovered hosts to %s", len(hosts), path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


TIMESERIES_FILENAME = "homesec_timeseries.yaml"
TIMESERIES_MAX_POINTS = 8640  # 30 days at 5-min resolution
TIMESERIES_INTERVAL_SECONDS = 300  # one point per 5 minutes


def _timeseries_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / TIMESERIES_FILENAME


def load_timeseries(hass_config_dir: str) -> list[dict[str, Any]]:
    """Load historical timeseries points from YAML. Returns empty list if missing."""
    path = _timeseries_path(hass_config_dir)
    if not path.is_file():
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            return []
        return [p for p in data if isinstance(p, dict) and "ts" in p]
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return []


def save_timeseries(hass_config_dir: str, points: list[dict[str, Any]]) -> None:
    """Persist timeseries history to YAML, capped at TIMESERIES_MAX_POINTS entries."""
    path = _timeseries_path(hass_config_dir)
    trimmed = points[-TIMESERIES_MAX_POINTS:]
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — historical timeseries data\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(trimmed, fh, default_flow_style=False, sort_keys=False)
        _LOGGER.debug("Saved timeseries (%d points) to %s", len(trimmed), path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


# ── DNS query log ─────────────────────────────────────────────────────────────

DNS_LOG_FILENAME = "homesec_dns_log.yaml"


def _dns_log_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / DNS_LOG_FILENAME


def load_dns_log(hass_config_dir: str) -> list[dict[str, Any]]:
    """Load persisted DNS query log from YAML. Returns empty list if missing."""
    path = _dns_log_path(hass_config_dir)
    if not path.is_file():
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            return []
        return [e for e in data if isinstance(e, dict) and "timestamp" in e]
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return []


def save_dns_log(hass_config_dir: str, entries: list[dict[str, Any]], max_entries: int = 10_000) -> None:
    """Persist DNS query log to YAML, capped at max_entries."""
    path = _dns_log_path(hass_config_dir)
    trimmed = entries[-max_entries:]
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — DNS query log\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(trimmed, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
        _LOGGER.debug("Saved DNS log (%d entries) to %s", len(trimmed), path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


# ── External IP tracking state ────────────────────────────────────────────────

EXT_IPS_FILENAME = "homesec_ext_ips.yaml"


def _ext_ips_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / EXT_IPS_FILENAME


def load_ext_ips(hass_config_dir: str) -> list[dict[str, Any]]:
    """Load persisted external IP tracking state from YAML. Returns empty list if missing."""
    path = _ext_ips_path(hass_config_dir)
    if not path.is_file():
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            return []
        return [e for e in data if isinstance(e, dict) and "ip" in e]
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return []


def save_ext_ips(hass_config_dir: str, data: list[dict[str, Any]]) -> None:
    """Persist external IP tracking state to YAML."""
    path = _ext_ips_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — external IP tracking state\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
        _LOGGER.debug("Saved external IPs (%d entries) to %s", len(data), path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


# ── External enrichment usage state ──────────────────────────────────────────

ENRICHMENT_STATE_FILENAME = "homesec_enrichment_state.yaml"


def _enrichment_state_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / ENRICHMENT_STATE_FILENAME


def load_enrichment_state(hass_config_dir: str) -> dict[str, Any]:
    """Load persisted external enrichment usage counters from YAML."""
    path = _enrichment_state_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_enrichment_state(hass_config_dir: str, state: dict[str, Any]) -> None:
    """Persist external enrichment usage counters to YAML."""
    path = _enrichment_state_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — external enrichment usage state\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(state, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
        _LOGGER.debug("Saved enrichment usage state to %s", path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)


# ── Dashboard chart state ────────────────────────────────────────────────────

CHART_STATE_FILENAME = "homesec_chart_state.yaml"


def _chart_state_path(hass_config_dir: str) -> Path:
    return Path(hass_config_dir) / CHART_STATE_FILENAME


def load_chart_state(hass_config_dir: str) -> dict[str, Any]:
    """Load persisted dashboard chart state from YAML."""
    path = _chart_state_path(hass_config_dir)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        _LOGGER.warning("Failed to read %s", path, exc_info=True)
        return {}


def save_chart_state(hass_config_dir: str, state: dict[str, Any]) -> None:
    """Persist dashboard chart state to YAML."""
    path = _chart_state_path(hass_config_dir)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Home Security Assistant — dashboard chart state\n")
            fh.write("# Auto-managed. Do not edit manually.\n\n")
            yaml.safe_dump(state, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
        _LOGGER.debug("Saved dashboard chart state to %s", path)
    except Exception:
        _LOGGER.warning("Failed to write %s", path, exc_info=True)
