"""Persistent storage for Home Security Assistant.

All runtime state is kept in Home Assistant ``Store`` objects under
``<config>/.storage/homesec.<name>``.  Store writes atomically (temp file +
rename), serialises with orjson, and coalesces frequent updates through
``async_delay_save``, so a crash can never leave a half-written file.

Versions up to 0.9.4 wrote YAML files directly into the config directory
(``homesec_*.yaml``).  :meth:`HomeSecStorage.async_load` migrates each one the
first time the matching Store is empty and then deletes the YAML file.

``homesec.yaml`` (settings, including API keys, duplicated from the config
entry) is no longer written; :func:`async_migrate_legacy_config` folds any
values the config entry is missing back into it once, then deletes the file.
"""

from __future__ import annotations

from collections.abc import Callable
import logging
from pathlib import Path
from typing import Any

import yaml

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1

# Store name -> legacy YAML file it replaces
STORE_NAMES: dict[str, str] = {
    "role_overrides": "homesec_roles.yaml",
    "name_overrides": "homesec_names.yaml",
    "dismissed": "homesec_dismissed.yaml",
    "hosts": "homesec_hosts.yaml",
    "timeseries": "homesec_timeseries.yaml",
    "dns_log": "homesec_dns_log.yaml",
    "suricata_log": "homesec_suricata_log.yaml",
    "ext_ips": "homesec_ext_ips.yaml",
    "enrichment_state": "homesec_enrichment_state.yaml",
    "baseline": "homesec_baseline.yaml",
    "chart_state": "homesec_chart_state.yaml",
    "event_state": "",
    # Downloaded data kept across restarts (no legacy YAML equivalent)
    "blocklists": "",
    "nvd_cache": "",
    "kev_catalog": "",
    "enrichment_cache": "",
}

LEGACY_CONFIG_FILENAME = "homesec.yaml"

TIMESERIES_MAX_POINTS = 8640  # 30 days at 5-min resolution
TIMESERIES_INTERVAL_SECONDS = 300  # one point per 5 minutes

# Keys the legacy homesec.yaml could carry back into the config entry
LEGACY_CONFIG_KEYS = (
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
    "dns_proxy_bind_host",
    "dns_proxy_port",
    "dns_proxy_upstream",
    "dns_log_retention_hours",
    "dns_warn_blocked_logs",
    "dns_blocked_categories",
    "dns_overrides",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "vt_abuseipdb_threshold",
)


# ── Legacy YAML readers (migration only) ─────────────────────────────────────


def _read_yaml(path: Path) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:  # noqa: BLE001
        _LOGGER.warning("Failed to read legacy file %s", path, exc_info=True)
        return None


def normalize_legacy(name: str, data: Any) -> Any:
    """Validate legacy YAML content for *name*; returns None when unusable."""
    if name in ("role_overrides", "name_overrides"):
        if not isinstance(data, dict):
            return None
        return {str(k): str(v) for k, v in data.items() if v is not None and str(v).strip()}
    if name == "dismissed":
        if isinstance(data, list):  # oldest format: plain list of keys
            return {str(k): "" for k in data if k}
        if isinstance(data, dict):
            return {str(k): str(v or "") for k, v in data.items() if k}
        return None
    if name == "hosts":
        if not isinstance(data, dict):
            return None
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    if name == "timeseries":
        if not isinstance(data, list):
            return None
        return [p for p in data if isinstance(p, dict) and "ts" in p][-TIMESERIES_MAX_POINTS:]
    if name in ("dns_log", "suricata_log"):
        if not isinstance(data, list):
            return None
        return [e for e in data if isinstance(e, dict) and "timestamp" in e]
    if name == "ext_ips":
        if not isinstance(data, list):
            return None
        return [e for e in data if isinstance(e, dict) and "ip" in e]
    if isinstance(data, dict):
        return data
    return None


def _jsonable(value: Any) -> Any:
    """Convert YAML-loaded values (dates, sets, tuples) into JSON-safe types."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _load_legacy(config_dir: str, name: str) -> Any:
    filename = STORE_NAMES.get(name)
    if not filename:
        return None
    path = Path(config_dir) / filename
    if not path.is_file():
        return None
    data = normalize_legacy(name, _read_yaml(path))
    return None if data is None else _jsonable(data)


def _delete_legacy(config_dir: str, name: str) -> None:
    filename = STORE_NAMES.get(name)
    if not filename:
        return
    path = Path(config_dir) / filename
    try:
        path.unlink(missing_ok=True)
    except OSError:
        _LOGGER.warning("Could not delete legacy file %s", path, exc_info=True)


def _read_and_remove_legacy_config(config_dir: str) -> dict[str, Any]:
    path = Path(config_dir) / LEGACY_CONFIG_FILENAME
    if not path.is_file():
        return {}
    data = _read_yaml(path)
    try:
        path.unlink()
        _LOGGER.info("Removed legacy %s (settings now live only in the config entry)", path)
    except OSError:
        _LOGGER.warning("Could not delete legacy %s", path, exc_info=True)
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in LEGACY_CONFIG_KEYS and v is not None and v != ""}


async def async_migrate_legacy_config(hass: HomeAssistant) -> dict[str, Any]:
    """Return settings from a legacy homesec.yaml (and delete the file)."""
    return await hass.async_add_executor_job(
        _read_and_remove_legacy_config, hass.config.config_dir
    )


# ── Store wrapper ────────────────────────────────────────────────────────────


class HomeSecStorage:
    """One ``Store`` per kind of state, with one-time YAML migration."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._stores: dict[str, Store] = {
            name: Store(hass, STORAGE_VERSION, f"homesec.{name}") for name in STORE_NAMES
        }

    async def async_load(self, name: str, default: Any) -> Any:
        """Load *name*, migrating its legacy YAML file on first use."""
        store = self._stores[name]
        data = await store.async_load()
        if data is None:
            legacy = await self._hass.async_add_executor_job(
                _load_legacy, self._hass.config.config_dir, name
            )
            if legacy is not None:
                await store.async_save(legacy)
                await self._hass.async_add_executor_job(
                    _delete_legacy, self._hass.config.config_dir, name
                )
                _LOGGER.info("Migrated %s to .storage/homesec.%s", STORE_NAMES[name], name)
                data = legacy
        if data is None or not isinstance(data, type(default)):
            return default
        return data

    def async_delay_save(self, name: str, data_func: Callable[[], Any], delay: float) -> None:
        """Schedule a save of ``data_func()`` in *delay* seconds (coalesced)."""
        self._stores[name].async_delay_save(data_func, delay)

    async def async_save(self, name: str, data: Any) -> None:
        await self._stores[name].async_save(data)

    async def async_remove(self, name: str) -> None:
        await self._stores[name].async_remove()

    async def async_remove_all(self) -> None:
        """Delete every store (used when the integration is removed)."""
        for store in self._stores.values():
            await store.async_remove()
