from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import frontend
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_ENABLE_WEBUI,
    CONF_WEBUI_REQUIRE_ADMIN,
    DEFAULT_ENABLE_WEBUI,
    DEFAULT_WEBUI_REQUIRE_ADMIN,
    DOMAIN,
    PLATFORMS,
    get_entry_value,
)
from .coordinator import HomeSecCollector, HomeSecCoordinator
from .dashboard import PANEL_URL_PATH, async_setup_dashboard
from .settings_schema import IN_PLACE_KEYS
from .storage import HomeSecStorage, async_migrate_legacy_config

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

SERVICE_TRIGGER_SCAN = "trigger_scan"
SERVICE_NVD_REFRESH = "nvd_refresh"
SERVICE_BLACKLIST_REFRESH = "blacklist_refresh"
SERVICE_START_BASELINE_TRAINING = "start_baseline_training"
SERVICE_STOP_BASELINE_TRAINING = "stop_baseline_training"
SERVICE_CLEAR_BASELINE = "clear_baseline"
SERVICE_RETRAIN_BASELINE = "retrain_baseline"


@dataclass
class HomeSecRuntimeData:
    """Objects owned by one loaded config entry."""

    collector: HomeSecCollector
    coordinator: HomeSecCoordinator
    role_overrides: dict[str, str] = field(default_factory=dict)
    name_overrides: dict[str, str] = field(default_factory=dict)
    # Effective settings the running objects were built/updated from
    applied_settings: dict[str, Any] = field(default_factory=dict)
    # Last persisted dashboard top lists (loaded lazily by the dashboard view)
    chart_state: dict[str, Any] | None = None


type HomeSecConfigEntry = ConfigEntry[HomeSecRuntimeData]


def _effective_settings(entry: ConfigEntry) -> dict[str, Any]:
    return {**entry.data, **entry.options}


def loaded_entries(hass: HomeAssistant) -> list[HomeSecConfigEntry]:
    """Config entries of this integration that are currently loaded."""
    return [
        entry
        for entry in hass.config_entries.async_entries(DOMAIN)
        if entry.state is ConfigEntryState.LOADED and hasattr(entry, "runtime_data")
    ]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's services (once, independent of entries)."""

    async def _for_each(call: ServiceCall, action: str, refresh: bool = True) -> None:
        for entry in loaded_entries(hass):
            runtime = entry.runtime_data
            await getattr(runtime.collector, action)()
            if refresh:
                await runtime.coordinator.async_request_refresh()

    async def _handle_trigger_scan(call: ServiceCall) -> None:
        # A full scan can take minutes: run it in the background and return.
        for entry in loaded_entries(hass):
            runtime = entry.runtime_data

            async def _scan_then_refresh(runtime: HomeSecRuntimeData = runtime) -> None:
                await runtime.collector.async_trigger_scan()
                await runtime.coordinator.async_request_refresh()

            entry.async_create_background_task(
                hass, _scan_then_refresh(), name="homesec_manual_scan"
            )

    async def _handle_nvd_refresh(call: ServiceCall) -> None:
        await _for_each(call, "async_nvd_refresh")

    async def _handle_blacklist_refresh(call: ServiceCall) -> None:
        await _for_each(call, "async_refresh_blacklist", refresh=False)

    async def _handle_start_baseline_training(call: ServiceCall) -> None:
        await _for_each(call, "async_start_baseline_training")

    async def _handle_stop_baseline_training(call: ServiceCall) -> None:
        await _for_each(call, "async_stop_baseline_training")

    async def _handle_clear_baseline(call: ServiceCall) -> None:
        await _for_each(call, "async_clear_baseline")

    async def _handle_retrain_baseline(call: ServiceCall) -> None:
        await _for_each(call, "async_retrain_baseline")

    for name, handler in (
        (SERVICE_TRIGGER_SCAN, _handle_trigger_scan),
        (SERVICE_NVD_REFRESH, _handle_nvd_refresh),
        (SERVICE_BLACKLIST_REFRESH, _handle_blacklist_refresh),
        (SERVICE_START_BASELINE_TRAINING, _handle_start_baseline_training),
        (SERVICE_STOP_BASELINE_TRAINING, _handle_stop_baseline_training),
        (SERVICE_CLEAR_BASELINE, _handle_clear_baseline),
        (SERVICE_RETRAIN_BASELINE, _handle_retrain_baseline),
    ):
        hass.services.async_register(DOMAIN, name, handler, schema=vol.Schema({}))
    return True


async def _async_migrate_legacy_settings(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Fold settings from a pre-0.9.5 homesec.yaml into the entry, once."""
    legacy = await async_migrate_legacy_config(hass)
    if not legacy:
        return
    current = _effective_settings(entry)
    missing = {
        key: value
        for key, value in legacy.items()
        if current.get(key) is None or current.get(key) == ""
    }
    if missing:
        hass.config_entries.async_update_entry(entry, options={**entry.options, **missing})
        _LOGGER.info("Migrated %d setting(s) from homesec.yaml into the config entry", len(missing))


async def async_setup_entry(hass: HomeAssistant, entry: HomeSecConfigEntry) -> bool:
    await _async_migrate_legacy_settings(hass, entry)

    collector = HomeSecCollector(hass, entry)
    try:
        await collector.async_start()
    except OSError as err:
        await collector.async_stop()
        raise ConfigEntryNotReady(
            f"Unable to bind NetFlow listener on {get_entry_value(entry, CONF_BIND_HOST)}:{get_entry_value(entry, CONF_BIND_PORT)}"
        ) from err

    coordinator = HomeSecCoordinator(hass, collector, entry)
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await collector.async_stop()
        raise

    storage: HomeSecStorage = collector.storage
    entry.runtime_data = HomeSecRuntimeData(
        collector=collector,
        coordinator=coordinator,
        role_overrides=await storage.async_load("role_overrides", {}),
        name_overrides=await storage.async_load("name_overrides", {}),
        applied_settings=_effective_settings(entry),
    )
    entry.async_on_unload(entry.add_update_listener(async_update_listener))

    if bool(get_entry_value(entry, CONF_ENABLE_WEBUI, DEFAULT_ENABLE_WEBUI)):
        await async_setup_dashboard(
            hass,
            require_admin=bool(
                get_entry_value(entry, CONF_WEBUI_REQUIRE_ADMIN, DEFAULT_WEBUI_REQUIRE_ADMIN)
            ),
        )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_update_listener(hass: HomeAssistant, entry: HomeSecConfigEntry) -> None:
    """Apply changed options: in place when possible, otherwise reload the entry."""
    runtime = entry.runtime_data
    new_settings = _effective_settings(entry)
    changed = {
        key
        for key in set(new_settings) | set(runtime.applied_settings)
        if new_settings.get(key) != runtime.applied_settings.get(key)
    }
    if not changed:
        return
    if changed <= IN_PLACE_KEYS:
        try:
            await runtime.collector.async_apply_entry_update(entry)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("In-place HomeSec options apply failed; reloading entry")
        else:
            runtime.applied_settings = new_settings
            await runtime.coordinator.async_request_refresh()
            _LOGGER.info("Applied HomeSec options in place: %s", ", ".join(sorted(changed)))
            return
    _LOGGER.info("HomeSec options changed (%s); reloading entry", ", ".join(sorted(changed)))
    hass.config_entries.async_schedule_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: HomeSecConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    await entry.runtime_data.collector.async_stop()

    other_loaded = [e for e in loaded_entries(hass) if e.entry_id != entry.entry_id]
    domain_data = hass.data.get(DOMAIN, {})
    if not other_loaded and domain_data.get("panel_registered"):
        frontend.async_remove_panel(hass, PANEL_URL_PATH)
        domain_data["panel_registered"] = False
    return True


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete all stored state when the integration is removed."""
    await HomeSecStorage(hass).async_remove_all()
