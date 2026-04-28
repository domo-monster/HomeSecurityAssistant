from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.components import frontend
from homeassistant.config_entries import ConfigEntry, ConfigEntryNotReady
from homeassistant.core import HomeAssistant, ServiceCall

from .const import (
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_ENABLE_WEBUI,
    DEFAULT_ENABLE_WEBUI,
    DOMAIN,
    PLATFORMS,
    get_entry_value,
)
from .coordinator import HomeSecCollector, HomeSecCoordinator
from .dashboard import async_setup_dashboard
from .storage import load_config, load_host_settings, save_config

_LOGGER = logging.getLogger(__name__)

SERVICE_TRIGGER_SCAN = "trigger_scan"
SERVICE_NVD_REFRESH = "nvd_refresh"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    # Load file-based config and merge into entry data where values are missing
    file_config = await hass.async_add_executor_job(load_config, hass.config.config_dir)
    if file_config:
        merged = dict(entry.data)
        for key, val in file_config.items():
            if key not in merged or merged[key] is None or merged[key] == "":
                merged[key] = val
        if merged != dict(entry.data):
            hass.config_entries.async_update_entry(entry, data=merged)
            _LOGGER.info("Restored HomeSec config values from homesec.yaml")

    # Save current config to file for persistence across component updates
    all_config = {**entry.data, **entry.options}
    await hass.async_add_executor_job(save_config, hass.config.config_dir, all_config)

    # Per-host scan overrides are loaded unconditionally so the scanner
    # honors them even when the Web UI is disabled.
    domain_data = hass.data.setdefault(DOMAIN, {"entries": {}, "panel_registered": False})
    if "host_settings" not in domain_data:
        domain_data["host_settings"] = await hass.async_add_executor_job(
            load_host_settings, hass.config.config_dir
        )

    enable_webui = bool(get_entry_value(entry, CONF_ENABLE_WEBUI, DEFAULT_ENABLE_WEBUI))
    if enable_webui:
        await async_setup_dashboard(hass)
        _LOGGER.info("HomeSec Web UI is enabled for entry %s", entry.entry_id)
    else:
        _LOGGER.info("HomeSec Web UI is disabled for entry %s", entry.entry_id)

    collector = HomeSecCollector(hass, entry)
    try:
        await collector.async_start()
    except OSError as err:
        raise ConfigEntryNotReady(
            f"Unable to bind NetFlow listener on {get_entry_value(entry, CONF_BIND_HOST)}:{get_entry_value(entry, CONF_BIND_PORT)}"
        ) from err

    coordinator = HomeSecCoordinator(hass, collector, entry)
    await coordinator.async_config_entry_first_refresh()

    domain_data["entries"][entry.entry_id] = {
        "collector": collector,
        "coordinator": coordinator,
        "entry": entry,
    }
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    # Register the trigger_scan service once (idempotent across multiple entries)
    if not hass.services.has_service(DOMAIN, SERVICE_TRIGGER_SCAN):
        async def _handle_trigger_scan(call: ServiceCall) -> None:
            for runtime in hass.data[DOMAIN]["entries"].values():
                await runtime["collector"].async_trigger_scan()
                await runtime["coordinator"].async_request_refresh()

        hass.services.async_register(
            DOMAIN, SERVICE_TRIGGER_SCAN, _handle_trigger_scan, schema=vol.Schema({})
        )
        _LOGGER.info("Registered %s.%s service", DOMAIN, SERVICE_TRIGGER_SCAN)

    if not hass.services.has_service(DOMAIN, SERVICE_NVD_REFRESH):
        async def _handle_nvd_refresh(call: ServiceCall) -> None:
            for runtime in hass.data[DOMAIN]["entries"].values():
                await runtime["collector"].async_nvd_refresh()
                await runtime["coordinator"].async_request_refresh()

        hass.services.async_register(
            DOMAIN, SERVICE_NVD_REFRESH, _handle_nvd_refresh, schema=vol.Schema({})
        )
        _LOGGER.info("Registered %s.%s service", DOMAIN, SERVICE_NVD_REFRESH)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    # Persist latest options to file before reload
    all_config = {**entry.data, **entry.options}
    await hass.async_add_executor_job(save_config, hass.config.config_dir, all_config)
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    domain_data = hass.data[DOMAIN]
    runtime = domain_data["entries"].pop(entry.entry_id)
    collector: HomeSecCollector = runtime["collector"]
    await collector.async_stop()

    if not domain_data["entries"]:
        try:
            if domain_data.get("panel_registered"):
                frontend.async_remove_panel(hass, "homesec")
                domain_data["panel_registered"] = False
            hass.services.async_remove(DOMAIN, SERVICE_TRIGGER_SCAN)
            hass.services.async_remove(DOMAIN, SERVICE_NVD_REFRESH)
        finally:
            hass.data.pop(DOMAIN)

    return True
