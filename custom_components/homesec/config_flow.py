from __future__ import annotations

from collections.abc import Mapping

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult

from .storage import load_config
from .const import (
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_ENABLE_NETFLOW_LISTENER,
    CONF_INTERNAL_NETWORKS,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_ENABLE_NETFLOW_LISTENER,
    DEFAULT_INTERNAL_NETWORKS,
    DOMAIN,
    get_entry_value,
)


def _build_schema(defaults: Mapping[str, object]) -> vol.Schema:
    return vol.Schema({
        vol.Required(CONF_BIND_HOST, default=defaults.get(CONF_BIND_HOST, DEFAULT_BIND_HOST)): str,
        vol.Required(CONF_BIND_PORT, default=defaults.get(CONF_BIND_PORT, DEFAULT_BIND_PORT)): int,
        vol.Required(CONF_ENABLE_NETFLOW_LISTENER, default=defaults.get(CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER)): bool,
        vol.Required(CONF_INTERNAL_NETWORKS, default=defaults.get(CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)): str,
    })


class HomeSecConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "HomeSecOptionsFlowHandler":
        return HomeSecOptionsFlowHandler()

    async def async_step_user(self, user_input: dict[str, object] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            await self.async_set_unique_id(f"{user_input[CONF_BIND_HOST]}:{user_input[CONF_BIND_PORT]}")
            self._abort_if_unique_id_configured(updates=user_input)
            return self.async_create_entry(title="Home Security Assistant", data=user_input)

        file_data = await self.hass.async_add_executor_job(
            load_config, self.hass.config.config_dir
        )

        def _d(key, default):
            v = file_data.get(key)
            return v if v is not None and v != "" else default

        schema = _build_schema({
            CONF_BIND_HOST: _d(CONF_BIND_HOST, DEFAULT_BIND_HOST),
            CONF_BIND_PORT: _d(CONF_BIND_PORT, DEFAULT_BIND_PORT),
            CONF_ENABLE_NETFLOW_LISTENER: _d(CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER),
            CONF_INTERNAL_NETWORKS: _d(CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS),
        })
        return self.async_show_form(step_id="user", data_schema=schema)


class HomeSecOptionsFlowHandler(config_entries.OptionsFlow):

    async def async_step_init(self, user_input: dict[str, object] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = _build_schema({
            CONF_BIND_HOST: get_entry_value(self.config_entry, CONF_BIND_HOST, DEFAULT_BIND_HOST),
            CONF_BIND_PORT: get_entry_value(self.config_entry, CONF_BIND_PORT, DEFAULT_BIND_PORT),
            CONF_ENABLE_NETFLOW_LISTENER: get_entry_value(self.config_entry, CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER),
            CONF_INTERNAL_NETWORKS: get_entry_value(self.config_entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS),
        })
        return self.async_show_form(step_id="init", data_schema=schema)
