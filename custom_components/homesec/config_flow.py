from __future__ import annotations

from collections.abc import Mapping
import ipaddress
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult

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


def _build_schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema({
        vol.Required(CONF_BIND_HOST, default=defaults.get(CONF_BIND_HOST, DEFAULT_BIND_HOST)): str,
        vol.Required(CONF_BIND_PORT, default=defaults.get(CONF_BIND_PORT, DEFAULT_BIND_PORT)): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=65535)
        ),
        vol.Required(CONF_ENABLE_NETFLOW_LISTENER, default=defaults.get(CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER)): bool,
        vol.Required(CONF_INTERNAL_NETWORKS, default=defaults.get(CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)): str,
    })


def validate_user_input(user_input: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Normalise setup/options input; returns (clean_input, errors)."""
    errors: dict[str, str] = {}
    clean = dict(user_input)
    host = str(user_input.get(CONF_BIND_HOST, "")).strip()
    try:
        ipaddress.ip_address(host)
        clean[CONF_BIND_HOST] = host
    except ValueError:
        errors[CONF_BIND_HOST] = "invalid_host"
    networks = [n.strip() for n in str(user_input.get(CONF_INTERNAL_NETWORKS, "")).split(",") if n.strip()]
    try:
        if not networks:
            raise ValueError
        for network in networks:
            ipaddress.ip_network(network, strict=False)
        clean[CONF_INTERNAL_NETWORKS] = ",".join(networks)
    except ValueError:
        errors[CONF_INTERNAL_NETWORKS] = "invalid_networks"
    return clean, errors


class HomeSecConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "HomeSecOptionsFlowHandler":
        return HomeSecOptionsFlowHandler()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        errors: dict[str, str] = {}
        if user_input is not None:
            clean, errors = validate_user_input(user_input)
            if not errors:
                return self.async_create_entry(title="Home Security Assistant", data=clean)

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(_build_schema({}), user_input or {}),
            errors=errors,
        )


class HomeSecOptionsFlowHandler(config_entries.OptionsFlow):

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            clean, errors = validate_user_input(user_input)
            if not errors:
                # Keep options set from the Settings page; only update these keys.
                return self.async_create_entry(title="", data={**self.config_entry.options, **clean})

        schema = _build_schema({
            CONF_BIND_HOST: get_entry_value(self.config_entry, CONF_BIND_HOST, DEFAULT_BIND_HOST),
            CONF_BIND_PORT: get_entry_value(self.config_entry, CONF_BIND_PORT, DEFAULT_BIND_PORT),
            CONF_ENABLE_NETFLOW_LISTENER: get_entry_value(self.config_entry, CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER),
            CONF_INTERNAL_NETWORKS: get_entry_value(self.config_entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS),
        })
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
