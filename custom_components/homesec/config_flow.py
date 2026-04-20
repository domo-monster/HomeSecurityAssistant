from __future__ import annotations

from collections.abc import Mapping
import ipaddress
from urllib.parse import urlsplit

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult

from .const import (
    CONF_ABUSEIPDB_API_KEY,
    CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_BLACKLIST_URLS,
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_SCANNER,
    CONF_ENABLE_WEBUI,
    CONF_ENRICHMENT_TTL_MINUTES,
    CONF_EXTERNAL_IP_RETENTION,
    CONF_HIGH_EGRESS_THRESHOLD,
    CONF_INTERNAL_NETWORKS,
    CONF_IPINFO_DAILY_BUDGET,
    CONF_IPINFO_TOKEN,
    CONF_SCAN_EXCEPTIONS,
    CONF_SCAN_INTERVAL,
    CONF_SCAN_PORT_THRESHOLD,
    CONF_SCAN_PORTS,
    CONF_SCAN_WINDOW_SECONDS,
    CONF_NVD_API_KEY,
    CONF_NVD_API_URL,
    CONF_NVD_TTL_HOURS,
    CONF_NVD_MIN_YEAR,
    CONF_NVD_KEYWORDS,
    CONF_SHODAN_API_KEY,
    CONF_SHODAN_DAILY_BUDGET,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    DEFAULT_ABUSEIPDB_API_KEY,
    DEFAULT_ABUSEIPDB_DAILY_BUDGET,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_BLACKLIST_URLS,
    DEFAULT_ENABLE_DNS_RESOLUTION,
    DEFAULT_ENABLE_SCANNER,
    DEFAULT_ENABLE_WEBUI,
    DEFAULT_ENRICHMENT_TTL_MINUTES,
    DEFAULT_EXTERNAL_IP_RETENTION,
    DEFAULT_HIGH_EGRESS_THRESHOLD,
    DEFAULT_INTERNAL_NETWORKS,
    DEFAULT_IPINFO_TOKEN,
    DEFAULT_IPINFO_DAILY_BUDGET,
    DEFAULT_SCAN_EXCEPTIONS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SCAN_PORT_THRESHOLD,
    DEFAULT_SCAN_PORTS,
    DEFAULT_SCAN_WINDOW_SECONDS,
    DEFAULT_NVD_API_KEY,
    DEFAULT_NVD_API_URL,
    DEFAULT_NVD_TTL_HOURS,
    DEFAULT_NVD_MIN_YEAR,
    DEFAULT_NVD_KEYWORDS,
    DEFAULT_SHODAN_API_KEY,
    DEFAULT_SHODAN_DAILY_BUDGET,
    DEFAULT_VIRUSTOTAL_API_KEY,
    DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    DOMAIN,
    get_entry_value,
)


_DEFAULT_MAP: dict[str, object] = {
    CONF_BIND_HOST: DEFAULT_BIND_HOST,
    CONF_BIND_PORT: DEFAULT_BIND_PORT,
    CONF_INTERNAL_NETWORKS: DEFAULT_INTERNAL_NETWORKS,
    CONF_SCAN_WINDOW_SECONDS: DEFAULT_SCAN_WINDOW_SECONDS,
    CONF_SCAN_PORT_THRESHOLD: DEFAULT_SCAN_PORT_THRESHOLD,
    CONF_HIGH_EGRESS_THRESHOLD: DEFAULT_HIGH_EGRESS_THRESHOLD,
    CONF_ENABLE_WEBUI: DEFAULT_ENABLE_WEBUI,
    CONF_ENABLE_SCANNER: DEFAULT_ENABLE_SCANNER,
    CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
    CONF_SCAN_PORTS: DEFAULT_SCAN_PORTS,
    CONF_SCAN_EXCEPTIONS: DEFAULT_SCAN_EXCEPTIONS,
    CONF_ENABLE_DNS_RESOLUTION: DEFAULT_ENABLE_DNS_RESOLUTION,
    CONF_BLACKLIST_URLS: DEFAULT_BLACKLIST_URLS,
    CONF_IPINFO_TOKEN: DEFAULT_IPINFO_TOKEN,
    CONF_VIRUSTOTAL_API_KEY: DEFAULT_VIRUSTOTAL_API_KEY,
    CONF_SHODAN_API_KEY: DEFAULT_SHODAN_API_KEY,
    CONF_ABUSEIPDB_API_KEY: DEFAULT_ABUSEIPDB_API_KEY,
    CONF_EXTERNAL_IP_RETENTION: DEFAULT_EXTERNAL_IP_RETENTION,
    CONF_ENRICHMENT_TTL_MINUTES: DEFAULT_ENRICHMENT_TTL_MINUTES,
    CONF_IPINFO_DAILY_BUDGET: DEFAULT_IPINFO_DAILY_BUDGET,
    CONF_VIRUSTOTAL_DAILY_BUDGET: DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    CONF_SHODAN_DAILY_BUDGET: DEFAULT_SHODAN_DAILY_BUDGET,
    CONF_ABUSEIPDB_DAILY_BUDGET: DEFAULT_ABUSEIPDB_DAILY_BUDGET,
    CONF_NVD_API_KEY: DEFAULT_NVD_API_KEY,
    CONF_NVD_API_URL: DEFAULT_NVD_API_URL,
    CONF_NVD_TTL_HOURS: DEFAULT_NVD_TTL_HOURS,
    CONF_NVD_MIN_YEAR: DEFAULT_NVD_MIN_YEAR,
    CONF_NVD_KEYWORDS: DEFAULT_NVD_KEYWORDS,
}


def _validate_bind_host(value: object) -> str:
    text = str(value).strip()
    if not text:
        raise vol.Invalid("bind host cannot be empty")
    try:
        ipaddress.ip_address(text)
    except ValueError as err:
        raise vol.Invalid(f"invalid bind host: {text}") from err
    return text


def _validate_networks(value: object) -> str:
    text = str(value).strip()
    if not text:
        raise vol.Invalid("at least one internal network is required")
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for part in parts:
        try:
            ipaddress.ip_network(part)
        except ValueError as err:
            raise vol.Invalid(f"invalid CIDR: {part}") from err
    return ",".join(parts)


def _validate_ip_list(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for part in parts:
        try:
            ipaddress.ip_address(part)
        except ValueError as err:
            raise vol.Invalid(f"invalid IP address: {part}") from err
    return ",".join(parts)


def _validate_ports(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as err:
                raise vol.Invalid(f"invalid port range: {token}") from err
            if lo < 1 or hi > 65535 or lo > hi:
                raise vol.Invalid(f"port range out of bounds: {token}")
        else:
            try:
                port = int(token)
            except ValueError as err:
                raise vol.Invalid(f"invalid port: {token}") from err
            if port < 1 or port > 65535:
                raise vol.Invalid(f"port out of range: {port}")
    return text


def _validate_urls(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for part in parts:
        parsed = urlsplit(part)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise vol.Invalid(f"invalid URL: {part}")
    return ",".join(parts)


def _validate_port(value: object) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid(f"invalid port: {value!r}") from err
    if port < 1 or port > 65535:
        raise vol.Invalid(f"port out of range: {port}")
    return port


def _positive_int(value: object) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid(f"expected integer, got {value!r}") from err
    if n < 1:
        raise vol.Invalid("must be >= 1")
    return n


def _non_negative_int(value: object) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid(f"expected integer, got {value!r}") from err
    if n < 0:
        raise vol.Invalid("must be >= 0")
    return n


def _build_schema(defaults: Mapping[str, object]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_BIND_HOST, default=defaults[CONF_BIND_HOST]): _validate_bind_host,
            vol.Required(CONF_BIND_PORT, default=defaults[CONF_BIND_PORT]): _validate_port,
            vol.Required(CONF_INTERNAL_NETWORKS, default=defaults[CONF_INTERNAL_NETWORKS]): _validate_networks,
            vol.Required(CONF_SCAN_WINDOW_SECONDS, default=defaults[CONF_SCAN_WINDOW_SECONDS]): _positive_int,
            vol.Required(CONF_SCAN_PORT_THRESHOLD, default=defaults[CONF_SCAN_PORT_THRESHOLD]): _positive_int,
            vol.Required(CONF_HIGH_EGRESS_THRESHOLD, default=defaults[CONF_HIGH_EGRESS_THRESHOLD]): _positive_int,
            vol.Required(CONF_ENABLE_WEBUI, default=defaults[CONF_ENABLE_WEBUI]): bool,
            vol.Required(CONF_ENABLE_SCANNER, default=defaults[CONF_ENABLE_SCANNER]): bool,
            vol.Required(CONF_SCAN_INTERVAL, default=defaults[CONF_SCAN_INTERVAL]): _positive_int,
            vol.Optional(CONF_SCAN_PORTS, default=defaults[CONF_SCAN_PORTS]): _validate_ports,
            vol.Optional(CONF_SCAN_EXCEPTIONS, default=defaults[CONF_SCAN_EXCEPTIONS]): _validate_ip_list,
            vol.Required(CONF_ENABLE_DNS_RESOLUTION, default=defaults[CONF_ENABLE_DNS_RESOLUTION]): bool,
            vol.Optional(CONF_BLACKLIST_URLS, default=defaults[CONF_BLACKLIST_URLS]): _validate_urls,
            vol.Optional(CONF_IPINFO_TOKEN, default=defaults[CONF_IPINFO_TOKEN]): str,
            vol.Optional(CONF_VIRUSTOTAL_API_KEY, default=defaults[CONF_VIRUSTOTAL_API_KEY]): str,
            vol.Optional(CONF_SHODAN_API_KEY, default=defaults[CONF_SHODAN_API_KEY]): str,
            vol.Optional(CONF_ABUSEIPDB_API_KEY, default=defaults[CONF_ABUSEIPDB_API_KEY]): str,
            vol.Optional(CONF_EXTERNAL_IP_RETENTION, default=defaults[CONF_EXTERNAL_IP_RETENTION]): _non_negative_int,
            vol.Optional(CONF_ENRICHMENT_TTL_MINUTES, default=defaults[CONF_ENRICHMENT_TTL_MINUTES]): _positive_int,
            vol.Optional(CONF_IPINFO_DAILY_BUDGET, default=defaults[CONF_IPINFO_DAILY_BUDGET]): _non_negative_int,
            vol.Optional(CONF_VIRUSTOTAL_DAILY_BUDGET, default=defaults[CONF_VIRUSTOTAL_DAILY_BUDGET]): _non_negative_int,
            vol.Optional(CONF_SHODAN_DAILY_BUDGET, default=defaults[CONF_SHODAN_DAILY_BUDGET]): _non_negative_int,
            vol.Optional(CONF_ABUSEIPDB_DAILY_BUDGET, default=defaults[CONF_ABUSEIPDB_DAILY_BUDGET]): _non_negative_int,
            vol.Optional(CONF_NVD_API_KEY, default=defaults[CONF_NVD_API_KEY]): str,
            vol.Optional(CONF_NVD_API_URL, default=defaults[CONF_NVD_API_URL]): _validate_urls,
            vol.Optional(CONF_NVD_TTL_HOURS, default=defaults[CONF_NVD_TTL_HOURS]): _positive_int,
            vol.Optional(CONF_NVD_MIN_YEAR, default=defaults[CONF_NVD_MIN_YEAR]): _non_negative_int,
            vol.Optional(CONF_NVD_KEYWORDS, default=defaults[CONF_NVD_KEYWORDS]): str,
        }
    )


class HomeSecConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "HomeSecOptionsFlowHandler":
        return HomeSecOptionsFlowHandler()

    async def async_step_user(self, user_input: dict[str, object] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            await self.async_set_unique_id(f"{user_input[CONF_BIND_HOST]}:{user_input[CONF_BIND_PORT]}")
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title="Home Security Assistant", data=user_input)

        return self.async_show_form(step_id="user", data_schema=_build_schema(_DEFAULT_MAP))


class HomeSecOptionsFlowHandler(config_entries.OptionsFlow):

    async def async_step_init(self, user_input: dict[str, object] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        defaults = {
            key: get_entry_value(self.config_entry, key, fallback)
            for key, fallback in _DEFAULT_MAP.items()
        }
        return self.async_show_form(step_id="init", data_schema=_build_schema(defaults))
