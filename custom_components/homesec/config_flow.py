from __future__ import annotations

from collections.abc import Mapping

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
    CONF_RETENTION_SUSPICIOUS_HOURS,
    CONF_RETENTION_MALICIOUS_HOURS,
    CONF_HIGH_EGRESS_THRESHOLD,
    CONF_INTERNAL_NETWORKS,
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
    CONF_STATS_TOP_N,
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
    DEFAULT_RETENTION_SUSPICIOUS_HOURS,
    DEFAULT_RETENTION_MALICIOUS_HOURS,
    DEFAULT_HIGH_EGRESS_THRESHOLD,
    DEFAULT_INTERNAL_NETWORKS,
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
    DEFAULT_STATS_TOP_N,
    DEFAULT_VIRUSTOTAL_API_KEY,
    DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    DOMAIN,
    get_entry_value,
)


def _build_schema(defaults: Mapping[str, object]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_BIND_HOST, default=defaults[CONF_BIND_HOST]): str,
            vol.Required(CONF_BIND_PORT, default=defaults[CONF_BIND_PORT]): int,
            vol.Required(CONF_INTERNAL_NETWORKS, default=defaults[CONF_INTERNAL_NETWORKS]): str,
            vol.Required(CONF_SCAN_WINDOW_SECONDS, default=defaults[CONF_SCAN_WINDOW_SECONDS]): int,
            vol.Required(CONF_SCAN_PORT_THRESHOLD, default=defaults[CONF_SCAN_PORT_THRESHOLD]): int,
            vol.Required(CONF_HIGH_EGRESS_THRESHOLD, default=defaults[CONF_HIGH_EGRESS_THRESHOLD]): int,
            vol.Required(CONF_ENABLE_WEBUI, default=defaults[CONF_ENABLE_WEBUI]): bool,
            vol.Required(CONF_ENABLE_SCANNER, default=defaults[CONF_ENABLE_SCANNER]): bool,
            vol.Required(CONF_SCAN_INTERVAL, default=defaults[CONF_SCAN_INTERVAL]): int,
            vol.Optional(CONF_SCAN_PORTS, default=defaults.get(CONF_SCAN_PORTS, DEFAULT_SCAN_PORTS)): str,
            vol.Optional(CONF_SCAN_EXCEPTIONS, default=defaults.get(CONF_SCAN_EXCEPTIONS, DEFAULT_SCAN_EXCEPTIONS)): str,
            vol.Required(CONF_ENABLE_DNS_RESOLUTION, default=defaults[CONF_ENABLE_DNS_RESOLUTION]): bool,
            vol.Optional(CONF_BLACKLIST_URLS, default=defaults.get(CONF_BLACKLIST_URLS, DEFAULT_BLACKLIST_URLS)): str,
            vol.Optional(CONF_VIRUSTOTAL_API_KEY, default=defaults.get(CONF_VIRUSTOTAL_API_KEY, DEFAULT_VIRUSTOTAL_API_KEY)): str,
            vol.Optional(CONF_ABUSEIPDB_API_KEY, default=defaults.get(CONF_ABUSEIPDB_API_KEY, DEFAULT_ABUSEIPDB_API_KEY)): str,
            vol.Optional(CONF_EXTERNAL_IP_RETENTION, default=defaults.get(CONF_EXTERNAL_IP_RETENTION, DEFAULT_EXTERNAL_IP_RETENTION)): int,
            vol.Optional(CONF_RETENTION_SUSPICIOUS_HOURS, default=defaults.get(CONF_RETENTION_SUSPICIOUS_HOURS, DEFAULT_RETENTION_SUSPICIOUS_HOURS)): int,
            vol.Optional(CONF_RETENTION_MALICIOUS_HOURS, default=defaults.get(CONF_RETENTION_MALICIOUS_HOURS, DEFAULT_RETENTION_MALICIOUS_HOURS)): int,
            vol.Optional(CONF_ENRICHMENT_TTL_MINUTES, default=defaults.get(CONF_ENRICHMENT_TTL_MINUTES, DEFAULT_ENRICHMENT_TTL_MINUTES)): int,
            vol.Optional(CONF_VIRUSTOTAL_DAILY_BUDGET, default=defaults.get(CONF_VIRUSTOTAL_DAILY_BUDGET, DEFAULT_VIRUSTOTAL_DAILY_BUDGET)): int,
            vol.Optional(CONF_ABUSEIPDB_DAILY_BUDGET, default=defaults.get(CONF_ABUSEIPDB_DAILY_BUDGET, DEFAULT_ABUSEIPDB_DAILY_BUDGET)): int,
            vol.Optional(CONF_NVD_API_KEY, default=defaults.get(CONF_NVD_API_KEY, DEFAULT_NVD_API_KEY)): str,
            vol.Optional(CONF_NVD_API_URL, default=defaults.get(CONF_NVD_API_URL, DEFAULT_NVD_API_URL)): str,
            vol.Optional(CONF_NVD_TTL_HOURS, default=defaults.get(CONF_NVD_TTL_HOURS, DEFAULT_NVD_TTL_HOURS)): int,
            vol.Optional(CONF_NVD_MIN_YEAR, default=defaults.get(CONF_NVD_MIN_YEAR, DEFAULT_NVD_MIN_YEAR)): int,
            vol.Optional(CONF_NVD_KEYWORDS, default=defaults.get(CONF_NVD_KEYWORDS, DEFAULT_NVD_KEYWORDS)): str,
            vol.Required(CONF_STATS_TOP_N, default=defaults.get(CONF_STATS_TOP_N, DEFAULT_STATS_TOP_N)): vol.All(int, vol.Range(min=3, max=25)),
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

        schema = _build_schema(
            {
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
                CONF_VIRUSTOTAL_API_KEY: DEFAULT_VIRUSTOTAL_API_KEY,
                CONF_ABUSEIPDB_API_KEY: DEFAULT_ABUSEIPDB_API_KEY,
                CONF_EXTERNAL_IP_RETENTION: DEFAULT_EXTERNAL_IP_RETENTION,
                CONF_RETENTION_SUSPICIOUS_HOURS: DEFAULT_RETENTION_SUSPICIOUS_HOURS,
                CONF_RETENTION_MALICIOUS_HOURS: DEFAULT_RETENTION_MALICIOUS_HOURS,
                CONF_ENRICHMENT_TTL_MINUTES: DEFAULT_ENRICHMENT_TTL_MINUTES,
                CONF_VIRUSTOTAL_DAILY_BUDGET: DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
                CONF_ABUSEIPDB_DAILY_BUDGET: DEFAULT_ABUSEIPDB_DAILY_BUDGET,
                CONF_NVD_API_KEY: DEFAULT_NVD_API_KEY,
                CONF_NVD_API_URL: DEFAULT_NVD_API_URL,
                CONF_NVD_TTL_HOURS: DEFAULT_NVD_TTL_HOURS,
                CONF_NVD_MIN_YEAR: DEFAULT_NVD_MIN_YEAR,
                CONF_NVD_KEYWORDS: DEFAULT_NVD_KEYWORDS,
                CONF_STATS_TOP_N: DEFAULT_STATS_TOP_N,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)


class HomeSecOptionsFlowHandler(config_entries.OptionsFlow):

    async def async_step_init(self, user_input: dict[str, object] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = _build_schema(
            {
                CONF_BIND_HOST: get_entry_value(self.config_entry, CONF_BIND_HOST, DEFAULT_BIND_HOST),
                CONF_BIND_PORT: get_entry_value(self.config_entry, CONF_BIND_PORT, DEFAULT_BIND_PORT),
                CONF_INTERNAL_NETWORKS: get_entry_value(self.config_entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS),
                CONF_SCAN_WINDOW_SECONDS: get_entry_value(self.config_entry, CONF_SCAN_WINDOW_SECONDS, DEFAULT_SCAN_WINDOW_SECONDS),
                CONF_SCAN_PORT_THRESHOLD: get_entry_value(self.config_entry, CONF_SCAN_PORT_THRESHOLD, DEFAULT_SCAN_PORT_THRESHOLD),
                CONF_HIGH_EGRESS_THRESHOLD: get_entry_value(self.config_entry, CONF_HIGH_EGRESS_THRESHOLD, DEFAULT_HIGH_EGRESS_THRESHOLD),
                CONF_ENABLE_WEBUI: get_entry_value(self.config_entry, CONF_ENABLE_WEBUI, DEFAULT_ENABLE_WEBUI),
                CONF_ENABLE_SCANNER: get_entry_value(self.config_entry, CONF_ENABLE_SCANNER, DEFAULT_ENABLE_SCANNER),
                CONF_SCAN_INTERVAL: get_entry_value(self.config_entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                CONF_SCAN_PORTS: get_entry_value(self.config_entry, CONF_SCAN_PORTS, DEFAULT_SCAN_PORTS),
                CONF_SCAN_EXCEPTIONS: get_entry_value(self.config_entry, CONF_SCAN_EXCEPTIONS, DEFAULT_SCAN_EXCEPTIONS),
                CONF_ENABLE_DNS_RESOLUTION: get_entry_value(self.config_entry, CONF_ENABLE_DNS_RESOLUTION, DEFAULT_ENABLE_DNS_RESOLUTION),
                CONF_BLACKLIST_URLS: get_entry_value(self.config_entry, CONF_BLACKLIST_URLS, DEFAULT_BLACKLIST_URLS),
                CONF_VIRUSTOTAL_API_KEY: get_entry_value(self.config_entry, CONF_VIRUSTOTAL_API_KEY, DEFAULT_VIRUSTOTAL_API_KEY),
                CONF_ABUSEIPDB_API_KEY: get_entry_value(self.config_entry, CONF_ABUSEIPDB_API_KEY, DEFAULT_ABUSEIPDB_API_KEY),
                CONF_EXTERNAL_IP_RETENTION: get_entry_value(self.config_entry, CONF_EXTERNAL_IP_RETENTION, DEFAULT_EXTERNAL_IP_RETENTION),
                CONF_RETENTION_SUSPICIOUS_HOURS: get_entry_value(self.config_entry, CONF_RETENTION_SUSPICIOUS_HOURS, DEFAULT_RETENTION_SUSPICIOUS_HOURS),
                CONF_RETENTION_MALICIOUS_HOURS: get_entry_value(self.config_entry, CONF_RETENTION_MALICIOUS_HOURS, DEFAULT_RETENTION_MALICIOUS_HOURS),
                CONF_ENRICHMENT_TTL_MINUTES: get_entry_value(self.config_entry, CONF_ENRICHMENT_TTL_MINUTES, DEFAULT_ENRICHMENT_TTL_MINUTES),
                CONF_VIRUSTOTAL_DAILY_BUDGET: get_entry_value(self.config_entry, CONF_VIRUSTOTAL_DAILY_BUDGET, DEFAULT_VIRUSTOTAL_DAILY_BUDGET),
                CONF_ABUSEIPDB_DAILY_BUDGET: get_entry_value(self.config_entry, CONF_ABUSEIPDB_DAILY_BUDGET, DEFAULT_ABUSEIPDB_DAILY_BUDGET),
                CONF_NVD_API_KEY: get_entry_value(self.config_entry, CONF_NVD_API_KEY, DEFAULT_NVD_API_KEY),
                CONF_NVD_API_URL: get_entry_value(self.config_entry, CONF_NVD_API_URL, DEFAULT_NVD_API_URL),
                CONF_NVD_TTL_HOURS: get_entry_value(self.config_entry, CONF_NVD_TTL_HOURS, DEFAULT_NVD_TTL_HOURS),
                CONF_NVD_MIN_YEAR: get_entry_value(self.config_entry, CONF_NVD_MIN_YEAR, DEFAULT_NVD_MIN_YEAR),
                CONF_NVD_KEYWORDS: get_entry_value(self.config_entry, CONF_NVD_KEYWORDS, DEFAULT_NVD_KEYWORDS),
                CONF_STATS_TOP_N: get_entry_value(self.config_entry, CONF_STATS_TOP_N, DEFAULT_STATS_TOP_N),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
