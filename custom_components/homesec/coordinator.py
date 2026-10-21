from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
import ipaddress
import logging
import socket
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .baseline import BASELINE_MODE_ACTIVE, BASELINE_MODE_DISABLED, BaselineManager
from .const import (
    CONF_ABUSEIPDB_API_KEY,
    CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_BASELINE_EGRESS_MULTIPLIER,
    CONF_BASELINE_ENABLED,
    CONF_BASELINE_MIN_OBSERVATIONS,
    CONF_BASELINE_TRAINING_HOURS,
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_BLACKLIST_URLS,
    CONF_DNS_BLOCKED_CATEGORIES,
    CONF_DNS_LOG_RETENTION_HOURS,
    CONF_DNS_OVERRIDES,
    CONF_DNS_PROXY_BIND_HOST,
    CONF_DNS_PROXY_ENABLED,
    CONF_DNS_PROXY_PORT,
    CONF_DNS_PROXY_UPSTREAM,
    CONF_DNS_WARN_BLOCKED_LOGS,
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_IP_GEOLOCATION,
    CONF_ENABLE_NETFLOW_LISTENER,
    CONF_ENABLE_SCANNER,
    CONF_ENRICHMENT_TTL_MINUTES,
    CONF_EXTERNAL_IP_RETENTION,
    CONF_HIGH_EGRESS_THRESHOLD,
    CONF_INTERNAL_NETWORKS,
    CONF_NETFLOW_ALLOWED_EXPORTERS,
    CONF_NVD_API_KEY,
    CONF_NVD_API_URL,
    CONF_NVD_KEYWORDS,
    CONF_NVD_MIN_YEAR,
    CONF_NVD_TTL_HOURS,
    CONF_RETENTION_MALICIOUS_HOURS,
    CONF_RETENTION_SUSPICIOUS_HOURS,
    CONF_SCAN_EXCEPTIONS,
    CONF_SCAN_INTERVAL,
    CONF_SCAN_PORT_THRESHOLD,
    CONF_SCAN_PORTS,
    CONF_SCAN_WINDOW_SECONDS,
    CONF_SURICATA_ALLOWED_SOURCES,
    CONF_SURICATA_AUTH_TOKEN,
    CONF_SURICATA_LISTENER_ENABLED,
    CONF_SURICATA_LISTENER_HOST,
    CONF_SURICATA_LISTENER_PORT,
    CONF_SURICATA_LOG_RETENTION_HOURS,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    CONF_VT_ABUSEIPDB_THRESHOLD,
    COORDINATOR_INTERVAL_SECONDS,
    DEFAULT_ABUSEIPDB_API_KEY,
    DEFAULT_ABUSEIPDB_DAILY_BUDGET,
    DEFAULT_BASELINE_EGRESS_MULTIPLIER,
    DEFAULT_BASELINE_ENABLED,
    DEFAULT_BASELINE_MIN_OBSERVATIONS,
    DEFAULT_BASELINE_TRAINING_HOURS,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_BLACKLIST_URLS,
    DEFAULT_DNS_BLOCKED_CATEGORIES,
    DEFAULT_DNS_LOG_RETENTION_HOURS,
    DEFAULT_DNS_OVERRIDES,
    DEFAULT_DNS_PROXY_BIND_HOST,
    DEFAULT_DNS_PROXY_ENABLED,
    DEFAULT_DNS_PROXY_PORT,
    DEFAULT_DNS_PROXY_UPSTREAM,
    DEFAULT_DNS_WARN_BLOCKED_LOGS,
    DEFAULT_ENABLE_DNS_RESOLUTION,
    DEFAULT_ENABLE_IP_GEOLOCATION,
    DEFAULT_ENABLE_NETFLOW_LISTENER,
    DEFAULT_ENABLE_SCANNER,
    DEFAULT_ENRICHMENT_TTL_MINUTES,
    DEFAULT_EXTERNAL_IP_RETENTION,
    DEFAULT_HIGH_EGRESS_THRESHOLD,
    DEFAULT_INTERNAL_NETWORKS,
    DEFAULT_NETFLOW_ALLOWED_EXPORTERS,
    DEFAULT_NVD_API_KEY,
    DEFAULT_NVD_API_URL,
    DEFAULT_NVD_KEYWORDS,
    DEFAULT_NVD_MIN_YEAR,
    DEFAULT_NVD_TTL_HOURS,
    DEFAULT_RETENTION_MALICIOUS_HOURS,
    DEFAULT_RETENTION_SUSPICIOUS_HOURS,
    DEFAULT_SCAN_EXCEPTIONS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SCAN_PORT_THRESHOLD,
    DEFAULT_SCAN_PORTS,
    DEFAULT_SCAN_WINDOW_SECONDS,
    DEFAULT_SURICATA_ALLOWED_SOURCES,
    DEFAULT_SURICATA_AUTH_TOKEN,
    DEFAULT_SURICATA_LISTENER_ENABLED,
    DEFAULT_SURICATA_LISTENER_HOST,
    DEFAULT_SURICATA_LISTENER_PORT,
    DEFAULT_SURICATA_LOG_RETENTION_HOURS,
    DEFAULT_VIRUSTOTAL_API_KEY,
    DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    DEFAULT_VT_ABUSEIPDB_THRESHOLD,
    DNS_LOG_MAX_ENTRIES,
    DOMAIN,
    SURICATA_LOG_MAX_ENTRIES,
    get_entry_float,
    get_entry_int,
    get_entry_value,
)
from .dns_proxy import DNSProxyServer
from .dns_resolver import DNSBlacklistChecker
from .enrichment import collect_tracker_enrichment
from .external_enrichment import ExternalIPEnricher
from .fingerprints import HomeSecurityAnalyzer
from .netflow import FlowRecord, NetFlowDatagramProtocol, parse_exporter_allowlist
from .nvd_enrichment import CISAKEVClient, NVDClient
from .scanner import NetworkScanner, parse_scan_ports
from .storage import (
    TIMESERIES_INTERVAL_SECONDS,
    TIMESERIES_MAX_POINTS,
    HomeSecStorage,
)
from .suricata import SuricataAlertListener, parse_allowed_networks, sanitize_stored_record
from .vulnerabilities import match_vulnerabilities

_LOGGER = logging.getLogger(__name__)

# Seconds to coalesce state writes (Store.async_delay_save)
_SAVE_DELAY_SECONDS = 60
_LOG_SAVE_DELAY_SECONDS = 300
_DISMISS_SAVE_DELAY_SECONDS = 1
# Upper bound on external IPs tracked at once (retention 0 means "no expiry")
MAX_TRACKED_EXTERNAL_IPS = 10_000


def _as_bool(value: Any) -> bool:
    """Parse common YAML/UI boolean forms safely."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


class HomeSecCollector:
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: NetFlowDatagramProtocol | None = None
        self._analyzer = HomeSecurityAnalyzer(
            internal_networks=str(get_entry_value(entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)).split(","),
            scan_window_seconds=get_entry_int(entry, CONF_SCAN_WINDOW_SECONDS, DEFAULT_SCAN_WINDOW_SECONDS),
            scan_port_threshold=get_entry_int(entry, CONF_SCAN_PORT_THRESHOLD, DEFAULT_SCAN_PORT_THRESHOLD),
            high_egress_threshold=get_entry_int(entry, CONF_HIGH_EGRESS_THRESHOLD, DEFAULT_HIGH_EGRESS_THRESHOLD),
        )
        self._storage = HomeSecStorage(hass)
        # Keys already announced on the event bus (fired only on transitions)
        self._announced_malicious_ips: set[str] = set()
        self._announced_vulns: set[str] = set()
        # Newest DNS timestamp already fed to baseline training
        self._baseline_dns_cursor: str = ""
        # True once persisted state has been loaded; nothing is saved before
        # that, so a failed setup can never overwrite stored data with empties.
        self._state_loaded = False
        # issue_id -> translation placeholders of currently raised repair issues
        self._active_issues: dict[str, dict[str, str]] = {}
        internal_nets = str(get_entry_value(entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)).split(",")
        scan_interval = get_entry_int(entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        exceptions_raw = str(get_entry_value(entry, CONF_SCAN_EXCEPTIONS, DEFAULT_SCAN_EXCEPTIONS))
        excluded_ips = [ip.strip() for ip in exceptions_raw.split(",") if ip.strip()]
        scan_ports_raw = str(get_entry_value(entry, CONF_SCAN_PORTS, DEFAULT_SCAN_PORTS))
        scan_ports = parse_scan_ports(scan_ports_raw)
        self._scanner = NetworkScanner(
            internal_networks=internal_nets,
            scan_interval_seconds=scan_interval,
            excluded_ips=excluded_ips,
            ports=scan_ports,
            on_scan_complete=self._persist_hosts,
        )
        self._netflow_allowed_exporters = self._parse_exporters(entry)
        self._bind_host = str(get_entry_value(entry, CONF_BIND_HOST, DEFAULT_BIND_HOST))
        self._bind_port = get_entry_int(entry, CONF_BIND_PORT, DEFAULT_BIND_PORT)
        self._netflow_listener_enabled = _as_bool(
            get_entry_value(entry, CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER)
        )
        self._scanner_enabled = _as_bool(get_entry_value(entry, CONF_ENABLE_SCANNER, DEFAULT_ENABLE_SCANNER))

        session = async_get_clientsession(hass)
        blacklist_raw = str(get_entry_value(entry, CONF_BLACKLIST_URLS, DEFAULT_BLACKLIST_URLS))
        import re as _re
        blacklist_urls = [u.strip() for u in _re.split(r"[\n\r,]+", blacklist_raw) if u.strip()]
        enable_dns = bool(get_entry_value(entry, CONF_ENABLE_DNS_RESOLUTION, DEFAULT_ENABLE_DNS_RESOLUTION))
        self._resolver = DNSBlacklistChecker(
            session=session,
            blacklist_urls=blacklist_urls,
            enable_resolution=enable_dns,
        )
        self._enricher = ExternalIPEnricher(
            session=session,
            virustotal_key=str(get_entry_value(entry, CONF_VIRUSTOTAL_API_KEY, DEFAULT_VIRUSTOTAL_API_KEY)) or None,
            abuseipdb_key=str(get_entry_value(entry, CONF_ABUSEIPDB_API_KEY, DEFAULT_ABUSEIPDB_API_KEY)) or None,
            enrichment_ttl_minutes=get_entry_int(entry, CONF_ENRICHMENT_TTL_MINUTES, DEFAULT_ENRICHMENT_TTL_MINUTES),
            vt_abuseipdb_threshold=get_entry_int(entry, CONF_VT_ABUSEIPDB_THRESHOLD, DEFAULT_VT_ABUSEIPDB_THRESHOLD),
            enable_ipwho=_as_bool(
                get_entry_value(entry, CONF_ENABLE_IP_GEOLOCATION, DEFAULT_ENABLE_IP_GEOLOCATION)
            ),
            daily_budgets={
                "virustotal": get_entry_int(entry, CONF_VIRUSTOTAL_DAILY_BUDGET, DEFAULT_VIRUSTOTAL_DAILY_BUDGET),
                "abuseipdb": get_entry_int(entry, CONF_ABUSEIPDB_DAILY_BUDGET, DEFAULT_ABUSEIPDB_DAILY_BUDGET),
            },
        )
        nvd_api_url = str(get_entry_value(entry, CONF_NVD_API_URL, DEFAULT_NVD_API_URL)) or DEFAULT_NVD_API_URL
        nvd_ttl_hours = get_entry_int(entry, CONF_NVD_TTL_HOURS, DEFAULT_NVD_TTL_HOURS)
        nvd_min_year = get_entry_int(entry, CONF_NVD_MIN_YEAR, DEFAULT_NVD_MIN_YEAR)
        nvd_keywords_raw = str(get_entry_value(entry, CONF_NVD_KEYWORDS, DEFAULT_NVD_KEYWORDS))
        nvd_custom_keywords = [k.strip() for k in nvd_keywords_raw.split(",") if k.strip()]
        self._nvd_client = NVDClient(
            session=session,
            api_url=nvd_api_url,
            api_key=str(get_entry_value(entry, CONF_NVD_API_KEY, DEFAULT_NVD_API_KEY) or "").strip() or None,
            ttl_hours=nvd_ttl_hours,
            min_year=nvd_min_year,
            custom_keywords=nvd_custom_keywords,
        )
        self._nvd_ttl_hours = nvd_ttl_hours
        self._kev_client = CISAKEVClient(session=session, ttl_hours=nvd_ttl_hours)
        # Results from the last background NVD fetch: ip -> list[vuln_dict]
        self._nvd_results: dict[str, list[dict[str, Any]]] = {}
        self._nvd_task: asyncio.Task | None = None
        self._nvd_last_fetch_at: datetime | None = None
        self._dismissed_findings: dict[str, str] = {}  # key -> note
        self._started_at: datetime | None = None
        self._ext_ip_last_seen: dict[str, datetime] = {}
        self._ext_ip_first_seen: dict[str, datetime] = {}
        self._ext_ip_sources: dict[str, set[str]] = {}
        self._ext_ip_outbound_sources: dict[str, set[str]] = {}
        self._ext_ip_inbound_sources: dict[str, set[str]] = {}
        self._ext_ip_ports: dict[str, set[int]] = {}
        self._ext_ip_total_octets: dict[str, int] = {}
        self._ext_ip_ratings: dict[str, str] = {}  # ip -> "clean" | "suspicious" | "malicious"
        self._ext_ip_has_outbound: set[str] = set()
        self._ext_ip_has_inbound: set[str] = set()
        self._ext_ip_retention_hours: int = get_entry_int(entry, CONF_EXTERNAL_IP_RETENTION, DEFAULT_EXTERNAL_IP_RETENTION)
        self._retention_suspicious_hours: int = get_entry_int(entry, CONF_RETENTION_SUSPICIOUS_HOURS, DEFAULT_RETENTION_SUSPICIOUS_HOURS)
        self._retention_malicious_hours: int = get_entry_int(entry, CONF_RETENTION_MALICIOUS_HOURS, DEFAULT_RETENTION_MALICIOUS_HOURS)
        self._post_scan_refresh: Callable[[], Coroutine[Any, Any, None]] | None = None
        self._timeseries: list[dict] = []
        self._ts_last_point: datetime | None = None
        self._timeseries_dirty: bool = False
        self._ext_state_dirty: bool = False
        self._suricata_log_dirty: bool = False
        self._baseline_manager = BaselineManager(
            training_hours=get_entry_int(entry, CONF_BASELINE_TRAINING_HOURS, DEFAULT_BASELINE_TRAINING_HOURS),
            min_observations=get_entry_int(entry, CONF_BASELINE_MIN_OBSERVATIONS, DEFAULT_BASELINE_MIN_OBSERVATIONS),
            egress_multiplier=get_entry_float(entry, CONF_BASELINE_EGRESS_MULTIPLIER, DEFAULT_BASELINE_EGRESS_MULTIPLIER),
        )
        self._baseline_enabled = bool(get_entry_value(entry, CONF_BASELINE_ENABLED, DEFAULT_BASELINE_ENABLED))

        # DNS proxy
        self._dns_log: deque = deque(maxlen=DNS_LOG_MAX_ENTRIES)
        self._dns_log_retention_hours: int = get_entry_int(entry, CONF_DNS_LOG_RETENTION_HOURS, DEFAULT_DNS_LOG_RETENTION_HOURS)
        dns_proxy_enabled = bool(get_entry_value(entry, CONF_DNS_PROXY_ENABLED, DEFAULT_DNS_PROXY_ENABLED))
        dns_allowed_subnets = [n.strip() for n in internal_nets if n.strip()]
        blocked_cats_raw = str(get_entry_value(entry, CONF_DNS_BLOCKED_CATEGORIES, DEFAULT_DNS_BLOCKED_CATEGORIES))
        blocked_categories: set[str] = {
            s.strip().lower() for s in _re.split(r"[\n\r,]+", blocked_cats_raw) if s.strip()
        }
        self._dns_warn_blocked_logs = bool(
            get_entry_value(entry, CONF_DNS_WARN_BLOCKED_LOGS, DEFAULT_DNS_WARN_BLOCKED_LOGS)
        )
        if dns_proxy_enabled:
            self._dns_proxy: DNSProxyServer | None = DNSProxyServer(
                host=str(get_entry_value(entry, CONF_DNS_PROXY_BIND_HOST, DEFAULT_DNS_PROXY_BIND_HOST)),
                port=get_entry_int(entry, CONF_DNS_PROXY_PORT, DEFAULT_DNS_PROXY_PORT),
                upstream=str(get_entry_value(entry, CONF_DNS_PROXY_UPSTREAM, DEFAULT_DNS_PROXY_UPSTREAM)),
                checker=self._resolver,
                dns_log=self._dns_log,
                on_malicious=self._on_malicious_dns,
                check_sources=None,
                allowed_subnets=dns_allowed_subnets,
                blocked_categories=blocked_categories or None,
                warn_blocked_logs=self._dns_warn_blocked_logs,
                overrides_raw=str(get_entry_value(entry, CONF_DNS_OVERRIDES, DEFAULT_DNS_OVERRIDES)),
            )
        else:
            self._dns_proxy = None

        # Suricata alert listener
        self._suricata_log: deque = deque(maxlen=SURICATA_LOG_MAX_ENTRIES)
        self._suricata_log_retention_hours: int = get_entry_int(entry, CONF_SURICATA_LOG_RETENTION_HOURS, DEFAULT_SURICATA_LOG_RETENTION_HOURS)
        suricata_enabled = bool(
            get_entry_value(entry, CONF_SURICATA_LISTENER_ENABLED, DEFAULT_SURICATA_LISTENER_ENABLED)
        )
        if suricata_enabled:
            self._suricata_listener: SuricataAlertListener | None = SuricataAlertListener(
                host=str(get_entry_value(entry, CONF_SURICATA_LISTENER_HOST, DEFAULT_SURICATA_LISTENER_HOST)),
                port=get_entry_int(entry, CONF_SURICATA_LISTENER_PORT, DEFAULT_SURICATA_LISTENER_PORT),
                alert_log=self._suricata_log,
                on_alert=self._on_suricata_alert,
                auth_token=str(
                    get_entry_value(entry, CONF_SURICATA_AUTH_TOKEN, DEFAULT_SURICATA_AUTH_TOKEN) or ""
                ),
                allowed_networks=self._parse_networks_option(
                    entry, CONF_SURICATA_ALLOWED_SOURCES, DEFAULT_SURICATA_ALLOWED_SOURCES
                ),
            )
        else:
            self._suricata_listener = None

    @staticmethod
    def _parse_networks_option(entry: ConfigEntry, key: str, default: str) -> list:
        raw = get_entry_value(entry, key, default)
        try:
            return parse_allowed_networks(str(raw or ""))
        except ValueError as err:
            _LOGGER.warning("Ignoring invalid %s value %r: %s", key, raw, err)
            return []

    async def _async_own_ips(self) -> set[str]:
        """Addresses of this Home Assistant host (never worth scanning)."""
        try:
            from homeassistant.components import network  # noqa: PLC0415

            adapters = await network.async_get_adapters(self.hass)
        except Exception:  # noqa: BLE001 - network integration unavailable
            _LOGGER.debug("Could not read network adapters", exc_info=True)
            return set()
        own: set[str] = set()
        for adapter in adapters:
            for info in adapter.get("ipv4", []) + adapter.get("ipv6", []):
                if info.get("address"):
                    own.add(str(info["address"]))
        return own

    def _parse_exporters(self, entry: ConfigEntry) -> list:
        raw = get_entry_value(entry, CONF_NETFLOW_ALLOWED_EXPORTERS, DEFAULT_NETFLOW_ALLOWED_EXPORTERS)
        try:
            return parse_exporter_allowlist(str(raw or ""))
        except ValueError as err:
            _LOGGER.warning("Ignoring invalid NetFlow exporter allowlist %r: %s", raw, err)
            return []

    async def _async_start_netflow_listener(self) -> None:
        loop = asyncio.get_running_loop()
        self._protocol = NetFlowDatagramProtocol(
            self._handle_records, allowed_exporters=self._netflow_allowed_exporters
        )
        if not self._netflow_allowed_exporters:
            _LOGGER.warning(
                "HomeSec NetFlow listener accepts flows from any sender. Set "
                "'Allowed NetFlow Exporters' to your router's address."
            )
        family = socket.AF_INET6 if ":" in self._bind_host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._bind_host, self._bind_port))
        except OSError as exc:
            sock.close()
            _LOGGER.error(
                "HomeSec could not bind NetFlow listener on %s:%d - %s. "
                "Check whether another process already owns UDP port %d, "
                "or change the bind port in integration options.",
                self._bind_host,
                self._bind_port,
                exc,
                self._bind_port,
            )
            raise
        sock.setblocking(False)
        protocol = self._protocol
        transport, _ = await loop.create_datagram_endpoint(lambda: protocol, sock=sock)
        self._transport = transport
        _LOGGER.info(
            "Home Security Assistant listening for NetFlow v5/v9/IPFIX on %s:%s",
            self._bind_host,
            self._bind_port,
        )

    async def _async_stop_netflow_listener(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._protocol = None

    async def async_start(self) -> None:
        self._started_at = datetime.now(UTC)
        startup_started = time.monotonic()

        def _log_step(step: str, started_at: float) -> None:
            _LOGGER.debug(
                "Home Security Assistant startup step %s took %.3f s",
                step,
                time.monotonic() - started_at,
            )

        if self._netflow_listener_enabled:
            step_started = time.monotonic()
            await self._async_start_netflow_listener()
            _log_step("netflow listener setup", step_started)
        else:
            await self._async_stop_netflow_listener()
            _LOGGER.info("NetFlow listener disabled by configuration")

        step_started = time.monotonic()
        persisted_hosts = await self._storage.async_load("hosts", {})
        if persisted_hosts:
            self._scanner.load_hosts(persisted_hosts)
            _LOGGER.info("Restored %d previously discovered hosts", len(persisted_hosts))
        _log_step("load discovered hosts", step_started)

        step_started = time.monotonic()
        persisted_dismissed = await self._storage.async_load("dismissed", {})
        if persisted_dismissed:
            self._dismissed_findings.update(
                {str(k): str(v or "") for k, v in persisted_dismissed.items() if k}
            )
            _LOGGER.info("Restored %d dismissed findings", len(persisted_dismissed))
        _log_step("load dismissed findings", step_started)

        step_started = time.monotonic()
        ts_data = [
            p for p in await self._storage.async_load("timeseries", [])
            if isinstance(p, dict) and "ts" in p
        ][-TIMESERIES_MAX_POINTS:]
        if ts_data:
            self._timeseries = ts_data
            try:
                self._ts_last_point = datetime.fromisoformat(ts_data[-1]["ts"])
            except (ValueError, TypeError, KeyError):
                pass
            _LOGGER.info("Restored %d timeseries points", len(ts_data))
        _log_step("load timeseries", step_started)

        # Restore persistent DNS log (filtered to configured retention window)
        step_started = time.monotonic()
        dns_data = [
            e for e in await self._storage.async_load("dns_log", [])
            if isinstance(e, dict) and isinstance(e.get("timestamp"), str)
        ]
        if dns_data:
            if self._dns_log_retention_hours > 0:
                cutoff = (datetime.now(UTC) - timedelta(hours=self._dns_log_retention_hours)).isoformat()
                dns_data = [e for e in dns_data if e.get("timestamp", "") >= cutoff]
            for entry in dns_data:
                self._dns_log.append(entry)
            _LOGGER.info("Restored %d DNS log entries", len(dns_data))
        _log_step("load dns log", step_started)

        # Restore persistent external IP tracking state
        step_started = time.monotonic()
        ext_ip_data = [
            e for e in await self._storage.async_load("ext_ips", [])
            if isinstance(e, dict) and e.get("ip")
        ]
        if ext_ip_data:
            now_ext = datetime.now(UTC)
            for rec in ext_ip_data:
                ip = rec.get("ip", "")
                if not ip:
                    continue
                ls = rec.get("last_seen")
                try:
                    self._ext_ip_last_seen[ip] = datetime.fromisoformat(str(ls)) if ls else now_ext
                except (ValueError, TypeError):
                    self._ext_ip_last_seen[ip] = now_ext
                fs = rec.get("first_seen")
                try:
                    self._ext_ip_first_seen[ip] = datetime.fromisoformat(str(fs)) if fs else self._ext_ip_last_seen[ip]
                except (ValueError, TypeError):
                    self._ext_ip_first_seen[ip] = self._ext_ip_last_seen[ip]
                sources = rec.get("sources")
                if isinstance(sources, list):
                    self._ext_ip_sources[ip] = set(sources)
                outbound_sources = rec.get("outbound_sources")
                if isinstance(outbound_sources, list):
                    self._ext_ip_outbound_sources[ip] = set(outbound_sources)
                inbound_sources = rec.get("inbound_sources")
                if isinstance(inbound_sources, list):
                    self._ext_ip_inbound_sources[ip] = set(inbound_sources)
                ports = rec.get("ports")
                if isinstance(ports, list):
                    self._ext_ip_ports[ip] = {int(p) for p in ports if p is not None}
                rating = rec.get("rating")
                if rating:
                    self._ext_ip_ratings[ip] = str(rating)
                direction = rec.get("direction", "outbound")
                if direction in ("outbound", "both"):
                    self._ext_ip_has_outbound.add(ip)
                if direction in ("inbound", "both"):
                    self._ext_ip_has_inbound.add(ip)
                try:
                    total_octets = int(rec.get("total_octets", 0) or 0)
                except (TypeError, ValueError):
                    total_octets = 0
                if total_octets > 0:
                    self._ext_ip_total_octets[ip] = total_octets
            _LOGGER.info("Restored %d external IP tracking entries", len(ext_ip_data))
        _log_step("load external ip state", step_started)

        # Restore enrichment usage counters (daily provider budgets)
        step_started = time.monotonic()
        # Downloaded data from the previous run: blocking and CVE matching work
        # immediately, and nothing is fetched again before its TTL expires.
        self._resolver.import_state(await self._storage.async_load("blocklists", {}))
        self._nvd_client.import_state(await self._storage.async_load("nvd_cache", {}))
        self._kev_client.import_state(await self._storage.async_load("kev_catalog", {}))
        self._enricher.import_cache(await self._storage.async_load("enrichment_cache", {}))
        _log_step("load downloaded data", step_started)
        step_started = time.monotonic()

        enr_state = await self._storage.async_load("enrichment_state", {})
        if enr_state:
            self._enricher.import_usage_state(enr_state)
            _LOGGER.info("Restored external enrichment usage state")
        _log_step("load enrichment state", step_started)

        step_started = time.monotonic()
        baseline_state = await self._storage.async_load("baseline", {})
        if baseline_state:
            self._baseline_manager.load_state(baseline_state)
            _LOGGER.info("Restored baseline training state")
        _log_step("load baseline state", step_started)

        step_started = time.monotonic()
        self._scanner.exclude_ips(await self._async_own_ips())
        if self._scanner_enabled:
            await self._scanner.async_start()
            _LOGGER.info("Home Security Assistant active network scanner started")
        _log_step("scanner startup", step_started)

        step_started = time.monotonic()
        await self._resolver.async_start()
        await self._enricher.async_start()
        if self._dns_proxy is not None:
            await self._dns_proxy.async_start()
        _log_step("resolver enrichment dns proxy startup", step_started)

        # Restore persisted Suricata alert log
        step_started = time.monotonic()
        suricata_data = [
            rec for rec in (
                sanitize_stored_record(e)
                for e in await self._storage.async_load("suricata_log", [])
            )
            if rec is not None
        ]
        if suricata_data:
            if self._suricata_log_retention_hours > 0:
                cutoff = (
                    datetime.now(UTC) - timedelta(hours=self._suricata_log_retention_hours)
                ).isoformat()
                suricata_data = [e for e in suricata_data if e.get("timestamp", "") >= cutoff]
            for _se in suricata_data:
                self._suricata_log.append(_se)
            _LOGGER.info("Restored %d Suricata alert log entries", len(suricata_data))
            self._suricata_log_dirty = False

        event_state = await self._storage.async_load("event_state", {})
        self._announced_malicious_ips = set(event_state.get("malicious_ips", []) or [])
        self._announced_vulns = set(event_state.get("vulnerabilities", []) or [])
        self._state_loaded = True
        if self._suricata_listener is not None:
            try:
                await self._suricata_listener.async_start()
            except OSError as err:
                # Reported as a repair issue; the rest of the integration runs.
                _LOGGER.error(
                    "HomeSec Suricata listener could not bind %s:%s - %s",
                    self._suricata_listener.stats()["host"],
                    self._suricata_listener.stats()["port"],
                    err,
                )
        _log_step("load suricata log and listener startup", step_started)

        self._nvd_task = self.entry.async_create_background_task(
            self.hass, self._nvd_background_loop(), name="homesec_nvd_background"
        )
        self._nvd_task.add_done_callback(self._nvd_task_done)
        _LOGGER.info(
            "Home Security Assistant collector startup completed in %.3f s",
            time.monotonic() - startup_started,
        )

    def _nvd_task_done(self, task: asyncio.Task) -> None:
        """Log unhandled exceptions from the NVD background task."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error("NVD background task crashed: %s", exc)

    def _on_malicious_dns(self, src_ip: str, domain: str, qtype: str, hit: dict) -> None:
        """Called by DNSProxyProtocol when a queried domain matches the threat-intel blacklist."""
        if self._dns_warn_blocked_logs:
            _LOGGER.warning(
                "HomeSec DNS proxy: malicious domain query from %s — %s (%s) matched %s",
                src_ip, domain, qtype, hit.get("source", "threat_intel"),
            )
        self.hass.bus.async_fire(
            f"{DOMAIN}_malicious_dns",
            {
                "src_ip": src_ip,
                "domain": domain,
                "qtype": qtype,
                "source": hit.get("source", "threat_intel"),
                "indicator": hit.get("indicator", domain),
            },
        )

    def _on_suricata_alert(self, record: dict) -> None:
        """Called when a new Suricata alert is received; fires an HA event for severity 1 alerts."""
        self._suricata_log_dirty = True
        if record.get("severity") == 1:
            self.hass.bus.async_fire(
                f"{DOMAIN}_suricata_alert",
                {
                    "src_ip": record.get("src_ip", ""),
                    "dest_ip": record.get("dest_ip", ""),
                    "signature": record.get("signature", ""),
                    "category": record.get("category", ""),
                    "severity": record.get("severity"),
                    "action": record.get("action", ""),
                },
            )

    def update_repair_issues(self) -> None:
        """Raise or clear repair issues for problems the user should act on."""
        wanted: dict[str, tuple[ir.IssueSeverity, dict[str, str]]] = {}
        if self._dns_proxy is not None and not self._dns_proxy.running:
            stats = self._dns_proxy.stats()
            wanted["dns_proxy_not_running"] = (
                ir.IssueSeverity.ERROR,
                {"host": str(stats["host"]), "port": str(stats["port"])},
            )
        if self._suricata_listener is not None:
            stats = self._suricata_listener.stats()
            placeholders = {"host": str(stats["host"]), "port": str(stats["port"])}
            if not stats["running"]:
                wanted["suricata_not_running"] = (ir.IssueSeverity.ERROR, placeholders)
            elif not stats["auth_required"] and not stats.get("allowlist"):
                wanted["suricata_unauthenticated"] = (ir.IssueSeverity.WARNING, placeholders)
        if self._transport is not None and not self._netflow_allowed_exporters:
            wanted["netflow_open_listener"] = (
                ir.IssueSeverity.WARNING,
                {"host": self._bind_host, "port": str(self._bind_port)},
            )
        blocklists = self._resolver.stats()
        if (
            blocklists["sources"]
            and blocklists["last_refresh"]
            and not blocklists["bad_domains"]
            and not blocklists["bad_ips"]
        ):
            wanted["blocklist_empty"] = (ir.IssueSeverity.WARNING, {})

        for issue_id in self._active_issues - wanted.keys():
            ir.async_delete_issue(self.hass, DOMAIN, issue_id)
        for issue_id, (severity, placeholders) in wanted.items():
            if self._active_issues.get(issue_id) == placeholders:
                continue
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=severity,
                translation_key=issue_id,
                translation_placeholders=placeholders,
            )
        self._active_issues = {k: v for k, (_, v) in wanted.items()}

    def clear_repair_issues(self) -> None:
        for issue_id in list(self._active_issues):
            ir.async_delete_issue(self.hass, DOMAIN, issue_id)
        self._active_issues = {}

    async def async_stop(self) -> None:
        self.clear_repair_issues()
        # Write all state now (pending delayed saves would otherwise be lost
        # when the entry is reloaded) before tearing down services.
        await self.async_save_all()

        if self._nvd_task is not None:
            self._nvd_task.cancel()
            self._nvd_task = None
        if self._suricata_listener is not None:
            await self._suricata_listener.async_stop()
        if self._dns_proxy is not None:
            await self._dns_proxy.async_stop()
        await self._async_stop_netflow_listener()
        await self._scanner.async_stop()
        await self._resolver.async_stop()
        await self._enricher.async_stop()

    async def async_apply_entry_update(self, entry: ConfigEntry) -> None:
        """Apply updated config-entry options in-place to avoid full teardown/reload."""
        self.entry = entry

        new_bind_host = str(get_entry_value(entry, CONF_BIND_HOST, DEFAULT_BIND_HOST))
        new_bind_port = get_entry_int(entry, CONF_BIND_PORT, DEFAULT_BIND_PORT)
        new_netflow_enabled = _as_bool(
            get_entry_value(entry, CONF_ENABLE_NETFLOW_LISTENER, DEFAULT_ENABLE_NETFLOW_LISTENER)
        )
        new_scanner_enabled = _as_bool(get_entry_value(entry, CONF_ENABLE_SCANNER, DEFAULT_ENABLE_SCANNER))
        new_exporters = self._parse_exporters(entry)

        internal_nets_raw = str(get_entry_value(entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS))
        internal_nets = [n.strip() for n in internal_nets_raw.split(",") if n.strip()]
        try:
            parsed_nets = [ipaddress.ip_network(n) for n in internal_nets]
            self._scanner._internal_networks = parsed_nets
            self._analyzer._internal_networks = parsed_nets
        except ValueError as exc:
            _LOGGER.warning("HomeSec: invalid internal networks update ignored: %s", exc)

        self._dns_log_retention_hours = get_entry_int(entry, CONF_DNS_LOG_RETENTION_HOURS, DEFAULT_DNS_LOG_RETENTION_HOURS)
        self._suricata_log_retention_hours = get_entry_int(entry, CONF_SURICATA_LOG_RETENTION_HOURS, DEFAULT_SURICATA_LOG_RETENTION_HOURS)
        self._resolver._enable_resolution = bool(
            get_entry_value(entry, CONF_ENABLE_DNS_RESOLUTION, DEFAULT_ENABLE_DNS_RESOLUTION)
        )

        netflow_rebind_required = (
            new_bind_host != self._bind_host
            or new_bind_port != self._bind_port
            or new_exporters != self._netflow_allowed_exporters
        )
        self._netflow_allowed_exporters = new_exporters
        if not new_netflow_enabled:
            await self._async_stop_netflow_listener()
        elif self._transport is None or not self._netflow_listener_enabled or netflow_rebind_required:
            await self._async_stop_netflow_listener()
            self._bind_host = new_bind_host
            self._bind_port = new_bind_port
            await self._async_start_netflow_listener()
        self._bind_host = new_bind_host
        self._bind_port = new_bind_port
        self._netflow_listener_enabled = new_netflow_enabled

        if new_scanner_enabled and not self._scanner_enabled:
            await self._scanner.async_start()
        elif not new_scanner_enabled and self._scanner_enabled:
            await self._scanner.async_stop()
        self._scanner_enabled = new_scanner_enabled

    async def async_trigger_scan(self) -> None:
        """Run an immediate active scan cycle outside the normal schedule."""
        await self._scanner.async_trigger_scan()

    async def async_refresh_blacklist(self) -> None:
        """Force-clear and re-download all threat-intel blocklist URLs immediately."""
        await self._resolver.async_force_refresh()

    async def async_nvd_refresh(self) -> None:
        """Flush the NVD CVE cache and restart the background fetch loop immediately."""
        self._nvd_client.invalidate_cache()
        self._nvd_results.clear()
        if self._nvd_task is not None:
            self._nvd_task.cancel()
        self._nvd_task = self.entry.async_create_background_task(
            self.hass, self._nvd_background_loop(), name="homesec_nvd_background"
        )
        self._nvd_task.add_done_callback(self._nvd_task_done)
        _LOGGER.info("NVD cache cleared — background re-fetch started")

    async def async_start_baseline_training(self) -> None:
        self._baseline_manager.start_training()
        self._baseline_enabled = True
        self._baseline_dns_cursor = self._newest_dns_timestamp()
        await self._storage.async_save("baseline", self._baseline_manager.export_state())
        self._baseline_manager.mark_clean()

    async def async_stop_baseline_training(self) -> None:
        self._baseline_manager.stop_training()
        await self._storage.async_save("baseline", self._baseline_manager.export_state())
        self._baseline_manager.mark_clean()

    async def async_clear_baseline(self) -> None:
        self._baseline_manager.clear()
        await self._storage.async_remove("baseline")
        self._baseline_manager.mark_clean()

    async def async_retrain_baseline(self) -> None:
        self._baseline_manager.retrain()
        self._baseline_enabled = True
        self._baseline_dns_cursor = self._newest_dns_timestamp()
        await self._storage.async_save("baseline", self._baseline_manager.export_state())
        self._baseline_manager.mark_clean()

    def _newest_dns_timestamp(self) -> str:
        return str(self._dns_log[-1].get("timestamp", "")) if self._dns_log else ""

    def _dns_entries_since(self, cursor: str) -> list[dict]:
        """DNS entries newer than *cursor* (log is in arrival order)."""
        newer: list[dict] = []
        for entry in reversed(self._dns_log):
            if str(entry.get("timestamp", "")) <= cursor:
                break
            newer.append(entry)
        newer.reverse()
        return newer

    async def _nvd_background_loop(self) -> None:
        """Background task: re-fetch NVD CVEs for all known services periodically."""
        retry_delay = 60  # seconds between retries while waiting for scan data
        while True:
            try:
                # Collect service names detected across all scanned hosts
                scan_results = self._scanner.snapshot_as_dicts()
                hosts_with_services = [
                    h for h in scan_results
                    if h.get("open_ports")
                ]
                active_services: set[str] = set()
                for h in hosts_with_services:
                    for svc in h.get("open_ports", []):
                        svc_name = str(svc.get("service_name", "")).lower()
                        if svc_name:
                            active_services.add(svc_name)
                # Pre-fetch NVD keywords for configured + detected services
                await self._nvd_client.prefetch_all_keywords(active_services)
                # Fetch CISA KEV catalog
                await self._kev_client.fetch()
                if not hosts_with_services:
                    _LOGGER.debug("NVD background loop: no scan results yet, retrying in %ds", retry_delay)
                    self._nvd_last_fetch_at = datetime.now(UTC)
                    await asyncio.sleep(retry_delay)
                    continue
                new_results: dict[str, list[dict[str, Any]]] = {}
                for host in hosts_with_services:
                    ip = str(host.get("ip", ""))
                    services = host.get("open_ports", [])
                    try:
                        vulns = await self._nvd_client.find_vulnerabilities(ip, services)
                        if vulns:
                            new_results[ip] = vulns
                    except Exception as exc:  # noqa: BLE001
                        _LOGGER.debug("NVD background fetch failed for %s: %s", ip, exc)
                self._nvd_results = new_results
                self._nvd_last_fetch_at = datetime.now(UTC)
                total_vulns = sum(len(v) for v in new_results.values())
                _LOGGER.info(
                    "NVD background fetch complete: %d hosts with CVEs, %d total findings, %d CVEs in cache",
                    len(new_results), total_vulns, self._nvd_client.total_cached_cves,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("NVD background loop error: %s", exc)
            await asyncio.sleep(self._nvd_ttl_hours * 3600)

    def snapshot(self) -> dict[str, Any]:
        enrichment_by_ip = collect_tracker_enrichment(self.hass)
        listener_stats = self._protocol.snapshot_stats() if self._protocol is not None else {}

        self._scanner.set_observed_ips(self._analyzer.get_observed_ips())

        scan_results = self._scanner.snapshot_as_dicts()
        vuln_findings = self._build_vuln_findings(scan_results)

        payload = self._analyzer.snapshot(
            enrichment_by_ip=enrichment_by_ip,
            listener_stats=listener_stats,
            scan_results=scan_results,
            vuln_findings=vuln_findings,
            alive_hosts=self._scanner.get_alive_hosts(),
            dismissed_findings=set(self._dismissed_findings),
        )

        if self._baseline_enabled or self._baseline_manager._mode != BASELINE_MODE_DISABLED:
            live_connections = list(payload.get("connections", []))
            new_dns = self._dns_entries_since(self._baseline_dns_cursor)
            if new_dns:
                self._baseline_dns_cursor = str(new_dns[-1].get("timestamp", ""))
            self._baseline_manager.observe_snapshot(
                devices=list(payload.get("devices", [])),
                dns_log=new_dns,
                scan_results=scan_results,
                vulnerabilities=vuln_findings,
                connections=live_connections,
            )
            # Anomaly findings
            anomalies = self._baseline_manager.get_anomalies(
                devices=list(payload.get("devices", [])),
                dns_log=list(self._dns_log),
                scan_results=scan_results,
                vulnerabilities=vuln_findings,
            )
            payload["baseline"] = self._baseline_manager.status_snapshot()
            payload["baseline_graph"] = self._baseline_manager.graph_snapshot()
            payload["baseline_anomalies"] = anomalies
            # Merge anomalies into findings
            if anomalies:
                payload["findings"].extend(anomalies)
        else:
            payload["baseline"] = self._baseline_manager.status_snapshot()
            payload["baseline_graph"] = self._baseline_manager.graph_snapshot()
            payload["baseline_anomalies"] = []

        # Filter out dismissed findings, keep them separately (with notes)
        findings = payload.get("findings", [])
        payload["findings"] = [f for f in findings if f.get("key") not in self._dismissed_findings]
        dismissed_list = []
        for f in findings:
            if f.get("key") in self._dismissed_findings:
                f = dict(f)
                f["dismiss_note"] = self._dismissed_findings.get(f["key"], "")
                dismissed_list.append(f)
        payload["dismissed_findings"] = dismissed_list

        # Collect unique external IPs from device peers + connections
        now = datetime.now(UTC)
        ext_state_changed = False
        external_ips: dict[str, dict[str, Any]] = {}
        multicast_ips: dict[str, dict[str, Any]] = {}
        external_ip_traffic: dict[str, dict[str, int]] = {}

        def _bump_ext_traffic(ip: str, flows: int = 0, octets: int = 0) -> None:
            if not ip:
                return
            totals = external_ip_traffic.setdefault(ip, {"total_flows": 0, "total_octets": 0})
            totals["total_flows"] += max(0, int(flows or 0))
            totals["total_octets"] += max(0, int(octets or 0))

        for device in payload.get("devices", []):
            device_ip = str(device.get("ip", ""))
            for ext_ip in device.get("external_peers", []):
                if ext_ip not in external_ips:
                    self._enricher.queue_ip(ext_ip)
                    self._resolver.queue_resolve(ext_ip)
                    external_ips[ext_ip] = self._build_ext_ip_entry(ext_ip)
                    # Only initialise last_seen / first_seen if not already recorded by _handle_records
                    if ext_ip not in self._ext_ip_last_seen:
                        self._ext_ip_last_seen[ext_ip] = now
                        ext_state_changed = True
                    if ext_ip not in self._ext_ip_first_seen:
                        self._ext_ip_first_seen[ext_ip] = now
                        ext_state_changed = True
                if device_ip:
                    srcs = self._ext_ip_sources.setdefault(ext_ip, set())
                    before = len(srcs)
                    srcs.add(device_ip)
                    if len(srcs) != before:
                        ext_state_changed = True
                    self._ext_ip_outbound_sources.setdefault(ext_ip, set()).add(device_ip)
                if ext_ip not in self._ext_ip_has_outbound:
                    self._ext_ip_has_outbound.add(ext_ip)
                    ext_state_changed = True
        for conn in payload.get("connections", []):
            target_kind = conn.get("target_kind", "")
            if target_kind == "multicast":
                mc_ip = str(conn["target"])
                source_ip = str(conn.get("source", ""))
                if mc_ip not in multicast_ips:
                    multicast_ips[mc_ip] = self._build_multicast_entry(mc_ip)
                if source_ip:
                    multicast_ips[mc_ip].setdefault("internal_sources", [])
                    if source_ip not in multicast_ips[mc_ip]["internal_sources"]:
                        multicast_ips[mc_ip]["internal_sources"].append(source_ip)
            elif target_kind == "external":
                ext_ip = str(conn["target"])
                source_ip = str(conn.get("source", ""))
                dst_port = conn.get("dst_port")
                _bump_ext_traffic(ext_ip, conn.get("flows", 1), conn.get("octets", 0))
                if ext_ip not in external_ips:
                    self._enricher.queue_ip(ext_ip)
                    self._resolver.queue_resolve(ext_ip)
                    external_ips[ext_ip] = self._build_ext_ip_entry(ext_ip)
                    if ext_ip not in self._ext_ip_last_seen:
                        self._ext_ip_last_seen[ext_ip] = now
                        ext_state_changed = True
                    if ext_ip not in self._ext_ip_first_seen:
                        self._ext_ip_first_seen[ext_ip] = now
                        ext_state_changed = True
                if source_ip:
                    srcs = self._ext_ip_sources.setdefault(ext_ip, set())
                    before = len(srcs)
                    srcs.add(source_ip)
                    if len(srcs) != before:
                        ext_state_changed = True
                    self._ext_ip_outbound_sources.setdefault(ext_ip, set()).add(source_ip)
                if dst_port:
                    ports = self._ext_ip_ports.setdefault(ext_ip, set())
                    before = len(ports)
                    ports.add(int(dst_port))
                    if len(ports) != before:
                        ext_state_changed = True
                if ext_ip not in self._ext_ip_has_outbound:
                    self._ext_ip_has_outbound.add(ext_ip)
                    ext_state_changed = True
            elif target_kind == "internal" and conn.get("source_kind") == "external":
                ext_ip = str(conn.get("source", ""))
                target_ip = str(conn.get("target", ""))
                if ext_ip:
                    _bump_ext_traffic(ext_ip, conn.get("flows", 1), conn.get("octets", 0))
                    if ext_ip not in external_ips:
                        self._enricher.queue_ip(ext_ip)
                        self._resolver.queue_resolve(ext_ip)
                        external_ips[ext_ip] = self._build_ext_ip_entry(ext_ip)
                        if ext_ip not in self._ext_ip_last_seen:
                            self._ext_ip_last_seen[ext_ip] = now
                            ext_state_changed = True
                        if ext_ip not in self._ext_ip_first_seen:
                            self._ext_ip_first_seen[ext_ip] = now
                            ext_state_changed = True
                    if target_ip:
                        srcs = self._ext_ip_sources.setdefault(ext_ip, set())
                        before = len(srcs)
                        srcs.add(target_ip)
                        if len(srcs) != before:
                            ext_state_changed = True
                        self._ext_ip_inbound_sources.setdefault(ext_ip, set()).add(target_ip)
                    if ext_ip not in self._ext_ip_has_inbound:
                        self._ext_ip_has_inbound.add(ext_ip)
                        ext_state_changed = True

        # Include previously-seen external IPs that are still within the retention window.
        # Update severity tracking from freshly built entries so pruning uses current ratings.
        for ip, entry in external_ips.items():
            blacklisted = bool(entry.get("blacklisted", False))
            rating = str(entry.get("rating") or "")
            if blacklisted or rating == "malicious":
                if self._ext_ip_ratings.get(ip) != "malicious":
                    ext_state_changed = True
                self._ext_ip_ratings[ip] = "malicious"
            elif rating == "suspicious":
                if self._ext_ip_ratings.get(ip) != "suspicious":
                    ext_state_changed = True
                self._ext_ip_ratings[ip] = "suspicious"
            else:
                if self._ext_ip_ratings.get(ip) != "clean":
                    ext_state_changed = True
                self._ext_ip_ratings[ip] = "clean"

        stale = []
        for ip, ts in self._ext_ip_last_seen.items():
            severity = self._ext_ip_ratings.get(ip, "clean")
            if severity == "malicious":
                h = self._retention_malicious_hours
            elif severity == "suspicious":
                h = self._retention_suspicious_hours
            else:
                h = self._ext_ip_retention_hours
            if h > 0 and ts < now - timedelta(hours=h):
                stale.append(ip)
        # Hard cap regardless of retention: evict least recently seen IPs,
        # clean ones before suspicious/malicious ones.
        overflow = len(self._ext_ip_last_seen) - len(stale) - MAX_TRACKED_EXTERNAL_IPS
        if overflow > 0:
            stale_set = set(stale)
            severity_rank = {"clean": 0, "suspicious": 1, "malicious": 2}
            candidates = sorted(
                (ip for ip in self._ext_ip_last_seen if ip not in stale_set),
                key=lambda ip: (
                    severity_rank.get(self._ext_ip_ratings.get(ip, "clean"), 0),
                    self._ext_ip_last_seen[ip],
                ),
            )
            stale.extend(candidates[:overflow])
        for ip in stale:
            self._ext_ip_last_seen.pop(ip, None)
            self._ext_ip_first_seen.pop(ip, None)
            self._ext_ip_sources.pop(ip, None)
            self._ext_ip_outbound_sources.pop(ip, None)
            self._ext_ip_inbound_sources.pop(ip, None)
            self._ext_ip_ports.pop(ip, None)
            self._ext_ip_ratings.pop(ip, None)
            self._ext_ip_has_outbound.discard(ip)
            self._ext_ip_has_inbound.discard(ip)
            self._ext_ip_total_octets.pop(ip, None)
            external_ips.pop(ip, None)
            ext_state_changed = True
        # Add retained IPs not in current snapshot
        for ip in self._ext_ip_last_seen:
            if ip not in external_ips:
                external_ips[ip] = self._build_ext_ip_entry(ip)

        # Attach last_seen, first_seen, and internal_sources to each entry
        for ip, entry_data in external_ips.items():
            last_ts = self._ext_ip_last_seen.get(ip)
            first_ts = self._ext_ip_first_seen.get(ip)
            entry_data["last_seen"] = last_ts.isoformat() if last_ts else None
            entry_data["first_seen"] = first_ts.isoformat() if first_ts else None
            traffic = external_ip_traffic.get(ip, {})
            entry_data["total_flows"] = int(traffic.get("total_flows", 0) or 0)
            curr_octets = int(traffic.get("total_octets", 0) or 0)
            prev_octets = int(self._ext_ip_total_octets.get(ip, 0) or 0)
            if curr_octets > 0 and curr_octets != prev_octets:
                self._ext_ip_total_octets[ip] = curr_octets
                ext_state_changed = True
            entry_data["total_octets"] = int(self._ext_ip_total_octets.get(ip, 0) or 0)
            entry_data["internal_sources"] = sorted(self._ext_ip_sources.get(ip, set()))
            entry_data["dst_ports"] = sorted(self._ext_ip_ports.get(ip, set()))
            _is_out = ip in self._ext_ip_has_outbound
            _is_in = ip in self._ext_ip_has_inbound
            entry_data["direction"] = "both" if (_is_out and _is_in) else ("inbound" if _is_in else "outbound")
            if _is_out and _is_in:
                _out_srcs = self._ext_ip_outbound_sources.get(ip, set())
                _in_srcs = self._ext_ip_inbound_sources.get(ip, set())
                entry_data["direction_alert"] = _out_srcs.isdisjoint(_in_srcs)
            else:
                entry_data["direction_alert"] = False

        payload["external_ips"] = sorted(
            external_ips.values(), key=lambda x: x.get("ip", "")
        )
        payload["multicast_ips"] = sorted(
            multicast_ips.values(), key=lambda x: x.get("ip", "")
        )
        payload["blacklist_stats"] = self._resolver.stats()
        payload["collector_started_at"] = self._started_at.isoformat() if self._started_at else None
        payload["enrichment_stats"] = self._enricher.enrichment_stats()
        # The DNS and Suricata logs are served on demand by the HTTP API, not
        # copied into coordinator data every refresh.
        self._purge_dns_log()
        payload["dns_log_size"] = len(self._dns_log)
        payload["dns_proxy_stats"] = self._dns_proxy.stats() if self._dns_proxy is not None else {"running": False}
        self._purge_suricata_log()
        payload["suricata_log_size"] = len(self._suricata_log)
        payload["suricata_stats"] = (
            self._suricata_listener.stats() if self._suricata_listener is not None else {"running": False}
        )
        nvd_ts = self._nvd_last_fetch_at
        payload["nvd_last_updated"] = nvd_ts.isoformat() if nvd_ts else None
        payload["nvd_ttl_hours"] = self._nvd_client._ttl_hours
        payload["nvd_total_cves"] = self._nvd_client.total_cached_cves
        payload["nvd_vuln_count"] = sum(len(v) for v in self._nvd_results.values())
        payload["nvd_keywords"] = self._nvd_client.cached_keywords
        payload["nvd_min_year"] = self._nvd_client._min_year
        payload["kev_total"] = self._kev_client.total
        payload["kev_ttl_hours"] = self._kev_client.ttl_hours
        kev_ts = self._kev_client.fetched_at
        payload["kev_last_updated"] = kev_ts.isoformat() if kev_ts else None
        payload["netflow_listener_enabled"] = self._netflow_listener_enabled

        if ext_state_changed:
            self._ext_state_dirty = True

        # Record timeseries point every TIMESERIES_INTERVAL_SECONDS
        _ts_now = datetime.now(UTC)
        if self._ts_last_point is None or (_ts_now - self._ts_last_point).total_seconds() >= TIMESERIES_INTERVAL_SECONDS:
            # Compute baseline deviance score (0-100) for this snapshot
            _deviance_score = 0
            if self._baseline_manager._mode == BASELINE_MODE_ACTIVE:
                _bg = self._baseline_manager.graph_snapshot()
                _base_edge_keys = {
                    (e["source"], e["target"])
                    for e in _bg.get("edges", [])
                    if e.get("source") and e.get("target")
                }
                _live_edge_keys: set = set()
                for _c in payload.get("connections", []):
                    _s, _t = _c.get("source", ""), _c.get("target", "")
                    if _s and _t:
                        _live_edge_keys.add((_s, _t))
                _cnt_new = len(_live_edge_keys - _base_edge_keys)
                _cnt_both = len(_live_edge_keys & _base_edge_keys)
                _cnt_missing = len(_base_edge_keys - _live_edge_keys)
                _active_live = _cnt_new + _cnt_both
                _total_known = _cnt_both + _cnt_missing
                _new_ratio = _cnt_new / _active_live if _active_live else 0.0
                _miss_ratio = _cnt_missing / _total_known if _total_known else 0.0
                _deviance_score = min(100, round(_new_ratio * 80 + _miss_ratio * 20))
            # Count DNS queries logged since the previous timeseries point
            _ts_cutoff_str = self._ts_last_point.isoformat() if self._ts_last_point else ""
            _dns_total = _dns_blocked = _dns_malicious = 0
            for _de in self._dns_entries_since(_ts_cutoff_str):
                _dns_total += 1
                if _de.get("malicious"):
                    _dns_malicious += 1
                if _de.get("status") == "blocked":
                    _dns_blocked += 1
            self._timeseries.append({
                "ts": _ts_now.isoformat(),
                "ext_ips": len(external_ips),
                "hosts": len(payload.get("devices", [])),
                "scanned": int(payload.get("scanned_devices", 0) or 0),
                "deviance_score": _deviance_score,
                "dns_total": _dns_total,
                "dns_blocked": _dns_blocked,
                "dns_malicious": _dns_malicious,
            })
            if len(self._timeseries) > TIMESERIES_MAX_POINTS:
                del self._timeseries[: len(self._timeseries) - TIMESERIES_MAX_POINTS]
            self._ts_last_point = _ts_now
            self._timeseries_dirty = True

        self._fire_transition_events(payload)

        return payload

    def _fire_transition_events(self, payload: dict[str, Any]) -> None:
        """Fire bus events only for newly malicious IPs and newly found vulnerabilities.

        Keys stay announced while the condition persists; once it clears the
        key is forgotten, so a recurrence is announced again.
        """
        current_ips: dict[str, dict] = {}
        for ext in payload.get("external_ips", []):
            if ext.get("blacklisted") or ext.get("rating") == "malicious":
                current_ips[str(ext.get("ip"))] = ext
        current_vulns: dict[str, dict] = {}
        for finding in payload.get("findings", []):
            if finding.get("severity") in ("critical", "high") and finding.get("category") == "vulnerability":
                details = finding.get("details", {}) or {}
                key = f"{finding.get('source_ip')}:{details.get('port')}:{details.get('cve_id')}"
                current_vulns[key] = finding

        for ip in current_ips.keys() - self._announced_malicious_ips:
            ext = current_ips[ip]
            self.hass.bus.async_fire(
                f"{DOMAIN}_malicious_ip",
                {
                    "ip": ext.get("ip"),
                    "hostname": ext.get("hostname"),
                    "country": ext.get("country"),
                    "org": ext.get("org"),
                    "blacklist_info": ext.get("blacklist_info"),
                    "internal_sources": ext.get("internal_sources", []),
                },
            )
        for key in current_vulns.keys() - self._announced_vulns:
            finding = current_vulns[key]
            details = finding.get("details", {}) or {}
            self.hass.bus.async_fire(
                f"{DOMAIN}_critical_vulnerability",
                {
                    "host_ip": finding.get("source_ip"),
                    "cve_id": details.get("cve_id"),
                    "severity": finding.get("severity"),
                    "cvss": details.get("cvss"),
                    "service": details.get("service"),
                    "summary": finding.get("summary"),
                    "port": details.get("port"),
                },
            )
        new_ips = set(current_ips)
        new_vulns = set(current_vulns)
        if new_ips != self._announced_malicious_ips or new_vulns != self._announced_vulns:
            self._announced_malicious_ips = new_ips
            self._announced_vulns = new_vulns
            self._storage.async_delay_save(
                "event_state", self._event_state_data, _SAVE_DELAY_SECONDS
            )

    def _event_state_data(self) -> dict[str, list[str]]:
        return {
            "malicious_ips": sorted(self._announced_malicious_ips),
            "vulnerabilities": sorted(self._announced_vulns),
        }

    async def _persist_hosts(self, hosts: dict[str, dict]) -> None:
        """Save discovered hosts after each scan cycle."""
        self._storage.async_delay_save("hosts", lambda: hosts, _DISMISS_SAVE_DELAY_SECONDS)
        if self._post_scan_refresh is not None:
            await self._post_scan_refresh()

    def dns_log_snapshot(self) -> list[dict]:
        """Return a snapshot of the DNS query ring buffer."""
        return list(self._dns_log)

    def clear_blocked_dns_log(self) -> int:
        """Remove all blocked/malicious entries from the DNS log. Returns count removed."""
        before = len(self._dns_log)
        keep = [e for e in self._dns_log if not (e.get("malicious") or e.get("status") == "blocked")]
        self._dns_log.clear()
        for e in keep:
            self._dns_log.append(e)
        return before - len(self._dns_log)

    def _purge_dns_log(self) -> None:
        """Remove DNS log entries older than the configured retention window."""
        if not self._dns_log or self._dns_log_retention_hours == 0:
            return
        cutoff = (datetime.now(UTC) - timedelta(hours=self._dns_log_retention_hours)).isoformat()
        while self._dns_log and self._dns_log[0].get("timestamp", "") < cutoff:
            self._dns_log.popleft()

    def _purge_suricata_log(self) -> None:
        """Remove Suricata alert log entries older than the configured retention window."""
        if not self._suricata_log or self._suricata_log_retention_hours == 0:
            return
        cutoff = (
            datetime.now(UTC) - timedelta(hours=self._suricata_log_retention_hours)
        ).isoformat()
        removed = False
        while self._suricata_log and self._suricata_log[0].get("timestamp", "") < cutoff:
            self._suricata_log.popleft()
            removed = True
        if removed:
            self._suricata_log_dirty = True

    def dns_proxy_stats(self) -> dict:
        """Return DNS proxy status stats."""
        if self._dns_proxy is not None:
            return self._dns_proxy.stats()
        return {"running": False}

    def suricata_stats(self) -> dict:
        """Return Suricata listener status stats."""
        if self._suricata_listener is not None:
            return self._suricata_listener.stats()
        return {"running": False}

    def suricata_log_snapshot(self) -> list[dict]:
        """Return a snapshot of the Suricata alert ring buffer."""
        return list(self._suricata_log)

    def dismiss_finding(self, key: str, note: str = "") -> None:
        self._dismissed_findings[key] = note
        self._storage.async_delay_save(
            "dismissed", lambda: dict(self._dismissed_findings), _DISMISS_SAVE_DELAY_SECONDS
        )

    def undismiss_finding(self, key: str) -> None:
        self._dismissed_findings.pop(key, None)
        self._storage.async_delay_save(
            "dismissed", lambda: dict(self._dismissed_findings), _DISMISS_SAVE_DELAY_SECONDS
        )

    @property
    def storage(self) -> HomeSecStorage:
        return self._storage

    def _build_ext_ip_entry(self, ip: str) -> dict[str, Any]:
        enrichment = self._enricher.get(ip)
        hostname = self._resolver.get_hostname(ip)
        blacklist = self._resolver.check(ip)
        hostname_threat = self._resolver.check(hostname) if hostname else None
        threat = blacklist or hostname_threat
        entry: dict[str, Any] = {
            "ip": ip,
            "hostname": hostname,
            "blacklisted": threat is not None,
            "blacklist_info": threat,
            **enrichment,
        }
        if threat is not None:
            entry["rating"] = "malicious"
            source_label = threat.get("source", "threat_intel") if isinstance(threat, dict) else "threat_intel"
            entry["rating_source"] = f"Blacklist: {source_label}"
        return entry

    @staticmethod
    def _build_multicast_entry(ip: str) -> dict[str, Any]:
        """Build a lightweight entry for a multicast destination (no enrichment)."""
        import ipaddress as _ip
        try:
            addr = _ip.ip_address(ip)
        except ValueError:
            return {"ip": ip, "label": "Multicast group", "kind": "multicast", "internal_sources": []}
        # Well-known multicast group labels (v4 + v6)
        _KNOWN: dict[str, str] = {
            "224.0.0.1": "All Hosts",
            "224.0.0.2": "All Routers",
            "224.0.0.5": "OSPF All Routers",
            "224.0.0.6": "OSPF Designated Routers",
            "224.0.0.9": "RIPv2 Routers",
            "224.0.0.22": "IGMP",
            "224.0.0.251": "mDNS",
            "224.0.0.252": "LLMNR",
            "239.255.255.250": "SSDP / UPnP",
            "239.255.255.253": "SLPv2",
            "ff02::1": "All Nodes (link-local)",
            "ff02::2": "All Routers (link-local)",
            "ff02::5": "OSPFv3 All Routers",
            "ff02::6": "OSPFv3 Designated Routers",
            "ff02::9": "RIPng Routers",
            "ff02::16": "MLDv2",
            "ff02::fb": "mDNSv6",
            "ff02::1:2": "DHCPv6 Relay/Server",
            "ff02::1:3": "LLMNRv6",
        }
        label = _KNOWN.get(ip, "")
        if not label:
            if isinstance(addr, _ip.IPv6Address):
                if addr in _ip.ip_network("ff02::/16"):
                    label = "Link-local multicast (v6)"
                elif addr in _ip.ip_network("ff05::/16"):
                    label = "Site-local multicast (v6)"
                elif addr in _ip.ip_network("ff0e::/16"):
                    label = "Global multicast (v6)"
                else:
                    label = "Multicast group (v6)"
            else:
                if addr in _ip.ip_network("239.0.0.0/8"):
                    label = "Admin-scoped multicast"
                elif addr in _ip.ip_network("224.0.0.0/24"):
                    label = "Local network control"
                else:
                    label = "Multicast group"
        return {
            "ip": ip,
            "label": label,
            "kind": "multicast",
            "internal_sources": [],
        }

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """On-demand enrichment + DNS lookup for a specific IP (used by the lookup endpoint)."""
        hostname = await self._resolver.resolve(ip)
        enrichment = await self._enricher.enrich_now(ip)
        blacklist = self._resolver.check(ip)
        hostname_threat = self._resolver.check(hostname) if hostname else None
        threat = blacklist or hostname_threat
        entry: dict[str, Any] = {
            "ip": ip,
            "hostname": hostname,
            "blacklisted": threat is not None,
            "blacklist_info": threat,
            **enrichment,
        }
        if threat is not None:
            entry["rating"] = "malicious"
            source_label = threat.get("source", "threat_intel") if isinstance(threat, dict) else "threat_intel"
            entry["rating_source"] = f"Blacklist: {source_label}"
        return entry

    def _build_vuln_findings(self, scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        all_vulns: list[dict[str, Any]] = []
        nvd_seen: set[str] = set()
        for host in scan_results:
            ip = str(host.get("ip", ""))
            services = host.get("open_ports", [])
            if not services:
                continue
            # Static rule database
            for m in match_vulnerabilities(ip, services):
                vuln_dict = m.as_dict()
                vuln_dict["host_ip"] = ip
                all_vulns.append(vuln_dict)
                nvd_seen.add(f"{ip}:{m.port}:{m.cve_id}")
            # NVD results from last background fetch (non-blocking)
            for v in self._nvd_results.get(ip, []):
                dedup = f"{ip}:{v.get('port', 0)}:{v.get('cve_id', '')}"
                if dedup not in nvd_seen:
                    nvd_seen.add(dedup)
                    all_vulns.append(v)
        return all_vulns

    def _handle_records(self, records: list[FlowRecord]) -> None:
        self._analyzer.ingest(records)
        # Update last_seen for external IPs appearing in live flow records
        now = datetime.now(UTC)
        is_internal = self._analyzer._is_internal
        is_multicast = self._analyzer._is_multicast
        for rec in records:
            src_internal = is_internal(rec.src_ip)
            dst_internal = is_internal(rec.dst_ip)
            if not src_internal and dst_internal and not is_multicast(rec.src_ip):
                ip = str(rec.src_ip)
                if ip not in self._ext_ip_first_seen:
                    self._ext_ip_first_seen[ip] = now
                    self._ext_state_dirty = True
                prev = self._ext_ip_last_seen.get(ip)
                self._ext_ip_last_seen[ip] = now
                if prev != now:
                    self._ext_state_dirty = True
            elif src_internal and not dst_internal and not is_multicast(rec.dst_ip):
                ip = str(rec.dst_ip)
                if ip not in self._ext_ip_first_seen:
                    self._ext_ip_first_seen[ip] = now
                    self._ext_state_dirty = True
                prev = self._ext_ip_last_seen.get(ip)
                self._ext_ip_last_seen[ip] = now
                if prev != now:
                    self._ext_state_dirty = True

    def _external_state_snapshot(self) -> list[dict[str, Any]]:
        return [
            {
                "ip": ip,
                "last_seen": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "first_seen": (
                    self._ext_ip_first_seen[ip].isoformat()
                    if ip in self._ext_ip_first_seen and isinstance(self._ext_ip_first_seen[ip], datetime)
                    else None
                ),
                "internal_sources": sorted(self._ext_ip_sources.get(ip, set())),
                "sources": sorted(self._ext_ip_sources.get(ip, set())),
                "outbound_sources": sorted(self._ext_ip_outbound_sources.get(ip, set())),
                "inbound_sources": sorted(self._ext_ip_inbound_sources.get(ip, set())),
                "ports": sorted(int(p) for p in self._ext_ip_ports.get(ip, set())),
                "rating": self._ext_ip_ratings.get(ip, "clean"),
                "total_octets": int(self._ext_ip_total_octets.get(ip, 0) or 0),
                "direction": (
                    "both" if (ip in self._ext_ip_has_outbound and ip in self._ext_ip_has_inbound)
                    else "inbound" if ip in self._ext_ip_has_inbound
                    else "outbound"
                ),
            }
            for ip, ts in self._ext_ip_last_seen.items()
        ]

    def schedule_persist(self) -> None:
        """Schedule (coalesced) saves for every piece of state that changed."""
        if not self._state_loaded:
            return
        if self._ext_state_dirty:
            self._ext_state_dirty = False
            self._storage.async_delay_save("ext_ips", self._external_state_snapshot, _SAVE_DELAY_SECONDS)
        for name, client, export in (
            ("blocklists", self._resolver, self._resolver.export_state),
            ("nvd_cache", self._nvd_client, self._nvd_client.export_state),
            ("kev_catalog", self._kev_client, self._kev_client.export_state),
        ):
            if client.is_state_dirty:
                client.mark_state_clean()
                self._storage.async_delay_save(name, export, _LOG_SAVE_DELAY_SECONDS)
        if self._enricher.is_cache_dirty:
            self._enricher.mark_cache_clean()
            self._storage.async_delay_save("enrichment_cache", self._enricher.export_cache, _LOG_SAVE_DELAY_SECONDS)
        if self._enricher.is_usage_state_dirty():
            self._enricher.mark_usage_state_clean()
            self._storage.async_delay_save(
                "enrichment_state", self._enricher.export_usage_state, _SAVE_DELAY_SECONDS
            )
        if self._baseline_manager.is_dirty:
            self._baseline_manager.mark_clean()
            self._storage.async_delay_save(
                "baseline", self._baseline_manager.export_state, _SAVE_DELAY_SECONDS
            )
        if self._suricata_log_dirty:
            self._suricata_log_dirty = False
            self._storage.async_delay_save(
                "suricata_log", lambda: list(self._suricata_log), _SAVE_DELAY_SECONDS
            )
        if self._timeseries_dirty:
            self._timeseries_dirty = False
            self._storage.async_delay_save(
                "timeseries", lambda: list(self._timeseries), _LOG_SAVE_DELAY_SECONDS
            )
            # The DNS log changes constantly; save it on the timeseries cadence.
            self._storage.async_delay_save(
                "dns_log", lambda: list(self._dns_log), _LOG_SAVE_DELAY_SECONDS
            )

    async def async_save_all(self) -> None:
        """Write every piece of state immediately (used on unload)."""
        if not self._state_loaded:
            return
        saves = {
            "dns_log": list(self._dns_log),
            "suricata_log": list(self._suricata_log),
            "timeseries": list(self._timeseries),
            "ext_ips": self._external_state_snapshot(),
            "enrichment_state": self._enricher.export_usage_state(),
            "dismissed": dict(self._dismissed_findings),
            "hosts": self._scanner.get_hosts_as_dicts(),
            "event_state": self._event_state_data(),
            "blocklists": self._resolver.export_state(),
            "nvd_cache": self._nvd_client.export_state(),
            "kev_catalog": self._kev_client.export_state(),
            "enrichment_cache": self._enricher.export_cache(),
        }
        if self._baseline_manager._mode != BASELINE_MODE_DISABLED or self._baseline_manager.is_dirty:
            saves["baseline"] = self._baseline_manager.export_state()
        for name, data in saves.items():
            try:
                await self._storage.async_save(name, data)
            except Exception:  # noqa: BLE001
                _LOGGER.warning("Failed to save HomeSec %s state", name, exc_info=True)
        self._ext_state_dirty = False
        self._timeseries_dirty = False
        self._suricata_log_dirty = False
        self._enricher.mark_usage_state_clean()
        self._baseline_manager.mark_clean()


class HomeSecCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, collector: HomeSecCollector, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(seconds=COORDINATOR_INTERVAL_SECONDS),
        )
        self.collector = collector
        collector._post_scan_refresh = self.async_request_refresh

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            result = self.collector.snapshot()
            self.collector.update_repair_issues()
            self.collector.schedule_persist()
            return result
        except Exception as err:
            raise UpdateFailed(f"Snapshot failed: {err}") from err
