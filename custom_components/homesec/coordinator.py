from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable, Coroutine
from typing import Any
from datetime import datetime, timedelta, timezone
import logging
import socket

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_ABUSEIPDB_API_KEY,
    CONF_ABUSEIPDB_DAILY_BUDGET,
    CONF_BIND_HOST,
    CONF_BIND_PORT,
    CONF_BLACKLIST_URLS,
    CONF_DNS_PROXY_ENABLED,
    CONF_DNS_PROXY_PORT,
    CONF_DNS_PROXY_UPSTREAM,
    CONF_DNS_LOG_RETENTION_HOURS,
    CONF_DNS_PROXY_CHECK_SOURCES,
    CONF_DNS_BLOCKED_CATEGORIES,
    CONF_DNS_OVERRIDES,
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_SCANNER,
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
    CONF_NVD_API_URL,
    CONF_NVD_TTL_HOURS,
    CONF_NVD_MIN_YEAR,
    CONF_NVD_KEYWORDS,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    CONF_VT_ABUSEIPDB_THRESHOLD,
    COORDINATOR_INTERVAL_SECONDS,
    DEFAULT_ABUSEIPDB_API_KEY,
    DEFAULT_ABUSEIPDB_DAILY_BUDGET,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_BLACKLIST_URLS,
    DEFAULT_DNS_PROXY_ENABLED,
    DEFAULT_DNS_PROXY_PORT,
    DEFAULT_DNS_PROXY_UPSTREAM,
    DEFAULT_DNS_LOG_RETENTION_HOURS,
    DEFAULT_DNS_PROXY_CHECK_SOURCES,
    DEFAULT_DNS_BLOCKED_CATEGORIES,
    DEFAULT_DNS_OVERRIDES,
    DEFAULT_ENABLE_DNS_RESOLUTION,
    DEFAULT_ENABLE_SCANNER,
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
    DEFAULT_NVD_API_URL,
    DEFAULT_NVD_TTL_HOURS,
    DEFAULT_NVD_MIN_YEAR,
    DEFAULT_NVD_KEYWORDS,
    DEFAULT_VIRUSTOTAL_API_KEY,
    DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    DEFAULT_VT_ABUSEIPDB_THRESHOLD,
    DOMAIN,
    get_entry_value,
)
from .dns_resolver import DNSBlacklistChecker
from .dns_proxy import DNSProxyServer, DNS_LOG_MAX
from .enrichment import collect_tracker_enrichment
from .external_enrichment import ExternalIPEnricher
from .fingerprints import HomeSecurityAnalyzer
from .netflow import FlowRecord, NetFlowDatagramProtocol
from .nvd_enrichment import NVDClient, CISAKEVClient
from .scanner import NetworkScanner, parse_scan_ports
from .storage import (
    load_discovered_hosts, save_discovered_hosts,
    load_dismissed_findings, save_dismissed_findings,
    load_timeseries, save_timeseries, TIMESERIES_INTERVAL_SECONDS,
    load_dns_log, save_dns_log,
    load_ext_ips, save_ext_ips,
    load_enrichment_state, save_enrichment_state,
)
from .vulnerabilities import match_vulnerabilities

_LOGGER = logging.getLogger(__name__)


class HomeSecCollector:
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: NetFlowDatagramProtocol | None = None
        self._analyzer = HomeSecurityAnalyzer(
            internal_networks=str(get_entry_value(entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)).split(","),
            scan_window_seconds=int(get_entry_value(entry, CONF_SCAN_WINDOW_SECONDS, DEFAULT_SCAN_WINDOW_SECONDS)),
            scan_port_threshold=int(get_entry_value(entry, CONF_SCAN_PORT_THRESHOLD, DEFAULT_SCAN_PORT_THRESHOLD)),
            high_egress_threshold=int(get_entry_value(entry, CONF_HIGH_EGRESS_THRESHOLD, DEFAULT_HIGH_EGRESS_THRESHOLD)),
        )
        self._config_dir: str = hass.config.config_dir
        internal_nets = str(get_entry_value(entry, CONF_INTERNAL_NETWORKS, DEFAULT_INTERNAL_NETWORKS)).split(",")
        scan_interval = int(get_entry_value(entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
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
        self._scanner_enabled = bool(get_entry_value(entry, CONF_ENABLE_SCANNER, DEFAULT_ENABLE_SCANNER))

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
            enrichment_ttl_minutes=int(get_entry_value(entry, CONF_ENRICHMENT_TTL_MINUTES, DEFAULT_ENRICHMENT_TTL_MINUTES)),
            vt_abuseipdb_threshold=int(get_entry_value(entry, CONF_VT_ABUSEIPDB_THRESHOLD, DEFAULT_VT_ABUSEIPDB_THRESHOLD)),
            daily_budgets={
                "virustotal": int(get_entry_value(entry, CONF_VIRUSTOTAL_DAILY_BUDGET, DEFAULT_VIRUSTOTAL_DAILY_BUDGET)),
                "abuseipdb": int(get_entry_value(entry, CONF_ABUSEIPDB_DAILY_BUDGET, DEFAULT_ABUSEIPDB_DAILY_BUDGET)),
            },
        )
        nvd_api_url = str(get_entry_value(entry, CONF_NVD_API_URL, DEFAULT_NVD_API_URL)) or DEFAULT_NVD_API_URL
        nvd_ttl_hours = int(get_entry_value(entry, CONF_NVD_TTL_HOURS, DEFAULT_NVD_TTL_HOURS))
        nvd_min_year = int(get_entry_value(entry, CONF_NVD_MIN_YEAR, DEFAULT_NVD_MIN_YEAR))
        nvd_keywords_raw = str(get_entry_value(entry, CONF_NVD_KEYWORDS, DEFAULT_NVD_KEYWORDS))
        nvd_custom_keywords = [k.strip() for k in nvd_keywords_raw.split(",") if k.strip()]
        self._nvd_client = NVDClient(
            session=session,
            api_url=nvd_api_url,
            api_key=None,
            ttl_hours=nvd_ttl_hours,
            min_year=nvd_min_year,
            custom_keywords=nvd_custom_keywords,
        )
        self._nvd_ttl_hours = nvd_ttl_hours
        self._kev_client = CISAKEVClient(session=session, ttl_hours=nvd_ttl_hours)
        # Results from the last background NVD fetch: ip -> list[vuln_dict]
        self._nvd_results: dict[str, list[dict[str, object]]] = {}
        self._nvd_task: asyncio.Task | None = None
        self._nvd_last_fetch_at: datetime | None = None
        self._dismissed_findings: dict[str, str] = {}  # key -> note
        self._started_at: datetime | None = None
        self._ext_ip_last_seen: dict[str, datetime] = {}
        self._ext_ip_first_seen: dict[str, datetime] = {}
        self._ext_ip_sources: dict[str, set[str]] = {}
        self._ext_ip_ports: dict[str, set[int]] = {}
        self._ext_ip_ratings: dict[str, str] = {}  # ip -> "clean" | "suspicious" | "malicious"
        self._ext_ip_retention_hours: int = int(
            get_entry_value(entry, CONF_EXTERNAL_IP_RETENTION, DEFAULT_EXTERNAL_IP_RETENTION)
        )
        self._retention_suspicious_hours: int = int(
            get_entry_value(entry, CONF_RETENTION_SUSPICIOUS_HOURS, DEFAULT_RETENTION_SUSPICIOUS_HOURS)
        )
        self._retention_malicious_hours: int = int(
            get_entry_value(entry, CONF_RETENTION_MALICIOUS_HOURS, DEFAULT_RETENTION_MALICIOUS_HOURS)
        )
        self._post_scan_refresh: Callable[[], Coroutine[Any, Any, None]] | None = None
        self._timeseries: list[dict] = []
        self._ts_last_point: datetime | None = None
        self._timeseries_dirty: bool = False
        self._ext_state_dirty: bool = False
        self._runtime_state_last_save: datetime | None = None

        # DNS proxy
        self._dns_log: deque = deque(maxlen=DNS_LOG_MAX)
        self._dns_log_retention_hours: int = int(
            get_entry_value(entry, CONF_DNS_LOG_RETENTION_HOURS, DEFAULT_DNS_LOG_RETENTION_HOURS)
        )
        dns_proxy_enabled = bool(get_entry_value(entry, CONF_DNS_PROXY_ENABLED, DEFAULT_DNS_PROXY_ENABLED))
        check_sources_raw = str(get_entry_value(entry, CONF_DNS_PROXY_CHECK_SOURCES, DEFAULT_DNS_PROXY_CHECK_SOURCES))
        def _to_hostname(s: str) -> str:
            """Accept either a bare hostname or a full URL and return just the hostname."""
            s = s.strip()
            if s.startswith("http://") or s.startswith("https://"):
                return s.split("/")[2]
            return s
        check_sources: set[str] | None = (
            {_to_hostname(s) for s in _re.split(r"[\n\r,]+", check_sources_raw) if s.strip()} or None
        )
        blocked_cats_raw = str(get_entry_value(entry, CONF_DNS_BLOCKED_CATEGORIES, DEFAULT_DNS_BLOCKED_CATEGORIES))
        blocked_categories: set[str] = {
            s.strip().lower() for s in _re.split(r"[\n\r,]+", blocked_cats_raw) if s.strip()
        }
        if dns_proxy_enabled:
            self._dns_proxy: DNSProxyServer | None = DNSProxyServer(
                host=str(get_entry_value(entry, CONF_BIND_HOST, DEFAULT_BIND_HOST)),
                port=int(get_entry_value(entry, CONF_DNS_PROXY_PORT, DEFAULT_DNS_PROXY_PORT)),
                upstream=str(get_entry_value(entry, CONF_DNS_PROXY_UPSTREAM, DEFAULT_DNS_PROXY_UPSTREAM)),
                checker=self._resolver,
                dns_log=self._dns_log,
                on_malicious=self._on_malicious_dns,
                check_sources=check_sources,
                blocked_categories=blocked_categories or None,
                overrides_raw=str(get_entry_value(entry, CONF_DNS_OVERRIDES, DEFAULT_DNS_OVERRIDES)),
            )
        else:
            self._dns_proxy = None

    async def async_start(self) -> None:
        self._started_at = datetime.now(timezone.utc)
        loop = asyncio.get_running_loop()
        bind_host = str(get_entry_value(self.entry, CONF_BIND_HOST, DEFAULT_BIND_HOST))
        bind_port = int(get_entry_value(self.entry, CONF_BIND_PORT, DEFAULT_BIND_PORT))
        self._protocol = NetFlowDatagramProtocol(self._handle_records)

        # Pre-create the socket with SO_REUSEADDR so that integration reloads
        # don't fail with EADDRINUSE while the previous socket is still draining.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_host, bind_port))
        except OSError as exc:
            sock.close()
            _LOGGER.error(
                "HomeSec could not bind NetFlow listener on %s:%d — %s. "
                "Check whether another process already owns UDP port %d, "
                "or change the bind port in integration options.",
                bind_host, bind_port, exc, bind_port,
            )
            raise
        sock.setblocking(False)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self._protocol,
            sock=sock,
        )
        self._transport = transport
        _LOGGER.info("Home Security Assistant listening for NetFlow v5/v9/IPFIX on %s:%s", bind_host, bind_port)

        persisted_hosts = await self.hass.async_add_executor_job(
            load_discovered_hosts, self._config_dir
        )
        if persisted_hosts:
            self._scanner.load_hosts(persisted_hosts)
            _LOGGER.info("Restored %d previously discovered hosts", len(persisted_hosts))

        persisted_dismissed = await self.hass.async_add_executor_job(
            load_dismissed_findings, self._config_dir
        )
        if persisted_dismissed:
            self._dismissed_findings.update(persisted_dismissed)
            _LOGGER.info("Restored %d dismissed findings", len(persisted_dismissed))

        ts_data = await self.hass.async_add_executor_job(load_timeseries, self._config_dir)
        if ts_data:
            self._timeseries = ts_data
            try:
                self._ts_last_point = datetime.fromisoformat(ts_data[-1]["ts"])
            except (ValueError, TypeError, KeyError):
                pass
            _LOGGER.info("Restored %d timeseries points", len(ts_data))

        # Restore persistent DNS log (filtered to configured retention window)
        dns_data = await self.hass.async_add_executor_job(load_dns_log, self._config_dir)
        if dns_data:
            if self._dns_log_retention_hours > 0:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=self._dns_log_retention_hours)).isoformat()
                dns_data = [e for e in dns_data if e.get("timestamp", "") >= cutoff]
            for entry in dns_data:
                self._dns_log.append(entry)
            _LOGGER.info("Restored %d DNS log entries", len(dns_data))

        # Restore persistent external IP tracking state
        ext_ip_data = await self.hass.async_add_executor_job(load_ext_ips, self._config_dir)
        if ext_ip_data:
            now_ext = datetime.now(timezone.utc)
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
                ports = rec.get("ports")
                if isinstance(ports, list):
                    self._ext_ip_ports[ip] = {int(p) for p in ports if p is not None}
                rating = rec.get("rating")
                if rating:
                    self._ext_ip_ratings[ip] = str(rating)
            _LOGGER.info("Restored %d external IP tracking entries", len(ext_ip_data))

        # Restore enrichment usage counters (daily provider budgets)
        enr_state = await self.hass.async_add_executor_job(load_enrichment_state, self._config_dir)
        if enr_state:
            self._enricher.import_usage_state(enr_state)
            _LOGGER.info("Restored external enrichment usage state")

        if self._scanner_enabled:
            await self._scanner.async_start()
            _LOGGER.info("Home Security Assistant active network scanner started")

        await self._resolver.async_start()
        await self._enricher.async_start()
        if self._dns_proxy is not None:
            await self._dns_proxy.async_start()
        self._nvd_task = self.hass.async_create_background_task(
            self._nvd_background_loop(), name="homesec_nvd_background"
        )
        self._nvd_task.add_done_callback(self._nvd_task_done)

    def _nvd_task_done(self, task: asyncio.Task) -> None:
        """Log unhandled exceptions from the NVD background task."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error("NVD background task crashed: %s", exc)

    def _on_malicious_dns(self, src_ip: str, domain: str, qtype: str, hit: dict) -> None:
        """Called by DNSProxyProtocol when a queried domain matches the threat-intel blacklist."""
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

    async def async_stop(self) -> None:
        # Persist DNS log and external IP state before tearing down services
        dns_snapshot = list(self._dns_log)
        await self.hass.async_add_executor_job(save_dns_log, self._config_dir, dns_snapshot)
        await self.async_persist_runtime_state(force=True)

        if self._nvd_task is not None:
            self._nvd_task.cancel()
            self._nvd_task = None
        if self._dns_proxy is not None:
            await self._dns_proxy.async_stop()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._protocol = None
        await self._scanner.async_stop()
        await self._resolver.async_stop()
        await self._enricher.async_stop()

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
        self._nvd_task = self.hass.async_create_background_task(
            self._nvd_background_loop(), name="homesec_nvd_background"
        )
        self._nvd_task.add_done_callback(self._nvd_task_done)
        _LOGGER.info("NVD cache cleared — background re-fetch started")

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
                    self._nvd_last_fetch_at = datetime.now(timezone.utc)
                    await asyncio.sleep(retry_delay)
                    continue
                new_results: dict[str, list[dict[str, object]]] = {}
                for host in hosts_with_services:
                    ip = str(host.get("ip", ""))
                    services = host.get("open_ports", [])
                    try:
                        vulns = await self._nvd_client.find_vulnerabilities(ip, services)
                        if vulns:
                            new_results[ip] = vulns
                    except Exception as exc:
                        _LOGGER.debug("NVD background fetch failed for %s: %s", ip, exc)
                self._nvd_results = new_results
                self._nvd_last_fetch_at = datetime.now(timezone.utc)
                total_vulns = sum(len(v) for v in new_results.values())
                _LOGGER.info(
                    "NVD background fetch complete: %d hosts with CVEs, %d total findings, %d CVEs in cache",
                    len(new_results), total_vulns, self._nvd_client.total_cached_cves,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.warning("NVD background loop error: %s", exc)
            await asyncio.sleep(self._nvd_ttl_hours * 3600)

    def snapshot(self) -> dict[str, object]:
        enrichment_by_ip = collect_tracker_enrichment(self.hass)
        listener_stats = self._protocol.snapshot_stats() if self._protocol is not None else {}

        observed_ips = set(self._analyzer.get_observed_ips())
        self._scanner.add_observed_ips(observed_ips)

        scan_results = self._scanner.snapshot_as_dicts()
        vuln_findings = self._build_vuln_findings(scan_results)

        payload = self._analyzer.snapshot(
            enrichment_by_ip=enrichment_by_ip,
            listener_stats=listener_stats,
            scan_results=scan_results,
            vuln_findings=vuln_findings,
            alive_hosts=self._scanner.get_alive_hosts(),
            dismissed_findings=self._dismissed_findings,
        )

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
        now = datetime.now(timezone.utc)
        ext_state_changed = False
        external_ips: dict[str, dict[str, object]] = {}
        multicast_ips: dict[str, dict[str, object]] = {}
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
                if dst_port:
                    ports = self._ext_ip_ports.setdefault(ext_ip, set())
                    before = len(ports)
                    ports.add(int(dst_port))
                    if len(ports) != before:
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
        for ip in stale:
            self._ext_ip_last_seen.pop(ip, None)
            self._ext_ip_first_seen.pop(ip, None)
            self._ext_ip_sources.pop(ip, None)
            self._ext_ip_ports.pop(ip, None)
            self._ext_ip_ratings.pop(ip, None)
            external_ips.pop(ip, None)
            ext_state_changed = True
        # Add retained IPs not in current snapshot
        for ip, ts in self._ext_ip_last_seen.items():
            if ip not in external_ips:
                external_ips[ip] = self._build_ext_ip_entry(ip)

        # Attach last_seen, first_seen, and internal_sources to each entry
        for ip, entry_data in external_ips.items():
            ts = self._ext_ip_last_seen.get(ip)
            first_ts = self._ext_ip_first_seen.get(ip)
            entry_data["last_seen"] = ts.isoformat() if ts else None
            entry_data["first_seen"] = first_ts.isoformat() if first_ts else None
            entry_data["internal_sources"] = sorted(self._ext_ip_sources.get(ip, set()))
            entry_data["dst_ports"] = sorted(self._ext_ip_ports.get(ip, set()))

        payload["external_ips"] = sorted(
            external_ips.values(), key=lambda x: x.get("ip", "")
        )
        payload["multicast_ips"] = sorted(
            multicast_ips.values(), key=lambda x: x.get("ip", "")
        )
        payload["blacklist_stats"] = self._resolver.stats()
        payload["collector_started_at"] = self._started_at.isoformat() if self._started_at else None
        payload["enrichment_stats"] = self._enricher.enrichment_stats()
        self._purge_dns_log()
        payload["dns_log"] = list(self._dns_log)
        payload["dns_proxy_stats"] = self._dns_proxy.stats() if self._dns_proxy is not None else {"running": False}
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

        if ext_state_changed:
            self._ext_state_dirty = True

        # Record timeseries point every TIMESERIES_INTERVAL_SECONDS
        _ts_now = datetime.now(timezone.utc)
        if self._ts_last_point is None or (_ts_now - self._ts_last_point).total_seconds() >= TIMESERIES_INTERVAL_SECONDS:
            self._timeseries.append({
                "ts": _ts_now.isoformat(),
                "ext_ips": len(external_ips),
                "hosts": len(payload.get("devices", [])),
                "scanned": int(payload.get("scanned_devices", 0) or 0),
            })
            self._ts_last_point = _ts_now
            self._timeseries_dirty = True

        # Fire HA events for malicious external IPs
        for ext in payload.get("external_ips", []):
            if ext.get("blacklisted") or ext.get("rating") == "malicious":
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

        # Fire HA events for critical / high vulnerability findings
        for finding in payload.get("findings", []):
            if finding.get("severity") in ("critical", "high") and finding.get("category") == "vulnerability":
                details = finding.get("details", {})
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

        return payload

    async def _persist_hosts(self, hosts: dict[str, dict]) -> None:
        """Save discovered hosts to disk after each scan cycle."""
        await self.hass.async_add_executor_job(
            save_discovered_hosts, self._config_dir, hosts
        )
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
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=self._dns_log_retention_hours)).isoformat()
        while self._dns_log and self._dns_log[0].get("timestamp", "") < cutoff:
            self._dns_log.popleft()

    def dns_proxy_stats(self) -> dict:
        """Return DNS proxy status stats."""
        if self._dns_proxy is not None:
            return self._dns_proxy.stats()
        return {"running": False}

    def dismiss_finding(self, key: str, note: str = "") -> None:
        self._dismissed_findings[key] = note
        self.hass.async_add_executor_job(
            save_dismissed_findings, self._config_dir, dict(self._dismissed_findings)
        )

    def undismiss_finding(self, key: str) -> None:
        self._dismissed_findings.pop(key, None)
        self.hass.async_add_executor_job(
            save_dismissed_findings, self._config_dir, dict(self._dismissed_findings)
        )

    def _build_ext_ip_entry(self, ip: str) -> dict[str, object]:
        enrichment = self._enricher.get(ip)
        hostname = self._resolver.get_hostname(ip)
        blacklist = self._resolver.check(ip)
        hostname_threat = self._resolver.check(hostname) if hostname else None
        threat = blacklist or hostname_threat
        entry: dict[str, object] = {
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
    def _build_multicast_entry(ip: str) -> dict[str, object]:
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

    async def lookup_ip(self, ip: str) -> dict[str, object]:
        """On-demand enrichment + DNS lookup for a specific IP (used by the lookup endpoint)."""
        hostname = await self._resolver.resolve(ip)
        self._resolver._hostname_cache[ip] = hostname
        enrichment = await self._enricher.enrich_now(ip)
        blacklist = self._resolver.check(ip)
        hostname_threat = self._resolver.check(hostname) if hostname else None
        threat = blacklist or hostname_threat
        entry: dict[str, object] = {
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

    def _build_vuln_findings(self, scan_results: list[dict[str, object]]) -> list[dict[str, object]]:
        all_vulns: list[dict[str, object]] = []
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
        now = datetime.now(timezone.utc)
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

    def _external_state_snapshot(self) -> list[dict[str, object]]:
        return [
            {
                "ip": ip,
                "last_seen": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "first_seen": (
                    self._ext_ip_first_seen[ip].isoformat()
                    if ip in self._ext_ip_first_seen and isinstance(self._ext_ip_first_seen[ip], datetime)
                    else None
                ),
                "sources": sorted(self._ext_ip_sources.get(ip, set())),
                "ports": sorted(int(p) for p in self._ext_ip_ports.get(ip, set())),
                "rating": self._ext_ip_ratings.get(ip, "clean"),
            }
            for ip, ts in self._ext_ip_last_seen.items()
        ]

    async def async_persist_runtime_state(self, force: bool = False) -> None:
        """Persist runtime state that should survive restarts/crashes."""
        now = datetime.now(timezone.utc)
        if not force and self._runtime_state_last_save is not None:
            if (now - self._runtime_state_last_save).total_seconds() < 60:
                return

        should_save_ext = force or self._ext_state_dirty
        should_save_enr = force or self._enricher.is_usage_state_dirty()
        if not should_save_ext and not should_save_enr:
            return

        if should_save_ext:
            await self.hass.async_add_executor_job(
                save_ext_ips, self._config_dir, self._external_state_snapshot()
            )
            self._ext_state_dirty = False

        if should_save_enr:
            await self.hass.async_add_executor_job(
                save_enrichment_state, self._config_dir, self._enricher.export_usage_state()
            )
            self._enricher.mark_usage_state_clean()

        self._runtime_state_last_save = now


class HomeSecCoordinator(DataUpdateCoordinator[dict[str, object]]):
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

    async def _async_update_data(self) -> dict[str, object]:
        try:
            result = self.collector.snapshot()
            if self.collector._timeseries_dirty:
                self.collector._timeseries_dirty = False
                ts_copy = list(self.collector._timeseries)
                self.hass.async_add_executor_job(
                    save_timeseries, self.collector._config_dir, ts_copy
                )
            await self.collector.async_persist_runtime_state()
            return result
        except Exception as err:
            raise UpdateFailed(f"Snapshot failed: {err}") from err
