from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any
from datetime import datetime, timedelta, timezone
import logging

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
    CONF_ENABLE_DNS_RESOLUTION,
    CONF_ENABLE_SCANNER,
    CONF_ENRICHMENT_TTL_MINUTES,
    CONF_EXTERNAL_IP_RETENTION,
    CONF_RETENTION_SUSPICIOUS_HOURS,
    CONF_RETENTION_MALICIOUS_HOURS,
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
    CONF_SHODAN_ENRICH_MODE,
    CONF_VIRUSTOTAL_API_KEY,
    CONF_VIRUSTOTAL_DAILY_BUDGET,
    COORDINATOR_INTERVAL_SECONDS,
    DEFAULT_ABUSEIPDB_API_KEY,
    DEFAULT_ABUSEIPDB_DAILY_BUDGET,
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    DEFAULT_BLACKLIST_URLS,
    DEFAULT_ENABLE_DNS_RESOLUTION,
    DEFAULT_ENABLE_SCANNER,
    DEFAULT_ENRICHMENT_TTL_MINUTES,
    DEFAULT_EXTERNAL_IP_RETENTION,
    DEFAULT_RETENTION_SUSPICIOUS_HOURS,
    DEFAULT_RETENTION_MALICIOUS_HOURS,
    DEFAULT_HIGH_EGRESS_THRESHOLD,
    DEFAULT_INTERNAL_NETWORKS,
    DEFAULT_IPINFO_DAILY_BUDGET,
    DEFAULT_IPINFO_TOKEN,
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
    DEFAULT_SHODAN_ENRICH_MODE,
    DEFAULT_VIRUSTOTAL_API_KEY,
    DEFAULT_VIRUSTOTAL_DAILY_BUDGET,
    DOMAIN,
    get_entry_value,
)
from .dns_resolver import DNSBlacklistChecker
from .enrichment import collect_tracker_enrichment
from .external_enrichment import ExternalIPEnricher
from .fingerprints import HomeSecurityAnalyzer
from .netflow import FlowRecord, NetFlowDatagramProtocol
from .nvd_enrichment import NVDClient, CISAKEVClient
from .scanner import NetworkScanner, parse_scan_ports
from .storage import load_discovered_hosts, save_discovered_hosts, load_dismissed_findings, save_dismissed_findings
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
        blacklist_urls = [u.strip() for u in blacklist_raw.split(",") if u.strip()]
        enable_dns = bool(get_entry_value(entry, CONF_ENABLE_DNS_RESOLUTION, DEFAULT_ENABLE_DNS_RESOLUTION))
        self._resolver = DNSBlacklistChecker(
            session=session,
            blacklist_urls=blacklist_urls,
            enable_resolution=enable_dns,
        )
        self._enricher = ExternalIPEnricher(
            session=session,
            ipinfo_token=str(get_entry_value(entry, CONF_IPINFO_TOKEN, DEFAULT_IPINFO_TOKEN)) or None,
            virustotal_key=str(get_entry_value(entry, CONF_VIRUSTOTAL_API_KEY, DEFAULT_VIRUSTOTAL_API_KEY)) or None,
            shodan_key=str(get_entry_value(entry, CONF_SHODAN_API_KEY, DEFAULT_SHODAN_API_KEY)) or None,
            abuseipdb_key=str(get_entry_value(entry, CONF_ABUSEIPDB_API_KEY, DEFAULT_ABUSEIPDB_API_KEY)) or None,
            enrichment_ttl_minutes=int(get_entry_value(entry, CONF_ENRICHMENT_TTL_MINUTES, DEFAULT_ENRICHMENT_TTL_MINUTES)),
            daily_budgets={
                "ipinfo": int(get_entry_value(entry, CONF_IPINFO_DAILY_BUDGET, DEFAULT_IPINFO_DAILY_BUDGET)),
                "virustotal": int(get_entry_value(entry, CONF_VIRUSTOTAL_DAILY_BUDGET, DEFAULT_VIRUSTOTAL_DAILY_BUDGET)),
                "shodan": int(get_entry_value(entry, CONF_SHODAN_DAILY_BUDGET, DEFAULT_SHODAN_DAILY_BUDGET)),
                "abuseipdb": int(get_entry_value(entry, CONF_ABUSEIPDB_DAILY_BUDGET, DEFAULT_ABUSEIPDB_DAILY_BUDGET)),
            },
            shodan_mode=str(get_entry_value(entry, CONF_SHODAN_ENRICH_MODE, DEFAULT_SHODAN_ENRICH_MODE)),
        )
        nvd_api_key = str(get_entry_value(entry, CONF_NVD_API_KEY, DEFAULT_NVD_API_KEY)) or None
        nvd_api_url = str(get_entry_value(entry, CONF_NVD_API_URL, DEFAULT_NVD_API_URL)) or DEFAULT_NVD_API_URL
        nvd_ttl_hours = int(get_entry_value(entry, CONF_NVD_TTL_HOURS, DEFAULT_NVD_TTL_HOURS))
        nvd_min_year = int(get_entry_value(entry, CONF_NVD_MIN_YEAR, DEFAULT_NVD_MIN_YEAR))
        nvd_keywords_raw = str(get_entry_value(entry, CONF_NVD_KEYWORDS, DEFAULT_NVD_KEYWORDS))
        nvd_custom_keywords = [k.strip() for k in nvd_keywords_raw.split(",") if k.strip()]
        self._nvd_client = NVDClient(
            session=session,
            api_url=nvd_api_url,
            api_key=nvd_api_key,
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

    async def async_start(self) -> None:
        self._started_at = datetime.now(timezone.utc)
        loop = asyncio.get_running_loop()
        bind_host = str(get_entry_value(self.entry, CONF_BIND_HOST, DEFAULT_BIND_HOST))
        bind_port = int(get_entry_value(self.entry, CONF_BIND_PORT, DEFAULT_BIND_PORT))
        self._protocol = NetFlowDatagramProtocol(self._handle_records)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: self._protocol,
            local_addr=(bind_host, bind_port),
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

        if self._scanner_enabled:
            await self._scanner.async_start()
            _LOGGER.info("Home Security Assistant active network scanner started")

        await self._resolver.async_start()
        await self._enricher.async_start()
        self._nvd_task = self.hass.async_create_task(self._nvd_background_loop())
        self._nvd_task.add_done_callback(self._nvd_task_done)

    def _nvd_task_done(self, task: asyncio.Task) -> None:
        """Log unhandled exceptions from the NVD background task."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error("NVD background task crashed: %s", exc)

    async def async_stop(self) -> None:
        if self._nvd_task is not None:
            self._nvd_task.cancel()
            self._nvd_task = None
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

    async def async_nvd_refresh(self) -> None:
        """Flush the NVD CVE cache and restart the background fetch loop immediately."""
        self._nvd_client.invalidate_cache()
        self._nvd_results.clear()
        if self._nvd_task is not None:
            self._nvd_task.cancel()
        self._nvd_task = self.hass.async_create_task(self._nvd_background_loop())
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
        external_ips: dict[str, dict[str, object]] = {}
        multicast_ips: dict[str, dict[str, object]] = {}
        for device in payload.get("devices", []):
            device_ip = str(device.get("ip", ""))
            for ext_ip in device.get("external_peers", []):
                if ext_ip not in external_ips:
                    self._enricher.queue_ip(ext_ip)
                    self._resolver.queue_resolve(ext_ip)
                    external_ips[ext_ip] = self._build_ext_ip_entry(ext_ip)
                    # Only initialise last_seen if not already recorded by _handle_records
                    self._ext_ip_last_seen.setdefault(ext_ip, now)
                if device_ip:
                    self._ext_ip_sources.setdefault(ext_ip, set()).add(device_ip)
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
                    self._ext_ip_last_seen.setdefault(ext_ip, now)
                if source_ip:
                    self._ext_ip_sources.setdefault(ext_ip, set()).add(source_ip)
                if dst_port:
                    self._ext_ip_ports.setdefault(ext_ip, set()).add(int(dst_port))

        # Include previously-seen external IPs that are still within the retention window.
        # Update severity tracking from freshly built entries so pruning uses current ratings.
        for ip, entry in external_ips.items():
            blacklisted = bool(entry.get("blacklisted", False))
            rating = str(entry.get("rating") or "")
            if blacklisted or rating == "malicious":
                self._ext_ip_ratings[ip] = "malicious"
            elif rating == "suspicious":
                self._ext_ip_ratings[ip] = "suspicious"
            else:
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
            self._ext_ip_sources.pop(ip, None)
            self._ext_ip_ports.pop(ip, None)
            self._ext_ip_ratings.pop(ip, None)
            external_ips.pop(ip, None)
        # Add retained IPs not in current snapshot
        for ip, ts in self._ext_ip_last_seen.items():
            if ip not in external_ips:
                external_ips[ip] = self._build_ext_ip_entry(ip)

        # Attach last_seen and internal_sources to each entry
        for ip, entry_data in external_ips.items():
            ts = self._ext_ip_last_seen.get(ip)
            entry_data["last_seen"] = ts.isoformat() if ts else None
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
                self._ext_ip_last_seen[str(rec.src_ip)] = now
            elif src_internal and not dst_internal and not is_multicast(rec.dst_ip):
                self._ext_ip_last_seen[str(rec.dst_ip)] = now


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
            return self.collector.snapshot()
        except Exception as err:
            raise UpdateFailed(f"Snapshot failed: {err}") from err
