"""Generate panel test fixtures from the real backend.

Runs the integration under the Home Assistant test harness, feeds it a
representative network (flows, scan results, DNS/Suricata logs, enrichment,
baseline, CVEs) and dumps the exact JSON the panel receives from each API.
Some fields carry hostile strings so the browser tests also check escaping.

Run from the repository root:
    pytest frontend/tests/fixtures/generate_fixture.py -p no:cacheprovider
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.homesec.const import DOMAIN
from custom_components.homesec.netflow import FlowRecord
from custom_components.homesec.scanner import ScannedHost

OUT = Path(__file__).parent
XSS = '<img src=x onerror="window.__xss=1">'
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def _flow(src: str, dst: str, dport: int, octets: int = 4096) -> FlowRecord:
    return FlowRecord(
        src_ip=ipaddress.ip_address(src),
        dst_ip=ipaddress.ip_address(dst),
        src_port=50000,
        dst_port=dport,
        protocol=6,
        packets=10,
        octets=octets,
        timestamp=datetime.now(UTC),
        tcp_flags=0x18,
    )


def _host(ip: str, ports: list[tuple[int, str, str]], os_guess: str = "linux/unix") -> dict:
    return ScannedHost.from_dict(
        {
            "ip": ip,
            "alive": True,
            "ping_ms": 1.2,
            "last_scan": datetime.now(UTC).isoformat(),
            "os_guess": os_guess,
            "os_confidence": "medium",
            "ttl": 64,
            "open_ports": [
                {"port": p, "protocol": "tcp", "state": "open", "service_name": s, "banner": b, "version": ""}
                for p, s, b in ports
            ],
        }
    )


async def test_generate_fixture(hass: HomeAssistant, enable_custom_integrations, hass_client) -> None:
    with (
        patch("custom_components.homesec.coordinator.DNSBlacklistChecker.async_start", AsyncMock()),
        patch("custom_components.homesec.coordinator.ExternalIPEnricher.async_start", AsyncMock()),
        patch("custom_components.homesec.coordinator.HomeSecCollector._nvd_background_loop", AsyncMock()),
        patch("custom_components.homesec.coordinator.NetworkScanner.async_start", AsyncMock()),
    ):
        await async_setup_component(hass, "http", {})
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={
                "bind_host": "127.0.0.1",
                "bind_port": 2055,
                "enable_netflow_listener": False,
                "internal_networks": "192.168.1.0/24",
            },
            options={
                "enable_scanner": True,
                "enable_ip_geolocation": True,
                "virustotal_api_key": "vt-key",
                "baseline_enabled": True,
                "dns_proxy_enabled": False,
                "stats_top_n": 5,
            },
            unique_id=DOMAIN,
            minor_version=2,
        )
        entry.add_to_hass(hass)
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    runtime = entry.runtime_data
    collector = runtime.collector

    # ── Flows: normal traffic, a suspicious port, a port scan, high egress ──
    flows = []
    externals = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "185.220.101.5", "45.33.32.156", "203.0.113.50"]
    for i, host in enumerate(range(10, 22)):
        src = f"192.168.1.{host}"
        flows.append(_flow(src, externals[i % len(externals)], 443, 20_000 * (i + 1)))
        flows.append(_flow(src, "192.168.1.1", 53, 512))
    flows.append(_flow("192.168.1.15", "185.220.101.5", 23))          # telnet out
    flows.append(_flow("192.168.1.16", "203.0.113.50", 3389))         # RDP out
    flows.extend(_flow("192.168.1.17", "192.168.1.20", port) for port in range(1, 150))  # scan
    flows.append(_flow("192.168.1.18", "45.33.32.156", 443, 80_000_000))  # high egress
    flows.append(_flow("185.220.101.5", "192.168.1.11", 22))          # inbound
    flows.append(_flow("192.168.1.12", "239.255.255.250", 1900))       # multicast
    collector._handle_records(flows)

    # ── Active scan results (banners trigger static CVE rules) ──
    scanner = collector._scanner
    scanner._hosts = {
        "192.168.1.10": _host("192.168.1.10", [(22, "ssh", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8"), (80, "http", "Server: nginx/1.10.3")]),
        "192.168.1.11": _host("192.168.1.11", [(445, "smb", ""), (3389, "rdp", "")], "windows"),
        "192.168.1.12": _host("192.168.1.12", [(554, "rtsp", "RTSP/1.0 200 OK"), (80, "http", "Server: " + XSS)], "embedded"),
        "192.168.1.13": _host("192.168.1.13", [(631, "ipp", ""), (9100, "jetdirect", "")]),
        "192.168.1.14": _host("192.168.1.14", [(23, "telnet", "BusyBox v1.19.4 built-in shell"), (5555, "adb", "")], "embedded"),
    }
    scanner._last_scan_at = datetime.now(UTC)
    scanner._last_scan_duration = 42.5
    scanner._last_scan_hosts = 5
    scanner._last_scan_status = "ok"
    scanner._last_scan_targets = 254

    # ── Enrichment, reverse DNS and blocklists ──
    enricher = collector._enricher
    now = datetime.now(UTC)
    enricher._store("185.220.101.5", {"ip": "185.220.101.5", "country": "DE", "country_name": "Germany", "asn": "AS205100", "as_name": "F3 Netze", "isp": "F3 Netze", "vt_malicious": 9, "abuse_confidence": 100, "sources": ["ipwho", "virustotal"], "rating": "malicious", "rating_source": "VirusTotal: 9 malicious detections", "enriched_at": now.isoformat()}, now)
    enricher._store("203.0.113.50", {"ip": "203.0.113.50", "country": "NL", "country_name": "Netherlands", "isp": XSS, "vt_malicious": 1, "sources": ["ipwho"], "rating": "suspicious", "rating_source": "VirusTotal: 1 malicious detection(s)", "enriched_at": now.isoformat()}, now)
    for ip, cc, name, isp in (("8.8.8.8", "US", "United States", "Google LLC"), ("1.1.1.1", "AU", "Australia", "Cloudflare"), ("93.184.216.34", "US", "United States", "Edgecast"), ("45.33.32.156", "US", "United States", "Linode")):
        enricher._store(ip, {"ip": ip, "country": cc, "country_name": name, "isp": isp, "as_name": isp, "sources": ["ipwho"], "rating": "clean", "rating_source": "No threats found across checked sources", "enriched_at": now.isoformat()}, now)
    resolver = collector._resolver
    resolver._hostname_cache.update({"8.8.8.8": "dns.google", "1.1.1.1": "one.one.one.one", "45.33.32.156": XSS})
    resolver._bad_ips = {"185.220.101.5"}
    resolver._bad_domains = {"evil.example", "tracker.example"}
    resolver._source_map = {"185.220.101.5": "feodotracker.abuse.ch", "evil.example": "test-list"}
    resolver._last_refresh = now

    # ── DNS log ──
    statuses = [
        ("www.example.org", "other", "allowed", False, "NOERROR", "93.184.216.34"),
        ("ads.doubleclick.net", "ads", "blocked", False, "NXDOMAIN", None),
        ("c2.evil.example", "malware", "blocked", True, "NXDOMAIN", None),
        ("nas.lan", "override", "overridden", False, "NOERROR", "192.168.1.5"),
        ("www.netflix.com", "streaming", "allowed", False, "NOERROR", "52.1.1.1"),
        (XSS + ".example", "other", "allowed", False, "NXDOMAIN", None),
    ]
    for i in range(60):
        domain, cat, status, mal, rcode, answer = statuses[i % len(statuses)]
        collector._dns_log.append({
            "timestamp": (now - timedelta(minutes=60 - i)).isoformat(),
            "src_ip": f"192.168.1.{10 + i % 6}",
            "domain": domain, "qtype": "A" if i % 3 else "AAAA", "malicious": mal,
            "category": cat, "status": status, "rcode": rcode, "answer": answer,
        })

    # ── Suricata log ──
    for i in range(30):
        collector._suricata_log.append({
            "timestamp": (now - timedelta(minutes=30 - i)).isoformat(),
            "event_timestamp": "2026-10-20T11:00:00+0000",
            "src_ip": "185.220.101.5" if i % 2 else "192.168.1.15",
            "src_port": 40000 + i, "dest_ip": "192.168.1.11", "dest_port": 22 if i % 2 else 443,
            "proto": "TCP", "app_proto": "ssh" if i % 2 else "tls",
            "signature": XSS if i == 0 else f"ET SCAN Potential SSH Scan {i}",
            "signature_id": 2001219 + i, "category": "Attempted Information Leak",
            "severity": 1 + i % 3, "action": "blocked" if i % 5 == 0 else "allowed",
            "in_iface": "eth0", "flow_id": 1000 + i,
        })
    collector._suricata_log_dirty = True

    # ── Timeseries (24 h at 5-minute points) ──
    collector._timeseries = [
        {
            "ts": (now - timedelta(minutes=5 * (288 - i))).isoformat(),
            "ext_ips": 4 + i % 5, "hosts": 10 + i % 3, "scanned": 5,
            "deviance_score": (i * 7) % 60, "dns_total": 20 + i % 15,
            "dns_blocked": i % 4, "dns_malicious": 1 if i % 40 == 0 else 0,
        }
        for i in range(288)
    ]
    collector._ts_last_point = now

    # ── CVE data (NVD cache + CISA KEV) ──
    nvd = collector._nvd_client
    cve = {"cve_id": "CVE-2016-6210", "cvss": 5.9, "severity": "MEDIUM", "summary": "OpenSSH user enumeration " + XSS, "published": "2017-02-13", "configurations": []}
    nvd._cache = {"OpenSSH": (now, [cve, {"cve_id": "CVE-2024-6387", "cvss": 8.1, "severity": "HIGH", "summary": "regreSSHion race condition", "published": "2024-07-01", "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}]}]}]}])}
    collector._nvd_results = {"192.168.1.10": [{**cve, "host_ip": "192.168.1.10", "port": 22, "service": "ssh", "remediation": "See https://nvd.nist.gov/vuln/detail/CVE-2016-6210", "source": "nvd"}]}
    collector._nvd_last_fetch_at = now
    collector._kev_client._catalog = {"CVE-2024-6387": {"cve_id": "CVE-2024-6387", "vendor": "OpenBSD", "product": "OpenSSH", "name": "regreSSHion", "description": "Race condition", "date_added": "2024-07-15", "due_date": "2024-08-05", "action": "Apply updates"}}
    collector._kev_client._fetched_at = now

    # ── Baseline: train on part of the network, then activate ──
    collector.snapshot()
    baseline = collector._baseline_manager
    baseline.start_training()
    trained = collector.snapshot()
    baseline.observe_snapshot(devices=[d for d in trained["devices"] if d["ip"] != "192.168.1.21"], dns_log=list(collector._dns_log)[:10], scan_results=[], connections=trained["connections"])
    baseline.stop_training()
    # Activity after training becomes anomalies: a new host and a new peer
    collector._handle_records([
        _flow("192.168.1.30", "198.51.100.77", 8443),
        _flow("192.168.1.10", "198.51.100.99", 443),
    ])

    # ── User state: dismissed finding, overrides ──
    collector.dismiss_finding("port:192.168.1.16:3389", "Known admin jump host")
    runtime.role_overrides["192.168.1.13"] = "printer"
    runtime.name_overrides["192.168.1.12"] = "Garage camera " + XSS

    await runtime.coordinator.async_refresh()

    client = await hass_client()
    fixtures = {}
    for name, path in (
        ("dashboard", "/api/homesec/dashboard"),
        ("vulnerabilities", "/api/homesec/vulnerabilities"),
        ("settings", "/api/homesec/settings"),
        ("lookup", "/api/homesec/lookup?ip=185.220.101.5"),
    ):
        resp = await client.get(path)
        assert resp.status == 200, (path, resp.status)
        fixtures[name] = await resp.json()

    fixtures["generated_at"] = datetime.now(UTC).isoformat()
    (OUT / "api.json").write_text(json.dumps(fixtures, indent=1, sort_keys=True))
    print("devices", len(fixtures["dashboard"]["devices"]), "findings", len(fixtures["dashboard"]["findings"]),
          "anomalies", len(fixtures["dashboard"]["baseline_anomalies"]), "recs", len(fixtures["dashboard"]["recommendations"]),
          "ext", len(fixtures["dashboard"]["external_ips"]), "vulns", fixtures["vulnerabilities"]["total"])
    await hass.config_entries.async_unload(entry.entry_id)
