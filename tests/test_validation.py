"""Settings validation, scan-port parsing, analyzer bounds and baseline counting."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress

import pytest

from custom_components.homesec.baseline import BaselineManager
from custom_components.homesec.fingerprints import MAX_DEVICES, HomeSecurityAnalyzer
from custom_components.homesec.netflow import FlowRecord
from custom_components.homesec.scanner import SCAN_PORTS, parse_scan_ports
from custom_components.homesec.settings_schema import (
    REDACTED_SECRET_VALUE,
    SETTINGS_KEYS,
    validate_settings,
)


# ── Settings ─────────────────────────────────────────────────────────────────


def test_valid_settings_are_normalised() -> None:
    updates, errors = validate_settings(
        {
            "bind_port": "2056",
            "enable_scanner": "false",
            "baseline_egress_multiplier": "3",
            "internal_networks": " 192.168.1.0/24, fd00::/8 ",
            "blacklist_urls": "https://a.example/x.txt\nhttps://b.example/y",
            "dns_proxy_upstream": "1.1.1.1, [2606:4700::1111]:53, dns.example:5353",
            "dns_overrides": "nas.lan=192.168.1.5\n# comment",
            "scan_ports": "22,80,8000-8010",
            "netflow_allowed_exporters": "192.168.1.1",
            "unknown_key": "ignored",
        }
    )
    assert errors == {}
    assert updates["bind_port"] == 2056
    assert updates["enable_scanner"] is False
    assert updates["baseline_egress_multiplier"] == 3.0
    assert updates["internal_networks"] == "192.168.1.0/24, fd00::/8"
    assert "unknown_key" not in updates


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("bind_port", 70000),
        ("bind_port", "abc"),
        ("bind_port", 1.5),
        ("bind_port", True),
        ("scan_interval", 10),
        ("enable_scanner", "maybe"),
        ("bind_host", "not-an-ip"),
        ("internal_networks", ""),
        ("internal_networks", "192.168.1.0/33"),
        ("blacklist_urls", "http://insecure.example/list"),
        ("nvd_api_url", "file:///etc/passwd"),
        ("dns_proxy_upstream", "1.1.1.1:99999"),
        ("dns_overrides", "nas.lan=not-an-ip"),
        ("scan_ports", "0-10"),
        ("scan_exceptions", "192.168.1.300"),
        ("suricata_allowed_sources", "nope"),
        ("virustotal_api_key", "bad\nkey"),
        ("dns_blocked_categories", 123),
        ("nvd_keywords", "x" * 5000),
    ],
)
def test_invalid_settings_are_rejected(key: str, value) -> None:
    updates, errors = validate_settings({key: value})
    assert key in errors
    assert key not in updates


def test_redacted_secret_is_kept() -> None:
    updates, errors = validate_settings({"virustotal_api_key": REDACTED_SECRET_VALUE})
    assert errors == {} and updates == {}


def test_none_resets_to_default() -> None:
    updates, _ = validate_settings({"scan_ports": None})
    assert updates == {"scan_ports": None}


def test_every_setting_has_a_default_or_is_optional() -> None:
    assert len(SETTINGS_KEYS) == len(set(SETTINGS_KEYS))
    assert {"suricata_auth_token", "suricata_allowed_sources", "netflow_allowed_exporters"} <= set(SETTINGS_KEYS)


# ── Scan ports ───────────────────────────────────────────────────────────────


def test_parse_scan_ports() -> None:
    assert parse_scan_ports("") == SCAN_PORTS
    assert parse_scan_ports("80, 22,20-21") == (20, 21, 22, 80)
    with pytest.raises(ValueError):
        parse_scan_ports("70000")


# ── Analyzer bounds (S6 / P4) ────────────────────────────────────────────────


def _flow(src: str, dst: str, dport: int = 443) -> FlowRecord:
    return FlowRecord(
        src_ip=ipaddress.ip_address(src),
        dst_ip=ipaddress.ip_address(dst),
        src_port=40000,
        dst_port=dport,
        protocol=6,
        packets=1,
        octets=100,
        timestamp=datetime.now(UTC),
        tcp_flags=0,
    )


def test_device_table_is_capped() -> None:
    analyzer = HomeSecurityAnalyzer(["10.0.0.0/8"], 600, 100, 10**9)
    flows = [
        _flow(str(ipaddress.IPv4Address(0x0A000000 + i)), "8.8.8.8")
        for i in range(1, MAX_DEVICES + 101)
    ]
    analyzer.ingest(flows)
    assert len(analyzer.get_observed_ips()) == MAX_DEVICES
    # each over-cap flow is dropped for its source and egress observation
    assert analyzer.snapshot()["device_updates_dropped"] == 200


def test_idle_devices_expire_by_receive_time() -> None:
    analyzer = HomeSecurityAnalyzer(["10.0.0.0/8"], 600, 100, 10**9)
    # An exporter with a wrong clock must not make devices expire instantly
    skewed = _flow("10.0.0.5", "8.8.8.8")
    skewed.timestamp = datetime.now(UTC) - timedelta(days=900)
    analyzer.ingest([skewed, _flow("10.0.0.6", "8.8.8.8")])
    analyzer.snapshot()
    assert sorted(analyzer.get_observed_ips()) == ["10.0.0.5", "10.0.0.6"]

    analyzer._devices["10.0.0.5"].received_at = datetime.now(UTC) - timedelta(days=30)
    analyzer.snapshot()
    assert analyzer.get_observed_ips() == ["10.0.0.6"]


# ── Baseline (B4) ────────────────────────────────────────────────────────────


def test_baseline_counts_each_dns_query_once() -> None:
    manager = BaselineManager(training_hours=24, min_observations=1, egress_multiplier=2)
    manager.start_training()
    device = {"ip": "10.0.0.5", "external_peers": [], "exposed_ports": []}
    batch = [{"src_ip": "10.0.0.5", "domain": "example.org", "category": "other"}]
    manager.observe_snapshot(devices=[device], dns_log=batch, scan_results=[])
    manager.observe_snapshot(devices=[device], dns_log=[], scan_results=[])
    assert manager._training_stats["dns_queries_seen"] == 1
    assert manager._hosts["10.0.0.5"]["dns_domains"] == ["example.org"]
