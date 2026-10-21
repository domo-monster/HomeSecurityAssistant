"""Tests for the flow analyzer (device profiles, findings, connections)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress

from custom_components.homesec.fingerprints import HomeSecurityAnalyzer
from custom_components.homesec.netflow import FlowRecord

T0 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def _flow(src: str, dst: str, dport: int, when: datetime = T0, octets: int = 100) -> FlowRecord:
    return FlowRecord(
        src_ip=ipaddress.ip_address(src),
        dst_ip=ipaddress.ip_address(dst),
        src_port=40000,
        dst_port=dport,
        protocol=6,
        packets=1,
        octets=octets,
        timestamp=when,
        tcp_flags=0x02,
    )


def _analyzer(threshold: int = 10) -> HomeSecurityAnalyzer:
    return HomeSecurityAnalyzer(["192.168.1.0/24"], 60, threshold, 10**9)


def test_port_scan_counts_unique_ports_in_window() -> None:
    analyzer = _analyzer(threshold=10)
    analyzer.ingest([_flow("192.168.1.5", "192.168.1.9", port) for port in range(1, 10)])
    analyzer.ingest([_flow("192.168.1.5", "192.168.1.9", 5)])  # repeat: still 9 unique
    assert "scan:192.168.1.5" not in analyzer._findings
    analyzer.ingest([_flow("192.168.1.5", "192.168.1.9", 10)])
    finding = analyzer._findings["scan:192.168.1.5"]
    assert finding.details["unique_ports"] == 10


def test_port_scan_window_forgets_old_ports() -> None:
    analyzer = _analyzer(threshold=10)
    analyzer.ingest([_flow("192.168.1.5", "192.168.1.9", port) for port in range(1, 10)])
    later = T0 + timedelta(seconds=61)
    analyzer.ingest([_flow("192.168.1.5", "192.168.1.9", 10, when=later)])
    assert "scan:192.168.1.5" not in analyzer._findings
    assert analyzer._recent_ports["192.168.1.5"] == {10: 1}
    assert len(analyzer._recent_activity["192.168.1.5"]) == 1


def test_profiles_connections_and_suspicious_ports() -> None:
    analyzer = _analyzer()
    analyzer.ingest(
        [
            _flow("192.168.1.5", "8.8.8.8", 443, octets=1000),
            _flow("192.168.1.5", "8.8.8.8", 443, octets=500),
            _flow("192.168.1.5", "203.0.113.9", 23),
            _flow("192.168.1.7", "192.168.1.5", 22),
            _flow("192.168.1.7", "239.255.255.250", 1900),
        ]
    )
    device = analyzer._devices["192.168.1.5"]
    assert device.total_flows == 3
    assert device.total_octets == 1600
    assert device.external_peers == {"8.8.8.8", "203.0.113.9"}
    assert device.exposed_ports == {22}
    assert device.probable_role == "linux_host"
    assert "port:192.168.1.5:23" in analyzer._findings
    conn = analyzer._connections["192.168.1.5->8.8.8.8:6:443"]
    assert (conn.flows, conn.octets, conn.target_kind) == (2, 1500, "external")
    assert analyzer._connections["192.168.1.7->239.255.255.250:6:1900"].target_kind == "multicast"
    assert analyzer._connections["192.168.1.7->192.168.1.5:6:22"].as_dict()["source_kind"] == "internal"


def test_changing_internal_networks_resets_classification() -> None:
    analyzer = _analyzer()
    address = ipaddress.ip_address("10.0.0.5")
    assert analyzer.classify(address) == ("10.0.0.5", False, False)
    analyzer.set_internal_networks([ipaddress.ip_network("10.0.0.0/8")])
    assert analyzer.classify(address) == ("10.0.0.5", True, False)
