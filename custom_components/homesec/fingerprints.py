from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress

from .netflow import FlowRecord

SUSPICIOUS_PORTS = {23, 2323, 3389, 4444, 5555, 6667}

MULTICAST_NETWORK = ipaddress.ip_network("224.0.0.0/4")
MULTICAST_NETWORK_V6 = ipaddress.ip_network("ff00::/8")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4, "info": 5}


@dataclass(slots=True)
class DeviceProfile:
    ip: str
    last_seen: str
    total_flows: int = 0
    total_octets: int = 0
    exposed_ports: set[int] = field(default_factory=set)
    external_peers: set[str] = field(default_factory=set)
    probable_role: str = "unknown"
    confidence: str = "low"
    alive: bool = False
    ping_ms: float | None = None
    os_guess: str = ""
    os_confidence: str = ""
    scanned_services: list[dict[str, object]] = field(default_factory=list)
    vulnerabilities: list[dict[str, object]] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "last_seen": self.last_seen,
            "total_flows": self.total_flows,
            "total_octets": self.total_octets,
            "exposed_ports": sorted(self.exposed_ports),
            "external_peers": sorted(self.external_peers),
            "probable_role": self.probable_role,
            "confidence": self.confidence,
            "alive": self.alive,
            "ping_ms": self.ping_ms,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "scanned_services": self.scanned_services,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass(slots=True)
class SecurityFinding:
    key: str
    category: str
    severity: str
    summary: str
    source_ip: str
    count: int
    last_seen: str
    details: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        return data


@dataclass(slots=True)
class NetworkConnection:
    key: str
    source: str
    target: str
    source_kind: str
    target_kind: str
    protocol: int
    dst_port: int
    octets: int
    flows: int
    last_seen: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class HomeSecurityAnalyzer:
    def __init__(
        self,
        internal_networks: Iterable[str],
        scan_window_seconds: int,
        scan_port_threshold: int,
        high_egress_threshold: int,
    ) -> None:
        self._internal_networks = [ipaddress.ip_network(network.strip()) for network in internal_networks if network.strip()]
        self._scan_window = timedelta(seconds=scan_window_seconds)
        self._scan_port_threshold = scan_port_threshold
        self._high_egress_threshold = high_egress_threshold

        self._devices: dict[str, DeviceProfile] = {}
        self._findings: dict[str, SecurityFinding] = {}
        self._recent_activity: dict[str, deque[tuple[datetime, int, str]]] = defaultdict(deque)
        self._interval_egress: dict[str, int] = defaultdict(int)
        self._connections: dict[str, NetworkConnection] = {}
        self._total_flows = 0
        self._last_flow_at: datetime | None = None

    def ingest(self, records: Iterable[FlowRecord]) -> None:
        for record in records:
            try:
                self._total_flows += 1
                self._last_flow_at = record.timestamp

                src_internal = self._is_internal(record.src_ip)
                dst_internal = self._is_internal(record.dst_ip)

                dst_multicast = self._is_multicast(record.dst_ip)

                if src_internal:
                    self._observe_internal_source(record)
                if dst_internal:
                    self._observe_internal_destination(record)

                if src_internal and not dst_internal and not dst_multicast:
                    self._observe_external_egress(record)

                self._observe_connection(record, src_internal, dst_internal, dst_multicast)
            except Exception:
                pass  # skip malformed record, keep processing

    def get_observed_ips(self) -> list[str]:
        """Return IPs of all devices seen via NetFlow."""
        return list(self._devices.keys())

    def snapshot(
        self,
        enrichment_by_ip: dict[str, dict[str, object]] | None = None,
        listener_stats: dict[str, object] | None = None,
        scan_results: list[dict[str, object]] | None = None,
        vuln_findings: list[dict[str, object]] | None = None,
        alive_hosts: list[str] | None = None,
        dismissed_findings: set[str] | None = None,
    ) -> dict[str, object]:
        enrichment_by_ip = enrichment_by_ip or {}
        listener_stats = listener_stats or {}
        scan_results = scan_results or []
        vuln_findings = vuln_findings or []
        alive_hosts = alive_hosts or []
        self._expire_stale_findings()

        # Merge scan results into device profiles
        scan_by_ip: dict[str, dict[str, object]] = {str(h["ip"]): h for h in scan_results}
        vuln_by_ip: dict[str, list[dict[str, object]]] = defaultdict(list)
        for v in vuln_findings:
            vuln_by_ip[str(v.get("host_ip", ""))].append(v)

        # Ensure scan-only hosts also have a DeviceProfile (only if alive)
        for ip in scan_by_ip:
            if ip not in self._devices:
                scan_data = scan_by_ip[ip]
                if not scan_data.get("alive", False):
                    continue
                self._devices[ip] = DeviceProfile(
                    ip=ip,
                    last_seen=str(scan_data.get("last_scan", "")),
                )

        # Apply scan data to profiles
        for ip, device in self._devices.items():
            scan_data = scan_by_ip.get(ip)
            if scan_data:
                device.alive = bool(scan_data.get("alive", False))
                # Refresh last_seen from the scan timestamp only while the host
                # is alive so that the live map can use this field as a freshness
                # indicator and hide hosts that have gone silent.
                if device.alive:
                    device.last_seen = str(scan_data.get("last_scan", device.last_seen))
                device.ping_ms = scan_data.get("ping_ms")
                device.os_guess = str(scan_data.get("os_guess", ""))
                device.os_confidence = str(scan_data.get("os_confidence", ""))
                device.scanned_services = scan_data.get("open_ports", [])
                # Merge scanned open ports into exposed_ports
                for svc in device.scanned_services:
                    port = svc.get("port")
                    if port is not None:
                        device.exposed_ports.add(int(port))
            elif ip in alive_hosts:
                device.alive = True
            device.vulnerabilities = vuln_by_ip.get(ip, [])

        # Convert vulnerability findings into SecurityFinding objects
        self._merge_vuln_findings(vuln_findings)

        suspicious_sources = sorted({finding.source_ip for finding in self._findings.values()})
        high_egress_sources = sorted(
            finding.source_ip for finding in self._findings.values() if finding.category == "high_egress"
        )

        # Sort all findings by severity; keep a count of actionable (critical/high) for the summary
        all_findings = [finding.as_dict() for _, finding in sorted(self._findings.items())]
        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
        actionable_count = sum(1 for f in all_findings if f["severity"] in ("critical", "high"))

        devices = [
            self._build_device_snapshot(device, enrichment_by_ip.get(device.ip, {}), dismissed=dismissed_findings)
            for _, device in sorted(self._devices.items())
        ]

        tracker_enriched_devices = sum(1 for device in devices if device["enriched"])

        payload = {
            "active_devices": len(self._devices),
            "total_flows": self._total_flows,
            "open_findings": actionable_count,
            "suspicious_sources": len(suspicious_sources),
            "high_egress_sources": len(set(high_egress_sources)),
            "tracker_enriched_devices": tracker_enriched_devices,
            "scanned_devices": sum(1 for d in devices if d.get("scanned_services")),
            "vulnerability_count": len(vuln_findings),
            "devices": devices,
            "findings": all_findings,
            "connections": [connection.as_dict() for connection in self._connection_snapshot()],
            "last_flow_at": self._last_flow_at.isoformat() if self._last_flow_at else None,
            "alive_hosts": alive_hosts,
            "listener": listener_stats,
        }

        self._interval_egress.clear()
        return payload

    def _merge_vuln_findings(self, vuln_findings: list[dict[str, object]]) -> None:
        """Promote vulnerability matches from the scanner into SecurityFindings."""
        for v in vuln_findings:
            cve_id = str(v.get("cve_id", ""))
            host_ip = str(v.get("host_ip", ""))
            port = int(v.get("port", 0))
            severity = str(v.get("severity", "medium"))
            key = f"vuln:{host_ip}:{port}:{cve_id}"
            self._findings[key] = SecurityFinding(
                key=key,
                category="vulnerability",
                severity=severity,
                summary=str(v.get("summary", "")),
                source_ip=host_ip,
                count=1,
                last_seen=datetime.now(timezone.utc).isoformat(),
                details={
                    "cve_id": cve_id,
                    "port": port,
                    "cvss": v.get("cvss"),
                    "service": v.get("service"),
                    "matched_version": v.get("matched_version"),
                    "remediation": v.get("remediation"),
                },
            )

    def _is_internal(self, address: IPAddress) -> bool:
        # ipaddress.IPv4Network.__contains__ returns False (not TypeError) for
        # a mismatched-version address, so iterating mixed v4/v6 CIDRs is safe.
        return any(address in network for network in self._internal_networks)

    @staticmethod
    def _is_multicast(address: IPAddress) -> bool:
        if isinstance(address, ipaddress.IPv6Address):
            return address in MULTICAST_NETWORK_V6
        return address in MULTICAST_NETWORK

    def _observe_internal_source(self, record: FlowRecord) -> None:
        device = self._device_for(record.src_ip, record.timestamp)
        device.total_flows += 1
        device.total_octets += record.octets

        activity = self._recent_activity[str(record.src_ip)]
        activity.append((record.timestamp, record.dst_port, str(record.dst_ip)))
        self._trim_activity(activity, record.timestamp)

        unique_ports = {dst_port for _, dst_port, _ in activity}
        if len(unique_ports) >= self._scan_port_threshold:
            self._upsert_finding(
                key=f"scan:{record.src_ip}",
                category="port_scan",
                severity="high",
                summary="Source contacted many destination ports in a short window",
                source_ip=str(record.src_ip),
                details={
                    "unique_ports": len(unique_ports),
                    "window_seconds": int(self._scan_window.total_seconds()),
                },
                when=record.timestamp,
            )

    def _observe_internal_destination(self, record: FlowRecord) -> None:
        device = self._device_for(record.dst_ip, record.timestamp)
        device.exposed_ports.add(record.dst_port)
        device.probable_role, device.confidence = self._infer_role(device.exposed_ports)

    def _observe_external_egress(self, record: FlowRecord) -> None:
        device = self._device_for(record.src_ip, record.timestamp)
        device.external_peers.add(str(record.dst_ip))
        self._interval_egress[str(record.src_ip)] += record.octets

        if record.dst_port in SUSPICIOUS_PORTS:
            self._upsert_finding(
                key=f"port:{record.src_ip}:{record.dst_port}",
                category="suspicious_port",
                severity="high",
                summary="Outbound flow matched a commonly abused destination port",
                source_ip=str(record.src_ip),
                details={
                    "destination_ip": str(record.dst_ip),
                    "destination_port": record.dst_port,
                    "protocol": record.protocol,
                },
                when=record.timestamp,
            )

        if self._interval_egress[str(record.src_ip)] >= self._high_egress_threshold:
            self._upsert_finding(
                key=f"egress:{record.src_ip}",
                category="high_egress",
                severity="medium",
                summary="Source exceeded the high egress threshold in the current interval",
                source_ip=str(record.src_ip),
                details={
                    "octets": self._interval_egress[str(record.src_ip)],
                    "threshold": self._high_egress_threshold,
                },
                when=record.timestamp,
            )

    def _device_for(self, address: IPAddress, when: datetime) -> DeviceProfile:
        key = str(address)
        device = self._devices.get(key)
        if device is None:
            device = DeviceProfile(ip=key, last_seen=when.isoformat())
            self._devices[key] = device
        else:
            device.last_seen = when.isoformat()
        return device

    def _observe_connection(self, record: FlowRecord, src_internal: bool, dst_internal: bool, dst_multicast: bool = False) -> None:
        source = str(record.src_ip)
        target = str(record.dst_ip)
        source_kind = "internal" if src_internal else "external"
        if dst_multicast:
            target_kind = "multicast"
        elif dst_internal:
            target_kind = "internal"
        else:
            target_kind = "external"
        key = f"{source}->{target}:{record.protocol}:{record.dst_port}"

        connection = self._connections.get(key)
        if connection is None:
            self._connections[key] = NetworkConnection(
                key=key,
                source=source,
                target=target,
                source_kind=source_kind,
                target_kind=target_kind,
                protocol=record.protocol,
                dst_port=record.dst_port,
                octets=record.octets,
                flows=1,
                last_seen=record.timestamp.isoformat(),
            )
            return

        connection.octets += record.octets
        connection.flows += 1
        connection.last_seen = record.timestamp.isoformat()

    def _connection_snapshot(self) -> list[NetworkConnection]:
        if self._last_flow_at is None:
            return []

        cutoff = datetime.now(timezone.utc) - (self._scan_window * 6)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        stale_keys = []
        for key, connection in self._connections.items():
            try:
                ts = datetime.fromisoformat(connection.last_seen)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    stale_keys.append(key)
            except (ValueError, TypeError):
                stale_keys.append(key)
        for key in stale_keys:
            self._connections.pop(key, None)

        # Also cap max size to prevent unbounded growth
        if len(self._connections) > 5000:
            by_age = sorted(self._connections.items(), key=lambda kv: kv[1].last_seen)
            for key, _ in by_age[:len(self._connections) - 5000]:
                self._connections.pop(key, None)

        return sorted(self._connections.values(), key=lambda connection: connection.octets, reverse=True)[:80]

    def _infer_role(
        self,
        exposed_ports: set[int],
        enrichment: dict[str, object] | None = None,
    ) -> tuple[str, str]:
        identity_text = " ".join(
            str(enrichment.get(key, "")).lower()
            for key in ("display_name", "hostname", "manufacturer")
        ) if enrichment else ""

        if any(token in identity_text for token in ("camera", "doorbell", "reolink", "arlo", "nest cam")):
            return "camera", "high"
        if any(token in identity_text for token in ("printer", "hp", "epson", "brother", "canon")):
            return "printer", "high"
        if any(token in identity_text for token in ("roku", "chromecast", "apple tv", "fire tv", "smart tv")):
            return "media_device", "medium"
        if any(token in identity_text for token in ("iphone", "ipad", "pixel", "android", "galaxy")):
            return "mobile_device", "medium"
        if {9100, 631, 515} & exposed_ports:
            return "printer", "medium"
        if 554 in exposed_ports:
            return "camera", "medium"
        if {445, 139, 548} & exposed_ports:
            return "nas_or_desktop", "medium"
        if 53 in exposed_ports:
            return "dns_or_gateway", "medium"
        if 22 in exposed_ports:
            return "linux_host", "low"
        if {80, 443} & exposed_ports:
            return "web_service", "low"
        return "unknown", "low"

    def _build_device_snapshot(self, device: DeviceProfile, enrichment: dict[str, object], dismissed: set[str] | None = None) -> dict[str, object]:
        snapshot = device.as_dict()
        probable_role, confidence = self._infer_role(device.exposed_ports, enrichment)
        snapshot["probable_role"] = probable_role
        snapshot["confidence"] = confidence
        snapshot["display_name"] = enrichment.get("display_name")
        snapshot["hostname"] = enrichment.get("hostname")
        snapshot["mac_address"] = enrichment.get("mac_address")
        snapshot["manufacturer"] = enrichment.get("manufacturer")
        snapshot["source_entity"] = enrichment.get("source_entity")
        snapshot["enriched"] = any(enrichment.values())
        # Flag devices with high/critical vulnerabilities (excluding dismissed)
        dismissed = dismissed or set()
        snapshot["at_risk"] = any(
            v.get("severity") in ("critical", "high")
            for v in device.vulnerabilities
            if f"vuln:{device.ip}:{v.get('port', 0)}:{v.get('cve_id', '')}" not in dismissed
        )
        return snapshot

    def _trim_activity(self, activity: deque[tuple[datetime, int, str]], now: datetime) -> None:
        while activity and now - activity[0][0] > self._scan_window:
            activity.popleft()

    def _upsert_finding(
        self,
        key: str,
        category: str,
        severity: str,
        summary: str,
        source_ip: str,
        details: dict[str, object],
        when: datetime,
    ) -> None:
        finding = self._findings.get(key)
        if finding is None:
            self._findings[key] = SecurityFinding(
                key=key,
                category=category,
                severity=severity,
                summary=summary,
                source_ip=source_ip,
                count=1,
                last_seen=when.isoformat(),
                details=details,
            )
            return

        finding.count += 1
        finding.last_seen = when.isoformat()
        finding.details = details

    def _expire_stale_findings(self) -> None:
        if self._last_flow_at is None:
            return

        cutoff = self._last_flow_at - (self._scan_window * 2)
        # Ensure cutoff is tz-aware for comparison
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        stale_keys = []
        for key, finding in self._findings.items():
            try:
                ts = datetime.fromisoformat(finding.last_seen)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    stale_keys.append(key)
            except (ValueError, TypeError):
                stale_keys.append(key)
        for key in stale_keys:
            self._findings.pop(key, None)

        # Also trim stale activity deques to prevent memory growth
        activity_cutoff = self._last_flow_at - self._scan_window
        if activity_cutoff.tzinfo is None:
            activity_cutoff = activity_cutoff.replace(tzinfo=timezone.utc)
        stale_activity = [
            ip for ip, dq in self._recent_activity.items()
            if not dq or dq[-1][0] < activity_cutoff
        ]
        for ip in stale_activity:
            self._recent_activity.pop(ip, None)
