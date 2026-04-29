from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


BASELINE_SCHEMA_VERSION = 1
BASELINE_MODE_DISABLED = "disabled"
BASELINE_MODE_TRAINING = "training"
BASELINE_MODE_ACTIVE = "active"



class BaselineManager:
    def __init__(self, training_hours: int, min_observations: int, egress_multiplier: float) -> None:
        self._training_hours = max(1, int(training_hours))
        self._min_observations = max(1, int(min_observations))
        self._egress_multiplier = max(1.0, float(egress_multiplier))
        self._mode = BASELINE_MODE_DISABLED
        self._training_started_at: datetime | None = None
        self._training_ends_at: datetime | None = None
        self._baseline_completed_at: datetime | None = None
        self._baseline_version = 0
        self._confidence = "none"
        self._hosts: dict[str, dict[str, Any]] = {}
        self._training_stats: dict[str, int] = {
            "snapshots_seen": 0,
            "devices_seen": 0,
            "dns_queries_seen": 0,
            "scan_cycles_seen": 0,
        }
        self._dirty = False
        # For anomaly detection
        self._last_anomalies: list[dict[str, Any]] = []

    def get_anomalies(self, devices, dns_log, scan_results, vulnerabilities, now=None):
        """
        Compare current snapshot to baseline and return anomaly findings.
        """
        if self._mode != BASELINE_MODE_ACTIVE or not self._hosts:
            self._last_anomalies = []
            return []
        now = now or datetime.now(timezone.utc)
        anomalies = []
        # Build lookup tables for baseline
        baseline_hosts = self._hosts
        baseline_ips = set(baseline_hosts.keys())
        # --- New host anomaly ---
        for device in devices:
            ip = str(device.get("ip") or "")
            if ip and ip not in baseline_ips:
                anomalies.append({
                    "key": f"baseline:new_host:{ip}",
                    "category": "anomaly_new_host",
                    "severity": "high",
                    "summary": f"New internal host {ip} not seen during baseline training",
                    "source_ip": ip,
                    "details": {"ip": ip},
                    "last_seen": now.isoformat(),
                })
        # --- New peer, port, DNS domain/category anomalies ---
        for device in devices:
            ip = str(device.get("ip") or "")
            if not ip or ip not in baseline_hosts:
                continue
            bhost = baseline_hosts[ip]
            # External peers
            peers_now = set(device.get("external_peers", []))
            peers_baseline = set(bhost.get("external_peers", []))
            for peer in peers_now:
                if peer not in peers_baseline:
                    anomalies.append({
                        "key": f"baseline:new_peer:{ip}:{peer}",
                        "category": "anomaly_new_peer",
                        "severity": "medium",
                        "summary": f"Host {ip} communicated with new external peer {peer}",
                        "source_ip": ip,
                        "details": {"peer": peer},
                        "last_seen": now.isoformat(),
                    })
            # Destination ports
            ports_now = set(device.get("exposed_ports", []))
            ports_baseline = set(bhost.get("exposed_ports", []))
            for port in ports_now:
                if port not in ports_baseline:
                    anomalies.append({
                        "key": f"baseline:new_port:{ip}:{port}",
                        "category": "anomaly_new_port",
                        "severity": "medium",
                        "summary": f"Host {ip} exposed new port {port}",
                        "source_ip": ip,
                        "details": {"port": port},
                        "last_seen": now.isoformat(),
                    })
            # DNS domains
            domains_now = set()
            categories_now = set()
            for entry in dns_log:
                if str(entry.get("src_ip", entry.get("source_ip", ""))) == ip:
                    domain = entry.get("domain") or entry.get("qname")
                    if domain:
                        domains_now.add(domain)
                    cat = entry.get("category")
                    if cat:
                        categories_now.add(cat)
            domains_baseline = set(bhost.get("dns_domains", []))
            for domain in domains_now:
                if domain not in domains_baseline:
                    anomalies.append({
                        "key": f"baseline:new_dns_domain:{ip}:{domain}",
                        "category": "anomaly_new_dns_domain",
                        "severity": "low",
                        "summary": f"Host {ip} queried new DNS domain {domain}",
                        "source_ip": ip,
                        "details": {"domain": domain},
                        "last_seen": now.isoformat(),
                    })
            categories_baseline = set(bhost.get("dns_categories", []))
            for cat in categories_now:
                if cat not in categories_baseline:
                    anomalies.append({
                        "key": f"baseline:new_dns_category:{ip}:{cat}",
                        "category": "anomaly_new_dns_category",
                        "severity": "low",
                        "summary": f"Host {ip} queried new DNS category {cat}",
                        "source_ip": ip,
                        "details": {"category": cat},
                        "last_seen": now.isoformat(),
                    })
        self._last_anomalies = anomalies
        return anomalies

    def observe_snapshot(
        self,
        devices: list[dict[str, Any]],
        dns_log: list[dict[str, Any]],
        scan_results: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]] = None,
        now: datetime | None = None,
        **kwargs,
    ) -> None:
        now = now or datetime.now(timezone.utc)
        if self._mode != BASELINE_MODE_TRAINING:
            return
        self._training_stats["snapshots_seen"] += 1
        self._training_stats["devices_seen"] += len(devices)
        self._training_stats["dns_queries_seen"] += len(dns_log)
        if scan_results:
            self._training_stats["scan_cycles_seen"] += 1
        for device in devices:
            ip = str(device.get("ip") or "")
            if not ip:
                continue
            host = self._hosts.setdefault(
                ip,
                {
                    "ip": ip,
                    "display_name": device.get("display_name"),
                    "hostname": device.get("hostname"),
                    "manufacturer": device.get("manufacturer"),
                    "probable_role": device.get("probable_role"),
                    "first_seen": self._iso(now),
                    "last_seen": self._iso(now),
                    "observation_count": 0,
                    "external_peers": [],
                    "exposed_ports": [],
                    "dns_domains": [],
                    "dns_categories": [],
                },
            )
            host["display_name"] = device.get("display_name") or host.get("display_name")
            host["hostname"] = device.get("hostname") or host.get("hostname")
            host["manufacturer"] = device.get("manufacturer") or host.get("manufacturer")
            host["probable_role"] = device.get("probable_role") or host.get("probable_role")
            host["last_seen"] = self._iso(now)
            host["observation_count"] = int(host.get("observation_count", 0) or 0) + 1
            # Learn external peers
            peers = set(host.get("external_peers", []))
            for peer in device.get("external_peers", []):
                peers.add(peer)
            host["external_peers"] = sorted(peers)
            # Learn exposed ports
            ports = set(host.get("exposed_ports", []))
            for port in device.get("exposed_ports", []):
                ports.add(port)
            host["exposed_ports"] = sorted(ports)
        # Learn DNS domains and categories
        for entry in dns_log:
            ip = str(entry.get("src_ip", entry.get("source_ip", "")))
            if not ip or ip not in self._hosts:
                continue
            host = self._hosts[ip]
            domains = set(host.get("dns_domains", []))
            domain = entry.get("domain") or entry.get("qname")
            if domain:
                domains.add(domain)
            host["dns_domains"] = sorted(domains)
            categories = set(host.get("dns_categories", []))
            cat = entry.get("category")
            if cat:
                categories.add(cat)
            host["dns_categories"] = sorted(categories)
        # Learn vulnerabilities (future: for vuln delta anomalies)
        # Not implemented in V1
        if self._training_ends_at is not None and now >= self._training_ends_at:
            self.stop_training(now=now)
        else:
            self._dirty = True

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def mark_clean(self) -> None:
        self._dirty = False

    def load_state(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        self._mode = str(data.get("mode") or BASELINE_MODE_DISABLED)
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        self._training_started_at = self._parse_ts(metadata.get("training_started_at"))
        self._training_ends_at = self._parse_ts(metadata.get("training_ends_at"))
        self._baseline_completed_at = self._parse_ts(metadata.get("baseline_completed_at"))
        self._baseline_version = int(metadata.get("baseline_version", 0) or 0)
        self._confidence = str(metadata.get("confidence") or "none")
        hosts = data.get("hosts")
        if isinstance(hosts, dict):
            self._hosts = {str(key): value for key, value in hosts.items() if isinstance(value, dict)}
        stats = data.get("training_stats")
        if isinstance(stats, dict):
            self._training_stats.update(
                {
                    "snapshots_seen": int(stats.get("snapshots_seen", 0) or 0),
                    "devices_seen": int(stats.get("devices_seen", 0) or 0),
                    "dns_queries_seen": int(stats.get("dns_queries_seen", 0) or 0),
                    "scan_cycles_seen": int(stats.get("scan_cycles_seen", 0) or 0),
                }
            )
        self._dirty = False

    def export_state(self) -> dict[str, Any]:
        return {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "mode": self._mode,
            "metadata": {
                "training_started_at": self._iso(self._training_started_at),
                "training_ends_at": self._iso(self._training_ends_at),
                "baseline_completed_at": self._iso(self._baseline_completed_at),
                "baseline_version": self._baseline_version,
                "confidence": self._confidence,
                "training_hours": self._training_hours,
                "min_observations": self._min_observations,
                "egress_multiplier": self._egress_multiplier,
                "learned_host_count": len(self._hosts),
            },
            "training_stats": dict(self._training_stats),
            "hosts": self._hosts,
        }

    def start_training(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        self._mode = BASELINE_MODE_TRAINING
        self._training_started_at = now
        self._training_ends_at = now + timedelta(hours=self._training_hours)
        self._baseline_completed_at = None
        self._confidence = "low"
        self._hosts = {}
        self._training_stats = {
            "snapshots_seen": 0,
            "devices_seen": 0,
            "dns_queries_seen": 0,
            "scan_cycles_seen": 0,
        }
        self._dirty = True

    def stop_training(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        if self._mode == BASELINE_MODE_TRAINING:
            self._baseline_completed_at = now
            self._mode = BASELINE_MODE_ACTIVE if self._hosts else BASELINE_MODE_DISABLED
            if self._hosts:
                self._baseline_version += 1
                self._confidence = self._compute_confidence()
            else:
                self._confidence = "none"
            self._dirty = True

    def clear(self) -> None:
        self._mode = BASELINE_MODE_DISABLED
        self._training_started_at = None
        self._training_ends_at = None
        self._baseline_completed_at = None
        self._baseline_version = 0
        self._confidence = "none"
        self._hosts = {}
        self._training_stats = {
            "snapshots_seen": 0,
            "devices_seen": 0,
            "dns_queries_seen": 0,
            "scan_cycles_seen": 0,
        }
        self._dirty = True

    def retrain(self, now: datetime | None = None) -> None:
        self.start_training(now=now)

    # Duplicate observe_snapshot removed (see above for correct definition)

    def status_snapshot(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        remaining_seconds = 0
        progress = 0
        if self._mode == BASELINE_MODE_TRAINING and self._training_started_at and self._training_ends_at:
            duration = max(1, int((self._training_ends_at - self._training_started_at).total_seconds()))
            remaining_seconds = max(0, int((self._training_ends_at - now).total_seconds()))
            elapsed = max(0, duration - remaining_seconds)
            progress = min(100, int((elapsed / duration) * 100))
        return {
            "mode": self._mode,
            "training_started_at": self._iso(self._training_started_at),
            "training_ends_at": self._iso(self._training_ends_at),
            "baseline_completed_at": self._iso(self._baseline_completed_at),
            "baseline_version": self._baseline_version,
            "confidence": self._confidence,
            "training_hours": self._training_hours,
            "min_observations": self._min_observations,
            "egress_multiplier": self._egress_multiplier,
            "learned_host_count": len(self._hosts),
            "training_remaining_seconds": remaining_seconds,
            "training_progress_percent": progress,
            "training_stats": dict(self._training_stats),
        }

    def _compute_confidence(self) -> str:
        if len(self._hosts) >= 10 and self._training_stats["snapshots_seen"] >= 20:
            return "high"
        if len(self._hosts) >= 3 and self._training_stats["snapshots_seen"] >= 5:
            return "medium"
        return "low"

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _iso(value: datetime | None) -> str | None:
        return value.isoformat() if value is not None else None