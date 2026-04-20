"""CVE / vulnerability matching for discovered services."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class VulnMatch:
    """A matched vulnerability for a service."""
    cve_id: str
    severity: str        # critical / high / medium / low
    cvss: float
    service: str
    matched_version: str
    summary: str
    remediation: str
    port: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss": self.cvss,
            "service": self.service,
            "matched_version": self.matched_version,
            "summary": self.summary,
            "remediation": self.remediation,
            "port": self.port,
        }


# ──────────────────────────────────────────────────────────────
# Built-in vulnerability database.
# Each entry: (service_pattern, version_range_check, cve_id, cvss, severity, summary, remediation)
# version_range_check is a callable(version_string) -> bool
# ──────────────────────────────────────────────────────────────

def _ver_tuple(version: str) -> tuple[int, ...]:
    """Parse '8.9.1' into (8, 9, 1)."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else ()


def _ver_lt(version: str, ceiling: str) -> bool:
    v = _ver_tuple(version)
    c = _ver_tuple(ceiling)
    return bool(v) and v < c


def _ver_between(version: str, floor: str, ceiling: str) -> bool:
    v = _ver_tuple(version)
    return bool(v) and _ver_tuple(floor) <= v < _ver_tuple(ceiling)


def _extract_version(banner: str, prefix: str) -> str:
    """Return the version string following *prefix* in *banner* or empty.

    Example: ``_extract_version('SSH-2.0-OpenSSH_8.9p1', 'openssh')`` → ``'8.9'``.
    Returns ``''`` when the prefix is absent so callers get a consistent,
    non-raising behaviour when banners don't match the expected shape.
    """
    match = re.search(rf"{re.escape(prefix)}[ _/]?([\d.]+)", banner, re.IGNORECASE)
    return match.group(1) if match else ""


# ──────────────────────────────────────────────────────────────
# Distro backport exemption engine
#
# Linux distributions (Debian, Ubuntu, RHEL, Alpine …) backport security
# fixes while keeping the upstream version number unchanged.  Instead of
# writing a per-CVE exemption function we represent the patched thresholds
# as structured data attached to each rule and evaluate them generically.
#
# Each entry in a rule's `distro_exemptions` list is a dict:
#   {
#     "pattern": r"deb12u(\d+)",   # regex with one capture group = revision
#     "min_revision": 3,            # revision >= this means patched
#   }
# The pattern is matched case-insensitively against the full banner string.
# If ANY entry matches a revision >= min_revision the finding is suppressed.
# ──────────────────────────────────────────────────────────────

def _backport_patched(banner: str, exemptions: list[dict]) -> bool:
    """Return True if *banner* matches at least one patched distro revision."""
    b = banner.lower()
    for ex in exemptions:
        m = re.search(ex["pattern"], b)
        if m and int(m.group(1)) >= ex["min_revision"]:
            return True
    return False


@dataclass(slots=True)
class _VulnRule:
    service_pattern: str
    version_check: object  # callable(str) -> bool; checks upstream version range only
    cve_id: str
    cvss: float
    severity: str
    summary: str
    remediation: str
    # Optional lower bound: versions below this are not affected (regression CVEs)
    version_floor: str = ""
    # Distro backport exemptions — evaluated by _backport_patched()
    distro_exemptions: list[dict] = field(default_factory=list)


def _rule_check(rule: "_VulnRule", banner: str) -> bool:
    """Unified check: upstream range → floor guard → distro backport exemptions."""
    if not rule.version_check(banner):
        return False
    if rule.version_floor:
        numeric = re.sub(r"[^0-9.]", ".", banner.lower())
        if _ver_lt(numeric, rule.version_floor):
            return False
    if rule.distro_exemptions and _backport_patched(banner, rule.distro_exemptions):
        return False
    return True



VULN_DATABASE: list[_VulnRule] = [
    # ── SSH ──────────────────────────────────────────────
    _VulnRule(
        service_pattern="ssh",
        version_check=lambda v: bool(_extract_version(v, "openssh")) and _ver_lt(_extract_version(v, "openssh"), "9.6"),
        cve_id="CVE-2023-51385",
        cvss=6.5,
        severity="medium",
        summary="OpenSSH < 9.6 OS command injection via expansion tokens in user/host names.",
        remediation="Upgrade OpenSSH to 9.6 or later.",
        distro_exemptions=[
            # Debian Bookworm: fixed in 1:9.2p1-2+deb12u2
            {"pattern": r"deb12u(\d+)", "min_revision": 2},
            # Debian Bullseye: fixed in 1:8.4p1-5+deb11u3
            {"pattern": r"deb11u(\d+)", "min_revision": 3},
            # Ubuntu Focal 20.04: fixed in 1:8.2p1-4ubuntu0.11
            {"pattern": r"ubuntu0\.(\d+)", "min_revision": 11},
        ],
    ),
    _VulnRule(
        service_pattern="ssh",
        version_check=lambda v: bool(_extract_version(v, "openssh")) and _ver_lt(_extract_version(v, "openssh"), "9.8"),
        cve_id="CVE-2024-6387",
        cvss=8.1,
        severity="high",
        summary="OpenSSH regreSSHion: unauthenticated remote code execution via signal handler race.",
        remediation="Upgrade OpenSSH to 9.8+ or apply vendor patches. Set LoginGraceTime to 0 as mitigation.",
        # CVE-2024-6387 is a regression reintroduced in 8.5p1 — versions < 8.5 are not affected
        version_floor="8.5",
        distro_exemptions=[
            # Debian Bookworm: fixed in 1:9.2p1-2+deb12u3
            {"pattern": r"deb12u(\d+)", "min_revision": 3},
            # Debian Bullseye: fixed in 1:8.4p1-5+deb11u8
            {"pattern": r"deb11u(\d+)", "min_revision": 8},
            # Ubuntu Focal 20.04: fixed in 1:8.2p1-4ubuntu0.12
            {"pattern": r"ubuntu0\.(\d+)", "min_revision": 12},
            # Ubuntu Jammy 22.04: fixed in 1:8.9p1-3ubuntu0.10
            {"pattern": r"ubuntu0\.(\d+)", "min_revision": 10},
        ],
    ),
    # ── HTTP/Web Servers ─────────────────────────────────
    _VulnRule(
        service_pattern="http",
        version_check=lambda v: bool(_extract_version(v, "apache")) and _ver_lt(_extract_version(v, "apache"), "2.4.58"),
        cve_id="CVE-2023-44487",
        cvss=7.5,
        severity="high",
        summary="Apache httpd: HTTP/2 rapid reset DoS (affects < 2.4.58).",
        remediation="Upgrade Apache to 2.4.58+ or disable mod_http2.",
    ),
    _VulnRule(
        service_pattern="http",
        version_check=lambda v: bool(_extract_version(v, "nginx")) and _ver_lt(_extract_version(v, "nginx"), "1.25.3"),
        cve_id="CVE-2023-44487",
        cvss=7.5,
        severity="high",
        summary="nginx: HTTP/2 rapid reset DoS (affects < 1.25.3).",
        remediation="Upgrade nginx to 1.25.3+ or disable HTTP/2.",
    ),
    # ── MySQL / MariaDB ──────────────────────────────────
    _VulnRule(
        service_pattern="mysql",
        version_check=lambda v: _ver_lt(v, "8.0.35"),
        cve_id="CVE-2024-20960",
        cvss=6.5,
        severity="medium",
        summary="MySQL Server (< 8.0.35) optimizer vulnerability allows DoS by authenticated user.",
        remediation="Upgrade MySQL to 8.0.35+ or latest LTS.",
    ),
    # ── Redis ────────────────────────────────────────────
    _VulnRule(
        service_pattern="redis",
        version_check=lambda v: True,  # Exposed Redis is always a finding
        cve_id="CVE-NONE-REDIS-EXPOSED",
        cvss=9.8,
        severity="critical",
        summary="Redis service exposed on the network without apparent authentication.",
        remediation="Bind Redis to 127.0.0.1 and enable requirepass. Do not expose on LAN.",
    ),
    # ── Telnet ───────────────────────────────────────────
    _VulnRule(
        service_pattern="telnet",
        version_check=lambda v: True,
        cve_id="CVE-NONE-TELNET-EXPOSED",
        cvss=9.0,
        severity="critical",
        summary="Telnet service transmits credentials in cleartext and is frequently targeted by botnets.",
        remediation="Disable Telnet and switch to SSH. If device requires Telnet, isolate it on a dedicated VLAN.",
    ),
    # ── RDP ──────────────────────────────────────────────
    _VulnRule(
        service_pattern="rdp",
        version_check=lambda v: True,
        cve_id="CVE-NONE-RDP-EXPOSED",
        cvss=8.5,
        severity="high",
        summary="RDP (3389) exposed on the local network. Frequently brute-forced and targeted by ransomware.",
        remediation="Restrict RDP access via VPN or firewall rules. Enable NLA and strong passwords.",
    ),
    # ── VNC ──────────────────────────────────────────────
    _VulnRule(
        service_pattern="vnc",
        version_check=lambda v: True,
        cve_id="CVE-NONE-VNC-EXPOSED",
        cvss=8.0,
        severity="high",
        summary="VNC (5900) exposed. Many VNC implementations lack strong auth or encryption.",
        remediation="Tunnel VNC through SSH or VPN. Restrict access via firewall.",
    ),
    # ── MongoDB ──────────────────────────────────────────
    _VulnRule(
        service_pattern="mongodb",
        version_check=lambda v: True,
        cve_id="CVE-NONE-MONGO-EXPOSED",
        cvss=9.1,
        severity="critical",
        summary="MongoDB port exposed. Default configuration often allows unauthenticated access.",
        remediation="Enable authentication, bind to 127.0.0.1, and restrict network access.",
    ),
    # ── Elasticsearch ────────────────────────────────────
    _VulnRule(
        service_pattern="elasticsearch",
        version_check=lambda v: True,
        cve_id="CVE-NONE-ELASTIC-EXPOSED",
        cvss=8.5,
        severity="high",
        summary="Elasticsearch exposed on the network. May allow data access without auth.",
        remediation="Enable X-Pack security, bind to localhost, and restrict via firewall.",
    ),
    # ── MQTT ─────────────────────────────────────────────
    _VulnRule(
        service_pattern="mqtt",
        version_check=lambda v: True,
        cve_id="CVE-NONE-MQTT-EXPOSED",
        cvss=7.5,
        severity="high",
        summary="MQTT broker exposed. May allow unauthorized subscribe/publish to IoT topics.",
        remediation="Require authentication and TLS on MQTT. Restrict client IPs via ACL.",
    ),
    # ── FTP ──────────────────────────────────────────────
    _VulnRule(
        service_pattern="ftp",
        version_check=lambda v: bool(_extract_version(v, "vsftpd")) and _ver_lt(_extract_version(v, "vsftpd"), "3.0.5"),
        cve_id="CVE-2021-3618",
        cvss=7.4,
        severity="high",
        summary="vsftpd < 3.0.5 vulnerable to ALPACA TLS cross-protocol attack.",
        remediation="Upgrade vsftpd to 3.0.5+ or disable TLS on FTP.",
    ),
    _VulnRule(
        service_pattern="ftp",
        version_check=lambda v: True,
        cve_id="CVE-NONE-FTP-CLEARTEXT",
        cvss=6.5,
        severity="medium",
        summary="FTP service transmits data in cleartext. Credentials and files may be intercepted.",
        remediation="Replace FTP with SFTP or FTPS. Restrict access via firewall.",
    ),
    # ── ADB ──────────────────────────────────────────────
    _VulnRule(
        service_pattern="adb",
        version_check=lambda v: True,
        cve_id="CVE-NONE-ADB-EXPOSED",
        cvss=9.8,
        severity="critical",
        summary="Android Debug Bridge (5555) exposed. Allows full shell access to the device.",
        remediation="Disable network ADB (adb tcpip). Device should only use USB debugging.",
    ),
]


def match_vulnerabilities(
    ip: str,
    services: list[dict[str, object]],
) -> list[VulnMatch]:
    """Match discovered services against the vulnerability database."""
    matches: list[VulnMatch] = []
    seen_cves: set[str] = set()

    for svc in services:
        svc_name = str(svc.get("service_name", "")).lower()
        svc_port = int(svc.get("port", 0))
        banner = str(svc.get("banner", ""))
        version = str(svc.get("version", ""))
        # Use banner as version source if version is empty
        version_input = version or banner

        for rule in VULN_DATABASE:
            if rule.service_pattern != svc_name:
                continue
            # Unique per CVE per host per port to avoid duplicates
            dedup_key = f"{ip}:{svc_port}:{rule.cve_id}"
            if dedup_key in seen_cves:
                continue
            try:
                if _rule_check(rule, version_input):
                    matches.append(
                        VulnMatch(
                            cve_id=rule.cve_id,
                            severity=rule.severity,
                            cvss=rule.cvss,
                            service=svc_name,
                            matched_version=version_input[:128],
                            summary=rule.summary,
                            remediation=rule.remediation,
                            port=svc_port,
                        )
                    )
                    seen_cves.add(dedup_key)
            except Exception:
                _LOGGER.debug(
                    "HSA: vulnerability rule %s failed on %s:%d",
                    rule.cve_id, ip, svc_port, exc_info=True,
                )

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matches.sort(key=lambda m: (severity_order.get(m.severity, 9), -m.cvss))
    return matches
