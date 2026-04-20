"""Active network scanner for HomeSec — ping, port scan, service/OS discovery."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import ssl
import sys
from collections.abc import Callable, Coroutine, Iterable
from typing import Any
from dataclasses import dataclass, field
from datetime import UTC, datetime

_LOGGER = logging.getLogger(__name__)

# Well-known ports to probe during a scan sweep.
SCAN_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 515,
    554, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2323, 3306,
    3389, 4443, 5000, 5060, 5432, 5555, 5900, 6379, 6667, 8000, 8008, 8080,
    8443, 8883, 8888, 9090, 9100, 9200, 27017, 49152,
)


def parse_scan_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated list of ports and port ranges into a sorted tuple.

    Accepts formats like: ``22,80,443`` or ``1-1024,3306,8080-8090``.
    Returns *SCAN_PORTS* when *raw* is empty or blank.
    Raises ``ValueError`` on invalid input.
    """
    raw = raw.strip()
    if not raw:
        return SCAN_PORTS
    ports: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            lo, hi = int(parts[0]), int(parts[1])
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    if not ports:
        return SCAN_PORTS
    return tuple(sorted(ports))

# Maps port to service name hint.
PORT_SERVICE_HINT: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    515: "lpd", 554: "rtsp", 587: "submission", 631: "ipp",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2323: "telnet-alt",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "upnp",
    5060: "sip", 5432: "postgresql", 5555: "adb", 5900: "vnc",
    6379: "redis", 6667: "irc", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8883: "mqtt-tls",
    8888: "http-alt", 9090: "prometheus", 9100: "jetdirect",
    9200: "elasticsearch", 27017: "mongodb", 49152: "upnp-alt",
}


@dataclass(slots=True)
class ServiceInfo:
    """A discovered service on an open port."""
    port: int
    protocol: str  # tcp
    state: str  # open / closed / filtered
    service_name: str
    banner: str
    version: str
    technologies: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "banner": self.banner,
            "version": self.version,
            "technologies": self.technologies,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ServiceInfo:
        return cls(
            port=int(d.get("port", 0)),
            protocol=str(d.get("protocol", "tcp")),
            state=str(d.get("state", "open")),
            service_name=str(d.get("service_name", "")),
            banner=str(d.get("banner", "")),
            version=str(d.get("version", "")),
            technologies=list(d.get("technologies", [])),
        )


@dataclass(slots=True)
class ScannedHost:
    """Result of an active scan for one IP address."""
    ip: str
    alive: bool
    ping_ms: float | None
    last_scan: str
    os_guess: str
    os_confidence: str
    ttl: int | None
    open_ports: list[ServiceInfo] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "alive": self.alive,
            "ping_ms": self.ping_ms,
            "last_scan": self.last_scan,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "ttl": self.ttl,
            "open_ports": [svc.as_dict() for svc in self.open_ports],
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScannedHost:
        return cls(
            ip=str(d.get("ip", "")),
            alive=bool(d.get("alive", False)),
            ping_ms=d.get("ping_ms"),
            last_scan=str(d.get("last_scan", "")),
            os_guess=str(d.get("os_guess", "unknown")),
            os_confidence=str(d.get("os_confidence", "none")),
            ttl=d.get("ttl"),
            open_ports=[ServiceInfo.from_dict(s) for s in d.get("open_ports", []) if isinstance(s, dict)],
        )


def _ping_command(ip: str, timeout: float) -> list[str]:
    """Build the ping command for the current platform.

    BSD/Linux/macOS use ``-c`` (count) and ``-W`` (seconds). Windows uses
    ``-n`` (count) and ``-w`` (milliseconds). IPv6 literals don't need a
    separate flag on modern pings — the address itself tells the OS.
    """
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]


async def ping_host(ip: str, timeout: float = 1.5) -> tuple[bool, float | None, int | None]:
    """ICMP-echo ping using subprocess (no raw-socket privilege needed).

    For IPv6 targets, switches to ``ping -6`` and matches the hop-limit
    field (``hlim=``) in addition to the v4 ``ttl=`` field.
    """
    try:
        version = ipaddress.ip_address(ip).version
    except ValueError:
        return False, None, None
    args: list[str] = ["ping"]
    if version == 6:
        args.append("-6")
    args.extend(["-c", "1", "-W", str(int(timeout)), ip])
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + 2)
        if process.returncode != 0:
            return False, None, None
        text = stdout.decode(errors="replace")
        rtt_match = re.search(r"time[=<]([\d.]+)", text)
        ttl_match = re.search(r"(?:ttl|hlim)=(\d+)", text, re.IGNORECASE)
        rtt = float(rtt_match.group(1)) if rtt_match else None
        ttl = int(ttl_match.group(1)) if ttl_match else None
        return True, rtt, ttl
    except (asyncio.TimeoutError, OSError):
        return False, None, None


async def tcp_connect_scan(ip: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    """Attempt a TCP connect and optionally grab a banner."""
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode(errors="replace").strip()[:256]
        except (asyncio.TimeoutError, ConnectionError):
            pass
        # If no banner received, send HTTP probe to detect HTTP servers
        # on non-standard ports (e.g. port 2323 running an HTTP service).
        if not banner:
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(512), timeout=1.0)
                banner = data.decode(errors="replace").strip()[:256]
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
        writer.close()
        await writer.wait_closed()
        return True, banner
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return False, ""


def guess_os_from_ttl(ttl: int | None) -> tuple[str, str]:
    """Heuristic OS guess based on ICMP TTL value."""
    if ttl is None:
        return "unknown", "none"
    if ttl <= 64:
        return "linux/unix", "medium"
    if ttl <= 128:
        return "windows", "medium"
    if ttl <= 255:
        return "network-device", "low"
    return "unknown", "low"


def parse_service_version(banner: str, service_hint: str) -> tuple[str, str]:
    """Extract a service name and version string from a banner."""
    if not banner:
        return service_hint, ""

    banner_lower = banner.lower()

    # SSH banner: SSH-2.0-OpenSSH_8.9p1
    if banner.startswith("SSH-"):
        parts = banner.split("-", 2)
        version = parts[2] if len(parts) > 2 else ""
        return "ssh", version.strip()

    # HTTP response
    if "HTTP/" in banner:
        server_match = re.search(r"[Ss]erver:\s*(.+)", banner)
        if server_match:
            return "http", server_match.group(1).strip()[:128]
        return "http", ""

    # FTP
    if "220" in banner[:10] and ("ftp" in banner_lower or "filezilla" in banner_lower or "vsftpd" in banner_lower or "proftpd" in banner_lower):
        return "ftp", banner[4:].strip()[:128]

    # SMTP
    if "220" in banner[:10] and ("smtp" in banner_lower or "postfix" in banner_lower or "exim" in banner_lower):
        return "smtp", banner[4:].strip()[:128]

    # MySQL
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        ver_match = re.search(r"([\d]+\.[\d]+\.[\d]+)", banner)
        return "mysql", ver_match.group(1) if ver_match else ""

    # Redis
    if banner.startswith("-ERR") or banner.startswith("+PONG") or "redis" in banner_lower:
        return "redis", ""

    # Generic version extraction
    ver_match = re.search(r"([\d]+\.[\d]+\.[\d]+)", banner)
    version = ver_match.group(1) if ver_match else ""
    return service_hint, version


# ---------------------------------------------------------------------------
# HTTP fingerprinting — lightweight WhatWeb-style technology detection
# ---------------------------------------------------------------------------

# HTTP ports where we attempt fingerprinting (after an open port is confirmed)
_HTTP_PORTS = frozenset({80, 443, 4443, 5000, 8000, 8008, 8080, 8443, 8888, 9090})

# Each entry: (technology_name, detection_sources)
# detection_sources is a list of dicts with:
#   "header"   – (header_name, regex) matched against response headers
#   "body"     – regex matched against the first 64 KB of response body
#   "cookie"   – regex matched against Set-Cookie header values
#   "url"      – path to probe (in addition to /)
_HTTP_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "WordPress",
        "body": [
            re.compile(r'wp-content/', re.I),
            re.compile(r'wp-includes/', re.I),
            re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', re.I),
        ],
        "header": [("X-Powered-By", re.compile(r'WordPress', re.I))],
        "cookie": [re.compile(r'wordpress_', re.I)],
        "url": "/wp-login.php",
    },
    {
        "name": "WooCommerce",
        "body": [
            re.compile(r'woocommerce', re.I),
            re.compile(r'wc-block', re.I),
        ],
    },
    {
        "name": "Joomla",
        "body": [
            re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', re.I),
            re.compile(r'/media/jui/', re.I),
            re.compile(r'/components/com_', re.I),
        ],
        "cookie": [re.compile(r'joomla_', re.I)],
    },
    {
        "name": "Drupal",
        "body": [
            re.compile(r'Drupal\.settings', re.I),
            re.compile(r'/sites/default/files/', re.I),
        ],
        "header": [
            ("X-Generator", re.compile(r'Drupal', re.I)),
            ("X-Drupal-Cache", re.compile(r'.')),
        ],
    },
    {
        "name": "Magento",
        "body": [
            re.compile(r'/skin/frontend/', re.I),
            re.compile(r'Mage\.Cookies', re.I),
        ],
        "cookie": [re.compile(r'frontend=', re.I)],
    },
    {
        "name": "phpMyAdmin",
        "body": [
            re.compile(r'phpMyAdmin', re.I),
            re.compile(r'pma_', re.I),
        ],
    },
    {
        "name": "Grafana",
        "body": [
            re.compile(r'grafana-app', re.I),
            re.compile(r'"appSubUrl"', re.I),
        ],
    },
    {
        "name": "GitLab",
        "body": [
            re.compile(r'gitlab-', re.I),
            re.compile(r'gon\.gitlab', re.I),
        ],
        "header": [("X-GitLab", re.compile(r'.'))],
    },
    {
        "name": "Nextcloud",
        "body": [
            re.compile(r'nextcloud', re.I),
        ],
        "header": [("X-Nextcloud", re.compile(r'.'))],
    },
    {
        "name": "Home Assistant",
        "body": [
            re.compile(r'home-assistant', re.I),
            re.compile(r'hassio', re.I),
        ],
    },
    {
        "name": "Tomcat",
        "body": [
            re.compile(r'Apache Tomcat', re.I),
        ],
        "header": [("Server", re.compile(r'Apache-Coyote|Tomcat', re.I))],
    },
    {
        "name": "Node.js",
        "header": [("X-Powered-By", re.compile(r'Express|Node', re.I))],
    },
    {
        "name": "PHP",
        "header": [("X-Powered-By", re.compile(r'PHP/([\d.]+)', re.I))],
    },
    {
        "name": "ASP.NET",
        "header": [("X-Powered-By", re.compile(r'ASP\.NET', re.I))],
    },
    {
        "name": "IIS",
        "header": [("Server", re.compile(r'Microsoft-IIS/([\d.]+)', re.I))],
    },
    {
        "name": "Caddy",
        "header": [("Server", re.compile(r'Caddy', re.I))],
    },
    {
        "name": "Varnish",
        "header": [
            ("Via", re.compile(r'varnish', re.I)),
            ("X-Varnish", re.compile(r'.')),
        ],
    },
    {
        "name": "HAProxy",
        "header": [("Server", re.compile(r'HAProxy', re.I))],
        "cookie": [re.compile(r'SERVERID=', re.I)],
    },
    {
        "name": "Pi-hole",
        "body": [
            re.compile(r'Pi-hole', re.I),
            re.compile(r'pihole', re.I),
        ],
    },
    {
        "name": "Synology DSM",
        "body": [
            re.compile(r'SYNO\.SDS', re.I),
            re.compile(r'synology', re.I),
        ],
    },
    {
        "name": "UniFi",
        "body": [
            re.compile(r'ubnt', re.I),
            re.compile(r'UniFi', re.I),
        ],
    },
    {
        "name": "Elasticsearch",
        "body": [
            re.compile(r'"cluster_name"\s*:', re.I),
            re.compile(r'"tagline"\s*:\s*"You Know, for Search"', re.I),
        ],
    },
    {
        "name": "Prometheus",
        "body": [
            re.compile(r'Prometheus Time Series', re.I),
        ],
    },
    {
        "name": "Jenkins",
        "header": [("X-Jenkins", re.compile(r'[\d.]+'))],
        "body": [re.compile(r'Jenkins', re.I)],
    },
]


async def _http_get(
    ip: str, port: int, path: str = "/", timeout: float = 4.0,
) -> tuple[dict[str, str], str]:
    """Perform a raw HTTP(S) GET and return (headers_dict, body_text).

    Uses raw sockets with optional TLS to avoid pulling in aiohttp just for
    the scanner module.  Returns ({}, "") on any failure.
    """
    use_tls = port in (443, 4443, 8443)
    try:
        if use_tls:
            # Fingerprinting probes target raw LAN IPs, so certificate verification
            # and SNI hostname validation would reject self-signed and LAN-only
            # services that we explicitly want to identify.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )

        # RFC 7230 §5.4: IPv6 literals must be bracketed in the Host header.
        try:
            host_header = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
        except ValueError:
            host_header = ip
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: HomeSec-Scanner/1.0\r\n"
            f"Accept: text/html,application/json,*/*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read up to 64 KB — enough for headers + initial HTML
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass

        text = data.decode(errors="replace")
        # Split headers and body
        header_end = text.find("\r\n\r\n")
        if header_end == -1:
            header_end = text.find("\n\n")
        if header_end == -1:
            return {}, text

        header_block = text[:header_end]
        body = text[header_end + 4:]

        headers: dict[str, str] = {}
        for line in header_block.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                # Accumulate Set-Cookie values
                lk = key.lower()
                if lk in headers:
                    headers[lk] += "; " + val
                else:
                    headers[lk] = val
        return headers, body

    except (asyncio.TimeoutError, OSError, ConnectionError, ssl.SSLError):
        return {}, ""


async def fingerprint_http(ip: str, port: int) -> list[str]:
    """Detect web technologies on an HTTP(S) service.

    Returns a list of technology names found (e.g. ["WordPress", "PHP"]).
    """
    detected: set[str] = set()

    headers, body = await _http_get(ip, port, "/")
    if not headers and not body:
        return []

    cookies = headers.get("set-cookie", "")

    for sig in _HTTP_SIGNATURES:
        found = False
        # Check headers
        for hdr_name, hdr_re in sig.get("header", []):
            val = headers.get(hdr_name.lower(), "")
            if val and hdr_re.search(val):
                found = True
                break
        # Check cookies
        if not found and cookies:
            for cookie_re in sig.get("cookie", []):
                if cookie_re.search(cookies):
                    found = True
                    break
        # Check body patterns
        if not found and body:
            for body_re in sig.get("body", []):
                if body_re.search(body):
                    found = True
                    break
        if found:
            detected.add(sig["name"])

    # Probe secondary URLs for signatures that define one (e.g. /wp-login.php)
    # Only if primary page didn't already detect it
    secondary_paths: list[tuple[str, str]] = []
    for sig in _HTTP_SIGNATURES:
        if sig["name"] not in detected and "url" in sig:
            secondary_paths.append((sig["name"], sig["url"]))

    if secondary_paths:
        for tech_name, url_path in secondary_paths:
            sec_headers, sec_body = await _http_get(ip, port, url_path, timeout=3.0)
            if not sec_headers and not sec_body:
                continue
            # A 200 response to a known path is a strong signal
            # Check for 200-level status in the raw header data
            raw_status = sec_headers.get("", "")
            # For path probes, finding the page exists (non-404) with
            # matching content is sufficient
            sig_def = next(s for s in _HTTP_SIGNATURES if s["name"] == tech_name)
            for body_re in sig_def.get("body", []):
                if sec_body and body_re.search(sec_body):
                    detected.add(tech_name)
                    break

    return sorted(detected)


async def scan_host(ip: str, ports: tuple[int, ...] = SCAN_PORTS, timeout: float = 1.5) -> ScannedHost:
    """Full scan of a single host: ping, port scan, banner grab, OS guess."""
    alive, rtt, ttl = await ping_host(ip, timeout=timeout)
    os_guess, os_confidence = guess_os_from_ttl(ttl)

    open_ports: list[ServiceInfo] = []
    # Always port-scan even if ping fails (like nmap -Pn)
    # Scan ports in batches to avoid overwhelming the network
    batch_size = 25
    for i in range(0, len(ports), batch_size):
        batch = ports[i : i + batch_size]
        tasks = [tcp_connect_scan(ip, port, timeout=timeout) for port in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for port, result in zip(batch, results):
            if isinstance(result, Exception):
                continue
            is_open, banner = result
            if is_open:
                service_hint = PORT_SERVICE_HINT.get(port, "unknown")
                service_name, version = parse_service_version(banner, service_hint)
                open_ports.append(
                    ServiceInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service_name=service_name,
                        banner=banner,
                        version=version,
                    )
                )

    # Host is alive if it responded to ping OR has any open port
    if not alive and open_ports:
        alive = True

    # HTTP fingerprinting: detect web technologies on HTTP(S) ports
    for svc in open_ports:
        if svc.port in _HTTP_PORTS or svc.service_name in ("http", "https", "http-alt", "http-proxy", "https-alt"):
            try:
                techs = await fingerprint_http(ip, svc.port)
                if techs:
                    svc.technologies = techs
                    _LOGGER.debug("HTTP fingerprint %s:%d → %s", ip, svc.port, techs)
            except Exception as exc:
                _LOGGER.debug("HTTP fingerprint failed for %s:%d: %s", ip, svc.port, exc)

    # Refine OS guess from service banners
    if alive and os_guess in ("unknown", "linux/unix"):
        os_guess, os_confidence = _refine_os_from_services(open_ports, os_guess, os_confidence)

    return ScannedHost(
        ip=ip,
        alive=alive,
        ping_ms=rtt,
        last_scan=datetime.now(UTC).isoformat(),
        os_guess=os_guess,
        os_confidence=os_confidence,
        ttl=ttl,
        open_ports=open_ports,
    )


def _refine_os_from_services(
    services: list[ServiceInfo], current_guess: str, current_confidence: str,
) -> tuple[str, str]:
    """Improve OS guess using discovered service banners."""
    all_banners = " ".join(s.banner.lower() + " " + s.version.lower() for s in services)

    if "windows" in all_banners or "microsoft" in all_banners or "win32" in all_banners:
        return "windows", "high"
    if "ubuntu" in all_banners or "debian" in all_banners:
        return "linux/debian", "high"
    if "centos" in all_banners or "red hat" in all_banners or "rhel" in all_banners:
        return "linux/rhel", "high"
    if "freebsd" in all_banners:
        return "freebsd", "high"
    if "openwrt" in all_banners or "ddwrt" in all_banners or "mikrotik" in all_banners:
        return "router/embedded", "high"

    # Port-based heuristic
    open_port_set = {s.port for s in services}
    if {135, 139, 445} & open_port_set:
        return "windows", "medium"
    if 548 in open_port_set:
        return "macos", "medium"
    if 22 in open_port_set and 445 not in open_port_set:
        if current_guess == "unknown":
            return "linux/unix", "low"

    return current_guess, current_confidence


async def scan_network(
    targets: Iterable[str],
    ports: tuple[int, ...] = SCAN_PORTS,
    timeout: float = 1.5,
    max_concurrent: int = 8,
) -> list[ScannedHost]:
    """Scan multiple hosts with a concurrency limit."""
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[ScannedHost] = []

    async def _scan_one(ip: str) -> ScannedHost:
        async with semaphore:
            return await scan_host(ip, ports=ports, timeout=timeout)

    tasks = [_scan_one(ip) for ip in targets]
    for coro in asyncio.as_completed(tasks):
        try:
            result = await coro
            results.append(result)
        except Exception as exc:
            _LOGGER.debug("Scan error: %s", exc)

    return results


class NetworkScanner:
    """Manages periodic network scanning for HomeSec."""

    def __init__(
        self,
        internal_networks: list[str],
        scan_interval_seconds: int = 300,
        max_concurrent: int = 8,
        excluded_ips: list[str] | None = None,
        ports: tuple[int, ...] = SCAN_PORTS,
        on_scan_complete: Callable[[dict[str, dict]], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        self._internal_networks = []
        for raw in internal_networks:
            token = raw.strip()
            if not token:
                continue
            try:
                self._internal_networks.append(ipaddress.ip_network(token))
            except ValueError:
                _LOGGER.warning("HSA: ignoring invalid internal network %r", token)
        self._scan_interval = scan_interval_seconds
        self._max_concurrent = max_concurrent
        self._excluded_ips: set[str] = set(excluded_ips or [])
        self._ports = ports
        self._hosts: dict[str, ScannedHost] = {}
        self._task: asyncio.Task | None = None
        self._known_ips: set[str] = set()
        self._running = False
        self._on_scan_complete = on_scan_complete
        self._last_scan_at: datetime | None = None
        self._last_scan_duration: float | None = None
        self._last_scan_hosts: int | None = None

    def add_observed_ips(self, ips: Iterable[str]) -> None:
        """Register IPs seen from netflow so the scanner knows what to probe."""
        self._known_ips.update(ips)

    def get_scan_targets(self) -> list[str]:
        """Build list of IPs to scan: union of known IPs and small subnet enumeration.

        IPv6 networks are never enumerated (a /64 alone is 2**64 addresses). For
        v6, only addresses observed via NetFlow or device trackers are scanned —
        the ``self._known_ips`` union already covers that path.
        """
        targets: set[str] = set(self._known_ips)
        for network in self._internal_networks:
            if network.version == 4 and network.prefixlen >= 24:
                targets.update(str(h) for h in network.hosts())
            # For larger v4 subnets and all v6 subnets, only scan known IPs.
        # Exclude network/broadcast addresses (v6 has no broadcast_address
        # concept in the traditional sense — the call still returns the last
        # address of the range, so discarding it is harmless).
        for network in self._internal_networks:
            targets.discard(str(network.network_address))
            if network.version == 4:
                targets.discard(str(network.broadcast_address))
        # Exclude user-configured safe IPs (e.g. printers)
        targets -= self._excluded_ips
        return sorted(targets)

    async def async_start(self) -> None:
        """Start the periodic scan loop."""
        self._running = True
        self._task = asyncio.create_task(self._scan_loop())

    async def async_stop(self) -> None:
        """Stop the periodic scan loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def async_trigger_scan(self) -> None:
        """Run an immediate scan cycle outside the normal schedule."""
        await self._run_scan()

    async def _scan_loop(self) -> None:
        """Repeatedly scan the network."""
        while self._running:
            try:
                await self._run_scan()
            except Exception:
                _LOGGER.exception("Network scan cycle failed")
            await asyncio.sleep(self._scan_interval)

    @property
    def last_scan_at(self) -> datetime | None:
        return self._last_scan_at

    @property
    def last_scan_duration(self) -> float | None:
        return self._last_scan_duration

    @property
    def last_scan_hosts(self) -> int | None:
        return self._last_scan_hosts

    async def _run_scan(self) -> None:
        """Execute one full scan cycle."""
        targets = self.get_scan_targets()
        if not targets:
            return
        _LOGGER.info("Starting network scan of %d hosts", len(targets))
        t0 = datetime.now(UTC)
        results = await scan_network(
            targets,
            ports=self._ports,
            max_concurrent=self._max_concurrent,
        )
        for host in results:
            self._hosts[host.ip] = host
        self._last_scan_at = datetime.now(UTC)
        self._last_scan_duration = (self._last_scan_at - t0).total_seconds()
        self._last_scan_hosts = sum(1 for h in results if h.alive)
        _LOGGER.info(
            "Scan complete: %d alive, %d total tracked (%.1fs)",
            self._last_scan_hosts,
            len(self._hosts),
            self._last_scan_duration,
        )
        if self._on_scan_complete is not None:
            await self._on_scan_complete(self.get_hosts_as_dicts())

    def load_hosts(self, data: dict[str, dict]) -> None:
        """Restore previously persisted hosts without overwriting fresher in-memory data."""
        for ip, host_dict in data.items():
            if ip not in self._hosts:
                try:
                    self._hosts[ip] = ScannedHost.from_dict(host_dict)
                except Exception:
                    _LOGGER.debug("Skipping invalid persisted host entry for %s", ip)

    def get_hosts_as_dicts(self) -> dict[str, dict]:
        """Return hosts as a serializable dict keyed by IP."""
        return {ip: host.as_dict() for ip, host in self._hosts.items()}

    def snapshot(self) -> dict[str, ScannedHost]:
        """Return current state of all scanned hosts."""
        return dict(self._hosts)

    def snapshot_as_dicts(self) -> list[dict[str, object]]:
        """Return scan results as serializable dicts."""
        return [host.as_dict() for host in sorted(self._hosts.values(), key=lambda h: h.ip)]

    def get_alive_hosts(self) -> list[str]:
        """Return list of IPs that responded to ping or have open ports."""
        return [ip for ip, host in self._hosts.items() if host.alive]
