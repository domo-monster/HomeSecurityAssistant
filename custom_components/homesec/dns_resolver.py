"""Reverse DNS resolution and threat-intel blacklist checking for Home Security Assistant."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime, UTC

_LOGGER = logging.getLogger(__name__)

_REFRESH_HOURS = 6
_LOOKUP_TIMEOUT = 3.0
_FETCH_TIMEOUT = 15


class DNSBlacklistChecker:
    """Background reverse-DNS resolver with configurable IP/domain blacklist checking."""

    def __init__(
        self,
        session,  # aiohttp.ClientSession
        blacklist_urls: list[str],
        enable_resolution: bool = True,
    ) -> None:
        self._session = session
        self._urls = [u.strip() for u in blacklist_urls if u.strip()]
        self._enable_resolution = enable_resolution
        self._bad_ips: set[str] = set()
        self._bad_domains: set[str] = set()
        self._source_map: dict[str, str] = {}
        self._hostname_cache: dict[str, str | None] = {}
        self._resolve_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        self._last_refresh: datetime | None = None
        self._tasks: list[asyncio.Task] = []

    # ------------------------------------------------------------------ #
    # Lifecycle

    async def async_start(self) -> None:
        await self._fetch_all()
        self._tasks = [
            asyncio.create_task(self._refresh_loop()),
            asyncio.create_task(self._resolve_worker()),
        ]

    async def async_stop(self) -> None:
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks = []

    # ------------------------------------------------------------------ #
    # Public API (sync, safe to call from snapshot())

    def queue_resolve(self, ip: str) -> None:
        """Queue an IP for background reverse-DNS lookup."""
        if ip not in self._hostname_cache and self._enable_resolution:
            try:
                self._resolve_queue.put_nowait(ip)
            except asyncio.QueueFull:
                pass

    def get_hostname(self, ip: str) -> str | None:
        """Return cached hostname, or None if not yet resolved."""
        return self._hostname_cache.get(ip)

    def check(self, indicator: str) -> dict[str, object] | None:
        """Return a hit dict if the IP or hostname is on a bad list, else None."""
        if not indicator:
            return None
        if indicator in self._bad_ips:
            return {
                "indicator": indicator,
                "type": "ip",
                "source": self._source_map.get(indicator, "threat_intel"),
            }
        lower = indicator.lower()
        parts = lower.split(".")
        for i in range(len(parts) - 1):
            sub = ".".join(parts[i:])
            if sub in self._bad_domains:
                return {
                    "indicator": sub,
                    "type": "domain",
                    "source": self._source_map.get(sub, "threat_intel"),
                }
        return None

    def stats(self) -> dict[str, object]:
        return {
            "bad_ips": len(self._bad_ips),
            "bad_domains": len(self._bad_domains),
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "sources": len(self._urls),
        }

    # ------------------------------------------------------------------ #
    # Async API (for on-demand lookups)

    async def resolve(self, ip: str) -> str | None:
        """Reverse-DNS lookup (awaitable). Results are cached."""
        if not self._enable_resolution:
            return None
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        hostname = await self._rdns(ip)
        self._hostname_cache[ip] = hostname
        return hostname

    # ------------------------------------------------------------------ #
    # Private helpers

    async def _rdns(self, ip: str) -> str | None:
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=_LOOKUP_TIMEOUT,
            )
            return result[0]
        except Exception:
            return None

    async def _resolve_worker(self) -> None:
        while True:
            ip = await self._resolve_queue.get()
            if ip not in self._hostname_cache:
                self._hostname_cache[ip] = await self._rdns(ip)

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(_REFRESH_HOURS * 3600)
            self._bad_ips.clear()
            self._bad_domains.clear()
            self._source_map.clear()
            await self._fetch_all()

    async def _fetch_all(self) -> None:
        for url in self._urls:
            try:
                await self._fetch_one(url)
            except Exception as exc:
                _LOGGER.warning("HSA: blacklist %s failed: %s", url, exc)
        self._last_refresh = datetime.now(UTC)
        _LOGGER.info(
            "HSA: threat intel loaded — %d blocked IPs, %d blocked domains from %d sources",
            len(self._bad_ips),
            len(self._bad_domains),
            len(self._urls),
        )

    async def _fetch_one(self, url: str) -> None:
        import aiohttp as _aiohttp  # imported here to avoid circular init issues

        source = url.split("/")[2] if url.count("/") >= 2 else url
        async with self._session.get(
            url,
            timeout=_aiohttp.ClientTimeout(total=_FETCH_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return
            text = await resp.text(encoding="utf-8", errors="replace")

        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in ("#", ";", "/"):
                continue
            # Strip trailing comments, split into tokens
            parts = line.split("#")[0].split(";")[0].split()
            if not parts:
                continue
            # Hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            # The first token is a redirect address — the domain(s) follow it.
            _HOSTS_REDIRECTS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
            if parts[0] in _HOSTS_REDIRECTS and len(parts) >= 2:
                for domain_part in parts[1:]:
                    d = domain_part.strip().rstrip(",").lower()
                    if d and "." in d and len(d) < 255:
                        self._bad_domains.add(d)
                        self._source_map.setdefault(d, source)
                continue
            token = parts[0].strip().rstrip(",")
            if not token:
                continue
            # Handle CIDR — only /32 treated as single IP
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    # num_addresses == 1 correctly identifies /32 (IPv4) and
                    # /128 (IPv6) as single-host entries; larger prefixes are
                    # network ranges and are skipped to avoid false positives.
                    if net.num_addresses == 1:
                        s = str(net.network_address)
                        self._bad_ips.add(s)
                        self._source_map.setdefault(s, source)
                except ValueError:
                    pass
                continue
            # Try as IP address
            try:
                ipaddress.ip_address(token)
                self._bad_ips.add(token)
                self._source_map.setdefault(token, source)
                continue
            except ValueError:
                pass
            # Treat as domain
            if "." in token and len(token) < 255 and " " not in token:
                d = token.lower()
                self._bad_domains.add(d)
                self._source_map.setdefault(d, source)
