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
_FETCH_TIMEOUT = 120

# IPs used as the redirect target in hosts-file format blocklists
_HOSTS_REDIRECTS: frozenset[str] = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


def _parse_blocklist_text(
    text: str, source: str
) -> tuple[set[str], set[str], dict[str, str]]:
    """Parse a raw blocklist text file.

    Supports:
      - Hosts-file format:   ``0.0.0.0 domain.com``
      - Plain IP/domain list (one entry per line)
      - ABP / AdBlock-Plus format: ``||domain.com^`` or ``||domain.com^$flags``

    Returns (domains, ips, source_map).  Runs synchronously so it can be
    offloaded to a thread-pool executor without blocking the event loop.
    """
    domains: set[str] = set()
    ips: set[str] = set()
    source_map: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ("#", "!", ";", "/", "["):
            continue
        # ABP whitelist entry — must NOT be added to blocklist
        if line.startswith("@@"):
            continue
        # ABP domain rule: ||domain.com^ or ||domain.com^$flags
        if line.startswith("||"):
            # Strip leading || and anything from ^ onward (flags, anchors)
            inner = line[2:].split("^")[0].split("$")[0].strip().lower()
            # Skip wildcards, pure TLDs, and non-domain entries
            if inner and "." in inner and "*" not in inner and len(inner) < 255:
                try:
                    ipaddress.ip_address(inner)
                    ips.add(inner)
                    source_map.setdefault(inner, source)
                except ValueError:
                    domains.add(inner)
                    source_map.setdefault(inner, source)
            continue
        parts = line.split("#")[0].split(";")[0].split()
        if not parts:
            continue
        # Hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        if parts[0] in _HOSTS_REDIRECTS and len(parts) >= 2:
            for domain_part in parts[1:]:
                d = domain_part.strip().rstrip(",").lower()
                if d and "." in d and len(d) < 255:
                    domains.add(d)
                    source_map.setdefault(d, source)
            continue
        token = parts[0].strip().rstrip(",")
        if not token:
            continue
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                if net.num_addresses == 1:
                    s = str(net.network_address)
                    ips.add(s)
                    source_map.setdefault(s, source)
            except ValueError:
                pass
            continue
        try:
            ipaddress.ip_address(token)
            ips.add(token)
            source_map.setdefault(token, source)
            continue
        except ValueError:
            pass
        if "." in token and len(token) < 255 and " " not in token:
            d = token.lower()
            domains.add(d)
            source_map.setdefault(d, source)
    return domains, ips, source_map


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
        if not self._urls:
            _LOGGER.error(
                "HSA: no blocklist URLs configured — threat-intel checking is DISABLED. "
                "Add URL(s) to the 'Blacklist URLs' option in the integration settings."
            )
        else:
            _LOGGER.warning(
                "HSA: starting threat-intel fetch for %d URL(s): %s",
                len(self._urls),
                ", ".join(self._urls),
            )
        # Fetch blocklists in a background task so HA setup is not blocked by
        # potentially slow or large downloads (multi-MB hosts files take >15 s).
        fetch_task = asyncio.create_task(self._fetch_all())
        fetch_task.add_done_callback(self._on_fetch_done)
        self._tasks = [
            asyncio.create_task(self._refresh_loop()),
            asyncio.create_task(self._resolve_worker()),
            fetch_task,
        ]

    @staticmethod
    def _on_fetch_done(task: asyncio.Task) -> None:
        if task.cancelled():
            # Normal during integration reload — not an error.
            _LOGGER.debug("HSA: blocklist fetch task cancelled (integration reload?)")
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error(
                "HSA: threat-intel fetch task raised an unexpected exception: %s",
                exc, exc_info=exc,
            )

    async def async_stop(self) -> None:
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks = []

    async def async_force_refresh(self) -> None:
        """Cancel any in-flight fetch, clear all loaded entries, and re-download all URLs."""
        # Cancel the current fetch task if it is still running
        for task in list(self._tasks):
            if task is not None and not task.done() and task.get_name().startswith("Task"):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._bad_ips.clear()
        self._bad_domains.clear()
        self._source_map.clear()
        _LOGGER.warning("HSA: force-refreshing threat intel from %d URL(s)", len(self._urls))
        fetch_task = asyncio.create_task(self._fetch_all())
        fetch_task.add_done_callback(self._on_fetch_done)
        # Replace the old fetch task slot; keep refresh loop and resolve worker alive
        self._tasks = [
            t for t in self._tasks
            if not t.done() and t is not fetch_task
        ] + [fetch_task]

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
            # Keep _last_refresh at the old timestamp so the UI never
            # regresses to "Downloading…" during a periodic re-fetch.
            await self._fetch_all()

    async def _fetch_all(self) -> None:
        for url in self._urls:
            before_d = len(self._bad_domains)
            before_i = len(self._bad_ips)
            try:
                await self._fetch_one(url)
            except Exception as exc:
                _LOGGER.error("HSA: blocklist download FAILED for %s: %s", url, exc)
                # Update timestamp even on failure so UI leaves "Downloading…" state
                self._last_refresh = datetime.now(UTC)
                continue
            added_d = len(self._bad_domains) - before_d
            added_i = len(self._bad_ips) - before_i
            # Update after every URL so partial results are visible immediately
            self._last_refresh = datetime.now(UTC)
            _LOGGER.warning(
                "HSA: loaded %d new domains + %d new IPs from %s",
                added_d, added_i,
                url.split("/")[2] if url.count("/") >= 2 else url,
            )
        _LOGGER.warning(
            "HSA: threat intel ready — %d blocked IPs, %d blocked domains from %d source(s)",
            len(self._bad_ips),
            len(self._bad_domains),
            len(self._urls),
        )
        if self._urls and not self._bad_domains and not self._bad_ips:
            _LOGGER.error(
                "HSA: threat intel loaded ZERO entries — check blocklist URLs and HA "
                "network connectivity (Settings \u2192 System \u2192 Logs for details)"
            )

    async def _fetch_one(self, url: str) -> None:
        import aiohttp as _aiohttp  # imported here to avoid circular init issues

        source = url.split("/")[2] if url.count("/") >= 2 else url
        async with self._session.get(
            url,
            timeout=_aiohttp.ClientTimeout(sock_connect=10, sock_read=_FETCH_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                _LOGGER.warning("HSA: blocklist %s returned HTTP %d", url, resp.status)
                return
            text = await resp.text(encoding="utf-8", errors="replace")

        # Parse in a thread-pool executor so large files (100k+ lines) do not
        # block the asyncio event loop and cause DNS query timeouts.
        loop = asyncio.get_running_loop()
        new_domains, new_ips, new_sources = await loop.run_in_executor(
            None, _parse_blocklist_text, text, source
        )
        self._bad_domains.update(new_domains)
        self._bad_ips.update(new_ips)
        for k, v in new_sources.items():
            self._source_map.setdefault(k, v)
