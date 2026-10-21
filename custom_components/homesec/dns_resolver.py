"""Reverse DNS resolution and threat-intel blacklist checking for Home Security Assistant."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import ipaddress
import logging
import socket
from typing import Any

_LOGGER = logging.getLogger(__name__)

_REFRESH_HOURS = 6
_LOOKUP_TIMEOUT = 3.0
_FETCH_TIMEOUT = 120
# Maximum reverse-DNS results kept in memory (oldest evicted first)
MAX_HOSTNAME_CACHE = 5000

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


def _source_name(url: str) -> str:
    """Short label for a blocklist URL (its host name)."""
    return url.split("/")[2] if url.count("/") >= 2 else url


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
        self._refresh_task: asyncio.Task | None = None
        self._resolve_task: asyncio.Task | None = None
        self._fetch_task: asyncio.Task | None = None
        # url -> {etag, last_modified, fetched_at, checked_at, domains, ips}
        self._source_state: dict[str, dict[str, Any]] = {}
        self._state_dirty = False
        # aiodns resolver (created lazily); False when aiodns is unavailable
        self._aiodns: Any = None

    # ------------------------------------------------------------------ #
    # Lifecycle

    async def async_start(self) -> None:
        if not self._urls:
            _LOGGER.error(
                "HomeSec: no blocklist URLs configured — threat-intel checking is DISABLED. "
                "Add URL(s) to the 'Blacklist URLs' option in the integration settings."
            )
        else:
            _LOGGER.info(
                "HomeSec: starting threat-intel fetch for %d URL(s): %s",
                len(self._urls),
                ", ".join(self._urls),
            )
        # Fetch blocklists in a background task so HA setup is not blocked by
        # potentially slow or large downloads (multi-MB hosts files take >15 s).
        self._start_fetch()
        self._refresh_task = asyncio.create_task(
            self._refresh_loop(), name="homesec_blocklist_refresh"
        )
        self._resolve_task = asyncio.create_task(
            self._resolve_worker(), name="homesec_rdns_worker"
        )

    def _start_fetch(self) -> None:
        self._fetch_task = asyncio.create_task(self._fetch_all(), name="homesec_blocklist_fetch")
        self._fetch_task.add_done_callback(self._on_fetch_done)

    @staticmethod
    def _on_fetch_done(task: asyncio.Task) -> None:
        if task.cancelled():
            # Normal during integration reload — not an error.
            _LOGGER.debug("HomeSec: blocklist fetch task cancelled (integration reload?)")
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error(
                "HomeSec: threat-intel fetch task raised an unexpected exception: %s",
                exc, exc_info=exc,
            )

    @staticmethod
    async def _cancel(task: asyncio.Task | None) -> None:
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def async_stop(self) -> None:
        for task in (self._fetch_task, self._refresh_task, self._resolve_task):
            await self._cancel(task)
        self._fetch_task = self._refresh_task = self._resolve_task = None

    async def async_force_refresh(self) -> None:
        """Re-download all URLs now; current lists stay active until the new ones are ready."""
        await self._cancel(self._fetch_task)
        _LOGGER.info("HomeSec: force-refreshing threat intel from %d URL(s)", len(self._urls))
        self._start_fetch()

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

    def check(self, indicator: str) -> dict[str, Any] | None:
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

    def stats(self) -> dict[str, Any]:
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
        self._cache_hostname(ip, hostname)
        return hostname

    def _cache_hostname(self, ip: str, hostname: str | None) -> None:
        self._hostname_cache[ip] = hostname
        while len(self._hostname_cache) > MAX_HOSTNAME_CACHE:
            # dicts keep insertion order: drop the oldest entry
            self._hostname_cache.pop(next(iter(self._hostname_cache)))

    # ------------------------------------------------------------------ #
    # Private helpers

    async def _rdns(self, ip: str) -> str | None:
        """Reverse lookup via aiodns (non-blocking; no executor thread per query)."""
        if self._aiodns is None:
            try:
                import aiodns  # noqa: PLC0415 - shipped with Home Assistant core

                self._aiodns = aiodns.DNSResolver(timeout=_LOOKUP_TIMEOUT, tries=1)
            except Exception:  # noqa: BLE001
                self._aiodns = False
        if self._aiodns:
            try:
                result = await asyncio.wait_for(
                    self._aiodns.gethostbyaddr(ip), timeout=_LOOKUP_TIMEOUT + 1
                )
                return str(result.name) or None
            except Exception:  # noqa: BLE001 - NXDOMAIN, timeout, ...
                return None
        # Fallback: blocking resolver in the executor
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=_LOOKUP_TIMEOUT,
            )
            return result[0]
        except Exception:  # noqa: BLE001
            return None

    async def _resolve_worker(self) -> None:
        while True:
            ip = await self._resolve_queue.get()
            if ip not in self._hostname_cache:
                self._cache_hostname(ip, await self._rdns(ip))

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(_REFRESH_HOURS * 3600)
            await self._cancel(self._fetch_task)
            self._start_fetch()
            # Wait for this cycle so refreshes never overlap
            assert self._fetch_task is not None
            try:
                await asyncio.shield(self._fetch_task)
            except Exception:  # noqa: BLE001 - logged by _on_fetch_done
                pass

    async def _fetch_all(self) -> None:
        """Refresh every URL, then swap the combined lists in atomically.

        The active lists stay in place while downloading.  Each source keeps
        its last good list (also across restarts, see export_state), so a
        failed or unchanged download never removes entries.
        """
        for url in self._urls:
            try:
                changed = await self._fetch_one(url)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.error("HomeSec: blocklist download FAILED for %s: %s", url, exc)
                continue
            state = self._source_state.get(url)
            if changed and state is not None:
                _LOGGER.info(
                    "HomeSec: loaded %d domains + %d IPs from %s",
                    len(state["domains"]), len(state["ips"]), _source_name(url),
                )
        self._rebuild_active()
        self._last_refresh = datetime.now(UTC)
        _LOGGER.info(
            "HomeSec: threat intel ready — %d blocked IPs, %d blocked domains from %d source(s)",
            len(self._bad_ips),
            len(self._bad_domains),
            len(self._urls),
        )
        if self._urls and not self._bad_domains and not self._bad_ips:
            _LOGGER.error(
                "HomeSec: threat intel loaded ZERO entries — check blocklist URLs and HA "
                "network connectivity (Settings \u2192 System \u2192 Logs for details)"
            )

    def _rebuild_active(self) -> None:
        """Combine the per-source lists of the configured URLs into the active sets."""
        domains: set[str] = set()
        ips: set[str] = set()
        sources: dict[str, str] = {}
        for url in self._urls:
            state = self._source_state.get(url)
            if not state:
                continue
            label = _source_name(url)
            for domain in state["domains"]:
                domains.add(domain)
                sources.setdefault(domain, label)
            for ip in state["ips"]:
                ips.add(ip)
                sources.setdefault(ip, label)
        self._bad_domains = domains
        self._bad_ips = ips
        self._source_map = sources

    async def _fetch_one(self, url: str) -> bool:
        """Refresh one blocklist; returns True when new content was downloaded.

        Sends If-None-Match / If-Modified-Since from the previous download,
        so an unchanged list costs a 304 instead of a full transfer.  Raises
        or returns False on failure (the previous list stays in use).
        """
        import aiohttp as _aiohttp  # imported here to avoid circular init issues

        previous = self._source_state.get(url) or {}
        headers: dict[str, str] = {}
        if previous.get("etag"):
            headers["If-None-Match"] = previous["etag"]
        if previous.get("last_modified"):
            headers["If-Modified-Since"] = previous["last_modified"]
        async with self._session.get(
            url,
            headers=headers,
            timeout=_aiohttp.ClientTimeout(sock_connect=10, sock_read=_FETCH_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status == 304 and previous:
                previous["checked_at"] = datetime.now(UTC).isoformat()
                self._state_dirty = True
                _LOGGER.debug("HomeSec: blocklist %s unchanged (304)", url)
                return False
            if resp.status != 200:
                _LOGGER.warning("HomeSec: blocklist %s returned HTTP %d", url, resp.status)
                return False
            text = await resp.text(encoding="utf-8", errors="replace")
            etag = resp.headers.get("ETag")
            last_modified = resp.headers.get("Last-Modified")

        # Parse in a thread-pool executor so large files (100k+ lines) do not
        # block the asyncio event loop and cause DNS query timeouts.
        loop = asyncio.get_running_loop()
        domains, ips, _ = await loop.run_in_executor(None, _parse_blocklist_text, text, _source_name(url))
        now = datetime.now(UTC).isoformat()
        self._source_state[url] = {
            "etag": etag,
            "last_modified": last_modified,
            "fetched_at": now,
            "checked_at": now,
            "domains": sorted(domains),
            "ips": sorted(ips),
        }
        self._state_dirty = True
        return True

    # ------------------------------------------------------------------ #
    # Persistence

    def export_state(self) -> dict[str, Any]:
        """Per-source lists and HTTP validators, for Store."""
        return {"sources": {url: dict(state) for url, state in self._source_state.items() if url in self._urls}}

    def import_state(self, data: Any) -> None:
        """Restore lists saved by export_state and activate them immediately."""
        sources = data.get("sources") if isinstance(data, dict) else None
        if not isinstance(sources, dict):
            return
        for url, state in sources.items():
            if url not in self._urls or not isinstance(state, dict):
                continue
            domains = state.get("domains")
            ips = state.get("ips")
            if not isinstance(domains, list) or not isinstance(ips, list):
                continue
            self._source_state[url] = {
                "etag": state.get("etag") if isinstance(state.get("etag"), str) else None,
                "last_modified": state.get("last_modified") if isinstance(state.get("last_modified"), str) else None,
                "fetched_at": str(state.get("fetched_at") or ""),
                "checked_at": str(state.get("checked_at") or ""),
                "domains": [str(d) for d in domains],
                "ips": [str(i) for i in ips],
            }
        if self._source_state:
            self._rebuild_active()
            checked = [s["checked_at"] for s in self._source_state.values() if s["checked_at"]]
            if checked:
                try:
                    self._last_refresh = datetime.fromisoformat(max(checked))
                except ValueError:
                    pass
            _LOGGER.info(
                "HomeSec: restored %d blocked domains + %d IPs from storage",
                len(self._bad_domains), len(self._bad_ips),
            )

    @property
    def is_state_dirty(self) -> bool:
        return self._state_dirty

    def mark_state_clean(self) -> None:
        self._state_dirty = False
