"""DNS Proxy for Home Security Assistant.

Listens on a UDP port (default 53), forwards every query to a configurable
upstream resolver (default 1.1.1.1), logs all queries in a ring buffer, and
checks queried domain names against the DNSBlacklistChecker threat-intel lists.

Architecture
------------
DNSProxyServer          — lifecycle wrapper (start / stop / stats)
DNSProxyProtocol        — asyncio DatagramProtocol; one per bound socket
_UpstreamProtocol       — one-shot protocol for each upstream relay leg

A query arriving from a LAN client is processed as follows:
  1. Parse the DNS question section to extract (qname, qtype).
  2. Check qname against DNSBlacklistChecker.check().
  3. Append a log entry to the shared deque (ring buffer).
  4. If malicious, call the on_malicious callback (fires HA event + finding).
  5. Open a one-shot UDP socket to the upstream resolver and relay the raw
     query bytes unchanged.  When the response arrives it is forwarded back
     to the original client and the upstream socket is closed.

Notes
-----
* No caching is done here — the upstream resolver is expected to handle that.
* EDNS0 / TCP fallback is NOT supported; TCP DNS is out of scope for this
  simple proxy.
* PTR (reverse DNS) queries are forwarded and logged like any other query;
  they are not blacklist-checked (qnames are in-addr.arpa form).
"""
from __future__ import annotations

import asyncio
import logging
import struct
from collections import deque
from datetime import datetime, UTC
from typing import Callable

_LOGGER = logging.getLogger(__name__)

DNS_LOG_MAX = 10_000  # ring-buffer capacity

# Human-readable QTYPE names for the most common record types
_QTYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}


def _parse_dns_question(data: bytes) -> tuple[str, str] | None:
    """Extract (qname, qtype_str) from the first question in a DNS message.

    Returns None if the message is malformed or contains no questions.
    The returned qname is lower-cased and has no trailing dot.
    """
    try:
        if len(data) < 13:
            return None
        qdcount = struct.unpack_from("!H", data, 4)[0]
        if qdcount == 0:
            return None
        pos = 12
        labels: list[str] = []
        max_pos = len(data)
        while pos < max_pos:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if (length & 0xC0) == 0xC0:
                # Pointer — shouldn't appear in questions but skip safely
                pos += 2
                break
            pos += 1
            end = pos + length
            if end > max_pos:
                return None
            labels.append(data[pos:end].decode("ascii", errors="replace"))
            pos = end
        if pos + 4 > max_pos:
            return None
        qtype = struct.unpack_from("!H", data, pos)[0]
        qname = ".".join(labels).lower().rstrip(".")
        return qname, _QTYPES.get(qtype, str(qtype))
    except Exception:
        return None


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """One-shot: send the raw DNS query to upstream, relay the response back."""

    def __init__(
        self,
        query: bytes,
        client_transport: asyncio.DatagramTransport,
        client_addr: tuple[str, int],
    ) -> None:
        self._query = query
        self._client_transport = client_transport
        self._client_addr = client_addr
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        transport.sendto(self._query)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if self._client_transport and not self._client_transport.is_closing():
            self._client_transport.sendto(data, self._client_addr)
        if self._transport:
            self._transport.close()

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("DNS proxy upstream error: %s", exc)
        if self._transport:
            self._transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class DNSProxyProtocol(asyncio.DatagramProtocol):
    """asyncio UDP DatagramProtocol — one instance per bound DNS proxy socket."""

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int,
        checker,  # DNSBlacklistChecker
        dns_log: deque,
        on_malicious: Callable[[str, str, str, dict], None],
    ) -> None:
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._checker = checker
        self._dns_log = dns_log
        self._on_malicious = on_malicious
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple) -> None:
        src_ip = str(addr[0])
        question = _parse_dns_question(data)
        qname = question[0] if question else ""
        qtype = question[1] if question else "?"
        is_malicious = False
        hit: dict | None = None

        if qname and not qname.endswith(".in-addr.arpa") and not qname.endswith(".ip6.arpa"):
            hit = self._checker.check(qname)
            if hit:
                is_malicious = True
                self._on_malicious(src_ip, qname, qtype, hit)

        self._dns_log.append({
            "ts": datetime.now(UTC).isoformat(),
            "src": src_ip,
            "domain": qname,
            "qtype": qtype,
            "malicious": is_malicious,
        })

        # Forward to upstream
        if self._transport is None or self._transport.is_closing():
            return
        try:
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(
                lambda: _UpstreamProtocol(data, self._transport, addr),
                remote_addr=(self._upstream_host, self._upstream_port),
            )
        except Exception as exc:
            _LOGGER.debug("DNS proxy forward error for %s: %s", qname, exc)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("DNS proxy socket error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class DNSProxyServer:
    """Lifecycle wrapper: create, start, stop, and expose stats for the DNS proxy."""

    def __init__(
        self,
        host: str,
        port: int,
        upstream: str,
        checker,  # DNSBlacklistChecker
        dns_log: deque,
        on_malicious: Callable[[str, str, str, dict], None],
    ) -> None:
        self._host = host
        self._port = port
        self._upstream_host, self._upstream_port = self._parse_upstream(upstream)
        self._checker = checker
        self._dns_log = dns_log
        self._on_malicious = on_malicious
        self._transport: asyncio.DatagramTransport | None = None
        self._running = False

    @staticmethod
    def _parse_upstream(upstream: str) -> tuple[str, int]:
        """Split 'host:port' or bare 'host' into (host, port) defaulting to 53."""
        upstream = upstream.strip()
        # IPv6 literal with port: [::1]:53
        if upstream.startswith("["):
            rbracket = upstream.find("]")
            if rbracket != -1 and rbracket + 1 < len(upstream) and upstream[rbracket + 1] == ":":
                return upstream[1:rbracket], int(upstream[rbracket + 2:])
            return upstream[1:upstream.find("]")] if rbracket != -1 else upstream, 53
        # IPv4 or hostname with port: 1.1.1.1:53
        if ":" in upstream:
            host, _, port = upstream.rpartition(":")
            return host, int(port)
        return upstream, 53

    async def async_start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: DNSProxyProtocol(
                    self._upstream_host,
                    self._upstream_port,
                    self._checker,
                    self._dns_log,
                    self._on_malicious,
                ),
                local_addr=(self._host, self._port),
            )
            self._transport = transport
            self._running = True
            _LOGGER.info(
                "HomeSec DNS proxy listening on %s:%d → upstream %s:%d",
                self._host, self._port,
                self._upstream_host, self._upstream_port,
            )
        except OSError as exc:
            _LOGGER.error(
                "HomeSec DNS proxy could not bind %s:%d — %s. "
                "Check whether another service (e.g. systemd-resolved or AdGuard) "
                "already owns port %d, or change dns_proxy_port in integration options.",
                self._host, self._port, exc, self._port,
            )

    async def async_stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def stats(self) -> dict:
        return {
            "running": self._running,
            "host": self._host,
            "port": self._port,
            "upstream": f"{self._upstream_host}:{self._upstream_port}",
        }
