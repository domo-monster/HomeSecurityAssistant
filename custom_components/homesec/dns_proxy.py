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
import socket
import struct
from collections import deque
from datetime import datetime, UTC
from typing import Callable

from .dns_categories import categorize_domain

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

_RCODES: dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

# Minimal EDNS0 OPT resource record appended to synthetic responses when the
# client query included an OPT record (RFC 6891 §7: responses MUST include OPT
# when the query did).  Format: root name (1B) + TYPE=OPT (2B) +
# CLASS=UDP-payload-4096 (2B) + TTL=0 (4B) + RDLENGTH=0 (2B) = 11 bytes.
_OPT_RR = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"


def _question_end(data: bytes) -> int:
    """Return the byte offset just past the question section.

    Skips *qdcount* question entries (name + qtype + qclass each).  On any
    parse error returns ``len(data)`` so callers safely include everything.
    This is used to strip EDNS0 OPT records (and any other additional-section
    records) that the client attached to the query before building a synthetic
    response — otherwise those extra bytes end up in the answer section and
    confuse client-side DNS parsers.
    """
    try:
        qdcount = struct.unpack_from("!H", data, 4)[0]
        pos = 12
        for _ in range(qdcount):
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0xC0) == 0xC0:
                    pos += 2
                    break
                pos += 1 + length
            pos += 4  # QTYPE + QCLASS
        return pos
    except Exception:
        return len(data)


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

def _parse_rcode(data: bytes) -> str:
    """Return the RCODE from a DNS response as a human-readable string."""
    if len(data) < 4:
        return "?"
    return _RCODES.get(data[3] & 0x0F, str(data[3] & 0x0F))


def _build_override_response(query: bytes, ip: str, qtype: str) -> bytes:
    """Synthesise a DNS A or AAAA answer for a local DNS override entry.

    Returns a correctly-formed response packet when *qtype* matches the
    address family of *ip* (A↔IPv4, AAAA↔IPv6).  When the types do not
    match (e.g. client asks for AAAA but the override is an IPv4 address)
    a NODATA response (NOERROR, zero answers) is returned so the client
    does not stall waiting for an upstream reply that will never match.
    """
    try:
        try:
            packed = socket.inet_pton(socket.AF_INET, ip)
            override_rtype = 1   # A
        except OSError:
            packed = socket.inet_pton(socket.AF_INET6, ip)
            override_rtype = 28  # AAAA

        if len(query) < 12:
            return b""

        qtype_matches = (
            (qtype == "A" and override_rtype == 1)
            or (qtype == "AAAA" and override_rtype == 28)
        )

        resp = bytearray(query[:12])
        resp[2] = 0x84 | (query[2] & 0x01)  # QR=1, AA=1, RD copied from query
        resp[3] = 0x80                       # RA=1, RCODE=0 (NOERROR)
        # QDCOUNT stays as-is (bytes 4-5 already copied)
        resp[6] = 0; resp[7] = 1 if qtype_matches else 0  # ANCOUNT
        resp[8] = 0; resp[9] = 0    # NSCOUNT
        # Echo EDNS0 OPT record when the query included one (RFC 6891 §7)
        has_edns = struct.unpack_from("!H", query, 10)[0] > 0
        resp[10] = 0; resp[11] = 1 if has_edns else 0  # ARCOUNT
        # Append only the question section — strip EDNS0 OPT records and any
        # other additional-section data the client included in the query.
        q_end = _question_end(query)
        resp += query[12:q_end]

        if qtype_matches:
            # Answer RR: name-ptr 0xC00C → TYPE → CLASS → TTL → RDLENGTH → RDATA
            resp += b"\xc0\x0c"
            resp += struct.pack("!HHIH", override_rtype, 1, 300, len(packed))
            resp += packed

        if has_edns:
            resp += _OPT_RR

        return bytes(resp)
    except Exception:
        return b""


def _build_block_response(query: bytes) -> bytes:
    """Synthesise a minimal NXDOMAIN DNS response to block a query.

    Copies the transaction ID and question section from *query* and sets
    the response flags to QR=1, RCODE=3 (NXDOMAIN) so the client treats
    the domain as non-existent.
    """
    if len(query) < 12:
        return b""
    resp = bytearray(query[:12])
    # Byte 2: QR=1, AA=1 (authoritative — stops resolvers treating NXDOMAIN as
    # provisional and retrying with a secondary DNS), RD copied from query.
    resp[2] = 0x84 | (query[2] & 0x01)
    # Byte 3: RA=1, Z=0, AD=0, CD=0, RCODE=3 (NXDOMAIN)
    resp[3] = 0x83
    resp[6] = resp[7] = 0    # ANCOUNT
    resp[8] = resp[9] = 0    # NSCOUNT
    # Echo EDNS0 OPT record when the query included one (RFC 6891 §7).
    # Without this, RFC-strict resolvers (systemd-resolved, macOS) discard our
    # NXDOMAIN and fall back to the next DNS server, resolving the blocked domain.
    has_edns = struct.unpack_from("!H", query, 10)[0] > 0
    resp[10] = 0; resp[11] = 1 if has_edns else 0  # ARCOUNT
    # Append only the question section — strip EDNS0 OPT records and any
    # other additional-section data the client included in the query.
    q_end = _question_end(query)
    resp += query[12:q_end]
    if has_edns:
        resp += _OPT_RR
    return bytes(resp)


def _parse_first_answer(data: bytes) -> str | None:
    """Extract the first A or AAAA answer value from a DNS response, or None."""
    try:
        if len(data) < 12:
            return None
        qdcount = struct.unpack_from("!H", data, 4)[0]
        ancount = struct.unpack_from("!H", data, 6)[0]
        if ancount == 0:
            return None
        pos = 12
        # skip question section
        for _ in range(qdcount):
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0xC0) == 0xC0:
                    pos += 2
                    break
                pos += 1 + length
            pos += 4  # qtype + qclass
        # walk answer records
        for _ in range(min(ancount, 5)):
            if pos + 2 > len(data):
                break
            if (data[pos] & 0xC0) == 0xC0:
                pos += 2
            else:
                while pos < len(data):
                    length = data[pos]
                    if length == 0:
                        pos += 1
                        break
                    if (length & 0xC0) == 0xC0:
                        pos += 2
                        break
                    pos += 1 + length
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if pos + rdlength > len(data):
                break
            if rtype == 1 and rdlength == 4:
                return socket.inet_ntoa(data[pos : pos + 4])
            if rtype == 28 and rdlength == 16:
                return socket.inet_ntop(socket.AF_INET6, data[pos : pos + 16])
            pos += rdlength
        return None
    except Exception:
        return None

class _UpstreamProtocol(asyncio.DatagramProtocol):
    """One-shot: send the raw DNS query to upstream, relay the response back."""

    def __init__(
        self,
        query: bytes,
        client_transport: asyncio.DatagramTransport,
        client_addr: tuple[str, int],
        log_entry: dict,
    ) -> None:
        self._query = query
        self._client_transport = client_transport
        self._client_addr = client_addr
        self._log_entry = log_entry
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        transport.sendto(self._query)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._log_entry["rcode"] = _parse_rcode(data)
        answer = _parse_first_answer(data)
        if answer:
            self._log_entry["answer"] = answer
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
        upstreams: list[tuple[str, int]],
        checker,  # DNSBlacklistChecker
        dns_log: deque,
        on_malicious: Callable[[str, str, str, dict], None],
        check_sources: set[str] | None = None,
        blocked_categories: set[str] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> None:
        self._upstreams = upstreams  # list of (host, port)
        self._upstream_idx: int = 0  # round-robin cursor
        self._checker = checker
        self._dns_log = dns_log
        self._on_malicious = on_malicious
        self._check_sources = check_sources  # None = all sources allowed
        self._blocked_categories: set[str] = blocked_categories or set()
        self._overrides: dict[str, str] = overrides or {}  # domain → IP
        self._transport: asyncio.DatagramTransport | None = None
        self._total_queries: int = 0
        self._warned_empty: bool = False  # log at most once when blocklist is not yet loaded

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        task = asyncio.ensure_future(self._handle(data, addr))
        task.add_done_callback(self._on_handle_done)

    @staticmethod
    def _on_handle_done(task: asyncio.Task) -> None:
        exc = task.exception() if not task.cancelled() else None
        if exc is not None:
            _LOGGER.error(
                "HSA DNS proxy: unhandled exception in _handle — "
                "query may have been forwarded to upstream instead of blocked: %s",
                exc, exc_info=exc,
            )

    async def _handle(self, data: bytes, addr: tuple) -> None:
        src_ip = str(addr[0])
        self._total_queries += 1
        question = _parse_dns_question(data)
        qname = question[0] if question else ""
        qtype = question[1] if question else "?"
        is_malicious = False
        hit: dict | None = None

        # Local DNS overrides — answer immediately without hitting upstream
        if qname and qname in self._overrides:
            override_ip = self._overrides[qname]
            entry: dict = {
                "timestamp": datetime.now(UTC).isoformat(),
                "src_ip": src_ip,
                "domain": qname,
                "qtype": qtype,
                "malicious": False,
                "category": "override",
                "status": "overridden",
                "rcode": "NOERROR",
                "answer": override_ip,
            }
            self._dns_log.append(entry)
            if self._transport and not self._transport.is_closing():
                resp = _build_override_response(data, override_ip, qtype)
                if resp:
                    self._transport.sendto(resp, addr)
            return

        if qname and not qname.endswith(".in-addr.arpa") and not qname.endswith(".ip6.arpa"):
            checker_stats = self._checker.stats()
            if not checker_stats["bad_domains"] and not checker_stats["bad_ips"]:
                if not self._warned_empty:
                    self._warned_empty = True
                    _LOGGER.warning(
                        "HSA DNS proxy: threat intel blocklist not yet loaded — "
                        "domain queries will NOT be checked until download completes. "
                        "Check HA logs for 'HSA: threat intel ready'."
                    )
            else:
                # List is now populated — reset so we log once when it was empty and once when ready
                if self._warned_empty:
                    self._warned_empty = False
                    _LOGGER.warning(
                        "HSA DNS proxy: threat intel blocklist is now active — "
                        "%d domains + %d IPs loaded, blocking is live.",
                        checker_stats["bad_domains"], checker_stats["bad_ips"],
                    )
            raw_hit = self._checker.check(qname)
            if raw_hit:
                # Filter by allowed sources if configured
                if self._check_sources is None or raw_hit.get("source", "") in self._check_sources:
                    hit = raw_hit
                    is_malicious = True
                else:
                    _LOGGER.warning(
                        "HSA DNS proxy: %s matched blocklist (source: %s) but was NOT blocked — "
                        "source excluded by the 'check_sources' filter (active filter: %s)",
                        qname, raw_hit.get("source", "?"), self._check_sources,
                    )

        # Content category and filtering decision
        category = "malware" if is_malicious else (categorize_domain(qname) if qname else "other")
        # Threat-intel hits are always blocked; category-based blocking is additive.
        blocked = is_malicious or (bool(self._blocked_categories) and category in self._blocked_categories)

        entry: dict = {
            "timestamp": datetime.now(UTC).isoformat(),
            "src_ip": src_ip,
            "domain": qname,
            "qtype": qtype,
            "malicious": is_malicious,
            "category": category,
            "status": "blocked" if blocked else "allowed",
            "rcode": None,
            "answer": None,
        }
        self._dns_log.append(entry)

        if blocked:
            # Send NXDOMAIN FIRST, before any callbacks that could raise and
            # prevent the block from taking effect.
            if self._transport and not self._transport.is_closing():
                block_resp = _build_block_response(data)
                if block_resp:
                    self._transport.sendto(block_resp, addr)
            entry["rcode"] = "NXDOMAIN"
            _LOGGER.warning(
                "HSA DNS proxy: BLOCKED %s [%s] from %s (reason: %s / source: %s)",
                qname, qtype, src_ip,
                "threat_intel" if is_malicious else category,
                hit.get("source", "n/a") if hit else category,
            )
            if is_malicious and hit:
                try:
                    self._on_malicious(src_ip, qname, qtype, hit)
                except Exception as exc:  # noqa: BLE001
                    _LOGGER.error("HSA DNS proxy: on_malicious callback error: %s", exc)
            return

        # Forward to upstream (round-robin across configured upstreams)
        if self._transport is None or self._transport.is_closing():
            return
        upstream_host, upstream_port = self._upstreams[self._upstream_idx % len(self._upstreams)]
        self._upstream_idx += 1
        try:
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(
                lambda: _UpstreamProtocol(data, self._transport, addr, entry),
                remote_addr=(upstream_host, upstream_port),
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
        check_sources: set[str] | None = None,
        blocked_categories: set[str] | None = None,
        overrides_raw: str = "",
    ) -> None:
        self._host = host
        self._port = port
        self._upstreams: list[tuple[str, int]] = [
            self._parse_upstream(u) for u in upstream.split(",") if u.strip()
        ] or [("1.1.1.1", 53)]
        self._checker = checker
        self._dns_log = dns_log
        self._on_malicious = on_malicious
        self._check_sources = check_sources
        self._blocked_categories = blocked_categories
        self._overrides: dict[str, str] = self._parse_overrides(overrides_raw)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: DNSProxyProtocol | None = None
        self._running = False

    @staticmethod
    def _parse_overrides(raw: str) -> dict[str, str]:
        """Parse 'domain=ip' override lines (one per line or comma-separated)."""
        result: dict[str, str] = {}
        for line in raw.replace(",", "\n").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                domain, _, ip = line.partition("=")
                domain = domain.strip().lower()
                ip = ip.strip()
                if domain and ip:
                    result[domain] = ip
        return result

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
            proto = DNSProxyProtocol(
                self._upstreams,
                self._checker,
                self._dns_log,
                self._on_malicious,
                self._check_sources,
                self._blocked_categories,
                self._overrides,
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self._host, self._port))
            except OSError as bind_exc:
                sock.close()
                _LOGGER.error(
                    "HomeSec DNS proxy could not bind %s:%d — %s. "
                    "Check whether another service (e.g. systemd-resolved or AdGuard) "
                    "already owns port %d, or change dns_proxy_port in integration options.",
                    self._host, self._port, bind_exc, self._port,
                )
                return
            sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: proto,
                sock=sock,
            )
            self._transport = transport
            self._protocol = proto
            self._running = True
            _LOGGER.info(
                "HomeSec DNS proxy listening on %s:%d → upstream(s) %s",
                self._host, self._port,
                ", ".join(f"{h}:{p}" for h, p in self._upstreams),
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
        self._protocol = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def stats(self) -> dict:
        total = self._protocol._total_queries if self._protocol is not None else 0
        return {
            "running": self._running,
            "host": self._host,
            "port": self._port,
            "upstream": ", ".join(f"{h}:{p}" for h, p in self._upstreams),
            "total_queries": total,
        }
