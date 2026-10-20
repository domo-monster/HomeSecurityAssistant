"""DNS Proxy for Home Security Assistant.

Listens on a UDP port (default 53), forwards every query to a configurable
upstream resolver (default 1.1.1.1), logs all queries in a ring buffer, and
checks queried domain names against the DNSBlacklistChecker threat-intel lists.

Architecture
------------
DNSProxyServer          — lifecycle wrapper (start / stop / stats)
DNSProxyProtocol        — asyncio DatagramProtocol; one per bound socket
_UpstreamClient         — one shared UDP socket per upstream resolver

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
* Queries are accepted over UDP and TCP (RFC 7766), on IPv4 and, when bound
  to 0.0.0.0, also on IPv6.  TCP queries are forwarded to the upstream over
  TCP, so truncated UDP answers can be retried by clients.
* PTR (reverse DNS) queries are forwarded and logged like any other query;
  they are not blacklist-checked (qnames are in-addr.arpa form).
"""
from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
import ipaddress
import logging
import secrets
import socket
import struct

from .dns_categories import categorize_domain

_LOGGER = logging.getLogger(__name__)


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
_UPSTREAM_TIMEOUT_SECONDS = 3.0


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
    except Exception:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
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
        resp[6] = 0
        resp[7] = 1 if qtype_matches else 0  # ANCOUNT
        resp[8] = resp[9] = 0  # NSCOUNT
        # Echo EDNS0 OPT record when the query included one (RFC 6891 §7)
        has_edns = struct.unpack_from("!H", query, 10)[0] > 0
        resp[10] = 0
        resp[11] = 1 if has_edns else 0  # ARCOUNT
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
    except Exception:  # noqa: BLE001
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
    resp[10] = 0
    resp[11] = 1 if has_edns else 0  # ARCOUNT
    # Append only the question section — strip EDNS0 OPT records and any
    # other additional-section data the client included in the query.
    q_end = _question_end(query)
    resp += query[12:q_end]
    if has_edns:
        resp += _OPT_RR
    return bytes(resp)


def _build_refused_response(query: bytes) -> bytes:
    """Synthesise a minimal REFUSED DNS response for denied clients."""
    if len(query) < 12:
        return b""
    resp = bytearray(query[:12])
    resp[2] = 0x80 | (query[2] & 0x01)  # QR=1, RD copied
    resp[3] = 0x85  # RA=1, RCODE=5 (REFUSED)
    resp[6] = resp[7] = 0
    resp[8] = resp[9] = 0
    has_edns = struct.unpack_from("!H", query, 10)[0] > 0
    resp[10] = 0
    resp[11] = 1 if has_edns else 0
    q_end = _question_end(query)
    resp += query[12:q_end]
    if has_edns:
        resp += _OPT_RR
    return bytes(resp)


def _build_servfail_response(query: bytes) -> bytes:
    """Synthesise a minimal SERVFAIL DNS response for upstream timeouts/errors."""
    if len(query) < 12:
        return b""
    resp = bytearray(query[:12])
    resp[2] = 0x80 | (query[2] & 0x01)  # QR=1, RD copied
    resp[3] = 0x82  # RA=1, RCODE=2 (SERVFAIL)
    resp[6] = resp[7] = 0
    resp[8] = resp[9] = 0
    has_edns = struct.unpack_from("!H", query, 10)[0] > 0
    resp[10] = 0
    resp[11] = 1 if has_edns else 0
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
    except Exception:  # noqa: BLE001
        return None

# Queries waiting for an answer per upstream; beyond this the proxy answers
# SERVFAIL immediately instead of queueing without bound.
_MAX_INFLIGHT_PER_UPSTREAM = 1024


class _UpstreamClient(asyncio.DatagramProtocol):
    """One long-lived UDP socket to one upstream resolver, shared by all queries.

    Each forwarded query gets a fresh random transaction ID (so concurrent
    clients that happen to use the same ID never collide).  A response is
    accepted only when its ID is pending and its question section matches the
    one sent; the client's original ID is restored before relaying.
    """

    def __init__(self, host: str, port: int) -> None:
        self._addr = (host, port)
        self._transport: asyncio.DatagramTransport | None = None
        self._connecting: asyncio.Future | None = None
        # new txid -> (original id bytes, question bytes, callback, timeout handle)
        self._pending: dict[int, tuple[bytes, bytes, Callable[[bytes | None], None], asyncio.TimerHandle]] = {}

    @property
    def inflight(self) -> int:
        return len(self._pending)

    async def _ensure_connected(self) -> None:
        if self._transport is not None and not self._transport.is_closing():
            return
        if self._connecting is None or self._connecting.done():
            loop = asyncio.get_running_loop()
            self._connecting = asyncio.ensure_future(
                loop.create_datagram_endpoint(lambda: self, remote_addr=self._addr)
            )
        await asyncio.shield(self._connecting)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def connection_lost(self, exc: Exception | None) -> None:
        self._transport = None  # reconnect on the next query; pending ones time out

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("DNS proxy upstream %s error: %s", self._addr, exc)

    def _new_txid(self) -> int:
        while True:
            txid = secrets.randbelow(0x10000)
            if txid not in self._pending:
                return txid

    async def query(self, query: bytes, callback: Callable[[bytes | None], None]) -> None:
        """Send *query*; *callback* gets the response, or None on timeout/error."""
        if len(query) < 12 or len(self._pending) >= _MAX_INFLIGHT_PER_UPSTREAM:
            callback(None)
            return
        try:
            await self._ensure_connected()
        except OSError as exc:
            _LOGGER.debug("DNS proxy cannot reach upstream %s: %s", self._addr, exc)
            callback(None)
            return
        transport = self._transport
        if transport is None:
            callback(None)
            return
        txid = self._new_txid()
        question = query[12:_question_end(query)].lower()
        handle = asyncio.get_running_loop().call_later(
            _UPSTREAM_TIMEOUT_SECONDS, self._expire, txid
        )
        self._pending[txid] = (query[:2], question, callback, handle)
        transport.sendto(struct.pack("!H", txid) + query[2:])

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 12:
            return
        (txid,) = struct.unpack_from("!H", data)
        pending = self._pending.get(txid)
        if pending is None:
            return
        original_id, question, callback, handle = pending
        if data[12:12 + len(question)].lower() != question:
            return  # not the answer to our question: ignore (spoofing / stale)
        del self._pending[txid]
        handle.cancel()
        callback(original_id + data[2:])

    def _expire(self, txid: int) -> None:
        pending = self._pending.pop(txid, None)
        if pending is not None:
            pending[2](None)

    def close(self) -> None:
        for txid in list(self._pending):
            _, _, callback, handle = self._pending.pop(txid)
            handle.cancel()
            callback(None)
        if self._transport is not None:
            self._transport.close()
            self._transport = None


class _UpstreamPool:
    """Shared upstream clients, one per (host, port)."""

    def __init__(self) -> None:
        self._clients: dict[tuple[str, int], _UpstreamClient] = {}

    def get(self, upstream: tuple[str, int]) -> _UpstreamClient:
        client = self._clients.get(upstream)
        if client is None:
            client = self._clients[upstream] = _UpstreamClient(*upstream)
        return client

    @property
    def inflight(self) -> int:
        return sum(client.inflight for client in self._clients.values())

    def close(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients.clear()


_TCP_IDLE_TIMEOUT_SECONDS = 10.0
_MAX_TCP_CONNECTIONS = 64


async def _read_tcp_message(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Read one length-prefixed DNS message (RFC 1035 §4.2.2); None on EOF/timeout."""
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        (length,) = struct.unpack("!H", header)
        if length == 0:
            return None
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return None


def _frame_tcp_message(message: bytes) -> bytes:
    return struct.pack("!H", len(message)) + message


async def _forward_tcp(query: bytes, upstream: tuple[str, int], entry: dict) -> bytes:
    """Relay *query* to *upstream* over TCP and return the raw response.

    Returns a SERVFAIL response when the upstream is unreachable or slow.
    """
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(upstream[0], upstream[1]),
            timeout=_UPSTREAM_TIMEOUT_SECONDS,
        )
        assert writer is not None
        writer.write(_frame_tcp_message(query))
        await writer.drain()
        response = await _read_tcp_message(reader, _UPSTREAM_TIMEOUT_SECONDS)
    except (TimeoutError, OSError) as exc:
        _LOGGER.debug("DNS proxy TCP upstream error: %s", exc)
        response = None
    finally:
        if writer is not None:
            writer.close()
    if not response:
        entry["rcode"] = "SERVFAIL"
        return _build_servfail_response(query)
    entry["rcode"] = _parse_rcode(response)
    answer = _parse_first_answer(response)
    if answer:
        entry["answer"] = answer
    return response


class DNSProxyProtocol(asyncio.DatagramProtocol):
    """asyncio UDP DatagramProtocol — one instance per bound DNS proxy socket."""

    def __init__(
        self,
        upstreams: list[tuple[str, int]],
        checker,  # DNSBlacklistChecker
        dns_log: deque,
        on_malicious: Callable[[str, str, str, dict], None],
        check_sources: set[str] | None = None,
        allowed_networks: list[ipaddress._BaseNetwork] | None = None,
        blocked_categories: set[str] | None = None,
        warn_blocked_logs: bool = False,
        overrides: dict[str, str] | None = None,
        upstream_pool: _UpstreamPool | None = None,
    ) -> None:
        self._upstreams = upstreams  # list of (host, port)
        self._upstream_pool = upstream_pool or _UpstreamPool()
        self._upstream_idx: int = 0  # round-robin cursor
        self._checker = checker
        self._dns_log = dns_log
        self._on_malicious = on_malicious
        self._check_sources = check_sources  # None = all sources allowed
        self._allowed_networks = allowed_networks
        self._blocked_categories: set[str] = blocked_categories or set()
        self._warn_blocked_logs: bool = bool(warn_blocked_logs)
        self._overrides: dict[str, str] = overrides or {}  # domain → IP
        self._transport: asyncio.DatagramTransport | None = None
        self._total_queries: int = 0
        self._denied_queries: int = 0
        self._warned_empty: bool = False  # log at most once when blocklist is not yet loaded

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    @property
    def total_queries(self) -> int:
        return self._total_queries

    @property
    def denied_queries(self) -> int:
        return self._denied_queries

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        task = asyncio.ensure_future(self._handle(data, addr))
        task.add_done_callback(self._on_handle_done)

    @staticmethod
    def _on_handle_done(task: asyncio.Task) -> None:
        exc = task.exception() if not task.cancelled() else None
        if exc is not None:
            _LOGGER.error(
                "HomeSec DNS proxy: unhandled exception in _handle — "
                "query may have been forwarded to upstream instead of blocked: %s",
                exc, exc_info=exc,
            )

    def evaluate(self, data: bytes, src_ip: str) -> tuple[bytes | None, dict | None]:
        """Decide how to answer one query (transport independent).

        Returns ``(response, None)`` when the proxy answers locally (refused,
        override, blocked) or ``(None, log_entry)`` when the query must be
        forwarded upstream; the caller fills ``rcode``/``answer`` in the
        entry once the upstream reply arrives.
        """
        self._total_queries += 1
        if self._allowed_networks is not None:
            try:
                src_addr = ipaddress.ip_address(src_ip)
            except ValueError:
                src_addr = None
            allowed = src_addr is not None and any(src_addr in net for net in self._allowed_networks)
            if not allowed:
                # Counted, not logged: a flood from outside the ACL must not
                # be able to push real queries out of the log.
                self._denied_queries += 1
                return _build_refused_response(data), None

        question = _parse_dns_question(data)
        qname = question[0] if question else ""
        qtype = question[1] if question else "?"
        is_malicious = False
        hit: dict | None = None

        # Local DNS overrides — answer immediately without hitting upstream
        if qname and qname in self._overrides:
            override_ip = self._overrides[qname]
            override_entry: dict = {
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
            self._dns_log.append(override_entry)
            return _build_override_response(data, override_ip, qtype), None

        if qname and not qname.endswith(".in-addr.arpa") and not qname.endswith(".ip6.arpa"):
            checker_stats = self._checker.stats()
            if not checker_stats["bad_domains"] and not checker_stats["bad_ips"]:
                if not self._warned_empty:
                    self._warned_empty = True
                    _LOGGER.warning(
                        "HomeSec DNS proxy: threat intel blocklist not yet loaded — "
                        "domain queries will NOT be checked until download completes. "
                        "Check HA logs for 'HomeSec: threat intel ready'."
                    )
            else:
                # List is now populated — reset so we log once when it was empty and once when ready
                if self._warned_empty:
                    self._warned_empty = False
                    _LOGGER.warning(
                        "HomeSec DNS proxy: threat intel blocklist is now active — "
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
                        "HomeSec DNS proxy: %s matched blocklist (source: %s) but was NOT blocked — "
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
            block_resp = _build_block_response(data)
            entry["rcode"] = "NXDOMAIN"
            if self._warn_blocked_logs:
                _LOGGER.warning(
                    "HomeSec DNS proxy: BLOCKED %s [%s] from %s (reason: %s / source: %s)",
                    qname, qtype, src_ip,
                    "threat_intel" if is_malicious else category,
                    hit.get("source", "n/a") if hit else category,
                )
            if is_malicious and hit:
                try:
                    self._on_malicious(src_ip, qname, qtype, hit)
                except Exception as exc:  # noqa: BLE001
                    _LOGGER.error("HomeSec DNS proxy: on_malicious callback error: %s", exc)
            return block_resp, None

        return None, entry

    def next_upstream(self) -> tuple[str, int]:
        """Return the next upstream resolver (round-robin)."""
        upstream = self._upstreams[self._upstream_idx % len(self._upstreams)]
        self._upstream_idx += 1
        return upstream

    async def _handle(self, data: bytes, addr: tuple) -> None:
        response, entry = self.evaluate(data, str(addr[0]))
        if self._transport is None or self._transport.is_closing():
            return
        if entry is None:
            # Answered locally (sent before any slow work so blocks always apply)
            if response:
                self._transport.sendto(response, addr)
            return
        transport = self._transport

        def _relay(response: bytes | None) -> None:
            if response is None:
                entry["rcode"] = "SERVFAIL"
                response = _build_servfail_response(data)
            else:
                entry["rcode"] = _parse_rcode(response)
                answer = _parse_first_answer(response)
                if answer:
                    entry["answer"] = answer
            if response and not transport.is_closing():
                transport.sendto(response, addr)

        await self._upstream_pool.get(self.next_upstream()).query(data, _relay)

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
        allowed_subnets: list[str] | None = None,
        blocked_categories: set[str] | None = None,
        warn_blocked_logs: bool = False,
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
        self._allowed_networks = self._parse_networks(allowed_subnets or [])
        self._blocked_categories = blocked_categories
        self._warn_blocked_logs = bool(warn_blocked_logs)
        self._overrides: dict[str, str] = self._parse_overrides(overrides_raw)
        self._transports: list[asyncio.DatagramTransport] = []
        self._tcp_servers: list[asyncio.AbstractServer] = []
        self._tcp_clients = 0
        self._protocols: list[DNSProxyProtocol] = []
        self._upstream_pool = _UpstreamPool()
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
    def _parse_networks(raw_networks: list[str]) -> list[ipaddress._BaseNetwork] | None:
        nets: list[ipaddress._BaseNetwork] = []
        for raw in raw_networks:
            net = raw.strip()
            if not net:
                continue
            try:
                nets.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                _LOGGER.warning("HomeSec DNS proxy: ignoring invalid allowed subnet '%s'", net)
        return nets or None

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
        # Bare IPv6 literal (several colons, no brackets): default port
        if upstream.count(":") > 1:
            return upstream, 53
        # IPv4 or hostname with port: 1.1.1.1:53
        if ":" in upstream:
            host, _, port = upstream.rpartition(":")
            return host, int(port)
        return upstream, 53

    def _bind_hosts(self) -> list[str]:
        """Addresses to listen on: the configured host, plus IPv6 any for 0.0.0.0."""
        if self._host == "0.0.0.0":
            return ["0.0.0.0", "::"]
        return [self._host]

    def _bind_udp(self, host: str) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            sock.bind((host, self._port))
        except OSError:
            sock.close()
            raise
        sock.setblocking(False)
        return sock

    def _new_protocol(self) -> DNSProxyProtocol:
        return DNSProxyProtocol(
            self._upstreams,
            self._checker,
            self._dns_log,
            self._on_malicious,
            self._check_sources,
            self._allowed_networks,
            self._blocked_categories,
            self._warn_blocked_logs,
            self._overrides,
            self._upstream_pool,
        )

    async def async_start(self) -> None:
        loop = asyncio.get_running_loop()
        for index, host in enumerate(self._bind_hosts()):
            # One protocol per socket: each keeps the transport it answers on.
            proto = self._new_protocol()
            # The first address is the configured one and must bind; the
            # implicit IPv6 companion is best effort (host may lack IPv6).
            try:
                sock = self._bind_udp(host)
                transport, _ = await loop.create_datagram_endpoint(
                    lambda proto=proto: proto,  # type: ignore[misc]
                    sock=sock,
                )
            except OSError as exc:
                if index == 0:
                    _LOGGER.error(
                        "HomeSec DNS proxy could not bind %s:%d — %s. "
                        "Check whether another service (e.g. systemd-resolved or AdGuard) "
                        "already owns port %d, or change dns_proxy_port in integration options.",
                        host, self._port, exc, self._port,
                    )
                    await self.async_stop()
                    return
                _LOGGER.debug("HomeSec DNS proxy: IPv6 UDP bind on %s skipped: %s", host, exc)
                continue
            self._transports.append(transport)
            self._protocols.append(proto)
        # TCP clients share a separate protocol instance (no UDP transport).
        self._protocol = self._new_protocol()
        self._running = True

        for host in self._bind_hosts():
            try:
                server = await asyncio.start_server(
                    self._handle_tcp_client, host, self._port, reuse_address=True
                )
            except OSError as exc:
                _LOGGER.warning(
                    "HomeSec DNS proxy: TCP listener on %s:%d unavailable (%s); "
                    "clients retrying truncated answers over TCP will fail",
                    host, self._port, exc,
                )
                continue
            self._tcp_servers.append(server)

        _LOGGER.info(
            "HomeSec DNS proxy listening on %s:%d (UDP%s) → upstream(s) %s",
            self._host, self._port,
            "+TCP" if self._tcp_servers else "",
            ", ".join(f"{h}:{p}" for h, p in self._upstreams),
        )
        if self._host == "0.0.0.0" and self._allowed_networks is None:
            _LOGGER.warning(
                "HomeSec DNS proxy is bound to 0.0.0.0 with no source ACL. "
                "Set dns_proxy_bind_host or internal networks to avoid open-resolver exposure."
            )

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        if self._protocol is None or self._tcp_clients >= _MAX_TCP_CONNECTIONS:
            writer.close()
            return
        self._tcp_clients += 1
        try:
            while True:
                query = await _read_tcp_message(reader, _TCP_IDLE_TIMEOUT_SECONDS)
                if query is None:
                    break
                response, entry = self._protocol.evaluate(query, str(peer[0]))
                if entry is not None:
                    response = await _forward_tcp(query, self._protocol.next_upstream(), entry)
                if not response:
                    break
                writer.write(_frame_tcp_message(response))
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self._tcp_clients -= 1
            writer.close()

    async def async_stop(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports = []
        for server in self._tcp_servers:
            server.close()
        for server in self._tcp_servers:
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._tcp_servers = []
        self._upstream_pool.close()
        self._protocols = []
        self._protocol = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def stats(self) -> dict:
        protocols = list(self._protocols)
        if self._protocol is not None:
            protocols.append(self._protocol)
        total = sum(proto.total_queries for proto in protocols)
        denied = sum(proto.denied_queries for proto in protocols)
        return {
            "running": self._running,
            "host": self._host,
            "port": self._port,
            "upstream": ", ".join(f"{h}:{p}" for h, p in self._upstreams),
            "total_queries": total,
            "denied_queries": denied,
            "upstream_inflight": self._upstream_pool.inflight,
            "tcp": bool(self._tcp_servers),
        }
