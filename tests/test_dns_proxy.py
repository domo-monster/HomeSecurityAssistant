"""DNS proxy tests: packet helpers, decision logic, UDP and TCP transport."""

from __future__ import annotations

import asyncio
from collections import deque
import socket
import struct

from hypothesis import given, settings, strategies as st
import pytest

from custom_components.homesec import dns_proxy
from custom_components.homesec.dns_proxy import (
    DNSProxyProtocol,
    DNSProxyServer,
    _AnswerCache,
    _build_block_response,
    _build_override_response,
    _parse_dns_question,
    _parse_first_answer,
    _UpstreamClient,
)


def _query(name: str, qtype: int = 1, txid: int = 0x1234, edns: bool = False) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 1 if edns else 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    msg = header + qname + struct.pack("!HH", qtype, 1)
    if edns:
        msg += b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
    return msg


class FakeChecker:
    def __init__(self, bad: set[str] | None = None) -> None:
        self.bad = bad or set()

    def stats(self) -> dict:
        return {"bad_domains": len(self.bad), "bad_ips": 0}

    def check(self, name: str):
        parts = name.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in self.bad:
                return {"indicator": name, "type": "domain", "source": "test"}
        return None


def _protocol(**kwargs) -> tuple[DNSProxyProtocol, deque, list]:
    log: deque = deque()
    hits: list = []
    proto = DNSProxyProtocol(
        upstreams=[("127.0.0.1", 53)],
        checker=kwargs.pop("checker", FakeChecker({"evil.example"})),
        dns_log=log,
        on_malicious=lambda *args: hits.append(args),
        **kwargs,
    )
    return proto, log, hits


def test_parse_question() -> None:
    assert _parse_dns_question(_query("WWW.Example.COM", 28)) == ("www.example.com", "AAAA")
    assert _parse_dns_question(b"\x00" * 5) is None


def test_block_response_is_nxdomain_with_same_id() -> None:
    query = _query("evil.example", edns=True)
    resp = _build_block_response(query)
    assert resp[:2] == query[:2]
    assert resp[3] & 0x0F == 3  # NXDOMAIN
    assert struct.unpack_from("!H", resp, 10)[0] == 1  # OPT echoed


def test_override_response_answers_a_record() -> None:
    resp = _build_override_response(_query("nas.lan"), "192.168.1.5", "A")
    assert _parse_first_answer(resp) == "192.168.1.5"


def test_evaluate_blocks_malicious_domain() -> None:
    proto, log, hits = _protocol()
    response, entry = proto.evaluate(_query("cdn.evil.example"), "192.168.1.20")
    assert entry is None and response
    assert response[3] & 0x0F == 3
    assert log[-1]["status"] == "blocked" and log[-1]["malicious"] is True
    assert hits and hits[0][1] == "cdn.evil.example"


def test_evaluate_forwards_clean_domain() -> None:
    proto, log, _ = _protocol()
    response, entry = proto.evaluate(_query("example.org"), "192.168.1.20")
    assert response is None
    assert entry is log[-1] and entry["status"] == "allowed"


def test_evaluate_refuses_clients_outside_acl() -> None:
    proto, log, _ = _protocol(
        allowed_networks=DNSProxyServer._parse_networks(["192.168.0.0/16"])
    )
    response, entry = proto.evaluate(_query("example.org"), "203.0.113.7")
    assert entry is None
    assert response[3] & 0x0F == 5  # REFUSED
    # Counted, not logged: a flood from outside cannot evict real entries
    assert len(log) == 0
    assert proto.denied_queries == 1


def test_evaluate_override() -> None:
    proto, _, _ = _protocol(overrides={"nas.lan": "192.168.1.5"})
    response, entry = proto.evaluate(_query("nas.lan"), "192.168.1.20")
    assert entry is None and _parse_first_answer(response) == "192.168.1.5"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.1.1.1", ("1.1.1.1", 53)),
        ("1.1.1.1:5353", ("1.1.1.1", 5353)),
        ("[2606:4700::1111]:53", ("2606:4700::1111", 53)),
        ("2606:4700::1111", ("2606:4700::1111", 53)),
        ("dns.example", ("dns.example", 53)),
    ],
)
def test_parse_upstream(raw: str, expected: tuple[str, int]) -> None:
    assert DNSProxyServer._parse_upstream(raw) == expected


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=600))
def test_fuzz_packet_helpers_never_raise(data: bytes) -> None:
    _parse_dns_question(data)
    _parse_first_answer(data)
    _build_block_response(data)


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=0, max_size=300))
def test_fuzz_evaluate_never_raises(data: bytes) -> None:
    proto, _, _ = _protocol()
    proto.evaluate(data, "192.168.1.20")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def test_tcp_query_is_forwarded_over_tcp(socket_enabled) -> None:
    """A TCP client query reaches the upstream over TCP and the answer comes back."""
    upstream_queries: list[bytes] = []

    async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        (length,) = struct.unpack("!H", await reader.readexactly(2))
        query = await reader.readexactly(length)
        upstream_queries.append(query)
        answer = _build_override_response(query, "198.51.100.7", "A")
        writer.write(struct.pack("!H", len(answer)) + answer)
        await writer.drain()
        writer.close()

    upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    upstream_port = upstream_server.sockets[0].getsockname()[1]
    proxy_port = _free_port()
    log: deque = deque()
    proxy = DNSProxyServer(
        host="127.0.0.1",
        port=proxy_port,
        upstream=f"127.0.0.1:{upstream_port}",
        checker=FakeChecker({"evil.example"}),
        dns_log=log,
        on_malicious=lambda *args: None,
        allowed_subnets=["127.0.0.0/8"],
    )
    await proxy.async_start()
    try:
        assert proxy.stats()["tcp"] is True
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        for name, expect_upstream in (("example.org", True), ("evil.example", False)):
            query = _query(name)
            writer.write(struct.pack("!H", len(query)) + query)
            await writer.drain()
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            response = await reader.readexactly(length)
            assert response[:2] == query[:2]
            if expect_upstream:
                assert _parse_first_answer(response) == "198.51.100.7"
            else:
                assert response[3] & 0x0F == 3
        writer.close()
        assert len(upstream_queries) == 1
        assert [e["status"] for e in log] == ["allowed", "blocked"]
        assert log[0]["answer"] == "198.51.100.7"
    finally:
        await proxy.async_stop()
        upstream_server.close()
        await upstream_server.wait_closed()


async def test_udp_block_is_answered(socket_enabled) -> None:
    proxy_port = _free_port()
    proxy = DNSProxyServer(
        host="127.0.0.1",
        port=proxy_port,
        upstream="127.0.0.1:9",
        checker=FakeChecker({"evil.example"}),
        dns_log=deque(),
        on_malicious=lambda *args: None,
        allowed_subnets=["127.0.0.0/8"],
    )
    await proxy.async_start()
    try:
        loop = asyncio.get_running_loop()
        received: asyncio.Future[bytes] = loop.create_future()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr) -> None:
                if not received.done():
                    received.set_result(data)

        transport, _ = await loop.create_datagram_endpoint(
            Client, remote_addr=("127.0.0.1", proxy_port)
        )
        transport.sendto(_query("www.evil.example"))
        response = await asyncio.wait_for(received, 2)
        transport.close()
        assert response[3] & 0x0F == 3
        assert proxy.stats()["total_queries"] == 1
    finally:
        await proxy.async_stop()


# ── Shared upstream socket (P5) ──────────────────────────────────────────────


class FakeUpstream(asyncio.DatagramProtocol):
    """UDP resolver on localhost that answers after an optional delay."""

    def __init__(self, delay: float = 0.0, spoof_first: bool = False) -> None:
        self.delay = delay
        self.spoof_first = spoof_first
        self.received: list[bytes] = []
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.received.append(data)
        answer = _build_override_response(data, "198.51.100.7", "A")

        def _send() -> None:
            if self.spoof_first:
                # Same transaction ID, different question: must be ignored
                self.spoof_first = False
                self.transport.sendto(
                    _build_override_response(_query("evil.example", txid=struct.unpack_from("!H", data)[0]), "6.6.6.6", "A"),
                    addr,
                )
            self.transport.sendto(answer, addr)

        asyncio.get_running_loop().call_later(self.delay, _send)


async def _start_upstream(**kwargs) -> tuple[asyncio.DatagramTransport, FakeUpstream, int]:
    loop = asyncio.get_running_loop()
    proto = FakeUpstream(**kwargs)
    transport, _ = await loop.create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", 0))
    return transport, proto, transport.get_extra_info("sockname")[1]


async def _ask(client: _UpstreamClient, query: bytes) -> bytes | None:
    future: asyncio.Future = asyncio.get_running_loop().create_future()
    await client.query(query, lambda resp: future.done() or future.set_result(resp))
    return await asyncio.wait_for(future, 5)


async def test_upstream_client_reuses_one_socket_and_restores_ids(socket_enabled) -> None:
    transport, upstream, port = await _start_upstream(delay=0.05)
    client = _UpstreamClient("127.0.0.1", port)
    try:
        # Two clients that happen to use the same transaction ID, concurrently
        q1, q2 = _query("a.example", txid=0x4242), _query("b.example", txid=0x4242)
        r1, r2 = await asyncio.gather(_ask(client, q1), _ask(client, q2))
        assert r1[:2] == b"\x42\x42" and r2[:2] == b"\x42\x42"
        assert _parse_dns_question(r1)[0] == "a.example"
        assert _parse_dns_question(r2)[0] == "b.example"
        # Upstream saw two different (randomised) IDs from one source port
        ids = {struct.unpack_from("!H", q)[0] for q in upstream.received}
        assert len(ids) == 2
        assert client.inflight == 0
    finally:
        client.close()
        transport.close()


async def test_upstream_client_ignores_mismatched_answer(socket_enabled) -> None:
    transport, _, port = await _start_upstream(spoof_first=True)
    client = _UpstreamClient("127.0.0.1", port)
    try:
        response = await _ask(client, _query("good.example"))
        assert _parse_first_answer(response) == "198.51.100.7"
    finally:
        client.close()
        transport.close()


async def test_upstream_client_timeout_and_cap(socket_enabled, monkeypatch) -> None:
    monkeypatch.setattr(dns_proxy, "_UPSTREAM_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(dns_proxy, "_MAX_INFLIGHT_PER_UPSTREAM", 1)
    transport, _, port = await _start_upstream(delay=5)
    client = _UpstreamClient("127.0.0.1", port)
    try:
        slow = asyncio.ensure_future(_ask(client, _query("slow.example")))
        await asyncio.sleep(0.01)
        assert await _ask(client, _query("over.example")) is None  # over the cap
        assert await slow is None  # timed out
    finally:
        client.close()
        transport.close()


# ── Answer cache (0.14) ──────────────────────────────────────────────────────


def _ttl_of_first_answer(response: bytes) -> int:
    pos = 12
    while response[pos] != 0:
        pos += 1 + response[pos]
    pos += 5  # root label + qtype/qclass
    return struct.unpack_from("!I", response, pos + 2 + 4)[0]


def test_cache_rewrites_id_case_and_ttl(monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(dns_proxy.time, "monotonic", lambda: clock[0])
    cache = _AnswerCache()
    query = _query("www.example.org", txid=0x1111)
    response = _build_override_response(query, "198.51.100.7", "A")  # TTL 300
    cache.put(query, response)
    clock[0] += 120
    hit = cache.get(_query("WwW.ExAmPlE.oRg", txid=0x2222))
    assert hit is not None
    assert hit[:2] == b"\x22\x22"
    assert _parse_dns_question(hit)[0] == "www.example.org"
    assert b"WwW" in hit  # client's case echoed
    assert _ttl_of_first_answer(hit) == 300 - 120
    clock[0] += 200  # past the TTL
    assert cache.get(query) is None


def test_cache_skips_unsafe_answers() -> None:
    cache = _AnswerCache()
    query = _query("x.example")
    good = bytearray(_build_override_response(query, "198.51.100.7", "A"))
    truncated = bytearray(good)
    truncated[2] |= 0x02
    servfail = bytearray(good)
    servfail[3] = (servfail[3] & 0xF0) | 2
    zero_ttl = bytearray(good)
    struct.pack_into("!I", zero_ttl, len(zero_ttl) - 10, 0)
    other_question = _build_override_response(_query("y.example"), "198.51.100.7", "A")
    for bad in (truncated, servfail, zero_ttl, other_question):
        cache.put(query, bytes(bad))
    assert len(cache) == 0
    # different EDNS presence is a different cache entry
    cache.put(query, bytes(good))
    assert cache.get(_query("x.example", edns=True)) is None
    assert cache.get(query) is not None


def test_cache_is_bounded() -> None:
    cache = _AnswerCache(max_entries=3)
    for i in range(5):
        q = _query(f"h{i}.example")
        cache.put(q, _build_override_response(q, "198.51.100.7", "A"))
    assert len(cache) == 3
    assert cache.get(_query("h0.example")) is None
    assert cache.get(_query("h4.example")) is not None


async def test_repeated_query_is_served_from_cache(socket_enabled) -> None:
    transport, upstream, port = await _start_upstream()
    proxy_port = _free_port()
    log: deque = deque()
    proxy = DNSProxyServer(
        host="127.0.0.1", port=proxy_port, upstream=f"127.0.0.1:{port}",
        checker=FakeChecker(), dns_log=log, on_malicious=lambda *a: None,
        allowed_subnets=["127.0.0.0/8"],
    )
    await proxy.async_start()
    try:
        loop = asyncio.get_running_loop()
        for txid in (0x0101, 0x0202):
            received: asyncio.Future = loop.create_future()

            class Client(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr, received=received) -> None:
                    if not received.done():
                        received.set_result(data)

            client, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", proxy_port))
            client.sendto(_query("cached.example", txid=txid))
            response = await asyncio.wait_for(received, 3)
            client.close()
            assert response[:2] == struct.pack("!H", txid)
            assert _parse_first_answer(response) == "198.51.100.7"
        assert len(upstream.received) == 1  # second answer came from the cache
        assert proxy.stats()["cache_hits"] == 1
        assert [e["answer"] for e in log] == ["198.51.100.7", "198.51.100.7"]
    finally:
        await proxy.async_stop()
        transport.close()
