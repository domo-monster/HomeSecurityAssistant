"""DNS proxy tests: packet helpers, decision logic, UDP and TCP transport."""

from __future__ import annotations

import asyncio
from collections import deque
import socket
import struct

from hypothesis import given, settings, strategies as st
import pytest

from custom_components.homesec.dns_proxy import (
    DNSProxyProtocol,
    DNSProxyServer,
    _build_block_response,
    _build_override_response,
    _parse_dns_question,
    _parse_first_answer,
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
    assert log[-1]["status"] == "denied"


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
