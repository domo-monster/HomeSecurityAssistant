"""NetFlow / IPFIX parser tests, including fuzzing."""

from __future__ import annotations

import ipaddress
import struct

from hypothesis import given, settings, strategies as st

from custom_components.homesec.netflow import (
    MAX_TEMPLATES_PER_EXPORTER,
    NetFlowDatagramProtocol,
    NetFlowParser,
    parse_exporter_allowlist,
)

EXPORTER = "192.168.1.1"


def _v5_datagram(records: list[tuple[str, str, int, int]]) -> bytes:
    header = struct.pack("!HHIIIIBBH", 5, len(records), 0, 1_700_000_000, 0, 0, 0, 0, 0)
    body = b""
    for src, dst, sport, dport in records:
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            int(ipaddress.IPv4Address(src)),
            int(ipaddress.IPv4Address(dst)),
            0, 0, 0,
            10,      # packets
            1500,    # octets
            0, 0,
            sport, dport,
            0, 0x18, 6, 0, 0, 0, 0, 0, 0,
        )
    return header + body


def _v9_template(template_id: int, fields: list[tuple[int, int]], source_id: int = 1) -> bytes:
    template = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        template += struct.pack("!HH", ftype, flen)
    flowset = struct.pack("!HH", 0, 4 + len(template)) + template
    header = struct.pack("!HHIIII", 9, 1, 0, 1_700_000_000, 0, source_id)
    return header + flowset


def _v9_data(template_id: int, payload: bytes, source_id: int = 1) -> bytes:
    flowset = struct.pack("!HH", template_id, 4 + len(payload)) + payload
    header = struct.pack("!HHIIII", 9, 1, 0, 1_700_000_000, 0, source_id)
    return header + flowset


IPV4_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]


def _v9_record(src: str, dst: str, sport: int, dport: int) -> bytes:
    return (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!HHBII", sport, dport, 6, 4096, 3)
    )


def test_v5_parses_records() -> None:
    parser = NetFlowParser()
    records = parser.parse(
        _v5_datagram([("192.168.1.10", "8.8.8.8", 51000, 443), ("192.168.1.11", "1.1.1.1", 51001, 53)]),
        EXPORTER,
    )
    assert [(str(r.src_ip), str(r.dst_ip), r.dst_port) for r in records] == [
        ("192.168.1.10", "8.8.8.8", 443),
        ("192.168.1.11", "1.1.1.1", 53),
    ]
    assert records[0].octets == 1500
    assert parser.snapshot_stats()["parsed_datagrams"] == 1


def test_v5_truncated_is_ignored() -> None:
    parser = NetFlowParser()
    data = _v5_datagram([("10.0.0.1", "10.0.0.2", 1, 2)])
    assert parser.parse(data[:-5], EXPORTER) == []


def test_v9_template_then_data() -> None:
    parser = NetFlowParser()
    assert parser.parse(_v9_template(256, IPV4_FIELDS), EXPORTER) == []
    records = parser.parse(
        _v9_data(256, _v9_record("10.0.0.5", "93.184.216.34", 40000, 80)), EXPORTER
    )
    assert len(records) == 1
    assert str(records[0].dst_ip) == "93.184.216.34"
    assert records[0].dst_port == 80
    assert records[0].octets == 4096


def test_v9_data_without_template_is_counted() -> None:
    parser = NetFlowParser()
    assert parser.parse(_v9_data(300, b"\x00" * 21), EXPORTER) == []
    assert parser.snapshot_stats()["data_sets_without_template"] == 1


def test_template_cache_is_capped_per_exporter() -> None:
    parser = NetFlowParser()
    for template_id in range(256, 256 + MAX_TEMPLATES_PER_EXPORTER + 50):
        parser.parse(_v9_template(template_id, IPV4_FIELDS), EXPORTER)
    stats = parser.snapshot_stats()
    assert stats["active_templates"] == MAX_TEMPLATES_PER_EXPORTER
    assert stats["templates_rejected"] == 50
    # A different exporter still gets its own quota
    parser.parse(_v9_template(256, IPV4_FIELDS), "192.168.1.2")
    assert parser.snapshot_stats()["active_templates"] == MAX_TEMPLATES_PER_EXPORTER + 1


def test_existing_template_can_be_refreshed_at_cap() -> None:
    parser = NetFlowParser()
    for template_id in range(256, 256 + MAX_TEMPLATES_PER_EXPORTER):
        parser.parse(_v9_template(template_id, IPV4_FIELDS), EXPORTER)
    parser.parse(_v9_template(256, IPV4_FIELDS), EXPORTER)
    assert parser.snapshot_stats()["templates_rejected"] == 0


def test_exporter_allowlist() -> None:
    received: list = []
    proto = NetFlowDatagramProtocol(
        received.append, allowed_exporters=parse_exporter_allowlist("192.168.1.1, 10.0.0.0/8")
    )
    data = _v5_datagram([("192.168.1.10", "8.8.8.8", 1, 443)])
    proto.datagram_received(data, ("192.168.1.99", 2055))
    assert received == []
    assert proto.snapshot_stats()["rejected_datagrams"] == 1
    proto.datagram_received(data, ("192.168.1.1", 2055))
    proto.datagram_received(data, ("10.20.30.40", 2055))
    assert len(received) == 2


def test_empty_allowlist_accepts_everyone() -> None:
    received: list = []
    proto = NetFlowDatagramProtocol(received.append, allowed_exporters=parse_exporter_allowlist(""))
    proto.datagram_received(_v5_datagram([("192.168.1.10", "8.8.8.8", 1, 443)]), ("203.0.113.9", 2055))
    assert len(received) == 1


@settings(max_examples=400, deadline=None)
@given(st.binary(max_size=1500))
def test_fuzz_parser_never_raises(data: bytes) -> None:
    parser = NetFlowParser()
    records = parser.parse(data, EXPORTER)
    assert isinstance(records, list)


@settings(max_examples=300, deadline=None)
@given(
    st.lists(st.tuples(st.integers(0, 400), st.integers(0, 70)), min_size=1, max_size=12),
    st.binary(max_size=600),
)
def test_fuzz_template_and_data(fields: list[tuple[int, int]], payload: bytes) -> None:
    parser = NetFlowParser()
    parser.parse(_v9_template(256, fields), EXPORTER)
    records = parser.parse(_v9_data(256, payload), EXPORTER)
    for record in records:
        assert isinstance(record.src_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))


async def test_datagrams_are_processed_in_batches() -> None:
    import asyncio

    batches: list[list] = []
    proto = NetFlowDatagramProtocol(batches.append)
    data = _v5_datagram([("192.168.1.10", "8.8.8.8", 1, 443)])
    for _ in range(5):
        proto.datagram_received(data, ("192.168.1.1", 2055))
    assert batches == []  # nothing parsed inside the receive callback
    await asyncio.sleep(0)
    assert len(batches) == 1 and len(batches[0]) == 5
