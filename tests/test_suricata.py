"""Suricata listener tests: input sanitizing, authentication and source allowlist."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import UTC, datetime, timedelta
import json
import socket

from hypothesis import given, settings, strategies as st

from custom_components.homesec.suricata import (
    SuricataAlertListener,
    parse_allowed_networks,
    sanitize_alert,
    sanitize_stored_record,
)

XSS = '"><img src=x onerror=alert(1)>'


def _alert(**overrides) -> dict:
    alert = {
        "event_type": "alert",
        "timestamp": "2026-01-01T00:00:00+0000",
        "src_ip": "192.168.1.50",
        "src_port": 51515,
        "dest_ip": "203.0.113.10",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"signature": "ET TEST", "signature_id": 2000001, "category": "Test", "severity": 1},
    }
    alert.update(overrides)
    return alert


def test_sanitize_keeps_valid_alert() -> None:
    record = sanitize_alert(_alert())
    assert record is not None
    assert record["signature_id"] == 2000001
    assert record["severity"] == 1
    assert record["src_ip"] == "192.168.1.50"
    assert record["event_timestamp"] == "2026-01-01T00:00:00+0000"


def test_sanitize_rejects_injected_signature_id() -> None:
    record = sanitize_alert(_alert(alert={"signature_id": XSS, "severity": "1; drop"}))
    assert record["signature_id"] is None
    assert record["severity"] == 3


def test_sanitize_rejects_bad_ips_and_types() -> None:
    record = sanitize_alert(_alert(src_ip=XSS, dest_ip={"x": 1}, src_port="99999", proto=["TCP"]))
    assert record["src_ip"] == ""
    assert record["dest_ip"] == ""
    assert record["src_port"] is None
    assert record["proto"] == ""


def test_sanitize_uses_receive_time_not_client_time() -> None:
    now = datetime(2026, 5, 1, tzinfo=UTC)
    record = sanitize_alert(_alert(timestamp="9999-12-31T00:00:00"), received_at=now)
    assert record["timestamp"] == now.isoformat()


def test_sanitize_caps_string_length() -> None:
    record = sanitize_alert(_alert(alert={"signature": "A" * 10_000}))
    assert len(record["signature"]) == 512


def test_non_alerts_are_ignored() -> None:
    assert sanitize_alert({"event_type": "dns"}) is None
    assert sanitize_alert(["not", "a", "dict"]) is None


def test_stored_records_are_revalidated() -> None:
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    future = (datetime.now(UTC) + timedelta(days=365)).isoformat()
    clean = sanitize_stored_record({"timestamp": past, "signature_id": XSS, "src_ip": XSS})
    assert clean is not None and clean["signature_id"] is None and clean["src_ip"] == ""
    assert sanitize_stored_record({"timestamp": future}) is None
    assert sanitize_stored_record({"timestamp": 12345}) is None


@settings(max_examples=300, deadline=None)
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=40),
        lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4),
        max_leaves=20,
    )
)
def test_fuzz_sanitize_returns_safe_types(value) -> None:
    for candidate in (value, {"event_type": "alert", "alert": value, "src_ip": value, "signature_id": value}):
        record = sanitize_alert(candidate)
        if record is None:
            continue
        for key in ("signature_id", "src_port", "dest_port", "flow_id"):
            assert record[key] is None or isinstance(record[key], int)
        assert isinstance(record["severity"], int)
        for key in ("signature", "category", "src_ip", "dest_ip", "proto", "action"):
            assert isinstance(record[key], str)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _send(port: int, lines: list[str]) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for line in lines:
        writer.write((line + "\n").encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _run_listener(socket_enabled, **kwargs) -> tuple[SuricataAlertListener, deque, int]:
    log: deque = deque(maxlen=100)
    port = _free_port()
    listener = SuricataAlertListener("127.0.0.1", port, log, **kwargs)
    await listener.async_start()
    return listener, log, port


async def _wait_for(predicate, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            return
        await asyncio.sleep(0.02)


async def test_listener_requires_token(socket_enabled) -> None:
    listener, log, port = await _run_listener(socket_enabled, auth_token="s3cret")
    try:
        await _send(port, [json.dumps(_alert())])  # no AUTH line
        await _send(port, ["AUTH wrong", json.dumps(_alert())])
        await _wait_for(lambda: listener.stats()["rejected_connections"] >= 2)
        assert len(log) == 0
        await _send(port, ["AUTH s3cret", json.dumps(_alert())])
        await _wait_for(lambda: len(log) == 1)
        assert len(log) == 1
        assert listener.stats()["auth_required"] is True
    finally:
        await listener.async_stop()


async def test_listener_source_allowlist(socket_enabled) -> None:
    listener, log, port = await _run_listener(
        socket_enabled, allowed_networks=parse_allowed_networks("192.0.2.1")
    )
    try:
        await _send(port, [json.dumps(_alert())])
        await _wait_for(lambda: listener.stats()["rejected_connections"] >= 1)
        assert len(log) == 0
    finally:
        await listener.async_stop()


async def test_listener_stores_sanitized_records(socket_enabled) -> None:
    received: list[dict] = []
    listener, log, port = await _run_listener(socket_enabled, on_alert=received.append)
    try:
        await _send(
            port,
            [
                json.dumps(_alert(alert={"signature_id": XSS, "signature": XSS})),
                "not json",
                json.dumps({"event_type": "flow"}),
            ],
        )
        await _wait_for(lambda: len(log) == 1)
        assert len(log) == 1
        assert log[0]["signature_id"] is None
        assert received and received[0] is log[0]
    finally:
        await listener.async_stop()
