"""Integration tests: config flow, setup/unload, migration, HTTP API access."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events
import yaml

from custom_components.homesec.const import DOMAIN
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component

ENTRY_DATA = {
    "bind_host": "127.0.0.1",
    "bind_port": 2055,
    "enable_netflow_listener": False,
    "internal_networks": "192.168.0.0/16",
}
# Keep the integration offline during tests
ENTRY_OPTIONS = {"enable_scanner": False, "enable_dns_resolution": False}


@pytest.fixture(autouse=True)
def offline_services() -> AsyncGenerator[None]:
    """Stub out every component that would touch the network."""
    with (
        patch("custom_components.homesec.coordinator.DNSBlacklistChecker.async_start", AsyncMock()),
        patch("custom_components.homesec.coordinator.ExternalIPEnricher.async_start", AsyncMock()),
        patch(
            "custom_components.homesec.coordinator.HomeSecCollector._nvd_background_loop",
            AsyncMock(),
        ),
        patch("custom_components.homesec.coordinator.NetworkScanner.async_start", AsyncMock()),
    ):
        yield


async def _setup(hass: HomeAssistant, options: dict | None = None) -> MockConfigEntry:
    await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=ENTRY_DATA,
        options={**ENTRY_OPTIONS, **(options or {})},
        unique_id=DOMAIN,
        minor_version=2,
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


# ── Config flow ──────────────────────────────────────────────────────────────


async def test_config_flow_validates_and_creates(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**ENTRY_DATA, "bind_host": "nope", "internal_networks": "10.0.0.0/33"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"bind_host": "invalid_host", "internal_networks": "invalid_networks"}

    result = await hass.config_entries.flow.async_configure(result["flow_id"], ENTRY_DATA)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "privacy"
    # Both privacy-sensitive features default to off
    defaults = {key.schema: key.default() for key in result["data_schema"].schema}
    assert defaults == {"enable_scanner": False, "enable_ip_geolocation": False}

    with (
        patch("custom_components.homesec.async_setup_entry", return_value=True),
        patch("custom_components.homesec.async_unload_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"enable_scanner": True, "enable_ip_geolocation": False}
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert result["data"]["bind_host"] == "127.0.0.1"
        assert result["options"] == {"enable_scanner": True, "enable_ip_geolocation": False}
        assert result["result"].minor_version == 2
        await hass.config_entries.async_unload(result["result"].entry_id)


async def test_single_instance(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=DOMAIN).add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT


async def test_options_flow_keeps_other_options(hass: HomeAssistant) -> None:
    entry = await _setup(hass, {"stats_top_n": 7})
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**ENTRY_DATA, "internal_networks": "10.0.0.0/8"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert entry.options["stats_top_n"] == 7
    assert entry.options["internal_networks"] == "10.0.0.0/8"
    assert entry.state is ConfigEntryState.LOADED


# ── Setup / unload / migration ───────────────────────────────────────────────


async def test_setup_and_unload(hass: HomeAssistant) -> None:
    entry = await _setup(hass)
    assert entry.state is ConfigEntryState.LOADED
    state = hass.states.get("sensor.home_security_assistant_open_findings")
    assert state is not None
    assert state.attributes["state_class"] == "measurement"
    assert hass.services.has_service(DOMAIN, "trigger_scan")

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED


async def test_legacy_yaml_is_migrated_and_removed(hass: HomeAssistant) -> None:
    config_dir = Path(hass.config.config_dir)
    (config_dir / "homesec.yaml").write_text(
        yaml.safe_dump({"virustotal_api_key": "vt-secret", "scan_exceptions": "192.168.1.9"})
    )
    (config_dir / "homesec_dismissed.yaml").write_text(yaml.safe_dump({"scan:10.0.0.1": "noisy"}))

    entry = await _setup(hass)

    assert not (config_dir / "homesec.yaml").exists()
    assert not (config_dir / "homesec_dismissed.yaml").exists()
    assert entry.options["virustotal_api_key"] == "vt-secret"
    assert entry.runtime_data.collector._dismissed_findings == {"scan:10.0.0.1": "noisy"}


# ── HTTP API ─────────────────────────────────────────────────────────────────


async def test_api_requires_admin_by_default(
    hass: HomeAssistant, hass_client, hass_read_only_access_token
) -> None:
    await _setup(hass)
    user_client = await hass_client(hass_read_only_access_token)
    admin_client = await hass_client()

    for method, path in (
        ("get", "/api/homesec/dashboard"),
        ("get", "/api/homesec/dns/log"),
        ("post", "/api/homesec/findings/dismiss"),
        ("post", "/api/homesec/findings/dismiss_by_pattern"),
        ("post", "/api/homesec/dns/log/clear_blocked"),
        ("get", "/api/homesec/lookup?ip=8.8.8.8"),
        ("get", "/api/homesec/settings"),
    ):
        resp = await getattr(user_client, method)(path, json={})
        assert resp.status == 403, path

    resp = await admin_client.get("/api/homesec/dashboard")
    assert resp.status == 200
    body = await resp.json()
    assert "entries" not in body  # duplicated snapshot no longer sent
    assert body["dns_log_total"] == 0


async def test_non_admin_can_read_when_panel_is_open(
    hass: HomeAssistant, hass_client, hass_read_only_access_token
) -> None:
    await _setup(hass, {"webui_require_admin": False})
    user_client = await hass_client(hass_read_only_access_token)
    assert (await user_client.get("/api/homesec/dashboard")).status == 200
    # Changing state still needs an admin
    resp = await user_client.post("/api/homesec/findings/dismiss", json={"key": "x"})
    assert resp.status == 403


async def test_settings_save_validates(hass: HomeAssistant, hass_client) -> None:
    entry = await _setup(hass)
    client = await hass_client()

    resp = await client.post("/api/homesec/settings/save", json={"bind_port": "abc", "stats_top_n": 5})
    assert resp.status == 400
    body = await resp.json()
    assert "bind_port" in body["errors"]
    assert "stats_top_n" not in entry.options  # nothing saved on error

    resp = await client.post("/api/homesec/settings/save", json={"stats_top_n": 5})
    assert resp.status == 200
    await hass.async_block_till_done()
    assert entry.options["stats_top_n"] == 5
    assert entry.state is ConfigEntryState.LOADED

    resp = await client.get("/api/homesec/settings")
    assert (await resp.json())["config"]["suricata_auth_token"] == ""


async def test_regex_dismiss_rejects_long_and_invalid_patterns(hass: HomeAssistant, hass_client) -> None:
    await _setup(hass)
    client = await hass_client()
    resp = await client.post("/api/homesec/findings/dismiss_by_pattern", json={"pattern": "a" * 201})
    assert resp.status == 400
    resp = await client.post("/api/homesec/findings/dismiss_by_pattern", json={"pattern": "("})
    assert resp.status == 400
    resp = await client.post("/api/homesec/findings/dismiss_by_pattern", json={"pattern": "scan"})
    assert resp.status == 200


# ── Events (H2) ──────────────────────────────────────────────────────────────


async def test_malicious_ip_event_fires_once(hass: HomeAssistant) -> None:
    entry = await _setup(hass)
    collector = entry.runtime_data.collector
    events = async_capture_events(hass, f"{DOMAIN}_malicious_ip")
    payload = {
        "external_ips": [{"ip": "198.51.100.66", "rating": "malicious"}],
        "findings": [],
    }
    collector._fire_transition_events(payload)
    collector._fire_transition_events(payload)
    await hass.async_block_till_done()
    assert len(events) == 1

    collector._fire_transition_events({"external_ips": [], "findings": []})
    collector._fire_transition_events(payload)
    await hass.async_block_till_done()
    assert len(events) == 2  # recurrence after it cleared is announced again


# ── End to end: real NetFlow + Suricata traffic through the dashboard ────────


def _free_port(kind: int) -> int:
    import socket

    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def test_end_to_end_traffic(
    hass: HomeAssistant, hass_client, hass_storage, socket_enabled
) -> None:
    import asyncio
    import json
    import socket

    from tests.test_netflow import _v5_datagram

    netflow_port = _free_port(socket.SOCK_DGRAM)
    suricata_port = _free_port(socket.SOCK_STREAM)
    entry = await _setup(
        hass,
        {
            "bind_host": "127.0.0.1",
            "bind_port": netflow_port,
            "enable_netflow_listener": True,
            "netflow_allowed_exporters": "127.0.0.1",
            "suricata_listener_enabled": True,
            "suricata_listener_host": "127.0.0.1",
            "suricata_listener_port": suricata_port,
            "suricata_auth_token": "tok",
        },
    )
    runtime = entry.runtime_data

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", netflow_port)
    )
    transport.sendto(_v5_datagram([("192.168.1.10", "8.8.8.8", 50000, 443)]))
    transport.close()

    reader, writer = await asyncio.open_connection("127.0.0.1", suricata_port)
    alert = {
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "dest_ip": "8.8.8.8",
        "alert": {"signature": "<b>x</b>", "signature_id": '"><svg onload=alert(1)>', "severity": 2},
    }
    writer.write(b"AUTH tok\n" + json.dumps(alert).encode() + b"\n")
    await writer.drain()
    writer.close()

    for _ in range(100):
        if runtime.collector.suricata_log_snapshot() and runtime.collector._analyzer.get_observed_ips():
            break
        await asyncio.sleep(0.02)

    await runtime.coordinator.async_refresh()
    client = await hass_client()
    body = await (await client.get("/api/homesec/dashboard")).json()
    assert [d["ip"] for d in body["devices"]] == ["192.168.1.10"]
    assert body["suricata_log"][0]["signature_id"] is None
    assert body["suricata_log_total"] == 1
    assert "dns_log" not in runtime.coordinator.data  # served by the API, not coordinator data

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert hass_storage["homesec.suricata_log"]["data"][0]["signature"] == "<b>x</b>"
    assert "homesec.ext_ips" in hass_storage


async def test_external_ip_tracking_is_capped(hass: HomeAssistant) -> None:
    from datetime import UTC, datetime, timedelta

    from custom_components.homesec.coordinator import MAX_TRACKED_EXTERNAL_IPS

    entry = await _setup(hass, {"external_ip_retention_hours": 0})
    collector = entry.runtime_data.collector
    base = datetime.now(UTC) - timedelta(hours=1)
    for i in range(MAX_TRACKED_EXTERNAL_IPS + 25):
        collector._ext_ip_last_seen[f"203.0.{i // 250}.{i % 250}"] = base + timedelta(seconds=i)
    collector._ext_ip_ratings["203.0.0.0"] = "malicious"  # oldest, but kept
    collector.snapshot()
    assert len(collector._ext_ip_last_seen) == MAX_TRACKED_EXTERNAL_IPS
    assert "203.0.0.0" in collector._ext_ip_last_seen
    assert "203.0.0.1" not in collector._ext_ip_last_seen


async def test_failed_setup_does_not_wipe_stored_state(hass: HomeAssistant, hass_storage) -> None:
    hass_storage["homesec.dismissed"] = {
        "version": 1,
        "minor_version": 1,
        "key": "homesec.dismissed",
        "data": {"scan:10.0.0.1": "keep me"},
    }
    with patch(
        "custom_components.homesec.coordinator.HomeSecCollector._async_start_netflow_listener",
        side_effect=OSError("address in use"),
    ):
        await async_setup_component(hass, "http", {})
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={**ENTRY_DATA, "enable_netflow_listener": True},
            options=ENTRY_OPTIONS,
            unique_id=DOMAIN,
        )
        entry.add_to_hass(hass)
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert hass_storage["homesec.dismissed"]["data"] == {"scan:10.0.0.1": "keep me"}


# ── Phase 3 ──────────────────────────────────────────────────────────────────


async def test_migration_keeps_previous_defaults(hass: HomeAssistant) -> None:
    """Entries from 0.10.x keep scanning and geolocation; explicit choices win."""
    await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=ENTRY_DATA,
        options={"enable_dns_resolution": False, "enable_ip_geolocation": False},
        unique_id=DOMAIN,
        version=1,
        minor_version=1,
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.minor_version == 2
    assert entry.options["enable_scanner"] is True
    assert entry.options["enable_ip_geolocation"] is False


async def test_diagnostics_redacts_secrets(hass: HomeAssistant) -> None:
    from custom_components.homesec.diagnostics import async_get_config_entry_diagnostics

    entry = await _setup(hass, {"virustotal_api_key": "vt-secret", "suricata_auth_token": "tok"})
    diag = await async_get_config_entry_diagnostics(hass, entry)
    text = str(diag)
    assert "vt-secret" not in text and "'tok'" not in text
    assert diag["entry"]["options"]["virustotal_api_key"] == "**REDACTED**"
    assert diag["counts"]["devices"] == 0


async def test_repair_issues(hass: HomeAssistant, socket_enabled) -> None:
    import socket

    from homeassistant.helpers import issue_registry as ir

    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    port = busy.getsockname()[1]
    try:
        entry = await _setup(
            hass,
            {
                "suricata_listener_enabled": True,
                "suricata_listener_host": "127.0.0.1",
                "suricata_listener_port": port,  # already taken
            },
        )
        registry = ir.async_get(hass)
        assert entry.state is ConfigEntryState.LOADED  # bind failure no longer aborts setup
        assert registry.async_get_issue(DOMAIN, "suricata_not_running") is not None

        await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()
        assert registry.async_get_issue(DOMAIN, "suricata_not_running") is None
    finally:
        busy.close()


async def test_open_listeners_raise_warnings(hass: HomeAssistant, socket_enabled) -> None:
    from homeassistant.helpers import issue_registry as ir

    entry = await _setup(
        hass,
        {
            "bind_port": _free_port(__import__("socket").SOCK_DGRAM),
            "enable_netflow_listener": True,
            "suricata_listener_enabled": True,
            "suricata_listener_host": "127.0.0.1",
            "suricata_listener_port": _free_port(__import__("socket").SOCK_STREAM),
        },
    )
    registry = ir.async_get(hass)
    assert registry.async_get_issue(DOMAIN, "netflow_open_listener") is not None
    assert registry.async_get_issue(DOMAIN, "suricata_unauthenticated") is not None

    hass.config_entries.async_update_entry(
        entry,
        options={**entry.options, "netflow_allowed_exporters": "127.0.0.1"},
    )
    await hass.async_block_till_done()
    await entry.runtime_data.coordinator.async_refresh()
    assert registry.async_get_issue(DOMAIN, "netflow_open_listener") is None


async def test_scanner_skips_own_addresses(hass: HomeAssistant) -> None:
    import ipaddress

    adapters = [
        {
            "name": "eth0",
            "index": 1,
            "enabled": True,
            "auto": True,
            "default": True,
            "ipv4": [{"address": "192.168.1.2", "network_prefix": 24}],
            "ipv6": [],
        }
    ]
    with patch(
        "homeassistant.components.network.async_get_adapters",
        AsyncMock(return_value=adapters),
    ):
        entry = await _setup(hass, {"internal_networks": "192.168.1.0/24"})
    scanner = entry.runtime_data.collector._scanner
    scanner._internal_networks = [ipaddress.ip_network("192.168.1.0/24")]
    targets = scanner.get_scan_targets()
    assert "192.168.1.2" not in targets
    assert "192.168.1.3" in targets


# ── 0.13: caching and persistence ────────────────────────────────────────────


async def test_panel_url_is_content_hashed(hass: HomeAssistant) -> None:
    await _setup(hass)
    panel = hass.data["frontend_panels"]["homesec"]
    module_url = panel.config["_panel_custom"]["module_url"]
    assert module_url.startswith("/api/homesec/frontend/homesec-panel.js?v=")
    assert len(module_url.split("?v=")[1]) == 12


async def test_downloaded_data_persists_across_reload(hass: HomeAssistant, hass_storage) -> None:
    from datetime import UTC, datetime

    entry = await _setup(hass, {"nvd_api_key": "nvd-key"})
    collector = entry.runtime_data.collector
    assert collector._nvd_client._api_key == "nvd-key"
    url = collector._resolver._urls[0]
    collector._resolver._source_state[url] = {
        "etag": '"x"', "last_modified": None, "fetched_at": datetime.now(UTC).isoformat(),
        "checked_at": datetime.now(UTC).isoformat(), "domains": ["evil.example"], "ips": [],
    }
    collector._kev_client._catalog = {"CVE-1": {"cve_id": "CVE-1"}}
    collector._kev_client._fetched_at = datetime.now(UTC)

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert hass_storage["homesec.blocklists"]["data"]["sources"][url]["domains"] == ["evil.example"]

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    collector = entry.runtime_data.collector
    assert collector._resolver.check("www.evil.example") is not None
    assert collector._kev_client.is_in_kev("CVE-1")


# ── 0.14: websocket push ─────────────────────────────────────────────────────


async def test_dashboard_subscription_pushes_changes(hass: HomeAssistant, hass_ws_client) -> None:
    entry = await _setup(hass)
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "homesec/subscribe_dashboard"})
    result = await client.receive_json()
    assert result["success"] is True
    first = await client.receive_json()
    assert "full" in first["event"]
    assert "dns_log_stats" in first["event"]["full"]

    # A user action changes the findings; a refresh request pushes only that
    entry.runtime_data.collector.dismiss_finding("scan:10.0.0.9", "test")
    entry.runtime_data.role_overrides["192.168.1.50"] = "camera"
    await client.send_json({"id": 2, "type": "homesec/refresh_dashboard"})
    messages = [await client.receive_json(), await client.receive_json()]
    event = next(m for m in messages if m.get("type") == "event")
    assert set(event["event"]["changed"]) == {"role_overrides"}
    assert next(m for m in messages if m.get("type") == "result")["success"] is True


async def test_dashboard_subscription_requires_admin(
    hass: HomeAssistant, hass_ws_client, hass_read_only_access_token
) -> None:
    await _setup(hass)
    client = await hass_ws_client(hass, hass_read_only_access_token)
    await client.send_json({"id": 1, "type": "homesec/subscribe_dashboard"})
    result = await client.receive_json()
    assert result["success"] is False
    assert result["error"]["code"] == "unauthorized"


def test_log_stats_aggregation() -> None:
    from custom_components.homesec.dashboard import build_log_stats

    dns = [
        {"src_ip": "10.0.0.2", "domain": "ads.example", "category": "Ads", "status": "blocked", "malicious": False},
        {"src_ip": "10.0.0.3", "domain": "c2.example", "category": "malware", "status": "blocked", "malicious": True},
        {"src_ip": "10.0.0.2", "domain": "ads.example", "category": "ads", "status": "blocked", "malicious": False},
        {"src_ip": "10.0.0.2", "domain": "ok.example", "category": "other", "status": "allowed", "malicious": False},
    ]
    sur = [{"severity": 1, "category": "Scan", "src_ip": "1.2.3.4"}, {"severity": 3, "category": "", "src_ip": ""}]
    stats = build_log_stats(dns, sur, top_n=1)
    d = stats["dns_log_stats"]
    assert (d["total"], d["blocked"], d["malicious"]) == (4, 3, 1)
    assert d["blocked_by_category"] == [{"cat": "ads", "count": 2}, {"cat": "malware", "count": 1}]
    assert d["blocked_by_client"] == [{"ip": "10.0.0.2", "count": 2}]  # top_n=1
    assert d["top_blocked_domains"] == [{"domain": "ads.example", "count": 2, "category": "Ads"}]
    s = stats["suricata_log_stats"]
    assert s["by_severity"] == {"1": 1, "3": 1}
    assert s["by_category"] == [{"category": "Scan", "count": 1}, {"category": "Other", "count": 1}]
