"""Threat-intel, enrichment and NVD client tests (no network: fake HTTP session)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from custom_components.homesec.dns_resolver import DNSBlacklistChecker, _parse_blocklist_text
from custom_components.homesec.external_enrichment import ExternalIPEnricher
from custom_components.homesec.nvd_enrichment import NVDClient


class FakeResponse:
    def __init__(self, status: int, body: Any = "", headers: dict | None = None) -> None:
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def text(self, **kwargs) -> str:
        return self._body

    async def json(self, **kwargs) -> Any:
        return self._body

    async def read(self) -> bytes:
        import json

        return json.dumps(self._body).encode() if not isinstance(self._body, (str, bytes)) else (
            self._body.encode() if isinstance(self._body, str) else self._body
        )


class FakeSession:
    """Maps URL prefixes to a response (or an exception) and records calls."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.calls.append(url)
        self.params_sent = getattr(self, "params_sent", []) + [dict(kwargs.get("params") or {})]
        self.headers_sent = getattr(self, "headers_sent", []) + [dict(kwargs.get("headers") or {})]
        for prefix, result in self.routes.items():
            if url.startswith(prefix):
                if isinstance(result, Exception):
                    raise result
                return result
        return FakeResponse(404)


# ── Blocklist parsing ────────────────────────────────────────────────────────


def test_parse_blocklist_formats() -> None:
    text = "\n".join(
        [
            "# comment",
            "0.0.0.0 ads.example",
            "||tracker.example^$third-party",
            "@@||allowed.example^",
            "198.51.100.7",
            "203.0.113.0/32",
            "plain.example",
        ]
    )
    domains, ips, sources = _parse_blocklist_text(text, "src")
    assert domains == {"ads.example", "tracker.example", "plain.example"}
    assert ips == {"198.51.100.7", "203.0.113.0"}
    assert set(sources.values()) == {"src"}


# ── Blocklist refresh (B1, S8) ───────────────────────────────────────────────


async def _wait_fetch(checker: DNSBlacklistChecker) -> None:
    assert checker._fetch_task is not None
    await asyncio.wait_for(asyncio.shield(checker._fetch_task), 5)


async def test_force_refresh_keeps_background_tasks() -> None:
    session = FakeSession({"https://a.example/": FakeResponse(200, "bad.example\n")})
    checker = DNSBlacklistChecker(session, ["https://a.example/list"], enable_resolution=True)
    await checker.async_start()
    try:
        await _wait_fetch(checker)
        refresh_task, resolve_task = checker._refresh_task, checker._resolve_task
        await checker.async_force_refresh()
        await _wait_fetch(checker)
        assert not refresh_task.done() and not resolve_task.done()
        assert checker.check("www.bad.example") is not None
    finally:
        await checker.async_stop()


async def test_failed_download_keeps_previous_entries() -> None:
    session = FakeSession(
        {
            "https://a.example/": FakeResponse(200, "bad-a.example\n"),
            "https://b.example/": FakeResponse(200, "bad-b.example\n198.51.100.9\n"),
        }
    )
    checker = DNSBlacklistChecker(
        session, ["https://a.example/list", "https://b.example/list"], enable_resolution=False
    )
    await checker.async_start()
    try:
        await _wait_fetch(checker)
        assert checker.check("bad-b.example") and checker.check("198.51.100.9")

        # Source b now fails; its entries must survive, a's entries update.
        session.routes["https://a.example/"] = FakeResponse(200, "new-a.example\n")
        session.routes["https://b.example/"] = OSError("network down")
        await checker.async_force_refresh()
        await _wait_fetch(checker)
        assert checker.check("bad-b.example") is not None
        assert checker.check("198.51.100.9") is not None
        assert checker.check("new-a.example") is not None
        assert checker.check("bad-a.example") is None
    finally:
        await checker.async_stop()


async def test_lists_stay_active_while_downloading() -> None:
    gate = asyncio.Event()

    class SlowSession(FakeSession):
        def get(self, url: str, **kwargs):
            response = super().get(url, **kwargs)
            outer = self

            class Slow(FakeResponse):
                async def text(self, **kw) -> str:
                    if outer.calls.count(url) > 1:
                        await gate.wait()
                    return await response.text()

            return Slow(response.status, response._body)

    session = SlowSession({"https://a.example/": FakeResponse(200, "bad.example\n")})
    checker = DNSBlacklistChecker(session, ["https://a.example/list"], enable_resolution=False)
    await checker.async_start()
    try:
        await _wait_fetch(checker)
        await checker.async_force_refresh()
        await asyncio.sleep(0.05)
        assert checker.check("bad.example") is not None  # still blocking mid-refresh
        gate.set()
        await _wait_fetch(checker)
    finally:
        await checker.async_stop()


# ── Enrichment (B2) ──────────────────────────────────────────────────────────


@pytest.fixture
def no_throttle(monkeypatch):
    async def _no_wait(self, provider: str) -> None:
        self._prov_daily_count[provider] = self._prov_daily_count.get(provider, 0) + 1

    monkeypatch.setattr(ExternalIPEnricher, "_throttle", _no_wait)


VT_BODY = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}


async def test_ipwho_is_opt_in(no_throttle) -> None:
    session = FakeSession({"https://ipwho.is/": FakeResponse(200, {"success": True, "country_code": "US"})})
    off = ExternalIPEnricher(session)
    assert not off.has_providers
    off.queue_ip("8.8.8.8")
    assert off._pending.qsize() == 0
    assert (await off._enrich("8.8.8.8"))["sources"] == []
    assert session.calls == []

    on = ExternalIPEnricher(session, enable_ipwho=True)
    result = await on._enrich("8.8.8.8")
    assert result["sources"] == ["ipwho"] and result["country"] == "US"


async def test_virustotal_used_without_abuseipdb(no_throttle) -> None:
    session = FakeSession(
        {
            "https://ipwho.is/": FakeResponse(200, {"success": True, "country_code": "US"}),
            "https://www.virustotal.com/": FakeResponse(200, VT_BODY),
        }
    )
    enricher = ExternalIPEnricher(session, virustotal_key="vt-key")
    result = await enricher._enrich("8.8.8.8")
    assert "virustotal" in result["sources"]
    assert result["rating"] == "malicious"


async def test_virustotal_gated_by_abuseipdb_score(no_throttle) -> None:
    session = FakeSession(
        {
            "https://ipwho.is/": FakeResponse(200, {"success": True}),
            "https://api.abuseipdb.com/": FakeResponse(200, {"data": {"abuseConfidenceScore": 5}}),
            "https://www.virustotal.com/": FakeResponse(200, VT_BODY),
        }
    )
    enricher = ExternalIPEnricher(session, virustotal_key="vt", abuseipdb_key="ab", vt_abuseipdb_threshold=30)
    result = await enricher._enrich("8.8.8.8")
    assert "virustotal" not in result["sources"]
    assert not any(call.startswith("https://www.virustotal.com/") for call in session.calls)


def test_enrichment_cache_is_bounded() -> None:
    from datetime import UTC, datetime

    from custom_components.homesec import external_enrichment

    enricher = ExternalIPEnricher(FakeSession({}))
    for i in range(external_enrichment.MAX_CACHE_ENTRIES + 10):
        enricher._store(f"ip{i}", {"ip": f"ip{i}"}, datetime.now(UTC))
    assert len(enricher._cache) == external_enrichment.MAX_CACHE_ENTRIES
    assert "ip0" not in enricher._cache


# ── NVD (B3) ─────────────────────────────────────────────────────────────────


def _nvd_page(cve_id: str, *criteria: str) -> dict:
    cve: dict = {
        "id": cve_id,
        "published": "2024-01-01T00:00:00",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "descriptions": [{"lang": "en", "value": "test"}],
    }
    if criteria:
        cve["configurations"] = [
            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c, "versionEndExcluding": "1.25.0"} for c in criteria]}]}
        ]
    return {"totalResults": 1, "vulnerabilities": [{"cve": cve}]}


NGINX_CPE = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


async def test_nvd_failure_keeps_previous_cache(monkeypatch) -> None:
    monkeypatch.setattr("custom_components.homesec.nvd_enrichment.asyncio.sleep", _instant_sleep)
    session = FakeSession({"https://nvd.example/": FakeResponse(200, _nvd_page("CVE-2024-0001"))})
    client = NVDClient(session, api_url="https://nvd.example/api", ttl_hours=0, min_year=2020)
    first = await client._get_cached("openssh")
    assert [c["cve_id"] for c in first] == ["CVE-2024-0001"]

    session.routes["https://nvd.example/"] = FakeResponse(429)
    second = await client._get_cached("openssh")
    assert [c["cve_id"] for c in second] == ["CVE-2024-0001"]
    assert client.total_cached_cves == 1


async def _instant_sleep(_delay: float) -> None:
    return None


# ── Persistence and conditional downloads (0.13) ─────────────────────────────


async def test_blocklist_conditional_request_keeps_list() -> None:
    session = FakeSession({"https://a.example/": FakeResponse(200, "bad.example\n", headers={"ETag": '"v1"'})})
    checker = DNSBlacklistChecker(session, ["https://a.example/list"], enable_resolution=False)
    await checker.async_start()
    try:
        await _wait_fetch(checker)
        session.routes["https://a.example/"] = FakeResponse(304, "")
        await checker.async_force_refresh()
        await _wait_fetch(checker)
        assert session.headers_sent[-1].get("If-None-Match") == '"v1"'
        assert checker.check("bad.example") is not None  # 304 kept the list
    finally:
        await checker.async_stop()


async def test_blocklist_state_survives_restart_without_network() -> None:
    session = FakeSession({"https://a.example/": FakeResponse(200, "bad.example\n198.51.100.9\n", headers={"Last-Modified": "Mon, 19 Oct 2026 10:00:00 GMT"})})
    first = DNSBlacklistChecker(session, ["https://a.example/list"], enable_resolution=False)
    await first.async_start()
    await _wait_fetch(first)
    await first.async_stop()
    saved = first.export_state()

    offline = FakeSession({})
    second = DNSBlacklistChecker(offline, ["https://a.example/list", "https://new.example/x"], enable_resolution=False)
    second.import_state(saved)
    # Blocking works before any download
    assert second.check("www.bad.example") is not None
    assert second.check("198.51.100.9") is not None
    assert offline.calls == []
    # State for URLs that are no longer configured is ignored
    third = DNSBlacklistChecker(offline, ["https://other.example/"], enable_resolution=False)
    third.import_state(saved)
    assert third.check("bad.example") is None


async def test_nvd_cache_survives_restart(monkeypatch) -> None:
    monkeypatch.setattr("custom_components.homesec.nvd_enrichment.asyncio.sleep", _instant_sleep)
    page = _nvd_page("CVE-2024-0002", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
    session = FakeSession({"https://nvd.example/": FakeResponse(200, page)})
    client = NVDClient(session, api_url="https://nvd.example/api", ttl_hours=12, min_year=2020)
    await client._get_cached("nginx")
    assert client.is_state_dirty
    saved = client.export_state()

    offline = FakeSession({})
    restored = NVDClient(offline, api_url="https://nvd.example/api", ttl_hours=12, min_year=2020)
    restored.import_state(saved)
    cves = await restored._get_cached("nginx")
    assert [c["cve_id"] for c in cves] == ["CVE-2024-0002"]
    assert offline.calls == []  # still fresh: no download


def test_nvd_api_key_speeds_up_requests() -> None:
    assert NVDClient(FakeSession({}), api_key="key")._rate_delay < 1
    assert NVDClient(FakeSession({}))._rate_delay > 6


async def test_kev_catalog_survives_restart() -> None:
    from custom_components.homesec.nvd_enrichment import CISAKEVClient

    session = FakeSession({"https://www.cisa.gov/": FakeResponse(200, {"vulnerabilities": [{"cveID": "CVE-2024-6387", "product": "OpenSSH"}]})})
    client = CISAKEVClient(session, ttl_hours=24)
    await client.fetch()
    saved = client.export_state()
    offline = FakeSession({})
    restored = CISAKEVClient(offline, ttl_hours=24)
    restored.import_state(saved)
    await restored.fetch()
    assert restored.total == 1 and restored.is_in_kev("CVE-2024-6387")
    assert offline.calls == []


def test_enrichment_cache_survives_restart_and_expires() -> None:
    from datetime import UTC, datetime, timedelta

    enricher = ExternalIPEnricher(FakeSession({}), enrichment_ttl_minutes=60)
    enricher._store("8.8.8.8", {"ip": "8.8.8.8", "rating": "clean"}, datetime.now(UTC))
    enricher._store("1.1.1.1", {"ip": "1.1.1.1"}, datetime.now(UTC) - timedelta(hours=3))
    saved = enricher.export_cache()
    assert [e["ip"] for e in saved["entries"]] == ["8.8.8.8"]  # stale entry not saved

    restored = ExternalIPEnricher(FakeSession({}), enrichment_ttl_minutes=60)
    restored.import_cache(saved)
    assert restored.get("8.8.8.8")["rating"] == "clean"
    assert not restored._is_stale("8.8.8.8")


async def test_nvd_known_products_are_fetched_by_cpe(monkeypatch) -> None:
    monkeypatch.setattr("custom_components.homesec.nvd_enrichment.asyncio.sleep", _instant_sleep)
    page = _nvd_page(
        "CVE-2024-0003",
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*",
        NGINX_CPE,
    )
    session = FakeSession({"https://nvd.example/": FakeResponse(200, page)})
    client = NVDClient(session, api_url="https://nvd.example/api", ttl_hours=12, min_year=2020)
    cves = await client._get_cached("nginx")
    assert session.params_sent[-1]["virtualMatchString"] == "cpe:2.3:*:nginx:nginx:*:*:*:*:*:*:*:*"
    assert "keywordSearch" not in session.params_sent[-1]
    # Only the vulnerable nginx:nginx match is kept
    [config] = cves[0]["configurations"]
    assert [m["criteria"] for m in config["nodes"][0]["cpeMatch"]] == ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]
    assert client.get_cached_cve("CVE-2024-0003") is cves[0]

    # Unknown products still use a keyword search; CVEs are kept as returned
    await client._get_cached("SomeDaemon")
    assert session.params_sent[-1]["keywordSearch"] == "SomeDaemon"
    assert len(client._cache["SomeDaemon"][1][0]["configurations"][0]["nodes"][0]["cpeMatch"]) == 3
    assert client.get_cached_cve("CVE-2024-9999") is None


async def test_nvd_cpe_lookup_drops_cves_without_the_product(monkeypatch) -> None:
    monkeypatch.setattr("custom_components.homesec.nvd_enrichment.asyncio.sleep", _instant_sleep)
    session = FakeSession({"https://nvd.example/": FakeResponse(200, _nvd_page("CVE-2024-0004", NGINX_CPE))})
    client = NVDClient(session, api_url="https://nvd.example/api", ttl_hours=12, min_year=2020)
    assert await client._get_cached("nginx") == []


def test_nvd_keyword_era_cache_is_refetched_for_cpe_products() -> None:
    saved = {
        "cache": {
            "nginx": {"fetched_at": "2026-10-21T00:00:00+00:00", "cves": [{"cve_id": "CVE-1"}]},
            "SomeDaemon": {"fetched_at": "2026-10-21T00:00:00+00:00", "cves": [{"cve_id": "CVE-2"}]},
        }
    }
    client = NVDClient(FakeSession({}), ttl_hours=12)
    client.import_state(saved)
    assert set(client._cache) == {"SomeDaemon"}
    assert client.export_state()["cache"]["SomeDaemon"]["query"] == "keyword"

