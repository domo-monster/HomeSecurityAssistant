"""External IP enrichment via IPInfo, VirusTotal, Shodan, and AbuseIPDB."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import ipaddress
import logging

_LOGGER = logging.getLogger(__name__)

_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_QUEUE_MAX = 500
_WORKER_DELAY = 1.2  # seconds between API calls (rate limiting)

# Per-provider rate limits: (min_interval_seconds, daily_budget)
_PROVIDER_LIMITS: dict[str, tuple[float, int]] = {
    "ipinfo":    (1.0,  1500),  # free: 50k/month ≈ 1 666/day
    "virustotal": (15.0, 480),  # free: 500/day, 4 req/min
    "shodan":    (1.2,  950),   # free: ~unlimited lookups with key, 1 req/s
    "abuseipdb": (1.5,  950),   # free: 1 000/day
}


# Minimal ISO-3166 alpha-2 → full name map
_COUNTRY_NAMES: dict[str, str] = {
    "US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
    "GB": "United Kingdom", "FR": "France", "JP": "Japan", "KR": "South Korea",
    "NL": "Netherlands", "CA": "Canada", "AU": "Australia", "BR": "Brazil",
    "IN": "India", "SG": "Singapore", "HK": "Hong Kong", "UA": "Ukraine",
    "IT": "Italy", "ES": "Spain", "SE": "Sweden", "NO": "Norway",
    "FI": "Finland", "CH": "Switzerland", "PL": "Poland", "CZ": "Czech Republic",
    "AT": "Austria", "BE": "Belgium", "DK": "Denmark", "IE": "Ireland",
    "IL": "Israel", "ZA": "South Africa", "MX": "Mexico", "AR": "Argentina",
    "TR": "Turkey", "SA": "Saudi Arabia", "AE": "UAE", "TW": "Taiwan",
    "TH": "Thailand", "ID": "Indonesia", "MY": "Malaysia", "VN": "Vietnam",
    "PH": "Philippines", "NG": "Nigeria", "EG": "Egypt", "KZ": "Kazakhstan",
    "IR": "Iran", "PK": "Pakistan", "BD": "Bangladesh", "IQ": "Iraq",
    "RO": "Romania", "HU": "Hungary", "SK": "Slovakia", "BG": "Bulgaria",
    "HR": "Croatia", "RS": "Serbia", "GR": "Greece", "PT": "Portugal",
}


class ExternalIPEnricher:
    """Background worker that enriches external IPs with OSINT data."""

    def __init__(
        self,
        session,  # aiohttp.ClientSession
        ipinfo_token: str | None = None,
        virustotal_key: str | None = None,
        shodan_key: str | None = None,
        abuseipdb_key: str | None = None,
        enrichment_ttl_minutes: int = 60,
        daily_budgets: dict[str, int] | None = None,
    ) -> None:
        self._session = session
        self._ipinfo_token = ipinfo_token
        self._vt_key = virustotal_key
        self._shodan_key = shodan_key
        self._abuse_key = abuseipdb_key
        self._ttl = timedelta(minutes=max(1, enrichment_ttl_minutes))
        self._cache: dict[str, dict[str, object]] = {}
        self._enriched_at: dict[str, datetime] = {}
        self._pending: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._queued: set[str] = set()  # IPs currently sitting in the queue
        self._task: asyncio.Task | None = None
        # Build effective per-provider limits (interval stays fixed, budget is configurable)
        self._limits: dict[str, tuple[float, int]] = {}
        for prov, (interval, default_budget) in _PROVIDER_LIMITS.items():
            budget = (daily_budgets or {}).get(prov, default_budget)
            self._limits[prov] = (interval, max(0, budget))
        # Per-provider rate-limit tracking
        self._prov_last_call: dict[str, float] = {}   # provider → monotonic ts
        self._prov_daily_count: dict[str, int] = {}   # provider → count today
        self._prov_day: str = ""                       # YYYY-MM-DD to reset

    # ------------------------------------------------------------------ #
    # Lifecycle

    async def async_start(self) -> None:
        self._task = asyncio.create_task(self._worker())

    async def async_stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------ #
    # Public API

    def _is_stale(self, ip: str) -> bool:
        """Return True if the cached enrichment for ip has expired or is absent."""
        if ip not in self._cache:
            return True
        ts = self._enriched_at.get(ip)
        if ts is None:
            return True
        return datetime.now() - ts > self._ttl

    @staticmethod
    def _is_public(ip: str) -> bool:
        """Return True only for globally routable (public) IP addresses."""
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def queue_ip(self, ip: str) -> None:
        """Request background enrichment for a *public* IP (non-blocking)."""
        if not self._is_public(ip):
            return
        if ip in self._queued:
            return
        if not self._is_stale(ip):
            return
        try:
            self._pending.put_nowait(ip)
            self._queued.add(ip)
        except asyncio.QueueFull:
            pass

    def get(self, ip: str) -> dict[str, object]:
        """Return cached enrichment, or empty dict if not yet enriched."""
        return dict(self._cache.get(ip, {}))

    async def enrich_now(self, ip: str) -> dict[str, object]:
        """Synchronously enrich an IP (for on-demand lookups)."""
        if not self._is_stale(ip):
            return dict(self._cache[ip])
        result = await self._enrich(ip)
        self._cache[ip] = result
        self._enriched_at[ip] = datetime.now()
        return dict(result)

    def enrichment_stats(self) -> list[dict[str, object]]:
        """Return per-provider enrichment usage vs daily budget."""
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self._prov_day:
            self._prov_day = today
            self._prov_daily_count.clear()
        stats: list[dict[str, object]] = []
        provider_keys = {
            "ipinfo": self._ipinfo_token or "_always_",
            "virustotal": self._vt_key,
            "shodan": self._shodan_key,
            "abuseipdb": self._abuse_key,
        }
        for prov, (interval, default_budget) in _PROVIDER_LIMITS.items():
            budget = self._limits.get(prov, (interval, default_budget))[1]
            used = self._prov_daily_count.get(prov, 0)
            configured = provider_keys.get(prov) not in (None, "")
            stats.append({
                "provider": prov,
                "used": used,
                "budget": budget,
                "configured": configured,
                "exhausted": used >= budget,
            })
        return stats

    # ------------------------------------------------------------------ #
    # Private

    def _budget_ok(self, provider: str) -> bool:
        """Return True if the daily budget for *provider* has not been exhausted."""
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self._prov_day:
            self._prov_day = today
            self._prov_daily_count.clear()
        limit = self._limits.get(provider, (1.0, 9999))
        return self._prov_daily_count.get(provider, 0) < limit[1]

    async def _throttle(self, provider: str) -> None:
        """Enforce per-provider minimum interval between consecutive API calls."""
        import time
        min_interval = self._limits.get(provider, (1.0, 9999))[0]
        last = self._prov_last_call.get(provider, 0.0)
        now = time.monotonic()
        elapsed = now - last
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._prov_last_call[provider] = time.monotonic()
        self._prov_daily_count[provider] = self._prov_daily_count.get(provider, 0) + 1

    async def _worker(self) -> None:
        while True:
            ip = await self._pending.get()
            self._queued.discard(ip)
            if self._is_stale(ip):
                try:
                    self._cache[ip] = await self._enrich(ip)
                    self._enriched_at[ip] = datetime.now()
                except Exception as exc:
                    _LOGGER.debug("HSA: enrichment error for %s: %s", ip, exc)
                    self._cache[ip] = {
                        "ip": ip,
                        "error": str(exc),
                        "enriched_at": datetime.now().isoformat(),
                        "sources": [],
                    }
                    self._enriched_at[ip] = datetime.now()
            await asyncio.sleep(_WORKER_DELAY)

    async def _enrich(self, ip: str) -> dict[str, object]:
        import aiohttp as _aiohttp  # lazy import

        result: dict[str, object] = {
            "ip": ip,
            "enriched_at": datetime.now().isoformat(),
            "sources": [],
        }

        # Each provider: check budget → throttle → call
        providers: list[tuple[str, str | None, object]] = [
            ("ipinfo",     "_always_",     self._ipinfo),
            ("virustotal", self._vt_key,    self._virustotal),
            ("shodan",     self._shodan_key, self._shodan),
            ("abuseipdb",  self._abuse_key,  self._abuseipdb),
        ]
        for name, gate, method in providers:
            if gate is None:
                continue
            if not self._budget_ok(name):
                _LOGGER.debug("HSA: %s daily budget exhausted (%d), skipping %s",
                              name, self._prov_daily_count.get(name, 0), ip)
                continue
            await self._throttle(name)
            try:
                data = await method(ip, _aiohttp)
                if data:
                    result.update(data)
                    result["sources"].append(name)  # type: ignore[union-attr]
            except Exception as exc:
                _LOGGER.debug("HSA: %s failed for %s: %s", name, ip, exc)

        result["rating"], result["rating_source"] = self._compute_rating(result)
        return result

    async def _ipinfo(self, ip: str, aiohttp) -> dict[str, object] | None:
        headers: dict[str, str] = {}
        if self._ipinfo_token:
            headers["Authorization"] = f"Bearer {self._ipinfo_token}"
        url = _IPINFO_URL.format(ip=ip)
        async with self._session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            if resp.status != 200:
                return None
            d = await resp.json(content_type=None)
        org = str(d.get("org") or "")
        asn = org.split(" ", 1)[0] if " " in org else ""
        isp = org.split(" ", 1)[1] if " " in org else org
        country = str(d.get("country") or "")
        return {
            "country": country,
            "country_name": _COUNTRY_NAMES.get(country, country),
            "city": str(d.get("city") or ""),
            "region": str(d.get("region") or ""),
            "org": org,
            "asn": asn,
            "isp": isp,
            "hostname_ipinfo": str(d.get("hostname") or ""),
            "timezone": str(d.get("timezone") or ""),
        }

    async def _virustotal(self, ip: str, aiohttp) -> dict[str, object] | None:
        url = _VT_URL.format(ip=ip)
        headers = {"x-apikey": self._vt_key}
        async with self._session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status != 200:
                return None
            d = await resp.json(content_type=None)
        attrs = d.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": int(stats.get("malicious") or 0),
            "vt_suspicious": int(stats.get("suspicious") or 0),
            "vt_harmless": int(stats.get("harmless") or 0),
            "vt_reputation": int(attrs.get("reputation") or 0),
            "vt_country": str(attrs.get("country") or ""),
            "vt_as_owner": str(attrs.get("as_owner") or ""),
            "vt_asn": int(attrs.get("asn") or 0),
        }

    async def _shodan(self, ip: str, aiohttp) -> dict[str, object] | None:
        url = _SHODAN_URL.format(ip=ip, key=self._shodan_key)
        async with self._session.get(
            url, timeout=aiohttp.ClientTimeout(total=12)
        ) as resp:
            if resp.status != 200:
                return None
            d = await resp.json(content_type=None)
        # Build enriched service list and collect web technologies from HTTP banners
        services: list[dict[str, object]] = []
        technologies: list[str] = []
        seen_tech: set[str] = set()
        for svc in (d.get("data") or []):
            port = svc.get("port")
            if port is not None:
                services.append({
                    "port": int(port),
                    "transport": str(svc.get("transport") or "tcp"),
                    "product": str(svc.get("product") or ""),
                    "version": str(svc.get("version") or ""),
                })
            http = svc.get("http") or {}
            for tech in (http.get("components") or {}).keys():
                if tech not in seen_tech:
                    seen_tech.add(tech)
                    technologies.append(tech)
        domains: list[str] = list(d.get("domains") or d.get("hostnames") or [])
        return {
            "shodan_ports": list(d.get("ports") or []),
            "shodan_services": services,
            "shodan_domains": domains,
            "shodan_technologies": technologies,
            "shodan_vulns": list((d.get("vulns") or {}).keys()),
            "shodan_org": str(d.get("org") or ""),
            "shodan_isp": str(d.get("isp") or ""),
            "shodan_country": str(d.get("country_name") or ""),
            "shodan_os": str(d.get("os") or ""),
            "shodan_tags": list(d.get("tags") or []),
        }

    async def _abuseipdb(self, ip: str, aiohttp) -> dict[str, object] | None:
        headers = {"Key": self._abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        async with self._session.get(
            _ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            if resp.status != 200:
                return None
            d = await resp.json(content_type=None)
        dd = d.get("data") or {}
        return {
            "abuse_confidence": int(dd.get("abuseConfidenceScore") or 0),
            "abuse_total_reports": int(dd.get("totalReports") or 0),
            "abuse_country": str(dd.get("countryCode") or ""),
            "abuse_isp": str(dd.get("isp") or ""),
            "abuse_domain": str(dd.get("domain") or ""),
            "abuse_is_whitelisted": bool(dd.get("isWhitelisted")),
        }

    @staticmethod
    def _compute_rating(data: dict[str, object]) -> tuple[str, str]:
        vt_mal = int(data.get("vt_malicious") or 0)
        vt_sus = int(data.get("vt_suspicious") or 0)
        abuse = int(data.get("abuse_confidence") or 0)
        if vt_mal >= 3:
            return "malicious", f"VirusTotal: {vt_mal} malicious detections"
        if abuse >= 50:
            return "malicious", f"AbuseIPDB: {abuse}% confidence score"
        if vt_mal >= 1:
            return "suspicious", f"VirusTotal: {vt_mal} malicious detection(s)"
        if vt_sus >= 3:
            return "suspicious", f"VirusTotal: {vt_sus} suspicious detections"
        if abuse >= 20:
            return "suspicious", f"AbuseIPDB: {abuse}% confidence score"
        if data.get("sources"):
            return "clean", "No threats found across checked sources"
        return "", ""
