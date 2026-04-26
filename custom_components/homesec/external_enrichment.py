"""External IP enrichment via ipwho.is, VirusTotal, and AbuseIPDB."""
from __future__ import annotations

import asyncio
import time as _time
from datetime import datetime, timedelta, UTC
import ipaddress
import logging

_LOGGER = logging.getLogger(__name__)

_IPWHO_URL = "https://ipwho.is/{ip}"  # free HTTPS, no auth, max ~1 req/s
_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_QUEUE_MAX = 500
_WORKER_DELAY = 1.2  # seconds between API calls (rate limiting)

# Human-readable notes for common HTTP error status codes
_HTTP_ERROR_NOTES: dict[int, str] = {
    401: "HTTP 401 – unauthorized (check API key)",
    403: "HTTP 403 – forbidden (invalid API key)",
    429: "HTTP 429 – rate limited",
    500: "HTTP 500 – server error",
    502: "HTTP 502 – bad gateway",
    503: "HTTP 503 – service unavailable",
    504: "HTTP 504 – gateway timeout",
}


class _ProviderError(Exception):
    """Raised by a provider method when the API returns a notable non-success status."""
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"HTTP {status}")


# Per-provider rate limits: (min_interval_seconds, daily_budget)
_PROVIDER_LIMITS: dict[str, tuple[float, int]] = {
    "ipwho":      (1.0,  999_999),  # ipwho.is: free, no daily cap — 1 req/s to be polite
    "virustotal": (15.0, 480),  # free: 500/day, 4 req/min
    "abuseipdb":  (1.5,  950),  # free: 1 000/day
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
        virustotal_key: str | None = None,
        abuseipdb_key: str | None = None,
        enrichment_ttl_minutes: int = 60,
        daily_budgets: dict[str, int] | None = None,
    ) -> None:
        self._session = session
        self._vt_key = virustotal_key
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
        # ipwho.is is effectively unlimited; override the internal budget counter.
        self._limits["ipwho"] = (self._limits["ipwho"][0], 999_999)
        # Per-provider rate-limit tracking
        self._prov_last_call: dict[str, float] = {}   # provider → monotonic ts
        self._prov_daily_count: dict[str, int] = {}   # provider → count today
        self._prov_day: str = ""                       # YYYY-MM-DD to reset
        self._prov_last_error: dict[str, str] = {}    # provider → last error note
        self._usage_state_dirty: bool = False
        # Pre-populate sensible tier defaults; detection at startup may refine these.
        self._prov_tier: dict[str, str] = {}
        self._prov_tier["ipwho"] = "free"  # ipwho.is is always active (no auth required)
        if self._vt_key:
            self._prov_tier["virustotal"] = "community"
        if self._abuse_key:
            self._prov_tier["abuseipdb"] = "basic"
        # Per-provider locks so concurrent enrich_now() calls don't burst past rate limits
        self._prov_locks: dict[str, asyncio.Lock] = {}
        # Per-provider backoff: monotonic timestamp until which the provider is skipped
        # (set after a 429/503 to avoid a flood of pointless retries)
        self._prov_backoff_until: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # Lifecycle

    async def async_start(self) -> None:
        self._task = asyncio.create_task(self._worker())
        asyncio.create_task(self._detect_tiers())

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
        return datetime.now(UTC) - ts > self._ttl

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
        """Return cached enrichment for on-demand lookups (non-blocking).

        If this IP has been enriched before (even if the cached entry is now
        stale), the cached data is returned immediately and the background
        worker is asked to refresh it.  If the IP has never been enriched at
        all, a fast ipwho.is-only enrich is done synchronously so the caller
        gets *some* data; the background worker will then perform the full
        enrichment on the next queue cycle.
        """
        if ip in self._cache:
            # Return cached data right away; queue background refresh if stale
            if self._is_stale(ip):
                self.queue_ip(ip)
            return dict(self._cache[ip])
        # First time we see this IP — do a fast ipwho.is-only enrich so the caller
        # gets location/ASN data without waiting for VT (15 s throttle) or AbuseIPDB.
        # Mark stale immediately so the background worker runs the full enrichment.
        result = await self._enrich(ip, fast_only=True)
        self._cache[ip] = result
        self._enriched_at[ip] = datetime.min.replace(tzinfo=UTC)
        self.queue_ip(ip)
        return dict(result)

    def enrichment_stats(self) -> list[dict[str, object]]:
        """Return per-provider enrichment usage vs daily budget."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if today != self._prov_day:
            self._prov_day = today
            self._prov_daily_count.clear()
            self._usage_state_dirty = True
        stats: list[dict[str, object]] = []
        for prov, (interval, default_budget) in _PROVIDER_LIMITS.items():
            budget = self._limits.get(prov, (interval, default_budget))[1]
            used = self._prov_daily_count.get(prov, 0)
            # ipwho.is: always active, no auth, no effective daily cap
            if prov == "ipwho":
                configured = True
                variant: str | None = "free"
                display_budget: int | None = None
            elif prov == "virustotal":
                configured = self._vt_key not in (None, "")
                variant = self._prov_tier.get("virustotal") if configured else None
                display_budget = budget
            elif prov == "abuseipdb":
                configured = self._abuse_key not in (None, "")
                variant = self._prov_tier.get("abuseipdb") if configured else None
                display_budget = budget
            else:
                configured = False
                variant = None
                display_budget = budget
            exhausted = (display_budget is not None) and (used >= display_budget)
            stats.append({
                "provider": prov,
                "used": used,
                "budget": display_budget,
                "configured": configured,
                "exhausted": exhausted,
                "last_error": self._prov_last_error.get(prov),
                "variant": variant,
            })
        return stats

    # ------------------------------------------------------------------ #
    # Private

    async def _detect_tiers(self) -> None:
        """One-time startup detection of provider account plan/tier."""
        import aiohttp as _aiohttp
        calls: list[tuple[str, object]] = []
        if self._vt_key:
            calls.append(("virustotal", self._detect_vt_tier(_aiohttp)))
        for prov, coro in calls:
            try:
                await coro  # type: ignore[misc]
            except Exception as exc:
                _LOGGER.debug("HSA: %s tier detection failed: %s", prov, exc)

    async def _detect_vt_tier(self, aiohttp) -> None:
        """Fetch VirusTotal account type (community / premium / enterprise …)."""
        url = "https://www.virustotal.com/api/v3/users/self"
        headers = {"x-apikey": self._vt_key}
        async with self._session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            if resp.status == 200:
                d = await resp.json(content_type=None)
                tier = str(d.get("data", {}).get("attributes", {}).get("type") or "community")
                self._prov_tier["virustotal"] = tier

    def _budget_ok(self, provider: str) -> bool:
        """Return True if the daily budget for *provider* has not been exhausted."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if today != self._prov_day:
            self._prov_day = today
            self._prov_daily_count.clear()
            self._usage_state_dirty = True
        limit = self._limits.get(provider, (1.0, 9999))
        return self._prov_daily_count.get(provider, 0) < limit[1]

    async def _throttle(self, provider: str) -> None:
        """Reserve a time slot for *provider* and sleep until it becomes available.

        The lock is held only for the dictionary read/write (microseconds).
        Sleeping happens *outside* the lock so concurrent callers can reserve
        their own slots in parallel rather than chaining 1-second waits.
        """
        if provider not in self._prov_locks:
            self._prov_locks[provider] = asyncio.Lock()
        min_interval = self._limits.get(provider, (1.0, 9999))[0]
        async with self._prov_locks[provider]:
            now = _time.monotonic()
            last = self._prov_last_call.get(provider, 0.0)
            # Reserve the next available slot (always at least min_interval after the last)
            next_slot = max(now, last + min_interval)
            self._prov_last_call[provider] = next_slot
            self._prov_daily_count[provider] = self._prov_daily_count.get(provider, 0) + 1
            self._usage_state_dirty = True
            sleep_for = next_slot - now
        # Sleep outside the lock so the next caller can reserve its slot immediately
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)

    async def _worker(self) -> None:
        while True:
            ip = await self._pending.get()
            self._queued.discard(ip)
            if self._is_stale(ip):
                try:
                    self._cache[ip] = await self._enrich(ip)
                    self._enriched_at[ip] = datetime.now(UTC)
                except Exception as exc:
                    _LOGGER.debug("HSA: enrichment error for %s: %s", ip, exc)
                    self._cache[ip] = {
                        "ip": ip,
                        "error": str(exc),
                        "enriched_at": datetime.now(UTC).isoformat(),
                        "sources": [],
                    }
                    self._enriched_at[ip] = datetime.now(UTC)
            await asyncio.sleep(_WORKER_DELAY)

    async def _enrich(self, ip: str, fast_only: bool = False) -> dict[str, object]:
        import aiohttp as _aiohttp  # lazy import

        result: dict[str, object] = {
            "ip": ip,
            "enriched_at": datetime.now(UTC).isoformat(),
            "sources": [],
        }

        # Each provider: check budget → throttle → call
        # Order matters: AbuseIPDB runs before VirusTotal so the score is available
        # to gate the VT call (VT only runs when abuse_confidence >= 50).
        providers: list[tuple[str, str | None, object]] = [
            ("ipwho",      "_always_",      self._ipwho),
            ("abuseipdb",  self._abuse_key, self._abuseipdb),
            ("virustotal", self._vt_key,    self._virustotal),
        ]
        for name, gate, method in providers:
            if gate is None:
                continue
            # fast_only: ipwho.is-only path for on-demand lookups (avoids VT 15 s throttle)
            if fast_only and name != "ipwho":
                continue
            # VT is expensive (quota): only query when AbuseIPDB already scored ≥ 50 %
            if name == "virustotal" and int(result.get("abuse_confidence") or 0) < 50:
                continue
            if not self._budget_ok(name):
                _LOGGER.debug("HSA: %s daily budget exhausted (%d), skipping %s",
                              name, self._prov_daily_count.get(name, 0), ip)
                continue
            # Skip provider if it returned 429/503 recently (backoff window)
            backoff_remaining = self._prov_backoff_until.get(name, 0.0) - _time.monotonic()
            if backoff_remaining > 0:
                _LOGGER.debug("HSA: %s in backoff, skipping %s (%.0fs remaining)",
                              name, ip, backoff_remaining)
                continue
            await self._throttle(name)
            try:
                data = await method(ip, _aiohttp)
                if data:
                    result.update(data)
                    result["sources"].append(name)  # type: ignore[union-attr]
                self._prov_last_error.pop(name, None)  # clear error on success
                self._prov_backoff_until.pop(name, None)  # clear backoff on success
            except _ProviderError as exc:
                note = _HTTP_ERROR_NOTES.get(exc.status, f"HTTP {exc.status}")
                if exc.status == 429:
                    backoff = 120.0
                    self._prov_backoff_until[name] = _time.monotonic() + backoff
                    # 429 is transient — don't persist it as a sticky error in the UI
                    self._prov_last_error.pop(name, None)
                    _LOGGER.warning(
                        "HSA: %s returned HTTP 429 (rate limited) – backing off for %.0fs. "
                        "If this recurs with a paid token, check your plan's per-second limit.",
                        name, backoff,
                    )
                else:
                    self._prov_last_error[name] = note
                    _LOGGER.debug("HSA: %s returned %s for %s", name, exc.status, ip)
            except Exception as exc:
                _LOGGER.debug("HSA: %s failed for %s: %s", name, ip, exc)

        result["rating"], result["rating_source"] = self._compute_rating(result)
        return result

    def export_usage_state(self) -> dict[str, object]:
        """Return serializable usage counters used for persistence."""
        return {
            "day": self._prov_day,
            "daily_count": dict(self._prov_daily_count),
        }

    def import_usage_state(self, state: dict[str, object]) -> None:
        """Restore persisted usage counters if they are valid for today."""
        if not isinstance(state, dict):
            return
        day = state.get("day")
        counts = state.get("daily_count")
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if not isinstance(day, str) or day != today:
            self._prov_day = today
            self._prov_daily_count.clear()
            self._usage_state_dirty = False
            return
        restored: dict[str, int] = {}
        if isinstance(counts, dict):
            for prov, value in counts.items():
                if isinstance(prov, str):
                    try:
                        restored[prov] = max(0, int(value))
                    except (TypeError, ValueError):
                        continue
        self._prov_day = day
        self._prov_daily_count = restored
        self._usage_state_dirty = False

    def is_usage_state_dirty(self) -> bool:
        return self._usage_state_dirty

    def mark_usage_state_clean(self) -> None:
        self._usage_state_dirty = False

    async def _ipwho(self, ip: str, aiohttp) -> dict[str, object] | None:
        """Query ipwho.is for country and ASN data (free, no auth, 1 req/s)."""
        url = _IPWHO_URL.format(ip=ip)
        async with self._session.get(
            url, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            if resp.status == 404:
                return None
            if resp.status != 200:
                raise _ProviderError(resp.status)
            d = await resp.json(content_type=None)
        if not d.get("success"):
            return None
        country_code = str(d.get("country_code") or "")
        conn = d.get("connection") or {}
        asn_num = conn.get("asn") or 0
        asn = f"AS{asn_num}" if asn_num else ""
        as_name = str(conn.get("isp") or conn.get("org") or "")
        return {
            "country": country_code,
            "country_name": _COUNTRY_NAMES.get(country_code, str(d.get("country") or "")),
            "city": str(d.get("city") or ""),
            "region": str(d.get("region") or ""),
            "asn": asn,
            "as_name": as_name,
            "isp": as_name,
        }

    async def _virustotal(self, ip: str, aiohttp) -> dict[str, object] | None:
        url = _VT_URL.format(ip=ip)
        headers = {"x-apikey": self._vt_key}
        async with self._session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status == 404:
                return None
            if resp.status != 200:
                raise _ProviderError(resp.status)
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

    async def _abuseipdb(self, ip: str, aiohttp) -> dict[str, object] | None:
        headers = {"Key": self._abuse_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        async with self._session.get(
            _ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            if resp.status == 404:
                return None
            if resp.status != 200:
                raise _ProviderError(resp.status)
            # Detect tier from rate-limit header on first successful response
            if "abuseipdb" not in self._prov_tier:
                try:
                    limit_val = int(resp.headers.get("X-RateLimit-Limit", 0))
                    if limit_val > 0:
                        self._prov_tier["abuseipdb"] = "basic" if limit_val <= 1000 else "premium"
                except (ValueError, TypeError):
                    pass
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
