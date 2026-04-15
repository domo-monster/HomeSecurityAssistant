"""NVD (National Vulnerability Database) CVE enrichment for discovered services.

Queries the NVD REST API 2.0 for CVEs affecting detected service banners.
Results are cached per product keyword with a configurable TTL (default 24 h).
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from .vulnerabilities import _ver_tuple, _backport_patched

_LOGGER = logging.getLogger(__name__)

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_TTL_HOURS = 24

_UTC = timezone.utc

# ---------------------------------------------------------------------------
# Product map: service_name -> list of product profiles.
# Each profile specifies:
#   keyword      – search term sent to NVD keywordSearch
#   banner_re    – regex to extract the upstream version from a banner string
#   cpe_vendor   – NVD CPE vendor string for precise filtering
#   cpe_product  – NVD CPE product string for precise filtering
#
# This map provides *precise* CPE-based version matching for well-known
# products.  Services NOT in this map are still queried via the generic
# banner parser (see _extract_product_from_banner), so every service with
# an identifiable banner gets NVD coverage.
# ---------------------------------------------------------------------------
_SERVICE_PRODUCT_MAP: dict[str, list[dict[str, str]]] = {
    "ssh": [
        {
            "keyword": "OpenSSH",
            "banner_re": r"openssh[_/]?(\d+\.\d+[\w.]*)",
            "cpe_vendor": "openbsd",
            "cpe_product": "openssh",
        },
        {
            "keyword": "Dropbear SSH",
            "banner_re": r"dropbear[_/ ]?(\d+\.\d+[\w.]*)",
            "cpe_vendor": "matt_johnston",
            "cpe_product": "dropbear_ssh_server",
        },
    ],
    "http": [
        {
            "keyword": "Apache HTTP Server",
            "banner_re": r"apache/(\d+\.\d+[\w.]*)",
            "cpe_vendor": "apache",
            "cpe_product": "http_server",
        },
        {
            "keyword": "nginx",
            "banner_re": r"nginx/(\d+\.\d+[\w.]*)",
            "cpe_vendor": "nginx",
            "cpe_product": "nginx",
        },
        {
            "keyword": "lighttpd",
            "banner_re": r"lighttpd/(\d+\.\d+[\w.]*)",
            "cpe_vendor": "lighttpd",
            "cpe_product": "lighttpd",
        },
    ],
    "mysql": [
        {
            "keyword": "MySQL",
            "banner_re": r"(\d+\.\d+\.\d+[\w.-]*)",
            "cpe_vendor": "mysql",
            "cpe_product": "mysql",
        },
        {
            "keyword": "MariaDB",
            "banner_re": r"(\d+\.\d+\.\d+[\w.-]*)",
            "cpe_vendor": "mariadb",
            "cpe_product": "mariadb",
        },
    ],
    "ftp": [
        {
            "keyword": "vsftpd",
            "banner_re": r"vsftpd\s+(\d+\.\d+[\w.]*)",
            "cpe_vendor": "vsftpd_project",
            "cpe_product": "vsftpd",
        },
        {
            "keyword": "ProFTPD",
            "banner_re": r"proftpd/(\d+\.\d+[\w.]*)",
            "cpe_vendor": "proftpd_project",
            "cpe_product": "proftpd",
        },
    ],
    "smtp": [
        {
            "keyword": "Postfix",
            "banner_re": r"postfix[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "postfix",
            "cpe_product": "postfix",
        },
        {
            "keyword": "Exim",
            "banner_re": r"exim[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "exim",
            "cpe_product": "exim",
        },
        {
            "keyword": "Sendmail",
            "banner_re": r"sendmail[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "sendmail",
            "cpe_product": "sendmail",
        },
    ],
    "redis": [
        {
            "keyword": "Redis",
            "banner_re": r"redis[_/]?(\d+\.\d+[\w.]*)",
            "cpe_vendor": "redis",
            "cpe_product": "redis",
        },
    ],
    "mongodb": [
        {
            "keyword": "MongoDB",
            "banner_re": r"(\d+\.\d+\.\d+)",
            "cpe_vendor": "mongodb",
            "cpe_product": "mongodb",
        },
    ],
    "postgresql": [
        {
            "keyword": "PostgreSQL",
            "banner_re": r"postgresql[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "postgresql",
            "cpe_product": "postgresql",
        },
    ],
    "smb": [
        {
            "keyword": "Samba",
            "banner_re": r"samba[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "samba",
            "cpe_product": "samba",
        },
    ],
    "netbios-ssn": [
        {
            "keyword": "Samba",
            "banner_re": r"samba[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "samba",
            "cpe_product": "samba",
        },
    ],
    "microsoft-ds": [
        {
            "keyword": "Samba",
            "banner_re": r"samba[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "samba",
            "cpe_product": "samba",
        },
    ],
    "imap": [
        {
            "keyword": "Dovecot",
            "banner_re": r"dovecot[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "dovecot",
            "cpe_product": "dovecot",
        },
    ],
    "mqtt": [
        {
            "keyword": "Mosquitto",
            "banner_re": r"mosquitto[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "eclipse",
            "cpe_product": "mosquitto",
        },
    ],
    "mqtt-tls": [
        {
            "keyword": "Mosquitto",
            "banner_re": r"mosquitto[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "eclipse",
            "cpe_product": "mosquitto",
        },
    ],
    "adb": [
        {
            "keyword": "Android Debug Bridge",
            "banner_re": r"android[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "google",
            "cpe_product": "android",
        },
    ],
    "dns": [
        {
            "keyword": "BIND",
            "banner_re": r"bind[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "isc",
            "cpe_product": "bind",
        },
        {
            "keyword": "dnsmasq",
            "banner_re": r"dnsmasq[/ -](\d+\.\d+[\w.]*)",
            "cpe_vendor": "thekelleys",
            "cpe_product": "dnsmasq",
        },
    ],
    "ntp": [
        {
            "keyword": "ntpd",
            "banner_re": r"ntpd[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "ntp",
            "cpe_product": "ntp",
        },
        {
            "keyword": "Chrony",
            "banner_re": r"chrony[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "tuxfamily",
            "cpe_product": "chrony",
        },
    ],
    "rtsp": [
        {
            "keyword": "Live555",
            "banner_re": r"live555[/ ]v?(\d+[\d.]*)",
            "cpe_vendor": "live555",
            "cpe_product": "streaming_media",
        },
        {
            "keyword": "GStreamer RTSP",
            "banner_re": r"gstreamer[/ ](\d+\.\d+[\w.]*)",
            "cpe_vendor": "gstreamer_project",
            "cpe_product": "gstreamer",
        },
    ],
}

# ---------------------------------------------------------------------------
# Technology → product profile map.
# Keys match the technology names produced by scanner.fingerprint_http().
# These are used when the scanner detects a technology via HTTP fingerprinting;
# CVEs are only reported for products confirmed present on the host.
# ---------------------------------------------------------------------------
_TECHNOLOGY_PRODUCT_MAP: dict[str, dict[str, str]] = {
    "WordPress": {
        "keyword": "WordPress",
        "cpe_vendor": "wordpress",
        "cpe_product": "wordpress",
    },
    "WooCommerce": {
        "keyword": "WooCommerce",
        "cpe_vendor": "woocommerce",
        "cpe_product": "woocommerce",
    },
    "Joomla": {
        "keyword": "Joomla",
        "cpe_vendor": "joomla",
        "cpe_product": "joomla\\!",
    },
    "Drupal": {
        "keyword": "Drupal",
        "cpe_vendor": "drupal",
        "cpe_product": "drupal",
    },
    "Magento": {
        "keyword": "Magento",
        "cpe_vendor": "magento",
        "cpe_product": "magento",
    },
    "phpMyAdmin": {
        "keyword": "phpMyAdmin",
        "cpe_vendor": "phpmyadmin",
        "cpe_product": "phpmyadmin",
    },
    "Grafana": {
        "keyword": "Grafana",
        "cpe_vendor": "grafana",
        "cpe_product": "grafana",
    },
    "GitLab": {
        "keyword": "GitLab",
        "cpe_vendor": "gitlab",
        "cpe_product": "gitlab",
    },
    "Nextcloud": {
        "keyword": "Nextcloud",
        "cpe_vendor": "nextcloud",
        "cpe_product": "nextcloud_server",
    },
    "Tomcat": {
        "keyword": "Apache Tomcat",
        "cpe_vendor": "apache",
        "cpe_product": "tomcat",
    },
    "Jenkins": {
        "keyword": "Jenkins",
        "cpe_vendor": "jenkins",
        "cpe_product": "jenkins",
    },
    "Elasticsearch": {
        "keyword": "Elasticsearch",
        "cpe_vendor": "elastic",
        "cpe_product": "elasticsearch",
    },
    "IIS": {
        "keyword": "Microsoft IIS",
        "cpe_vendor": "microsoft",
        "cpe_product": "internet_information_services",
    },
    "Varnish": {
        "keyword": "Varnish",
        "cpe_vendor": "varnish-software",
        "cpe_product": "varnish_cache",
    },
    "Caddy": {
        "keyword": "Caddy",
        "cpe_vendor": "caddyserver",
        "cpe_product": "caddy",
    },
    "PHP": {
        "keyword": "PHP",
        "cpe_vendor": "php",
        "cpe_product": "php",
    },
    "Node.js": {
        "keyword": "Node.js",
        "cpe_vendor": "nodejs",
        "cpe_product": "node.js",
    },
}

# ---------------------------------------------------------------------------
# Generic product/version extraction from arbitrary banners
# ---------------------------------------------------------------------------

# Matches patterns like "ProductName/1.2.3", "ProductName 1.2.3", "ProductName_1.2"
_GENERIC_PRODUCT_RE = re.compile(
    r"(?i)\b([A-Za-z][\w.-]{1,30})[/_\s]v?(\d+\.\d+[\w.]*)"
)

# Words that are NOT product names (noise from banners)
_PRODUCT_STOPWORDS = frozenset({
    "http", "https", "ssh", "tcp", "udp", "tls", "ssl", "protocol",
    "rtsp", "rtp", "rtcp", "sip", "sdp",  # streaming / VoIP protocols
    "server", "service", "version", "release", "build", "status",
    "ubuntu", "debian", "centos", "rhel", "fedora", "alpine",
    "win32", "win64", "linux", "freebsd", "unix",
    "charset", "content", "transfer", "encoding", "connection",
    "date", "host", "accept", "cache", "pragma",
})


def _extract_product_from_banner(banner: str) -> tuple[str, str] | None:
    """Try to extract (product_name, version) from an arbitrary banner.

    Returns None when no identifiable product/version pair is found.
    """
    for m in _GENERIC_PRODUCT_RE.finditer(banner):
        name = m.group(1)
        ver = m.group(2)
        if name.lower() in _PRODUCT_STOPWORDS:
            continue
        if len(name) < 2:
            continue
        return name, ver
    return None


# ---------------------------------------------------------------------------
# CPE version-range matching
# ---------------------------------------------------------------------------

def _ver_in_cpe_range(version: str, cpe_match: dict[str, Any]) -> bool:
    """Return True if *version* falls within the CPE match criteria range."""
    v = _ver_tuple(version)
    if not v:
        return False

    vsi = cpe_match.get("versionStartIncluding")
    vse = cpe_match.get("versionStartExcluding")
    vei = cpe_match.get("versionEndIncluding")
    vee = cpe_match.get("versionEndExcluding")

    if not any([vsi, vse, vei, vee]):
        # No range bounds at all — only accept if CPE criteria carries an
        # exact upstream version.  Wildcard (* or -) CPEs mean "unspecified":
        # we cannot confirm this version is affected, so we skip rather than
        # produce false positives.
        criteria = str(cpe_match.get("criteria", ""))
        parts = criteria.split(":")
        if len(parts) > 5 and parts[5] not in ("*", "-", ""):
            cpe_ver = re.sub(r"[^0-9.]", ".", parts[5])
            return bool(cpe_ver) and _ver_tuple(version) == _ver_tuple(cpe_ver)
        return False

    # Range bounds present — apply each constraint that is set.
    if vsi and v < _ver_tuple(str(vsi)):
        return False
    if vse and v <= _ver_tuple(str(vse)):
        return False
    if vei and v > _ver_tuple(str(vei)):
        return False
    if vee and v >= _ver_tuple(str(vee)):
        return False
    return True


def _is_version_vulnerable(
    version: str,
    configurations: list[dict[str, Any]],
    cpe_vendor: str = "",
    cpe_product: str = "",
    cpe_keyword: str = "",
) -> bool:
    """Return True if *version* matches at least one vulnerable CPE range.

    When *cpe_vendor* and *cpe_product* are provided, only CPE entries whose
    criteria string contains that exact vendor and product are considered.

    When *cpe_keyword* is provided (generic banner matches), CPE vendor and
    product fields are split into tokens (on ``_`` / ``-``) and the keyword
    must match a complete token\u200a—\u200anot merely appear as a substring.  This
    prevents false positives such as ``rtsp`` matching Realtek ``rtsper``.
    """
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                criteria = str(cpe_match.get("criteria", "")).lower()
                # Exact vendor/product filtering (precise map matches)
                if cpe_vendor or cpe_product:
                    parts = criteria.split(":")
                    if len(parts) > 5:
                        if cpe_vendor and parts[3] != cpe_vendor:
                            continue
                        if cpe_product and parts[4] != cpe_product:
                            continue
                    else:
                        continue
                # Keyword filtering (generic banner matches) — match
                # against CPE vendor/product fields as whole tokens to
                # avoid false positives where a short keyword is a
                # substring of an unrelated product (e.g. "rtsp" in
                # "rtsper").
                elif cpe_keyword:
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        cpe_v = parts[3]
                        cpe_p = parts[4]
                        tokens = set(cpe_p.replace("-", "_").split("_")) | set(cpe_v.replace("-", "_").split("_"))
                        if cpe_keyword not in tokens and cpe_keyword != cpe_p and cpe_keyword != cpe_v:
                            continue
                    else:
                        continue
                if _ver_in_cpe_range(version, cpe_match):
                    return True
    return False


def _has_matching_cpe(
    configurations: list[dict[str, Any]],
    cpe_vendor: str,
    cpe_product: str,
) -> bool:
    """Return True if any vulnerable CPE entry references the given vendor/product.

    Used for versionless technology detections — confirms the CVE is relevant
    even when the exact version is unknown.
    """
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                criteria = str(cpe_match.get("criteria", "")).lower()
                parts = criteria.split(":")
                if len(parts) > 5:
                    if cpe_vendor and parts[3] != cpe_vendor:
                        continue
                    if cpe_product and parts[4] != cpe_product:
                        continue
                    return True
    return False


# Regex patterns to extract versions from banners for fingerprinted technologies
_TECH_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "WordPress": re.compile(r'WordPress\s*([\d.]+)', re.I),
    "PHP": re.compile(r'PHP/([\d.]+)', re.I),
    "Tomcat": re.compile(r'Tomcat/([\d.]+)', re.I),
    "IIS": re.compile(r'Microsoft-IIS/([\d.]+)', re.I),
    "Grafana": re.compile(r'grafana[/ ]([\d.]+)', re.I),
    "Jenkins": re.compile(r'Jenkins[/ ]([\d.]+)', re.I),
    "Nextcloud": re.compile(r'Nextcloud[/ ]([\d.]+)', re.I),
    "Elasticsearch": re.compile(r'"number"\s*:\s*"([\d.]+)"', re.I),
    "Varnish": re.compile(r'varnish[/ ]([\d.]+)', re.I),
    "Caddy": re.compile(r'Caddy[/ ]([\d.]+)', re.I),
    "Node.js": re.compile(r'(?:Express|Node)/([\d.]+)', re.I),
    "GitLab": re.compile(r'GitLab[/ ]([\d.]+)', re.I),
}


def _extract_tech_version(tech_name: str, banner: str, version: str) -> str:
    """Try to extract a version string for a detected technology from the banner."""
    pat = _TECH_VERSION_PATTERNS.get(tech_name)
    if not pat:
        return ""
    combined = f"{banner} {version}"
    m = pat.search(combined)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# CVSS / description helpers
# ---------------------------------------------------------------------------

def _extract_cvss(cve: dict[str, Any]) -> tuple[float, str]:
    """Return (score, severity) from the highest-priority CVSS metric present."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev = data.get("baseSeverity", "medium").lower()
            return score, sev
    # Fall back to CVSSv2
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        score = float(data.get("baseScore", 0.0))
        # v2 severity labels map to our levels
        raw = data.get("baseSeverity", data.get("severity", "medium")).lower()
        sev = {"high": "high", "medium": "medium", "low": "low"}.get(raw, "medium")
        return score, sev
    return 5.0, "medium"


def _extract_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return str(desc.get("value", ""))[:300]
    return ""


# ---------------------------------------------------------------------------
# NVD client
# ---------------------------------------------------------------------------

class NVDClient:
    """Async NVD CVE API client with per-keyword TTL caching.

    Usage (called from coordinator):
        client = NVDClient(session, api_url, api_key, ttl_hours)
        nvd_vulns = await client.find_vulnerabilities(ip, services)
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_url: str = DEFAULT_NVD_API_URL,
        api_key: str | None = None,
        ttl_hours: int = DEFAULT_NVD_TTL_HOURS,
        min_year: int = 2020,
        custom_keywords: list[str] | None = None,
    ) -> None:
        self._session = session
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._ttl = timedelta(hours=ttl_hours)
        self._ttl_hours = ttl_hours
        self._min_year = min_year
        self._custom_keywords = custom_keywords
        # keyword -> (fetched_at, simplified_cve_list)
        self._cache: dict[str, tuple[datetime, list[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()
        # NVD rate limits: 5 req/30 s without key, 50 req/30 s with key
        self._rate_delay = 0.6 if api_key else 6.5

    async def _fetch_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """Query NVD for CVEs matching *keyword*. Returns simplified CVE list.

        Paginates automatically when the total exceeds a single page.
        Filters by ``_min_year`` client-side (the NVD date-range parameters
        require both start+end and a ≤120-day window which makes server-side
        filtering impractical for multi-year ranges).
        """
        page_size = 2000
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        min_year_prefix = f"{self._min_year}-" if self._min_year else ""
        all_results: list[dict[str, Any]] = []
        start_index = 0

        while True:
            params: dict[str, Any] = {
                "keywordSearch": keyword,
                "noRejected": "",
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }
            try:
                async with self._session.get(
                    self._api_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 429:
                        _LOGGER.warning("NVD rate limit hit for keyword %r — will retry next cycle", keyword)
                        return all_results
                    if resp.status != 200:
                        _LOGGER.warning("NVD API HTTP %d for keyword %r", resp.status, keyword)
                        return all_results
                    data: dict[str, Any] = await resp.json(content_type=None)
            except Exception as exc:
                _LOGGER.warning("NVD fetch error for %r: %s", keyword, exc)
                return all_results

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = str(cve.get("id", ""))
                if not cve_id:
                    continue
                # Client-side min-year filter using published date
                published = str(cve.get("published", ""))
                if min_year_prefix and published and published < min_year_prefix:
                    continue
                score, severity = _extract_cvss(cve)
                if score < 4.0:
                    continue
                all_results.append({
                    "cve_id": cve_id,
                    "cvss": score,
                    "severity": severity,
                    "summary": _extract_description(cve),
                    "published": published[:10],  # YYYY-MM-DD
                    "configurations": cve.get("configurations", []),
                })

            total_results = int(data.get("totalResults", 0))
            start_index += page_size
            if start_index >= total_results:
                break
            await asyncio.sleep(self._rate_delay)

        _LOGGER.info("NVD: %d CVEs fetched for keyword %r (>= %s)", len(all_results), keyword, self._min_year or 'all years')
        return all_results

    async def _get_cached(self, keyword: str) -> list[dict[str, Any]]:
        """Return cached or freshly fetched CVE list for *keyword*."""
        async with self._lock:
            entry = self._cache.get(keyword)
            if entry:
                age = datetime.now(_UTC) - entry[0]
                if age < self._ttl:
                    return entry[1]

            cves = await self._fetch_keyword(keyword)
            self._cache[keyword] = (datetime.now(_UTC), cves)
            await asyncio.sleep(self._rate_delay)
            return cves

    def invalidate_cache(self) -> None:
        """Clear all cached CVE data so the next lookup re-fetches from NVD."""
        self._cache.clear()
        _LOGGER.debug("NVD cache invalidated")

    @property
    def total_cached_cves(self) -> int:
        """Return total number of unique CVEs currently held in the cache."""
        seen: set[str] = set()
        for _, cves in self._cache.values():
            for cve in cves:
                seen.add(cve.get("cve_id", ""))
        return len(seen)

    def get_cached_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Return a single cached CVE by ID, or None if not cached."""
        for _, cves in self._cache.values():
            for cve in cves:
                if cve.get("cve_id") == cve_id:
                    return cve
        return None

    @property
    def all_cached_cves(self) -> list[dict[str, Any]]:
        """Return a flat deduplicated list of all CVEs in the cache."""
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for _, cves in self._cache.values():
            for cve in cves:
                cid = cve.get("cve_id", "")
                if cid and cid not in seen:
                    seen.add(cid)
                    out.append(cve)
        return out

    async def prefetch_all_keywords(
        self, active_services: set[str] | None = None,
    ) -> None:
        """Pre-fetch CVEs for configured keywords and product-map keywords.

        Custom keywords are always fetched.  Product-map keywords are only
        fetched for service names present in *active_services* (the set of
        service names actually detected on the network).  When
        *active_services* is ``None``, all product-map keywords are fetched
        (backwards-compatible fallback).  Also re-fetches any dynamically
        discovered keywords already in the cache.
        """
        keywords_done: set[str] = set()
        if self._custom_keywords is not None:
            for kw in self._custom_keywords:
                if kw in keywords_done:
                    continue
                keywords_done.add(kw)
                await self._get_cached(kw)
        # Fetch product-map keywords only for services detected on the network
        for svc_name, products in _SERVICE_PRODUCT_MAP.items():
            if active_services is not None and svc_name not in active_services:
                continue
            for prod in products:
                kw = prod["keyword"]
                if kw in keywords_done:
                    continue
                keywords_done.add(kw)
                await self._get_cached(kw)
        # Also refresh any dynamically discovered keywords already in cache
        for kw in list(self._cache.keys()):
            if kw not in keywords_done:
                keywords_done.add(kw)
                await self._get_cached(kw)
        _LOGGER.info(
            "NVD prefetch complete: %d keywords, %d total cached CVEs",
            len(keywords_done),
            self.total_cached_cves,
        )

    @property
    def last_updated(self) -> datetime | None:
        """Return the most recent fetch timestamp across all cached keywords."""
        if not self._cache:
            return None
        return max(ts for ts, _ in self._cache.values())

    @property
    def cached_keywords(self) -> list[dict[str, Any]]:
        """Return info about every keyword currently in the cache.

        Each entry: {keyword, cve_count, fetched_at, source} where source is
        'product_map' for static keywords and 'banner' for dynamically
        discovered ones.
        """
        static_kws: set[str] = set()
        for products in _SERVICE_PRODUCT_MAP.values():
            for prod in products:
                static_kws.add(prod["keyword"])
        tech_kws: set[str] = {tp["keyword"] for tp in _TECHNOLOGY_PRODUCT_MAP.values()}
        custom_kws: set[str] = set(self._custom_keywords) if self._custom_keywords is not None else set()
        result: list[dict[str, Any]] = []
        for kw, (ts, cves) in self._cache.items():
            if kw in custom_kws:
                source = "custom"
            elif kw in static_kws:
                source = "product_map"
            elif kw in tech_kws:
                source = "fingerprint"
            else:
                source = "banner"
            result.append({
                "keyword": kw,
                "cve_count": len(cves),
                "fetched_at": ts.isoformat(),
                "source": source,
            })
        result.sort(key=lambda e: e["keyword"].lower())
        return result

    async def find_vulnerabilities(
        self,
        ip: str,
        services: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return NVD-sourced vuln dicts for the given *ip* and *services* list.

        For services in ``_SERVICE_PRODUCT_MAP`` uses precise CPE vendor/product
        filtering.  For HTTP services with detected ``technologies``, matches
        against ``_TECHNOLOGY_PRODUCT_MAP`` so only confirmed products produce
        findings (e.g. WooCommerce CVEs only appear if WooCommerce was actually
        fingerprinted).  For **all other** non-HTTP services with an
        identifiable banner, falls back to generic keyword search with
        version-range matching.
        """
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for svc in services:
            svc_name = str(svc.get("service_name", "")).lower()
            svc_port = int(svc.get("port", 0))
            banner = str(svc.get("banner", ""))
            version = str(svc.get("version", ""))
            technologies: list[str] = list(svc.get("technologies", []))
            banner_input = (banner or version).lower()
            if not banner_input:
                continue

            matched_from_map = False

            # --- Precise matching via service product map ---
            for prod in _SERVICE_PRODUCT_MAP.get(svc_name, []):
                parsed_version = re.search(prod["banner_re"], banner_input)
                if not parsed_version:
                    continue
                version_str = parsed_version.group(1)
                matched_from_map = True

                cves = await self._get_cached(prod["keyword"])
                for cve in cves:
                    key = f"{ip}:{svc_port}:{cve['cve_id']}"
                    if key in seen:
                        continue
                    if not cve["configurations"]:
                        continue
                    if not _is_version_vulnerable(
                        version_str,
                        cve["configurations"],
                        cpe_vendor=prod["cpe_vendor"],
                        cpe_product=prod["cpe_product"],
                    ):
                        continue
                    seen.add(key)
                    results.append({
                        "host_ip": ip,
                        "port": svc_port,
                        "cve_id": cve["cve_id"],
                        "cvss": cve["cvss"],
                        "severity": cve["severity"],
                        "service": svc_name,
                        "summary": cve["summary"],
                        "published": cve.get("published", ""),
                        "remediation": f"See https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
                        "matched_version": version_str,
                    })

            # --- Technology-based matching (HTTP fingerprinting results) ---
            if technologies:
                for tech_name in technologies:
                    tech_prod = _TECHNOLOGY_PRODUCT_MAP.get(tech_name)
                    if not tech_prod:
                        continue
                    # Try to extract a version from the banner for this technology
                    tech_version = _extract_tech_version(tech_name, banner, version)
                    cves = await self._get_cached(tech_prod["keyword"])
                    for cve in cves:
                        key = f"{ip}:{svc_port}:{cve['cve_id']}"
                        if key in seen:
                            continue
                        if not cve["configurations"]:
                            continue
                        if tech_version:
                            if not _is_version_vulnerable(
                                tech_version,
                                cve["configurations"],
                                cpe_vendor=tech_prod["cpe_vendor"],
                                cpe_product=tech_prod["cpe_product"],
                            ):
                                continue
                        else:
                            # No version detected — only include if CPE
                            # vendor/product matches (versionless confirmation)
                            if not _has_matching_cpe(
                                cve["configurations"],
                                tech_prod["cpe_vendor"],
                                tech_prod["cpe_product"],
                            ):
                                continue
                        seen.add(key)
                        results.append({
                            "host_ip": ip,
                            "port": svc_port,
                            "cve_id": cve["cve_id"],
                            "cvss": cve["cvss"],
                            "severity": cve["severity"],
                            "service": f"{svc_name}/{tech_name}",
                            "summary": cve["summary"],
                            "published": cve.get("published", ""),
                            "remediation": f"See https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
                            "matched_version": tech_version or "detected",
                        })

            if matched_from_map:
                continue

            # --- Generic banner-based matching ---
            # For HTTP services, skip the generic path: fingerprinting should
            # have identified any relevant products.  This prevents unrelated
            # CVEs (e.g. WooCommerce on a plain Apache server).
            is_http = svc_name in ("http", "https", "http-alt", "http-proxy", "https-alt")
            if is_http:
                continue

            extracted = _extract_product_from_banner(banner_input)
            if not extracted:
                # Try the version field too
                extracted = _extract_product_from_banner(version)
            if not extracted:
                continue

            product_keyword, version_str = extracted
            cves = await self._get_cached(product_keyword)
            for cve in cves:
                key = f"{ip}:{svc_port}:{cve['cve_id']}"
                if key in seen:
                    continue
                if not cve["configurations"]:
                    continue
                # Generic match: require product keyword in CPE criteria
                # so we only report CVEs that actually reference this product
                if not _is_version_vulnerable(
                    version_str,
                    cve["configurations"],
                    cpe_keyword=product_keyword.lower(),
                ):
                    continue
                seen.add(key)
                results.append({
                    "host_ip": ip,
                    "port": svc_port,
                    "cve_id": cve["cve_id"],
                    "cvss": cve["cvss"],
                    "severity": cve["severity"],
                    "service": svc_name,
                    "summary": cve["summary"],
                    "published": cve.get("published", ""),
                    "remediation": f"See https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
                    "matched_version": version_str,
                })

        if results:
            _LOGGER.info("NVD find_vulnerabilities(%s): %d CVEs matched across %d services", ip, len(results), len(services))
        return results


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities) catalog
# ---------------------------------------------------------------------------

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVClient:
    """Downloads and caches the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, session: aiohttp.ClientSession, ttl_hours: int = 24) -> None:
        self._session = session
        self._ttl = timedelta(hours=ttl_hours)
        self._catalog: dict[str, dict[str, Any]] = {}  # cve_id -> entry
        self._fetched_at: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def total(self) -> int:
        return len(self._catalog)

    @property
    def ttl_hours(self) -> int:
        return int(self._ttl.total_seconds() // 3600)

    @property
    def fetched_at(self) -> datetime | None:
        return self._fetched_at

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        """Return KEV entry for *cve_id* or None."""
        return self._catalog.get(cve_id)

    def is_in_kev(self, cve_id: str) -> bool:
        return cve_id in self._catalog

    def all_entries(self) -> list[dict[str, Any]]:
        """Return all KEV catalog entries."""
        return list(self._catalog.values())

    async def fetch(self) -> None:
        """Download the catalog if the cache has expired."""
        async with self._lock:
            if self._fetched_at and (datetime.now(_UTC) - self._fetched_at) < self._ttl:
                return
            try:
                async with self._session.get(
                    _KEV_URL, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        _LOGGER.warning("CISA KEV fetch HTTP %d", resp.status)
                        return
                    data = await resp.json(content_type=None)
                vulns = data.get("vulnerabilities", [])
                catalog: dict[str, dict[str, Any]] = {}
                for v in vulns:
                    cve_id = v.get("cveID", "")
                    if cve_id:
                        catalog[cve_id] = {
                            "cve_id": cve_id,
                            "vendor": v.get("vendorProject", ""),
                            "product": v.get("product", ""),
                            "name": v.get("vulnerabilityName", ""),
                            "description": v.get("shortDescription", ""),
                            "date_added": v.get("dateAdded", ""),
                            "due_date": v.get("dueDate", ""),
                            "action": v.get("requiredAction", ""),
                        }
                self._catalog = catalog
                self._fetched_at = datetime.now(_UTC)
                _LOGGER.info("CISA KEV catalog loaded: %d known exploited vulnerabilities", len(catalog))
            except Exception as exc:
                _LOGGER.warning("CISA KEV fetch error: %s", exc)
