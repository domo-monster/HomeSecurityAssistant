from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform

DOMAIN = "homesec"
PLATFORMS: list[Platform] = [Platform.SENSOR]

CONF_BIND_HOST = "bind_host"
CONF_BIND_PORT = "bind_port"
CONF_INTERNAL_NETWORKS = "internal_networks"
CONF_SCAN_PORT_THRESHOLD = "scan_port_threshold"
CONF_SCAN_WINDOW_SECONDS = "scan_window_seconds"
CONF_HIGH_EGRESS_THRESHOLD = "high_egress_threshold"
CONF_ENABLE_WEBUI = "enable_webui"
CONF_ENABLE_SCANNER = "enable_scanner"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_SCAN_PORTS = "scan_ports"
CONF_SCAN_EXCEPTIONS = "scan_exceptions"
CONF_EXTERNAL_IP_RETENTION = "external_ip_retention_hours"
CONF_RETENTION_SUSPICIOUS_HOURS = "retention_suspicious_hours"
CONF_RETENTION_MALICIOUS_HOURS = "retention_malicious_hours"
CONF_ENRICHMENT_TTL_MINUTES = "enrichment_ttl_minutes"

# External IP enrichment
CONF_VIRUSTOTAL_API_KEY = "virustotal_api_key"
CONF_ABUSEIPDB_API_KEY = "abuseipdb_api_key"
CONF_VIRUSTOTAL_DAILY_BUDGET = "virustotal_daily_budget"
CONF_ABUSEIPDB_DAILY_BUDGET = "abuseipdb_daily_budget"

# DNS resolution + blacklists
CONF_ENABLE_DNS_RESOLUTION = "enable_dns_resolution"
CONF_BLACKLIST_URLS = "blacklist_urls"

# DNS proxy
CONF_DNS_PROXY_ENABLED = "dns_proxy_enabled"
CONF_DNS_PROXY_PORT = "dns_proxy_port"
CONF_DNS_PROXY_UPSTREAM = "dns_proxy_upstream"
CONF_DNS_LOG_RETENTION_HOURS = "dns_log_retention_hours"
CONF_DNS_PROXY_CHECK_SOURCES = "dns_proxy_check_sources"
CONF_DNS_BLOCKED_CATEGORIES = "dns_blocked_categories"
CONF_DNS_OVERRIDES = "dns_overrides"

# NVD CVE enrichment
CONF_NVD_API_KEY = "nvd_api_key"
CONF_NVD_API_URL = "nvd_api_url"
CONF_NVD_TTL_HOURS = "nvd_ttl_hours"
CONF_NVD_MIN_YEAR = "nvd_min_year"
CONF_NVD_KEYWORDS = "nvd_keywords"

# Statistics view
CONF_STATS_TOP_N = "stats_top_n"

DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 2055
DEFAULT_INTERNAL_NETWORKS = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fd00::/8,fe80::/10"
DEFAULT_SCAN_PORT_THRESHOLD = 100
DEFAULT_SCAN_WINDOW_SECONDS = 600
DEFAULT_HIGH_EGRESS_THRESHOLD = 50_000_000
DEFAULT_ENABLE_WEBUI = True
DEFAULT_ENABLE_SCANNER = True
DEFAULT_SCAN_INTERVAL = 3000
DEFAULT_SCAN_PORTS = (
    "21-23,25,53,80,110,111,135,139,143,443,445,465,515,554,587,631,"
    "993,995,1080,1433,1521,1723,1883,2049,2323,3306,3389,4443,5000,"
    "5060,5432,5555,5900,6379,6667,8000,8008,8080,8443,8883,8888,"
    "9090,9100,9200,27017,49152"
)
DEFAULT_SCAN_EXCEPTIONS = ""
DEFAULT_EXTERNAL_IP_RETENTION = 5
DEFAULT_RETENTION_SUSPICIOUS_HOURS = 48   # 2 days
DEFAULT_RETENTION_MALICIOUS_HOURS = 168  # 7 days
DEFAULT_ENRICHMENT_TTL_MINUTES = 1440  # 24 hours

# External enrichment defaults (empty = disabled)
DEFAULT_VIRUSTOTAL_API_KEY = ""
DEFAULT_ABUSEIPDB_API_KEY = ""
DEFAULT_VIRUSTOTAL_DAILY_BUDGET = 500
DEFAULT_ABUSEIPDB_DAILY_BUDGET = 1000

# NVD defaults
DEFAULT_NVD_API_KEY = ""
DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_TTL_HOURS = 12
DEFAULT_NVD_MIN_YEAR = 2020
DEFAULT_NVD_KEYWORDS = (
    "OpenSSH,Android Debug Bridge,Apache HTTP Server,nginx,MySQL,MariaDB,Samba"
)

# Statistics view defaults
DEFAULT_STATS_TOP_N = 10

# DNS / blacklist defaults
DEFAULT_ENABLE_DNS_RESOLUTION = True
DEFAULT_BLACKLIST_URLS = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt,"
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt,"
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
)

# DNS proxy defaults
DEFAULT_DNS_PROXY_ENABLED = False
DEFAULT_DNS_PROXY_PORT = 53
DEFAULT_DNS_PROXY_UPSTREAM = "1.1.1.1"
DEFAULT_DNS_LOG_RETENTION_HOURS = 24
DEFAULT_DNS_PROXY_CHECK_SOURCES = ""  # empty = check all sources
DEFAULT_DNS_BLOCKED_CATEGORIES = ""  # empty = block nothing
DEFAULT_DNS_OVERRIDES = ""  # empty = no local overrides

COORDINATOR_INTERVAL_SECONDS = 30


def get_entry_value(entry: ConfigEntry, key: str, default: Any | None = None) -> Any:
    if key in entry.options:
        return entry.options[key]
    if key in entry.data:
        return entry.data[key]
    return default
