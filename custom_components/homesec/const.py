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
CONF_ENRICHMENT_TTL_MINUTES = "enrichment_ttl_minutes"

# External IP enrichment
CONF_IPINFO_TOKEN = "ipinfo_token"
CONF_VIRUSTOTAL_API_KEY = "virustotal_api_key"
CONF_SHODAN_API_KEY = "shodan_api_key"
CONF_ABUSEIPDB_API_KEY = "abuseipdb_api_key"
CONF_IPINFO_DAILY_BUDGET = "ipinfo_daily_budget"
CONF_VIRUSTOTAL_DAILY_BUDGET = "virustotal_daily_budget"
CONF_SHODAN_DAILY_BUDGET = "shodan_daily_budget"
CONF_ABUSEIPDB_DAILY_BUDGET = "abuseipdb_daily_budget"

# DNS resolution + blacklists
CONF_ENABLE_DNS_RESOLUTION = "enable_dns_resolution"
CONF_BLACKLIST_URLS = "blacklist_urls"

# NVD CVE enrichment
CONF_NVD_API_KEY = "nvd_api_key"
CONF_NVD_API_URL = "nvd_api_url"
CONF_NVD_TTL_HOURS = "nvd_ttl_hours"
CONF_NVD_MIN_YEAR = "nvd_min_year"
CONF_NVD_KEYWORDS = "nvd_keywords"

DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 2055
DEFAULT_INTERNAL_NETWORKS = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
DEFAULT_SCAN_PORT_THRESHOLD = 100
DEFAULT_SCAN_WINDOW_SECONDS = 600
DEFAULT_HIGH_EGRESS_THRESHOLD = 50_000_000
DEFAULT_ENABLE_WEBUI = True
DEFAULT_ENABLE_SCANNER = True
DEFAULT_SCAN_INTERVAL = 300
DEFAULT_SCAN_PORTS = (
    "21-23,25,53,80,110,111,135,139,143,443,445,465,515,554,587,631,"
    "993,995,1080,1433,1521,1723,1883,2049,2323,3306,3389,4443,5000,"
    "5060,5432,5555,5900,6379,6667,8000,8008,8080,8443,8883,8888,"
    "9090,9100,9200,27017,49152"
)
DEFAULT_SCAN_EXCEPTIONS = ""
DEFAULT_EXTERNAL_IP_RETENTION = 5
DEFAULT_ENRICHMENT_TTL_MINUTES = 300

# External enrichment defaults (empty = disabled)
DEFAULT_IPINFO_TOKEN = ""
DEFAULT_VIRUSTOTAL_API_KEY = ""
DEFAULT_SHODAN_API_KEY = ""
DEFAULT_ABUSEIPDB_API_KEY = ""
DEFAULT_IPINFO_DAILY_BUDGET = 1500
DEFAULT_VIRUSTOTAL_DAILY_BUDGET = 500
DEFAULT_SHODAN_DAILY_BUDGET = 1000
DEFAULT_ABUSEIPDB_DAILY_BUDGET = 1000

# NVD defaults
DEFAULT_NVD_API_KEY = ""
DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_TTL_HOURS = 12
DEFAULT_NVD_MIN_YEAR = 2020
DEFAULT_NVD_KEYWORDS = (
    "OpenSSH,Apache HTTP Server,nginx,MySQL,MariaDB,vsftpd,Samba"
)

# DNS / blacklist defaults
DEFAULT_ENABLE_DNS_RESOLUTION = True
DEFAULT_BLACKLIST_URLS = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt,"
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
)

COORDINATOR_INTERVAL_SECONDS = 30


def get_entry_value(entry: ConfigEntry, key: str, default: Any | None = None) -> Any:
    if key in entry.options:
        return entry.options[key]
    if key in entry.data:
        return entry.data[key]
    return default
