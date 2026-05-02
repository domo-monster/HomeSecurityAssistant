<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/brand/logo%402x.png" alt="Home Security Assistant" width="200">
</p>

# Home Security Assistant

Home Security Assistant is a custom Home Assistant integration that provides real-time network security monitoring for your home. It combines passive NetFlow/IPFIX traffic analysis with active network scanning, external IP threat intelligence, DNS blacklist checks, and vulnerability detection — all presented through a dedicated multi-view sidebar dashboard.

**Website:** [https://domotic.monster/homesec.html](https://domotic.monster/homesec.html)

## Features

### Network Flow Analysis
- Listens for **NetFlow v5, v9, and IPFIX** datagrams on a configurable UDP port
- Classifies internal vs. external traffic using configurable CIDR ranges
- Tracks per-device flow counts, byte volumes, and connection history
- Detects suspicious patterns: outbound traffic to abused ports, port scanning, unusual egress volume

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_netmap.png" alt="Network Map Example" width="600">
  <br>
  <em>Example: Network Flow Analysis Map</em>
</p>

### Active Network Scanner
- Optional ping + port scan of all observed internal hosts (nmap-style, configurable interval)
- **Configurable scan ports** — specify individual ports, ranges, or both (e.g. `22,80,443,8000-9000`). Defaults to 47 well-known ports: 21-23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 515, 554, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2323, 3306, 3389, 4443, 5000, 5060, 5432, 5555, 5900, 6379, 6667, 8000, 8008, 8080, 8443, 8883, 8888, 9090, 9100, 9200, 27017, 49152
- Discovers open services and OS fingerprints even when hosts block ping
- **HTTP fingerprinting** — lightweight WhatWeb-style technology detection on HTTP(S) ports. Identifies CMS platforms (WordPress, WooCommerce, Joomla, Drupal, Magento), web servers (Tomcat, IIS, Caddy, Varnish, HAProxy), applications (Grafana, GitLab, Nextcloud, Jenkins, phpMyAdmin, Pi-hole, Synology DSM, UniFi, Elasticsearch, Prometheus), and runtimes (PHP, Node.js, ASP.NET) from response headers, cookies, and HTML content
- Reports scan results per host: alive status, ping latency, open ports, OS guess, detected technologies

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_hosts.png" alt="Active Network Scanner Example" width="600">
  <br>
  <em>Example: Active Network Scanner Hosts View</em>
</p>

### External IP Intelligence
- Enriches external IPs with **ipwho.is** (free, no auth), **VirusTotal**, and **AbuseIPDB** (all optional, API keys configurable)
- **Background-only enrichment** — all provider calls run in a background worker queue; on-demand lookups (IP detail panel) return cached results instantly, never blocking the UI
- **Reverse DNS resolution** for external IPs
- Checks external IPs and hostnames against **threat intel blacklists** (abuse.ch feeds by default, customizable)
- **Severity-based retention** — separate configurable windows for clean, suspicious, and malicious IPs (clean: default 24 h, suspicious: 48 h, malicious: 168 h / 7 days)

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_pip.png" alt="External IP Intelligence Example" width="600">
  <br>
  <em>Example: External IP Intelligence Table</em>
</p>

### Vulnerability Detection
- **NVD enrichment** — queries the NIST National Vulnerability Database REST API 2.0 for CVEs matching detected service banners. Precise CPE vendor/product filtering for 20+ service mappings: SSH (OpenSSH, Dropbear), HTTP (Apache, nginx, lighttpd), MySQL/MariaDB, FTP (vsftpd, ProFTPD), SMTP (Postfix, Exim, Sendmail), Redis, MongoDB, PostgreSQL, SMB/NetBIOS/Microsoft-DS (Samba), IMAP (Dovecot), MQTT/MQTT-TLS (Mosquitto), ADB (Android Debug Bridge), DNS (BIND, dnsmasq), NTP (ntpd, Chrony), RTSP (Live555, GStreamer), and UPnP (MiniUPnP). Generic banner-based matching covers any other service with an identifiable version string
- **Service-aware prefetching** — NVD keyword prefetch is scoped to services actually detected on the network, avoiding unnecessary API calls for products not present
- **HTTP technology validation** — CVEs for web applications (WordPress, WooCommerce, Drupal, etc.) are only reported if the technology was actually **confirmed via HTTP fingerprinting**, eliminating false positives
- **CISA KEV integration** — cross-references findings against the CISA Known Exploited Vulnerabilities catalog, flagging CVEs under active exploitation
- **Version-range matching** — uses CPE configuration data to check if the exact detected version falls within a vulnerable range


<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_nvdbrowser.png" alt="Vulnerability Detection Example" width="600">
  <br>
  <em>Example: Vulnerability Detection & NVD Browser</em>
</p>

### Device Fingerprinting & Enrichment
- Fingerprints devices from observed service ports and traffic behavior
- Infers device roles: gateway, camera, IoT, unknown, etc.
- **Editable roles** — correct any auto-detected role via dropdown in the Hosts view; overrides are persisted across restarts
- Enriches device identities from Home Assistant `device_tracker` entities (IP, name, hostname, MAC)
- Flags devices with known high/critical CVE vulnerabilities as "at risk"

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_ov_cards.png" alt="Device Fingerprinting and Enrichment Example" width="600">
  <br>
  <em>Example: Device Fingerprinting & Enrichment Overview Cards</em>
</p>

### Security Findings
- Actionable findings for high/critical issues with severity, source IP, category, and occurrence count
- Categories: suspicious ports, port scanning, high egress, vulnerabilities
- **Grouped findings view** (default) — findings with the same title are collapsed into a single card showing a severity badge, host count, aggregated occurrence count, and latest timestamp. Expand any group with ▶ to see per-host rows with individual dismiss buttons
- **Dismiss all** — one-click button on each group dismisses every finding in that group simultaneously
- **Regex dismiss** — "🗑 Pattern…" button opens a modal with a regex input, a live preview of all matched findings, and an optional note field; matching findings across all groups are dismissed in one action
- **Flat view** toggle switches back to the original per-finding card layout
- **Dismissible findings** — dismiss individual findings from the UI; a `POST /api/homesec/findings/dismiss_by_pattern` endpoint is also available for scripting
- **Hardening recommendations** with expand panels — click any recommendation card to reveal affected hosts (IP, tracker name, role badge, CVE links) and related findings (severity badge, source IP, summary); cards without structured data remain static

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_reco.png" alt="Security Findings Example" width="600">
  <br>
  <em>Example: Security Findings & Recommendations</em>
</p>

### DNS Proxy
- Built-in **DNS proxy server** that intercepts all DNS queries on a configurable port and upstream resolver
- Checks every queried **domain** against the loaded threat-intel blacklists and blocks known-malicious lookups
- **Per-category blocking** — optionally restrict entire categories (e.g. `malware`, `phishing`, `ads`) from configured blocklist feeds
- **Source filtering** (`check_sources`) — optionally limit blocking to queries forwarded from specific upstream resolvers
- **DNS overrides** — define custom `domain=ip` rules to resolve specific hostnames to fixed IPs, useful for local split-DNS or ad-hoc redirects
- Maintains a rolling **DNS query log** (configurable retention; up to 10 000 entries in memory) showing timestamp, client IP, queried domain, query type, verdict (allowed / blocked), and matched source feed
- Fires a `homesec_malicious_dns` HA event whenever a blocked domain is queried, with src IP, domain, query type, and source feed
- **Automatic hiding** — the DNS Queries sidebar nav item and the Overview DNS Proxy card are hidden when the proxy is not running, keeping the UI uncluttered

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_dns.png" alt="DNS Proxy Example" width="600">
  <br>
  <em>Example: DNS Proxy Query Log</em>
</p>

### Statistics Dashboard

A dedicated statistics view consolidates all operational metrics in one place:

- **Activity Timeline** (full-width) — three stacked bar charts covering the last 24 hours: Public IPs seen per hour, internal Hosts per hour, and DNS queries per hour (colour-coded: clean / blocked / malicious)
- **Top N Public IPs** — most-contacted external IPs ranked by flow count, with Pie / List toggle
- **Top N Countries** — contacted countries ranked by flow count, with Pie / List toggle
- **Top N Internal Talkers** — highest-traffic internal devices ranked by total bytes, with Pie / List toggle
- **Top N Threat IPs** — external IPs rated suspicious or malicious, with Pie / List toggle
- **Blocked DNS Queries by Category** — breakdown of blocked/malicious DNS queries by threat category, with Pie / List toggle
- **Top N Blocked Queries by Client** — internal hosts generating the most blocked/malicious DNS queries, with Pie / List toggle
- **Top N Blocked / Malicious Domains** (full-width) — table of most-queried blocked or malicious domains with category pills and query counts
- **Enrichment Budget** (full-width) — per-provider daily usage, budget, usage bar, status badge, detected tier/plan, and recent API errors

The configurable **Statistics top N** option (3–25, default 10) controls the depth of all ranked lists.

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_stats.png" alt="Statistics Dashboard Example" width="600">
  <br>
  <em>Example: Statistics Dashboard</em>
</p>

### Sidebar Dashboard
A dedicated multi-view single-page application registered in the HA sidebar:

- **Overview** — summary stats, **Active Scan** card (last scan time, duration, hosts found, scan interval), NetFlow listener health, recent alerts, **DNS Proxy** card (running/stopped, total queries, blocked count, blocked %), and **NVD keyword chips** showing all active search keywords color-coded by source (violet for user-configured, green for scan-derived). Quick-access navigation links at the bottom of the overview jump directly to the Vulnerabilities, Statistics, and DNS Queries views. The DNS Proxy card and DNS Queries link are hidden when the proxy is disabled.
- **Network Map** — live force-directed graph with zoom/pan, showing scanned hosts, flow-active hosts, at-risk devices, gateways, and top external peers. Filter toggles: All / Scanned / Flow only / External
- **Hosts** — searchable device inventory with inferred roles, scan results, and tracker-enriched names (alive hosts only)
- **Findings** — actionable security findings with grouped view (default), regex dismiss, CVE details, and remediation hints
- **External IPs** — enriched external IP table with threat ratings, VirusTotal hits, AbuseIPDB scores, **traffic volume (KB)** column (sortable), last-seen timestamps, and on-demand lookup
- **Vulnerabilities** — sortable vulnerability browser listing **all cached NVD CVEs** (not just network-detected) with CVSS scores, severity, affected service/technology, published date, CISA KEV flags, detected-on-network count, and a **CVE detail modal** showing full description and CPE criteria. CVEs not matching any host on the network are shown with a dimmed "not detected" indicator
- **Statistics** — at-a-glance operational dashboard. The **Activity Timeline** card (full-width) now contains three bar charts side-by-side: Public IPs per hour, Hosts per hour, and DNS queries per hour (stacked: clean/blocked/malicious). Below it: Top N Public IPs, Top N Countries, Top N Internal Talkers, and Top N Threat IPs (each with Pie/List toggle). Next row: **Blocked DNS Queries by Category** and **Top N Blocked Queries by Client** — both styled with the same Pie/List toggle as the other stat cards. Then a full-width **Top N Blocked/Malicious Domains** table, and finally the **Enrichment Budget** card with per-provider usage, daily budget (∞ for unlimited tiers), usage bar, status badge, detected account tier/plan, and recent API errors
- **DNS Queries** — paginated DNS query log (default 25 rows per page, adjustable to 10/25/50/100) with global filters for domain/client IP, verdict, category, and malicious-only. Includes a **Blocked / Malicious by Category** pie chart and a **🚫 Clear blocked** button to remove all blocked entries from the log in one click. Hidden when the DNS proxy is disabled.
- **Recommendations** — prioritized hardening suggestions based on current network state; expandable cards show affected hosts and related findings

The dashboard auto-refreshes every 30 seconds. The network map updates live without resetting the physics simulation.

### Brand Icons
Custom integration icons (including dark mode variants) are shipped in the `brand/` subdirectory of the component. Home Assistant 2026.3+ automatically serves them through the local brands API — no external CDN or brands repository submission required.

## Sensors

| Sensor | Description |
|---|---|
| Active Devices | Count of observed internal devices |
| Scanned Devices | Count of devices with active scan results |
| Total Flows | Total NetFlow/IPFIX records ingested |
| Open Findings | Count of actionable (high/critical) findings |
| Vulnerability Count | Count of CVE vulnerabilities detected |
| Suspicious Sources | Devices reaching commonly abused ports |
| High Egress Sources | Devices exceeding outbound data threshold |
| NVD Keywords | Count of NVD search keywords in cache (attributes: per-keyword CVE count, source classification — `custom` / `product_map` / `fingerprint` / `banner` — and fetch time) |

Each sensor exposes diagnostic attributes including device inventory, listener health, exporter IPs, protocol versions, template counts, and dropped datagram counters.

## Services

All services are callable from **Developer Tools → Actions** in Home Assistant.

| Service | Description |
|---|---|
| `homesec.trigger_scan` | Immediately run a full active network scan without waiting for the next scheduled interval |
| `homesec.nvd_refresh` | Flush the local NVD CVE cache and re-fetch fresh vulnerability data from NVD |
| `homesec.blacklist_refresh` | Clear all loaded threat-intel entries and immediately re-download every configured blocklist URL. Useful after adding or changing URLs, or when you need up-to-date coverage without waiting for the next scheduled refresh |

## Installation

### Installation via HACS (Recommended)

1. In Home Assistant, go to **HACS → Integrations → Custom Repositories**.
2. Add this repository URL: `https://github.com/domo-monster/HomeSecurityAssistant` as a custom integration.
3. Search for "Home Security Assistant" in HACS and click **Install**.
4. Restart Home Assistant.
5. Go to **Settings → Devices & Services → Add Integration** and search for "Home Security Assistant".
6. Configure the bind host, UDP port, internal network CIDRs, scanner settings, and optional API keys.
7. Point your router or flow exporter at the Home Assistant host and configured port.

### Manual Installation

1. Copy the `custom_components/homesec` directory into your Home Assistant `custom_components/` folder.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for "Home Security Assistant".
4. Configure the bind host, UDP port, internal network CIDRs, scanner settings, and optional API keys.
5. Point your router or flow exporter at the Home Assistant host and configured port.

Device tracker enrichment is automatic — if you have router or presence integrations that create `device_tracker` entities, Home Security Assistant will use those names, hostnames, and MAC addresses.

## Configuration Options

| Option | Default | Description |
|---|---|---|
| Bind host | `0.0.0.0` | UDP listen address |
| Bind port | `2055` | UDP listen port |
| Internal networks | `192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fd00::/8, fe80::/10` | Comma-separated CIDRs |
| Port-scan detection window | `600` s | Time window for port-scan heuristic |
| Unique ports before scan alert | `100` | Threshold for port-scan finding |
| High egress threshold | `50 MB` | Octets per interval to trigger alert |
| Enable sidebar panel | `true` | Register the Web UI panel |
| Sidebar panel requires admin | `true` | Restrict sidebar panel visibility to Home Assistant admin users |
| Enable active scanner | `true` | Ping + port scan internal hosts |
| Scan interval | `3000` s | Seconds between active scans |
| Scan exceptions | _(empty)_ | Comma-separated IPs to skip during active scanning |
| Scan ports | _(47 default ports)_ | Comma-separated ports or ranges to probe (e.g. `22,80,443,8000-9000`) |
| External IP retention (clean) | `5` h | How long to keep clean external IPs (0 = forever) |
| Suspicious IP retention | `48` h | How long to keep external IPs rated as suspicious |
| Malicious IP retention | `168` h | How long to keep external IPs rated as malicious (default 7 days) |
| Enable reverse DNS | `true` | Resolve external IP hostnames |
| Blacklist URLs | abuse.ch feeds | Comma-separated threat intel feed URLs |
| VirusTotal API key | _(empty)_ | Optional, enables VT lookups |
| AbuseIPDB API key | _(empty)_ | Optional, enables abuse score lookups |
| Enrichment cache TTL | `1440` min | Minutes before re-querying external enrichment providers |
| AbuseIPDB confidence required before querying VirusTotal | `30` | VirusTotal is queried only when AbuseIPDB confidence meets/exceeds this threshold (0–100) |
| VirusTotal daily budget | `500` | Max daily VirusTotal queries |
| AbuseIPDB daily budget | `1000` | Max daily AbuseIPDB queries |
| NVD cache TTL | `12` h | Hours before re-fetching CVE data from NVD |
| NVD minimum CVE year | `2020` | Oldest CVE year to include (0 = all years) |
| NVD search keywords | _(16 defaults)_ | Comma-separated product names to query NVD for (e.g. OpenSSH, nginx, WordPress) |
| Statistics top N | `10` | Number of top entries shown in the Statistics view (3–25) |
| Enable DNS proxy | `false` | Run a local DNS proxy that filters queries against threat-intel blacklists |
| DNS proxy port | `53` | UDP port the DNS proxy listens on |
| DNS proxy upstream | `1.1.1.1` | Upstream resolver for non-blocked queries |
| DNS proxy check sources | _(empty)_ | Comma-separated threat-feed source names to use for blocking decisions (empty = all sources). If set, matches from other feed sources are logged but not blocked. |
| DNS blocked categories | _(empty)_ | Comma-separated feed categories to block (e.g. `malware,phishing,ads`) |
| DNS overrides | _(empty)_ | Static `domain=ip` override rules (one per line or comma-separated). Persisted in `homesec.yaml` and restored on startup. |
| DNS log retention | `24` h | Hours to keep DNS query log entries (0 = keep all) |

All options can be changed after setup via **Configure** on the integration card. Changes trigger an automatic reload.

## Recommended Exporters

- OpenWrt with `softflowd`
- OPNsense / pfSense NetFlow or IPFIX export
- UniFi gateway flow export
- MikroTik Traffic Flow

### Example: softflowd

```sh
softflowd -i br-lan -n 192.168.1.10:2055 -v 5
```

### Example: OPNsense / pfSense

- Target host: Home Assistant IP
- Target port: `2055`
- Version: `9` or `IPFIX`
- Interfaces: LAN and any VLANs you want visibility for

## Troubleshooting

### Sidebar Panel Missing

1. Confirm the integration is loaded in **Settings → Devices & Services**.
2. Restart Home Assistant after updating the component files.
3. Hard-refresh your browser (Ctrl+Shift+R).
4. Try the fallback URL: `/api/homesec/panel`
5. Check that the sidebar panel isn't hidden in your user profile customization.
6. Verify "Enable sidebar panel" is enabled in the integration configuration.

### No Flows Arriving

- Check that your exporter targets the correct IP and port.
- Verify firewall rules allow UDP traffic on the configured port.
- If using Docker, ensure the port is mapped through to the container.

## Practical Limits

- Flow analysis is based on metadata (IPs, ports, byte counts), not packet payload. It cannot identify every protocol misuse or exploit.
- Device fingerprinting is heuristic and informative, not authoritative.
- Active scanning requires network access to internal hosts from the HA instance.
- External IP enrichment quality depends on the optional API keys configured.
- Tracker enrichment depends on existing HA integrations exposing device IPs through `device_tracker` entities.

## Persistent Storage

Home Security Assistant writes multiple plain YAML files to the Home Assistant config directory (alongside `configuration.yaml`). They survive integration updates, HA restarts, and config-entry reloads. Do not place them under version control if they contain API keys.

### `homesec.yaml` — integration settings

All user-facing configuration options are mirrored here on every reload. At startup the file is read back and merged into the active config entry so that values are never lost when the component is updated via HACS or a manual file copy. Only the keys listed below are ever written; any other keys present in the file are ignored.

| Key | Description |
|---|---|
| `bind_host` / `bind_port` | UDP listener address and port |
| `internal_networks` | Comma-separated internal CIDR ranges |
| `scan_window_seconds` / `scan_port_threshold` | Port-scan detection parameters |
| `high_egress_threshold` | Byte threshold for the high-egress finding |
| `enable_webui` | Whether the sidebar panel is registered |
| `enable_scanner` / `scan_interval` / `scan_exceptions` / `scan_ports` | Active scanner settings |
| `external_ip_retention_hours` | Retention window for external IP history |
| `enable_dns_resolution` / `blacklist_urls` | DNS resolution and threat-feed URLs |
| `dns_proxy_enabled` / `dns_proxy_port` / `dns_proxy_upstream` | DNS proxy enable flag, port, and upstream resolver |
| `dns_proxy_check_sources` / `dns_blocked_categories` / `dns_overrides` | DNS proxy source filter, category blocklist, and static overrides |
| `dns_log_retention_hours` | DNS query log retention window |
| `virustotal_api_key` / `abuseipdb_api_key` | External enrichment API credentials |
| `vt_abuseipdb_threshold` | AbuseIPDB confidence threshold required before querying VirusTotal |
| `enrichment_ttl_minutes` | Enrichment provider cache TTL |
| `virustotal_daily_budget` / `abuseipdb_daily_budget` | Per-provider daily query budgets |
| `retention_suspicious_hours` / `retention_malicious_hours` | Severity-based retention windows for external IPs |
| `stats_top_n` | Number of top entries shown in the Statistics view |
| `nvd_api_url` / `nvd_ttl_hours` / `nvd_min_year` | NVD CVE enrichment settings |
| `nvd_keywords` | Comma-separated NVD search keywords |

**Merge behaviour:** file values fill in keys that are absent or empty in the config entry — the UI always wins for keys that have a value in both places. This allows pre-seeding settings by writing the file before the integration is installed.

### `homesec_roles.yaml` — device role overrides

Stores manual role corrections made via the Hosts view dropdown. Structure is a flat `ip: role` mapping. Written every time a role is changed; read at startup so overrides are immediately applied to all hosts without waiting for a new scan cycle.

```yaml
# Home Security Assistant — device role overrides
192.168.1.1: gateway
192.168.1.50: camera
192.168.1.101: iot
```

Available roles match the fingerprinting vocabulary: `gateway`, `camera`, `iot`, `desktop`, `server`, `mobile`, `unknown`.

### `homesec_hosts.yaml` — discovered hosts

Written after each active-scanner cycle and reloaded at startup. Ensures the Hosts view and network map are immediately populated on restart without waiting for the first full scan. Each key is an IP address; each value is a dict of scan results (`alive`, `open_ports`, `os_guess`, `ping_ms`, etc.).

This file is auto-managed — editing it manually is not recommended as it will be overwritten after the next scan.

### `homesec_names.yaml` — device name overrides

Stores manual host display-name overrides made in the Hosts view. Structure is a flat `ip: name` mapping.

### `homesec_dismissed.yaml` — dismissed findings

Written every time a finding is dismissed via the Findings dashboard view; read at startup so dismissals survive restarts and component updates. Structure is a flat YAML list of finding-key strings. You can manually remove a key from this file to restore a previously dismissed finding — it will reappear after the next coordinator refresh.

```yaml
# Home Security Assistant — dismissed findings
- "vuln:192.168.1.50:80:CVE-2021-1234"
- "suspicious_port:192.168.1.20"
```

### `homesec_dns_log.yaml` — DNS query log

Written on integration shutdown and reloaded at startup (filtered to the configured retention window). Stores the rolling DNS proxy query log so that history survives restarts. Entries contain `timestamp`, `src_ip`, `domain`, `qtype`, `verdict`, and matched `source`. This file is auto-managed — do not edit it manually.

Additional runtime state files used by recent versions:

- `homesec_ext_ips.yaml` — persisted external IP state (first/last seen, sources, ports, severity)
- `homesec_timeseries.yaml` — persisted statistics timeline points
- `homesec_enrichment_state.yaml` — per-provider daily enrichment usage counters
- `homesec_chart_state.yaml` — persisted top statistics chart snapshots (restart fallback)

These files don't exist yet — they are created at runtime by a running Home Assistant instance, not in this development workspace. They are written to hass.config.config_dir, which is wherever your HA configuration lives (the directory containing configuration.yaml).

Typical locations depending on your install type:

HA install type	Config directory
Home Assistant OS / Supervised	/config/
Home Assistant Container (Docker)	the volume mapped to /config
Home Assistant Core (venv)	~/.homeassistant/

So the files will appear as:
/config/homesec.yaml
/config/homesec_roles.yaml
/config/homesec_names.yaml
/config/homesec_hosts.yaml
/config/homesec_dismissed.yaml
/config/homesec_dns_log.yaml
/config/homesec_ext_ips.yaml
/config/homesec_timeseries.yaml
/config/homesec_enrichment_state.yaml
/config/homesec_chart_state.yaml

They are created:

homesec.yaml — the first time the integration loads after setup
homesec_roles.yaml — the first time you save a role override in the Hosts view
homesec_names.yaml — the first time you save a custom host name in the Hosts view
homesec_hosts.yaml — after the first active scanner cycle completes
homesec_dismissed.yaml — the first time you dismiss a finding in the Findings view
homesec_dns_log.yaml / homesec_ext_ips.yaml / homesec_timeseries.yaml — after corresponding runtime data is produced

## FAQ

### Why does the CISA KEV match count seem low?

The Vulnerability Browser only shows CVEs that are relevant to services actually detected on your network. The CISA Known Exploited Vulnerabilities (KEV) catalog contains ~1,100 CVEs across hundreds of products (Microsoft Windows, Adobe, Cisco, Apple, etc.), but the NVD cache only holds CVEs for the specific services running on your hosts — for example OpenSSH, nginx, or PostgreSQL. The KEV match count reflects the real overlap between those two sets, which is typically small (single digits to low tens) for a home network.

This is expected behavior, not a bug: a low KEV count means few of the actively-exploited vulnerabilities in the CISA catalog apply to the software versions found on your network.

## Changelog

### 0.6.2

- **Recommendation count fix** — "Unknown roles" and "Tracker enrichment" recommendation thresholds now count only *alive* devices, matching the filter used in the Hosts view. Previously offline devices could inflate counts and trigger recommendations unnecessarily.
- **Clickable recommendation cards** — each recommendation now exposes structured `hosts` and `findings_refs` metadata. In the UI, cards with data show a ▶ chevron and expand on click to reveal: affected hosts (IP, tracker name, role badge, CVE links) and related findings (severity badge, source IP, summary).
- **Traffic (KB) in External IPs** — each external IP entry now aggregates total byte volume from flow records. A sortable **Traffic (KB)** column appears in the External IPs table.
- **Grouped findings view** — the Findings view defaults to grouped mode: findings sharing the same summary are collapsed into one card. Expanding a group shows per-host rows. A "Dismiss all N" button dismisses the entire group at once. A header toggle switches to the original flat layout.
- **Regex dismiss** — a "🗑 Pattern…" button opens a dismiss-by-regex modal with live preview. The backend also exposes `POST /api/homesec/findings/dismiss_by_pattern` for scripting.
- **Statistics view DNS reorganisation** — the DNS Activity bar chart moved into the Activity Timeline card (alongside Public IPs/hr and Hosts/hr). "Blocked DNS Queries by Category" and "Top N Blocked Queries by Client" are now styled stat-cards with Pie/List toggle buttons. "Top N Blocked/Malicious Domains" is promoted to a full-width card.

### 0.6.1

See [GitHub releases](https://github.com/domo-monster/HomeSecurityAssistant/releases) for earlier history.

## Development

Syntax check:

```sh
python3 -m compileall custom_components/homesec
```
