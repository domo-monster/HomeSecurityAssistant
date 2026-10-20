<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/brand/logo%402x.png" alt="Security Assistant" width="200">
</p>


[![Forum FR](https://img.shields.io/badge/Forum-Home%20Assistant-41BDF5?style=flat-square)](https://forum.hacf.fr/t/integration-posture-securite-du-reseau-informatique-domestique/78744/102) [![Forum EN](https://img.shields.io/badge/Forum-Home%20Assistant-41BDF5?style=flat-square)](https://community.home-assistant.io/t/custom-component-security-posture/1005268) [![Donate](https://img.shields.io/badge/Donate-Buy%20Me%20a%20Coffee-FFDD00?style=flat-square&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/domo.monster)

# Security Assistant

Security Assistant is a custom Home Assistant integration that provides real-time network security monitoring for your home. It combines passive NetFlow/IPFIX traffic analysis with active network scanning, external IP threat intelligence, DNS blacklist checks, and vulnerability detection — all presented through a dedicated multi-view sidebar dashboard.

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
- **Inbound traffic detection** — external IPs that initiate connections *to* your internal servers (e.g. hosted services, exposed ports) are tracked and enriched exactly like outbound peers — same blacklist checks, same threat ratings, same retention rules
- **Traffic direction** — each external IP entry carries a direction badge: `↑ Outbound` (your device reached out), `↓ Inbound` (it connected to one of your servers), or `↕ Both`. When both directions are observed and the internal hosts involved are *different* (an external IP contacted a host it never received outbound traffic from), an amber ⚠ warning is shown — a pattern consistent with C2 beacon-then-callback or post-reconnaissance probing

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

### Baseline Learning Mode
- **Automated normal-behavior profiling** — enable training mode and the integration observes your network for a configurable duration (default 7 days) to build a baseline of normal hosts, external peers, open ports, DNS domains, and traffic volume
- **Three modes**: `Disabled` (no baseline), `Learning` (actively training), `Active` (baseline ready, anomaly detection enabled)
- **Confidence scoring** — baseline is rated `low`, `medium`, or `high` based on the number of hosts and training snapshots observed
- **Anomaly detection** — once active, flags deviations from the baseline as findings: new internal hosts, new external peers, newly opened ports, new DNS domain categories, and egress volume spikes (configurable multiplier)
- **Persistent baseline** — learned state is saved in Home Assistant storage (`.storage/homesec.baseline`) and survives restarts and component updates
- **Network Map integration** — the Network Map gains two extra view modes: **Baseline Snapshot** (the learned graph) and **Live vs Baseline** (overlay comparison highlighting new edges in a distinct colour)
- Controlled via four HA services: `start_baseline_training`, `stop_baseline_training`, `retrain_baseline`, and `clear_baseline`, all callable from Developer Tools → Actions or automations
- **Overview card** — a new Baseline card in the Overview shows current mode, training progress (elapsed / remaining time), baseline creation age, confidence level, and quick-action buttons

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_baseline_comparison.png" alt="Live vs Baseline comparison" width="600">
  <br>
  <em>Example: Live vs Baseline comparison</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_baseline_deviation.png" alt="Baseline deviation summary" width="600">
  <br>
  <em>Example: Baseline deviation summary</em>
</p>

### Suricata Alert Streaming
- **Suricata EVE alert listener** — Home Security Assistant can receive Suricata alert events over TCP and ingest them into the sidebar dashboard and alert log.
- **Companion pusher script** — the included `suricata_pusher.py` script tails Suricata's EVE JSON alert file and streams each alert line to the listener.
- **Alert visibility** — Suricata alerts are shown in the sidebar dashboard and are persisted with the other runtime logs so they survive restarts.
- **Securing the listener** — anyone who can reach the listener port can submit alerts, so set an **auth token** and/or **allowed pusher sources** in *Settings → Suricata Alert Listener*. Then start the pusher with the same token (the environment variable keeps it out of `ps` output):

  ```sh
  HSA_SURICATA_TOKEN='your-token' python3 suricata_pusher.py --ha-host 192.168.1.10 --ha-port 6343
  ```

  Every received field is type-checked and length-limited, and the stored timestamp is the time Home Assistant received the alert (the sensor's own timestamp is kept as `event_timestamp`).

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_suricata_ov.png" alt="Suricata overview" width="600">
  <br>
  <em>Example: Suricata overview card</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_suricata_alerts.png" alt="Suricata alerts list" width="600">
  <br>
  <em>Example: Suricata alerts view</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/domo-monster/HomeSecurityAssistant/main/custom_components/homesec/hsa_suricata_stats.png" alt="Suricata statistics" width="600">
  <br>
  <em>Example: Suricata statistics</em>
</p>

### Security Findings
- Actionable findings for high/critical issues with severity, source IP, category, and occurrence count
- Categories: suspicious ports, port scanning, high egress, vulnerabilities, **baseline anomalies** (new host, new peer, new port, new DNS category, egress spike)
- **Four view modes** — **By Category** (default), **By Host**, **By Severity**, and **Flat**; mode buttons appear below the section title for both the active Security Findings section and the Dismissed section
- **By Category** — groups findings by their type with human-friendly labels (Vulnerability / CVE, Port Scan, Suspicious Open Port, High Egress Traffic); each group shows a severity badge, finding count, aggregated occurrences, and latest timestamp
- **By Host** — groups all findings for the same source IP into a single expandable card, sorted by severity then IP address
- **By Severity** — groups findings into Critical / High / Medium / Low / Info buckets
- **Flat** — individual per-finding cards unchanged
- Expand any group with ▶ to see per-item rows with individual dismiss or restore buttons
- **Dismiss all** — one-click button on each group dismisses every finding in that group simultaneously
- **Regex dismiss** — "🗑 Pattern…" button opens a modal with a regex input, a live preview of all matched findings, and an optional note field; matching findings across all groups are dismissed in one action
- **Per-section search** — each section (Baseline Anomalies, Security Findings, Dismissed) has its own live search bar filtering by summary, source IP, category, or CVE ID; active filter counts shown in the section header
- **Unified Dismissed section** — dismissed security findings and dismissed baseline anomalies are shown together; baseline items carry a teal `Baseline` chip; the same four view modes and search bar apply
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

- **Overview** — summary stats, **Active Scan** card (last scan time, duration, hosts found, scan interval), NetFlow listener health, recent alerts, **DNS Proxy** card (running/stopped, total queries, blocked count, blocked %), **Baseline** card (current mode, training progress or baseline age, confidence, and action buttons), and **NVD keyword chips** showing all active search keywords color-coded by source (violet for user-configured, green for scan-derived). Quick-access navigation links at the bottom of the overview jump directly to the Vulnerabilities, Statistics, and DNS Queries views. The DNS Proxy card and DNS Queries link are hidden when the proxy is disabled.
- **Network Map** — live force-directed graph with zoom/pan, showing scanned hosts, flow-active hosts, at-risk devices, gateways, and top external peers. Filter toggles: All / Scanned / Flow only / External. When a baseline is available, two additional view modes are unlocked: **Baseline Snapshot** (the learned graph) and **Live vs Baseline** (overlay showing new edges in a distinct colour with a host/edge count chip)
- **Hosts** — searchable device inventory with inferred roles, scan results, and tracker-enriched names (alive hosts only)
- **Findings** — actionable security findings with four view modes (**By Category**, **By Host**, **By Severity**, **Flat**) and a live search bar per section. Dismissed security findings and dismissed baseline anomalies are consolidated in a single Dismissed section with teal `Baseline` chips on baseline items. Regex dismiss, CVE details, and remediation hints included
- **External IPs** — enriched external IP table with threat ratings, VirusTotal hits, AbuseIPDB scores, **traffic volume (KB)** column (sortable), **direction badge** (`↑ Outbound` / `↓ Inbound` / `↕ Both`, sortable and filterable) with an amber ⚠ alert when the same external IP contacted a different internal host than the one that initiated the outbound relationship, last-seen timestamps, and on-demand lookup
- **Vulnerabilities** — sortable vulnerability browser listing **all cached NVD CVEs** (not just network-detected) with CVSS scores, severity, affected service/technology, published date, CISA KEV flags, detected-on-network count, and a **CVE detail modal** showing full description and CPE criteria. CVEs not matching any host on the network are shown with a dimmed "not detected" indicator
- **Statistics** — at-a-glance operational dashboard. The **Activity Timeline** card (full-width) now contains three bar charts side-by-side: Public IPs per hour, Hosts per hour, and DNS queries per hour (stacked: clean/blocked/malicious). Below it: Top N Public IPs, Top N Countries, Top N Internal Talkers, and Top N Threat IPs (each with Pie/List toggle). Next row: **Blocked DNS Queries by Category** and **Top N Blocked Queries by Client** — both styled with the same Pie/List toggle as the other stat cards. Then a full-width **Top N Blocked/Malicious Domains** table, and finally the **Enrichment Budget** card with per-provider usage, daily budget (∞ for unlimited tiers), usage bar, status badge, detected account tier/plan, and recent API errors
- **DNS Queries** — paginated DNS query log (default 25 rows per page, adjustable to 10/25/50/100) with global filters for domain/client IP, verdict, category, and malicious-only. Includes a **Blocked / Malicious by Category** pie chart and a **🚫 Clear blocked** button to remove all blocked entries from the log in one click. Hidden when the DNS proxy is disabled.
- **Recommendations** — prioritized hardening suggestions based on current network state; expandable cards show affected hosts and related findings

The dashboard auto-refreshes every 30 seconds. The network map updates live without resetting the physics simulation.

### Brand Icons
Custom integration icons (including dark mode variants) are shipped in the `brand/` subdirectory of the component. Home Assistant 2026.3+ automatically serves them through the local brands API — no external CDN or brands repository submission required.

The `brands.home-assistant.io` CDN no longer hosts custom integrations, so `https://brands.home-assistant.io/_/homesec/...` returns "icon not available" by design. The HACS (2.0.x) store and search look icons up there and therefore show a placeholder for every integration that ships local brand images; this is fixed in the Marketplace integration that replaces HACS in Home Assistant 2026.11. Inside Home Assistant (Settings → Devices & services) the icon already shows on 2026.3+.

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
| `homesec.start_baseline_training` | Start baseline training mode and begin learning a normal activity profile for the configured training duration |
| `homesec.stop_baseline_training` | Stop baseline training immediately and promote the learned state to the active baseline if any hosts were observed |
| `homesec.retrain_baseline` | Clear the current baseline and immediately restart training mode |
| `homesec.clear_baseline` | Remove the current baseline state and all training progress from persistent storage |

## Installation

### Installation via HACS (Recommended)

[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?repository=https%3A%2F%2Fgithub.com%2Fdomo-monster%2FHomeSecurityAssistant&category=Integration&owner=domo-monster)

1. In Home Assistant, go to **HACS → Integrations → Custom Repositories**.
2. Add this repository URL: `https://github.com/domo-monster/HomeSecurityAssistant` as a custom integration.
3. Search for "Security Assistant" in HACS and click **Install**.
4. Restart Home Assistant.
5. Go to **Settings → Devices & Services → Add Integration** and search for "Security Assistant".
6. Configure the bind host, UDP port, internal network CIDRs, scanner settings, and optional API keys.
7. Point your router or flow exporter at the Home Assistant host and configured port.

### Manual Installation

1. Copy the `custom_components/homesec` directory into your Home Assistant `custom_components/` folder.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for "Security Assistant".
4. Configure the bind host, UDP port, internal network CIDRs, scanner settings, and optional API keys.
5. Point your router or flow exporter at the Home Assistant host and configured port.

Device tracker enrichment is automatic — if you have router or presence integrations that create `device_tracker` entities, Security Assistant will use those names, hostnames, and MAC addresses.

## Configuration Options

| Option | Default | Description |
|---|---|---|
| Bind host | `0.0.0.0` | UDP listen address |
| Bind port | `2055` | UDP listen port |
| Allowed NetFlow exporters | _(empty)_ | Comma-separated IPs/CIDRs allowed to send flows (e.g. your router). Empty accepts any sender — setting it is strongly recommended |
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
| Blacklist URLs | abuse.ch feeds | Comma-separated threat intel feed URLs (HTTPS only). On refresh, lists are swapped in only after a successful download; a failed source keeps its previous entries |
| VirusTotal API key | _(empty)_ | Optional, enables VT lookups |
| AbuseIPDB API key | _(empty)_ | Optional, enables abuse score lookups |
| Enrichment cache TTL | `1440` min | Minutes before re-querying external enrichment providers |
| AbuseIPDB confidence required before querying VirusTotal | `30` | When an AbuseIPDB key is set, VirusTotal is queried only when AbuseIPDB confidence meets/exceeds this threshold (0–100). Without an AbuseIPDB key, VirusTotal is queried directly (within its daily budget) |
| VirusTotal daily budget | `500` | Max daily VirusTotal queries |
| AbuseIPDB daily budget | `1000` | Max daily AbuseIPDB queries |
| NVD cache TTL | `12` h | Hours before re-fetching CVE data from NVD |
| NVD minimum CVE year | `2020` | Oldest CVE year to include (0 = all years) |
| NVD search keywords | _(16 defaults)_ | Comma-separated product names to query NVD for (e.g. OpenSSH, nginx, WordPress) |
| Statistics top N | `10` | Number of top entries shown in the Statistics view (3–25) |
| Enable baseline learning | `false` | Enable the baseline training and anomaly detection engine |
| Baseline training duration | `168` h | How many hours to observe the network before promoting the baseline to active |
| Baseline minimum observations | `3` | Minimum number of coordinator snapshots a host must appear in before it is included in the baseline |
| Baseline egress anomaly multiplier | `2.5` | Egress volume is flagged as anomalous when it exceeds the baseline average by this factor |
| Enable DNS proxy | `false` | Run a local DNS proxy that filters queries against threat-intel blacklists |
| DNS proxy port | `53` | UDP and TCP port the DNS proxy listens on (bound on IPv4 and, for `0.0.0.0`, IPv6 too) |
| DNS proxy upstream | `1.1.1.1` | Upstream resolver for non-blocked queries |
| DNS proxy check sources | _(empty)_ | Comma-separated threat-feed source names to use for blocking decisions (empty = all sources). If set, matches from other feed sources are logged but not blocked. |
| DNS blocked categories | _(empty)_ | Comma-separated feed categories to block (e.g. `malware,phishing,ads`) |
| DNS overrides | _(empty)_ | Static `domain=ip` override rules (one per line or comma-separated) |
| DNS log retention | `24` h | Hours to keep DNS query log entries (0 = keep up to the 10,000-entry cap) |
| Suricata listener auth token | _(empty)_ | Shared secret the pusher must send before any alert (`--token` / `HSA_SURICATA_TOKEN`) |
| Allowed pusher sources | _(empty)_ | Comma-separated IPs/CIDRs allowed to connect to the Suricata listener |

The listener address and internal networks can be changed via **Configure** on the integration card; everything else is in the panel's **Settings** page (admin only). Values are validated before they are saved. Network listener and retention changes apply immediately; other changes reload the integration automatically.

### Access control

All data and actions in the panel go through `/api/homesec/*`. Changing anything (dismissing findings, renaming hosts, settings, lookups that spend API quota) always requires a Home Assistant **admin**. Reading the dashboard also requires an admin unless *Sidebar panel requires admin* is turned off.

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

Since 0.10.0, all state is kept in Home Assistant's own storage, in `.storage/` inside your configuration directory. Files are written atomically (no corruption on power loss), writes are batched, and the files are removed when the integration is deleted.

| Storage file | Contents |
|---|---|
| `homesec.dismissed` | Dismissed findings and their notes |
| `homesec.role_overrides` / `homesec.name_overrides` | Manual role and name overrides from the Hosts view |
| `homesec.hosts` | Active-scanner results, so the Hosts view is populated right after a restart |
| `homesec.dns_log` | DNS proxy query log (newest 10,000 entries, within the retention window) |
| `homesec.suricata_log` | Suricata alert log (newest 10,000 entries, within the retention window) |
| `homesec.ext_ips` | External IP tracking state (first/last seen, sources, ports, rating) |
| `homesec.timeseries` | Statistics timeline (30 days at 5-minute resolution) |
| `homesec.enrichment_state` | Per-provider daily enrichment usage counters |
| `homesec.baseline` | Baseline learning state |
| `homesec.chart_state` | Last top-N statistics lists (restart fallback) |
| `homesec.event_state` | Which malicious IPs / vulnerabilities were already announced on the event bus |

Settings, including API keys and the Suricata token, live only in the config entry.

**Upgrading from 0.9.x:** on first start, the old `homesec_*.yaml` files in the config directory are imported into `.storage/` and then deleted. Settings from the old `homesec.yaml` that the config entry did not have are copied into it, and the file is deleted, because it held API keys in plain text.

### Events

| Event | Fired when |
|---|---|
| `homesec_malicious_ip` | An external IP becomes malicious or blacklisted (once; again only if it clears and recurs) |
| `homesec_critical_vulnerability` | A new critical/high vulnerability finding appears (once per host, port and CVE) |
| `homesec_malicious_dns` | The DNS proxy blocks a threat-intel domain (per query) |
| `homesec_suricata_alert` | A severity-1 Suricata alert is received (per alert) |

## ☕ Support Home Security Assistant

If you find **Home Security Assistant** useful and would like to support its continued development, you can buy me a coffee.

<a href="https://www.buymeacoffee.com/domo.monster" target="_blank">
  <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png"
       alt="Buy Me A Coffee"
       style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190,190,190,0.5) !important;">
</a>

Your support helps with the time and resources required to develop, test, and maintain this integration. ❤️

**Donations are completely optional — Home Security Assistant will always remain free and open source.**

## FAQ

### Why does the CISA KEV match count seem low?

The Vulnerability Browser only shows CVEs that are relevant to services actually detected on your network. The CISA Known Exploited Vulnerabilities (KEV) catalog contains ~1,100 CVEs across hundreds of products (Microsoft Windows, Adobe, Cisco, Apple, etc.), but the NVD cache only holds CVEs for the specific services running on your hosts — for example OpenSSH, nginx, or PostgreSQL. The KEV match count reflects the real overlap between those two sets, which is typically small (single digits to low tens) for a home network.

This is expected behavior, not a bug: a low KEV count means few of the actively-exploited vulnerabilities in the CISA catalog apply to the software versions found on your network.

## Version History

Release notes and historical changes are now maintained in `changelog.txt` at the repository root.

For older releases, GitHub release notes are also available at:
https://github.com/domo-monster/HomeSecurityAssistant/releases

## Development

Syntax check:

```sh
python3 -m compileall custom_components/homesec
```

Tests (Python 3.13):

```sh
pip install -r requirements_test.txt
pytest                      # integration, parser and fuzz tests
node --test tests/js/       # panel escaping regression tests
```
