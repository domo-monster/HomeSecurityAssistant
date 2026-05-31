Security Assistant

Security Assistant is a custom Home Assistant integration for home network security monitoring.
It combines passive NetFlow/IPFIX traffic analysis, active host scanning, DNS threat-intel checks,
external IP enrichment, and CVE visibility in one sidebar dashboard.

Website
- https://domotic.monster/homesec.html

Repository
- https://github.com/domo-monster/HomeSecurityAssistant

Documentation languages
- English: https://domotic.monster/homesec.html
- French:  https://domotic.monster/homesec_fr.html
- German:  https://domotic.monster/homesec_de.html

Version
- 0.9.0

What is included
- NetFlow v5/v9/IPFIX listener with internal/external traffic classification.
- Active scanner (optional): host availability, open ports, service hints, lightweight fingerprinting.
- External IP intelligence via ipwho.is (default), optional VirusTotal and AbuseIPDB.
- DNS blacklist and DNS proxy features with query logging.
- Vulnerability visibility using NVD + CISA KEV correlation.
- Findings, recommendations, and baseline anomaly detection.
- Multi-view frontend panel: Overview, Network Map, Hosts, Findings, External IPs,
  Vulnerabilities, Statistics, DNS, Suricata, Recommendations, Settings.

Recent 0.9.0 updates
- Faster settings workflow via in-place option application (reduced disruptive full reload behavior).
- Non-blocking settings save path.
- Startup/reload timing instrumentation in backend logs for profiling.
- Settings page links card (GitHub + language-aware documentation link).
- Sidebar copyright link points to https://domotic.monster.

Installation (HACS)
1. Open HACS -> Integrations -> Custom Repositories.
2. Add repository URL: https://github.com/domo-monster/HomeSecurityAssistant
3. Install Security Assistant.
4. Restart Home Assistant.
5. Add integration from Settings -> Devices & Services.

Manual installation
1. Copy custom_components/homesec into your Home Assistant custom_components folder.
2. Restart Home Assistant.
3. Add integration from Settings -> Devices & Services.

Core sensors
- Active Devices
- Scanned Devices
- Total Flows
- Open Findings
- Vulnerability Count
- Suspicious Sources
- High Egress Sources

Core services
- homesec.trigger_scan
- homesec.nvd_refresh
- homesec.blacklist_refresh
- homesec.start_baseline_training
- homesec.stop_baseline_training
- homesec.retrain_baseline
- homesec.clear_baseline

Important notes
- Flow analysis is metadata-based (not full packet payload inspection).
- Fingerprinting and role detection are heuristic.
- External enrichment quality depends on optional API keys/providers.

Persistent files
The integration stores runtime and settings state in YAML files under /config,
including homesec.yaml, homesec_hosts.yaml, homesec_dns_log.yaml, homesec_ext_ips.yaml,
homesec_baseline.yaml, and related files.

Version history
- See changelog.txt in this repository.