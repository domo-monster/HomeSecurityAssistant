Security Assistant

Security Assistant ist eine benutzerdefinierte Home-Assistant-Integration zur
Sicherheitsuberwachung des Heimnetzwerks. Sie kombiniert passive NetFlow/IPFIX-
Analyse, aktives Host-Scanning, DNS-Bedrohungslisten, externe IP-Anreicherung
und CVE-Transparenz in einem Sidebar-Dashboard.

Website
- https://domotic.monster/homesec.html

GitHub-Repository
- https://github.com/domo-monster/HomeSecurityAssistant

Dokumentation nach Sprache
- Englisch: https://domotic.monster/homesec.html
- Franzosisch: https://domotic.monster/homesec_fr.html
- Deutsch: https://domotic.monster/homesec_de.html

Version
- 0.9.0

Enthaltene Funktionen
- NetFlow v5/v9/IPFIX Listener mit intern/externer Traffic-Klassifizierung.
- Aktiver Scanner (optional): Host-Erreichbarkeit, offene Ports,
  Service-Hinweise, leichtes Fingerprinting.
- Externe IP-Intelligence uber ipwho.is (standard), optional VirusTotal und
  AbuseIPDB.
- DNS-Proxy- und Blacklist-Funktionen mit Query-Logging.
- Schwachstellenansicht mit NVD und CISA-KEV-Korrelation.
- Findings, Empfehlungen und Baseline-Anomalieerkennung.
- Multi-View-Frontend: Overview, Network Map, Hosts, Findings, External IPs,
  Vulnerabilities, Statistics, DNS, Suricata, Recommendations, Settings.

Neue Anderungen in 0.9.0
- In-Place-Anwendung von Optionen (weniger storende Komplett-Reloads).
- Nicht blockierender Einstellungen-Speicherpfad.
- Start/Reload-Timing-Logs zur Performance-Analyse.
- Link-Karte unten auf der Settings-Seite (GitHub + sprachabhangige Doku).
- Sidebar-Copyright-Link auf https://domotic.monster aktualisiert.

Baseline-Bilder
- Live-vs-Baseline-Vergleich:

  ![Live vs Baseline](custom_components/homesec/hsa_baseline_comparison.png)

- Baseline-Abweichungsuebersicht:

  ![Baseline deviation](custom_components/homesec/hsa_baseline_deviation.png)

Installation (HACS)
1. HACS -> Integrations -> Custom Repositories offnen.
2. Repository hinzufugen: https://github.com/domo-monster/HomeSecurityAssistant
3. Security Assistant installieren.
4. Home Assistant neu starten.
5. Integration unter Settings -> Devices & Services hinzufugen.

Manuelle Installation
1. custom_components/homesec in den custom_components-Ordner kopieren.
2. Home Assistant neu starten.
3. Integration unter Settings -> Devices & Services hinzufugen.

Wichtige Services
- homesec.trigger_scan
- homesec.nvd_refresh
- homesec.blacklist_refresh
- homesec.start_baseline_training
- homesec.stop_baseline_training
- homesec.retrain_baseline
- homesec.clear_baseline

Wichtige Hinweise
- Die Flow-Analyse basiert auf Metadaten (keine vollstandige Payload-Inspektion).
- Fingerprinting und Rollen-Erkennung sind heuristisch.
- Die Qualitat der externen Anreicherung hangt von optionalen API-Schlusseln ab.

Persistente Dateien
Die Integration speichert Zustand und Konfiguration als YAML in /config,
einschliesslich homesec.yaml, homesec_hosts.yaml, homesec_dns_log.yaml,
homesec_ext_ips.yaml, homesec_baseline.yaml und weiterer Dateien.

Versionsverlauf
- Siehe changelog.txt in diesem Repository.