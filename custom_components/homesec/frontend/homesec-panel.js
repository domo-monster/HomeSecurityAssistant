// ── Home Security Assistant · Panel ─────────────────────────────────────────
// Multi-view web-component for the Home Security Assistant HA integration.
// Views: Overview · Network Map · Hosts · Findings · External IPs · Recommendations
// ─────────────────────────────────────────────────────────────────────────────

const _VIEWS = ['overview', 'map', 'hosts', 'findings', 'external', 'vulnerabilities', 'statistics', 'dns', 'suricata', 'recommendations', 'settings'];
const _VIEW_LABELS = {
  overview:        'Overview',
  map:             'Network Map',
  hosts:           'Hosts',
  findings:        'Findings',
  external:        'External IPs',
  vulnerabilities:  'Vulnerabilities',
  statistics:      'Statistics',
  dns:             'DNS Queries',
  suricata:        'Suricata Alerts',
  recommendations: 'Recommendations',
  settings:        'Settings',
};
const _UI_I18N = {
  fr: {
    'view.overview': 'Vue d\'ensemble',
    'view.map': 'Carte réseau',
    'view.hosts': 'Hôtes',
    'view.findings': 'Constats',
    'view.external': 'IP externes',
    'view.vulnerabilities': 'Vulnérabilités',
    'view.statistics': 'Statistiques',
    'view.dns': 'Requêtes DNS',
    'view.suricata': 'Alertes Suricata',
    'view.recommendations': 'Recommandations',
    'view.settings': 'Paramètres',
    'page.overview': 'Vue d\'ensemble',
    'page.findings': 'Constats',
    'page.statistics': 'Statistiques',
    'page.dns_queries': 'Requêtes DNS',
    'page.suricata_alerts': 'Alertes Suricata',
    'app.title': 'Security Assistant',
    'settings.title': 'Paramètres',
    'settings.subtitle': 'Les changements prennent effet après le rechargement de l\'integration.',
    'settings.loading': 'Chargement des paramètres…',
    'settings.loading_short': 'Chargement…',
    'settings.links': 'Liens',
    'settings.project': 'Projet',
    'settings.github_repo': 'Depot GitHub',
    'settings.documentation': 'Documentation',
    'settings.open_documentation': 'Ouvrir la documentation',
    'settings.unsaved': 'Vous avez des changements non enregistrés.',
    'settings.save': 'Enregistrer les paramètres',
    'settings.reload_server': 'Recharger depuis le serveur',
    'settings.failed_load': 'Échec du chargement des paramètres : ',
    'settings.failed_save': 'Échec de l\'enregistrement des paramètres : ',
    'settings.saved_reload': 'Paramètres enregistrés. L\'integration va se recharger pour appliquer les changements.',
    'settings.unsaved_title': 'Modifications non enregistrées',
    'settings.unsaved_body': 'Vous avez des changements de paramètres non enregistrés. Si vous quittez maintenant, ils seront perdus.',
    'settings.stay': 'Rester sur Paramètres',
    'settings.discard_leave': 'Ignorer et quitter',
    'settings.beforeunload': 'Vous avez des changements non enregistrés dans les paramètres. Quitter et les ignorer ?',
    'sidebar.tagline': 'Télémétrie réseau de sécurité avec contexte de flux en direct',
    'sidebar.collector_active': 'Collecteur actif',
    'sidebar.awaiting_flows': 'En attente de flux',
    // ── Overview page ────────────────────────────────────────────────
    'overview.active_findings': 'Alertes actives',
    'overview.active_cves': 'CVEs actifs',
    'overview.dismissed': 'ignoré(s)',
    'overview.never_fetched': 'jamais récupéré',
    'overview.never': 'jamais',
    'overview.stat_devices': 'Appareils',
    'overview.stat_scanned': 'Scannés',
    'overview.stat_nvd_cves': 'CVEs NVD',
    'overview.stat_cisa_kev': 'CISA KEV',
    'overview.stat_flows': 'Flux',
    'overview.stat_exporters': 'Exporteurs',
    'overview.stat_suricata_alerts': 'Alertes Suricata',
    'overview.stat_critical_alerts': 'Alertes critiques',
    // Baseline
    'overview.baseline_learning': 'Apprentissage',
    'overview.baseline_active': 'Actif',
    'overview.baseline_disabled': 'Désactivé',
    'overview.elapsed': 'Écoulé',
    'overview.progress': 'Progression',
    'overview.btn_start_training': 'Démarrer l\'apprentissage',
    'overview.btn_stop_training': 'Arrêter l\'apprentissage',
    'overview.btn_retrain': 'Réentraîner',
    'overview.btn_clear': 'Effacer',
    'overview.baseline_title': 'Référence',
    'overview.mode_label': 'Mode',
    'overview.baseline_created_label': 'Référence créée',
    // NetFlow
    'overview.netflow_title': 'Santé du collecteur NetFlow',
    'overview.status_label': 'Statut',
    'overview.no_flows_seen': 'Aucun flux reçu',
    'overview.receiving_flows': 'Flux en cours',
    'overview.no_flows_idle_prefix': 'Aucun flux (inactif ',
    'overview.uptime_label': 'Disponibilité',
    'overview.exporters_label': 'Exporteurs',
    'overview.flow_versions': 'Versions de flux',
    'overview.total_datagrams': 'Datagrammes totaux',
    'overview.parsed': 'Analysés',
    'overview.dropped': 'Perdus',
    'overview.last_flow': 'Dernier flux',
    'overview.last_error': 'Dernière erreur',
    'overview.view_statistics': 'Voir les statistiques \u2192',
    // Recent Alerts
    'overview.recent_alerts': 'Alertes récentes',
    'overview.no_active_findings': 'Aucun constat actif haut/critique',
    'overview.view_all_findings': 'Voir tous les constats \u2192',
    // Active Scan
    'overview.active_scan_title': 'Scan actif',
    'overview.last_scan': 'Dernier scan',
    'overview.last_result': 'Dernier résultat',
    'overview.duration': 'Durée',
    'overview.hosts_found': 'Hôtes trouvés',
    'overview.targets_scanned': 'Cibles scannées',
    'overview.scan_interval': 'Intervalle de scan',
    'overview.scan_completed': 'Terminé',
    'overview.scan_skipped': 'Ignoré \u2014 aucune cible découverte',
    'overview.force_scan_btn': 'Forcer le scan \u21bb',
    // NVD
    'overview.nvd_title': 'Renseignement sur les vulnérabilités (NVD)',
    'overview.last_db_fetch': 'Dernière mise à jour de la base',
    'overview.cache_ttl': 'Durée de cache',
    'overview.cves_in_db': 'CVEs en base',
    'overview.min_pub_year': 'Année de publication minimale',
    'overview.all_years': 'Toutes les années',
    'overview.keywords_label': 'Mots-clés',
    'overview.none_loaded': 'Aucun chargé',
    'overview.kw_configured': 'Configurés',
    'overview.kw_from_scans': 'Issus des scans',
    'overview.browse_vulns_btn': 'Parcourir les vulnérabilités \u2192',
    'overview.force_nvd_refresh_btn': 'Forcer la mise à jour \u21bb',
    // KEV
    'overview.kev_title': 'Vulnérabilités exploitées connues CISA (KEV)',
    'overview.last_catalog_fetch': 'Dernière récupération du catalogue',
    'overview.catalog_size': 'Taille du catalogue',
    // DNS Proxy
    'overview.dns_domains': 'domaines',
    'overview.dns_blocked_suffix': 'bloqués',
    'overview.dns_bl_empty': '0 entrées \u2014 vérifiez les URLs',
    'overview.dns_bl_downloading': 'Téléchargement\u2026',
    'overview.dns_proxy_title': 'Proxy DNS',
    'overview.dns_running': 'En cours',
    'overview.port_label': 'Port',
    'overview.upstream_label': 'Serveur amont',
    'overview.blocklist_label': 'Liste de blocage',
    'overview.last_refreshed': 'Dernière actualisation',
    'overview.queries_in_log': 'Requêtes enregistrées',
    'overview.malicious_queries': 'Requêtes malveillantes',
    'overview.blocked_queries': 'Requêtes bloquées',
    'overview.view_dns_btn': 'Voir les requêtes DNS \u2192',
    // Suricata
    'overview.suricata_listener_title': 'Récepteur d\'alertes Suricata',
    'overview.suricata_active': 'Actif',
    'overview.suricata_inactive': 'Inactif',
    'overview.exporter_ips_label': 'IP(s) exporteur',
    'overview.active_connections': 'Connexions actives',
    'overview.alerts_in_log': 'Alertes enregistrées',
    'overview.critical_alerts_label': 'Alertes critiques',
    'overview.view_suricata_btn': 'Voir les alertes Suricata \u2192',
    // Network Behaviour (baseline deviance)
    'overview.network_behaviour_title': 'Comportement réseau',
    'overview.band_normal': 'Normal',
    'overview.band_review': 'Réviser',
    'overview.band_investigate': 'Enquêter',
    'overview.band_critical': 'Critique',
    'overview.band_desc_normal': 'Le trafic correspond étroitement à votre référence. Aucune action requise.',
    'overview.band_desc_review': 'Quelques déviations détectées. Un coup d\'œil s\'impose.',
    'overview.band_desc_investigate': 'Déviations notables. Vérifiez les connexions inattendues.',
    'overview.band_desc_critical': 'Déviations importantes. Enquêtez immédiatement.',
    'overview.new_conn_single': 'nouvelle connexion inattendue',
    'overview.new_conn_plural': 'nouvelles connexions inattendues',
    'overview.new_conn_note_none': 'Aucune activité inconnue \u2014 tout le trafic actuel a été vu en formation.',
    'overview.new_conn_note_some': 'Ces connexions n\'étaient pas présentes lors de la formation.',
    'overview.new_conn_note_investigate': 'C\'est le principal facteur de votre score \u2014 enquêtez.',
    'overview.new_conn_note_review': 'Vérifiez qu\'elles sont attendues.',
    'overview.missing_conn_single': 'connexion de référence inactive',
    'overview.missing_conn_plural': 'connexions de référence inactives',
    'overview.missing_conn_note': 'Connexions vues en formation silencieuses maintenant. C\'est habituellement normal \u2014 les appareils ne maintiennent pas toutes les connexions en permanence.',
    'overview.missing_conn_note_high': 'Le nombre est très élevé, mais votre référence a probablement capturé de nombreux flux courts sur une longue fenêtre d\'apprentissage.',
    'overview.both_conn_single': 'connexion correspond à la référence',
    'overview.both_conn_plural': 'connexions correspondent à la référence',
    'overview.both_conn_note_some': 'Ces connexions sont actives et ont été vues en formation \u2014 votre trafic normal attendu.',
    'overview.both_conn_note_none': 'Aucune connexion active n\'a encore été vue dans la référence.',
    'overview.biggest_traffic_change': '\u0394 Plus grande variation de trafic',
    'overview.traffic_change_pre': 'Cette connexion connue est',
    'overview.traffic_change_mid': 'que d\'habitude',
    'overview.traffic_change_post': 'flux/snapshot).',
    'overview.traffic_change_file_hint': 'Cela pourrait être un transfert de fichier, une sauvegarde ou une mise à jour.',
    'overview.traffic_far_busier': 'beaucoup plus chargé',
    'overview.traffic_noticeably_busier': 'nettement plus chargé',
    'overview.traffic_somewhat_busier': 'légèrement plus chargé',
    'overview.traffic_slightly_busier': 'un peu plus chargé',
    'overview.traffic_far_quieter': 'beaucoup plus calme',
    'overview.traffic_noticeably_quieter': 'nettement plus calme',
    'overview.traffic_somewhat_quieter': 'légèrement plus calme',
    'overview.traffic_slightly_quieter': 'un peu plus calme',
    'overview.view_map_btn': 'Voir sur la carte réseau \u2192',
  },
  de: {
    'view.overview': '\u00dcbersicht',
    'view.map': 'Netzwerkkarte',
    'view.hosts': 'Hosts',
    'view.findings': 'Befunde',
    'view.external': 'Externe IPs',
    'view.vulnerabilities': 'Schwachstellen',
    'view.statistics': 'Statistiken',
    'view.dns': 'DNS-Anfragen',
    'view.suricata': 'Suricata-Alarme',
    'view.recommendations': 'Empfehlungen',
    'view.settings': 'Einstellungen',
    'page.overview': '\u00dcbersicht',
    'page.findings': 'Befunde',
    'page.statistics': 'Statistiken',
    'page.dns_queries': 'DNS-Anfragen',
    'page.suricata_alerts': 'Suricata-Alarme',
    'app.title': 'Security Assistant',
    'settings.title': 'Einstellungen',
    'settings.subtitle': '\u00c4nderungen werden nach dem Neuladen der Integration wirksam.',
    'settings.loading': 'Einstellungen werden geladen\u2026',
    'settings.loading_short': 'Laden\u2026',
    'settings.links': 'Links',
    'settings.project': 'Projekt',
    'settings.github_repo': 'GitHub-Repository',
    'settings.documentation': 'Dokumentation',
    'settings.open_documentation': 'Dokumentation \u00f6ffnen',
    'settings.unsaved': 'Sie haben nicht gespeicherte \u00c4nderungen.',
    'settings.save': 'Einstellungen speichern',
    'settings.reload_server': 'Vom Server neu laden',
    'settings.failed_load': 'Fehler beim Laden der Einstellungen: ',
    'settings.failed_save': 'Fehler beim Speichern der Einstellungen: ',
    'settings.saved_reload': 'Einstellungen gespeichert. Die Integration wird neu geladen, um die \u00c4nderungen zu \u00fcbernehmen.',
    'settings.unsaved_title': 'Nicht gespeicherte \u00c4nderungen',
    'settings.unsaved_body': 'Sie haben nicht gespeicherte Einstellungs\u00e4nderungen. Wenn Sie jetzt verlassen, gehen sie verloren.',
    'settings.stay': 'Bei Einstellungen bleiben',
    'settings.discard_leave': 'Verwerfen und verlassen',
    'settings.beforeunload': 'Sie haben nicht gespeicherte Einstellungs\u00e4nderungen. Verlassen und verwerfen?',
    'sidebar.tagline': 'Sicherheitsnetzwerk-Telemetrie mit Live-Flow-Kontext',
    'sidebar.collector_active': 'Collector aktiv',
    'sidebar.awaiting_flows': 'Warte auf Flows',
    // \u2500\u2500 Overview page \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    'overview.active_findings': 'Aktive Befunde',
    'overview.active_cves': 'Aktive CVEs',
    'overview.dismissed': 'ignoriert',
    'overview.never_fetched': 'nie abgerufen',
    'overview.never': 'nie',
    'overview.stat_devices': 'Ger\u00e4te',
    'overview.stat_scanned': 'Gescannt',
    'overview.stat_nvd_cves': 'NVD CVEs',
    'overview.stat_cisa_kev': 'CISA KEV',
    'overview.stat_flows': 'Flows',
    'overview.stat_exporters': 'Exporteure',
    'overview.stat_suricata_alerts': 'Suricata-Alarme',
    'overview.stat_critical_alerts': 'Kritische Alarme',
    // Baseline
    'overview.baseline_learning': 'Lernend',
    'overview.baseline_active': 'Aktiv',
    'overview.baseline_disabled': 'Deaktiviert',
    'overview.elapsed': 'Vergangen',
    'overview.progress': 'Fortschritt',
    'overview.btn_start_training': 'Training starten',
    'overview.btn_stop_training': 'Training stoppen',
    'overview.btn_retrain': 'Neu trainieren',
    'overview.btn_clear': 'L\u00f6schen',
    'overview.baseline_title': 'Baseline',
    'overview.mode_label': 'Modus',
    'overview.baseline_created_label': 'Baseline erstellt',
    // NetFlow
    'overview.netflow_title': 'NetFlow-Collector-Status',
    'overview.status_label': 'Status',
    'overview.no_flows_seen': 'Keine Flows empfangen',
    'overview.receiving_flows': 'Flows werden empfangen',
    'overview.no_flows_idle_prefix': 'Keine Flows (inaktiv ',
    'overview.uptime_label': 'Betriebszeit',
    'overview.exporters_label': 'Exporteure',
    'overview.flow_versions': 'Flow-Versionen',
    'overview.total_datagrams': 'Gesamte Datagramme',
    'overview.parsed': 'Verarbeitet',
    'overview.dropped': 'Verworfen',
    'overview.last_flow': 'Letzter Flow',
    'overview.last_error': 'Letzter Fehler',
    'overview.view_statistics': 'Statistiken anzeigen \u2192',
    // Recent Alerts
    'overview.recent_alerts': 'Aktuelle Alarme',
    'overview.no_active_findings': 'Keine aktiven hohen/kritischen Befunde',
    'overview.view_all_findings': 'Alle Befunde anzeigen \u2192',
    // Active Scan
    'overview.active_scan_title': 'Aktiver Scan',
    'overview.last_scan': 'Letzter Scan',
    'overview.last_result': 'Letztes Ergebnis',
    'overview.duration': 'Dauer',
    'overview.hosts_found': 'Hosts gefunden',
    'overview.targets_scanned': 'Gescannte Ziele',
    'overview.scan_interval': 'Scan-Intervall',
    'overview.scan_completed': 'Abgeschlossen',
    'overview.scan_skipped': 'Übersprungen \u2014 keine Ziele gefunden',
    'overview.force_scan_btn': 'Scan erzwingen \u21bb',
    // NVD
    'overview.nvd_title': 'Schwachstellen-Intelligence (NVD)',
    'overview.last_db_fetch': 'Letztes Datenbank-Update',
    'overview.cache_ttl': 'Cache-G\u00fcltigkeitsdauer',
    'overview.cves_in_db': 'CVEs in der Datenbank',
    'overview.min_pub_year': 'Minimales Ver\u00f6ffentlichungsjahr',
    'overview.all_years': 'Alle Jahre',
    'overview.keywords_label': 'Schl\u00fcsselw\u00f6rter',
    'overview.none_loaded': 'Keine geladen',
    'overview.kw_configured': 'Konfiguriert',
    'overview.kw_from_scans': 'Aus Scans',
    'overview.browse_vulns_btn': 'Schwachstellen durchsuchen \u2192',
    'overview.force_nvd_refresh_btn': 'NVD-Aktualisierung erzwingen \u21bb',
    // KEV
    'overview.kev_title': 'CISA Bekannte ausgenutzte Schwachstellen (KEV)',
    'overview.last_catalog_fetch': 'Letzter Katalogabruf',
    'overview.catalog_size': 'Kataloggr\u00f6\u00dfe',
    // DNS Proxy
    'overview.dns_domains': 'Domains',
    'overview.dns_blocked_suffix': 'blockiert',
    'overview.dns_bl_empty': '0 Eintr\u00e4ge \u2014 URLs pr\u00fcfen',
    'overview.dns_bl_downloading': 'Wird heruntergeladen\u2026',
    'overview.dns_proxy_title': 'DNS-Proxy',
    'overview.dns_running': 'L\u00e4uft',
    'overview.port_label': 'Port',
    'overview.upstream_label': 'Upstream-Server',
    'overview.blocklist_label': 'Blockliste',
    'overview.last_refreshed': 'Zuletzt aktualisiert',
    'overview.queries_in_log': 'Anfragen im Protokoll',
    'overview.malicious_queries': 'Sch\u00e4dliche Anfragen',
    'overview.blocked_queries': 'Blockierte Anfragen',
    'overview.view_dns_btn': 'DNS-Anfragen anzeigen \u2192',
    // Suricata
    'overview.suricata_listener_title': 'Suricata-Alarm-Listener',
    'overview.suricata_active': 'Aktiv',
    'overview.suricata_inactive': 'Inaktiv',
    'overview.exporter_ips_label': 'Exporteur-IP(s)',
    'overview.active_connections': 'Aktive Verbindungen',
    'overview.alerts_in_log': 'Alarme im Protokoll',
    'overview.critical_alerts_label': 'Kritische Alarme',
    'overview.view_suricata_btn': 'Suricata-Alarme anzeigen \u2192',
    // Network Behaviour
    'overview.network_behaviour_title': 'Netzwerkverhalten',
    'overview.band_normal': 'Normal',
    'overview.band_review': 'Pr\u00fcfen',
    'overview.band_investigate': 'Untersuchen',
    'overview.band_critical': 'Kritisch',
    'overview.band_desc_normal': 'Der Datenverkehr entspricht weitgehend Ihrer Baseline. Kein Handlungsbedarf.',
    'overview.band_desc_review': 'Einige Abweichungen erkannt. Ein kurzer Blick lohnt sich.',
    'overview.band_desc_investigate': 'Deutliche Abweichungen. Pr\u00fcfen Sie unerwartete Verbindungen.',
    'overview.band_desc_critical': 'Erhebliche Abweichungen. Sofort untersuchen.',
    'overview.new_conn_single': 'unerwartete neue Verbindung',
    'overview.new_conn_plural': 'unerwartete neue Verbindungen',
    'overview.new_conn_note_none': 'Keine unbekannte Aktivit\u00e4t \u2014 der gesamte aktuelle Datenverkehr wurde beim Training gesehen.',
    'overview.new_conn_note_some': 'Diese Verbindungen waren beim Baseline-Training nicht vorhanden.',
    'overview.new_conn_note_investigate': 'Dies ist der Haupttreiber Ihres Scores \u2014 untersuchen Sie es.',
    'overview.new_conn_note_review': 'Pr\u00fcfen Sie, ob sie erwartet werden.',
    'overview.missing_conn_single': 'Baseline-Verbindung jetzt inaktiv',
    'overview.missing_conn_plural': 'Baseline-Verbindungen jetzt inaktiv',
    'overview.missing_conn_note': 'Beim Training gesehene Verbindungen, die jetzt still sind. Das ist meist normal \u2014 Ger\u00e4te halten nicht alle Verbindungen dauerhaft aufrecht.',
    'overview.missing_conn_note_high': 'Die Anzahl ist sehr hoch, aber Ihre Baseline hat wahrscheinlich viele kurzlebige Flows \u00fcber ein langes Trainingsfenster erfasst.',
    'overview.both_conn_single': 'Verbindung entspricht der Baseline',
    'overview.both_conn_plural': 'Verbindungen entsprechen der Baseline',
    'overview.both_conn_note_some': 'Diese Verbindungen sind aktiv und wurden beim Training gesehen \u2014 Ihr erwarteter normaler Datenverkehr.',
    'overview.both_conn_note_none': 'Noch keine aktiven Verbindungen in der Baseline gesehen.',
    'overview.biggest_traffic_change': '\u0394 Gr\u00f6\u00dfte Verkehrs\u00e4nderung',
    'overview.traffic_change_pre': 'Diese bekannte Verbindung ist',
    'overview.traffic_change_mid': 'als \u00fcblich',
    'overview.traffic_change_post': 'Flows/Snapshot).',
    'overview.traffic_change_file_hint': 'K\u00f6nnte eine Datei\u00fcbertragung, ein Backup oder ein Update sein.',
    'overview.traffic_far_busier': 'viel st\u00e4rker belastet',
    'overview.traffic_noticeably_busier': 'merklich st\u00e4rker belastet',
    'overview.traffic_somewhat_busier': 'etwas st\u00e4rker belastet',
    'overview.traffic_slightly_busier': 'leicht st\u00e4rker belastet',
    'overview.traffic_far_quieter': 'viel ruhiger',
    'overview.traffic_noticeably_quieter': 'merklich ruhiger',
    'overview.traffic_somewhat_quieter': 'etwas ruhiger',
    'overview.traffic_slightly_quieter': 'leicht ruhiger',
    'overview.view_map_btn': 'Auf Netzwerkkarte anzeigen \u2192',
  },
  es: {
    'view.overview': 'Resumen',
    'view.map': 'Mapa de red',
    'view.hosts': 'Hosts',
    'view.findings': 'Hallazgos',
    'view.external': 'IPs externas',
    'view.vulnerabilities': 'Vulnerabilidades',
    'view.statistics': 'Estad\u00edsticas',
    'view.dns': 'Consultas DNS',
    'view.suricata': 'Alertas Suricata',
    'view.recommendations': 'Recomendaciones',
    'view.settings': 'Configuraci\u00f3n',
    'page.overview': 'Resumen',
    'page.findings': 'Hallazgos',
    'page.statistics': 'Estad\u00edsticas',
    'page.dns_queries': 'Consultas DNS',
    'page.suricata_alerts': 'Alertas Suricata',
    'app.title': 'Security Assistant',
    'settings.title': 'Configuraci\u00f3n',
    'settings.subtitle': 'Los cambios surten efecto tras recargar la integraci\u00f3n.',
    'settings.loading': 'Cargando configuraci\u00f3n\u2026',
    'settings.loading_short': 'Cargando\u2026',
    'settings.links': 'Enlaces',
    'settings.project': 'Proyecto',
    'settings.github_repo': 'Repositorio GitHub',
    'settings.documentation': 'Documentaci\u00f3n',
    'settings.open_documentation': 'Abrir documentaci\u00f3n',
    'settings.unsaved': 'Tiene cambios sin guardar.',
    'settings.save': 'Guardar configuraci\u00f3n',
    'settings.reload_server': 'Recargar desde el servidor',
    'settings.failed_load': 'Error al cargar la configuraci\u00f3n: ',
    'settings.failed_save': 'Error al guardar la configuraci\u00f3n: ',
    'settings.saved_reload': 'Configuraci\u00f3n guardada. La integraci\u00f3n se recargar\u00e1 para aplicar los cambios.',
    'settings.unsaved_title': 'Cambios sin guardar',
    'settings.unsaved_body': 'Tiene cambios de configuraci\u00f3n sin guardar. Si sale ahora, se perder\u00e1n.',
    'settings.stay': 'Permanecer en Configuraci\u00f3n',
    'settings.discard_leave': 'Descartar y salir',
    'settings.beforeunload': '\u00bfSalir y descartar los cambios no guardados de la configuraci\u00f3n?',
    'sidebar.tagline': 'Telemetr\u00eda de red de seguridad con contexto de flujo en vivo',
    'sidebar.collector_active': 'Colector activo',
    'sidebar.awaiting_flows': 'Esperando flujos',
    // \u2500\u2500 Overview page \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    'overview.active_findings': 'Hallazgos activos',
    'overview.active_cves': 'CVEs activos',
    'overview.dismissed': 'ignorado(s)',
    'overview.never_fetched': 'nunca obtenido',
    'overview.never': 'nunca',
    'overview.stat_devices': 'Dispositivos',
    'overview.stat_scanned': 'Analizados',
    'overview.stat_nvd_cves': 'CVEs NVD',
    'overview.stat_cisa_kev': 'CISA KEV',
    'overview.stat_flows': 'Flujos',
    'overview.stat_exporters': 'Exportadores',
    'overview.stat_suricata_alerts': 'Alertas Suricata',
    'overview.stat_critical_alerts': 'Alertas cr\u00edticas',
    // Baseline
    'overview.baseline_learning': 'Aprendiendo',
    'overview.baseline_active': 'Activo',
    'overview.baseline_disabled': 'Desactivado',
    'overview.elapsed': 'Transcurrido',
    'overview.progress': 'Progreso',
    'overview.btn_start_training': 'Iniciar entrenamiento',
    'overview.btn_stop_training': 'Detener entrenamiento',
    'overview.btn_retrain': 'Reentrenar',
    'overview.btn_clear': 'Limpiar',
    'overview.baseline_title': 'L\u00ednea base',
    'overview.mode_label': 'Modo',
    'overview.baseline_created_label': 'L\u00ednea base creada',
    // NetFlow
    'overview.netflow_title': 'Estado del colector NetFlow',
    'overview.status_label': 'Estado',
    'overview.no_flows_seen': 'Sin flujos recibidos',
    'overview.receiving_flows': 'Recibiendo flujos',
    'overview.no_flows_idle_prefix': 'Sin flujos (inactivo ',
    'overview.uptime_label': 'Tiempo activo',
    'overview.exporters_label': 'Exportadores',
    'overview.flow_versions': 'Versiones de flujo',
    'overview.total_datagrams': 'Datagramas totales',
    'overview.parsed': 'Analizados',
    'overview.dropped': 'Descartados',
    'overview.last_flow': '\u00daltimo flujo',
    'overview.last_error': '\u00daltimo error',
    'overview.view_statistics': 'Ver estad\u00edsticas \u2192',
    // Recent Alerts
    'overview.recent_alerts': 'Alertas recientes',
    'overview.no_active_findings': 'Sin hallazgos activos altos/cr\u00edticos',
    'overview.view_all_findings': 'Ver todos los hallazgos \u2192',
    // Active Scan
    'overview.active_scan_title': 'An\u00e1lisis activo',
    'overview.last_scan': '\u00daltimo an\u00e1lisis',
    'overview.last_result': '\u00daltimo resultado',
    'overview.duration': 'Duraci\u00f3n',
    'overview.hosts_found': 'Hosts encontrados',
    'overview.targets_scanned': 'Objetivos analizados',
    'overview.scan_interval': 'Intervalo de an\u00e1lisis',
    'overview.scan_completed': 'Completado',
    'overview.scan_skipped': 'Omitido \u2014 sin objetivos descubiertos',
    'overview.force_scan_btn': 'Forzar an\u00e1lisis \u21bb',
    // NVD
    'overview.nvd_title': 'Inteligencia de vulnerabilidades (NVD)',
    'overview.last_db_fetch': '\u00daltima actualizaci\u00f3n de BD',
    'overview.cache_ttl': 'TTL de cach\u00e9',
    'overview.cves_in_db': 'CVEs en BD',
    'overview.min_pub_year': 'A\u00f1o de publicaci\u00f3n m\u00ednimo',
    'overview.all_years': 'Todos los a\u00f1os',
    'overview.keywords_label': 'Palabras clave',
    'overview.none_loaded': 'Ninguna cargada',
    'overview.kw_configured': 'Configuradas',
    'overview.kw_from_scans': 'De an\u00e1lisis',
    'overview.browse_vulns_btn': 'Explorar vulnerabilidades \u2192',
    'overview.force_nvd_refresh_btn': 'Forzar actualizaci\u00f3n NVD \u21bb',
    // KEV
    'overview.kev_title': 'Vulnerabilidades explotadas conocidas CISA (KEV)',
    'overview.last_catalog_fetch': '\u00daltima obtenci\u00f3n del cat\u00e1logo',
    'overview.catalog_size': 'Tama\u00f1o del cat\u00e1logo',
    // DNS Proxy
    'overview.dns_domains': 'dominios',
    'overview.dns_blocked_suffix': 'bloqueados',
    'overview.dns_bl_empty': '0 entradas \u2014 verificar URLs',
    'overview.dns_bl_downloading': 'Descargando\u2026',
    'overview.dns_proxy_title': 'Proxy DNS',
    'overview.dns_running': 'Ejecut\u00e1ndose',
    'overview.port_label': 'Puerto',
    'overview.upstream_label': 'Servidor upstream',
    'overview.blocklist_label': 'Lista de bloqueo',
    'overview.last_refreshed': '\u00daltima actualizaci\u00f3n',
    'overview.queries_in_log': 'Consultas en registro',
    'overview.malicious_queries': 'Consultas maliciosas',
    'overview.blocked_queries': 'Consultas bloqueadas',
    'overview.view_dns_btn': 'Ver consultas DNS \u2192',
    // Suricata
    'overview.suricata_listener_title': 'Receptor de alertas Suricata',
    'overview.suricata_active': 'Activo',
    'overview.suricata_inactive': 'Inactivo',
    'overview.exporter_ips_label': 'IP(s) exportador',
    'overview.active_connections': 'Conexiones activas',
    'overview.alerts_in_log': 'Alertas en registro',
    'overview.critical_alerts_label': 'Alertas cr\u00edticas',
    'overview.view_suricata_btn': 'Ver alertas Suricata \u2192',
    // Network Behaviour
    'overview.network_behaviour_title': 'Comportamiento de red',
    'overview.band_normal': 'Normal',
    'overview.band_review': 'Revisar',
    'overview.band_investigate': 'Investigar',
    'overview.band_critical': 'Cr\u00edtico',
    'overview.band_desc_normal': 'El tr\u00e1fico coincide estrechamente con su l\u00ednea base. No se requiere acci\u00f3n.',
    'overview.band_desc_review': 'Algunas desviaciones detectadas. Vale la pena echar un vistazo.',
    'overview.band_desc_investigate': 'Desviaciones notables. Revise las conexiones inesperadas.',
    'overview.band_desc_critical': 'Desviaciones significativas. Investigue de inmediato.',
    'overview.new_conn_single': 'nueva conexi\u00f3n inesperada',
    'overview.new_conn_plural': 'nuevas conexiones inesperadas',
    'overview.new_conn_note_none': 'Sin actividad desconocida \u2014 todo el tr\u00e1fico actual se vio durante el entrenamiento.',
    'overview.new_conn_note_some': 'Estas conexiones no estaban presentes durante el entrenamiento de l\u00ednea base.',
    'overview.new_conn_note_investigate': 'Este es el principal factor de su puntuaci\u00f3n \u2014 investigue.',
    'overview.new_conn_note_review': 'Verifique que sean esperadas.',
    'overview.missing_conn_single': 'conexi\u00f3n de l\u00ednea base inactiva ahora',
    'overview.missing_conn_plural': 'conexiones de l\u00ednea base inactivas ahora',
    'overview.missing_conn_note': 'Conexiones vistas durante el entrenamiento que ahora est\u00e1n silenciosas. Esto es normalmente normal \u2014 los dispositivos no mantienen todas las conexiones en todo momento.',
    'overview.missing_conn_note_high': 'El recuento es muy alto, pero su l\u00ednea base probablemente captur\u00f3 muchos flujos de corta duraci\u00f3n durante un largo per\u00edodo de entrenamiento.',
    'overview.both_conn_single': 'conexi\u00f3n coincide con la l\u00ednea base',
    'overview.both_conn_plural': 'conexiones coinciden con la l\u00ednea base',
    'overview.both_conn_note_some': 'Estas conexiones est\u00e1n activas y se vieron durante el entrenamiento \u2014 su tr\u00e1fico normal esperado.',
    'overview.both_conn_note_none': 'A\u00fan no se han visto conexiones activas en la l\u00ednea base.',
    'overview.biggest_traffic_change': '\u0394 Mayor cambio de tr\u00e1fico',
    'overview.traffic_change_pre': 'Esta conexi\u00f3n conocida est\u00e1',
    'overview.traffic_change_mid': 'que de costumbre',
    'overview.traffic_change_post': 'flujos/snapshot).',
    'overview.traffic_change_file_hint': 'Podr\u00eda ser una transferencia de archivos, copia de seguridad o actualizaci\u00f3n en progreso.',
    'overview.traffic_far_busier': 'mucho m\u00e1s activo',
    'overview.traffic_noticeably_busier': 'notablemente m\u00e1s activo',
    'overview.traffic_somewhat_busier': 'algo m\u00e1s activo',
    'overview.traffic_slightly_busier': 'ligeramente m\u00e1s activo',
    'overview.traffic_far_quieter': 'mucho m\u00e1s tranquilo',
    'overview.traffic_noticeably_quieter': 'notablemente m\u00e1s tranquilo',
    'overview.traffic_somewhat_quieter': 'algo m\u00e1s tranquilo',
    'overview.traffic_slightly_quieter': 'ligeramente m\u00e1s tranquilo',
    'overview.view_map_btn': 'Ver en mapa de red \u2192',
  },
  it: {
    'view.overview': 'Panoramica',
    'view.map': 'Mappa di rete',
    'view.hosts': 'Host',
    'view.findings': 'Rilevamenti',
    'view.external': 'IP esterni',
    'view.vulnerabilities': 'Vulnerabilit\u00e0',
    'view.statistics': 'Statistiche',
    'view.dns': 'Query DNS',
    'view.suricata': 'Avvisi Suricata',
    'view.recommendations': 'Raccomandazioni',
    'view.settings': 'Impostazioni',
    'page.overview': 'Panoramica',
    'page.findings': 'Rilevamenti',
    'page.statistics': 'Statistiche',
    'page.dns_queries': 'Query DNS',
    'page.suricata_alerts': 'Avvisi Suricata',
    'app.title': 'Security Assistant',
    'settings.title': 'Impostazioni',
    'settings.subtitle': 'Le modifiche hanno effetto dopo il ricaricamento dell\u2019integrazione.',
    'settings.loading': 'Caricamento impostazioni\u2026',
    'settings.loading_short': 'Caricamento\u2026',
    'settings.links': 'Link',
    'settings.project': 'Progetto',
    'settings.github_repo': 'Repository GitHub',
    'settings.documentation': 'Documentazione',
    'settings.open_documentation': 'Apri documentazione',
    'settings.unsaved': 'Hai modifiche non salvate.',
    'settings.save': 'Salva impostazioni',
    'settings.reload_server': 'Ricarica dal server',
    'settings.failed_load': 'Errore nel caricamento delle impostazioni: ',
    'settings.failed_save': 'Errore nel salvataggio delle impostazioni: ',
    'settings.saved_reload': 'Impostazioni salvate. L\u2019integrazione verr\u00e0 ricaricata per applicare le modifiche.',
    'settings.unsaved_title': 'Modifiche non salvate',
    'settings.unsaved_body': 'Hai modifiche alle impostazioni non salvate. Se esci ora, andranno perse.',
    'settings.stay': 'Resta nelle impostazioni',
    'settings.discard_leave': 'Ignora ed esci',
    'settings.beforeunload': 'Hai modifiche non salvate nelle impostazioni. Uscire e ignorarle?',
    'sidebar.tagline': 'Telemetria di rete di sicurezza con contesto di flusso in tempo reale',
    'sidebar.collector_active': 'Collector attivo',
    'sidebar.awaiting_flows': 'In attesa di flussi',
    // \u2500\u2500 Overview page \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    'overview.active_findings': 'Rilevamenti attivi',
    'overview.active_cves': 'CVE attivi',
    'overview.dismissed': 'ignorato/i',
    'overview.never_fetched': 'mai recuperato',
    'overview.never': 'mai',
    'overview.stat_devices': 'Dispositivi',
    'overview.stat_scanned': 'Scansionati',
    'overview.stat_nvd_cves': 'CVE NVD',
    'overview.stat_cisa_kev': 'CISA KEV',
    'overview.stat_flows': 'Flussi',
    'overview.stat_exporters': 'Esportatori',
    'overview.stat_suricata_alerts': 'Avvisi Suricata',
    'overview.stat_critical_alerts': 'Avvisi critici',
    // Baseline
    'overview.baseline_learning': 'Apprendimento',
    'overview.baseline_active': 'Attivo',
    'overview.baseline_disabled': 'Disabilitato',
    'overview.elapsed': 'Trascorso',
    'overview.progress': 'Avanzamento',
    'overview.btn_start_training': 'Avvia addestramento',
    'overview.btn_stop_training': 'Ferma addestramento',
    'overview.btn_retrain': 'Riaddestrare',
    'overview.btn_clear': 'Cancella',
    'overview.baseline_title': 'Baseline',
    'overview.mode_label': 'Modalit\u00e0',
    'overview.baseline_created_label': 'Baseline creata',
    // NetFlow
    'overview.netflow_title': 'Stato collector NetFlow',
    'overview.status_label': 'Stato',
    'overview.no_flows_seen': 'Nessun flusso ricevuto',
    'overview.receiving_flows': 'Ricezione flussi',
    'overview.no_flows_idle_prefix': 'Nessun flusso (inattivo ',
    'overview.uptime_label': 'Tempo di attivit\u00e0',
    'overview.exporters_label': 'Esportatori',
    'overview.flow_versions': 'Versioni flusso',
    'overview.total_datagrams': 'Datagrammi totali',
    'overview.parsed': 'Analizzati',
    'overview.dropped': 'Scartati',
    'overview.last_flow': 'Ultimo flusso',
    'overview.last_error': 'Ultimo errore',
    'overview.view_statistics': 'Vedi statistiche \u2192',
    // Recent Alerts
    'overview.recent_alerts': 'Avvisi recenti',
    'overview.no_active_findings': 'Nessun rilevamento attivo alto/critico',
    'overview.view_all_findings': 'Vedi tutti i rilevamenti \u2192',
    // Active Scan
    'overview.active_scan_title': 'Scansione attiva',
    'overview.last_scan': 'Ultima scansione',
    'overview.last_result': 'Ultimo risultato',
    'overview.duration': 'Durata',
    'overview.hosts_found': 'Host trovati',
    'overview.targets_scanned': 'Obiettivi scansionati',
    'overview.scan_interval': 'Intervallo di scansione',
    'overview.scan_completed': 'Completato',
    'overview.scan_skipped': 'Saltato \u2014 nessun obiettivo scoperto',
    'overview.force_scan_btn': 'Forza scansione \u21bb',
    // NVD
    'overview.nvd_title': 'Intelligence vulnerabilit\u00e0 (NVD)',
    'overview.last_db_fetch': 'Ultimo aggiornamento DB',
    'overview.cache_ttl': 'TTL cache',
    'overview.cves_in_db': 'CVE nel DB',
    'overview.min_pub_year': 'Anno di pubblicazione minimo',
    'overview.all_years': 'Tutti gli anni',
    'overview.keywords_label': 'Parole chiave',
    'overview.none_loaded': 'Nessuna caricata',
    'overview.kw_configured': 'Configurate',
    'overview.kw_from_scans': 'Dalle scansioni',
    'overview.browse_vulns_btn': 'Sfoglia vulnerabilit\u00e0 \u2192',
    'overview.force_nvd_refresh_btn': 'Forza aggiornamento NVD \u21bb',
    // KEV
    'overview.kev_title': 'Vulnerabilit\u00e0 note sfruttate CISA (KEV)',
    'overview.last_catalog_fetch': 'Ultimo recupero catalogo',
    'overview.catalog_size': 'Dimensione catalogo',
    // DNS Proxy
    'overview.dns_domains': 'domini',
    'overview.dns_blocked_suffix': 'bloccati',
    'overview.dns_bl_empty': '0 voci \u2014 verificare gli URL',
    'overview.dns_bl_downloading': 'Scaricamento\u2026',
    'overview.dns_proxy_title': 'Proxy DNS',
    'overview.dns_running': 'In esecuzione',
    'overview.port_label': 'Porta',
    'overview.upstream_label': 'Server upstream',
    'overview.blocklist_label': 'Lista di blocco',
    'overview.last_refreshed': 'Ultimo aggiornamento',
    'overview.queries_in_log': 'Query nel registro',
    'overview.malicious_queries': 'Query dannose',
    'overview.blocked_queries': 'Query bloccate',
    'overview.view_dns_btn': 'Vedi query DNS \u2192',
    // Suricata
    'overview.suricata_listener_title': 'Listener avvisi Suricata',
    'overview.suricata_active': 'Attivo',
    'overview.suricata_inactive': 'Inattivo',
    'overview.exporter_ips_label': 'IP esportatore/i',
    'overview.active_connections': 'Connessioni attive',
    'overview.alerts_in_log': 'Avvisi nel registro',
    'overview.critical_alerts_label': 'Avvisi critici',
    'overview.view_suricata_btn': 'Vedi avvisi Suricata \u2192',
    // Network Behaviour
    'overview.network_behaviour_title': 'Comportamento di rete',
    'overview.band_normal': 'Normale',
    'overview.band_review': 'Revisione',
    'overview.band_investigate': 'Indagare',
    'overview.band_critical': 'Critico',
    'overview.band_desc_normal': 'Il traffico corrisponde strettamente alla tua baseline. Nessuna azione necessaria.',
    'overview.band_desc_review': 'Alcune deviazioni rilevate. Vale la pena dare un\u2019occhiata.',
    'overview.band_desc_investigate': 'Deviazioni notevoli. Controlla le connessioni impreviste.',
    'overview.band_desc_critical': 'Deviazioni significative. Indagare immediatamente.',
    'overview.new_conn_single': 'nuova connessione inaspettata',
    'overview.new_conn_plural': 'nuove connessioni inaspettate',
    'overview.new_conn_note_none': 'Nessuna attivit\u00e0 sconosciuta \u2014 tutto il traffico attuale \u00e8 stato visto durante l\u2019addestramento.',
    'overview.new_conn_note_some': 'Queste connessioni non erano presenti durante l\u2019addestramento della baseline.',
    'overview.new_conn_note_investigate': 'Questo \u00e8 il principale fattore del tuo punteggio \u2014 indaga.',
    'overview.new_conn_note_review': 'Verifica che siano previste.',
    'overview.missing_conn_single': 'connessione baseline ora inattiva',
    'overview.missing_conn_plural': 'connessioni baseline ora inattive',
    'overview.missing_conn_note': 'Connessioni viste durante l\u2019addestramento che ora sono silenziose. Di solito \u00e8 normale \u2014 i dispositivi non mantengono tutte le connessioni in ogni momento.',
    'overview.missing_conn_note_high': 'Il conteggio \u00e8 molto alto, ma la tua baseline ha probabilmente catturato molti flussi di breve durata durante una lunga finestra di addestramento.',
    'overview.both_conn_single': 'connessione corrisponde alla baseline',
    'overview.both_conn_plural': 'connessioni corrispondono alla baseline',
    'overview.both_conn_note_some': 'Queste connessioni sono attive e sono state viste durante l\u2019addestramento \u2014 il tuo traffico normale atteso.',
    'overview.both_conn_note_none': 'Nessuna connessione attiva \u00e8 stata ancora vista nella baseline.',
    'overview.biggest_traffic_change': '\u0394 Maggiore variazione di traffico',
    'overview.traffic_change_pre': 'Questa connessione nota \u00e8',
    'overview.traffic_change_mid': 'del solito',
    'overview.traffic_change_post': 'flussi/snapshot).',
    'overview.traffic_change_file_hint': 'Potrebbe essere un trasferimento di file, un backup o un aggiornamento in corso.',
    'overview.traffic_far_busier': 'molto pi\u00f9 trafficata',
    'overview.traffic_noticeably_busier': 'notevolmente pi\u00f9 trafficata',
    'overview.traffic_somewhat_busier': 'un po\u2019 pi\u00f9 trafficata',
    'overview.traffic_slightly_busier': 'leggermente pi\u00f9 trafficata',
    'overview.traffic_far_quieter': 'molto pi\u00f9 silenziosa',
    'overview.traffic_noticeably_quieter': 'notevolmente pi\u00f9 silenziosa',
    'overview.traffic_somewhat_quieter': 'un po\u2019 pi\u00f9 silenziosa',
    'overview.traffic_slightly_quieter': 'leggermente pi\u00f9 silenziosa',
    'overview.view_map_btn': 'Vedi sulla mappa di rete \u2192',
  }
};

const _UI_I18N_EXTRA = {
  fr: {
    'common.allowed': 'Autorisé',
    'common.blocked': 'Bloqué',
    'common.rows': 'Lignes',
    'common.previous': 'Précédent',
    'common.next': 'Suivant',
    'common.search_enter': 'Rechercher + Entrée',
    'suricata.sev_critical': 'Critique',
    'suricata.sev_major': 'Majeur',
    'suricata.sev_minor': 'Mineur',
    'suricata.sev_unknown': 'Inconnu',
    'suricata.filter_placeholder': 'Filtrer par IP, signature…',
    'suricata.all_severities': 'Toutes les sévérités',
    'suricata.all_actions': 'Toutes les actions',
    'suricata.entries': 'entrées',
    'suricata.showing': 'Affichage',
    'suricata.col_time': 'Heure',
    'suricata.col_src_ip': 'IP source',
    'suricata.col_dest_ip': 'IP dest.',
    'suricata.col_proto': 'Proto',
    'suricata.col_signature': 'Signature',
    'suricata.col_category': 'Catégorie',
    'suricata.col_severity': 'Sévérité',
    'suricata.col_action': 'Action',
    'suricata.click_details': 'Cliquer pour les détails',
    'suricata.badge_blocked': '🚫 Bloqué',
    'suricata.badge_allowed': '✓ Autorisé',
    'suricata.critical_badge': 'critique',
    'suricata.detail_title': 'Détail de l’alerte',
    'suricata.alert_info': 'Informations sur l’alerte',
    'suricata.timestamp': 'Horodatage',
    'suricata.flow': 'Flux',
    'suricata.protocol': 'Protocole',
    'suricata.interface': 'Interface',
    'suricata.signature_id': 'ID signature',
    'suricata.source_host': 'Hôte source',
    'suricata.destination_host': 'Hôte destination',
    'suricata.host_info': 'Infos hôte',
    'common.close': 'Fermer'
  },
  de: {
    'common.allowed': 'Erlaubt',
    'common.blocked': 'Blockiert',
    'common.rows': 'Zeilen',
    'common.previous': 'Zurück',
    'common.next': 'Weiter',
    'common.search_enter': 'Suchen + Enter',
    'suricata.sev_critical': 'Kritisch',
    'suricata.sev_major': 'Hoch',
    'suricata.sev_minor': 'Niedrig',
    'suricata.sev_unknown': 'Unbekannt',
    'suricata.filter_placeholder': 'Nach IP, Signatur filtern…',
    'suricata.all_severities': 'Alle Schweregrade',
    'suricata.all_actions': 'Alle Aktionen',
    'suricata.entries': 'Einträge',
    'suricata.showing': 'Anzeige',
    'suricata.col_time': 'Zeit',
    'suricata.col_src_ip': 'Quell-IP',
    'suricata.col_dest_ip': 'Ziel-IP',
    'suricata.col_proto': 'Proto',
    'suricata.col_signature': 'Signatur',
    'suricata.col_category': 'Kategorie',
    'suricata.col_severity': 'Schweregrad',
    'suricata.col_action': 'Aktion',
    'suricata.click_details': 'Für Details klicken',
    'suricata.badge_blocked': '🚫 Blockiert',
    'suricata.badge_allowed': '✓ Erlaubt',
    'suricata.critical_badge': 'kritisch',
    'suricata.detail_title': 'Alarmdetails',
    'suricata.alert_info': 'Alarminfo',
    'suricata.timestamp': 'Zeitstempel',
    'suricata.flow': 'Flow',
    'suricata.protocol': 'Protokoll',
    'suricata.interface': 'Schnittstelle',
    'suricata.signature_id': 'Signatur-ID',
    'suricata.source_host': 'Quellhost',
    'suricata.destination_host': 'Zielhost',
    'suricata.host_info': 'Host-Infos',
    'common.close': 'Schließen'
  },
  es: {
    'common.allowed': 'Permitido',
    'common.blocked': 'Bloqueado',
    'common.rows': 'Filas',
    'common.previous': 'Anterior',
    'common.next': 'Siguiente',
    'common.search_enter': 'Buscar + Enter',
    'suricata.sev_critical': 'Crítico',
    'suricata.sev_major': 'Alto',
    'suricata.sev_minor': 'Menor',
    'suricata.sev_unknown': 'Desconocido',
    'suricata.filter_placeholder': 'Filtrar por IP, firma…',
    'suricata.all_severities': 'Todas las severidades',
    'suricata.all_actions': 'Todas las acciones',
    'suricata.entries': 'entradas',
    'suricata.showing': 'Mostrando',
    'suricata.col_time': 'Hora',
    'suricata.col_src_ip': 'IP origen',
    'suricata.col_dest_ip': 'IP destino',
    'suricata.col_proto': 'Proto',
    'suricata.col_signature': 'Firma',
    'suricata.col_category': 'Categoría',
    'suricata.col_severity': 'Severidad',
    'suricata.col_action': 'Acción',
    'suricata.click_details': 'Haz clic para ver detalles',
    'suricata.badge_blocked': '🚫 Bloqueado',
    'suricata.badge_allowed': '✓ Permitido',
    'suricata.critical_badge': 'crítico',
    'suricata.detail_title': 'Detalle de alerta',
    'suricata.alert_info': 'Información de alerta',
    'suricata.timestamp': 'Marca de tiempo',
    'suricata.flow': 'Flujo',
    'suricata.protocol': 'Protocolo',
    'suricata.interface': 'Interfaz',
    'suricata.signature_id': 'ID de firma',
    'suricata.source_host': 'Host origen',
    'suricata.destination_host': 'Host destino',
    'suricata.host_info': 'Info del host',
    'common.close': 'Cerrar'
  },
  it: {
    'common.allowed': 'Consentito',
    'common.blocked': 'Bloccato',
    'common.rows': 'Righe',
    'common.previous': 'Precedente',
    'common.next': 'Successivo',
    'common.search_enter': 'Cerca + Invio',
    'suricata.sev_critical': 'Critico',
    'suricata.sev_major': 'Alto',
    'suricata.sev_minor': 'Minore',
    'suricata.sev_unknown': 'Sconosciuto',
    'suricata.filter_placeholder': 'Filtra per IP, firma…',
    'suricata.all_severities': 'Tutte le gravità',
    'suricata.all_actions': 'Tutte le azioni',
    'suricata.entries': 'voci',
    'suricata.showing': 'Visualizzazione',
    'suricata.col_time': 'Ora',
    'suricata.col_src_ip': 'IP sorgente',
    'suricata.col_dest_ip': 'IP destinazione',
    'suricata.col_proto': 'Proto',
    'suricata.col_signature': 'Firma',
    'suricata.col_category': 'Categoria',
    'suricata.col_severity': 'Gravità',
    'suricata.col_action': 'Azione',
    'suricata.click_details': 'Fai clic per i dettagli',
    'suricata.badge_blocked': '🚫 Bloccato',
    'suricata.badge_allowed': '✓ Consentito',
    'suricata.critical_badge': 'critico',
    'suricata.detail_title': 'Dettaglio avviso',
    'suricata.alert_info': 'Informazioni avviso',
    'suricata.timestamp': 'Timestamp',
    'suricata.flow': 'Flusso',
    'suricata.protocol': 'Protocollo',
    'suricata.interface': 'Interfaccia',
    'suricata.signature_id': 'ID firma',
    'suricata.source_host': 'Host sorgente',
    'suricata.destination_host': 'Host destinazione',
    'suricata.host_info': 'Info host',
    'common.close': 'Chiudi'
  }
};

Object.keys(_UI_I18N_EXTRA).forEach(function(locale) {
  Object.assign(_UI_I18N[locale], _UI_I18N_EXTRA[locale]);
});

const _UI_I18N_EXTRA_2 = {
  fr: {
    'map.disabled': 'Le collecteur NetFlow est désactivé.',
    'map.enable_in': 'Activez-le dans',
    'map.to_use': 'pour utiliser la carte réseau.',
    'map.filter_all': 'Tous',
    'map.filter_scanned': 'Scannés',
    'map.filter_flow_only': 'Flux seuls',
    'map.filter_external': 'Externes',
    'map.mode_live': 'Live',
    'map.mode_baseline': 'Baseline',
    'map.mode_compare': 'Comparer',
    'map.label_baseline_snapshot': 'Instantané de référence',
    'map.label_live_vs_baseline': 'Temps réel vs référence',
    'map.label_live_network': 'Carte réseau en direct',
    'map.baseline_chip': 'Référence',
    'map.hosts': 'hôtes',
    'map.edges': 'liaisons',
    'map.compare': 'Comparer :',
    'map.new_edge_one': 'nouvelle liaison',
    'map.new_edge_many': 'nouvelles liaisons',
    'map.missing_edge_one': 'liaison manquante',
    'map.missing_edge_many': 'liaisons manquantes',
    'map.unchanged': 'inchangées',
    'map.strongest': 'Δ le plus fort :',
    'map.reset': '↺ Réinitialiser',
    'map.legend_scanned': 'Scanné',
    'map.legend_flow_only': 'Flux seul',
    'map.legend_baseline_edge': 'Liaison de référence',
    'map.legend_missing': 'Manquante',
    'map.legend_new': 'Nouvelle',
    'map.legend_at_risk': 'À risque',
    'map.legend_gateway': 'Passerelle',
    'map.legend_external': 'Externe',
    'map.legend_multicast': 'Multicast',
    'map.at_risk': 'À risque',
    'map.multicast_note': 'Multicast · non routé sur Internet',
    'map.sources': 'Sources',
    'map.click_full_lookup': 'Cliquer pour la recherche complète',
    'map.baseline_presence': 'Présence de référence',
    'map.live_load': 'Indice de charge live',
    'hosts.page_title': 'Hôtes réseau',
    'hosts.alive_suffix': 'actifs',
    'hosts.filter_placeholder': 'Filtrer par IP, nom, rôle…',
    'hosts.no_match': 'Aucun hôte ne correspond au filtre',
    'hosts.col_name': 'Nom',
    'hosts.col_role': 'Rôle',
    'hosts.col_open_ports': 'Ports ouverts',
    'hosts.col_traffic': 'Trafic',
    'hosts.rename': 'Renommer',
    'hosts.manual': '(manuel)',
    'hosts.section_open_ports': 'Ports ouverts',
    'hosts.section_vulnerabilities': 'Vulnérabilités',
    'hosts.no_vulnerabilities': 'Aucune vulnérabilité détectée',
    'hosts.port': 'Port',
    'hosts.service': 'Service',
    'hosts.banner': 'Banner',
    'hosts.version': 'Version',
    'hosts.technologies': 'Technologies',
    'hosts.fix': 'Correctif',
    'hosts.note': 'Note',
    'hosts.kv_hostname': 'Nom d’hôte',
    'hosts.kv_manufacturer': 'Fabricant',
    'hosts.kv_flows': 'Flux',
    'hosts.kv_external_peers': 'Pairs externes',
    'hosts.kv_last_seen': 'Dernière vue',
    'external.page_title': 'IP externes',
    'external.filter_placeholder': 'Filtrer par IP, nom d’hôte, pays, org…',
    'external.col_hostname': 'Nom d’hôte',
    'external.col_traffic_kb': 'Trafic (KB)',
    'external.col_country': 'Pays',
    'external.col_asn_org': 'ASN / Org',
    'external.col_rating': 'Évaluation',
    'external.col_vt_hits': 'Hits VT',
    'external.col_abuse': 'Abus %',
    'external.col_ports': 'Ports',
    'external.col_direction': 'Direction',
    'external.col_internal_host': 'Hôte interne',
    'external.col_last_seen': 'Dernière vue',
    'external.showing': 'Affichage',
    'external.no_match': 'Aucune IP externe ne correspond au filtre',
    'external.direction_both': '↕ Bidirectionnel',
    'external.direction_inbound': '↓ Entrant',
    'external.direction_outbound': '↑ Sortant',
    'external.running_lookup': 'Recherche d’enrichissement en cours…',
    'external.enrichment_details': 'Détails d’enrichissement',
    'external.run_full_lookup': '🔍 Lancer une recherche complète',
    'external.ip_info': 'Infos IP',
    'external.traffic': 'Trafic',
    'external.blacklisted': 'Blacklistée',
    'external.ports_contacted': 'Ports contactés',
    'external.internal_hosts': 'Hôtes internes',
    'external.total_traffic': 'Trafic total',
    'vuln.page_title': 'Navigateur de vulnérabilités',
    'vuln.loading': 'Chargement des vulnérabilités…',
    'vuln.search_placeholder': 'Rechercher CVE, port, service, CPE, mot-clé…',
    'vuln.refresh': '↻ Actualiser',
    'vuln.stat_cves_db': 'CVE dans la base',
    'vuln.stat_detected_network': 'détectées sur le réseau',
    'vuln.stat_in_kev': 'dans le KEV CISA',
    'vuln.stat_matching': 'résultats correspondants',
    'vuln.col_cve_id': 'ID CVE',
    'vuln.col_published': 'Publication',
    'vuln.col_cvss': 'CVSS',
    'vuln.col_severity': 'Sévérité',
    'vuln.col_services': 'Services',
    'vuln.col_ports': 'Ports',
    'vuln.col_hosts': 'Hôtes',
    'vuln.col_kev': 'KEV',
    'vuln.col_summary': 'Résumé',
    'vuln.not_detected': 'non détectée',
    'vuln.prev': '◀ Préc.',
    'vuln.page': 'Page',
    'vuln.of': 'sur',
    'vuln.next': 'Suiv. ▶',
    'vuln.not_detected_network': 'Non détectée sur ce réseau',
    'vuln.kev_title': 'Vulnérabilité exploitée connue par la CISA',
    'vuln.name': 'Nom',
    'vuln.product': 'Produit',
    'vuln.added_to_kev': 'Ajoutée au KEV',
    'vuln.required_action': 'Action requise',
    'vuln.summary_title': 'Résumé',
    'vuln.affected_hosts': 'Hôtes affectés',
    'vuln.cpe_criteria': 'Critères CPE',
    'vuln.view_on_nvd': 'Voir sur NVD',
    'vuln.cve_details': 'Détails CVE',
    'vuln.no_description': 'Aucune description disponible.',
    'dns.filter_placeholder': 'Filtrer par IP ou domaine…',
    'dns.all_categories': 'Toutes les catégories',
    'dns.all_status': 'Tous les statuts',
    'dns.malicious_only': 'Malveillant uniquement',
    'dns.showing': 'Affichage',
    'dns.malicious_badge': 'malveillant',
    'dns.col_time': 'Heure',
    'dns.col_client_ip': 'IP client',
    'dns.col_domain': 'Domaine',
    'dns.col_type': 'Type',
    'dns.col_category': 'Catégorie',
    'dns.col_response': 'Réponse',
    'dns.col_answer': 'Réponse DNS',
    'dns.col_status': 'Statut',
    'dns.entries': 'entrées',
    'dns.cat.override': 'Override',
    'recs.page_title': 'Recommandations de sécurité',
    'recs.no_recommendations': 'Aucune recommandation pour le moment.',
    'recs.affected_hosts': 'Hôtes affectés',
    'recs.related_findings': 'Résultats liés'
  },
  de: {
    'map.disabled': 'Der NetFlow-Listener ist deaktiviert.',
    'map.enable_in': 'Aktiviere ihn in',
    'map.to_use': 'um die Netzwerkkarte zu verwenden.',
    'map.filter_all': 'Alle', 'map.filter_scanned': 'Gescannt', 'map.filter_flow_only': 'Nur Flows', 'map.filter_external': 'Extern',
    'map.mode_live': 'Live', 'map.mode_baseline': 'Baseline', 'map.mode_compare': 'Vergleich',
    'map.label_baseline_snapshot': 'Baseline-Snapshot', 'map.label_live_vs_baseline': 'Live vs. Baseline', 'map.label_live_network': 'Live-Netzwerkkarte',
    'map.baseline_chip': 'Baseline', 'map.hosts': 'Hosts', 'map.edges': 'Kanten', 'map.compare': 'Vergleich:',
    'map.new_edge_one': 'neue Kante', 'map.new_edge_many': 'neue Kanten', 'map.missing_edge_one': 'fehlende Kante', 'map.missing_edge_many': 'fehlende Kanten', 'map.unchanged': 'unverändert', 'map.strongest': 'Δ stärkste:', 'map.reset': '↺ Zurücksetzen',
    'map.legend_scanned': 'Gescannt', 'map.legend_flow_only': 'Nur Flow', 'map.legend_baseline_edge': 'Baseline-Kante', 'map.legend_missing': 'Fehlend', 'map.legend_new': 'Neu', 'map.legend_at_risk': 'Gefährdet', 'map.legend_gateway': 'Gateway', 'map.legend_external': 'Extern', 'map.legend_multicast': 'Multicast',
    'map.at_risk': 'Gefährdet', 'map.multicast_note': 'Multicast · nicht internetgeroutet', 'map.sources': 'Quellen', 'map.click_full_lookup': 'Für vollständige Abfrage klicken', 'map.baseline_presence': 'Baseline-Präsenz', 'map.live_load': 'Live-Lastindex',
    'hosts.page_title': 'Netzwerk-Hosts', 'hosts.alive_suffix': 'aktiv', 'hosts.filter_placeholder': 'Nach IP, Name, Rolle filtern…', 'hosts.no_match': 'Keine Hosts entsprechen dem Filter', 'hosts.col_name': 'Name', 'hosts.col_role': 'Rolle', 'hosts.col_open_ports': 'Offene Ports', 'hosts.col_traffic': 'Traffic', 'hosts.rename': 'Umbenennen', 'hosts.manual': '(manuell)', 'hosts.section_open_ports': 'Offene Ports', 'hosts.section_vulnerabilities': 'Schwachstellen', 'hosts.no_vulnerabilities': 'Keine Schwachstellen erkannt', 'hosts.port': 'Port', 'hosts.service': 'Dienst', 'hosts.banner': 'Banner', 'hosts.version': 'Version', 'hosts.technologies': 'Technologien', 'hosts.fix': 'Fix', 'hosts.note': 'Notiz', 'hosts.kv_hostname': 'Hostname', 'hosts.kv_manufacturer': 'Hersteller', 'hosts.kv_flows': 'Flows', 'hosts.kv_external_peers': 'Externe Peers', 'hosts.kv_last_seen': 'Zuletzt gesehen',
    'external.page_title': 'Externe IPs', 'external.filter_placeholder': 'Nach IP, Hostname, Land, Org filtern…', 'external.col_hostname': 'Hostname', 'external.col_traffic_kb': 'Traffic (KB)', 'external.col_country': 'Land', 'external.col_asn_org': 'ASN / Org', 'external.col_rating': 'Bewertung', 'external.col_vt_hits': 'VT-Treffer', 'external.col_abuse': 'Missbrauch %', 'external.col_ports': 'Ports', 'external.col_direction': 'Richtung', 'external.col_internal_host': 'Interner Host', 'external.col_last_seen': 'Zuletzt gesehen', 'external.showing': 'Anzeige', 'external.no_match': 'Keine externen IPs entsprechen dem Filter', 'external.direction_both': '↕ Beide', 'external.direction_inbound': '↓ Eingehend', 'external.direction_outbound': '↑ Ausgehend', 'external.running_lookup': 'Enrichment-Abfrage läuft…', 'external.enrichment_details': 'Enrichment-Details', 'external.run_full_lookup': '🔍 Vollständige Abfrage ausführen', 'external.ip_info': 'IP-Info', 'external.traffic': 'Traffic', 'external.blacklisted': 'Blacklisted', 'external.ports_contacted': 'Kontaktierte Ports', 'external.internal_hosts': 'Interne Hosts', 'external.total_traffic': 'Gesamtverkehr',
    'vuln.page_title': 'Schwachstellen-Browser', 'vuln.loading': 'Schwachstellen werden geladen…', 'vuln.search_placeholder': 'Suche nach CVE, Port, Dienst, CPE, Stichwort…', 'vuln.refresh': '↻ Aktualisieren', 'vuln.stat_cves_db': 'CVEs in Datenbank', 'vuln.stat_detected_network': 'im Netzwerk erkannt', 'vuln.stat_in_kev': 'im CISA KEV', 'vuln.stat_matching': 'passende Ergebnisse', 'vuln.col_cve_id': 'CVE-ID', 'vuln.col_published': 'Veröffentlicht', 'vuln.col_cvss': 'CVSS', 'vuln.col_severity': 'Schweregrad', 'vuln.col_services': 'Dienste', 'vuln.col_ports': 'Ports', 'vuln.col_hosts': 'Hosts', 'vuln.col_kev': 'KEV', 'vuln.col_summary': 'Zusammenfassung', 'vuln.not_detected': 'nicht erkannt', 'vuln.prev': '◀ Zurück', 'vuln.page': 'Seite', 'vuln.of': 'von', 'vuln.next': 'Weiter ▶', 'vuln.not_detected_network': 'In diesem Netzwerk nicht erkannt', 'vuln.kev_title': 'CISA Known Exploited Vulnerability', 'vuln.name': 'Name', 'vuln.product': 'Produkt', 'vuln.added_to_kev': 'Zum KEV hinzugefügt', 'vuln.required_action': 'Erforderliche Aktion', 'vuln.summary_title': 'Zusammenfassung', 'vuln.affected_hosts': 'Betroffene Hosts', 'vuln.cpe_criteria': 'CPE-Kriterien', 'vuln.view_on_nvd': 'Auf NVD ansehen', 'vuln.cve_details': 'CVE-Details', 'vuln.no_description': 'Keine Beschreibung verfügbar.',
    'dns.filter_placeholder': 'Nach IP oder Domain filtern…', 'dns.all_categories': 'Alle Kategorien', 'dns.all_status': 'Alle Status', 'dns.malicious_only': 'Nur bösartig', 'dns.showing': 'Anzeige', 'dns.malicious_badge': 'bösartig', 'dns.col_time': 'Zeit', 'dns.col_client_ip': 'Client-IP', 'dns.col_domain': 'Domain', 'dns.col_type': 'Typ', 'dns.col_category': 'Kategorie', 'dns.col_response': 'Antwortcode', 'dns.col_answer': 'Antwort', 'dns.col_status': 'Status', 'dns.entries': 'Einträge', 'dns.cat.override': 'Override',
    'recs.page_title': 'Sicherheitsempfehlungen', 'recs.no_recommendations': 'Derzeit keine Empfehlungen.', 'recs.affected_hosts': 'Betroffene Hosts', 'recs.related_findings': 'Zugehörige Befunde'
  },
  es: {
    'map.disabled': 'El receptor NetFlow está deshabilitado.', 'map.enable_in': 'Actívalo en', 'map.to_use': 'para usar el mapa de red.', 'map.filter_all': 'Todo', 'map.filter_scanned': 'Escaneados', 'map.filter_flow_only': 'Solo flujo', 'map.filter_external': 'Externos', 'map.mode_live': 'Live', 'map.mode_baseline': 'Línea base', 'map.mode_compare': 'Comparar', 'map.label_baseline_snapshot': 'Instantánea de línea base', 'map.label_live_vs_baseline': 'En vivo vs línea base', 'map.label_live_network': 'Mapa de red en vivo', 'map.baseline_chip': 'Línea base', 'map.hosts': 'hosts', 'map.edges': 'enlaces', 'map.compare': 'Comparar:', 'map.new_edge_one': 'nuevo enlace', 'map.new_edge_many': 'nuevos enlaces', 'map.missing_edge_one': 'enlace faltante', 'map.missing_edge_many': 'enlaces faltantes', 'map.unchanged': 'sin cambios', 'map.strongest': 'Δ más fuerte:', 'map.reset': '↺ Restablecer', 'map.legend_scanned': 'Escaneado', 'map.legend_flow_only': 'Solo flujo', 'map.legend_baseline_edge': 'Enlace de línea base', 'map.legend_missing': 'Faltante', 'map.legend_new': 'Nuevo', 'map.legend_at_risk': 'En riesgo', 'map.legend_gateway': 'Puerta de enlace', 'map.legend_external': 'Externo', 'map.legend_multicast': 'Multicast', 'map.at_risk': 'En riesgo', 'map.multicast_note': 'Multicast · no enrutable por Internet', 'map.sources': 'Orígenes', 'map.click_full_lookup': 'Haz clic para la consulta completa', 'map.baseline_presence': 'Presencia en línea base', 'map.live_load': 'Índice de carga live',
    'hosts.page_title': 'Hosts de red', 'hosts.alive_suffix': 'activos', 'hosts.filter_placeholder': 'Filtrar por IP, nombre, rol…', 'hosts.no_match': 'Ningún host coincide con el filtro', 'hosts.col_name': 'Nombre', 'hosts.col_role': 'Rol', 'hosts.col_open_ports': 'Puertos abiertos', 'hosts.col_traffic': 'Tráfico', 'hosts.rename': 'Renombrar', 'hosts.manual': '(manual)', 'hosts.section_open_ports': 'Puertos abiertos', 'hosts.section_vulnerabilities': 'Vulnerabilidades', 'hosts.no_vulnerabilities': 'No se detectaron vulnerabilidades', 'hosts.port': 'Puerto', 'hosts.service': 'Servicio', 'hosts.banner': 'Banner', 'hosts.version': 'Versión', 'hosts.technologies': 'Tecnologías', 'hosts.fix': 'Corrección', 'hosts.note': 'Nota', 'hosts.kv_hostname': 'Hostname', 'hosts.kv_manufacturer': 'Fabricante', 'hosts.kv_flows': 'Flujos', 'hosts.kv_external_peers': 'Pares externos', 'hosts.kv_last_seen': 'Última vez visto',
    'external.page_title': 'IPs externas', 'external.filter_placeholder': 'Filtrar por IP, hostname, país, org…', 'external.col_hostname': 'Hostname', 'external.col_traffic_kb': 'Tráfico (KB)', 'external.col_country': 'País', 'external.col_asn_org': 'ASN / Org', 'external.col_rating': 'Clasificación', 'external.col_vt_hits': 'Aciertos VT', 'external.col_abuse': 'Abuso %', 'external.col_ports': 'Puertos', 'external.col_direction': 'Dirección', 'external.col_internal_host': 'Host interno', 'external.col_last_seen': 'Última vez visto', 'external.showing': 'Mostrando', 'external.no_match': 'Ninguna IP externa coincide con el filtro', 'external.direction_both': '↕ Ambas', 'external.direction_inbound': '↓ Entrante', 'external.direction_outbound': '↑ Saliente', 'external.running_lookup': 'Ejecutando búsqueda de enriquecimiento…', 'external.enrichment_details': 'Detalles de enriquecimiento', 'external.run_full_lookup': '🔍 Ejecutar búsqueda completa', 'external.ip_info': 'Información IP', 'external.traffic': 'Tráfico', 'external.blacklisted': 'En lista negra', 'external.ports_contacted': 'Puertos contactados', 'external.internal_hosts': 'Hosts internos', 'external.total_traffic': 'Tráfico total',
    'vuln.page_title': 'Explorador de vulnerabilidades', 'vuln.loading': 'Cargando vulnerabilidades…', 'vuln.search_placeholder': 'Buscar CVE, puerto, servicio, CPE, palabra clave…', 'vuln.refresh': '↻ Actualizar', 'vuln.stat_cves_db': 'CVEs en la base', 'vuln.stat_detected_network': 'detectadas en la red', 'vuln.stat_in_kev': 'en CISA KEV', 'vuln.stat_matching': 'resultados coincidentes', 'vuln.col_cve_id': 'ID CVE', 'vuln.col_published': 'Publicado', 'vuln.col_cvss': 'CVSS', 'vuln.col_severity': 'Severidad', 'vuln.col_services': 'Servicios', 'vuln.col_ports': 'Puertos', 'vuln.col_hosts': 'Hosts', 'vuln.col_kev': 'KEV', 'vuln.col_summary': 'Resumen', 'vuln.not_detected': 'no detectado', 'vuln.prev': '◀ Ant.', 'vuln.page': 'Página', 'vuln.of': 'de', 'vuln.next': 'Sig. ▶', 'vuln.not_detected_network': 'No detectado en esta red', 'vuln.kev_title': 'Vulnerabilidad explotada conocida por CISA', 'vuln.name': 'Nombre', 'vuln.product': 'Producto', 'vuln.added_to_kev': 'Añadido a KEV', 'vuln.required_action': 'Acción requerida', 'vuln.summary_title': 'Resumen', 'vuln.affected_hosts': 'Hosts afectados', 'vuln.cpe_criteria': 'Criterios CPE', 'vuln.view_on_nvd': 'Ver en NVD', 'vuln.cve_details': 'Detalles CVE', 'vuln.no_description': 'No hay descripción disponible.',
    'dns.filter_placeholder': 'Filtrar por IP o dominio…', 'dns.all_categories': 'Todas las categorías', 'dns.all_status': 'Todos los estados', 'dns.malicious_only': 'Solo malicioso', 'dns.showing': 'Mostrando', 'dns.malicious_badge': 'malicioso', 'dns.col_time': 'Hora', 'dns.col_client_ip': 'IP cliente', 'dns.col_domain': 'Dominio', 'dns.col_type': 'Tipo', 'dns.col_category': 'Categoría', 'dns.col_response': 'Respuesta', 'dns.col_answer': 'Respuesta DNS', 'dns.col_status': 'Estado', 'dns.entries': 'entradas', 'dns.cat.override': 'Override',
    'recs.page_title': 'Recomendaciones de seguridad', 'recs.no_recommendations': 'No hay recomendaciones en este momento.', 'recs.affected_hosts': 'Hosts afectados', 'recs.related_findings': 'Hallazgos relacionados'
  },
  it: {
    'map.disabled': 'Il listener NetFlow è disattivato.', 'map.enable_in': 'Attivalo in', 'map.to_use': 'per usare la mappa di rete.', 'map.filter_all': 'Tutto', 'map.filter_scanned': 'Scansionati', 'map.filter_flow_only': 'Solo flussi', 'map.filter_external': 'Esterni', 'map.mode_live': 'Live', 'map.mode_baseline': 'Baseline', 'map.mode_compare': 'Confronta', 'map.label_baseline_snapshot': 'Snapshot baseline', 'map.label_live_vs_baseline': 'Live vs baseline', 'map.label_live_network': 'Mappa rete live', 'map.baseline_chip': 'Baseline', 'map.hosts': 'host', 'map.edges': 'connessioni', 'map.compare': 'Confronta:', 'map.new_edge_one': 'nuova connessione', 'map.new_edge_many': 'nuove connessioni', 'map.missing_edge_one': 'connessione mancante', 'map.missing_edge_many': 'connessioni mancanti', 'map.unchanged': 'immutate', 'map.strongest': 'Δ più forte:', 'map.reset': '↺ Reimposta', 'map.legend_scanned': 'Scansionato', 'map.legend_flow_only': 'Solo flusso', 'map.legend_baseline_edge': 'Connessione baseline', 'map.legend_missing': 'Mancante', 'map.legend_new': 'Nuova', 'map.legend_at_risk': 'A rischio', 'map.legend_gateway': 'Gateway', 'map.legend_external': 'Esterno', 'map.legend_multicast': 'Multicast', 'map.at_risk': 'A rischio', 'map.multicast_note': 'Multicast · non instradato su Internet', 'map.sources': 'Sorgenti', 'map.click_full_lookup': 'Clicca per la ricerca completa', 'map.baseline_presence': 'Presenza baseline', 'map.live_load': 'Indice carico live',
    'hosts.page_title': 'Host di rete', 'hosts.alive_suffix': 'attivi', 'hosts.filter_placeholder': 'Filtra per IP, nome, ruolo…', 'hosts.no_match': 'Nessun host corrisponde al filtro', 'hosts.col_name': 'Nome', 'hosts.col_role': 'Ruolo', 'hosts.col_open_ports': 'Porte aperte', 'hosts.col_traffic': 'Traffico', 'hosts.rename': 'Rinomina', 'hosts.manual': '(manuale)', 'hosts.section_open_ports': 'Porte aperte', 'hosts.section_vulnerabilities': 'Vulnerabilità', 'hosts.no_vulnerabilities': 'Nessuna vulnerabilità rilevata', 'hosts.port': 'Porta', 'hosts.service': 'Servizio', 'hosts.banner': 'Banner', 'hosts.version': 'Versione', 'hosts.technologies': 'Tecnologie', 'hosts.fix': 'Correzione', 'hosts.note': 'Nota', 'hosts.kv_hostname': 'Hostname', 'hosts.kv_manufacturer': 'Produttore', 'hosts.kv_flows': 'Flussi', 'hosts.kv_external_peers': 'Peer esterni', 'hosts.kv_last_seen': 'Ultima vista',
    'external.page_title': 'IP esterni', 'external.filter_placeholder': 'Filtra per IP, hostname, paese, org…', 'external.col_hostname': 'Hostname', 'external.col_traffic_kb': 'Traffico (KB)', 'external.col_country': 'Paese', 'external.col_asn_org': 'ASN / Org', 'external.col_rating': 'Valutazione', 'external.col_vt_hits': 'Hit VT', 'external.col_abuse': 'Abuso %', 'external.col_ports': 'Porte', 'external.col_direction': 'Direzione', 'external.col_internal_host': 'Host interno', 'external.col_last_seen': 'Ultima vista', 'external.showing': 'Visualizzazione', 'external.no_match': 'Nessun IP esterno corrisponde al filtro', 'external.direction_both': '↕ Entrambe', 'external.direction_inbound': '↓ In entrata', 'external.direction_outbound': '↑ In uscita', 'external.running_lookup': 'Ricerca di arricchimento in corso…', 'external.enrichment_details': 'Dettagli arricchimento', 'external.run_full_lookup': '🔍 Esegui ricerca completa', 'external.ip_info': 'Info IP', 'external.traffic': 'Traffico', 'external.blacklisted': 'In blacklist', 'external.ports_contacted': 'Porte contattate', 'external.internal_hosts': 'Host interni', 'external.total_traffic': 'Traffico totale',
    'vuln.page_title': 'Browser vulnerabilità', 'vuln.loading': 'Caricamento vulnerabilità…', 'vuln.search_placeholder': 'Cerca CVE, porta, servizio, CPE, parola chiave…', 'vuln.refresh': '↻ Aggiorna', 'vuln.stat_cves_db': 'CVE nel database', 'vuln.stat_detected_network': 'rilevate sulla rete', 'vuln.stat_in_kev': 'nel CISA KEV', 'vuln.stat_matching': 'risultati corrispondenti', 'vuln.col_cve_id': 'ID CVE', 'vuln.col_published': 'Pubblicato', 'vuln.col_cvss': 'CVSS', 'vuln.col_severity': 'Gravità', 'vuln.col_services': 'Servizi', 'vuln.col_ports': 'Porte', 'vuln.col_hosts': 'Host', 'vuln.col_kev': 'KEV', 'vuln.col_summary': 'Riepilogo', 'vuln.not_detected': 'non rilevato', 'vuln.prev': '◀ Prec.', 'vuln.page': 'Pagina', 'vuln.of': 'di', 'vuln.next': 'Succ. ▶', 'vuln.not_detected_network': 'Non rilevato su questa rete', 'vuln.kev_title': 'Vulnerabilità nota sfruttata da CISA', 'vuln.name': 'Nome', 'vuln.product': 'Prodotto', 'vuln.added_to_kev': 'Aggiunta a KEV', 'vuln.required_action': 'Azione richiesta', 'vuln.summary_title': 'Riepilogo', 'vuln.affected_hosts': 'Host interessati', 'vuln.cpe_criteria': 'Criteri CPE', 'vuln.view_on_nvd': 'Vedi su NVD', 'vuln.cve_details': 'Dettagli CVE', 'vuln.no_description': 'Nessuna descrizione disponibile.',
    'dns.filter_placeholder': 'Filtra per IP o dominio…', 'dns.all_categories': 'Tutte le categorie', 'dns.all_status': 'Tutti gli stati', 'dns.malicious_only': 'Solo malevole', 'dns.showing': 'Visualizzazione', 'dns.malicious_badge': 'malevole', 'dns.col_time': 'Ora', 'dns.col_client_ip': 'IP client', 'dns.col_domain': 'Dominio', 'dns.col_type': 'Tipo', 'dns.col_category': 'Categoria', 'dns.col_response': 'Risposta', 'dns.col_answer': 'Risposta DNS', 'dns.col_status': 'Stato', 'dns.entries': 'voci', 'dns.cat.override': 'Override',
    'recs.page_title': 'Raccomandazioni di sicurezza', 'recs.no_recommendations': 'Nessuna raccomandazione al momento.', 'recs.affected_hosts': 'Host interessati', 'recs.related_findings': 'Rilevamenti correlati'
  }
};

Object.keys(_UI_I18N_EXTRA_2).forEach(function(locale) {
  Object.assign(_UI_I18N[locale], _UI_I18N_EXTRA_2[locale]);
});

const _UI_I18N_EXTRA_3 = {
  fr: {
    'time.just_now': 'à l’instant',
    'time.minutes_ago': 'il y a {n} min',
    'time.hours_ago': 'il y a {n} h',
    'time.days_ago': 'il y a {n} j',
    'recs.title_patch_vulnerable': 'Corriger les appareils vulnérables',
    'recs.detail_patch_vulnerable': '{n} appareil(s) ont des vulnérabilités CVE connues de niveau élevé ou critique. Mettez à jour le micrologiciel / logiciel ou limitez immédiatement l’accès réseau.',
    'recs.title_review_vulnerability_findings': 'Examiner les constats de vulnérabilité',
    'recs.detail_review_vulnerability_findings': 'L’analyse active a trouvé des services présentant des problèmes de sécurité connus. Consultez l’onglet des constats pour les détails CVE et les étapes de correction.',
    'recs.title_connect_exporter': 'Connecter un exporteur de flux',
    'recs.detail_connect_exporter': 'Aucun exporteur NetFlow ou IPFIX n’a encore été observé. Configurez votre passerelle, pare-feu ou commutateur pour exporter les flux vers HomeSec.',
    'recs.title_verify_exporter': 'Vérifier la connectivité de l’exporteur',
    'recs.detail_verify_exporter': 'Des exporteurs sont configurés, mais HomeSec n’a encore reçu aucun datagramme. Vérifiez l’IP / le port cible, les règles du pare-feu et le réseau du conteneur.',
    'recs.title_check_flow_format': 'Vérifier le format d’export des flux',
    'recs.detail_check_flow_format': 'Les datagrammes arrivent, mais aucun n’a produit d’enregistrements. Confirmez que l’exporteur utilise NetFlow v5/v9/IPFIX avec des champs IPv4 et des modèles valides.',
    'recs.title_restrict_risky_ports': 'Limiter les ports sortants risqués',
    'recs.detail_restrict_risky_ports': 'Au moins un appareil a contacté un port externe souvent abusé, comme Telnet ou RDP. Bloquez ou surveillez ces ports à la passerelle et corrigez l’appareil source.',
    'recs.title_isolate_scanning_hosts': 'Isoler les hôtes qui scannent',
    'recs.detail_isolate_scanning_hosts': 'Un appareil touche de nombreux ports sur une courte période. Placez-le sur un VLAN isolé ou un réseau invité jusqu’à confirmation du comportement attendu.',
    'recs.title_review_high_egress_devices': 'Examiner les appareils à fort trafic sortant',
    'recs.detail_review_high_egress_devices': 'Un ou plusieurs appareils ont dépassé le seuil de données sortantes. Vérifiez si le trafic correspond à des sauvegardes, caméras ou envois de médias plutôt qu’à un logiciel malveillant ou à de l’exfiltration.',
    'recs.title_improve_device_identity_coverage': 'Améliorer la couverture d’identité des appareils',
    'recs.detail_improve_device_identity_coverage': '{n} appareil(s) ont encore un rôle inconnu. Ajoutez des intégrations routeur, DHCP ou tracker pour permettre à HomeSec de corréler noms, adresses MAC et noms d’hôte.',
    'recs.title_enable_device_tracker_enrichment': 'Activer l’enrichissement des traceurs d’appareils',
    'recs.detail_enable_device_tracker_enrichment': 'HomeSec voit des appareils, mais aucun n’a été enrichi à partir des traceurs Home Assistant. Ajouter des intégrations routeur ou présence rendra le tableau de bord beaucoup plus lisible.',
    'recs.title_stabilize_exporter_templates': 'Stabiliser les modèles de l’exporteur',
    'recs.detail_stabilize_exporter_templates': 'Certains datagrammes de flux ont été perdus ou sont arrivés avant leurs modèles. Réduisez les redémarrages de l’exporteur ou raccourcissez les intervalles d’actualisation des modèles.',
    'findings.pattern': '🗑 Motif…', 'findings.security': 'Constats de sécurité', 'findings.actionable': 'actionnables', 'findings.shown': 'affichés', 'findings.dismissed': 'ignorés', 'findings.baseline': 'Anomalies de référence', 'findings.dismissed_title': 'Ignorés', 'findings.by_category': 'Par catégorie', 'findings.by_host': 'Par hôte', 'findings.by_severity': 'Par sévérité', 'findings.flat': 'À plat', 'findings.no_results': 'Aucun résultat pour', 'findings.no_active': 'Aucun constat actif élevé ou critique.', 'findings.host_one': 'hôte', 'findings.host_many': 'hôtes', 'findings.finding_one': 'constat', 'findings.finding_many': 'constats', 'findings.total': 'total', 'findings.latest': 'Dernier :', 'findings.restore': 'Restaurer', 'findings.dismiss': 'Ignorer', 'findings.restore_all': 'Tout restaurer', 'findings.dismiss_all': 'Tout ignorer', 'findings.category': 'Catégorie', 'findings.source': 'Source', 'findings.port': 'Port', 'findings.seen': 'vus', 'findings.remediation': 'Correction', 'findings.note': 'Note', 'findings.baseline_badge': 'Référence', 'findings.cat_new_host': 'Nouvel hôte détecté', 'findings.cat_new_peer': 'Nouveau pair externe', 'findings.cat_new_port': 'Nouveau port ouvert', 'findings.cat_new_dns_domain': 'Nouveau domaine DNS', 'findings.cat_new_dns_category': 'Nouvelle catégorie DNS', 'findings.cat_missing_host': 'Hôte connu manquant', 'findings.cat_missing_peer': 'Pair connu manquant', 'findings.cat_vulnerability': 'Vulnérabilité / CVE', 'findings.cat_port_scan': 'Scan de ports', 'findings.cat_suspicious_port': 'Port ouvert suspect', 'findings.cat_high_egress': 'Trafic sortant élevé', 'findings.sev_critical': 'Critique', 'findings.sev_high': 'Élevée', 'findings.sev_medium': 'Moyenne', 'findings.sev_low': 'Faible', 'findings.sev_info': 'Info',
    'stats.activity_timeline': 'CHRONOLOGIE D’ACTIVITÉ', 'stats.public_ips_per_hour': 'IP publiques vues par heure (24 h)', 'stats.no_public_ips': 'Aucune IP publique suivie pour le moment', 'stats.hosts_per_hour': 'Hôtes par heure (24 h)', 'stats.no_host_data': 'Aucune donnée d’hôte pour le moment', 'stats.hosts_seen': 'Hôtes vus', 'stats.scanned_alive': 'Scannés actifs', 'stats.pie': 'Camembert', 'stats.list': 'Liste', 'stats.no_external_flow_data': 'Aucune donnée de flux externe pour le moment', 'stats.ranked_by_flow_count': 'Classé par nombre de flux', 'stats.view_all_external_ips': 'Voir toutes les IP externes →', 'stats.no_country_data': 'Aucune donnée pays pour le moment', 'stats.no_traffic_data': 'Aucune donnée trafic pour le moment', 'stats.ranked_by_total_traffic': 'Classé par trafic total', 'stats.view_all_hosts': 'Voir tous les hôtes →', 'stats.no_enrichment_data': 'Aucune donnée d’enrichissement', 'stats.provider': 'Fournisseur', 'stats.used_today': 'Utilisé aujourd’hui', 'stats.daily_budget': 'Budget journalier', 'stats.usage': 'Utilisation', 'stats.status': 'Statut', 'stats.errors_notes': 'Erreurs / Notes', 'stats.not_configured': 'non configuré', 'stats.exhausted': 'épuisé', 'stats.unlimited': '∞ illimité', 'stats.ok': 'ok', 'stats.high': 'élevé', 'stats.no_threat_ips': 'Aucune IP suspecte ou malveillante détectée', 'stats.malicious_first': 'Malveillantes d’abord, puis par nombre de flux', 'stats.no_dns_queries': 'Aucune requête DNS enregistrée', 'stats.total': 'Total', 'stats.blocked': 'Bloqué', 'stats.malicious': 'Malveillant', 'stats.no_dns_detected': 'Aucune requête DNS malveillante ou bloquée détectée', 'stats.view_dns_log': 'Voir le journal DNS →', 'stats.no_blocked_yet': 'Aucune requête DNS bloquée ou malveillante pour le moment', 'stats.no_blocked_clients': 'Aucune requête client bloquée ou malveillante pour le moment', 'stats.no_deviance': 'Aucune donnée d’écart pour le moment — les données s’accumulent toutes les 5 min', 'stats.normal': '≤20% Normal', 'stats.review': '≤50% À revoir', 'stats.investigate': '≤75% À investiguer', 'stats.critical': '>75% Critique', 'stats.no_findings': 'Aucun constat enregistré pour le moment', 'stats.no_ext_peers': 'Aucun nouveau pair externe dans les écarts de référence', 'stats.baseline_deviance_hourly': 'Écart à la référence par heure (24 h)', 'stats.dns_queries_hourly': 'Requêtes DNS par heure (24 h)', 'stats.top_public_ips': 'Top {n} IP publiques', 'stats.top_countries': 'Top {n} pays', 'stats.top_internal_talkers': 'Top {n} émetteurs internes', 'stats.top_threat_ips': 'Top {n} IP menaçantes', 'stats.blocked_dns_by_category': 'Requêtes DNS bloquées par catégorie', 'stats.top_blocked_by_client': 'Top {n} requêtes bloquées par client', 'stats.top_hosts_deviations': 'Top {n} hôtes en écart', 'stats.top_ext_deviations': 'Top {n} IP externes en écart', 'stats.suricata_by_severity': 'Alertes Suricata — par sévérité', 'stats.suricata_by_category': 'Alertes Suricata — par catégorie', 'stats.suricata_top_source': 'Alertes Suricata — Top {n} IP source', 'stats.top_blocked_domains': 'Top {n} domaines bloqués / malveillants', 'stats.enrichment_budget': 'Budget d’enrichissement (aujourd’hui)', 'stats.no_alerts': 'Aucune alerte pour le moment', 'stats.no_data': 'Aucune donnée', 'external.modal_hostname': 'Nom d’hôte', 'external.modal_country': 'Pays', 'external.modal_asn': 'ASN', 'external.modal_org_isp': 'Org / FAI', 'external.modal_vt': 'VirusTotal', 'external.modal_abuse': 'Score d’abus', 'external.modal_direction': 'Direction', 'external.modal_reports': 'Rapports', 'external.modal_internal_host': 'Hôte interne', 'external.modal_data_sources': 'Sources de données', 'external.modal_enriched_at': 'Enrichi le', 'external.modal_last_seen': 'Dernière vue', 'external.modal_yes': 'Oui', 'external.modal_no': 'Non', 'external.modal_error': 'Erreur d’enrichissement :'
  },
  de: {
    'time.just_now': 'gerade eben',
    'time.minutes_ago': 'vor {n} Min.',
    'time.hours_ago': 'vor {n} Std.',
    'time.days_ago': 'vor {n} Tg.',
    'recs.title_patch_vulnerable': 'Verwundbare Geräte patchen',
    'recs.detail_patch_vulnerable': '{n} Gerät(e) haben bekannte CVE-Schwachstellen mit hohem oder kritischem Schweregrad. Aktualisieren Sie Firmware/Software oder beschränken Sie sofort den Netzwerkzugriff.',
    'recs.title_review_vulnerability_findings': 'Schwachstellenbefunde prüfen',
    'recs.detail_review_vulnerability_findings': 'Der aktive Scan hat Dienste mit bekannten Sicherheitsproblemen gefunden. Prüfen Sie den Befunde-Tab für CVE-Details und Behebungsschritte.',
    'recs.title_connect_exporter': 'Einen Flow-Exporter verbinden',
    'recs.detail_connect_exporter': 'Es wurden noch keine NetFlow- oder IPFIX-Exporter beobachtet. Konfigurieren Sie Ihr Gateway, Ihre Firewall oder Ihren Switch so, dass Flows an HomeSec exportiert werden.',
    'recs.title_verify_exporter': 'Exporter-Erreichbarkeit prüfen',
    'recs.detail_verify_exporter': 'Exporter sind konfiguriert, aber HomeSec hat noch keine Datagramme empfangen. Prüfen Sie Ziel-IP/-Port, Firewall-Regeln und das Containernetzwerk.',
    'recs.title_check_flow_format': 'Flow-Exportformat prüfen',
    'recs.detail_check_flow_format': 'Datagramme treffen ein, aber keine erzeugten Datensätze. Stellen Sie sicher, dass der Exporter NetFlow v5/v9/IPFIX mit IPv4-Feldern und gültigen Templates verwendet.',
    'recs.title_restrict_risky_ports': 'Riskante ausgehende Ports einschränken',
    'recs.detail_restrict_risky_ports': 'Mindestens ein Gerät hat einen häufig missbrauchten externen Port wie Telnet oder RDP erreicht. Blockieren oder überwachen Sie diese Ports am Gateway und patchen Sie das Quellgerät.',
    'recs.title_isolate_scanning_hosts': 'Scannende Hosts isolieren',
    'recs.detail_isolate_scanning_hosts': 'Ein Gerät spricht in kurzer Zeit viele Ports an. Verschieben Sie es in ein isoliertes VLAN oder Gastnetz, bis das Verhalten geklärt ist.',
    'recs.title_review_high_egress_devices': 'Geräte mit hohem ausgehendem Traffic prüfen',
    'recs.detail_review_high_egress_devices': 'Ein oder mehrere Geräte haben den Schwellenwert für ausgehende Daten überschritten. Prüfen Sie, ob der Traffic zu Backups, Kameras oder Medien-Uploads statt zu Malware oder Exfiltration passt.',
    'recs.title_improve_device_identity_coverage': 'Geräteidentität verbessern',
    'recs.detail_improve_device_identity_coverage': '{n} Gerät(e) haben noch eine unbekannte Rolle. Fügen Sie Router-, DHCP- oder Tracker-Integrationen hinzu, damit HomeSec Namen, MAC-Adressen und Hostnamen korrelieren kann.',
    'recs.title_enable_device_tracker_enrichment': 'Enrichment für Gerätetracker aktivieren',
    'recs.detail_enable_device_tracker_enrichment': 'HomeSec sieht Geräte, aber keine wurden aus Home-Assistant-Trackern angereichert. Router- oder Präsenzintegrationen machen das Dashboard deutlich lesbarer.',
    'recs.title_stabilize_exporter_templates': 'Exporter-Templates stabilisieren',
    'recs.detail_stabilize_exporter_templates': 'Einige Flow-Datagramme wurden verworfen oder trafen vor ihren Templates ein. Reduzieren Sie Neustarts des Exporters oder verkürzen Sie die Template-Aktualisierungsintervalle.',
    'findings.pattern': '🗑 Muster…', 'findings.security': 'Sicherheitsbefunde', 'findings.actionable': 'bearbeitbar', 'findings.shown': 'angezeigt', 'findings.dismissed': 'ausgeblendet', 'findings.baseline': 'Baseline-Anomalien', 'findings.dismissed_title': 'Ausgeblendet', 'findings.by_category': 'Nach Kategorie', 'findings.by_host': 'Nach Host', 'findings.by_severity': 'Nach Schweregrad', 'findings.flat': 'Flach', 'findings.no_results': 'Keine Ergebnisse für', 'findings.no_active': 'Keine aktiven hohen oder kritischen Befunde.', 'findings.host_one': 'Host', 'findings.host_many': 'Hosts', 'findings.finding_one': 'Befund', 'findings.finding_many': 'Befunde', 'findings.total': 'gesamt', 'findings.latest': 'Neueste:', 'findings.restore': 'Wiederherstellen', 'findings.dismiss': 'Ausblenden', 'findings.restore_all': 'Alle wiederherstellen', 'findings.dismiss_all': 'Alle ausblenden', 'findings.category': 'Kategorie', 'findings.source': 'Quelle', 'findings.port': 'Port', 'findings.seen': 'gesehen', 'findings.remediation': 'Behebung', 'findings.note': 'Notiz', 'findings.baseline_badge': 'Baseline', 'findings.cat_new_host': 'Neuer Host erkannt', 'findings.cat_new_peer': 'Neuer externer Peer', 'findings.cat_new_port': 'Neuer offener Port', 'findings.cat_new_dns_domain': 'Neue DNS-Domain', 'findings.cat_new_dns_category': 'Neue DNS-Kategorie', 'findings.cat_missing_host': 'Bekannter Host fehlt', 'findings.cat_missing_peer': 'Bekannter Peer fehlt', 'findings.cat_vulnerability': 'Schwachstelle / CVE', 'findings.cat_port_scan': 'Portscan', 'findings.cat_suspicious_port': 'Verdächtiger offener Port', 'findings.cat_high_egress': 'Hoher ausgehender Traffic', 'findings.sev_critical': 'Kritisch', 'findings.sev_high': 'Hoch', 'findings.sev_medium': 'Mittel', 'findings.sev_low': 'Niedrig', 'findings.sev_info': 'Info',
    'stats.activity_timeline': 'AKTIVITÄTSZEITLEISTE', 'stats.public_ips_per_hour': 'Öffentliche IPs pro Stunde (24 h)', 'stats.no_public_ips': 'Noch keine öffentlichen IPs verfolgt', 'stats.hosts_per_hour': 'Hosts pro Stunde (24 h)', 'stats.no_host_data': 'Noch keine Host-Daten', 'stats.hosts_seen': 'Gesehene Hosts', 'stats.scanned_alive': 'Lebend gescannt', 'stats.pie': 'Kreis', 'stats.list': 'Liste', 'stats.no_external_flow_data': 'Noch keine externen Flow-Daten', 'stats.ranked_by_flow_count': 'Nach Flow-Anzahl sortiert', 'stats.view_all_external_ips': 'Alle externen IPs anzeigen →', 'stats.no_country_data': 'Noch keine Länderdaten', 'stats.no_traffic_data': 'Noch keine Traffic-Daten', 'stats.ranked_by_total_traffic': 'Nach Gesamttraffic sortiert', 'stats.view_all_hosts': 'Alle Hosts anzeigen →', 'stats.no_enrichment_data': 'Keine Enrichment-Daten', 'stats.provider': 'Anbieter', 'stats.used_today': 'Heute genutzt', 'stats.daily_budget': 'Tagesbudget', 'stats.usage': 'Nutzung', 'stats.status': 'Status', 'stats.errors_notes': 'Fehler / Hinweise', 'stats.not_configured': 'nicht konfiguriert', 'stats.exhausted': 'erschöpft', 'stats.unlimited': '∞ unbegrenzt', 'stats.ok': 'ok', 'stats.high': 'hoch', 'stats.no_threat_ips': 'Keine verdächtigen oder bösartigen IPs erkannt', 'stats.malicious_first': 'Zuerst bösartig, dann nach Flow-Anzahl', 'stats.no_dns_queries': 'Keine DNS-Anfragen aufgezeichnet', 'stats.total': 'Gesamt', 'stats.blocked': 'Blockiert', 'stats.malicious': 'Bösartig', 'stats.no_dns_detected': 'Keine bösartigen oder blockierten DNS-Anfragen erkannt', 'stats.view_dns_log': 'DNS-Protokoll anzeigen →', 'stats.no_blocked_yet': 'Noch keine blockierten oder bösartigen DNS-Anfragen', 'stats.no_blocked_clients': 'Noch keine blockierten oder bösartigen Client-Anfragen', 'stats.no_deviance': 'Noch keine Abweichungsdaten — Daten sammeln sich alle 5 Min. an', 'stats.normal': '≤20% Normal', 'stats.review': '≤50% Prüfen', 'stats.investigate': '≤75% Untersuchen', 'stats.critical': '>75% Kritisch', 'stats.no_findings': 'Noch keine Befunde erfasst', 'stats.no_ext_peers': 'Keine neuen externen Peers in Baseline-Abweichungen', 'stats.baseline_deviance_hourly': 'Baseline-Abweichung pro Stunde (24 h)', 'stats.dns_queries_hourly': 'DNS-Anfragen pro Stunde (24 h)', 'stats.top_public_ips': 'Top {n} öffentliche IPs', 'stats.top_countries': 'Top {n} Länder', 'stats.top_internal_talkers': 'Top {n} interne Sprecher', 'stats.top_threat_ips': 'Top {n} Bedrohungs-IPs', 'stats.blocked_dns_by_category': 'Blockierte DNS-Anfragen nach Kategorie', 'stats.top_blocked_by_client': 'Top {n} blockierte Anfragen nach Client', 'stats.top_hosts_deviations': 'Top {n} Hosts in Abweichungen', 'stats.top_ext_deviations': 'Top {n} externe IPs in Abweichungen', 'stats.suricata_by_severity': 'Suricata-Warnungen — nach Schweregrad', 'stats.suricata_by_category': 'Suricata-Warnungen — nach Kategorie', 'stats.suricata_top_source': 'Suricata-Warnungen — Top {n} Quell-IPs', 'stats.top_blocked_domains': 'Top {n} blockierte / bösartige Domains', 'stats.enrichment_budget': 'Enrichment-Budget (heute)', 'stats.no_alerts': 'Noch keine Warnungen', 'stats.no_data': 'Keine Daten', 'external.modal_hostname': 'Hostname', 'external.modal_country': 'Land', 'external.modal_asn': 'ASN', 'external.modal_org_isp': 'Org / ISP', 'external.modal_vt': 'VirusTotal', 'external.modal_abuse': 'Missbrauchswert', 'external.modal_direction': 'Richtung', 'external.modal_reports': 'Berichte', 'external.modal_internal_host': 'Interner Host', 'external.modal_data_sources': 'Datenquellen', 'external.modal_enriched_at': 'Angereichert am', 'external.modal_last_seen': 'Zuletzt gesehen', 'external.modal_yes': 'Ja', 'external.modal_no': 'Nein', 'external.modal_error': 'Anreicherungsfehler:'
  },
  es: {
    'time.just_now': 'ahora mismo',
    'time.minutes_ago': 'hace {n} min',
    'time.hours_ago': 'hace {n} h',
    'time.days_ago': 'hace {n} d',
    'recs.title_patch_vulnerable': 'Corregir dispositivos vulnerables',
    'recs.detail_patch_vulnerable': '{n} dispositivo(s) tienen vulnerabilidades CVE conocidas de nivel alto o crítico. Actualice firmware/software o restrinja el acceso de red de inmediato.',
    'recs.title_review_vulnerability_findings': 'Revisar hallazgos de vulnerabilidad',
    'recs.detail_review_vulnerability_findings': 'El análisis activo encontró servicios con problemas de seguridad conocidos. Consulte la pestaña de hallazgos para ver los detalles CVE y los pasos de remediación.',
    'recs.title_connect_exporter': 'Conectar un exportador de flujo',
    'recs.detail_connect_exporter': 'Aún no se ha observado ningún exportador NetFlow o IPFIX. Configure su puerta de enlace, firewall o switch para exportar flujos a HomeSec.',
    'recs.title_verify_exporter': 'Verificar la conectividad del exportador',
    'recs.detail_verify_exporter': 'Hay exportadores configurados, pero HomeSec aún no ha recibido ningún datagrama. Compruebe la IP/puerto destino, las reglas del firewall y la red del contenedor.',
    'recs.title_check_flow_format': 'Comprobar el formato de exportación de flujos',
    'recs.detail_check_flow_format': 'Llegan datagramas, pero ninguno ha producido registros. Confirme que el exportador usa NetFlow v5/v9/IPFIX con campos IPv4 y plantillas válidas.',
    'recs.title_restrict_risky_ports': 'Restringir puertos salientes de riesgo',
    'recs.detail_restrict_risky_ports': 'Al menos un dispositivo contactó un puerto externo muy abusado como Telnet o RDP. Bloquee o alerte sobre estos puertos en la puerta de enlace y aplique parches al dispositivo origen.',
    'recs.title_isolate_scanning_hosts': 'Aislar hosts que escanean',
    'recs.detail_isolate_scanning_hosts': 'Un dispositivo está tocando muchos puertos en poco tiempo. Muévalo a una VLAN aislada o red de invitados hasta confirmar que el comportamiento es esperado.',
    'recs.title_review_high_egress_devices': 'Revisar dispositivos con alto tráfico saliente',
    'recs.detail_review_high_egress_devices': 'Uno o más dispositivos superaron el umbral de datos salientes. Compruebe si el tráfico corresponde a copias de seguridad, cámaras o subidas de medios en lugar de malware o exfiltración.',
    'recs.title_improve_device_identity_coverage': 'Mejorar la cobertura de identidad de dispositivos',
    'recs.detail_improve_device_identity_coverage': '{n} dispositivo(s) aún tienen un rol desconocido. Añada integraciones de router, DHCP o rastreo para que HomeSec pueda correlacionar nombres, direcciones MAC y nombres de host.',
    'recs.title_enable_device_tracker_enrichment': 'Activar enriquecimiento de rastreadores de dispositivos',
    'recs.detail_enable_device_tracker_enrichment': 'HomeSec ve dispositivos, pero ninguno se enriqueció desde rastreadores de Home Assistant. Añadir integraciones de router o presencia hará que el panel sea mucho más legible.',
    'recs.title_stabilize_exporter_templates': 'Estabilizar plantillas del exportador',
    'recs.detail_stabilize_exporter_templates': 'Algunos datagramas de flujo se descartaron o llegaron antes de sus plantillas. Reduzca los reinicios del exportador o acorte los intervalos de actualización de plantillas.',
    'findings.pattern': '🗑 Patrón…', 'findings.security': 'Hallazgos de seguridad', 'findings.actionable': 'accionables', 'findings.shown': 'mostrados', 'findings.dismissed': 'descartados', 'findings.baseline': 'Anomalías de línea base', 'findings.dismissed_title': 'Descartados', 'findings.by_category': 'Por categoría', 'findings.by_host': 'Por host', 'findings.by_severity': 'Por severidad', 'findings.flat': 'Plano', 'findings.no_results': 'Sin resultados para', 'findings.no_active': 'No hay hallazgos activos altos o críticos.', 'findings.host_one': 'host', 'findings.host_many': 'hosts', 'findings.finding_one': 'hallazgo', 'findings.finding_many': 'hallazgos', 'findings.total': 'total', 'findings.latest': 'Último:', 'findings.restore': 'Restaurar', 'findings.dismiss': 'Descartar', 'findings.restore_all': 'Restaurar todo', 'findings.dismiss_all': 'Descartar todo', 'findings.category': 'Categoría', 'findings.source': 'Origen', 'findings.port': 'Puerto', 'findings.seen': 'visto', 'findings.remediation': 'Remediación', 'findings.note': 'Nota', 'findings.baseline_badge': 'Línea base', 'findings.cat_new_host': 'Nuevo host detectado', 'findings.cat_new_peer': 'Nuevo par externo', 'findings.cat_new_port': 'Nuevo puerto abierto', 'findings.cat_new_dns_domain': 'Nuevo dominio DNS', 'findings.cat_new_dns_category': 'Nueva categoría DNS', 'findings.cat_missing_host': 'Falta host conocido', 'findings.cat_missing_peer': 'Falta par conocido', 'findings.cat_vulnerability': 'Vulnerabilidad / CVE', 'findings.cat_port_scan': 'Escaneo de puertos', 'findings.cat_suspicious_port': 'Puerto abierto sospechoso', 'findings.cat_high_egress': 'Tráfico saliente alto', 'findings.sev_critical': 'Crítico', 'findings.sev_high': 'Alto', 'findings.sev_medium': 'Medio', 'findings.sev_low': 'Bajo', 'findings.sev_info': 'Info',
    'stats.activity_timeline': 'LÍNEA DE TIEMPO DE ACTIVIDAD', 'stats.public_ips_per_hour': 'IPs públicas vistas por hora (24 h)', 'stats.no_public_ips': 'Aún no hay IPs públicas rastreadas', 'stats.hosts_per_hour': 'Hosts por hora (24 h)', 'stats.no_host_data': 'Aún no hay datos de hosts', 'stats.hosts_seen': 'Hosts vistos', 'stats.scanned_alive': 'Analizados activos', 'stats.pie': 'Tarta', 'stats.list': 'Lista', 'stats.no_external_flow_data': 'Aún no hay datos de flujo externo', 'stats.ranked_by_flow_count': 'Clasificado por número de flujos', 'stats.view_all_external_ips': 'Ver todas las IPs externas →', 'stats.no_country_data': 'Aún no hay datos de países', 'stats.no_traffic_data': 'Aún no hay datos de tráfico', 'stats.ranked_by_total_traffic': 'Clasificado por tráfico total', 'stats.view_all_hosts': 'Ver todos los hosts →', 'stats.no_enrichment_data': 'Sin datos de enriquecimiento', 'stats.provider': 'Proveedor', 'stats.used_today': 'Usado hoy', 'stats.daily_budget': 'Presupuesto diario', 'stats.usage': 'Uso', 'stats.status': 'Estado', 'stats.errors_notes': 'Errores / Notas', 'stats.not_configured': 'no configurado', 'stats.exhausted': 'agotado', 'stats.unlimited': '∞ ilimitado', 'stats.ok': 'ok', 'stats.high': 'alto', 'stats.no_threat_ips': 'No se detectaron IPs sospechosas o maliciosas', 'stats.malicious_first': 'Primero maliciosas, luego por número de flujos', 'stats.no_dns_queries': 'No se registraron consultas DNS', 'stats.total': 'Total', 'stats.blocked': 'Bloqueado', 'stats.malicious': 'Malicioso', 'stats.no_dns_detected': 'No se detectaron consultas DNS maliciosas o bloqueadas', 'stats.view_dns_log': 'Ver registro DNS →', 'stats.no_blocked_yet': 'Aún no hay consultas DNS bloqueadas o maliciosas', 'stats.no_blocked_clients': 'Aún no hay consultas cliente bloqueadas o maliciosas', 'stats.no_deviance': 'Aún no hay datos de desviación — los datos se acumulan cada 5 min', 'stats.normal': '≤20% Normal', 'stats.review': '≤50% Revisar', 'stats.investigate': '≤75% Investigar', 'stats.critical': '>75% Crítico', 'stats.no_findings': 'Aún no hay hallazgos registrados', 'stats.no_ext_peers': 'No hay nuevos pares externos en desviaciones de línea base', 'stats.baseline_deviance_hourly': 'Desviación de línea base por hora (24 h)', 'stats.dns_queries_hourly': 'Consultas DNS por hora (24 h)', 'stats.top_public_ips': 'Top {n} IPs públicas', 'stats.top_countries': 'Top {n} países', 'stats.top_internal_talkers': 'Top {n} emisores internos', 'stats.top_threat_ips': 'Top {n} IPs de amenaza', 'stats.blocked_dns_by_category': 'Consultas DNS bloqueadas por categoría', 'stats.top_blocked_by_client': 'Top {n} consultas bloqueadas por cliente', 'stats.top_hosts_deviations': 'Top {n} hosts en desviaciones', 'stats.top_ext_deviations': 'Top {n} IPs externas en desviaciones', 'stats.suricata_by_severity': 'Alertas Suricata — por severidad', 'stats.suricata_by_category': 'Alertas Suricata — por categoría', 'stats.suricata_top_source': 'Alertas Suricata — Top {n} IPs origen', 'stats.top_blocked_domains': 'Top {n} dominios bloqueados / maliciosos', 'stats.enrichment_budget': 'Presupuesto de enriquecimiento (hoy)', 'stats.no_alerts': 'Aún no hay alertas', 'stats.no_data': 'Sin datos', 'external.modal_hostname': 'Nombre de host', 'external.modal_country': 'País', 'external.modal_asn': 'ASN', 'external.modal_org_isp': 'Org / ISP', 'external.modal_vt': 'VirusTotal', 'external.modal_abuse': 'Nivel de abuso', 'external.modal_direction': 'Dirección', 'external.modal_reports': 'Informes', 'external.modal_internal_host': 'Host interno', 'external.modal_data_sources': 'Fuentes de datos', 'external.modal_enriched_at': 'Enriquecido el', 'external.modal_last_seen': 'Última vez visto', 'external.modal_yes': 'Sí', 'external.modal_no': 'No', 'external.modal_error': 'Error de enriquecimiento:'
  },
  it: {
    'time.just_now': 'proprio ora',
    'time.minutes_ago': 'fa {n} min',
    'time.hours_ago': 'fa {n} h',
    'time.days_ago': 'fa {n} g',
    'recs.title_patch_vulnerable': 'Correggi i dispositivi vulnerabili',
    'recs.detail_patch_vulnerable': '{n} dispositivo/i hanno vulnerabilità CVE note di livello alto o critico. Aggiorna firmware/software o limita subito l’accesso alla rete.',
    'recs.title_review_vulnerability_findings': 'Esamina i rilevamenti di vulnerabilità',
    'recs.detail_review_vulnerability_findings': 'La scansione attiva ha trovato servizi con problemi di sicurezza noti. Controlla la scheda dei rilevamenti per i dettagli CVE e i passaggi di rimedio.',
    'recs.title_connect_exporter': 'Collega un esportatore di flussi',
    'recs.detail_connect_exporter': 'Non è ancora stato osservato alcun esportatore NetFlow o IPFIX. Configura gateway, firewall o switch per esportare i flussi verso HomeSec.',
    'recs.title_verify_exporter': 'Verifica la raggiungibilità dell’esportatore',
    'recs.detail_verify_exporter': 'Gli esportatori sono configurati, ma HomeSec non ha ancora ricevuto datagrammi. Controlla IP/porta di destinazione, regole firewall e rete del contenitore.',
    'recs.title_check_flow_format': 'Controlla il formato di esportazione dei flussi',
    'recs.detail_check_flow_format': 'I datagrammi arrivano, ma nessuno ha prodotto record. Conferma che l’esportatore usi NetFlow v5/v9/IPFIX con campi IPv4 e template validi.',
    'recs.title_restrict_risky_ports': 'Limita le porte in uscita rischiose',
    'recs.detail_restrict_risky_ports': 'Almeno un dispositivo ha contattato una porta esterna spesso abusata, come Telnet o RDP. Blocca o segnala queste porte sul gateway e correggi il dispositivo sorgente.',
    'recs.title_isolate_scanning_hosts': 'Isola gli host che eseguono scansioni',
    'recs.detail_isolate_scanning_hosts': 'Un dispositivo sta toccando molte porte in poco tempo. Spostalo in una VLAN isolata o rete guest finché non confermi che il comportamento è previsto.',
    'recs.title_review_high_egress_devices': 'Esamina i dispositivi con traffico in uscita elevato',
    'recs.detail_review_high_egress_devices': 'Uno o più dispositivi hanno superato la soglia dei dati in uscita. Verifica se il traffico corrisponde a backup, telecamere o upload multimediali invece che a malware o esfiltrazione.',
    'recs.title_improve_device_identity_coverage': 'Migliora la copertura dell’identità dei dispositivi',
    'recs.detail_improve_device_identity_coverage': '{n} dispositivo/i hanno ancora un ruolo sconosciuto. Aggiungi integrazioni router, DHCP o tracker così HomeSec può correlare nomi, indirizzi MAC e hostname.',
    'recs.title_enable_device_tracker_enrichment': 'Abilita l’arricchimento dei tracker dei dispositivi',
    'recs.detail_enable_device_tracker_enrichment': 'HomeSec vede i dispositivi, ma nessuno è stato arricchito dai tracker di Home Assistant. Aggiungere integrazioni router o di presenza renderà la dashboard molto più leggibile.',
    'recs.title_stabilize_exporter_templates': 'Stabilizza i template dell’esportatore',
    'recs.detail_stabilize_exporter_templates': 'Alcuni datagrammi di flusso sono stati scartati o arrivati prima dei loro template. Riduci i riavvii dell’esportatore o accorcia gli intervalli di aggiornamento dei template.',
    'findings.pattern': '🗑 Pattern…', 'findings.security': 'Rilevamenti di sicurezza', 'findings.actionable': 'azionabili', 'findings.shown': 'mostrati', 'findings.dismissed': 'ignorati', 'findings.baseline': 'Anomalie baseline', 'findings.dismissed_title': 'Ignorati', 'findings.by_category': 'Per categoria', 'findings.by_host': 'Per host', 'findings.by_severity': 'Per gravità', 'findings.flat': 'Piatto', 'findings.no_results': 'Nessun risultato per', 'findings.no_active': 'Nessun rilevamento attivo alto o critico.', 'findings.host_one': 'host', 'findings.host_many': 'host', 'findings.finding_one': 'rilevamento', 'findings.finding_many': 'rilevamenti', 'findings.total': 'totale', 'findings.latest': 'Ultimo:', 'findings.restore': 'Ripristina', 'findings.dismiss': 'Ignora', 'findings.restore_all': 'Ripristina tutto', 'findings.dismiss_all': 'Ignora tutto', 'findings.category': 'Categoria', 'findings.source': 'Sorgente', 'findings.port': 'Porta', 'findings.seen': 'visto', 'findings.remediation': 'Rimedio', 'findings.note': 'Nota', 'findings.baseline_badge': 'Baseline', 'findings.cat_new_host': 'Nuovo host rilevato', 'findings.cat_new_peer': 'Nuovo peer esterno', 'findings.cat_new_port': 'Nuova porta aperta', 'findings.cat_new_dns_domain': 'Nuovo dominio DNS', 'findings.cat_new_dns_category': 'Nuova categoria DNS', 'findings.cat_missing_host': 'Host noto mancante', 'findings.cat_missing_peer': 'Peer noto mancante', 'findings.cat_vulnerability': 'Vulnerabilità / CVE', 'findings.cat_port_scan': 'Scansione porte', 'findings.cat_suspicious_port': 'Porta aperta sospetta', 'findings.cat_high_egress': 'Traffico in uscita elevato', 'findings.sev_critical': 'Critico', 'findings.sev_high': 'Alto', 'findings.sev_medium': 'Medio', 'findings.sev_low': 'Basso', 'findings.sev_info': 'Info',
    'stats.activity_timeline': 'CRONOLOGIA ATTIVITÀ', 'stats.public_ips_per_hour': 'IP pubblici visti per ora (24 h)', 'stats.no_public_ips': 'Nessun IP pubblico tracciato per ora', 'stats.hosts_per_hour': 'Host per ora (24 h)', 'stats.no_host_data': 'Nessun dato host ancora', 'stats.hosts_seen': 'Host visti', 'stats.scanned_alive': 'Scansionati attivi', 'stats.pie': 'Torta', 'stats.list': 'Lista', 'stats.no_external_flow_data': 'Nessun dato di flusso esterno ancora', 'stats.ranked_by_flow_count': 'Ordinato per numero di flussi', 'stats.view_all_external_ips': 'Vedi tutti gli IP esterni →', 'stats.no_country_data': 'Nessun dato paese ancora', 'stats.no_traffic_data': 'Nessun dato traffico ancora', 'stats.ranked_by_total_traffic': 'Ordinato per traffico totale', 'stats.view_all_hosts': 'Vedi tutti gli host →', 'stats.no_enrichment_data': 'Nessun dato di arricchimento', 'stats.provider': 'Provider', 'stats.used_today': 'Usato oggi', 'stats.daily_budget': 'Budget giornaliero', 'stats.usage': 'Utilizzo', 'stats.status': 'Stato', 'stats.errors_notes': 'Errori / Note', 'stats.not_configured': 'non configurato', 'stats.exhausted': 'esaurito', 'stats.unlimited': '∞ illimitato', 'stats.ok': 'ok', 'stats.high': 'alto', 'stats.no_threat_ips': 'Nessun IP sospetto o malevolo rilevato', 'stats.malicious_first': 'Prima i malevoli, poi per numero di flussi', 'stats.no_dns_queries': 'Nessuna query DNS registrata', 'stats.total': 'Totale', 'stats.blocked': 'Bloccato', 'stats.malicious': 'Malevolo', 'stats.no_dns_detected': 'Nessuna query DNS malevola o bloccata rilevata', 'stats.view_dns_log': 'Vedi log DNS →', 'stats.no_blocked_yet': 'Nessuna query DNS bloccata o malevola per ora', 'stats.no_blocked_clients': 'Nessuna query client bloccata o malevola per ora', 'stats.no_deviance': 'Nessun dato di deviazione ancora — i dati si accumulano ogni 5 min', 'stats.normal': '≤20% Normale', 'stats.review': '≤50% Rivedi', 'stats.investigate': '≤75% Indaga', 'stats.critical': '>75% Critico', 'stats.no_findings': 'Nessun rilevamento registrato ancora', 'stats.no_ext_peers': 'Nessun nuovo peer esterno nelle deviazioni baseline', 'stats.baseline_deviance_hourly': 'Deviazione baseline per ora (24 h)', 'stats.dns_queries_hourly': 'Query DNS per ora (24 h)', 'stats.top_public_ips': 'Top {n} IP pubblici', 'stats.top_countries': 'Top {n} paesi', 'stats.top_internal_talkers': 'Top {n} interlocutori interni', 'stats.top_threat_ips': 'Top {n} IP di minaccia', 'stats.blocked_dns_by_category': 'Query DNS bloccate per categoria', 'stats.top_blocked_by_client': 'Top {n} query bloccate per client', 'stats.top_hosts_deviations': 'Top {n} host in deviazione', 'stats.top_ext_deviations': 'Top {n} IP esterni in deviazione', 'stats.suricata_by_severity': 'Avvisi Suricata — per gravità', 'stats.suricata_by_category': 'Avvisi Suricata — per categoria', 'stats.suricata_top_source': 'Avvisi Suricata — Top {n} IP sorgente', 'stats.top_blocked_domains': 'Top {n} domini bloccati / malevoli', 'stats.enrichment_budget': 'Budget arricchimento (oggi)', 'stats.no_alerts': 'Nessun avviso ancora', 'stats.no_data': 'Nessun dato', 'external.modal_hostname': 'Hostname', 'external.modal_country': 'Paese', 'external.modal_asn': 'ASN', 'external.modal_org_isp': 'Org / ISP', 'external.modal_vt': 'VirusTotal', 'external.modal_abuse': 'Livello abuso', 'external.modal_direction': 'Direzione', 'external.modal_reports': 'Report', 'external.modal_internal_host': 'Host interno', 'external.modal_data_sources': 'Sorgenti dati', 'external.modal_enriched_at': 'Arricchito il', 'external.modal_last_seen': 'Ultima vista', 'external.modal_yes': 'Sì', 'external.modal_no': 'No', 'external.modal_error': 'Errore di arricchimento:'
  }
};

Object.keys(_UI_I18N_EXTRA_3).forEach(function(locale) {
  Object.assign(_UI_I18N[locale], _UI_I18N_EXTRA_3[locale]);
});

const _SETTINGS_SCHEMA_I18N = {
  fr: {
    sections: {
      'Network & NetFlow': 'Réseau et NetFlow',
      'Threat Detection': 'Détection des menaces',
      'Active Scanner': 'Scanner actif',
      'DNS & Threat Intelligence': 'DNS et renseignement sur les menaces',
      'DNS Proxy': 'Proxy DNS',
      'External IP Enrichment': 'Enrichissement des IP externes',
      'NVD Vulnerability Intelligence': 'Renseignement vulnérabilités NVD',
      'Baseline & Behaviour Analysis': 'Baseline et analyse comportementale',
      'Display': 'Affichage',
      'Suricata Alert Listener': 'Récepteur d\'alertes Suricata',
    },
    labels: {
      bind_host: 'Hôte d\'écoute NetFlow',
      bind_port: 'Port d\'écoute NetFlow',
      enable_netflow_listener: 'Activer l\'écouteur NetFlow',
      internal_networks: 'Réseaux internes',
      scan_window_seconds: 'Fenêtre de scan de ports (s)',
      scan_port_threshold: 'Seuil de scan de ports',
      high_egress_threshold: 'Seuil de trafic sortant élevé (octets)',
      enable_scanner: 'Activer le scanner',
      scan_interval: 'Intervalle de scan (s)',
      scan_ports: 'Ports à scanner',
      scan_exceptions: 'Exceptions de scan',
      enable_dns_resolution: 'Activer la résolution DNS',
      blacklist_urls: 'URLs de blacklist',
      dns_proxy_enabled: 'Activer le proxy DNS',
      dns_proxy_bind_host: 'Hôte d\'écoute du proxy DNS',
      dns_proxy_port: 'Port du proxy DNS',
      dns_proxy_upstream: 'Serveur DNS amont',
      dns_log_retention_hours: 'Rétention des journaux DNS (h)',
      dns_warn_blocked_logs: 'Journaux d\'alerte pour domaines bloqués',
      dns_blocked_categories: 'Catégories DNS bloquées',
      dns_overrides: 'Overrides DNS locaux',
      virustotal_api_key: 'Clé API VirusTotal',
      abuseipdb_api_key: 'Clé API AbuseIPDB',
      vt_abuseipdb_threshold: 'Seuil de score de menace (%)',
      virustotal_daily_budget: 'Budget quotidien VirusTotal',
      abuseipdb_daily_budget: 'Budget quotidien AbuseIPDB',
      enrichment_ttl_minutes: 'TTL du cache d\'enrichissement (min)',
      external_ip_retention_hours: 'Rétention des IP externes (h)',
      retention_suspicious_hours: 'Rétention des IP suspectes (h)',
      retention_malicious_hours: 'Rétention des IP malveillantes (h)',
      nvd_api_url: 'URL API NVD',
      nvd_ttl_hours: 'TTL du cache NVD (h)',
      nvd_min_year: 'Année minimale CVE',
      nvd_keywords: 'Mots-clés NVD',
      baseline_enabled: 'Activer la baseline',
      baseline_training_hours: 'Durée d\'apprentissage (h)',
      baseline_min_observations: 'Observations minimales',
      baseline_egress_multiplier: 'Multiplicateur d\'anomalie sortante',
      webui_require_admin: 'Le panneau latéral requiert un admin',
      stats_top_n: 'Top N des statistiques',
      suricata_listener_enabled: 'Activer le récepteur Suricata',
      suricata_listener_host: 'Hôte d\'écoute du récepteur',
      suricata_listener_port: 'Port TCP du récepteur',
      suricata_log_retention_hours: 'Rétention des journaux d\'alertes (h)',
    },
    helps: {
      bind_host: 'Adresse IP sur laquelle écouter les datagrammes NetFlow UDP (utilisez 0.0.0.0 pour toutes les interfaces).',
      bind_port: 'Port UDP pour les datagrammes NetFlow v5/v9/IPFIX (2055 par défaut).',
      enable_netflow_listener: 'Active l\'écoute UDP NetFlow/IPFIX et l\'ingestion des flux.',
      internal_networks: 'Plages CIDR séparées par des virgules considérées comme internes (ex. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Fenêtre temporelle en secondes pour détecter les scans de ports.',
      scan_port_threshold: 'Nombre de ports distincts contactés dans la fenêtre pour déclencher une alerte de scan de ports.',
      high_egress_threshold: 'Volume d\'octets envoyés vers l\'extérieur pour déclencher une alerte de trafic sortant élevé.',
      enable_scanner: 'Active le scan actif périodique des hôtes internes.',
      scan_interval: 'Nombre de secondes entre deux cycles de scan actif.',
      scan_ports: 'Ports à scanner (plages et virgules autorisées, ex. 22,80,443,8080-8090).',
      scan_exceptions: 'IPs à exclure du scan actif, séparées par des virgules.',
      enable_dns_resolution: 'Résout les noms d\'hôte pour les IP externes et les vérifie dans les blacklists.',
      blacklist_urls: 'URLs de listes de blocage threat-intel, séparées par virgules ou retours à la ligne.',
      dns_proxy_enabled: 'Lance un proxy DNS qui journalise et peut bloquer les requêtes.',
      dns_proxy_bind_host: 'Adresse d\'écoute du proxy DNS (recommandé : 127.0.0.1 ou une IP LAN spécifique).',
      dns_proxy_port: 'Port UDP du proxy DNS (53 par défaut, nécessite root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP du résolveur DNS amont (ex. 1.1.1.1).',
      dns_log_retention_hours: 'Nombre d\'heures de conservation des entrées de journal DNS (0 = illimité).',
      dns_warn_blocked_logs: 'Écrit un journal de niveau warning pour chaque requête DNS bloquée (désactivé par défaut pour limiter le bruit).',
      dns_blocked_categories: 'Noms de catégories à bloquer, séparés par virgules ou retours à la ligne (ex. ads,malware,tracking).',
      dns_overrides: 'Overrides DNS locaux, une entrée par ligne : hostname=IP (ex. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Clé API VirusTotal optionnelle pour l\'évaluation de réputation des IP externes.',
      abuseipdb_api_key: 'Clé API AbuseIPDB optionnelle pour l\'évaluation de réputation des IP externes.',
      vt_abuseipdb_threshold: 'Score de confiance d\'abus minimal (0-100) pour marquer une IP comme suspecte.',
      virustotal_daily_budget: 'Nombre maximal de requêtes API VirusTotal par jour.',
      abuseipdb_daily_budget: 'Nombre maximal de requêtes API AbuseIPDB par jour.',
      enrichment_ttl_minutes: 'Nombre de minutes avant de réinterroger les APIs d\'enrichissement pour une IP connue.',
      external_ip_retention_hours: 'Nombre d\'heures de conservation des IP externes propres dans le tableau de bord.',
      retention_suspicious_hours: 'Nombre d\'heures de conservation des IP suspectes.',
      retention_malicious_hours: 'Nombre d\'heures de conservation des IP malveillantes.',
      nvd_api_url: 'URL du point de terminaison de l\'API CVE NVD.',
      nvd_ttl_hours: 'Nombre d\'heures avant rafraîchissement du cache CVE NVD.',
      nvd_min_year: 'Afficher uniquement les CVE publiées à partir de cette année.',
      nvd_keywords: 'Mots-clés produits séparés par des virgules à précharger depuis NVD (ex. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Active l\'apprentissage de baseline comportementale et la détection d\'anomalies.',
      baseline_training_hours: 'Nombre d\'heures de trafic à observer avant de considérer la baseline entraînée.',
      baseline_min_observations: 'Nombre minimal d\'observations de flux avant de considérer un motif comme normal.',
      baseline_egress_multiplier: 'Nombre de fois où le trafic sortant baseline d\'un appareil doit être dépassé avant signalement.',
      webui_require_admin: 'Quand activé, seuls les utilisateurs administrateurs Home Assistant peuvent voir le panneau latéral Security Assistant.',
      stats_top_n: 'Nombre d\'entrées principales à afficher dans les graphiques de statistiques.',
      suricata_listener_enabled: 'Accepte les alertes Suricata EVE JSON sur TCP depuis suricata_pusher.py.',
      suricata_listener_host: 'Adresse IP d\'écoute du récepteur TCP (0.0.0.0 pour toutes les interfaces).',
      suricata_listener_port: 'Port TCP auquel le pusher Suricata se connecte (6343 par défaut).',
      suricata_log_retention_hours: 'Nombre d\'heures de conservation des entrées de journal d\'alertes Suricata (0 = illimité).',
    },
  },
  de: {
    sections: {
      'Network & NetFlow': 'Netzwerk und NetFlow',
      'Threat Detection': 'Bedrohungserkennung',
      'Active Scanner': 'Aktiver Scanner',
      'DNS & Threat Intelligence': 'DNS und Threat Intelligence',
      'DNS Proxy': 'DNS-Proxy',
      'External IP Enrichment': 'Externe IP-Anreicherung',
      'NVD Vulnerability Intelligence': 'NVD-Schwachstelleninformationen',
      'Baseline & Behaviour Analysis': 'Baseline und Verhaltensanalyse',
      'Display': 'Anzeige',
      'Suricata Alert Listener': 'Suricata-Alarm-Listener',
    },
    labels: {
      bind_host: 'NetFlow-Bind-Host',
      bind_port: 'NetFlow-Bind-Port',
      enable_netflow_listener: 'NetFlow-Listener aktivieren',
      internal_networks: 'Interne Netzwerke',
      scan_window_seconds: 'Portscan-Fenster (s)',
      scan_port_threshold: 'Portscan-Schwelle',
      high_egress_threshold: 'Schwelle für hohen ausgehenden Traffic (Bytes)',
      enable_scanner: 'Scanner aktivieren',
      scan_interval: 'Scan-Intervall (s)',
      scan_ports: 'Zu scannende Ports',
      scan_exceptions: 'Scan-Ausnahmen',
      enable_dns_resolution: 'DNS-Auflösung aktivieren',
      blacklist_urls: 'Blacklist-URLs',
      dns_proxy_enabled: 'DNS-Proxy aktivieren',
      dns_proxy_bind_host: 'DNS-Proxy-Bind-Host',
      dns_proxy_port: 'DNS-Proxy-Port',
      dns_proxy_upstream: 'Upstream-DNS-Server',
      dns_log_retention_hours: 'DNS-Log-Aufbewahrung (h)',
      dns_warn_blocked_logs: 'Warn-Logs für blockierte Domains',
      dns_blocked_categories: 'Blockierte DNS-Kategorien',
      dns_overrides: 'Lokale DNS-Overrides',
      virustotal_api_key: 'VirusTotal-API-Schlüssel',
      abuseipdb_api_key: 'AbuseIPDB-API-Schlüssel',
      vt_abuseipdb_threshold: 'Threat-Score-Schwelle (%)',
      virustotal_daily_budget: 'VirusTotal-Tagesbudget',
      abuseipdb_daily_budget: 'AbuseIPDB-Tagesbudget',
      enrichment_ttl_minutes: 'TTL für Anreicherungs-Cache (min)',
      external_ip_retention_hours: 'Aufbewahrung externer IPs (h)',
      retention_suspicious_hours: 'Aufbewahrung verdächtiger IPs (h)',
      retention_malicious_hours: 'Aufbewahrung bösartiger IPs (h)',
      nvd_api_url: 'NVD-API-URL',
      nvd_ttl_hours: 'NVD-Cache-TTL (h)',
      nvd_min_year: 'CVE-Mindestjahr',
      nvd_keywords: 'NVD-Schlüsselwörter',
      baseline_enabled: 'Baseline aktivieren',
      baseline_training_hours: 'Trainingsdauer (h)',
      baseline_min_observations: 'Minimale Beobachtungen',
      baseline_egress_multiplier: 'Egress-Anomalie-Multiplikator',
      webui_require_admin: 'Seitenleistenpanel erfordert Admin',
      stats_top_n: 'Statistik Top N',
      suricata_listener_enabled: 'Suricata-Listener aktivieren',
      suricata_listener_host: 'Listener-Bind-Host',
      suricata_listener_port: 'Listener-TCP-Port',
      suricata_log_retention_hours: 'Aufbewahrung Alarm-Logs (h)',
    },
    helps: {
      bind_host: 'IP-Adresse für den NetFlow-UDP-Listener (0.0.0.0 für alle Interfaces).',
      bind_port: 'UDP-Port für NetFlow-v5/v9/IPFIX-Datagramme (Standard 2055).',
      enable_netflow_listener: 'Aktiviert den UDP-NetFlow/IPFIX-Listener und die Flow-Erfassung.',
      internal_networks: 'Kommagetrennte CIDR-Bereiche, die als intern gelten (z. B. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Zeitfenster in Sekunden für die Portscan-Erkennung.',
      scan_port_threshold: 'Anzahl unterschiedlicher Ports im Fenster, um einen Portscan-Alarm auszulösen.',
      high_egress_threshold: 'Ausgehend gesendete Bytes für einen High-Egress-Alarm.',
      enable_scanner: 'Aktiviert periodisches aktives Port-Scanning interner Hosts.',
      scan_interval: 'Sekunden zwischen aktiven Scan-Zyklen.',
      scan_ports: 'Zu scannende Ports (Bereiche und Kommas erlaubt, z. B. 22,80,443,8080-8090).',
      scan_exceptions: 'Kommagetrennte IPs, die vom aktiven Scan ausgeschlossen werden.',
      enable_dns_resolution: 'Löst Hostnamen für externe IPs auf und prüft sie gegen Blacklists.',
      blacklist_urls: 'Komma- oder zeilengetrennte URLs von Threat-Intel-Blocklisten zum Herunterladen.',
      dns_proxy_enabled: 'Startet einen DNS-Proxy, der Anfragen protokolliert und optional blockiert.',
      dns_proxy_bind_host: 'Bind-Adresse des DNS-Proxys (empfohlen: 127.0.0.1 oder eine spezifische LAN-IP).',
      dns_proxy_port: 'UDP-Port für den DNS-Proxy-Listener (Standard 53, benötigt root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP des Upstream-DNS-Resolvers (z. B. 1.1.1.1).',
      dns_log_retention_hours: 'Wie viele Stunden DNS-Logeinträge aufbewahrt werden (0 = unbegrenzt).',
      dns_warn_blocked_logs: 'Schreibt Warn-Logs für jede blockierte DNS-Anfrage (standardmäßig aus, um Log-Rauschen zu reduzieren).',
      dns_blocked_categories: 'Komma- oder zeilengetrennte Kategorienamen zum Blockieren (z. B. ads,malware,tracking).',
      dns_overrides: 'Lokale DNS-Overrides, eine Zeile pro Eintrag: hostname=IP (z. B. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Optionaler VirusTotal-API-Schlüssel für Reputationsabfragen externer IPs.',
      abuseipdb_api_key: 'Optionaler AbuseIPDB-API-Schlüssel für Reputationsabfragen externer IPs.',
      vt_abuseipdb_threshold: 'Mindest-Missbrauchsscore (0-100), um eine IP als verdächtig zu markieren.',
      virustotal_daily_budget: 'Maximale Anzahl VirusTotal-API-Abfragen pro Tag.',
      abuseipdb_daily_budget: 'Maximale Anzahl AbuseIPDB-API-Abfragen pro Tag.',
      enrichment_ttl_minutes: 'Minuten bis zur erneuten Abfrage von Anreicherungs-APIs für bekannte IPs.',
      external_ip_retention_hours: 'Stunden zur Aufbewahrung unauffälliger externer IPs im Dashboard.',
      retention_suspicious_hours: 'Stunden zur Aufbewahrung verdächtiger IPs.',
      retention_malicious_hours: 'Stunden zur Aufbewahrung bösartiger IPs.',
      nvd_api_url: 'URL des NVD-CVE-API-Endpunkts.',
      nvd_ttl_hours: 'Stunden bis zur Aktualisierung des NVD-CVE-Caches.',
      nvd_min_year: 'Nur CVEs anzeigen, die in oder nach diesem Jahr veröffentlicht wurden.',
      nvd_keywords: 'Kommagetrennte Produkt-Schlüsselwörter zum Vorababruf aus NVD (z. B. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Aktiviert lernende Verhaltens-Baseline und Anomalieerkennung.',
      baseline_training_hours: 'Stunden Traffic-Beobachtung, bevor die Baseline als trainiert gilt.',
      baseline_min_observations: 'Minimale Anzahl an Flow-Beobachtungen, bevor ein Muster als normal gilt.',
      baseline_egress_multiplier: 'Wie oft die Baseline-Egress eines Geräts überschritten werden muss, bevor es markiert wird.',
      webui_require_admin: 'Wenn aktiviert, sehen nur Home-Assistant-Administratoren das Security-Assistant-Seitenpanel.',
      stats_top_n: 'Wie viele Top-Einträge in Statistikdiagrammen gezeigt werden.',
      suricata_listener_enabled: 'Akzeptiert Suricata-EVE-JSON-Alarme per TCP von suricata_pusher.py.',
      suricata_listener_host: 'IP-Adresse für den TCP-Listener (0.0.0.0 für alle Interfaces).',
      suricata_listener_port: 'TCP-Port, mit dem sich der Suricata-Pusher verbindet (Standard 6343).',
      suricata_log_retention_hours: 'Stunden zur Aufbewahrung von Suricata-Alarm-Logeinträgen (0 = unbegrenzt).',
    },
  },
  es: {
    sections: {
      'Network & NetFlow': 'Red y NetFlow',
      'Threat Detection': 'Detección de amenazas',
      'Active Scanner': 'Escáner activo',
      'DNS & Threat Intelligence': 'DNS e inteligencia de amenazas',
      'DNS Proxy': 'Proxy DNS',
      'External IP Enrichment': 'Enriquecimiento de IP externa',
      'NVD Vulnerability Intelligence': 'Inteligencia de vulnerabilidades NVD',
      'Baseline & Behaviour Analysis': 'Línea base y análisis de comportamiento',
      'Display': 'Visualización',
      'Suricata Alert Listener': 'Receptor de alertas Suricata',
    },
    labels: {
      bind_host: 'Host de enlace NetFlow',
      bind_port: 'Puerto de enlace NetFlow',
      enable_netflow_listener: 'Activar receptor NetFlow',
      internal_networks: 'Redes internas',
      scan_window_seconds: 'Ventana de escaneo de puertos (s)',
      scan_port_threshold: 'Umbral de escaneo de puertos',
      high_egress_threshold: 'Umbral de tráfico saliente alto (bytes)',
      enable_scanner: 'Activar escáner',
      scan_interval: 'Intervalo de escaneo (s)',
      scan_ports: 'Puertos a escanear',
      scan_exceptions: 'Excepciones de escaneo',
      enable_dns_resolution: 'Activar resolución DNS',
      blacklist_urls: 'URLs de blacklist',
      dns_proxy_enabled: 'Activar proxy DNS',
      dns_proxy_bind_host: 'Host de enlace del proxy DNS',
      dns_proxy_port: 'Puerto del proxy DNS',
      dns_proxy_upstream: 'Servidor DNS upstream',
      dns_log_retention_hours: 'Retención de logs DNS (h)',
      dns_warn_blocked_logs: 'Logs de aviso para dominios bloqueados',
      dns_blocked_categories: 'Categorías DNS bloqueadas',
      dns_overrides: 'Overrides DNS locales',
      virustotal_api_key: 'Clave API de VirusTotal',
      abuseipdb_api_key: 'Clave API de AbuseIPDB',
      vt_abuseipdb_threshold: 'Umbral de puntuación de amenaza (%)',
      virustotal_daily_budget: 'Presupuesto diario de VirusTotal',
      abuseipdb_daily_budget: 'Presupuesto diario de AbuseIPDB',
      enrichment_ttl_minutes: 'TTL de caché de enriquecimiento (min)',
      external_ip_retention_hours: 'Retención de IP externas (h)',
      retention_suspicious_hours: 'Retención de IP sospechosas (h)',
      retention_malicious_hours: 'Retención de IP maliciosas (h)',
      nvd_api_url: 'URL de API NVD',
      nvd_ttl_hours: 'TTL de caché NVD (h)',
      nvd_min_year: 'Año mínimo CVE',
      nvd_keywords: 'Palabras clave NVD',
      baseline_enabled: 'Activar línea base',
      baseline_training_hours: 'Duración del entrenamiento (h)',
      baseline_min_observations: 'Observaciones mínimas',
      baseline_egress_multiplier: 'Multiplicador de anomalía de egreso',
      webui_require_admin: 'El panel lateral requiere admin',
      stats_top_n: 'Top N de estadísticas',
      suricata_listener_enabled: 'Activar receptor Suricata',
      suricata_listener_host: 'Host de enlace del receptor',
      suricata_listener_port: 'Puerto TCP del receptor',
      suricata_log_retention_hours: 'Retención de logs de alertas (h)',
    },
    helps: {
      bind_host: 'Dirección IP para enlazar el receptor UDP de NetFlow (use 0.0.0.0 para todas las interfaces).',
      bind_port: 'Puerto UDP para datagramas NetFlow v5/v9/IPFIX (2055 por defecto).',
      enable_netflow_listener: 'Activa el receptor UDP NetFlow/IPFIX y la ingesta de flujos.',
      internal_networks: 'Rangos CIDR separados por comas que se consideran internos (p. ej. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Ventana temporal en segundos para detectar escaneo de puertos.',
      scan_port_threshold: 'Número de puertos distintos contactados en la ventana para activar una alerta de escaneo.',
      high_egress_threshold: 'Bytes enviados al exterior para activar una alerta de tráfico saliente alto.',
      enable_scanner: 'Activa el escaneo activo periódico de hosts internos.',
      scan_interval: 'Segundos entre ciclos de escaneo activo.',
      scan_ports: 'Puertos a escanear (rangos y comas permitidos, p. ej. 22,80,443,8080-8090).',
      scan_exceptions: 'IPs separadas por comas a excluir del escaneo activo.',
      enable_dns_resolution: 'Resuelve nombres de host para IP externas y los comprueba contra blacklists.',
      blacklist_urls: 'URLs separadas por comas o saltos de línea de blocklists de inteligencia de amenazas para descargar.',
      dns_proxy_enabled: 'Ejecuta un proxy DNS que registra y opcionalmente bloquea consultas.',
      dns_proxy_bind_host: 'Dirección de enlace del proxy DNS (recomendado: 127.0.0.1 o una IP LAN específica).',
      dns_proxy_port: 'Puerto UDP para el receptor del proxy DNS (53 por defecto, requiere root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP del resolvedor DNS upstream (p. ej. 1.1.1.1).',
      dns_log_retention_hours: 'Cuántas horas conservar entradas del registro DNS (0 = ilimitado).',
      dns_warn_blocked_logs: 'Escribe logs de advertencia para cada consulta DNS bloqueada (desactivado por defecto para reducir ruido).',
      dns_blocked_categories: 'Nombres de categorías separados por comas o saltos de línea para bloquear (p. ej. ads,malware,tracking).',
      dns_overrides: 'Overrides DNS locales, una por línea: hostname=IP (p. ej. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Clave API opcional de VirusTotal para reputación de IP externas.',
      abuseipdb_api_key: 'Clave API opcional de AbuseIPDB para reputación de IP externas.',
      vt_abuseipdb_threshold: 'Puntuación mínima de confianza de abuso (0-100) para marcar una IP como sospechosa.',
      virustotal_daily_budget: 'Máximo de consultas API de VirusTotal por día.',
      abuseipdb_daily_budget: 'Máximo de consultas API de AbuseIPDB por día.',
      enrichment_ttl_minutes: 'Minutos antes de volver a consultar APIs de enriquecimiento para una IP conocida.',
      external_ip_retention_hours: 'Horas para conservar IP externas limpias en el panel.',
      retention_suspicious_hours: 'Horas para conservar IP sospechosas.',
      retention_malicious_hours: 'Horas para conservar IP maliciosas.',
      nvd_api_url: 'URL del endpoint de la API CVE de NVD.',
      nvd_ttl_hours: 'Horas antes de refrescar la caché CVE de NVD.',
      nvd_min_year: 'Mostrar solo CVE publicadas en o después de este año.',
      nvd_keywords: 'Palabras clave de productos separadas por comas para precargar desde NVD (p. ej. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Activa el aprendizaje de línea base de comportamiento y la detección de anomalías.',
      baseline_training_hours: 'Horas de tráfico a observar antes de considerar entrenada la línea base.',
      baseline_min_observations: 'Número mínimo de observaciones de flujo antes de tratar un patrón como normal.',
      baseline_egress_multiplier: 'Cuántas veces debe superarse el egreso de línea base de un dispositivo para marcarlo.',
      webui_require_admin: 'Cuando está activado, solo los usuarios administradores de Home Assistant pueden ver el panel lateral de Security Assistant.',
      stats_top_n: 'Cuántas entradas principales mostrar en los gráficos de estadísticas.',
      suricata_listener_enabled: 'Acepta alertas Suricata EVE JSON por TCP desde suricata_pusher.py.',
      suricata_listener_host: 'Dirección IP para enlazar el receptor TCP (0.0.0.0 para todas las interfaces).',
      suricata_listener_port: 'Puerto TCP para conectar el pusher de Suricata (6343 por defecto).',
      suricata_log_retention_hours: 'Horas para conservar entradas del log de alertas de Suricata (0 = ilimitado).',
    },
  },
  it: {
    sections: {
      'Network & NetFlow': 'Rete e NetFlow',
      'Threat Detection': 'Rilevamento minacce',
      'Active Scanner': 'Scanner attivo',
      'DNS & Threat Intelligence': 'DNS e threat intelligence',
      'DNS Proxy': 'Proxy DNS',
      'External IP Enrichment': 'Arricchimento IP esterni',
      'NVD Vulnerability Intelligence': 'Intelligence vulnerabilità NVD',
      'Baseline & Behaviour Analysis': 'Baseline e analisi comportamentale',
      'Display': 'Visualizzazione',
      'Suricata Alert Listener': 'Listener avvisi Suricata',
    },
    labels: {
      bind_host: 'Host di bind NetFlow',
      bind_port: 'Porta di bind NetFlow',
      enable_netflow_listener: 'Abilita listener NetFlow',
      internal_networks: 'Reti interne',
      scan_window_seconds: 'Finestra scansione porte (s)',
      scan_port_threshold: 'Soglia scansione porte',
      high_egress_threshold: 'Soglia traffico in uscita elevato (byte)',
      enable_scanner: 'Abilita scanner',
      scan_interval: 'Intervallo scansione (s)',
      scan_ports: 'Porte da scansionare',
      scan_exceptions: 'Eccezioni scansione',
      enable_dns_resolution: 'Abilita risoluzione DNS',
      blacklist_urls: 'URL blacklist',
      dns_proxy_enabled: 'Abilita proxy DNS',
      dns_proxy_bind_host: 'Host di bind proxy DNS',
      dns_proxy_port: 'Porta proxy DNS',
      dns_proxy_upstream: 'Server DNS upstream',
      dns_log_retention_hours: 'Conservazione log DNS (h)',
      dns_warn_blocked_logs: 'Log di avviso per domini bloccati',
      dns_blocked_categories: 'Categorie DNS bloccate',
      dns_overrides: 'Override DNS locali',
      virustotal_api_key: 'Chiave API VirusTotal',
      abuseipdb_api_key: 'Chiave API AbuseIPDB',
      vt_abuseipdb_threshold: 'Soglia punteggio minaccia (%)',
      virustotal_daily_budget: 'Budget giornaliero VirusTotal',
      abuseipdb_daily_budget: 'Budget giornaliero AbuseIPDB',
      enrichment_ttl_minutes: 'TTL cache arricchimento (min)',
      external_ip_retention_hours: 'Conservazione IP esterni (h)',
      retention_suspicious_hours: 'Conservazione IP sospetti (h)',
      retention_malicious_hours: 'Conservazione IP malevoli (h)',
      nvd_api_url: 'URL API NVD',
      nvd_ttl_hours: 'TTL cache NVD (h)',
      nvd_min_year: 'Anno minimo CVE',
      nvd_keywords: 'Parole chiave NVD',
      baseline_enabled: 'Abilita baseline',
      baseline_training_hours: 'Durata training (h)',
      baseline_min_observations: 'Osservazioni minime',
      baseline_egress_multiplier: 'Moltiplicatore anomalia egress',
      webui_require_admin: 'Il pannello sidebar richiede admin',
      stats_top_n: 'Top N statistiche',
      suricata_listener_enabled: 'Abilita listener Suricata',
      suricata_listener_host: 'Host di bind listener',
      suricata_listener_port: 'Porta TCP listener',
      suricata_log_retention_hours: 'Conservazione log avvisi (h)',
    },
    helps: {
      bind_host: 'Indirizzo IP su cui collegare il listener UDP NetFlow (usa 0.0.0.0 per tutte le interfacce).',
      bind_port: 'Porta UDP per datagrammi NetFlow v5/v9/IPFIX (default 2055).',
      enable_netflow_listener: 'Abilita listener UDP NetFlow/IPFIX e ingestione dei flussi.',
      internal_networks: 'Intervalli CIDR separati da virgola considerati interni (es. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Finestra temporale in secondi per il rilevamento scansione porte.',
      scan_port_threshold: 'Numero di porte distinte contattate nella finestra per generare un avviso di scansione porte.',
      high_egress_threshold: 'Byte inviati in uscita per generare un avviso di traffico elevato.',
      enable_scanner: 'Abilita la scansione attiva periodica delle porte sugli host interni.',
      scan_interval: 'Secondi tra i cicli di scansione attiva.',
      scan_ports: 'Porte da scansionare (range e virgole consentiti, es. 22,80,443,8080-8090).',
      scan_exceptions: 'IP separate da virgole da escludere dalla scansione attiva.',
      enable_dns_resolution: 'Risolvi hostname per IP esterni e confrontali con le blacklist.',
      blacklist_urls: 'URL di blocklist threat-intel separati da virgole o nuove righe da scaricare.',
      dns_proxy_enabled: 'Esegue un proxy DNS che registra e opzionalmente blocca le query.',
      dns_proxy_bind_host: 'Indirizzo di bind per il proxy DNS (consigliato: 127.0.0.1 o un IP LAN specifico).',
      dns_proxy_port: 'Porta UDP del listener proxy DNS (default 53, richiede root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP del resolver DNS upstream (es. 1.1.1.1).',
      dns_log_retention_hours: 'Quante ore mantenere le voci del log query DNS (0 = illimitato).',
      dns_warn_blocked_logs: 'Scrive log di warning per ogni query DNS bloccata (disabilitato per default per ridurre rumore).',
      dns_blocked_categories: 'Nomi categoria separati da virgole o nuove righe da bloccare (es. ads,malware,tracking).',
      dns_overrides: 'Override DNS locali, una riga per voce: hostname=IP (es. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Chiave API VirusTotal opzionale per reputazione IP esterne.',
      abuseipdb_api_key: 'Chiave API AbuseIPDB opzionale per reputazione IP esterne.',
      vt_abuseipdb_threshold: 'Punteggio minimo di confidenza abuso (0-100) per segnalare un IP come sospetto.',
      virustotal_daily_budget: 'Massimo numero di lookup API VirusTotal al giorno.',
      abuseipdb_daily_budget: 'Massimo numero di lookup API AbuseIPDB al giorno.',
      enrichment_ttl_minutes: 'Minuti prima di interrogare di nuovo le API di arricchimento per un IP noto.',
      external_ip_retention_hours: 'Ore per mantenere IP esterni puliti nella dashboard.',
      retention_suspicious_hours: 'Ore per mantenere IP sospetti.',
      retention_malicious_hours: 'Ore per mantenere IP malevoli.',
      nvd_api_url: 'URL endpoint API CVE NVD.',
      nvd_ttl_hours: 'Ore prima di aggiornare la cache CVE NVD.',
      nvd_min_year: 'Mostra solo CVE pubblicate da questo anno in poi.',
      nvd_keywords: 'Parole chiave prodotto separate da virgole da prelevare da NVD (es. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Abilita apprendimento baseline comportamentale e rilevamento anomalie.',
      baseline_training_hours: 'Ore di traffico da osservare prima di considerare la baseline addestrata.',
      baseline_min_observations: 'Numero minimo di osservazioni di flusso prima di considerare un pattern normale.',
      baseline_egress_multiplier: 'Quante volte l\'egress baseline di un dispositivo deve essere superato prima della segnalazione.',
      webui_require_admin: 'Se abilitato, solo gli utenti admin Home Assistant possono vedere il pannello sidebar Security Assistant.',
      stats_top_n: 'Quante voci principali mostrare nei grafici statistici.',
      suricata_listener_enabled: 'Accetta avvisi Suricata EVE JSON via TCP da suricata_pusher.py.',
      suricata_listener_host: 'Indirizzo IP su cui collegare il listener TCP (0.0.0.0 per tutte le interfacce).',
      suricata_listener_port: 'Porta TCP a cui si connette il pusher Suricata (default 6343).',
      suricata_log_retention_hours: 'Ore di conservazione voci log avvisi Suricata (0 = illimitato).',
    },
  },
  de: {
    sections: {
      'Network & NetFlow': 'Netzwerk und NetFlow',
      'Threat Detection': 'Bedrohungserkennung',
      'Active Scanner': 'Aktiver Scanner',
      'DNS & Threat Intelligence': 'DNS und Threat Intelligence',
      'DNS Proxy': 'DNS-Proxy',
      'External IP Enrichment': 'Externe IP-Anreicherung',
      'NVD Vulnerability Intelligence': 'NVD-Schwachstelleninformationen',
      'Baseline & Behaviour Analysis': 'Baseline- und Verhaltensanalyse',
      'Display': 'Anzeige',
      'Suricata Alert Listener': 'Suricata-Alarm-Listener',
    },
    labels: {
      bind_host: 'NetFlow-Bind-Host',
      bind_port: 'NetFlow-Bind-Port',
      enable_netflow_listener: 'NetFlow-Listener aktivieren',
      internal_networks: 'Interne Netzwerke',
      scan_window_seconds: 'Portscan-Fenster (s)',
      scan_port_threshold: 'Portscan-Schwellenwert',
      high_egress_threshold: 'Schwellenwert hoher Egress-Traffic (Bytes)',
      enable_scanner: 'Scanner aktivieren',
      scan_interval: 'Scan-Intervall (s)',
      scan_ports: 'Zu scannende Ports',
      scan_exceptions: 'Scan-Ausnahmen',
      enable_dns_resolution: 'DNS-Auflösung aktivieren',
      blacklist_urls: 'Blacklist-URLs',
      dns_proxy_enabled: 'DNS-Proxy aktivieren',
      dns_proxy_bind_host: 'DNS-Proxy-Bind-Host',
      dns_proxy_port: 'DNS-Proxy-Port',
      dns_proxy_upstream: 'Upstream-DNS-Server',
      dns_log_retention_hours: 'DNS-Log-Aufbewahrung (h)',
      dns_warn_blocked_logs: 'Warn-Logs für blockierte Domains',
      dns_blocked_categories: 'Blockierte DNS-Kategorien',
      dns_overrides: 'Lokale DNS-Overrides',
      virustotal_api_key: 'VirusTotal-API-Schlüssel',
      abuseipdb_api_key: 'AbuseIPDB-API-Schlüssel',
      vt_abuseipdb_threshold: 'Bedrohungsscore-Schwelle (%)',
      virustotal_daily_budget: 'VirusTotal-Tagesbudget',
      abuseipdb_daily_budget: 'AbuseIPDB-Tagesbudget',
      enrichment_ttl_minutes: 'Anreicherungs-Cache-TTL (min)',
      external_ip_retention_hours: 'Externe-IP-Aufbewahrung (h)',
      retention_suspicious_hours: 'Aufbewahrung verdächtiger IPs (h)',
      retention_malicious_hours: 'Aufbewahrung bösartiger IPs (h)',
      nvd_api_url: 'NVD-API-URL',
      nvd_ttl_hours: 'NVD-Cache-TTL (h)',
      nvd_min_year: 'CVE-Mindestjahr',
      nvd_keywords: 'NVD-Schlüsselwörter',
      baseline_enabled: 'Baseline aktivieren',
      baseline_training_hours: 'Trainingsdauer (h)',
      baseline_min_observations: 'Minimale Beobachtungen',
      baseline_egress_multiplier: 'Egress-Anomalie-Multiplikator',
      webui_require_admin: 'Sidebar-Panel erfordert Admin',
      stats_top_n: 'Statistiken Top N',
      suricata_listener_enabled: 'Suricata-Listener aktivieren',
      suricata_listener_host: 'Listener-Bind-Host',
      suricata_listener_port: 'Listener-TCP-Port',
      suricata_log_retention_hours: 'Alarm-Log-Aufbewahrung (h)',
    },
    helps: {
      bind_host: 'IP-Adresse, an die der NetFlow-UDP-Listener gebunden wird (0.0.0.0 für alle Interfaces).',
      bind_port: 'UDP-Port für NetFlow-v5/v9/IPFIX-Datagramme (Standard: 2055).',
      enable_netflow_listener: 'Aktiviert den UDP-NetFlow/IPFIX-Listener und die Flow-Erfassung.',
      internal_networks: 'Kommagetrennte CIDR-Bereiche, die als intern gelten (z. B. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Zeitfenster in Sekunden für die Portscan-Erkennung.',
      scan_port_threshold: 'Anzahl unterschiedlicher Ports im Fenster, um einen Portscan-Alarm auszulösen.',
      high_egress_threshold: 'Ausgehend gesendete Bytes, um einen High-Egress-Alarm auszulösen.',
      enable_scanner: 'Aktiviert periodische aktive Portscans interner Hosts.',
      scan_interval: 'Sekunden zwischen aktiven Scan-Zyklen.',
      scan_ports: 'Zu scannende Ports (Bereiche und Kommas erlaubt, z. B. 22,80,443,8080-8090).',
      scan_exceptions: 'Kommagetrennte IPs, die vom aktiven Scan ausgeschlossen werden.',
      enable_dns_resolution: 'Löst Hostnamen für externe IPs auf und prüft sie gegen Blacklists.',
      blacklist_urls: 'URL-Liste von Threat-Intel-Blocklisten, getrennt durch Komma oder Zeilenumbruch.',
      dns_proxy_enabled: 'Startet einen DNS-Proxy, der Anfragen protokolliert und optional blockiert.',
      dns_proxy_bind_host: 'Bind-Adresse für den DNS-Proxy (empfohlen: 127.0.0.1 oder eine spezifische LAN-IP).',
      dns_proxy_port: 'UDP-Port des DNS-Proxy-Listeners (Standard 53, benötigt root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP des Upstream-DNS-Resolvers (z. B. 1.1.1.1).',
      dns_log_retention_hours: 'Stunden, wie lange DNS-Logeinträge aufbewahrt werden (0 = unbegrenzt).',
      dns_warn_blocked_logs: 'Schreibt Warn-Logs für jede blockierte DNS-Anfrage (standardmäßig aus, um Log-Rauschen zu reduzieren).',
      dns_blocked_categories: 'Kategorie-Namen zum Blockieren, per Komma oder Zeilenumbruch getrennt (z. B. ads,malware,tracking).',
      dns_overrides: 'Lokale DNS-Overrides, eine Zeile pro Eintrag: hostname=IP (z. B. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Optionaler VirusTotal-API-Schlüssel für externe IP-Reputationsabfragen.',
      abuseipdb_api_key: 'Optionaler AbuseIPDB-API-Schlüssel für externe IP-Reputationsabfragen.',
      vt_abuseipdb_threshold: 'Minimaler Abuse-Confidence-Score (0-100), um eine IP als verdächtig zu markieren.',
      virustotal_daily_budget: 'Maximale Anzahl VirusTotal-API-Abfragen pro Tag.',
      abuseipdb_daily_budget: 'Maximale Anzahl AbuseIPDB-API-Abfragen pro Tag.',
      enrichment_ttl_minutes: 'Minuten bis zur erneuten Abfrage von Anreicherungs-APIs für eine bekannte IP.',
      external_ip_retention_hours: 'Stunden zur Aufbewahrung unauffälliger externer IPs im Dashboard.',
      retention_suspicious_hours: 'Stunden zur Aufbewahrung verdächtiger IPs.',
      retention_malicious_hours: 'Stunden zur Aufbewahrung bösartiger IPs.',
      nvd_api_url: 'NVD-CVE-API-Endpunkt-URL.',
      nvd_ttl_hours: 'Stunden bis zur Aktualisierung des NVD-CVE-Caches.',
      nvd_min_year: 'Zeigt nur CVEs, die in oder nach diesem Jahr veröffentlicht wurden.',
      nvd_keywords: 'Kommagetrennte Produkt-Schlüsselwörter zum Vorabruf aus NVD (z. B. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Aktiviert Verhaltens-Baseline-Lernen und Anomalieerkennung.',
      baseline_training_hours: 'Stunden Traffic-Beobachtung, bevor die Baseline als trainiert gilt.',
      baseline_min_observations: 'Minimale Anzahl Flow-Beobachtungen, bevor ein Muster als normal gilt.',
      baseline_egress_multiplier: 'Faktor, um den Baseline-Egress eines Geräts überschritten werden muss, bevor es markiert wird.',
      webui_require_admin: 'Wenn aktiviert, können nur Home-Assistant-Admins das Security-Assistant-Sidebar-Panel sehen.',
      stats_top_n: 'Anzahl der Top-Einträge in Statistikdiagrammen.',
      suricata_listener_enabled: 'Akzeptiert Suricata-EVE-JSON-Alarme per TCP von suricata_pusher.py.',
      suricata_listener_host: 'IP-Adresse zum Binden des TCP-Listeners (0.0.0.0 für alle Interfaces).',
      suricata_listener_port: 'TCP-Port, mit dem sich der Suricata-Pusher verbindet (Standard: 6343).',
      suricata_log_retention_hours: 'Stunden zur Aufbewahrung von Suricata-Alarm-Logs (0 = unbegrenzt).',
    },
  },
  es: {
    sections: {
      'Network & NetFlow': 'Red y NetFlow',
      'Threat Detection': 'Detección de amenazas',
      'Active Scanner': 'Escáner activo',
      'DNS & Threat Intelligence': 'DNS e inteligencia de amenazas',
      'DNS Proxy': 'Proxy DNS',
      'External IP Enrichment': 'Enriquecimiento de IP externas',
      'NVD Vulnerability Intelligence': 'Inteligencia de vulnerabilidades NVD',
      'Baseline & Behaviour Analysis': 'Línea base y análisis de comportamiento',
      'Display': 'Visualización',
      'Suricata Alert Listener': 'Receptor de alertas Suricata',
    },
    labels: {
      bind_host: 'Host de enlace NetFlow',
      bind_port: 'Puerto de enlace NetFlow',
      enable_netflow_listener: 'Activar receptor NetFlow',
      internal_networks: 'Redes internas',
      scan_window_seconds: 'Ventana de escaneo de puertos (s)',
      scan_port_threshold: 'Umbral de escaneo de puertos',
      high_egress_threshold: 'Umbral de tráfico saliente alto (bytes)',
      enable_scanner: 'Activar escáner',
      scan_interval: 'Intervalo de escaneo (s)',
      scan_ports: 'Puertos a escanear',
      scan_exceptions: 'Excepciones de escaneo',
      enable_dns_resolution: 'Activar resolución DNS',
      blacklist_urls: 'URLs de blacklist',
      dns_proxy_enabled: 'Activar proxy DNS',
      dns_proxy_bind_host: 'Host de enlace del proxy DNS',
      dns_proxy_port: 'Puerto del proxy DNS',
      dns_proxy_upstream: 'Servidor DNS ascendente',
      dns_log_retention_hours: 'Retención de logs DNS (h)',
      dns_warn_blocked_logs: 'Logs de advertencia para dominios bloqueados',
      dns_blocked_categories: 'Categorías DNS bloqueadas',
      dns_overrides: 'Overrides DNS locales',
      virustotal_api_key: 'Clave API de VirusTotal',
      abuseipdb_api_key: 'Clave API de AbuseIPDB',
      vt_abuseipdb_threshold: 'Umbral de puntuación de amenaza (%)',
      virustotal_daily_budget: 'Presupuesto diario de VirusTotal',
      abuseipdb_daily_budget: 'Presupuesto diario de AbuseIPDB',
      enrichment_ttl_minutes: 'TTL de caché de enriquecimiento (min)',
      external_ip_retention_hours: 'Retención de IP externas (h)',
      retention_suspicious_hours: 'Retención de IP sospechosas (h)',
      retention_malicious_hours: 'Retención de IP maliciosas (h)',
      nvd_api_url: 'URL de API NVD',
      nvd_ttl_hours: 'TTL de caché NVD (h)',
      nvd_min_year: 'Año mínimo CVE',
      nvd_keywords: 'Palabras clave NVD',
      baseline_enabled: 'Activar línea base',
      baseline_training_hours: 'Duración de entrenamiento (h)',
      baseline_min_observations: 'Observaciones mínimas',
      baseline_egress_multiplier: 'Multiplicador de anomalía de salida',
      webui_require_admin: 'El panel lateral requiere admin',
      stats_top_n: 'Top N de estadísticas',
      suricata_listener_enabled: 'Activar receptor Suricata',
      suricata_listener_host: 'Host de enlace del receptor',
      suricata_listener_port: 'Puerto TCP del receptor',
      suricata_log_retention_hours: 'Retención de logs de alertas (h)',
    },
    helps: {
      bind_host: 'Dirección IP donde enlazar el receptor UDP NetFlow (usa 0.0.0.0 para todas las interfaces).',
      bind_port: 'Puerto UDP para datagramas NetFlow v5/v9/IPFIX (2055 por defecto).',
      enable_netflow_listener: 'Activa el receptor UDP NetFlow/IPFIX y la ingesta de flujos.',
      internal_networks: 'Rangos CIDR separados por comas considerados internos (p. ej. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Ventana temporal en segundos para detección de escaneo de puertos.',
      scan_port_threshold: 'Número de puertos distintos contactados en la ventana para disparar una alerta de escaneo.',
      high_egress_threshold: 'Bytes enviados al exterior para disparar una alerta de alto tráfico saliente.',
      enable_scanner: 'Activa el escaneo activo periódico de hosts internos.',
      scan_interval: 'Segundos entre ciclos de escaneo activo.',
      scan_ports: 'Puertos a escanear (se permiten rangos y comas, p. ej. 22,80,443,8080-8090).',
      scan_exceptions: 'IPs separadas por comas que se excluirán del escaneo activo.',
      enable_dns_resolution: 'Resuelve nombres de host para IPs externas y los verifica contra blacklists.',
      blacklist_urls: 'URLs de listas de bloqueo threat-intel separadas por coma o salto de línea.',
      dns_proxy_enabled: 'Ejecuta un proxy DNS que registra y opcionalmente bloquea consultas.',
      dns_proxy_bind_host: 'Dirección de enlace del proxy DNS (recomendado: 127.0.0.1 o una IP LAN específica).',
      dns_proxy_port: 'Puerto UDP del receptor del proxy DNS (53 por defecto; requiere root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP del resolvedor DNS ascendente (p. ej. 1.1.1.1).',
      dns_log_retention_hours: 'Cuántas horas conservar entradas del log DNS (0 = ilimitado).',
      dns_warn_blocked_logs: 'Escribe logs de advertencia por cada consulta DNS bloqueada (desactivado por defecto para reducir ruido).',
      dns_blocked_categories: 'Categorías a bloquear separadas por coma o salto de línea (p. ej. ads,malware,tracking).',
      dns_overrides: 'Overrides DNS locales, una por línea: hostname=IP (p. ej. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Clave API opcional de VirusTotal para reputación de IPs externas.',
      abuseipdb_api_key: 'Clave API opcional de AbuseIPDB para reputación de IPs externas.',
      vt_abuseipdb_threshold: 'Puntuación mínima de confianza de abuso (0-100) para marcar una IP como sospechosa.',
      virustotal_daily_budget: 'Máximo de consultas API de VirusTotal por día.',
      abuseipdb_daily_budget: 'Máximo de consultas API de AbuseIPDB por día.',
      enrichment_ttl_minutes: 'Minutos antes de volver a consultar APIs de enriquecimiento para una IP conocida.',
      external_ip_retention_hours: 'Horas para retener IPs externas limpias en el panel.',
      retention_suspicious_hours: 'Horas para retener IPs sospechosas.',
      retention_malicious_hours: 'Horas para retener IPs maliciosas.',
      nvd_api_url: 'URL del endpoint API CVE de NVD.',
      nvd_ttl_hours: 'Horas antes de refrescar la caché CVE de NVD.',
      nvd_min_year: 'Mostrar solo CVEs publicadas en o después de este año.',
      nvd_keywords: 'Palabras clave de productos separadas por comas para precargar desde NVD (p. ej. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Activa el aprendizaje de línea base de comportamiento y detección de anomalías.',
      baseline_training_hours: 'Horas de tráfico a observar antes de considerar entrenada la línea base.',
      baseline_min_observations: 'Número mínimo de observaciones de flujo antes de tratar un patrón como normal.',
      baseline_egress_multiplier: 'Cuántas veces debe superar un dispositivo su tráfico saliente de línea base para marcarse.',
      webui_require_admin: 'Si está activado, solo usuarios administradores de Home Assistant podrán ver el panel lateral de Security Assistant.',
      stats_top_n: 'Cuántas entradas superiores mostrar en los gráficos de estadísticas.',
      suricata_listener_enabled: 'Acepta alertas Suricata EVE JSON por TCP desde suricata_pusher.py.',
      suricata_listener_host: 'Dirección IP para enlazar el receptor TCP (0.0.0.0 para todas las interfaces).',
      suricata_listener_port: 'Puerto TCP al que se conecta el pusher de Suricata (6343 por defecto).',
      suricata_log_retention_hours: 'Horas para conservar entradas de log de alertas Suricata (0 = ilimitado).',
    },
  },
  it: {
    sections: {
      'Network & NetFlow': 'Rete e NetFlow',
      'Threat Detection': 'Rilevamento minacce',
      'Active Scanner': 'Scanner attivo',
      'DNS & Threat Intelligence': 'DNS e threat intelligence',
      'DNS Proxy': 'Proxy DNS',
      'External IP Enrichment': 'Arricchimento IP esterni',
      'NVD Vulnerability Intelligence': 'Intelligence vulnerabilità NVD',
      'Baseline & Behaviour Analysis': 'Baseline e analisi comportamentale',
      'Display': 'Visualizzazione',
      'Suricata Alert Listener': 'Listener allerte Suricata',
    },
    labels: {
      bind_host: 'Host bind NetFlow',
      bind_port: 'Porta bind NetFlow',
      enable_netflow_listener: 'Abilita listener NetFlow',
      internal_networks: 'Reti interne',
      scan_window_seconds: 'Finestra scansione porte (s)',
      scan_port_threshold: 'Soglia scansione porte',
      high_egress_threshold: 'Soglia traffico uscente elevato (byte)',
      enable_scanner: 'Abilita scanner',
      scan_interval: 'Intervallo scansione (s)',
      scan_ports: 'Porte da scansionare',
      scan_exceptions: 'Eccezioni scansione',
      enable_dns_resolution: 'Abilita risoluzione DNS',
      blacklist_urls: 'URL blacklist',
      dns_proxy_enabled: 'Abilita proxy DNS',
      dns_proxy_bind_host: 'Host bind proxy DNS',
      dns_proxy_port: 'Porta proxy DNS',
      dns_proxy_upstream: 'Server DNS upstream',
      dns_log_retention_hours: 'Retention log DNS (h)',
      dns_warn_blocked_logs: 'Log warning per domini bloccati',
      dns_blocked_categories: 'Categorie DNS bloccate',
      dns_overrides: 'Override DNS locali',
      virustotal_api_key: 'Chiave API VirusTotal',
      abuseipdb_api_key: 'Chiave API AbuseIPDB',
      vt_abuseipdb_threshold: 'Soglia punteggio minaccia (%)',
      virustotal_daily_budget: 'Budget giornaliero VirusTotal',
      abuseipdb_daily_budget: 'Budget giornaliero AbuseIPDB',
      enrichment_ttl_minutes: 'TTL cache arricchimento (min)',
      external_ip_retention_hours: 'Retention IP esterni (h)',
      retention_suspicious_hours: 'Retention IP sospetti (h)',
      retention_malicious_hours: 'Retention IP malevoli (h)',
      nvd_api_url: 'URL API NVD',
      nvd_ttl_hours: 'TTL cache NVD (h)',
      nvd_min_year: 'Anno minimo CVE',
      nvd_keywords: 'Parole chiave NVD',
      baseline_enabled: 'Abilita baseline',
      baseline_training_hours: 'Durata training (h)',
      baseline_min_observations: 'Osservazioni minime',
      baseline_egress_multiplier: 'Moltiplicatore anomalia egress',
      webui_require_admin: 'Il pannello sidebar richiede admin',
      stats_top_n: 'Statistiche Top N',
      suricata_listener_enabled: 'Abilita listener Suricata',
      suricata_listener_host: 'Host bind listener',
      suricata_listener_port: 'Porta TCP listener',
      suricata_log_retention_hours: 'Retention log allerte (h)',
    },
    helps: {
      bind_host: 'Indirizzo IP su cui fare bind del listener NetFlow UDP (usa 0.0.0.0 per tutte le interfacce).',
      bind_port: 'Porta UDP per datagrammi NetFlow v5/v9/IPFIX (default 2055).',
      enable_netflow_listener: 'Abilita listener UDP NetFlow/IPFIX e ingestione flussi.',
      internal_networks: 'Intervalli CIDR separati da virgola considerati interni (es. 192.168.0.0/16,10.0.0.0/8).',
      scan_window_seconds: 'Finestra temporale in secondi per rilevamento scansione porte.',
      scan_port_threshold: 'Numero di porte distinte contattate nella finestra per attivare un alert di scansione porte.',
      high_egress_threshold: 'Byte inviati in uscita per attivare un alert di traffico uscente elevato.',
      enable_scanner: 'Abilita scansione attiva periodica delle porte degli host interni.',
      scan_interval: 'Secondi tra i cicli di scansione attiva.',
      scan_ports: 'Porte da scansionare (range e virgole consentiti, es. 22,80,443,8080-8090).',
      scan_exceptions: 'IP separati da virgole da escludere dalla scansione attiva.',
      enable_dns_resolution: 'Risolvi hostname per IP esterni e verifica contro blacklist.',
      blacklist_urls: 'URL di blocklist threat-intel separati da virgola o nuova riga.',
      dns_proxy_enabled: 'Esegue un proxy DNS che registra e opzionalmente blocca query.',
      dns_proxy_bind_host: 'Indirizzo bind del proxy DNS (consigliato: 127.0.0.1 o IP LAN specifico).',
      dns_proxy_port: 'Porta UDP per listener proxy DNS (default 53, richiede root/CAP_NET_BIND_SERVICE).',
      dns_proxy_upstream: 'IP del resolver DNS upstream (es. 1.1.1.1).',
      dns_log_retention_hours: 'Ore di conservazione delle voci del log DNS (0 = illimitato).',
      dns_warn_blocked_logs: 'Scrive log warning per ogni query DNS bloccata (disabilitato di default per ridurre rumore).',
      dns_blocked_categories: 'Nomi categoria da bloccare, separati da virgola o nuova riga (es. ads,malware,tracking).',
      dns_overrides: 'Override DNS locali, una riga per voce: hostname=IP (es. myhost.local=192.168.1.5).',
      virustotal_api_key: 'Chiave API VirusTotal opzionale per lookup reputazione IP esterni.',
      abuseipdb_api_key: 'Chiave API AbuseIPDB opzionale per lookup reputazione IP esterni.',
      vt_abuseipdb_threshold: 'Punteggio minimo di abuso (0-100) per contrassegnare un IP come sospetto.',
      virustotal_daily_budget: 'Numero massimo di lookup API VirusTotal al giorno.',
      abuseipdb_daily_budget: 'Numero massimo di lookup API AbuseIPDB al giorno.',
      enrichment_ttl_minutes: 'Minuti prima di interrogare di nuovo le API di arricchimento per un IP noto.',
      external_ip_retention_hours: 'Ore di conservazione degli IP esterni puliti nella dashboard.',
      retention_suspicious_hours: 'Ore di conservazione degli IP sospetti.',
      retention_malicious_hours: 'Ore di conservazione degli IP malevoli.',
      nvd_api_url: 'URL endpoint API CVE NVD.',
      nvd_ttl_hours: 'Ore prima di aggiornare la cache CVE NVD.',
      nvd_min_year: 'Mostra solo CVE pubblicate da questo anno in poi.',
      nvd_keywords: 'Parole chiave prodotto separate da virgola da prelevare da NVD (es. OpenSSH,nginx,Samba).',
      baseline_enabled: 'Abilita apprendimento baseline comportamentale e rilevamento anomalie.',
      baseline_training_hours: 'Ore di traffico da osservare prima di considerare la baseline addestrata.',
      baseline_min_observations: 'Numero minimo di osservazioni di flusso prima di considerare normale un pattern.',
      baseline_egress_multiplier: 'Quante volte il traffico egress baseline di un dispositivo deve essere superato prima di segnalarlo.',
      webui_require_admin: 'Se abilitato, solo gli utenti admin Home Assistant possono vedere il pannello sidebar Security Assistant.',
      stats_top_n: 'Quante voci principali mostrare nei grafici statistici.',
      suricata_listener_enabled: 'Accetta alert Suricata EVE JSON via TCP da suricata_pusher.py.',
      suricata_listener_host: 'Indirizzo IP su cui fare bind del listener TCP (0.0.0.0 per tutte le interfacce).',
      suricata_listener_port: 'Porta TCP a cui si connette il pusher Suricata (default 6343).',
      suricata_log_retention_hours: 'Ore di conservazione delle voci di log allerte Suricata (0 = illimitato).',
    },
  },
};

const _VIEW_ICONS = {
  overview:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>`,
  map:             `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.5 3l-.16.03L15 5.1 9 3 3.36 4.9c-.21.07-.36.25-.36.48V20.5c0 .28.22.5.5.5l.16-.03L9 18.9l6 2.1 5.64-1.9c.21-.07.36-.25.36-.48V3.5c0-.28-.22-.5-.5-.5zM15 19l-6-2.11V5l6 2.11V19z"/></svg>`,
  hosts:           `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 3H4v10c0 2.21 1.79 4 4 4h6c2.21 0 4-1.79 4-4v-3h2c1.11 0 2-.89 2-2V5c0-1.11-.89-2-2-2zm0 5h-2V5h2v3zM4 19h16v2H4z"/></svg>`,
  findings:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z"/></svg>`,
  external:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`,
  vulnerabilities:  `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14.4 6L14 4H5v17h2v-7h5.6l.4 2h7V6h-5.6z"/></svg>`,
  statistics:      `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11 2v20c-5.07-.5-9-4.79-9-10s3.93-9.5 9-10zm2.03 0v8.99H22c-.47-4.74-4.24-8.52-8.97-8.99zm0 11.01V22c4.74-.47 8.5-4.25 8.97-8.99h-8.97z"/></svg>`,
  dns:             `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`,
  suricata:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm1 14h-2v-2h2v2zm0-4h-2V7h2v4z"/></svg>`,
  recommendations: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>`,
  settings:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>`,
};

class HomeSecurityAssistantPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._view        = 'overview';
    this._data        = null;
    this._hass        = null;
    this._loading     = false;
    this._error       = null;
    this._refreshTimer = null;
    this._mapNodes     = new Map();
    this._mapEdges     = [];
    this._mapAnim      = null;
    this._mapTick      = 0;
    this._mapZoom      = 1;
    this._mapPanX      = 0;
    this._mapPanY      = 0;
    this._mapDragging  = false;
    this._mapDragLastX = 0;
    this._mapDragLastY = 0;
    this._mapPinchDist = null;
    this._mapPinchMidX = 0;
    this._mapPinchMidY = 0;
    this._lookupIP     = null;
    this._lookingUp    = false;
    this._lookupResult = null;
    this._vulnData     = null;
    this._vulnLoading  = false;
    this._vulnFilter   = '';
    this._vulnPage     = 1;
    this._vulnPageSize = 25;
    this._vulnSort     = 'cvss';
    this._vulnSortDir  = -1;
    this._hostFilter   = '';
    this._hostSort     = 'ip';
    this._hostSortDir  = 1;
    this._extFilter    = '';
    this._extSort      = 'rating';
    this._extSortDir   = 1;
    this._extPage      = 1;
    this._extPageSize  = 25;
    this._extIPDetail  = null;
    this._editorOpen   = false;
    this._editorMode   = '';
    this._editorIP     = '';
    this._editorTitle  = '';
    this._editorHelp   = '';
    this._editorValue  = '';
    this._editorPlaceholder = '';
    this._vulnDetail   = null;
    this._expandedRec  = null;
    this._findingsGroupMode    = 'category'; // 'category' | 'host' | 'severity' | 'flat'
    this._dismissedGroupMode   = 'category'; // 'category' | 'host' | 'severity' | 'flat'
    this._findingsSearch       = '';
    this._baselineSearch       = '';
    this._dismissedSearch      = '';
    this._expandedFindingGroup = null;
    this._showBaselineFindings = true;
    this._baselineGroupMode    = 'category'; // 'category' | 'host' | 'flat'
    this._expandedBaselineGroup = null;
    this._regexDismissOpen     = false;
    this._regexDismissPattern  = '';
    this._regexDismissNote     = '';
    this._mapFilter    = 'all';
    this._mapMode      = 'live';
    this._mapBaselineGraph = null;
    this._mapParticles = [];
    this._statsViewModes = { public_ips: 'pie', countries: 'pie', talkers: 'pie', threat_ips: 'pie', dns_categories: 'pie', dns_clients: 'pie', host_findings: 'pie', ext_deviations: 'pie', suricata_severity: 'pie', suricata_category: 'pie', suricata_src: 'pie' };
    this._dnsSearch = '';
    this._dnsCategoryFilter = '';
    this._dnsStatusFilter = '';
    this._dnsMaliciousOnly = false;
    this._dnsSort = 'time';
    this._dnsSortDir = -1;
    this._suricataSearch = '';
    this._suricataSeverityFilter = '';
    this._suricataActionFilter = '';
    this._suricataSort = 'time';
    this._suricataSortDir = -1;
    this._suricataPage = 0;
    this._suricataPageSize = 25;
    this._suricataAlertDetail = null;
    this._mobileMenuOpen = false;
    this._settingsData    = null;
    this._settingsLoading = false;
    this._settingsMsg     = '';
    this._settingsMsgType = '';
    this._settingsDraft   = null;
    this._settingsDirty   = false;
    this._pendingView     = null;
    this._beforeUnloadHandler = null;
  }

  set hass(v) {
    this._hass = v;
    if (!this._data && !this._loading) this._fetch();
  }

  connectedCallback()    { this._startRefresh(); }

  disconnectedCallback() {
    this._stopRefresh();
    this._stopMap();
    this._unregisterBeforeUnload();
  }

  _registerBeforeUnload() {
    if (this._beforeUnloadHandler) return;
    this._beforeUnloadHandler = (e) => {
      if (this._settingsDirty) {
        e.preventDefault();
        e.returnValue = this._t('settings.beforeunload', 'You have unsaved Settings changes. Leave and discard them?');
        return e.returnValue;
      }
    };
    window.addEventListener('beforeunload', this._beforeUnloadHandler);
  }

  _unregisterBeforeUnload() {
    if (this._beforeUnloadHandler) {
      window.removeEventListener('beforeunload', this._beforeUnloadHandler);
      this._beforeUnloadHandler = null;
    }
  }

  _startRefresh() {
    if (this._refreshTimer) return;
    this._fetch();
    this._refreshTimer = setInterval(() => {
      if (this._view === 'settings') return;
      this._fetch();
    }, 30000);
  }
  _stopRefresh() { clearInterval(this._refreshTimer); this._refreshTimer = null; }

  async _fetch() {
    if (this._loading || !this._hass) return;
    this._loading = true;
    // Show loading spinner immediately on initial load before awaiting
    if (!this._data) this._render();
    try {
      this._data  = await this._hass.callApi('GET', 'homesec/dashboard');
      this._error = null;
    } catch (e) {
      this._error = e.message;
    } finally {
      this._loading = false;
      if (this._view === 'map' && this._mapAnim) {
        this._liveUpdateMap();
      } else {
        this._render();
      }
    }
  }

  _setView(v) {
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    if (!netflowEnabled && (v === 'map' || v === 'external')) v = 'overview';
    var suricataEnabled = (this._data && this._data.suricata_stats && this._data.suricata_stats.running) || false;
    if (!suricataEnabled && v === 'suricata') v = 'overview';
    if (v === this._view) return;
    if (this._view === 'settings' && v !== 'settings' && this._settingsDirty) {
      this._pendingView = v;
      this._render();
      return;
    }
    if (v === 'settings') this._registerBeforeUnload();
    else this._unregisterBeforeUnload();
    this._stopMap();
    this._mobileMenuOpen = false;
    this._lookupResult = null;
    this._lookupIP     = null;
    this._extIPDetail  = null;
    if (this._view === 'vulnerabilities') this._vulnData = null;
    if (v === 'settings') {
      this._settingsData = null;
      this._settingsMsg = '';
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._settingsRetries = 0;
    }
    this._dnsPage = 0;
    this._dnsPageSize = 25;
    this._suricataPage = 0;
    this._suricataPageSize = 25;
    this._view = v;
    this._render();
  }

  _render() {
    const root = this.shadowRoot;
    if (!root.querySelector('.app')) {
      root.innerHTML = '<style>' + _CSS + '</style><div class="app"><header class="mobile-topbar"><button class="mobile-menu-btn" data-mobile-menu-toggle aria-label="Open menu">☰</button><div class="mobile-topbar-title" id="hsa-mobile-title">Security Assistant</div></header><div class="mobile-backdrop" data-mobile-menu-close></div><nav class="sidebar" id="hsa-sidebar"></nav><main class="content" id="hsa-content"></main></div>';
      root.querySelector('.app').addEventListener('click', e => this._onClick(e));
      root.querySelector('.app').addEventListener('input', e => this._onInput(e));
      root.querySelector('.app').addEventListener('change', e => this._onChange(e));
      root.querySelector('.app').addEventListener('keydown', e => this._onKeyDown(e));
    }
    var app = root.querySelector('.app');
    app.classList.toggle('mobile-menu-open', !!this._mobileMenuOpen);
    var mobileTitle = root.getElementById('hsa-mobile-title');
    if (mobileTitle) mobileTitle.textContent = this._viewLabel(this._view) || this._t('app.title', 'Security Assistant');
    root.getElementById('hsa-sidebar').innerHTML = this._sidebar();
    const content = root.getElementById('hsa-content');
    if (this._error && !this._data) {
      content.innerHTML = '<div class="state-box"><div class="state-icon">\u26A0</div><p>' + this._esc(this._error) + '</p></div>';
      return;
    }
    if (!this._data) {
      content.innerHTML = '<div class="state-box"><div class="loader"></div><p>Loading\u2026</p></div>';
      return;
    }
    try {
      switch (this._view) {
        case 'overview':
          content.innerHTML = this._viewOverview();
          break;
        case 'map':             this._viewMap(content);                    break;
        case 'hosts':           content.innerHTML = this._viewHosts();     break;
        case 'findings':        content.innerHTML = this._viewFindings();  break;
        case 'external':        content.innerHTML = this._viewExternal();  break;
        case 'vulnerabilities':  content.innerHTML = this._viewVulns();        break;
        case 'statistics':       content.innerHTML = this._viewStatistics();   break;
        case 'dns':             content.innerHTML = this._viewDns();       break;
        case 'suricata':        content.innerHTML = this._viewSuricata();   break;
        case 'recommendations': content.innerHTML = this._viewRecs();      break;
        case 'settings':        content.innerHTML = this._viewSettings();  break;
      }
    } catch (err) {
      console.error('[HomeSec] render error in view \'' + this._view + '\':', err);
      content.innerHTML = '<div class="state-box"><div class="state-icon">⚠</div><p>Display error — <button class="btn" onclick="this.closest(\'homesec-panel\').dispatchEvent(new Event(\'_hsreload\'))">Reload</button></p></div>';
    }
    var existingModal = root.getElementById('hsa-editor-modal');
    if (existingModal) existingModal.remove();
    if (this._editorOpen) root.querySelector('.app').insertAdjacentHTML('beforeend', this._editorModal());
    var existingVuln = root.getElementById('hsa-vuln-modal');
    if (existingVuln) existingVuln.remove();
    if (this._vulnDetail) root.querySelector('.app').insertAdjacentHTML('beforeend', this._vulnDetailModal());
    var existingSuricataDetail = root.getElementById('hsa-suricata-detail-modal');
    if (existingSuricataDetail) existingSuricataDetail.remove();
    if (this._suricataAlertDetail !== null) root.querySelector('.app').insertAdjacentHTML('beforeend', this._suricataAlertDetailModal());
    var existingExtIPModal = root.getElementById('hsa-ext-ip-modal');
    if (existingExtIPModal) existingExtIPModal.remove();
    if (this._extIPDetail !== null) root.querySelector('.app').insertAdjacentHTML('beforeend', this._extIPDetailModal());
    var existingRegex = root.getElementById('hsa-regex-dismiss-modal');
    if (existingRegex) existingRegex.remove();
    if (this._regexDismissOpen) root.querySelector('.app').insertAdjacentHTML('beforeend', this._regexDismissModal());
    var existingUnsaved = root.getElementById('hsa-unsaved-modal');
    if (existingUnsaved) existingUnsaved.remove();
    if (this._pendingView) root.querySelector('.app').insertAdjacentHTML('beforeend', this._unsavedConfirmModal());
  }

  _onClick(e) {
    var mToggle = e.target.closest('[data-mobile-menu-toggle]');
    if (mToggle) { this._mobileMenuOpen = !this._mobileMenuOpen; this._render(); return; }
    var mClose = e.target.closest('[data-mobile-menu-close]');
    if (mClose) { this._mobileMenuOpen = false; this._render(); return; }
    var editorClose = e.target.closest('[data-editor-close]');
    if (editorClose) { this._closeEditor(); return; }
    var editorSave = e.target.closest('[data-editor-save]');
    if (editorSave) { this._saveEditor(); return; }
    var nav = e.target.closest('[data-view]');
    if (nav) { if (nav.dataset.mapMode) this._mapMode = nav.dataset.mapMode; this._setView(nav.dataset.view); return; }
    var extPage = e.target.closest('[data-extpage]');
    if (extPage) {
      var total = this._extPreparedList().length;
      var totalPages = Math.max(1, Math.ceil(total / this._extPageSize));
      if (extPage.dataset.extpage === 'prev') this._extPage = Math.max(1, this._extPage - 1);
      if (extPage.dataset.extpage === 'next') this._extPage = Math.min(totalPages, this._extPage + 1);
      this._render();
      return;
    }
    var en = e.target.closest('[data-editname]');
    if (en) { this._editHostName(en.dataset.editname); return; }
    var extClose = e.target.closest('[data-ext-close]');
    if (extClose) { this._extIPDetail = null; this._lookupResult = null; this._lookupIP = null; this._render(); return; }
    if (e.target.id === 'hsa-ext-ip-modal') { this._extIPDetail = null; this._lookupResult = null; this._lookupIP = null; this._render(); return; }
    var extLookup = e.target.closest('[data-ext-lookup]');
    if (extLookup) { this._doLookup(extLookup.dataset.extLookup); return; }
    var extRow = e.target.closest('[data-ext-ip-row]');
    if (extRow && !e.target.closest('[data-ext-close]')) {
      var _extAllIPs = (this._data && this._data.external_ips) || [];
      var _extEntry = _extAllIPs.find(function(x) { return x.ip === extRow.dataset.extIpRow; });
      if (_extEntry) {
        this._extIPDetail = _extEntry;
        this._lookupResult = null;
        this._lookupIP = null;
        this._render();
        this._doLookup(_extEntry.ip);
      }
      return;
    }
    var hr = e.target.closest('tr[data-ip]');
    if (hr && !e.target.closest('select')) { this._toggleRow(hr.dataset.ip); return; }
    var dismiss = e.target.closest('[data-dismiss]');
    if (dismiss) { this._dismissFinding(dismiss.dataset.dismiss); return; }
    var undismiss = e.target.closest('[data-undismiss]');
    if (undismiss) { this._undismissFinding(undismiss.dataset.undismiss); return; }
    var undismissGroup = e.target.closest('[data-undismiss-group]');
    if (undismissGroup) { this._undismissGroup(undismissGroup.dataset.undismissGroup); return; }
    // Findings: grouped view toggle
    if (e.target.closest('[data-findings-group-mode]')) {
      var _fgm = e.target.closest('[data-findings-group-mode]');
      this._findingsGroupMode = _fgm.dataset.findingsGroupMode;
      this._expandedFindingGroup = null;
      this._render();
      return;
    }
    if (e.target.closest('[data-dismissed-group-mode]')) {
      var _dgm = e.target.closest('[data-dismissed-group-mode]');
      this._dismissedGroupMode = _dgm.dataset.dismissedGroupMode;
      this._expandedFindingGroup = null;
      this._render();
      return;
    }
    // Findings: show/hide baseline anomalies
    if (e.target.closest('[data-baseline-findings-toggle]')) {
      this._showBaselineFindings = !this._showBaselineFindings;
      this._expandedFindingGroup = null;
      this._expandedBaselineGroup = null;
      this._render();
      return;
    }
    // Findings: baseline group mode switcher
    var bgm = e.target.closest('[data-baseline-group-mode]');
    if (bgm) {
      this._baselineGroupMode = bgm.dataset.baselineGroupMode;
      this._expandedBaselineGroup = null;
      this._render();
      return;
    }
    // Findings: expand/collapse a baseline group
    var fbge = e.target.closest('[data-expand-baseline-group]');
    if (fbge && !e.target.closest('[data-dismiss-group]') && !e.target.closest('[data-undismiss-group]')) {
      var bgk = fbge.dataset.expandBaselineGroup;
      this._expandedBaselineGroup = (this._expandedBaselineGroup === bgk) ? null : bgk;
      this._render();
      return;
    }
    // Findings: expand/collapse a finding group
    var fge = e.target.closest('[data-expand-group]');
    if (fge && !e.target.closest('[data-dismiss-group]') && !e.target.closest('[data-undismiss-group]')) {
      var gk = fge.dataset.expandGroup;
      this._expandedFindingGroup = (this._expandedFindingGroup === gk) ? null : gk;
      this._render();
      return;
    }
    // Findings: dismiss all findings in a group
    var fdg = e.target.closest('[data-dismiss-group]');
    if (fdg && !e.target.closest('[data-undismiss-group]')) { this._dismissGroup(fdg.dataset.dismissGroup); return; }
    // Findings: open regex dismiss modal
    if (e.target.closest('[data-regex-dismiss-open]')) {
      this._regexDismissOpen = true;
      this._regexDismissPattern = '';
      this._regexDismissNote = '';
      this._render();
      return;
    }
    // Findings: close regex dismiss modal
    if (e.target.closest('[data-regex-dismiss-close]')) {
      this._regexDismissOpen = false;
      this._render();
      return;
    }
    // Findings: confirm regex dismiss
    if (e.target.closest('[data-regex-dismiss-confirm]')) {
      this._applyRegexDismiss();
      return;
    }
    if (e.target.closest('[data-unsaved-stay]')) {
      this._pendingView = null;
      this._render();
      return;
    }
    if (e.target.closest('[data-unsaved-leave]')) {
      var dest = this._pendingView;
      this._pendingView = null;
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._unregisterBeforeUnload();
      this._setView(dest);
      return;
    }
    var mf = e.target.closest('[data-mapfilter]');
    if (mf) { this._setMapFilter(mf.dataset.mapfilter); return; }
    var mm = e.target.closest('[data-mapmode]');
    if (mm) { this._setMapMode(mm.dataset.mapmode); return; }
    var hs = e.target.closest('[data-hostsort]');
    if (hs) { this._setHostSort(hs.dataset.hostsort); return; }
    var es = e.target.closest('[data-extsort]');
    if (es) { this._setExtSort(es.dataset.extsort); return; }
    var vs = e.target.closest('[data-vulnsort]');
    if (vs) { this._setVulnSort(vs.dataset.vulnsort); return; }
    var vp = e.target.closest('[data-vuln-page]');
    if (vp) { this._vulnPage = parseInt(vp.dataset.vulnPage, 10) || 1; this._render(); return; }
    var dnsPager = e.target.closest('[data-dns-page]');
    if (dnsPager) { var pg = parseInt(dnsPager.dataset.dnsPage, 10); if (!isNaN(pg)) { this._dnsPage = pg; this._render(); } return; }
    var ds = e.target.closest('[data-dnssort]');
    if (ds) { this._setDnsSort(ds.dataset.dnssort); return; }
    var suricataPager = e.target.closest('[data-suricata-page]');
    if (suricataPager) { var spg = parseInt(suricataPager.dataset.suricataPage, 10); if (!isNaN(spg)) { this._suricataPage = spg; this._render(); } return; }
    var ss = e.target.closest('[data-suricatasort]');
    if (ss) { this._setSuricataSort(ss.dataset.suricatasort); return; }
    var sc = e.target.closest('[data-suricata-close]');
    if (sc) { this._suricataAlertDetail = null; this._render(); return; }
    var sad = e.target.closest('[data-suricata-alert-idx]');
    if (sad && !e.target.closest('[data-suricata-close]')) {
      var idx = parseInt(sad.dataset.suricataAlertIdx, 10);
      var _log = (this._data && this._data.suricata_log) || [];
      var _filtered = this._suricataFilteredLog(_log);
      var _sorted = this._suricataSortedLog(_filtered);
      var _PAGE_SIZE = this._suricataPageSize || 25;
      var _page = this._suricataPage || 0;
      var _absIdx = _page * _PAGE_SIZE + idx;
      if (_sorted[_absIdx]) { this._suricataAlertDetail = _sorted[_absIdx]; this._render(); }
      return;
    }
    var vr = e.target.closest('[data-vuln-refresh]');
    if (vr) { this._vulnData = null; this._vulnLoading = false; this._render(); return; }
    var vc = e.target.closest('[data-vuln-close]');
    if (vc) {
      // Only close if clicking the backdrop directly or the close button, not card contents
      if (e.target.hasAttribute('data-vuln-close') || e.target.closest('button[data-vuln-close]')) {
        this._vulnDetail = null; this._render(); return;
      }
    }
    var vd = e.target.closest('[data-vuln-detail]');
    if (vd) { this._openVulnDetail(vd.dataset.vulnDetail); return; }
    var st = e.target.closest('[data-statstoggle]');
    if (st) { var _sp = st.dataset.statstoggle.split(':'); this._statsViewModes[_sp[0]] = _sp[1]; this._render(); return; }
    var ri = e.target.closest('[data-rec-idx]');
    if (ri) {
      var idx = parseInt(ri.dataset.recIdx, 10);
      this._expandedRec = (this._expandedRec === idx) ? null : idx;
      this._render();
      return;
    }
    var ba = e.target.closest('[data-baseline-action]');
    if (ba) {
      var action = ba.getAttribute('data-baseline-action');
      var svc = null;
      var actionLabel = ba.textContent.trim();
      if (action === 'start') svc = 'start_baseline_training';
      else if (action === 'stop') svc = 'stop_baseline_training';
      else if (action === 'retrain') svc = 'retrain_baseline';
      else if (action === 'clear') svc = 'clear_baseline';
      if (svc && this._hass) {
        // Show an immediate "working" overlay on the baseline card
        var card = this.shadowRoot && this.shadowRoot.getElementById('baseline-card');
        if (card) {
          card.style.position = 'relative';
          var overlay = document.createElement('div');
          overlay.id = 'baseline-working-overlay';
          overlay.style.cssText = 'position:absolute;inset:0;background:rgba(0,0,0,0.45);border-radius:inherit;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;z-index:10;';
          overlay.innerHTML =
            '<div style="width:32px;height:32px;border:3px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite"></div>' +
            '<div style="color:#fff;font-size:13px;font-weight:600">' + this._esc(actionLabel) + '\u2026</div>';
          card.appendChild(overlay);
        }
        console.log('[HomeSec] Calling service:', svc);
        this._hass.callService('homesec', svc, {}).then(() => {
          setTimeout(() => this._fetch(), 800);
        }).catch(() => {
          // Remove overlay on error so user can try again
          var ov = this.shadowRoot && this.shadowRoot.getElementById('baseline-working-overlay');
          if (ov) ov.remove();
        });
      }
      return;
    }
    var sa = e.target.closest('[data-service-action]');
    if (sa && this._hass) {
      var svc = sa.getAttribute('data-service-action');
      var btn = sa;
      var origText = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Working\u2026';
      console.log('[HomeSec] Calling service:', svc);
      this._hass.callService('homesec', svc, {})
        .then((resp) => {
          if (svc === 'trigger_scan' && resp && resp.scan && resp.scan.status === 'no_targets') {
            btn.textContent = 'No targets';
          } else {
            btn.textContent = 'Done \u2713';
          }
          setTimeout(() => { btn.disabled = false; btn.textContent = origText; }, 2000);
          setTimeout(() => this._fetch(), 1500);
        })
        .catch((err) => {
          btn.textContent = 'Error \u2717';
          btn.style.borderColor = 'var(--danger, #ff4e4e)';
          console.error('[HomeSec] Service action failed:', svc, err);
          setTimeout(() => { btn.disabled = false; btn.textContent = origText; btn.style.borderColor = ''; }, 3000);
        });
      return;
    }
    if (e.target.closest('[data-settings-save]')) { this._onSettingsSave(); return; }
    if (e.target.closest('[data-settings-reset]')) {
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._settingsData = null;
      this._settingsMsg = '';
      this._unregisterBeforeUnload();
      this._registerBeforeUnload();
      this._render();
      return;
    }
  }

  _onInput(e) {
    if (e.target && e.target.id && e.target.id.indexOf('hsa-setting-') === 0) {
      if (e.target.type === 'checkbox') return;
      var key = e.target.id.slice('hsa-setting-'.length);
      this._settingsDraft = this._settingsDraft || {};
      this._settingsDraft[key] = e.target.value;
      this._settingsDirty = true;
      this._registerBeforeUnload();
      return;
    }
    if (e.target.id === 'hsa-host-filter') {
      this._hostFilter = e.target.value;
      var tbody = this.shadowRoot.getElementById('hsa-host-tbody');
      if (tbody) tbody.innerHTML = this._hostRows();
    }
    if (e.target.id === 'hsa-ext-filter') {
      this._extFilter = e.target.value;
      this._extPage = 1;
      var tbody = this.shadowRoot.getElementById('hsa-ext-tbody');
      if (tbody) tbody.innerHTML = this._extRows();
      var pg = this.shadowRoot.getElementById('hsa-ext-pagebar');
      if (pg) pg.innerHTML = this._extPageBar();
    }
    if (e.target.hasAttribute('data-vuln-search')) {
      this._vulnFilter = e.target.value;
      this._vulnPage = 1;
      this._render();
    }
    if (e.target.id === 'hsa-regex-pattern') {
      this._regexDismissPattern = e.target.value;
      var prev = this.shadowRoot && this.shadowRoot.getElementById('hsa-regex-preview');
      if (prev) prev.innerHTML = this._regexPreviewHtml();
    }
    if (e.target.id === 'hsa-regex-note') {
      this._regexDismissNote = e.target.value;
    }
  }

  _onKeyDown(e) {
    if (e.key !== 'Enter') return;
    if (e.target.hasAttribute('data-findings-search')) {
      this._findingsSearch = e.target.value;
      this._render();
    } else if (e.target.hasAttribute('data-baseline-search')) {
      this._baselineSearch = e.target.value;
      this._render();
    } else if (e.target.hasAttribute('data-dismissed-search')) {
      this._dismissedSearch = e.target.value;
      this._render();
    }
  }

  _setVulnSort(col) {
    if (this._vulnSort === col) {
      this._vulnSortDir *= -1;
    } else {
      this._vulnSort = col;
      this._vulnSortDir = col === 'cve_id' || col === 'severity' || col === 'published' ? 1 : -1;
    }
    this._render();
  }

  _setHostSort(col) {
    if (this._hostSort === col) {
      this._hostSortDir *= -1;
    } else {
      this._hostSort = col;
      this._hostSortDir = 1;
    }
    var tbody = this.shadowRoot.getElementById('hsa-host-tbody');
    if (tbody) tbody.innerHTML = this._hostRows();
    var thead = this.shadowRoot.getElementById('hsa-host-thead');
    if (thead) thead.innerHTML = this._hostThead();
  }

  _setExtSort(col) {
    if (this._extSort === col) {
      this._extSortDir *= -1;
    } else {
      this._extSort = col;
      // Numeric/threat columns: default descending (highest first)
      var descFirst = { vt: 1, abuse: 1, traffic_kb: 1, rating: 1 };
      this._extSortDir = descFirst[col] ? -1 : 1;
    }
    this._extPage = 1;
    var tbody = this.shadowRoot.getElementById('hsa-ext-tbody');
    if (tbody) tbody.innerHTML = this._extRows();
    var thead = this.shadowRoot.getElementById('hsa-ext-thead');
    if (thead) thead.innerHTML = this._extThead();
    var pg = this.shadowRoot.getElementById('hsa-ext-pagebar');
    if (pg) pg.innerHTML = this._extPageBar();
  }

  _setDnsSort(col) {
    if (this._dnsSort === col) {
      this._dnsSortDir *= -1;
    } else {
      this._dnsSort = col;
      this._dnsSortDir = col === 'time' ? -1 : 1;
    }
    this._dnsPage = 0;
    this._render();
  }

  _dnsIpSortKey(ip) {
    var raw = String(ip || '').trim();
    if (raw.indexOf(':') >= 0) return '1:' + raw.toLowerCase();
    var parts = raw.split('.');
    if (parts.length !== 4) return '0:' + raw.toLowerCase();
    for (var i = 0; i < parts.length; i++) {
      if (!/^\d+$/.test(parts[i])) return '0:' + raw.toLowerCase();
    }
    return '0:' + parts.map(function(p) {
      var n = Math.max(0, Math.min(255, parseInt(p, 10)));
      return ('000' + n).slice(-3);
    }).join('.');
  }

  // ── Suricata view ────────────────────────────────────────────────────────────

  _viewSuricata() {
    var self = this;
    var stats = (this._data && this._data.suricata_stats) || {};
    var log   = (this._data && this._data.suricata_log) || [];
    var filteredLog = this._suricataFilteredLog(log);
    var sortedLog   = this._suricataSortedLog(filteredLog);

    // Severity colour helpers
    var SEV_COLORS = { 1:'rgba(255,77,109,1)', 2:'rgba(255,179,71,1)', 3:'rgba(107,255,200,1)' };
    var SEV_LABELS = {
      1:self._t('suricata.sev_critical', 'Critical'),
      2:self._t('suricata.sev_major', 'Major'),
      3:self._t('suricata.sev_minor', 'Minor')
    };
    function sevColor(s) { return SEV_COLORS[s] || 'rgba(90,106,128,1)'; }
    function sevLabel(s) { return SEV_LABELS[s] || self._t('suricata.sev_unknown', 'Unknown'); }
    function sevBadge(s) {
      var c = sevColor(s); var l = sevLabel(s);
      return '<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:' +
        c.replace(',1)',',0.18)') + ';color:' + c + ';border:1px solid ' + c.replace(',1)',',0.4)') + '">' + l + '</span>';
    }

    var critCount  = log.filter(function(e) { return e.severity === 1; }).length;

    // ── filter bar ────────────────────────────────────────────────────────────
    var filterBar = '<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap">' +
      '<input class="search-bar" id="suricata-search" placeholder="' + self._esc(self._t('suricata.filter_placeholder', 'Filter by IP, signature…')) + '" style="width:230px" ' +
        'value="' + self._esc(this._suricataSearch) + '" onkeydown="if(event.key===\'Enter\')this.getRootNode().host._suricataFilter()" />' +
      '<select id="suricata-sev-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" ' +
        'onchange="this.getRootNode().host._suricataFilter()">' +
        '<option value="">' + self._t('suricata.all_severities', 'All severities') + '</option>' +
        [1,2,3].map(function(s){ return '<option value="'+s+'"'+(self._suricataSeverityFilter===String(s)?' selected':'')+'>'+sevLabel(s)+'</option>'; }).join('') +
      '</select>' +
      '<select id="suricata-action-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" ' +
        'onchange="this.getRootNode().host._suricataFilter()">' +
        '<option value="">' + self._t('suricata.all_actions', 'All actions') + '</option>' +
        '<option value="allowed"'+(self._suricataActionFilter==='allowed'?' selected':'')+'>' + self._t('common.allowed', 'Allowed') + '</option>' +
        '<option value="blocked"'+(self._suricataActionFilter==='blocked'?' selected':'')+'>' + self._t('common.blocked', 'Blocked') + '</option>' +
      '</select>' +
      '<span style="font-size:11px;color:var(--muted);margin-left:auto">' + sortedLog.length + ' / ' + log.length + ' ' + self._t('suricata.entries', 'entries') + '</span>' +
    '</div>';

    // ── table ─────────────────────────────────────────────────────────────────
    var PAGE_SIZE = this._suricataPageSize || 25;
    var page = this._suricataPage || 0;
    var totalPages = Math.max(1, Math.ceil(sortedLog.length / PAGE_SIZE));
    if (page >= totalPages) page = totalPages - 1;
    var pageLog = sortedLog.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    var pageStart = sortedLog.length === 0 ? 0 : (page * PAGE_SIZE + 1);
    var pageEnd = Math.min(sortedLog.length, (page + 1) * PAGE_SIZE);

    var topPagination = '<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap">' +
      '<div class="row-gap" style="font-size:11px;color:var(--muted)">' + self._t('suricata.showing', 'Showing') + ' ' + pageStart + '\u2013' + pageEnd + ' of ' + sortedLog.length + '</div>' +
      '<div class="row-gap" style="gap:6px">' +
        '<label class="dim" style="font-size:11px">' + self._t('common.rows', 'Rows') + '</label>' +
        '<select id="hsa-suricata-pagesize" class="role-select">' +
          [10,25,50,100].map(function(n){return '<option value="'+n+'"'+(n===PAGE_SIZE?' selected':'')+'>'+n+'</option>';}).join('') +
        '</select>' +
        '<button class="btn" data-suricata-page="'+(page-1)+'"'+(page<=0?' disabled':'')+'>' + self._t('common.previous', 'Previous') + '</button>' +
        '<span class="dim" style="font-size:11px;min-width:70px;text-align:center">'+(page+1)+' / '+totalPages+'</span>' +
        '<button class="btn" data-suricata-page="'+(page+1)+'"'+(page>=totalPages-1?' disabled':'')+'>' + self._t('common.next', 'Next') + '</button>' +
      '</div>' +
    '</div>';

    var SORT_COLS = [
      { key:'time',      label:self._t('suricata.col_time', 'Time') },
      { key:'src_ip',    label:self._t('suricata.col_src_ip', 'Src IP') },
      { key:'dest_ip',   label:self._t('suricata.col_dest_ip', 'Dest IP') },
      { key:'proto',     label:self._t('suricata.col_proto', 'Proto') },
      { key:'signature', label:self._t('suricata.col_signature', 'Signature') },
      { key:'category',  label:self._t('suricata.col_category', 'Category') },
      { key:'severity',  label:self._t('suricata.col_severity', 'Severity') },
      { key:'action',    label:self._t('suricata.col_action', 'Action') },
    ];
    var thead = '<table class="data-table" style="min-width:960px"><thead><tr>' +
      SORT_COLS.map(function(c) {
        var arrow = self._suricataSort === c.key ? (self._suricataSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
        return '<th class="sortable-th" data-suricatasort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
      }).join('') +
    '</tr></thead><tbody>';

    var rows = pageLog.map(function(e, rowIdx) {
      var ts    = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
      var sip   = self._esc(e.src_ip || '—');
      var dip   = self._esc(e.dest_ip || '—');
      var sproto = self._esc(e.proto || '');
      var sig   = self._esc(e.signature || '—');
      var cat   = self._esc(e.category || '—');
      var sev   = parseInt(e.severity) || 3;
      var action = (e.action || 'allowed').toLowerCase();

      var actionBadge = action === 'blocked'
        ? '<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">' + self._t('suricata.badge_blocked', '🚫 Blocked') + '</span>'
        : '<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">' + self._t('suricata.badge_allowed', '✓ Allowed') + '</span>';

      var rowBg = sev === 1 ? 'rgba(255,77,109,.06)' : sev === 2 ? 'rgba(255,179,71,.04)' : '';
      var rowStyle = 'cursor:pointer' + (rowBg ? ';background:' + rowBg : '');
      return '<tr style="' + rowStyle + '" data-suricata-alert-idx="' + rowIdx + '" title="' + self._esc(self._t('suricata.click_details', 'Click for details')) + '">' +
        '<td class="mono" style="white-space:nowrap;font-size:11px">' + ts + '</td>' +
        '<td class="mono ip">' + sip + '</td>' +
        '<td class="mono ip">' + dip + '</td>' +
        '<td><span class="chip">' + sproto + '</span></td>' +
        '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + sig + '">' + sig + '</td>' +
        '<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--muted)" title="' + cat + '">' + cat + '</td>' +
        '<td>' + sevBadge(sev) + '</td>' +
        '<td>' + actionBadge + '</td>' +
      '</tr>';
    }).join('');

    var critBadge = critCount > 0
      ? '<span class="badge badge-malicious" style="margin-left:8px">' + critCount + ' ' + self._t('suricata.critical_badge', 'critical') + '</span>'
      : '';

    return '<div>' +
      '<div class="view-header"><h1>' + this._t('page.suricata_alerts', 'Suricata Alerts') + ' ' + critBadge + '</h1></div>' +
      '<div class="card table-card">' +
        '<div style="padding:14px 14px 8px">' + filterBar + '</div>' +
        topPagination +
        '<div style="overflow-x:auto">' + thead + rows + '</tbody></table></div>' +
      '</div>' +
    '</div>';
  }

  _suricataFilter() {
    this._suricataSearch   = ((this.shadowRoot.getElementById('suricata-search') || {}).value || '').toLowerCase().trim();
    this._suricataSeverityFilter = ((this.shadowRoot.getElementById('suricata-sev-filter') || {}).value || '');
    this._suricataActionFilter   = ((this.shadowRoot.getElementById('suricata-action-filter') || {}).value || '');
    this._suricataPage = 0;
    this._render();
  }

  _suricataFilteredLog(log) {
    var search = this._suricataSearch || '';
    var sevF   = this._suricataSeverityFilter || '';
    var actF   = this._suricataActionFilter || '';
    return (log || []).filter(function(e) {
      if (sevF && String(e.severity) !== sevF) return false;
      if (actF && (e.action || 'allowed').toLowerCase() !== actF) return false;
      if (search) {
        var hay = [e.src_ip, e.dest_ip, e.signature, e.category, e.proto, e.app_proto].join(' ').toLowerCase();
        if (hay.indexOf(search) < 0) return false;
      }
      return true;
    });
  }

  _suricataSortedLog(log) {
    var self = this;
    var key  = this._suricataSort || 'time';
    var dir  = this._suricataSortDir || -1;
    var out  = (log || []).slice();
    out.sort(function(a, b) {
      var va, vb;
      if (key === 'time') {
        va = Date.parse(a.timestamp || '') || 0;
        vb = Date.parse(b.timestamp || '') || 0;
      } else if (key === 'severity') {
        va = parseInt(a.severity) || 3;
        vb = parseInt(b.severity) || 3;
      } else if (key === 'src_ip') {
        va = self._dnsIpSortKey(a.src_ip);
        vb = self._dnsIpSortKey(b.src_ip);
      } else if (key === 'dest_ip') {
        va = self._dnsIpSortKey(a.dest_ip);
        vb = self._dnsIpSortKey(b.dest_ip);
      } else {
        va = String(a[key] || '').toLowerCase();
        vb = String(b[key] || '').toLowerCase();
      }
      if (va < vb) return -dir;
      if (va > vb) return dir;
      return 0;
    });
    return out;
  }

  _setSuricataSort(col) {
    if (this._suricataSort === col) {
      this._suricataSortDir *= -1;
    } else {
      this._suricataSort = col;
      this._suricataSortDir = col === 'time' ? -1 : 1;
    }
    this._suricataPage = 0;
    this._render();
  }

  _onChange(e) {
    if (e.target && e.target.id && e.target.id.indexOf('hsa-setting-') === 0) {
      var key = e.target.id.slice('hsa-setting-'.length);
      this._settingsDraft = this._settingsDraft || {};
      this._settingsDraft[key] = e.target.type === 'checkbox' ? !!e.target.checked : e.target.value;
      this._settingsDirty = true;
      this._registerBeforeUnload();
      return;
    }
    if (e.target.id === 'hsa-ext-pagesize') {
      this._extPageSize = Math.max(5, Math.min(200, parseInt(e.target.value, 10) || 25));
      this._extPage = 1;
      this._render();
      return;
    }
    if (e.target.id === 'hsa-dns-pagesize') {
      this._dnsPageSize = Math.max(10, Math.min(100, parseInt(e.target.value, 10) || 25));
      this._dnsPage = 0;
      this._render();
      return;
    }
    if (e.target.id === 'hsa-suricata-pagesize') {
      this._suricataPageSize = Math.max(10, Math.min(100, parseInt(e.target.value, 10) || 25));
      this._suricataPage = 0;
      this._render();
      return;
    }
    if (e.target.classList.contains('role-select')) {
      var ip = e.target.dataset.roleip;
      var role = e.target.value;
      if (!ip) return;
      if (role === '__custom__') {
        this._openEditor({
          mode: 'role',
          ip: ip,
          title: 'Set Custom Role',
          help: 'Use lowercase letters, digits, and underscores.',
          value: '',
          placeholder: 'example_role'
        });
      } else {
        this._saveRole(ip, role);
      }
    }
  }

  _dismissFinding(key) {
    if (!key) return;
    this._openEditor({
      mode:        'dismiss',
      ip:          key,
      title:       'Dismiss Finding',
      help:        'Optionally add a note explaining why this finding is dismissed (e.g. "false positive", "patched", "accepted risk"). Leave blank to dismiss without a note.',
      placeholder: 'Reason for dismissing (optional)',
      value:       '',
    });
  }

  async _undismissGroup(groupKey) {
    var dismissed = (this._data && this._data.dismissed_findings) || [];
    var BASELINE_ONLY_CATS = { anomaly_new_host:1, anomaly_new_peer:1, anomaly_new_port:1, anomaly_new_dns_domain:1, anomaly_new_dns_category:1 };
    var toMatch;
    if (groupKey.startsWith('fcat:')) {
      var cat = groupKey.slice(5);
      toMatch = dismissed.filter(function(f) { return (f.category || 'unknown') === cat; });
    } else if (groupKey.startsWith('fhost:')) {
      var ip = groupKey.slice(6);
      toMatch = dismissed.filter(function(f) { return (f.source_ip || 'unknown') === ip; });
    } else if (groupKey.startsWith('fsev:')) {
      var sev = groupKey.slice(5);
      toMatch = dismissed.filter(function(f) { return (f.severity || 'info') === sev; });
    } else {
      // legacy: match by summary (renderGrouped path)
      toMatch = dismissed.filter(function(f) { return (f.summary || f.category || 'Unknown') === groupKey; });
    }
    if (!toMatch.length) return;
    try {
      await Promise.all(toMatch.map(f => this._hass.callApi('POST', 'homesec/findings/undismiss', {
        key: f.key || (f.source_ip + ':' + f.category),
      })));
      this._expandedFindingGroup = null;
      this._fetch();
    } catch (err) {
      alert('Failed to restore group: ' + (err.message || String(err)));
    }
  }

  async _undismissFinding(key) {
    if (!key) return;
    try {
      await this._hass.callApi('POST', 'homesec/findings/undismiss', { key: key });
      this._fetch();
    } catch (err) {
      alert('Failed to restore finding: ' + (err.message || String(err)));
    }
  }

  async _dismissGroup(summary) {
    var findings = (this._data && this._data.findings) || [];
    var baselineAnomalies = (this._data && this._data.baseline_anomalies) || [];
    var toMatch;
    if (summary.startsWith('bhost:')) {
      var ip = summary.slice(6);
      toMatch = baselineAnomalies.filter(function(f) { return f.source_ip === ip; });
    } else if (summary.startsWith('bcat:')) {
      var cat = summary.slice(5);
      toMatch = baselineAnomalies.filter(function(f) { return f.category === cat; });
    } else if (summary.startsWith('fcat:')) {
      var fcat = summary.slice(5);
      toMatch = findings.filter(function(f) { return (f.category || 'unknown') === fcat; });
    } else if (summary.startsWith('fhost:')) {
      var fip = summary.slice(6);
      toMatch = findings.filter(function(f) { return (f.source_ip || 'unknown') === fip; });
    } else if (summary.startsWith('fsev:')) {
      var fsev = summary.slice(5);
      toMatch = findings.filter(function(f) { return (f.severity || 'info') === fsev; });
    } else {
      toMatch = findings.filter(function(f) { return f.summary === summary; });
      if (!toMatch.length) toMatch = baselineAnomalies.filter(function(f) { return f.summary === summary; });
    }
    if (!toMatch.length) return;
    try {
      await Promise.all(toMatch.map(f => this._hass.callApi('POST', 'homesec/findings/dismiss', {
        key: f.key || (f.source_ip + ':' + f.category),
        note: 'Dismissed as group',
      })));
      this._expandedFindingGroup = null;
      this._fetch();
    } catch (err) {
      alert('Failed to dismiss group: ' + (err.message || String(err)));
    }
  }

  async _applyRegexDismiss() {
    var pattern = this._regexDismissPattern.trim();
    var note = this._regexDismissNote.trim();
    if (!pattern) return;
    var rx;
    try { rx = new RegExp(pattern, 'i'); } catch (e) { alert('Invalid regex: ' + e.message); return; }
    var findings = (this._data && this._data.findings) || [];
    var matched = findings.filter(function(f) { return rx.test(f.summary || '') || rx.test(f.key || ''); });
    if (!matched.length) { alert('No active findings match this pattern.'); return; }
    this._regexDismissOpen = false;
    this._render();
    var autoNote = (note || ('Regex dismiss: ' + pattern)).slice(0, 500);
    try {
      await Promise.all(matched.map(f => this._hass.callApi('POST', 'homesec/findings/dismiss', {
        key: f.key || (f.source_ip + ':' + f.category),
        note: autoNote,
      })));
      this._fetch();
    } catch (err) {
      alert('Failed to dismiss findings: ' + (err.message || String(err)));
    }
  }

  _regexPreviewHtml() {
    var pattern = this._regexDismissPattern;
    if (!pattern) return '<div style="font-size:11px;color:var(--muted)">Enter a regex above to preview matches.</div>';
    var rx = null;
    var rxErr = '';
    try { rx = new RegExp(pattern, 'i'); } catch (e) { rxErr = e.message; }
    if (rxErr) return '<div style="font-size:11px;color:var(--danger)">\u26A0 Invalid regex: ' + this._esc(rxErr) + '</div>';
    var findings = (this._data && this._data.findings) || [];
    var matched = findings.filter(function(f) { return rx.test(f.summary || '') || rx.test(f.key || ''); });
    if (!matched.length) return '<div style="font-size:11px;color:var(--muted)">No active findings match this pattern.</div>';
    var self = this;
    return '<div style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:6px">Would dismiss ' + matched.length + ' finding' + (matched.length !== 1 ? 's' : '') + ':</div>' +
      matched.map(function(f) {
        return '<div style="display:flex;gap:8px;align-items:center;padding:3px 0;border-bottom:1px solid rgba(98,232,255,.06);flex-wrap:wrap">' +
          self._sev(f.severity) +
          '<span class="ip" style="font-size:11px">' + self._esc(f.source_ip || '') + '</span>' +
          '<span style="font-size:11px;color:var(--text);flex:1">' + self._esc(f.summary || '') + '</span>' +
        '</div>';
      }).join('');
  }

  _regexDismissModal() {
    var self = this;
    return '<div id="hsa-regex-dismiss-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px">' +
      '<div class="card" style="width:min(640px,96vw);margin:0;border:1px solid rgba(98,232,255,.26)">' +
        '<div class="view-header" style="margin-bottom:10px"><h1 style="font-size:16px">\uD83D\uDDD1 Dismiss by Pattern</h1></div>' +
        '<div class="dim" style="font-size:11px;margin-bottom:12px">Enter a regular expression to match against finding summaries or keys. All matching <strong>active</strong> findings will be dismissed.</div>' +
        '<label class="dim" style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;display:block;margin-bottom:4px">Regex pattern</label>' +
        '<input id="hsa-regex-pattern" class="search-bar" style="width:100%;font-family:monospace" type="text" maxlength="200" placeholder="e.g. port.scan|high.egress" value="' + self._esc(self._regexDismissPattern) + '" autocomplete="off" spellcheck="false">' +
        '<label class="dim" style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;display:block;margin-top:10px;margin-bottom:4px">Dismiss note (optional)</label>' +
        '<input id="hsa-regex-note" class="search-bar" style="width:100%" type="text" maxlength="500" placeholder="e.g. accepted risk, false positive" value="' + self._esc(self._regexDismissNote) + '">' +
        '<div id="hsa-regex-preview" style="margin-top:12px;padding:10px;background:rgba(0,0,0,.25);border-radius:6px;max-height:200px;overflow-y:auto">' + self._regexPreviewHtml() + '</div>' +
        '<div class="row-gap" style="justify-content:flex-end;margin-top:14px;gap:8px">' +
          '<button class="btn" data-regex-dismiss-close>Cancel</button>' +
          '<button class="btn" style="background:rgba(255,77,109,.12);border-color:rgba(255,77,109,.4);color:#ff4d6d" data-regex-dismiss-confirm>Dismiss matching</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  _unsavedConfirmModal() {
    return '<div id="hsa-unsaved-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px">' +
      '<div class="card" style="width:min(420px,94vw);margin:0;border:1px solid rgba(255,180,0,.3)">' +
        '<div class="view-header" style="margin-bottom:10px">' +
          '<h1 style="font-size:16px">⚠️ ' + this._t('settings.unsaved_title', 'Unsaved Changes') + '</h1>' +
        '</div>' +
        '<p class="dim" style="font-size:13px;margin:0 0 18px">' + this._t('settings.unsaved_body', 'You have unsaved settings changes. If you leave now they will be discarded.') + '</p>' +
        '<div class="row-gap" style="justify-content:flex-end;gap:8px">' +
          '<button class="btn" data-unsaved-stay>' + this._t('settings.stay', 'Stay on Settings') + '</button>' +
          '<button class="btn" style="background:rgba(255,77,109,.12);border-color:rgba(255,77,109,.4);color:#ff4d6d" data-unsaved-leave>' + this._t('settings.discard_leave', 'Discard &amp; Leave') + '</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  async _saveRole(ip, role) {
    try {
      await this._hass.callApi('POST', 'homesec/device/role', { ip: ip, role: role });
      this._fetch();
    } catch (err) {
      alert('Failed to save role: ' + (err.message || String(err)));
    }
  }

  async _saveHostName(ip, name) {
    try {
      await this._hass.callApi('POST', 'homesec/device/name', { ip: ip, name: name });
      this._fetch();
    } catch (err) {
      alert('Failed to save name: ' + (err.message || String(err)));
    }
  }

  _openEditor(cfg) {
    this._editorOpen = true;
    this._editorMode = cfg.mode || '';
    this._editorIP = cfg.ip || '';
    this._editorTitle = cfg.title || 'Edit';
    this._editorHelp = cfg.help || '';
    this._editorValue = cfg.value || '';
    this._editorPlaceholder = cfg.placeholder || '';
    this._render();
    var self = this;
    requestAnimationFrame(function() {
      var input = self.shadowRoot && self.shadowRoot.getElementById('hsa-editor-input');
      if (input) input.focus();
    });
  }

  _closeEditor() {
    this._editorOpen = false;
    this._editorMode = '';
    this._editorIP = '';
    this._editorTitle = '';
    this._editorHelp = '';
    this._editorValue = '';
    this._editorPlaceholder = '';
    this._render();
  }

  async _saveEditor() {
    var input = this.shadowRoot && this.shadowRoot.getElementById('hsa-editor-input');
    if (!input) return;
    var raw = (input.value || '').trim();
    var mode = this._editorMode;
    var ip = this._editorIP;
    this._closeEditor();
    if (mode === 'dismiss') {
      try {
        await this._hass.callApi('POST', 'homesec/findings/dismiss', { key: ip, note: raw.slice(0, 500) });
        this._fetch();
      } catch (err) {
        alert('Failed to dismiss finding: ' + (err.message || String(err)));
      }
      return;
    }
    if (mode === 'name') {
      await this._saveHostName(ip, raw.slice(0, 64));
      return;
    }
    if (mode === 'role') {
      var slug = raw.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
      if (!slug || slug === '__custom__') return;
      await this._saveRole(ip, slug);
    }
  }

  _editorModal() {
    return '<div id="hsa-editor-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.68);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px">' +
      '<div class="card" style="width:min(560px,96vw);margin:0;border:1px solid rgba(98,232,255,.26)">' +
      '<div class="view-header" style="margin-bottom:10px"><h1 style="font-size:16px">' + this._esc(this._editorTitle) + '</h1></div>' +
      (this._editorHelp ? '<div class="dim" style="font-size:11px;margin-bottom:8px">' + this._esc(this._editorHelp) + '</div>' : '') +
      '<input id="hsa-editor-input" class="search-bar" style="width:100%" type="text" maxlength="' + (this._editorMode === 'dismiss' ? '500' : '64') + '" placeholder="' + this._esc(this._editorPlaceholder || '') + '" value="' + this._esc(this._editorValue || '') + '">' +
      '<div class="row-gap" style="justify-content:flex-end;margin-top:12px">' +
      '<button class="btn" data-editor-close="1">Cancel</button>' +
      '<button class="btn" data-editor-save="1">' + (this._editorMode === 'dismiss' ? 'Dismiss' : 'Save') + '</button>' +
      '</div></div></div>';
  }

  _editHostName(ip) {
    if (!this._data || !ip) return;
    var devices = this._data.devices || [];
    var d = devices.find(function(x) { return x.ip === ip; }) || {};
    var current = (d.display_name || d.hostname || '').trim();
    this._openEditor({
      mode: 'name',
      ip: ip,
      title: 'Rename Host',
      help: 'Leave empty and Save to clear the manual name.',
      value: current,
      placeholder: 'Kitchen Camera'
    });
  }

  _sidebar() {
    var _BL_ONLY = { anomaly_new_host:1, anomaly_new_peer:1, anomaly_new_port:1, anomaly_new_dns_domain:1, anomaly_new_dns_category:1 };
    var secFindings = ((this._data && this._data.findings) || []).filter(function(f) { return !_BL_ONLY[f.category]; });
    var findingGroups = {};
    secFindings.forEach(function(f) { findingGroups[f.summary || f.category || 'Unknown'] = true; });
    var blAnoms = (this._data && this._data.baseline_anomalies) || [];
    var blCats = {};
    blAnoms.forEach(function(a) { blCats[a.category || 'unknown'] = true; });
    var totalFindings = Object.keys(findingGroups).length + Object.keys(blCats).length;
    var ext_threat = (this._data && this._data.external_ips || []).filter(function(e) { return e.blacklisted; }).length;
    var dnsEnabled = (this._data && this._data.dns_proxy_stats && this._data.dns_proxy_stats.running) || false;
    var suricataEnabled = (this._data && this._data.suricata_stats && this._data.suricata_stats.running) || false;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var self = this;
    var views = dnsEnabled ? _VIEWS.slice() : _VIEWS.filter(function(v) { return v !== 'dns'; });
    if (!netflowEnabled) {
      views = views.filter(function(v) { return v !== 'map' && v !== 'external'; });
    }
    if (!suricataEnabled) {
      views = views.filter(function(v) { return v !== 'suricata'; });
    }
    var items = views.map(function(v) {
      var badge = '';
      if (v === 'findings' && totalFindings > 0)       badge = '<span class="nav-badge">' + totalFindings + '</span>';
      if (v === 'external' && ext_threat > 0)     badge = '<span class="nav-badge danger">' + ext_threat + '</span>';
      return '<li class="nav-item ' + (self._view === v ? 'active' : '') + '" data-view="' + v + '">' +
        _VIEW_ICONS[v] + '<span class="nav-label">' + self._viewLabel(v) + '</span>' + badge + '</li>';
    }).join('');
    var exporters = (this._data && this._data.summary && this._data.summary.exporters) || [];
    var status = exporters.length > 0 ? 'online' : 'waiting';
    return '<div class="brand"><img src="/api/homesec/frontend/hsa-logo.svg" alt="logo" style="height:32px;width:32px;margin-right:10px;border-radius:8px;box-shadow:0 0 8px #62e8ff55;vertical-align:middle">' +
      '<div class="brand-text"><span class="brand-name">Security</span><span class="brand-sub">Assistant</span><span class="brand-tagline">' + this._t('sidebar.tagline', 'Network security telemetry with live flow context') + '</span></div></div>' +
      '<ul class="nav-list">' + items + '</ul>' +
      '<div class="sidebar-status ' + status + '"><div class="status-dot"></div><span>' +
      (status === 'online' ? this._t('sidebar.collector_active', 'Collector active') : this._t('sidebar.awaiting_flows', 'Awaiting flows')) + '</span>' +
      '<span style="margin-left:auto;opacity:.45;font-size:9px">v' + ((this._data && this._data.summary && this._data.summary.version) || '…') + '</span>' +
      '</div>' +
        '<div class="sidebar-copy"><a href="https://domotic.monster" target="_blank" rel="noopener noreferrer">© 2026 domotic.monster</a></div>';
  }

  _viewOverview() {
    var _BL_ONLY_OV = { anomaly_new_host:1, anomaly_new_peer:1, anomaly_new_port:1, anomaly_new_dns_domain:1, anomaly_new_dns_category:1 };
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var baselineEnabledRaw = this._data && this._data.baseline_enabled;
    var baselineEnabled = baselineEnabledRaw === true || baselineEnabledRaw === 'true' || baselineEnabledRaw === 1 || baselineEnabledRaw === '1';
    var s       = (this._data && this._data.summary) || {};
    var findings = ((this._data && this._data.findings) || []).filter(function(f) { return !_BL_ONLY_OV[f.category]; });
    var dismissed = ((this._data && this._data.dismissed_findings) || []).filter(function(f) { return !_BL_ONLY_OV[f.category]; });
    var dismissedVulns = dismissed.filter(function(f) { return f.category === 'vulnerability'; }).length;
    var recent   = findings.slice(0, 5);
    var exporters = s.exporters || [];
    var totalDatagrams = s.total_datagrams || 0;
    var parsed   = s.parsed_datagrams || 0;
    var dropped  = s.dropped_datagrams || 0;
    var pct      = totalDatagrams > 0 ? Math.round((parsed / totalDatagrams) * 100) : 0;
    var self = this;
    var findingsLabel = this._t('overview.active_findings', 'Active Findings') + (dismissed.length ? ' <span class="dim" style="font-size:10px;text-transform:none">(' + dismissed.length + ' ' + this._t('overview.dismissed', 'dismissed') + ')</span>' : '');
    var cvesLabel = this._t('overview.active_cves', 'Active CVEs') + (dismissedVulns ? ' <span class="dim" style="font-size:10px;text-transform:none">(' + dismissedVulns + ' ' + this._t('overview.dismissed', 'dismissed') + ')</span>' : '');
    var nvdTs = this._data && this._data.nvd_last_updated;
    var nvdTtl = (this._data && this._data.nvd_ttl_hours != null) ? this._data.nvd_ttl_hours + '\u00a0h' : '\u2014';
    var nvdTotalCves = (this._data && this._data.nvd_total_cves != null) ? this._data.nvd_total_cves : 0;
    var nvdMinYear = (this._data && this._data.nvd_min_year != null) ? this._data.nvd_min_year : null;
    var nvdAge = nvdTs ? this._ago(nvdTs) : this._t('overview.never_fetched', 'never fetched');
    var nvdStatus = nvdTs ? ((Date.now() - new Date(nvdTs).getTime()) < 26 * 3600 * 1000 ? 'good' : 'warn') : 'warn';

    // Suricata stats for overview cards
    var suricataEnabledOv = (this._data && this._data.suricata_stats && this._data.suricata_stats.running) || false;
    var suricataStatsOv = (this._data && this._data.suricata_stats) || {};
    var suricataLogOv = (this._data && this._data.suricata_log) || [];
    var suricataTotalOv = suricataLogOv.length;
    var suricataCritOv = suricataLogOv.filter(function(e) { return e.severity === 1; }).length;

    // Baseline card
    var baseline = (this._data && this._data.baseline) || {};
    var baselineMode = baseline.mode || 'disabled';
    var baselineModeLabel = baselineMode === 'training' ? this._t('overview.baseline_learning', 'Learning') : (baselineMode === 'active' ? this._t('overview.baseline_active', 'Active') : this._t('overview.baseline_disabled', 'Disabled'));
    var baselineIcon = baselineMode === 'training' ? '🧠' : (baselineMode === 'active' ? '✅' : '⏸');
    var sinceStr = baseline.baseline_completed_at ? self._ago(baseline.baseline_completed_at) : '';
    var trainingElapsed = '';
    if (baselineMode === 'training') {
      var started = baseline.training_started_at;
      var ends = baseline.training_ends_at;
      var now = Date.now();
      var startMs = started ? new Date(started).getTime() : null;
      var endMs = ends ? new Date(ends).getTime() : null;
      var elapsed = startMs ? Math.max(0, Math.min(now, endMs || now) - startMs) : 0;
      var trainingTotalMs = (endMs && startMs) ? endMs - startMs : null;
      var trainingPct = trainingTotalMs ? Math.round((elapsed / trainingTotalMs) * 100) : 0;
      trainingElapsed = '<div>' +
        '<span style="font-size:13px">' + self._t('overview.elapsed', 'Elapsed') + ': <b>' + self._ago(started) + '</b></span>' +
        (trainingTotalMs ? ' &nbsp; <span style="font-size:13px">' + self._t('overview.progress', 'Progress') + ': <b>' + trainingPct + '%</b></span>' : '') +
        '</div>';
    }
    // Action buttons
    var btns = '';
    btns += '<button class="btn" data-baseline-action="start">' + this._t('overview.btn_start_training', 'Start Training') + '</button>';
    btns += '<button class="btn" data-baseline-action="stop">' + this._t('overview.btn_stop_training', 'Stop Training') + '</button>';
    btns += '<button class="btn" data-baseline-action="retrain">' + this._t('overview.btn_retrain', 'Retrain') + '</button>';
    btns += '<button class="btn" data-baseline-action="clear">' + this._t('overview.btn_clear', 'Clear') + '</button>';

    var baselineCard = '<div class="card" id="baseline-card" style="margin-bottom:12px">' +
      '<div class="card-title">' + this._t('overview.baseline_title', 'Baseline') + ' <span style="font-size:18px;margin-left:6px">' + baselineIcon + '</span></div>' +
      '<div style="margin-bottom:6px"><b>' + this._t('overview.mode_label', 'Mode') + ':</b> ' + baselineModeLabel + '</div>' +
      (baselineMode === 'training' ? trainingElapsed : '') +
      (baselineMode === 'active' && sinceStr ? '<div><b>' + this._t('overview.baseline_created_label', 'Baseline created') + ':</b> ' + sinceStr + '</div>' : '') +
      '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">' + btns + '</div>' +
      '</div>';

    return '<div>' +
      '<div class="page-header"><h1 class="page-title">' + this._t('page.overview', 'Overview') + '</h1></div>' +
      '<div class="stat-grid">' +
        this._stat(s.devices || 0, this._t('overview.stat_devices', 'Devices'), 'success') +
        this._stat((this._data && this._data.scan_hosts_found) != null ? this._data.scan_hosts_found : (s.scanned_devices || 0), this._t('overview.stat_scanned', 'Scanned'), '') +
        this._stat(s.findings || 0, findingsLabel, (s.findings || 0) > 0 ? 'danger' : '') +
        this._stat(s.vulnerability_count || 0, cvesLabel, (s.vulnerability_count || 0) > 0 ? 'warn' : '') +
        this._stat(nvdTotalCves, this._t('overview.stat_nvd_cves', 'NVD CVEs') + (nvdMinYear ? ' <span class="dim" style="font-size:10px;text-transform:none">(\u2265\u00a0' + nvdMinYear + ')</span>' : ''), '') +
        this._stat((this._data && this._data.kev_total) || 0, this._t('overview.stat_cisa_kev', 'CISA KEV'), '') +
        this._stat(this._fmtN(s.total_flows || 0), this._t('overview.stat_flows', 'Flows'), '') +
        this._stat(exporters.length, this._t('overview.stat_exporters', 'Exporters'), exporters.length > 0 ? 'success' : 'warn') +
        (suricataEnabledOv ? (
          this._stat(suricataTotalOv, this._t('overview.stat_suricata_alerts', 'Suricata Alerts'), suricataTotalOv > 0 ? 'warn' : '') +
          this._stat(suricataCritOv, this._t('overview.stat_critical_alerts', 'Critical Alerts'), suricataCritOv > 0 ? 'danger' : '')
        ) : '') +
      '</div>' +
      '<div class="two-col">' +
        (netflowEnabled ? ('<div class="card">' +
          '<div class="card-title">' + this._t('overview.netflow_title', 'NetFlow Listener Health') + '</div>' +
          this._hrow(this._t('overview.status_label', 'Status'), (function(){ var lf = s.last_flow_at; if (!lf) return self._t('overview.no_flows_seen', 'No flows seen'); var age = Date.now() - new Date(lf).getTime(); return age < 90000 ? self._t('overview.receiving_flows', 'Receiving flows') : self._t('overview.no_flows_idle_prefix', 'No flows (idle ') + (age < 3600000 ? Math.floor(age/60000) + 'm' : Math.floor(age/3600000) + 'h') + ')'; })(), (function(){ var lf = s.last_flow_at; return lf && (Date.now() - new Date(lf).getTime()) < 90000 ? 'good' : 'warn'; })()) +
          this._hrow(this._t('overview.uptime_label', 'Uptime'), this._uptime(s.collector_started_at), '') +
          this._hrow(this._t('overview.exporters_label', 'Exporters'), exporters.join(', ') || '\u2014', '') +
          this._hrow(this._t('overview.flow_versions', 'Flow versions'), (s.versions_seen || []).join(', ') || '\u2014', '') +
          this._hrow(this._t('overview.total_datagrams', 'Total datagrams'), totalDatagrams.toLocaleString(), '') +
          this._hrow(this._t('overview.parsed', 'Parsed'), parsed.toLocaleString() + ' (' + pct + '%)', pct > 90 ? 'good' : pct > 50 ? 'warn' : 'bad') +
          this._hrow(this._t('overview.dropped', 'Dropped'), dropped.toLocaleString(), dropped > 0 ? 'warn' : 'good') +
          this._hrow(this._t('overview.last_flow', 'Last flow'), this._ago(s.last_flow_at), '') +
          (s.last_parser_error ? this._hrow(this._t('overview.last_error', 'Last error'), s.last_parser_error, 'bad') : '') +
          '<div style="margin-top:10px"><button class="btn" data-view="statistics">' + this._t('overview.view_statistics', 'View Statistics \u2192') + '</button></div>' +
        '</div>') : '') +
        '<div class="card"' + (!netflowEnabled ? ' style="grid-column:1/-1"' : '') + '>' +
          '<div class="card-title">' + this._t('overview.recent_alerts', 'Recent Alerts') + '</div>' +
          (recent.length === 0
            ? '<div class="empty-state"><div class="empty-icon">\u2713</div><p>' + self._t('overview.no_active_findings', 'No active high/critical findings') + '</p></div>'
            : recent.map(function(f) {
                return '<div class="alert-row">' + self._sev(f.severity) +
                  '<div class="alert-body"><div class="alert-sum">' + self._esc(f.summary) + '</div>' +
                  '<div class="alert-meta"><span class="ip">' + f.source_ip + '</span> \u00B7 ' + self._ago(f.last_seen) + '</div></div></div>';
              }).join('')
          ) +
          (findings.length > 5 ? '<button class="btn" style="margin-top:10px" data-view="findings">' + self._t('overview.view_all_findings', 'View all findings \u2192') + '</button>' : '') +
        '</div>' +
      '</div>' +
      (function() {
        var scanAt = self._data && self._data.scan_last_at;
        var scanDur = self._data && self._data.scan_duration;
        var scanHosts = self._data && self._data.scan_hosts_found;
        var scanInterval = self._data && self._data.scan_interval;
        var scanResult = self._data && self._data.scan_last_status;
        var scanTargets = self._data && self._data.scan_last_targets;
        var scanAge = scanAt ? self._ago(scanAt) : self._t('overview.never', 'never');
        var scanStatus = scanAt ? ((Date.now() - new Date(scanAt).getTime()) < (scanInterval || 300) * 2 * 1000 ? 'good' : 'warn') : 'warn';
        var durStr = scanDur != null ? (scanDur < 60 ? scanDur.toFixed(1) + '\u00a0s' : (scanDur / 60).toFixed(1) + '\u00a0min') : '\u2014';
        var hostsStr = scanHosts != null ? scanHosts.toLocaleString() : '\u2014';
        var intervalStr = scanInterval != null ? (scanInterval < 60 ? scanInterval + '\u00a0s' : Math.round(scanInterval / 60) + '\u00a0min') : '\u2014';
        var targetsStr = scanTargets != null ? scanTargets.toLocaleString() : '\u2014';
        var resultText = '\u2014', resultTone = '';
        if (scanResult === 'ok') { resultText = self._t('overview.scan_completed', 'Completed'); resultTone = 'good'; }
        else if (scanResult === 'no_targets') { resultText = self._t('overview.scan_skipped', 'Skipped \u2014 no targets discovered yet'); resultTone = 'warn'; }
        return '<div class="card" style="margin-top:12px">' +
          '<div class="card-title">' + self._t('overview.active_scan_title', 'Active Scan') + '</div>' +
          self._hrow(self._t('overview.last_scan', 'Last scan'), scanAge, scanStatus) +
          self._hrow(self._t('overview.last_result', 'Last result'), resultText, resultTone) +
          self._hrow(self._t('overview.duration', 'Duration'), durStr, '') +
          self._hrow(self._t('overview.hosts_found', 'Hosts found'), hostsStr, scanHosts > 0 ? '' : 'warn') +
          self._hrow(self._t('overview.targets_scanned', 'Targets scanned'), targetsStr, (scanTargets != null && scanTargets > 0) ? '' : 'warn') +
          self._hrow(self._t('overview.scan_interval', 'Scan interval'), intervalStr, '') +
          '<div style="margin-top:10px"><button class="btn" data-service-action="trigger_scan">' + self._t('overview.force_scan_btn', 'Force hosts scan \u21bb') + '</button></div>' +
        '</div>';
      })() +
      '<div class="card" style="margin-top:12px">' +
        '<div class="card-title">' + this._t('overview.nvd_title', 'Vulnerability Intelligence (NVD)') + '</div>' +
        this._hrow(this._t('overview.last_db_fetch', 'Last database fetch'), nvdAge, nvdStatus) +
        this._hrow(this._t('overview.cache_ttl', 'Cache TTL'), nvdTtl, '') +
        this._hrow(this._t('overview.cves_in_db', 'CVEs in database'), nvdTotalCves.toLocaleString(), '') +
        this._hrow(this._t('overview.min_pub_year', 'Min publication year'), nvdMinYear ? nvdMinYear : this._t('overview.all_years', 'All years'), '') +
        (function() {
          var kws = (self._data && self._data.nvd_keywords) || [];
          if (!kws.length) return self._hrow(self._t('overview.keywords_label', 'Keywords'), self._t('overview.none_loaded', 'None loaded yet'), 'warn');
          var configured = kws.filter(function(k) { return k.source === 'custom'; });
          var dynamic = kws.filter(function(k) { return k.source !== 'custom'; });
          var cfgStyle = 'background:rgba(158,150,255,.22);border-color:rgba(158,150,255,.5);color:#c4bfff';
          var dynStyle = 'background:rgba(107,255,200,.18);border-color:rgba(107,255,200,.45);color:#6bffc8';
          function renderChips(list, style) {
            return list.map(function(k) {
              return '<span class="chip" style="' + style + '" title="' + self._esc(k.keyword) + ' \u00B7 ' + k.cve_count + ' CVEs \u00B7 source: ' + self._esc(k.source) + '">'
                + self._esc(k.keyword) + ' <span style="opacity:.55;font-size:9px">(' + k.cve_count + ')</span></span>';
            }).join(' ');
          }
          var html = '<div class="section-label" style="margin-top:10px;margin-bottom:4px">NVD ' + self._t('overview.keywords_label', 'Keywords') + ' (' + kws.length + ')</div>';
          html += '<div style="display:flex;gap:14px;align-items:center;font-size:10px;color:var(--muted);margin-bottom:6px">' +
            '<span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(158,150,255,.7);background:rgba(158,150,255,.35)"></span> ' + self._t('overview.kw_configured', 'Configured') + '</span>' +
            '<span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(107,255,200,.6);background:rgba(107,255,200,.3)"></span> ' + self._t('overview.kw_from_scans', 'From scans') + '</span>' +
          '</div>';
          html += '<div style="line-height:2">';
          if (configured.length) html += renderChips(configured, cfgStyle);
          if (configured.length && dynamic.length) html += ' ';
          if (dynamic.length) html += renderChips(dynamic, dynStyle);
          html += '</div>';
          return html;
        })() +
        '<div style="margin-top:10px"><button class="btn" data-view="vulnerabilities">' + this._t('overview.browse_vulns_btn', 'Browse all vulnerabilities \u2192') + '</button>' +
        ' <button class="btn" data-service-action="nvd_refresh">' + this._t('overview.force_nvd_refresh_btn', 'Force intelligence refresh \u21bb') + '</button></div>' +
      '</div>' +
      (function() {
        var kevTotal = (self._data && self._data.kev_total != null) ? self._data.kev_total : 0;
        var kevTs = self._data && self._data.kev_last_updated;
        var kevTtl = (self._data && self._data.kev_ttl_hours != null) ? self._data.kev_ttl_hours + '\u00a0h' : '\u2014';
        var kevAge = kevTs ? self._ago(kevTs) : self._t('overview.never_fetched', 'never fetched');
        var kevStatus = kevTs ? ((Date.now() - new Date(kevTs).getTime()) < 26 * 3600 * 1000 ? 'good' : 'warn') : 'warn';
        return '<div class="card">' +
          '<div class="card-title">' + self._t('overview.kev_title', 'CISA Known Exploited Vulnerabilities (KEV)') + '</div>' +
          self._hrow(self._t('overview.last_catalog_fetch', 'Last catalog fetch'), kevAge, kevStatus) +
          self._hrow(self._t('overview.cache_ttl', 'Cache TTL'), kevTtl, '') +
          self._hrow(self._t('overview.catalog_size', 'Catalog size'), kevTotal.toLocaleString(), kevTotal > 0 ? '' : 'warn') +
        '</div>';
      })() +
      (function() {
        var dnsStats = (self._data && self._data.dns_proxy_stats) || {};
        var dnsLog   = (self._data && self._data.dns_log) || [];
        var bs       = (self._data && self._data.blacklist_stats) || {};
        var dnsRunning = dnsStats.running || false;
        if (!dnsRunning) return '';
        var dnsMal  = dnsLog.filter(function(e) { return e.malicious; }).length;
        var dnsTotal = dnsStats.total_queries != null ? dnsStats.total_queries : dnsLog.length;
        var blDomains = bs.bad_domains || 0;
        var blIPs     = bs.bad_ips || 0;
        var blTotal   = blDomains + blIPs;
        var blLoaded  = blTotal > 0;
        var blParts   = [];
        if (blDomains > 0) blParts.push(blDomains.toLocaleString() + ' ' + self._t('overview.dns_domains', 'domains'));
        if (blIPs > 0)     blParts.push(blIPs.toLocaleString() + ' IPs');
        var blLabel   = blLoaded ? blParts.join(' + ') + ' ' + self._t('overview.dns_blocked_suffix', 'blocked') : (bs.last_refresh ? self._t('overview.dns_bl_empty', '0 entries \u2014 check URLs') : self._t('overview.dns_bl_downloading', 'Downloading\u2026'));
        var blStatus  = blLoaded ? 'good' : (bs.last_refresh ? 'bad' : '');
        return '<div class="card" style="margin-top:12px">' +
          '<div class="card-title">' + self._t('overview.dns_proxy_title', 'DNS Proxy') + '</div>' +
          self._hrow(self._t('overview.status_label', 'Status'), self._t('overview.dns_running', 'Running'), 'good') +
          self._hrow(self._t('overview.port_label', 'Port'), String(dnsStats.port || '\u2014'), '') +
          self._hrow(self._t('overview.upstream_label', 'Upstream'), String(dnsStats.upstream || '\u2014'), '') +
          self._hrow(self._t('overview.blocklist_label', 'Blocklist'), blLabel, blStatus) +
          (bs.last_refresh ? self._hrow(self._t('overview.last_refreshed', 'Last refreshed'), self._ago(bs.last_refresh), '') : '') +
          self._hrow(self._t('overview.queries_in_log', 'Queries in log'), dnsLog.length.toLocaleString(), '') +
          self._hrow(self._t('overview.malicious_queries', 'Malicious queries'), dnsMal.toLocaleString(), dnsMal > 0 ? 'bad' : 'good') +
          (function() {
            var dnsBlocked = dnsLog.filter(function(e) { return e.status === 'blocked'; }).length;
            return dnsBlocked > 0 ? self._hrow(self._t('overview.blocked_queries', 'Blocked queries'), dnsBlocked.toLocaleString(), 'bad') : '';
          })() +
          '<div style="margin-top:10px"><button class="btn" data-view="dns">' + self._t('overview.view_dns_btn', 'View DNS Queries \u2192') + '</button></div>' +
        '</div>';
      })() +
      (function() {
        if (!suricataEnabledOv) return '';
        var sStats = suricataStatsOv;
        var sLog   = suricataLogOv;
        var sRunning = sStats.running || false;
        var sPort    = sStats.port || '\u2014';
        var sUptime  = sStats.started_at ? self._uptime(sStats.started_at) : '\u2014';
        var sExporters = (sStats.exporter_ips && sStats.exporter_ips.length) ? sStats.exporter_ips.join(', ') : '\u2014';
        var sTotal   = sLog.length;
        var sCrit    = sLog.filter(function(e) { return e.severity === 1; }).length;
        var sConns   = sStats.active_connections != null ? sStats.active_connections : 0;
        return '<div class="card" style="margin-top:12px">' +
          '<div class="card-title">' + self._t('overview.suricata_listener_title', 'Suricata Alert Listener') + '</div>' +
          self._hrow(self._t('overview.status_label', 'Status'), sRunning ? self._t('overview.suricata_active', 'Active') : self._t('overview.suricata_inactive', 'Inactive'), sRunning ? 'good' : 'warn') +
          self._hrow(self._t('overview.port_label', 'Port'), String(sPort), '') +
          self._hrow(self._t('overview.uptime_label', 'Uptime'), sUptime, '') +
          self._hrow(self._t('overview.exporter_ips_label', 'Exporter IP(s)'), sExporters, sConns > 0 ? 'good' : '') +
          self._hrow(self._t('overview.active_connections', 'Active connections'), String(sConns), sConns > 0 ? 'good' : '') +
          self._hrow(self._t('overview.alerts_in_log', 'Alerts in log'), sTotal.toLocaleString(), sTotal > 0 ? 'warn' : 'good') +
          self._hrow(self._t('overview.critical_alerts_label', 'Critical alerts'), sCrit.toLocaleString(), sCrit > 0 ? 'bad' : 'good') +
          '<div style="margin-top:10px"><button class="btn" data-view="suricata">' + self._t('overview.view_suricata_btn', 'View Suricata Alerts \u2192') + '</button></div>' +
        '</div>';
      })() +
      (baselineEnabled ? (baselineCard + self._baselineDevianceCard()) : '') +
    '</div>';
  }

  // ── Baseline deviance score card ─────────────────────────────────────
  _baselineDevianceCard() {
    var self = this;
    var baseline = (this._data && this._data.baseline) || {};
    if ((baseline.mode || 'disabled') !== 'active') return '';
    var baselineGraph = (this._data && this._data.baseline_graph) || null;
    if (!baselineGraph || !(baselineGraph.edges && baselineGraph.edges.length)) return '';
    var connections = (this._data && this._data.connections) || [];

    // Build edge indices (same logic as _composeMapEdges but mode-neutral)
    var live = this._buildLiveEdgeIndex(connections);
    var base = this._buildBaselineEdgeIndex(baselineGraph);
    var keys = {};
    Object.keys(live).forEach(function(k) { keys[k] = true; });
    Object.keys(base).forEach(function(k) { keys[k] = true; });

    var cntNew = 0, cntMissing = 0, cntBoth = 0;
    var topDelta = null, topDeltaAbs = 0;
    for (var key in keys) {
      var le = live[key];
      var be = base[key];
      if (le && be)       { cntBoth++;    var d = (le.live_flows || 0) - (be.avg_flows || 0); if (Math.abs(d) > topDeltaAbs) { topDeltaAbs = Math.abs(d); topDelta = { source: le.source, target: le.target, delta: d }; } }
      else if (le && !be) { cntNew++;     }
      else                { cntMissing++; }
    }

    // ── Score (0-100) ────────────────────────────────────────────────
    // New connections are the primary security signal (weight 80%).
    // Missing connections are expected in any snapshot vs. the full training
    // period, so they only contribute 20% to keep the score fair.
    var activeLive   = cntNew + cntBoth;
    var totalKnown   = cntBoth + cntMissing;
    var newRatio     = activeLive  > 0 ? cntNew     / activeLive  : 0;
    var missingRatio = totalKnown  > 0 ? cntMissing / totalKnown  : 0;
    var score        = Math.min(100, Math.round(newRatio * 80 + missingRatio * 20));

    // ── Band ─────────────────────────────────────────────────────────
    var band, bandColor, bandBg, bandBorder, bandDesc;
    if (score <= 20) {
      band = this._t('overview.band_normal', 'Normal');         bandColor = '#3ddc84'; bandBg = 'rgba(61,220,132,.10)'; bandBorder = 'rgba(61,220,132,.35)';
      bandDesc = this._t('overview.band_desc_normal', 'Traffic closely matches your baseline. No action needed.');
    } else if (score <= 50) {
      band = this._t('overview.band_review', 'Review');         bandColor = '#ffce54'; bandBg = 'rgba(255,206,84,.10)'; bandBorder = 'rgba(255,206,84,.35)';
      bandDesc = this._t('overview.band_desc_review', 'Some deviation from baseline detected. Worth a quick look.');
    } else if (score <= 75) {
      band = this._t('overview.band_investigate', 'Investigate');    bandColor = '#ff9640'; bandBg = 'rgba(255,150,64,.10)'; bandBorder = 'rgba(255,150,64,.35)';
      bandDesc = this._t('overview.band_desc_investigate', 'Noticeable deviation from baseline. Review unexpected connections.');
    } else {
      band = this._t('overview.band_critical', 'Critical');       bandColor = '#ff5a32'; bandBg = 'rgba(255,90,50,.10)'; bandBorder = 'rgba(255,90,50,.40)';
      bandDesc = this._t('overview.band_desc_critical', 'Significant deviation from baseline. Investigate immediately.');
    }

    // ── Progress bar ─────────────────────────────────────────────────
    var barFill = score <= 20 ? '#3ddc84' : score <= 50 ? '#ffce54' : score <= 75 ? '#ff9640' : '#ff5a32';

    // ── Row helpers ──────────────────────────────────────────────────
    function row(icon, count, label, note, iconColor) {
      return '<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">' +
        '<span style="font-size:16px;line-height:1.2;flex-shrink:0;color:' + iconColor + '">' + icon + '</span>' +
        '<div style="flex:1;min-width:0">' +
          '<span style="font-size:14px;font-weight:600;color:' + iconColor + '">' + count + '</span>' +
          ' <span style="font-size:12px;color:var(--fg)">' + label + '</span>' +
          '<div style="font-size:11px;color:var(--muted);margin-top:1px">' + note + '</div>' +
        '</div>' +
      '</div>';
    }

    // ── Top-delta plain English ──────────────────────────────────────
    var topDeltaHtml = '';
    if (topDelta) {
      var d   = topDelta.delta;
      var abs = Math.abs(d);
      var dirKey = d > 0 ? 'busier' : 'quieter';
      var magKey = abs > 10000 ? 'far' : abs > 1000 ? 'noticeably' : abs > 100 ? 'somewhat' : 'slightly';
      var trafficMagDir = self._t('overview.traffic_' + magKey + '_' + dirKey, magKey + ' ' + dirKey);
      var sign = d > 0 ? '+' : '';
      topDeltaHtml =
        '<div style="margin-top:10px;padding:8px 10px;border-radius:8px;background:rgba(255,206,84,.07);border:1px solid rgba(255,206,84,.22);font-size:11px">' +
          '<span style="color:#ffce54;font-weight:600">' + self._t('overview.biggest_traffic_change', '\u0394 Biggest traffic change') + '</span>' +
          '<div style="margin-top:3px;color:var(--fg)">' +
            '<span style="font-family:monospace;font-size:11px">' + topDelta.source + ' \u2192 ' + topDelta.target + '</span>' +
          '</div>' +
          '<div style="color:var(--muted);margin-top:2px">' + self._t('overview.traffic_change_pre', 'This known connection is') + ' <b style="color:var(--fg)">' + trafficMagDir + '</b> ' + self._t('overview.traffic_change_mid', 'than usual') + ' (' + sign + Math.round(d) + '\u00a0' + self._t('overview.traffic_change_post', 'flows/snapshot).') +
            (abs > 1000 ? ' ' + self._t('overview.traffic_change_file_hint', 'Could be a file transfer, backup, or update in progress.') : '') +
          '</div>' +
        '</div>';
    }

    return '<div class="card" style="margin-top:12px">' +
      '<div class="card-title">' + this._t('overview.network_behaviour_title', 'Network Behaviour') + '</div>' +

      // Score row
      '<div style="display:flex;align-items:center;gap:14px;margin-bottom:10px">' +
        '<div style="position:relative;flex-shrink:0">' +
          '<svg width="64" height="64" viewBox="0 0 64 64">' +
            // background ring
            '<circle cx="32" cy="32" r="26" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="7"/>' +
            // foreground arc: circumference = 2πr ≈ 163.4; dashoffset drives fill
            '<circle cx="32" cy="32" r="26" fill="none" stroke="' + barFill + '" stroke-width="7"' +
              ' stroke-dasharray="163.4" stroke-dashoffset="' + (163.4 * (1 - score / 100)).toFixed(1) + '"' +
              ' stroke-linecap="round" transform="rotate(-90 32 32)"/>' +
            '<text x="32" y="37" text-anchor="middle" font-size="14" font-weight="700" fill="' + barFill + '">' + score + '</text>' +
          '</svg>' +
        '</div>' +
        '<div style="flex:1">' +
          '<div style="display:inline-block;padding:3px 12px;border-radius:100px;background:' + bandBg + ';border:1px solid ' + bandBorder + ';color:' + bandColor + ';font-size:12px;font-weight:600;margin-bottom:5px">' + band + '</div>' +
          '<div style="font-size:12px;color:var(--muted)">' + bandDesc + '</div>' +
        '</div>' +
      '</div>' +

      // Breakdown rows
      row('\u2191', cntNew,
        cntNew === 1 ? self._t('overview.new_conn_single', 'unexpected new connection') : self._t('overview.new_conn_plural', 'unexpected new connections'),
        cntNew === 0
          ? self._t('overview.new_conn_note_none', 'No unknown activity \u2014 all current traffic was seen during training.')
          : self._t('overview.new_conn_note_some', 'These connections were not present during baseline training.') + ' ' + (cntNew > 5 ? self._t('overview.new_conn_note_investigate', 'This is the main driver of your score \u2014 investigate.') : self._t('overview.new_conn_note_review', 'Review to confirm they are expected.')),
        cntNew === 0 ? '#3ddc84' : cntNew <= 3 ? '#ffce54' : '#ff5a32') +

      row('\u2193', cntMissing,
        cntMissing === 1 ? self._t('overview.missing_conn_single', 'baseline connection not active now') : self._t('overview.missing_conn_plural', 'baseline connections not active now'),
        self._t('overview.missing_conn_note', 'Connections seen during training that are quiet right now. This is usually normal \u2014 devices don\u2019t maintain all connections at all times.') + ' ' +
          (cntMissing > totalKnown * 0.9
            ? self._t('overview.missing_conn_note_high', 'The count is very high, but your baseline likely captured many short-lived flows over a long training window.')
            : ''),
        '#88a7c7') +

      row('=', cntBoth,
        cntBoth === 1 ? self._t('overview.both_conn_single', 'connection matches baseline exactly') : self._t('overview.both_conn_plural', 'connections match baseline exactly'),
        cntBoth > 0
          ? self._t('overview.both_conn_note_some', 'These connections are active now and were seen during training \u2014 your expected, normal traffic.')
          : self._t('overview.both_conn_note_none', 'No currently active connections were seen in the baseline yet.'),
        '#3ac5c9') +

      topDeltaHtml +

      '<div style="margin-top:10px"><button class="btn" data-view="map" data-map-mode="compare">' + self._t('overview.view_map_btn', 'View on Network Map \u2192') + '</button></div>' +
    '</div>';
  }

  // ── SVG donut-pie chart helper ───────────────────────────────────────
  _pieSvg(items, getVal, getLabel, colors) {
    var total = items.reduce(function(s, it) { return s + getVal(it); }, 0);
    if (!total) return '<div style="text-align:center;color:var(--muted);padding:20px;font-size:11px">No data</div>';
    var size = 130, cx = 65, cy = 65, r = 52, ri = 28;
    var TAU = Math.PI * 2;
    var angle = -Math.PI / 2;
    var GAP = 0.018;
    var paths = '';
    items.forEach(function(it, i) {
      var val = getVal(it);
      if (!val) return;
      var sweep = (val / total) * TAU;
      if (sweep < 0.004) return;
      var a1 = angle + GAP / 2;
      var a2 = angle + sweep - GAP / 2;
      var x1 = (cx + r * Math.cos(a1)).toFixed(2), y1 = (cy + r * Math.sin(a1)).toFixed(2);
      var x2 = (cx + r * Math.cos(a2)).toFixed(2), y2 = (cy + r * Math.sin(a2)).toFixed(2);
      var xi1 = (cx + ri * Math.cos(a1)).toFixed(2), yi1 = (cy + ri * Math.sin(a1)).toFixed(2);
      var xi2 = (cx + ri * Math.cos(a2)).toFixed(2), yi2 = (cy + ri * Math.sin(a2)).toFixed(2);
      var large = (a2 - a1) > Math.PI ? 1 : 0;
      var d = 'M ' + x1 + ' ' + y1 +
              ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + x2 + ' ' + y2 +
              ' L ' + xi2 + ' ' + yi2 +
              ' A ' + ri + ' ' + ri + ' 0 ' + large + ' 0 ' + xi1 + ' ' + yi1 + ' Z';
      paths += '<path d="' + d + '" fill="' + colors[i % colors.length] + '" opacity="0.88"><title>' + getLabel(it) + '</title></path>';
      angle += sweep;
    });
    return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" style="flex-shrink:0">' + paths + '</svg>';
  }

  // ── Pie chart legend helper ──────────────────────────────────────────
  _statsLegend(items, getVal, getLabel, colors) {
    var total = items.reduce(function(s, it) { return s + getVal(it); }, 0);
    return items.map(function(it, i) {
      var val = getVal(it);
      var pct = total > 0 ? Math.round((val / total) * 100) : 0;
      return '<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;font-size:11px">' +
        '<div style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + colors[i % colors.length] + ';opacity:.88"></div>' +
        '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + getLabel(it) + '</span>' +
        '<span style="color:var(--muted);white-space:nowrap;margin-left:4px">' + pct + '%</span>' +
      '</div>';
    }).join('');
  }

  // ── SVG line/area chart helper ───────────────────────────────────────
  // series: [{key, label, color}]  points: array of timeseries objects with a "ts" field
  _lineChart(points, series) {
    var W = 560, H = 120, ML = 42, MR = 14, MT = 8, MB = 28;
    var PW = W - ML - MR, PH = H - MT - MB;
    if (!points || points.length < 2) {
      return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">Not enough data yet — check back after a few minutes</div>';
    }
    var parsed = [];
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (!isNaN(t)) parsed.push({ t: t, d: points[i] });
    }
    if (parsed.length < 2) return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">No data for this period</div>';
    var tMin = parsed[0].t, tMax = parsed[parsed.length - 1].t, tRange = tMax - tMin || 1;
    function xp(t) { return (ML + (t - tMin) / tRange * PW).toFixed(1); }
    var svg = '';
    // Border + horizontal gridlines
    svg += '<rect x="' + ML + '" y="' + MT + '" width="' + PW + '" height="' + PH + '" fill="none" stroke="rgba(255,255,255,.08)" rx="2"/>';
    [0.25, 0.5, 0.75].forEach(function(f) {
      var gy = (MT + PH * f).toFixed(1);
      svg += '<line x1="' + ML + '" y1="' + gy + '" x2="' + (ML + PW) + '" y2="' + gy + '" stroke="rgba(255,255,255,.05)"/>';
    });
    // X-axis ticks
    var xRangeH = tRange / 3600000;
    for (var ti = 0; ti <= 5; ti++) {
      var tt = tMin + tRange * ti / 5;
      var tx = xp(tt);
      var dd = new Date(tt);
      var lbl = xRangeH <= 48
        ? dd.getHours().toString().padStart(2,'0') + ':' + dd.getMinutes().toString().padStart(2,'0')
        : (dd.getMonth()+1) + '/' + dd.getDate();
      svg += '<line x1="' + tx + '" y1="' + (MT+PH) + '" x2="' + tx + '" y2="' + (MT+PH+4) + '" stroke="rgba(255,255,255,.15)"/>';
      svg += '<text x="' + tx + '" y="' + (MT+PH+14) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + lbl + '</text>';
      if (ti > 0 && ti < 5) svg += '<line x1="' + tx + '" y1="' + MT + '" x2="' + tx + '" y2="' + (MT+PH) + '" stroke="rgba(255,255,255,.04)"/>';
    }
    // Compute overall Y max across all series for a shared scale
    var yMaxAll = 1;
    series.forEach(function(s) {
      parsed.forEach(function(p) { var v = Number(p.d[s.key] || 0); if (v > yMaxAll) yMaxAll = v; });
    });
    // Y-axis labels (left side)
    [0, 0.5, 1].forEach(function(f) {
      var yv = Math.round(yMaxAll * f);
      var yy = (MT + PH - f * PH).toFixed(1);
      svg += '<text x="' + (ML-4) + '" y="' + yy + '" dy="0.35em" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="end">' + yv + '</text>';
    });
    // Series lines + area fills
    series.forEach(function(s, si) {
      var gradId = 'tlg-' + s.key;
      svg += '<defs><linearGradient id="' + gradId + '" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="' + s.color + '" stop-opacity="0.28"/>' +
        '<stop offset="100%" stop-color="' + s.color + '" stop-opacity="0.02"/>' +
        '</linearGradient></defs>';
      function yp(v) { return (MT + PH - (Math.min(v, yMaxAll) / yMaxAll) * PH).toFixed(1); }
      var lineD = parsed.map(function(p, i) {
        return (i === 0 ? 'M' : 'L') + xp(p.t) + ',' + yp(Number(p.d[s.key] || 0));
      }).join(' ');
      var areaD = lineD + ' L' + xp(parsed[parsed.length-1].t) + ',' + (MT+PH) + ' L' + xp(parsed[0].t) + ',' + (MT+PH) + ' Z';
      svg += '<path d="' + areaD + '" fill="url(#' + gradId + ')"/>';
      svg += '<path d="' + lineD + '" fill="none" stroke="' + s.color + '" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>';
    });
    var legend = series.map(function(s) {
      return '<span style="color:' + s.color + ';font-size:10px;margin-right:10px">' +
        '<svg width="14" height="2" style="vertical-align:middle;margin-right:3px;overflow:visible"><line x1="0" y1="1" x2="14" y2="1" stroke="' + s.color + '" stroke-width="2"/></svg>' + s.label + '</span>';
    }).join('');
    return '<div style="width:100%;height:' + H + 'px">' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="100%" preserveAspectRatio="none">' + svg + '</svg>' +
      '</div><div style="text-align:right;margin-top:3px">' + legend + '</div>';
  }

  // ── Hourly bar chart (max value per 1-hour bucket) ────────────────────
  _hourlyBarChart(points, key, color) {
    var W = 560, H = 120, ML = 42, MR = 14, MT = 8, MB = 28;
    var PW = W - ML - MR, PH = H - MT - MB;
    if (!points || points.length < 2) {
      return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">Not enough data yet — check back after a few minutes</div>';
    }
    // Determine time range from the points
    var tMin = Infinity, tMax = -Infinity;
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (!isNaN(t)) { if (t < tMin) tMin = t; if (t > tMax) tMax = t; }
    }
    if (!isFinite(tMin)) return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">No data for this period</div>';
    // Snap tMin back to the start of its hour so buckets align to clock hours
    var tMinHour = Math.floor(tMin / 3600000) * 3600000;
    var numBuckets = Math.max(1, Math.ceil((tMax - tMinHour) / 3600000));
    // Limit to a reasonable display maximum
    if (numBuckets > 168) numBuckets = 168;  // cap at 7 days of hours
    var buckets = new Array(numBuckets).fill(0);
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (isNaN(t)) continue;
      var bi = Math.floor((t - tMinHour) / 3600000);
      if (bi < 0) bi = 0;
      if (bi >= numBuckets) bi = numBuckets - 1;
      var v = Number(points[i][key] || 0);
      if (v > buckets[bi]) buckets[bi] = v;
    }
    var yMax = 1;
    for (var i = 0; i < buckets.length; i++) { if (buckets[i] > yMax) yMax = buckets[i]; }
    var barW = Math.max(1, (PW / numBuckets) - 1);
    var svg = '';
    // Border
    svg += '<rect x="' + ML + '" y="' + MT + '" width="' + PW + '" height="' + PH + '" fill="none" stroke="rgba(255,255,255,.08)" rx="2"/>';
    // Horizontal gridlines
    [0.25, 0.5, 0.75].forEach(function(f) {
      var gy = (MT + PH * f).toFixed(1);
      svg += '<line x1="' + ML + '" y1="' + gy + '" x2="' + (ML + PW) + '" y2="' + gy + '" stroke="rgba(255,255,255,.05)"/>';
    });
    // Bars
    for (var i = 0; i < numBuckets; i++) {
      var bh = ((buckets[i] / yMax) * PH);
      var bx = (ML + i * (PW / numBuckets)).toFixed(1);
      var by = (MT + PH - bh).toFixed(1);
      svg += '<rect x="' + bx + '" y="' + by + '" width="' + barW.toFixed(1) + '" height="' + bh.toFixed(1) + '" fill="' + color + '" opacity="0.75" rx="1"/>';
    }
    // X-axis ticks — show up to 6 labels
    var tickCount = Math.min(6, numBuckets);
    for (var ti = 0; ti <= tickCount; ti++) {
      var frac = ti / tickCount;
      var tx = (ML + frac * PW).toFixed(1);
      var tt = tMinHour + frac * (numBuckets * 3600000);
      var dd = new Date(tt);
      var lbl = numBuckets <= 48
        ? dd.getHours().toString().padStart(2,'0') + ':00'
        : (dd.getMonth()+1) + '/' + dd.getDate();
      svg += '<line x1="' + tx + '" y1="' + (MT+PH) + '" x2="' + tx + '" y2="' + (MT+PH+4) + '" stroke="rgba(255,255,255,.15)"/>';
      svg += '<text x="' + tx + '" y="' + (MT+PH+14) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + lbl + '</text>';
    }
    // Y-axis labels
    [0, 0.5, 1].forEach(function(f) {
      var yv = Math.round(yMax * f);
      var yy = (MT + PH - f * PH).toFixed(1);
      svg += '<text x="' + (ML-4) + '" y="' + yy + '" dy="0.35em" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="end">' + yv + '</text>';
    });
    return '<div style="width:100%;height:' + H + 'px">' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="100%" preserveAspectRatio="none">' + svg + '</svg>' +
      '</div>';
  }

  // ── Statistics view ──────────────────────────────────────────────────
  _viewStatistics() {
    var self = this;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var dnsProxyEnabledRaw = this._data && this._data.dns_proxy_enabled;
    var dnsProxyEnabled = dnsProxyEnabledRaw === true || dnsProxyEnabledRaw === 'true' || dnsProxyEnabledRaw === 1 || dnsProxyEnabledRaw === '1';
    var suricataEnabledStats = (this._data && this._data.suricata_stats && this._data.suricata_stats.running) || false;
    var modes = this._statsViewModes;
    var topN = (this._data && this._data.stats_top_n) || 10;
    var COLORS = ['#8f86ff','#3ac5c9','#6bffc8','#ffc107','#ff8c42','#ff4d6d','#7fb3f5','#d4a843','#a8e063','#f472b6','#60a5fa','#34d399','#fb923c','#a78bfa','#22d3ee'];

    // ── Suricata pie data ─────────────────────────────────────────────
    var suricataLogStats = (this._data && this._data.suricata_log) || [];
    var SUC_SEV_COLORS = ['rgba(255,77,109,1)','rgba(255,179,71,1)','rgba(107,255,200,1)'];
    var SUC_CAT_PALETTE = ['rgba(255,77,109,1)','rgba(255,179,71,1)','rgba(107,255,200,1)','rgba(98,232,255,1)','rgba(191,111,255,1)','rgba(59,178,255,1)','rgba(72,199,142,1)','rgba(255,159,67,1)'];
    var SUC_SRC_PALETTE = ['rgba(98,232,255,1)','rgba(59,178,255,1)','rgba(72,199,142,1)','rgba(191,111,255,1)','rgba(255,179,71,1)','rgba(255,77,109,1)','rgba(107,255,200,1)','rgba(155,135,245,1)'];
    var sucSevLabels = { 1:this._t('suricata.sev_critical', 'Critical'), 2:this._t('suricata.sev_major', 'Major'), 3:this._t('suricata.sev_minor', 'Minor') };
    var sucSevData = [1,2,3].filter(function(s){return suricataLogStats.some(function(e){return e.severity===s;});}).map(function(s){return{label:sucSevLabels[s],value:suricataLogStats.filter(function(e){return e.severity===s;}).length};});
    var sucCatCounts = {}; var sucCatColors = [];
    suricataLogStats.forEach(function(e){var c=e.category||'Other';sucCatCounts[c]=(sucCatCounts[c]||0)+1;});
    var sucCatData = Object.keys(sucCatCounts).sort(function(a,b){return sucCatCounts[b]-sucCatCounts[a];}).map(function(k,i){sucCatColors.push(SUC_CAT_PALETTE[i%SUC_CAT_PALETTE.length]);return{label:k,value:sucCatCounts[k]};});
    var sucSrcCounts = {};
    suricataLogStats.forEach(function(e){var ip=e.src_ip||'unknown';sucSrcCounts[ip]=(sucSrcCounts[ip]||0)+1;});
    var sucSrcData = Object.keys(sucSrcCounts).sort(function(a,b){return sucSrcCounts[b]-sucSrcCounts[a];}).slice(0,topN).map(function(k){return{label:k,value:sucSrcCounts[k]};});

    // ── Timeline ─────────────────────────────────────────────────────
    var allPoints = (this._data && this._data.timeseries) || [];


    // Public IPs per period — derived from last_seen on each external IP entry
    var _extIpsList = (this._data && this._data.external_ips) || [];
    var _now = Date.now();
    var extIps1h    = _extIpsList.filter(function(e) { return e.last_seen && (_now - new Date(e.last_seen).getTime()) <= 3600000; }).length;
    var extIps24h   = _extIpsList.filter(function(e) { return e.last_seen && (_now - new Date(e.last_seen).getTime()) <= 86400000; }).length;
    var extIps7d    = _extIpsList.filter(function(e) { return e.last_seen && (_now - new Date(e.last_seen).getTime()) <= 604800000; }).length;
    var extIpsTotal = _extIpsList.length;
    var extIpsBadges =
      '<span style="font-size:10px;color:var(--muted)">' +
        '1h\u00a0<strong style="color:var(--fg)">' + extIps1h + '</strong>' +
        '\u2002\u00b7\u2002' +
        '24h\u00a0<strong style="color:var(--fg)">' + extIps24h + '</strong>' +
        '\u2002\u00b7\u2002' +
        '7d\u00a0<strong style="color:var(--fg)">' + extIps7d + '</strong>' +
        '\u2002\u00b7\u2002' +
        'all\u00a0<strong style="color:var(--fg)">' + extIpsTotal + '</strong>' +
      '</span>';

    var timelineHtml = '<div class="stat-card" style="grid-column:1/-1">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">' +
        '<span class="card-title" style="margin-bottom:0">' + this._t('stats.activity_timeline', 'ACTIVITY TIMELINE') + '</span>' +
      '</div>' +
      '<div style="margin-bottom:16px">' +
        '<div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px">' +
          '<span style="font-size:10px;color:var(--muted)">' + this._t('stats.public_ips_per_hour', 'Public IPs seen per hour (last 24h)') + '</span>' +
          extIpsBadges +
        '</div>' +
        (function() {
          var EXT_H = 24, BAR_W = 18, BAR_GAP = 3, CHART_H = 60, LABEL_H = 16;
          var nowMs = Date.now();
          var extBuckets = new Array(EXT_H).fill(0);
          for (var ei = 0; ei < _extIpsList.length; ei++) {
            var fs = _extIpsList[ei].first_seen;
            if (!fs) continue;
            var ago = Math.floor((nowMs - new Date(fs).getTime()) / 3600000);
            if (ago >= 0 && ago < EXT_H) extBuckets[EXT_H - 1 - ago]++;
          }
          var maxExt = Math.max.apply(null, extBuckets) || 1;
          var svgW = EXT_H * (BAR_W + BAR_GAP);
          var bars = extBuckets.map(function(cnt, i) {
            var x = i * (BAR_W + BAR_GAP);
            var bh = Math.max(2, Math.round((cnt / maxExt) * CHART_H));
            var lhour = new Date(nowMs - (EXT_H - 1 - i) * 3600000).getHours();
            var tip = lhour + 'h \u2014 ' + cnt + ' IP' + (cnt !== 1 ? 's' : '');
            return '<rect x="' + x + '" y="' + (CHART_H - bh) + '" width="' + BAR_W + '" height="' + bh + '" fill="#8f86ff" opacity="0.75" rx="2"><title>' + tip + '</title></rect>';
          }).join('');
          var labels = '';
          for (var li = 0; li < EXT_H; li += 4) {
            var lx = li * (BAR_W + BAR_GAP) + BAR_W / 2;
            var lhour = new Date(nowMs - (EXT_H - 1 - li) * 3600000).getHours();
            labels += '<text x="' + lx + '" y="' + (CHART_H + LABEL_H - 3) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + lhour + 'h</text>';
          }
          if (!_extIpsList.length) return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">' + self._t('stats.no_public_ips', 'No public IPs tracked yet') + '</div>';
          return '<svg viewBox="0 0 ' + svgW + ' ' + (CHART_H + LABEL_H) + '" width="100%" height="' + (CHART_H + LABEL_H) + '" preserveAspectRatio="none" style="display:block">' + bars + labels + '</svg>';
        })() +
      '</div>' +
      '<div style="margin-top:16px">' +
        '<div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px">' +
          '<span style="font-size:10px;color:var(--muted)">' + this._t('stats.hosts_per_hour', 'Hosts per hour (last 24h)') + '</span>' +
        '</div>' +
        (function() {
          var H_HOURS = 24, H_BAR_W = 18, H_BAR_GAP = 3, H_CHART = 60, H_LABEL = 16;
          var nowMs2 = Date.now();
          var hostBkts = [], scannedBkts = [];
          for (var hbi = 0; hbi < H_HOURS; hbi++) {
            var hbEnd = nowMs2 - hbi * 3600000, hbStart = hbEnd - 3600000;
            var mxH = 0, mxS = 0;
            for (var hpi = 0; hpi < allPoints.length; hpi++) {
              var hpt = new Date(allPoints[hpi].ts).getTime();
              if (hpt >= hbStart && hpt < hbEnd) {
                var hv = Number(allPoints[hpi].hosts || 0), sv = Number(allPoints[hpi].scanned || 0);
                if (hv > mxH) mxH = hv;
                if (sv > mxS) mxS = sv;
              }
            }
            hostBkts.unshift(mxH);
            scannedBkts.unshift(mxS);
          }
          if (!allPoints.length) return '<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">' + self._t('stats.no_host_data', 'No host data yet') + '</div>';
          var mxAll = Math.max.apply(null, hostBkts) || 1;
          var hSvgW = H_HOURS * (H_BAR_W + H_BAR_GAP);
          var hBars = hostBkts.map(function(h, i) {
            var s = scannedBkts[i];
            var x = i * (H_BAR_W + H_BAR_GAP);
            var bh = Math.max(2, Math.round((h / mxAll) * H_CHART));
            var sh = s > 0 ? Math.max(2, Math.round((s / mxAll) * H_CHART)) : 0;
            var lhour = new Date(nowMs2 - (H_HOURS - 1 - i) * 3600000).getHours();
            var tip = lhour + 'h \u2014 ' + h + ' host' + (h !== 1 ? 's' : '') + (s > 0 ? ' (' + s + ' scanned)' : '');
            return '<rect x="' + x + '" y="' + (H_CHART - bh) + '" width="' + H_BAR_W + '" height="' + bh + '" fill="rgba(58,197,201,.45)" rx="2"><title>' + tip + '</title></rect>' +
              (sh > 0 ? '<rect x="' + x + '" y="' + (H_CHART - sh) + '" width="' + H_BAR_W + '" height="' + sh + '" fill="rgba(107,255,200,.75)" rx="2"><title>' + tip + '</title></rect>' : '');
          }).join('');
          var hLabels = '';
          for (var hl = 0; hl < H_HOURS; hl += 4) {
            var hlx = hl * (H_BAR_W + H_BAR_GAP) + H_BAR_W / 2;
            var hlHour = new Date(nowMs2 - (H_HOURS - 1 - hl) * 3600000).getHours();
            hLabels += '<text x="' + hlx + '" y="' + (H_CHART + H_LABEL - 3) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + hlHour + 'h</text>';
          }
          return '<svg viewBox="0 0 ' + hSvgW + ' ' + (H_CHART + H_LABEL) + '" width="100%" height="' + (H_CHART + H_LABEL) + '" preserveAspectRatio="none" style="display:block">' + hBars + hLabels + '</svg>' +
            '<div style="display:flex;gap:12px;margin-top:4px;font-size:10px">' +
              '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(58,197,201,.45);display:inline-block;border-radius:2px"></span>' + self._t('stats.hosts_seen', 'Hosts seen') + '</span>' +
              '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(107,255,200,.75);display:inline-block;border-radius:2px"></span>' + self._t('stats.scanned_alive', 'Scanned alive') + '</span>' +
            '</div>';
        })() +
      '</div>';
    // stat-card outer </div> is appended in the return after the DNS Activity section

    function toggleBtns(id, current) {
      return '<span style="display:flex;gap:4px;flex-shrink:0">' +
        '<button class="btn' + (current === 'pie' ? ' active' : '') + '" style="padding:3px 8px;font-size:10px" data-statstoggle="' + id + ':pie">' +
        '<svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M7 1.07A7 7 0 1 0 15 9H7V1.07z"/><path d="M8.5.5v7h7A7.5 7.5 0 0 0 8.5.5z"/></svg>' + self._t('stats.pie', 'Pie') + '</button>' +
        '<button class="btn' + (current === 'list' ? ' active' : '') + '" style="padding:3px 8px;font-size:10px" data-statstoggle="' + id + ':list">' +
        '<svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5z"/></svg>' + self._t('stats.list', 'List') + '</button>' +
      '</span>';
    }

    function chartSection(svgHtml, legendHtml) {
      return '<div class="stats-chart-row">' +
        svgHtml + '<div class="stats-chart-legend">' + legendHtml + '</div>' +
      '</div>';
    }

    // ── Top public IPs ────────────────────────────────────────────────
    var topIPs = (this._data && this._data.top_public_ips) || [];
    var ipsSection;
    if (!topIPs.length) {
      ipsSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_external_flow_data', 'No external flow data yet') + '</p></div>';
    } else if (modes.public_ips === 'pie') {
      ipsSection = chartSection(
        self._pieSvg(topIPs, function(e) { return e.flows; }, function(e) { return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : ''); }, COLORS),
        self._statsLegend(topIPs, function(e) { return e.flows; }, function(e) {
          return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : '') + (e.blacklisted ? ' \u26a0' : '');
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">' + this._t('stats.ranked_by_flow_count', 'Ranked by flow count') + '</div>' +
        '<button class="btn" style="margin-top:8px" data-view="external">' + this._t('stats.view_all_external_ips', 'View all external IPs →') + '</button>'
      );
    } else {
      ipsSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th>' +
        '</tr></thead><tbody>' +
        topIPs.map(function(e, i) {
          var label = e.hostname || e.org || e.ip;
          var country = e.country_name || e.country || '';
          var countryFlag = self._countryFlag(e.country);
          var bc = e.blacklisted ? 'badge-critical' : (e.rating === 'suspicious' ? 'badge-warn' : 'badge-ok');
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(e.ip) + '</span></td>' +
            '<td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(label) + '</td>' +
            '<td>' + (countryFlag
              ? '<span title="' + self._esc(country) + '" style="font-size:15px;line-height:1">' + countryFlag + '</span>'
              : '<span class="dim">' + self._esc(country || '—') + '</span>') + '</td>' +
            '<td style="text-align:right">' + e.flows.toLocaleString() + '</td>' +
            '<td><span class="badge ' + bc + '">' + self._esc(e.blacklisted ? 'malicious' : (e.rating || 'ok')) + '</span></td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="external">' + this._t('stats.view_all_external_ips', 'View all external IPs →') + '</button>';
    }

    // ── Top countries ─────────────────────────────────────────────────
    var topC = (this._data && this._data.top_countries) || [];
    var countriesSection;
    if (!topC.length) {
      countriesSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_country_data', 'No country data yet') + '</p></div>';
    } else if (modes.countries === 'pie') {
      countriesSection = chartSection(
        self._pieSvg(topC, function(c) { return c.flow_count; }, function(c) { return (c.country_name || c.country) + ' (' + c.ip_count + ' IPs)'; }, COLORS),
        self._statsLegend(topC, function(c) { return c.flow_count; }, function(c) {
          return (c.country_name || c.country || '\u2014') + ' (' + c.ip_count + ' IPs)';
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">' + this._t('stats.ranked_by_flow_count', 'Ranked by flow count') + '</div>'
      );
    } else {
      var maxFlows = topC[0] ? topC[0].flow_count : 1;
      countriesSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>CC</th><th>Country</th><th style="text-align:right">Unique IPs</th><th style="text-align:right">Flows</th><th>Share</th>' +
        '</tr></thead><tbody>' +
        topC.map(function(c, i) {
          var pct = maxFlows > 0 ? Math.round((c.flow_count / maxFlows) * 100) : 0;
          var ccFlag = self._countryFlag(c.country);
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><b>' + (ccFlag
              ? '<span title="' + self._esc(c.country || '—') + '" style="font-size:15px;line-height:1">' + ccFlag + '</span>'
              : self._esc(c.country || '\u2014')) + '</b></td>' +
            '<td>' + self._esc(c.country_name || c.country || '\u2014') + '</td>' +
            '<td style="text-align:right">' + c.ip_count.toLocaleString() + '</td>' +
            '<td style="text-align:right">' + c.flow_count.toLocaleString() + '</td>' +
            '<td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + pct + '%;background:var(--accent,#8f86ff);border-radius:3px;height:8px"></div></div></td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    // ── Top internal talkers ──────────────────────────────────────────
    var topT = (this._data && this._data.top_internal_talkers) || [];
    var talkersSection;
    if (!topT.length) {
      talkersSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_traffic_data', 'No traffic data yet') + '</p></div>';
    } else if (modes.talkers === 'pie') {
      talkersSection = chartSection(
        self._pieSvg(topT, function(d) { return d.total_octets; }, function(d) { return d.display_name || d.ip; }, COLORS),
        self._statsLegend(topT, function(d) { return d.total_octets; }, function(d) {
          return (d.display_name || d.ip) + ' \u00b7 ' + self._bytes(d.total_octets);
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">' + this._t('stats.ranked_by_total_traffic', 'Ranked by total traffic') + '</div>' +
        '<button class="btn" style="margin-top:8px" data-view="hosts">' + this._t('stats.view_all_hosts', 'View all hosts →') + '</button>'
      );
    } else {
      var maxOct = topT[0] ? topT[0].total_octets : 1;
      talkersSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Name</th><th>Role</th><th style="text-align:right">Traffic</th><th>Share</th>' +
        '</tr></thead><tbody>' +
        topT.map(function(d, i) {
          var pct = maxOct > 0 ? Math.round((d.total_octets / maxOct) * 100) : 0;
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(d.ip) + '</span></td>' +
            '<td>' + self._esc(d.display_name) + '</td>' +
            '<td>' + self._esc(d.probable_role || '\u2014') + '</td>' +
            '<td style="text-align:right">' + self._bytes(d.total_octets) + '</td>' +
            '<td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + pct + '%;background:#3ac5c9;border-radius:3px;height:8px"></div></div></td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="hosts">' + this._t('stats.view_all_hosts', 'View all hosts →') + '</button>';
    }

    // ── Enrichment budget (table only) ────────────────────────────────
    var eStats = (this._data && this._data.enrichment_stats) || [];
    var enrichSection;
    if (!eStats.length) {
      enrichSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_enrichment_data', 'No enrichment data') + '</p></div>';
    } else {
      enrichSection = '<div style="overflow-x:auto"><table class="data-table" style="width:100%;min-width:480px"><thead><tr>' +
        '<th>' + this._t('stats.provider', 'Provider') + '</th><th style="width:80px;text-align:right">' + this._t('stats.used_today', 'Used today') + '</th><th style="width:90px;text-align:right">' + this._t('stats.daily_budget', 'Daily budget') + '</th><th style="width:110px">' + this._t('stats.usage', 'Usage') + '</th><th style="width:80px">' + this._t('stats.status', 'Status') + '</th><th>' + this._t('stats.errors_notes', 'Errors / Notes') + '</th>' +
        '</tr></thead><tbody>' +
        eStats.map(function(s) {
          var PROV_LABELS = { ipwho: 'ipwho.is', virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB' };
          var provLabel = (PROV_LABELS[s.provider] || s.provider) + (s.variant ? ' (' + s.variant + ')' : '');
          var unlimited = s.budget === null || s.budget === undefined;
          var pct = (!unlimited && s.budget > 0) ? Math.min(100, Math.round((s.used / s.budget) * 100)) : 0;
          var barColor = s.exhausted ? '#ff4d6d' : (unlimited || pct <= 80 ? '#6bffc8' : '#ffc107');
          var badge = !s.configured ? '<span class="badge badge-dim">' + self._t('stats.not_configured', 'not configured') + '</span>' :
            (s.exhausted ? '<span class="badge badge-critical">' + self._t('stats.exhausted', 'exhausted') + '</span>' :
            (unlimited ? '<span class="badge badge-ok">' + self._t('stats.unlimited', '∞ unlimited') + '</span>' :
            (pct > 80 ? '<span class="badge badge-warn">' + self._t('stats.high', 'high') + '</span>' : '<span class="badge badge-ok">' + self._t('stats.ok', 'ok') + '</span>')));
          var errCell = '';
          if (s.last_error) {
            var errStr = String(s.last_error);
            // Auth errors (401/403) in orange; server errors (5xx) in red
            var errColor = (errStr.indexOf('401') !== -1 || errStr.indexOf('403') !== -1)
              ? '#ffc107' : '#ff4d6d';
            errCell = '<span style="color:' + errColor + ';font-size:11px;font-weight:600">\u26A0\uFE0F ' + self._esc(errStr) + '</span>';
          }
          return '<tr><td><b>' + self._esc(provLabel) + '</b></td>' +
            '<td style="text-align:right">' + s.used.toLocaleString() + '</td>' +
            '<td style="text-align:right">' + (unlimited ? '\u221e' : s.budget.toLocaleString()) + '</td>' +
            '<td style="width:120px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + (unlimited ? 100 : pct) + '%;background:' + barColor + ';border-radius:3px;height:8px"></div></div></td>' +
            '<td>' + badge + '</td>' +
            '<td>' + errCell + '</td></tr>';
        }).join('') +
        '</tbody></table></div>';
    }

    // ── Top suspicious / malicious IPs ────────────────────────────────
    var THREAT_COLORS = ['#ff4d6d','#ff8c42','#ffc107','#f472b6','#fb923c','#ff6b6b','#e879f9','#facc15','#fd8dac','#ffb347'];
    var topThr = (this._data && this._data.top_threat_ips) || [];
    var threatSection;
    if (!topThr.length) {
      threatSection = '<div class="empty-state"><div class="empty-icon" style="font-size:24px">✅</div><p style="margin:8px 0">' + this._t('stats.no_threat_ips', 'No suspicious or malicious IPs detected') + '</p></div>';
    } else if (modes.threat_ips === 'pie') {
      threatSection = chartSection(
        self._pieSvg(topThr, function(e) { return Math.max(e.flows, 1); }, function(e) {
          return e.ip + (e.hostname ? ' (' + e.hostname + ')' : '') + ' — ' + e.rating;
        }, THREAT_COLORS),
        self._statsLegend(topThr, function(e) { return Math.max(e.flows, 1); }, function(e) {
          var label = e.hostname || e.org || e.ip;
          return label + ' · ' + e.rating + (e.flows ? ' · ' + e.flows.toLocaleString() + ' flows' : '');
        }, THREAT_COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">' + this._t('stats.malicious_first', 'Malicious first, then by flow count') + '</div>' +
        '<button class="btn" style="margin-top:8px" data-view="external">' + this._t('stats.view_all_external_ips', 'View all external IPs →') + '</button>'
      );
    } else {
      threatSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th><th>Details</th>' +
        '</tr></thead><tbody>' +
        topThr.map(function(e, i) {
          var label = e.hostname || e.org || e.ip;
          var country = e.country_name || e.country || '';
          var countryFlag = self._countryFlag(e.country);
          var bc = e.rating === 'malicious' ? 'badge-critical' : 'badge-warn';
          var details = [];
          if (e.vt_malicious != null && e.vt_malicious > 0) details.push('VT ' + e.vt_malicious);
          if (e.abuse_confidence != null && e.abuse_confidence > 0) details.push('Abuse ' + e.abuse_confidence + '%');
          if (e.blacklist_info && typeof e.blacklist_info === 'object' && e.blacklist_info.source) details.push(self._esc(e.blacklist_info.source));
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(e.ip) + '</span></td>' +
            '<td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(label) + '</td>' +
            '<td>' + (countryFlag
              ? '<span title="' + self._esc(country) + '" style="font-size:15px;line-height:1">' + countryFlag + '</span>'
              : '<span class="dim">' + self._esc(country || '—') + '</span>') + '</td>' +
            '<td style="text-align:right">' + (e.flows || 0).toLocaleString() + '</td>' +
            '<td><span class="badge ' + bc + '">' + self._esc(e.rating) + '</span></td>' +
            '<td style="font-size:10px;color:var(--muted)">' + details.join(', ') + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="external">' + this._t('stats.view_all_external_ips', 'View all external IPs →') + '</button>';
    }

    // ── DNS activity ──────────────────────────────────────────────────
    var dnsLog = (this._data && this._data.dns_log) || [];
    var dnsStats = (this._data && this._data.dns_proxy_stats) || {};

    // Hourly stacked bar chart — built from timeseries points so data persists
    // beyond the raw-log retention window.
    var dnsChartHtml = (function() {
          var D_HOURS = 24, D_BAR_W = 18, D_BAR_GAP = 3, D_CHART = 60, D_LABEL = 16;
          var nowMs = Date.now();
          var dnsBuckets = new Array(D_HOURS).fill(null).map(function() {
            return { total: 0, blocked: 0, mal: 0 };
          });
          // Aggregate timeseries points into hourly buckets (sum dns counts per hour).
          var hasTsData = false;
          for (var ti = 0; ti < allPoints.length; ti++) {
            var tpt = allPoints[ti];
            if (tpt.dns_total == null) continue;
            var tts = new Date(tpt.ts).getTime();
            var tago = Math.floor((nowMs - tts) / 3600000);
            if (tago < 0 || tago >= D_HOURS) continue;
            var tbi = D_HOURS - 1 - tago;
            dnsBuckets[tbi].total   += (tpt.dns_total    || 0);
            dnsBuckets[tbi].blocked += (tpt.dns_blocked  || 0);
            dnsBuckets[tbi].mal     += (tpt.dns_malicious|| 0);
            hasTsData = true;
          }
          // Fall back to raw dns_log entries when no timeseries dns data exists yet
          // (e.g. first start before any interval has elapsed).
          if (!hasTsData) {
            for (var di = 0; di < dnsLog.length; di++) {
              var row = dnsLog[di] || {};
              var rawTs = row.timestamp;
              var et = (rawTs == null) ? NaN
                : (typeof rawTs === 'number') ? (rawTs < 1e12 ? rawTs * 1000 : rawTs)
                : (function() {
                    var txt = String(rawTs).trim();
                    var n = Number(txt);
                    if (!isNaN(n)) return n < 1e12 ? n * 1000 : n;
                    var m = new Date(txt).getTime();
                    return isNaN(m) ? new Date(txt.replace(' ', 'T')).getTime() : m;
                  })();
              if (isNaN(et)) continue;
              var ago = Math.floor((nowMs - et) / 3600000);
              if (ago < 0 || ago >= D_HOURS) continue;
              var bi = D_HOURS - 1 - ago;
              dnsBuckets[bi].total++;
              if (row.malicious) dnsBuckets[bi].mal++;
              if (row.status === 'blocked') dnsBuckets[bi].blocked++;
            }
          }
          var hasAny = dnsBuckets.some(function(b) { return b.total > 0; });
          if (!hasAny) return '<div class="empty-state"><p style="margin:12px 0">' + self._t('stats.no_dns_queries', 'No DNS queries recorded') + '</p></div>';
          var maxDns = 1;
          for (var mi = 0; mi < dnsBuckets.length; mi++) {
            if (dnsBuckets[mi].total > maxDns) maxDns = dnsBuckets[mi].total;
          }
          var dSvgW = D_HOURS * (D_BAR_W + D_BAR_GAP);
          var dBars = dnsBuckets.map(function(b, i) {
            var x = i * (D_BAR_W + D_BAR_GAP);
            var th  = Math.max(2, Math.round((b.total   / maxDns) * D_CHART));
            var bkh = b.blocked > 0 ? Math.max(2, Math.round((b.blocked / maxDns) * D_CHART)) : 0;
            var mh  = b.mal     > 0 ? Math.max(2, Math.round((b.mal     / maxDns) * D_CHART)) : 0;
            var lhour = new Date(nowMs - (D_HOURS - 1 - i) * 3600000).getHours();
            var tip = lhour + 'h \u2014 ' + b.total + ' total' +
              (b.blocked > 0 ? ', ' + b.blocked + ' blocked' : '') +
              (b.mal     > 0 ? ', ' + b.mal     + ' malicious' : '');
            return '<rect x="' + x + '" y="' + (D_CHART - th)  + '" width="' + D_BAR_W + '" height="' + th  + '" fill="rgba(98,232,255,.35)"  rx="2"><title>' + tip + '</title></rect>' +
              (bkh > 0 ? '<rect x="' + x + '" y="' + (D_CHART - bkh) + '" width="' + D_BAR_W + '" height="' + bkh + '" fill="rgba(191,111,255,.7)"  rx="2"><title>' + tip + '</title></rect>' : '') +
              (mh  > 0 ? '<rect x="' + x + '" y="' + (D_CHART - mh)  + '" width="' + D_BAR_W + '" height="' + mh  + '" fill="rgba(255,77,109,.7)"   rx="2"><title>' + tip + '</title></rect>' : '');
          }).join('');
          var dLabels = '';
          for (var dl = 0; dl < D_HOURS; dl += 4) {
            var dlx   = dl * (D_BAR_W + D_BAR_GAP) + D_BAR_W / 2;
            var dlHour = new Date(nowMs - (D_HOURS - 1 - dl) * 3600000).getHours();
            dLabels += '<text x="' + dlx + '" y="' + (D_CHART + D_LABEL - 3) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + dlHour + 'h</text>';
          }
          return '<svg viewBox="0 0 ' + dSvgW + ' ' + (D_CHART + D_LABEL) + '" width="100%" height="' + (D_CHART + D_LABEL) + '" preserveAspectRatio="none" style="display:block">' + dBars + dLabels + '</svg>' +
            '<div style="display:flex;gap:12px;margin-top:4px;font-size:10px">' +
              '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(98,232,255,.35);display:inline-block;border-radius:2px"></span>' + self._t('stats.total', 'Total') + '</span>' +
              '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(191,111,255,.7);display:inline-block;border-radius:2px"></span>' + self._t('stats.blocked', 'Blocked') + '</span>' +
              '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(255,77,109,.7);display:inline-block;border-radius:2px"></span>' + self._t('stats.malicious', 'Malicious') + '</span>' +
            '</div>';
        })();

    // Top N malicious/blocked domains (uses configured statistics topN)
    var topMalDomains = [];
    (function() {
      var counts = {};
      for (var i = 0; i < dnsLog.length; i++) {
        var e = dnsLog[i];
        if ((e.malicious || e.status === 'blocked') && e.domain) {
          counts[e.domain] = (counts[e.domain] || 0) + 1;
        }
      }
      topMalDomains = Object.keys(counts).map(function(d) {
        var cat = 'other';
        for (var i = 0; i < dnsLog.length; i++) {
          if (dnsLog[i].domain === d) { cat = dnsLog[i].category || 'other'; break; }
        }
        return { domain: d, count: counts[d], category: cat };
      });
      topMalDomains.sort(function(a, b) { return b.count - a.count; });
      topMalDomains = topMalDomains.slice(0, topN);
    })();

    var dnsTopMalHtml;
    if (!topMalDomains.length) {
      dnsTopMalHtml = '<div class="empty-state"><div class="empty-icon" style="font-size:22px">\u2705</div><p style="margin:8px 0">' + this._t('stats.no_dns_detected', 'No malicious or blocked DNS queries detected') + '</p></div>';
    } else {
      var DNS_CAT_COLORS_STAT = {
        malware:'rgba(255,77,109,1)', adult:'rgba(191,111,255,1)', gambling:'rgba(255,179,71,1)',
        ads:'rgba(255,209,102,1)', tracking:'rgba(107,140,186,1)', social:'rgba(91,170,236,1)',
        gaming:'rgba(107,255,200,1)', streaming:'rgba(58,197,201,1)', news:'rgba(245,158,11,1)',
        cdn:'rgba(72,199,142,1)', cloud:'rgba(59,178,255,1)', iot:'rgba(255,159,67,1)', tech:'rgba(155,135,245,1)',
        intel:'rgba(248,84,84,1)', override:'rgba(98,232,255,1)', other:'rgba(90,106,128,1)'
      };
      dnsTopMalHtml = '<table class="data-table" style="width:100%;margin-top:8px;table-layout:fixed"><thead><tr>' +
        '<th style="width:26px">#</th><th>Domain</th><th style="width:88px">Category</th><th style="width:64px;text-align:right">Queries</th>' +
        '</tr></thead><tbody>' +
        topMalDomains.map(function(d, i) {
          var cc = DNS_CAT_COLORS_STAT[d.category] || DNS_CAT_COLORS_STAT['other'];
          var catPill = '<span style="font-size:10px;padding:1px 6px;border-radius:8px;background:' +
            cc.replace(',1)', ',.15)') + ';color:' + cc + ';border:1px solid ' + cc.replace(',1)', ',.35)') + '">' +
            (d.category || 'other') + '</span>';
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(d.domain) + '</td>' +
            '<td>' + catPill + '</td>' +
            '<td style="text-align:right"><span class="badge badge-malicious">' + d.count + '</span></td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="dns">' + this._t('stats.view_dns_log', 'View DNS log →') + '</button>';
    }

    // ── DNS blocked-by-category pie chart ────────────────────────────
    var _STAT_CAT_COLORS = {
      malware:'rgba(255,77,109,1)', adult:'rgba(191,111,255,1)', gambling:'rgba(255,179,71,1)',
      ads:'rgba(255,209,102,1)', tracking:'rgba(107,140,186,1)', social:'rgba(91,170,236,1)',
      gaming:'rgba(107,255,200,1)', streaming:'rgba(58,197,201,1)', news:'rgba(245,158,11,1)',
      cdn:'rgba(72,199,142,1)', cloud:'rgba(59,178,255,1)', iot:'rgba(255,159,67,1)', tech:'rgba(155,135,245,1)',
      intel:'rgba(248,84,84,1)', override:'rgba(98,232,255,1)', other:'rgba(90,106,128,1)'
    };
    var _STAT_CAT_LABELS = {
      malware:'Malware', adult:'Adult', gambling:'Gambling', ads:'Ads',
      tracking:'Tracking', social:'Social', gaming:'Gaming', streaming:'Streaming', news:'News',
      cdn:'CDN', cloud:'Cloud', iot:'IoT', tech:'Tech', intel:'Threat Intel', override:'Override', other:'Other'
    };
    var _dnsCatCounts = {};
    for (var _dci = 0; _dci < dnsLog.length; _dci++) {
      var _dce = dnsLog[_dci];
      if (_dce.malicious || _dce.status === 'blocked') {
        var _dcc = (_dce.category || 'other').toLowerCase();
        _dnsCatCounts[_dcc] = (_dnsCatCounts[_dcc] || 0) + 1;
      }
    }
    var _dnsCatItems = Object.keys(_dnsCatCounts)
      .map(function(c) { return { cat: c, count: _dnsCatCounts[c] }; })
      .sort(function(a, b) { return b.count - a.count; });
    var _dnsCatTotal = _dnsCatItems.reduce(function(s, x) { return s + x.count; }, 0);
    var dnsCatSection;
    if (!_dnsCatTotal) {
      dnsCatSection = '<div class="empty-state"><div class="empty-icon" style="font-size:22px">\u2705</div><p style="margin:8px 0">' + this._t('stats.no_blocked_yet', 'No blocked or malicious DNS queries yet') + '</p></div>';
    } else if (modes.dns_categories === 'pie') {
      var _dnsCatPieColors = _dnsCatItems.map(function(x) { return _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other']; });
      var _dnsCatPieSvg = self._pieSvg(_dnsCatItems, function(x) { return x.count; }, function(x) { return (_STAT_CAT_LABELS[x.cat] || x.cat) + ': ' + x.count; }, _dnsCatPieColors);
      var _dnsCatLegend = '<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">' +
        _dnsCatItems.map(function(x) {
          var col = _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other'];
          var pct = Math.round((x.count / _dnsCatTotal) * 100);
          return '<div style="display:flex;align-items:center;gap:6px">' +
            '<span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + col + '"></span>' +
            '<span style="flex:1;color:var(--fg)">' + (_STAT_CAT_LABELS[x.cat] || x.cat) + '</span>' +
            '<span style="color:var(--muted);font-variant-numeric:tabular-nums">' + x.count + ' (' + pct + '%)</span>' +
          '</div>';
        }).join('') +
      '</div>';
      dnsCatSection = '<div class="stats-chart-row">' + _dnsCatPieSvg + '<div class="stats-chart-legend">' + _dnsCatLegend + '</div></div>';
    } else {
      var _dnsCatMax = _dnsCatItems[0] ? _dnsCatItems[0].count : 1;
      dnsCatSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>Category</th><th style="text-align:right">Queries</th><th>Share</th>' +
        '</tr></thead><tbody>' +
        _dnsCatItems.map(function(x, i) {
          var col = _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other'];
          var pct = _dnsCatMax > 0 ? Math.round((x.count / _dnsCatMax) * 100) : 0;
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span style="font-size:10px;padding:1px 6px;border-radius:8px;background:' + col.replace(',1)', ',.15)') + ';color:' + col + ';border:1px solid ' + col.replace(',1)', ',.35)') + '">' + (_STAT_CAT_LABELS[x.cat] || x.cat) + '</span></td>' +
            '<td style="text-align:right">' + x.count + '</td>' +
            '<td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + pct + '%;background:' + col + ';border-radius:3px;height:8px"></div></div></td>' +
          '</tr>';
        }).join('') +
        '</tbody></table>';
    }

    // ── Top blocked/malicious DNS queries by client (pie) ───────────
    var _dnsClientCounts = {};
    for (var _dsi = 0; _dsi < dnsLog.length; _dsi++) {
      var _dse = dnsLog[_dsi];
      if (_dse.malicious || _dse.status === 'blocked') {
        var _src = String(_dse.src_ip || '').trim();
        if (!_src) continue;
        _dnsClientCounts[_src] = (_dnsClientCounts[_src] || 0) + 1;
      }
    }
    var _dnsClientItems = Object.keys(_dnsClientCounts)
      .map(function(ip) { return { ip: ip, count: _dnsClientCounts[ip] }; })
      .sort(function(a, b) { return b.count - a.count; })
      .slice(0, topN);
    var _dnsClientTotal = _dnsClientItems.reduce(function(s, x) { return s + x.count; }, 0);
    var dnsClientSection;
    if (!_dnsClientTotal) {
      dnsClientSection = '<div class="empty-state"><div class="empty-icon" style="font-size:22px">\u2705</div><p style="margin:8px 0">' + this._t('stats.no_blocked_clients', 'No blocked or malicious client queries yet') + '</p></div>';
    } else if (modes.dns_clients === 'pie') {
      var _dnsClientColors = ['#ff4d6d','#ff8c42','#ffc107','#f472b6','#fb923c','#ff6b6b','#e879f9','#facc15','#fd8dac','#ffb347','#6bffc8','#5baaec'];
      var _dnsClientPieSvg = self._pieSvg(
        _dnsClientItems,
        function(x) { return x.count; },
        function(x) { return x.ip + ': ' + x.count + ' blocked/malicious queries'; },
        _dnsClientColors
      );
      var _dnsClientLegend = '<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">' +
        _dnsClientItems.map(function(x, i) {
          var col = _dnsClientColors[i % _dnsClientColors.length];
          var pct = Math.round((x.count / _dnsClientTotal) * 100);
          return '<div style="display:flex;align-items:center;gap:6px">' +
            '<span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + col + '"></span>' +
            '<span class="ip" style="flex:1;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(x.ip) + '</span>' +
            '<span style="color:var(--muted);font-variant-numeric:tabular-nums">' + x.count + ' (' + pct + '%)</span>' +
          '</div>';
        }).join('') +
      '</div>';
      dnsClientSection = '<div class="stats-chart-row">' + _dnsClientPieSvg + '<div class="stats-chart-legend">' + _dnsClientLegend + '</div></div>';
    } else {
      var _dnsClientMax = _dnsClientItems[0] ? _dnsClientItems[0].count : 1;
      dnsClientSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>Client IP</th><th style="text-align:right">Blocked/Malicious</th><th>Share</th>' +
        '</tr></thead><tbody>' +
        _dnsClientItems.map(function(x, i) {
          var pct = _dnsClientMax > 0 ? Math.round((x.count / _dnsClientMax) * 100) : 0;
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(x.ip) + '</span></td>' +
            '<td style="text-align:right">' + x.count + '</td>' +
            '<td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + pct + '%;background:#ff4d6d;border-radius:3px;height:8px"></div></div></td>' +
          '</tr>';
        }).join('') +
        '</tbody></table>';
    }

    // ── Baseline deviance timeline bar chart (last 24 h) ─────────────
    var blInfo = (self._data && self._data.baseline) || {};
    var devianceChartHtml = (function() {
      if ((blInfo.mode || 'disabled') !== 'active') {
        return '';
      }
      var DV_H = 24, DV_BAR_W = 18, DV_GAP = 3, DV_CHART = 60, DV_LABEL = 16;
      var dvNow = Date.now();
      var dvBkts = new Array(DV_H).fill(null);
      for (var dvi = 0; dvi < allPoints.length; dvi++) {
        var dvpt = allPoints[dvi];
        if (dvpt.deviance_score == null) continue;
        var dago = Math.floor((dvNow - new Date(dvpt.ts).getTime()) / 3600000);
        if (dago < 0 || dago >= DV_H) continue;
        var dbi = DV_H - 1 - dago;
        if (dvBkts[dbi] === null || dvpt.deviance_score > dvBkts[dbi]) dvBkts[dbi] = dvpt.deviance_score;
      }
      if (!dvBkts.some(function(v) { return v !== null; })) {
        return '<div style="text-align:center;padding:14px;color:var(--muted);font-size:11px">' + self._t('stats.no_deviance', 'No deviance data yet — data accumulates every 5 min') + '</div>';
      }
      var dvSvgW = DV_H * (DV_BAR_W + DV_GAP);
      var dvGuides = [25, 50, 75].map(function(g) {
        var gy = DV_CHART - Math.round((g / 100) * DV_CHART);
        return '<line x1="0" y1="' + gy + '" x2="' + dvSvgW + '" y2="' + gy + '" stroke="rgba(255,255,255,.07)" stroke-width="1"/>';
      }).join('');
      var dvBars = dvBkts.map(function(v, i) {
        var x = i * (DV_BAR_W + DV_GAP);
        if (v === null) return '<rect x="' + x + '" y="' + (DV_CHART - 2) + '" width="' + DV_BAR_W + '" height="2" fill="rgba(255,255,255,.06)" rx="1"><title>No data</title></rect>';
        var clr = v <= 20 ? '#6bffc8' : v <= 50 ? '#ffc107' : v <= 75 ? '#ff8c42' : '#ff4d6d';
        var bh = Math.max(2, Math.round((v / 100) * DV_CHART));
        var tip = new Date(dvNow - (DV_H - 1 - i) * 3600000).getHours() + 'h \u2014 deviance\u00a0' + v + '%';
        return '<rect x="' + x + '" y="' + (DV_CHART - bh) + '" width="' + DV_BAR_W + '" height="' + bh + '" fill="' + clr + '" opacity="0.85" rx="2"><title>' + tip + '</title></rect>';
      }).join('');
      var dvLabels = '';
      for (var dl = 0; dl < DV_H; dl += 4) {
        var dlx = dl * (DV_BAR_W + DV_GAP) + DV_BAR_W / 2;
        dvLabels += '<text x="' + dlx + '" y="' + (DV_CHART + DV_LABEL - 3) + '" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">' + new Date(dvNow - (DV_H - 1 - dl) * 3600000).getHours() + 'h</text>';
      }
      return '<svg viewBox="0 0 ' + dvSvgW + ' ' + (DV_CHART + DV_LABEL) + '" width="100%" height="' + (DV_CHART + DV_LABEL) + '" preserveAspectRatio="none" style="display:block">' + dvGuides + dvBars + dvLabels + '</svg>' +
        '<div style="display:flex;gap:12px;margin-top:4px;font-size:10px;flex-wrap:wrap">' +
          '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#6bffc8;display:inline-block;border-radius:2px"></span>' + self._t('stats.normal', '≤20% Normal') + '</span>' +
          '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ffc107;display:inline-block;border-radius:2px"></span>' + self._t('stats.review', '≤50% Review') + '</span>' +
          '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ff8c42;display:inline-block;border-radius:2px"></span>' + self._t('stats.investigate', '≤75% Investigate') + '</span>' +
          '<span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ff4d6d;display:inline-block;border-radius:2px"></span>' + self._t('stats.critical', '>75% Critical') + '</span>' +
        '</div>';
    })();

    // ── Top N hosts with most findings (security + baseline) ─────────
    var _allFindings = ((this._data && this._data.findings) || []).concat((this._data && this._data.baseline_anomalies) || []);
    var _hostFindCounts = {};
    for (var _hfi = 0; _hfi < _allFindings.length; _hfi++) {
      var _hfip = String(_allFindings[_hfi].source_ip || '').trim();
      if (_hfip) _hostFindCounts[_hfip] = (_hostFindCounts[_hfip] || 0) + 1;
    }
    var _hostFindItems = Object.keys(_hostFindCounts)
      .map(function(ip) { return { ip: ip, count: _hostFindCounts[ip] }; })
      .sort(function(a, b) { return b.count - a.count; })
      .slice(0, topN);
    var _hostFindTotal = _hostFindItems.reduce(function(s, x) { return s + x.count; }, 0);
    var _devicesMap = {};
    ((this._data && this._data.devices) || []).forEach(function(d) { if (d.ip) _devicesMap[d.ip] = d; });
    var _hfColors = ['#ff8c42','#ffc107','#ff4d6d','#8f86ff','#3ac5c9','#6bffc8','#f472b6','#fb923c','#a78bfa','#22d3ee'];
    var hostFindingsSection;
    if (!_hostFindTotal) {
      hostFindingsSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_findings', 'No findings recorded yet') + '</p></div>';
    } else if (modes.host_findings === 'pie') {
      var _hfPieSvg = self._pieSvg(_hostFindItems, function(x) { return x.count; }, function(x) {
        var d = _devicesMap[x.ip]; return ((d && (d.name || d.hostname)) || x.ip) + ': ' + x.count;
      }, _hfColors);
      var _hfLegend = '<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">' +
        _hostFindItems.map(function(x, i) {
          var col = _hfColors[i % _hfColors.length];
          var d = _devicesMap[x.ip];
          var label = (d && (d.name || d.hostname)) ? (d.name || d.hostname) + ' (' + x.ip + ')' : x.ip;
          return '<div style="display:flex;align-items:center;gap:6px">' +
            '<span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + col + '"></span>' +
            '<span class="ip" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(label) + '</span>' +
            '<span style="color:var(--muted)">' + x.count + '\u00a0(' + Math.round((x.count / _hostFindTotal) * 100) + '%)</span>' +
          '</div>';
        }).join('') + '</div>';
      hostFindingsSection = '<div class="stats-chart-row">' + _hfPieSvg + '<div class="stats-chart-legend">' + _hfLegend + '</div></div>';
    } else {
      hostFindingsSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Name / Hostname</th><th style="text-align:right">Deviations</th>' +
        '</tr></thead><tbody>' +
        _hostFindItems.map(function(x, i) {
          var d = _devicesMap[x.ip];
          var name = (d && (d.name || d.hostname)) || '';
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(x.ip) + '</span></td>' +
            '<td>' + self._esc(name) + '</td>' +
            '<td style="text-align:right">' + x.count + '</td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    // ── Top N external IPs appearing in new-peer baseline deviations ──
    var _blAnoms = (this._data && this._data.baseline_anomalies) || [];
    var _extDevCounts = {};
    for (var _edi = 0; _edi < _blAnoms.length; _edi++) {
      var _editem = _blAnoms[_edi];
      if (_editem.category === 'anomaly_new_peer' && _editem.details && _editem.details.peer) {
        var _peer = String(_editem.details.peer).trim();
        if (_peer) _extDevCounts[_peer] = (_extDevCounts[_peer] || 0) + 1;
      }
    }
    var _extDevItems = Object.keys(_extDevCounts)
      .map(function(ip) { return { ip: ip, count: _extDevCounts[ip] }; })
      .sort(function(a, b) { return b.count - a.count; })
      .slice(0, topN);
    var _extDevTotal = _extDevItems.reduce(function(s, x) { return s + x.count; }, 0);
    var _extIpEnrich = {};
    ((this._data && this._data.external_ips) || []).forEach(function(e) { if (e.ip) _extIpEnrich[e.ip] = e; });
    var _edColors = ['#ff4d6d','#ff8c42','#ffc107','#f472b6','#fb923c','#ff6b6b','#e879f9','#facc15','#fd8dac','#ffb347'];
    var extIpDeviationSection;
    if (!_extDevTotal) {
      extIpDeviationSection = '<div class="empty-state"><p style="margin:12px 0">' + this._t('stats.no_ext_peers', 'No new external peers in baseline deviations') + '</p></div>';
    } else if (modes.ext_deviations === 'pie') {
      var _edPieSvg = self._pieSvg(_extDevItems, function(x) { return x.count; }, function(x) {
        var enr = _extIpEnrich[x.ip];
        return x.ip + (enr && enr.org ? ' \u2014 ' + enr.org : '') + (enr && enr.country ? ' [' + enr.country + ']' : '') + ': ' + x.count;
      }, _edColors);
      var _edLegend = '<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">' +
        _extDevItems.map(function(x, i) {
          var col = _edColors[i % _edColors.length];
          var enr = _extIpEnrich[x.ip];
          var label = x.ip + (enr && enr.org ? ' \u2014 ' + enr.org : '') + (enr && enr.country ? ' [' + enr.country + ']' : '');
          return '<div style="display:flex;align-items:center;gap:6px">' +
            '<span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + col + '"></span>' +
            '<span class="ip" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + self._esc(x.ip) + '">' + self._esc(label) + '</span>' +
            '<span style="color:var(--muted)">' + x.count + '\u00a0(' + Math.round((x.count / _extDevTotal) * 100) + '%)</span>' +
          '</div>';
        }).join('') + '</div>';
      extIpDeviationSection = '<div class="stats-chart-row">' + _edPieSvg + '<div class="stats-chart-legend">' + _edLegend + '</div></div>';
    } else {
      extIpDeviationSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Org / Hostname</th><th>Country</th><th style="text-align:right">Deviations</th>' +
        '</tr></thead><tbody>' +
        _extDevItems.map(function(x, i) {
          var enr = _extIpEnrich[x.ip];
          var org = (enr && (enr.org || enr.hostname)) || '';
          var country = (enr && (enr.country_name || enr.country)) || '';
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(x.ip) + '</span></td>' +
            '<td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(org) + '</td>' +
            '<td>' + self._esc(country) + '</td>' +
            '<td style="text-align:right">' + x.count + '</td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    return '<div>' +
      '<div class="page-header"><h1 class="page-title">' + this._t('page.statistics', 'Statistics') + ' <span class="dim" style="font-size:12px;font-weight:400;text-transform:none">\u2014 top\u00a0' + topN + '</span></h1></div>' +
      timelineHtml +
      (devianceChartHtml ? '<div style="margin-top:16px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">' + this._t('stats.baseline_deviance_hourly', 'Baseline Deviance per hour (last 24 h)') + '</div>' + devianceChartHtml + '</div>' : '') +
      (dnsProxyEnabled ? '<div style="margin-top:16px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">' + this._t('stats.dns_queries_hourly', 'DNS Queries per hour (last 24 h)') + '</div>' + dnsChartHtml + '</div>' : '') + '</div>' +
      '<div class="two-col stats-two-col" style="margin-top:12px">' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + this._t('stats.top_public_ips', 'Top {n} Public IPs').replace('{n}', topN) + toggleBtns('public_ips', modes.public_ips) + '</div>' +
          ipsSection +
        '</div>' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + this._t('stats.top_countries', 'Top {n} Countries').replace('{n}', topN) + toggleBtns('countries', modes.countries) + '</div>' +
          countriesSection +
        '</div>' +
      '</div>' +
      '<div class="two-col stats-two-col" style="margin-top:12px">' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + this._t('stats.top_internal_talkers', 'Top {n} Internal Talkers').replace('{n}', topN) + toggleBtns('talkers', modes.talkers) + '</div>' +
          talkersSection +
        '</div>' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">' +
          (topThr.length ? '<span style="display:flex;align-items:center;gap:6px">' + this._t('stats.top_threat_ips', 'Top {n} Threat IPs').replace('{n}', topN) + ' <span class="badge badge-critical" style="font-size:9px">' + topThr.length + '</span></span>' : this._t('stats.top_threat_ips', 'Top {n} Threat IPs').replace('{n}', topN)) +
          toggleBtns('threat_ips', modes.threat_ips) + '</div>' +
          threatSection +
        '</div>' +
      '</div>' +
      (dnsProxyEnabled ? ('<div class="two-col stats-two-col" style="margin-top:12px">' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + this._t('stats.blocked_dns_by_category', 'Blocked DNS Queries by Category') + toggleBtns('dns_categories', modes.dns_categories) + '</div>' +
          dnsCatSection +
        '</div>' +
        '<div class="card stats-panel-card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + this._t('stats.top_blocked_by_client', 'Top {n} Blocked Queries by Client').replace('{n}', topN) + toggleBtns('dns_clients', modes.dns_clients) + '</div>' +
          dnsClientSection +
        '</div>' +
      '</div>') : '') +
      '<div class="two-col stats-two-col" style="margin-top:12px">' +
        ((function() {
          var blMode = (self._data && self._data.baseline && self._data.baseline.mode) || 'disabled';
          if (blMode !== 'active') return '';
          return '<div class="card stats-panel-card">' +
              '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + self._t('stats.top_hosts_deviations', 'Top {n} Hosts in Deviations').replace('{n}', topN) + toggleBtns('host_findings', modes.host_findings) + '</div>' +
              hostFindingsSection +
            '</div>' +
            '<div class="card stats-panel-card">' +
              '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' + self._t('stats.top_ext_deviations', 'Top {n} External IPs in Deviations').replace('{n}', topN) + toggleBtns('ext_deviations', modes.ext_deviations) + '</div>' +
              extIpDeviationSection +
            '</div>';
        })()) +
      '</div>' +
      (suricataEnabledStats ? (function() {
        function _sucPie(data, colors, key, title, noDataMsg) {
          var mode = modes[key] || 'pie';
          var total = data.reduce(function(s,d){return s+d.value;},0);
          var SIZE = 130; var CX = SIZE/2; var CY = SIZE/2; var R = 52; var IR = 28;
          var pieSvg = '';
          if (total > 0) {
            var startAngle = -Math.PI/2;
            for (var i = 0; i < data.length; i++) {
              var frac = data[i].value/total;
              var end = startAngle + frac*2*Math.PI;
              var x1=CX+R*Math.cos(startAngle),y1=CY+R*Math.sin(startAngle);
              var x2=CX+R*Math.cos(end),y2=CY+R*Math.sin(end);
              var ix1=CX+IR*Math.cos(startAngle),iy1=CY+IR*Math.sin(startAngle);
              var ix2=CX+IR*Math.cos(end),iy2=CY+IR*Math.sin(end);
              var lg=frac>0.5?1:0;
              var d='M '+ix1+' '+iy1+' L '+x1+' '+y1+' A '+R+' '+R+' 0 '+lg+' 1 '+x2+' '+y2+' L '+ix2+' '+iy2+' A '+IR+' '+IR+' 0 '+lg+' 0 '+ix1+' '+iy1;
              pieSvg += '<path d="'+d+'" fill="'+colors[i%colors.length]+'" opacity="0.92"/>';
              startAngle = end;
            }
          }
          var legend = data.slice(0,8).map(function(item,i){
            return '<div class="row-gap" style="font-size:10px;gap:5px;margin-bottom:3px">' +
              '<span style="width:9px;height:9px;border-radius:2px;background:'+colors[i%colors.length]+';flex-shrink:0;display:inline-block"></span>' +
              '<span style="color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+self._esc(item.label)+'</span>' +
              '<span style="color:var(--text);font-weight:600;font-variant-numeric:tabular-nums">'+item.value+'</span>' +
            '</div>';
          }).join('');
          var tableHtml = total === 0 ? '<div style="color:var(--muted);font-size:12px;padding:12px 0">'+(noDataMsg||'No data')+'</div>' :
            '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>Label</th><th style="text-align:right">Count</th></tr></thead><tbody>' +
            data.map(function(item,i){return '<tr><td style="color:var(--muted)">'+(i+1)+'</td><td><span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:'+colors[i%colors.length]+';margin-right:5px;vertical-align:middle"></span>'+self._esc(item.label)+'</td><td style="text-align:right">'+item.value+'</td></tr>';}).join('') +
            '</tbody></table>';
          var toggleHtml = '<div style="display:flex;gap:4px">' +
            '<button class="btn'+(mode==='pie'?' active':'')+'" style="padding:2px 8px;font-size:10px" data-statstoggle="'+key+':pie">' + self._t('stats.pie', 'Pie') + '</button>' +
            '<button class="btn'+(mode==='bar'?' active':'')+'" style="padding:2px 8px;font-size:10px" data-statstoggle="'+key+':bar">' + self._t('stats.list', 'List') + '</button>' +
          '</div>';
          var content = (mode === 'pie' && total > 0)
            ? '<div class="stats-chart-row"><svg width="'+SIZE+'" height="'+SIZE+'" viewBox="0 0 '+SIZE+' '+SIZE+'" style="flex-shrink:0">'+pieSvg+'</svg><div class="stats-chart-legend" style="min-width:0;flex:1">'+legend+'</div></div>'
            : tableHtml;
          return '<div class="card stats-panel-card">' +
            '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">'+title+toggleHtml+'</div>' +
            (total === 0 ? '<div style="color:var(--muted);font-size:12px;padding:8px 0">'+(noDataMsg||self._t('stats.no_data', 'No data'))+'</div>' : content) +
          '</div>';
        }
        return '<div class="two-col stats-two-col" style="margin-top:12px">' +
          _sucPie(sucSevData, SUC_SEV_COLORS, 'suricata_severity', self._t('stats.suricata_by_severity', 'Suricata Alerts — By Severity'), self._t('stats.no_alerts', 'No alerts yet')) +
          _sucPie(sucCatData, sucCatColors.length ? sucCatColors : SUC_CAT_PALETTE, 'suricata_category', self._t('stats.suricata_by_category', 'Suricata Alerts — By Category'), self._t('stats.no_alerts', 'No alerts yet')) +
        '</div>' +
        '<div class="two-col stats-two-col" style="margin-top:12px">' +
          _sucPie(sucSrcData, SUC_SRC_PALETTE, 'suricata_src', self._t('stats.suricata_top_source', 'Suricata Alerts — Top {n} Source IPs').replace('{n}', topN), self._t('stats.no_alerts', 'No alerts yet')) +
        '</div>';
      })() : '') +
      (dnsProxyEnabled ? '<div class="card" style="margin-top:12px">' +
        '<div class="card-title" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        (topMalDomains.length ? '<span style="display:flex;align-items:center;gap:6px">' + this._t('stats.top_blocked_domains', 'Top {n} Blocked / Malicious Domains').replace('{n}', topN) + ' <span class="badge badge-critical" style="font-size:9px">' + topMalDomains.length + '</span></span>' : this._t('stats.top_blocked_domains', 'Top {n} Blocked / Malicious Domains').replace('{n}', topN)) +
        '</div>' +
        dnsTopMalHtml +
      '</div>' : '') +
      '<div class="card" style="margin-top:12px">' +
        '<div class="card-title">' + this._t('stats.enrichment_budget', 'Enrichment Budget (Today)') + '</div>' +
        enrichSection +
      '</div>' +
    '</div>';
  }

  _viewMap(container) {
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    if (!netflowEnabled) {
      container.innerHTML = '<div class="state-box"><div class="state-icon">\u23f8</div><p>' + this._t('map.disabled', 'NetFlow listener is disabled.') + ' ' + this._t('map.enable_in', 'Enable it in') + ' <button class="btn" style="display:inline;padding:2px 10px;font-size:11px" data-view="settings">' + this._t('view.settings', 'Settings') + '</button> ' + this._t('map.to_use', 'to use the Network Map.') + '</p></div>';
      return;
    }
    var baselineEnabledRaw = this._data && this._data.baseline_enabled;
    var baselineEnabled = baselineEnabledRaw === true || baselineEnabledRaw === 'true' || baselineEnabledRaw === 1 || baselineEnabledRaw === '1';
    var allDevices = this._mapAllDevices();
    var connections = (this._data && this._data.connections) || [];
    var baselineGraph = (this._data && this._data.baseline_graph) || null;
    this._mapBaselineGraph = baselineGraph;
    var extIPs     = (this._data && this._data.external_ips) || [];
    var mcIPs      = (this._data && this._data.multicast_ips) || [];
    var flows      = (this._data && this._data.summary && this._data.summary.total_flows) || 0;
    var f = this._mapFilter;
    var m = this._mapMode;
    var hasBaselineGraph = !!(baselineGraph && baselineGraph.edges && baselineGraph.edges.length);
    if (!baselineEnabled) m = 'live';
    if (m !== 'live' && !hasBaselineGraph) m = 'live';
    this._mapMode = m;
    var filters = [
      { id: 'all',      label: this._t('map.filter_all', 'All') },
      { id: 'scanned',  label: this._t('map.filter_scanned', 'Scanned') },
      { id: 'flow',     label: this._t('map.filter_flow_only', 'Flow only') },
      { id: 'external', label: this._t('map.filter_external', 'External'), hide: !netflowEnabled },
    ].filter(function(b) { return !b.hide; });
    var filterBtns = filters.map(function(b) {
      return '<button class="btn map-fbtn' + (f === b.id ? ' active' : '') + '" data-mapfilter="' + b.id + '">' + b.label + '</button>';
    }).join('');
    var mapModes = [
      { id: 'live', label: this._t('map.mode_live', 'Live') },
      { id: 'baseline', label: this._t('map.mode_baseline', 'Baseline'), disabled: !hasBaselineGraph || !baselineEnabled },
      { id: 'compare', label: this._t('map.mode_compare', 'Compare'), disabled: !hasBaselineGraph || !baselineEnabled },
    ];
    var modeBtns = baselineEnabled ? mapModes.map(function(mm) {
      var disabledAttr = mm.disabled ? ' disabled' : '';
      return '<button class="btn map-mbtn' + (m === mm.id ? ' active' : '') + '" data-mapmode="' + mm.id + '"' + disabledAttr + '>' + mm.label + '</button>';
    }).join('') : '';
    var modeLabel = m === 'baseline' ? this._t('map.label_baseline_snapshot', 'Baseline Snapshot') : (m === 'compare' ? this._t('map.label_live_vs_baseline', 'Live vs Baseline') : this._t('map.label_live_network', 'Live Network Map'));
    var baselineInfo = '';
    if (hasBaselineGraph) {
      var edgeCount = (baselineGraph.edges || []).length;
      var hostCount = (baselineGraph.hosts || []).length;
      baselineInfo = '<span class="chip" style="margin-left:6px">' + this._t('map.baseline_chip', 'Baseline') + ' ' + hostCount + ' ' + this._t('map.hosts', 'hosts') + ' \u00B7 ' + edgeCount + ' ' + this._t('map.edges', 'edges') + '</span>';
    }
    // ── Compare summary chips ─────────────────────────────────────────
    var compareSummaryHtml = '';
    if (m === 'compare' && hasBaselineGraph) {
      var _compEdges = this._composeMapEdges(connections, baselineGraph);
      var _cntNew = 0, _cntMissing = 0, _cntBoth = 0;
      var _topDelta = [], _topDeltaLabel = '';
      for (var _ci = 0; _ci < _compEdges.length; _ci++) {
        var _ce = _compEdges[_ci];
        if (_ce.edge_mode === 'new')     _cntNew++;
        else if (_ce.edge_mode === 'missing') _cntMissing++;
        else if (_ce.edge_mode === 'both')    _cntBoth++;
        if (_ce.edge_mode === 'both' && _ce.delta != null) _topDelta.push(_ce);
      }
      _topDelta.sort(function(a, b) { return Math.abs(b.delta) - Math.abs(a.delta); });
      if (_topDelta.length) {
        var _td = _topDelta[0];
        var _sign = _td.delta > 0 ? '+' : '';
        _topDeltaLabel = _td.source + ' \u2192 ' + _td.target + ' (' + _sign + Math.round(_td.delta * 100) / 100 + ' flows/snap)';
      }
      compareSummaryHtml =
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;font-size:11px">' +
          '<span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em">' + this._t('map.compare', 'Compare:') + '</span>' +
          '<span style="background:rgba(50,255,120,.12);border:1px solid rgba(50,255,120,.35);border-radius:100px;padding:2px 10px;color:#32ff78">' +
            '\u2191 ' + _cntNew + ' ' + this._t(_cntNew === 1 ? 'map.new_edge_one' : 'map.new_edge_many', _cntNew === 1 ? 'new edge' : 'new edges') +
          '</span>' +
          '<span style="background:rgba(255,90,50,.12);border:1px solid rgba(255,90,50,.35);border-radius:100px;padding:2px 10px;color:#ff5a32">' +
            '\u2193 ' + _cntMissing + ' ' + this._t(_cntMissing === 1 ? 'map.missing_edge_one' : 'map.missing_edge_many', _cntMissing === 1 ? 'missing edge' : 'missing edges') +
          '</span>' +
          '<span style="background:rgba(98,232,255,.08);border:1px solid rgba(98,232,255,.2);border-radius:100px;padding:2px 10px;color:var(--accent)">' +
            _cntBoth + ' ' + this._t('map.unchanged', 'unchanged') +
          '</span>' +
          (_topDeltaLabel ? '<span style="background:rgba(255,206,84,.08);border:1px solid rgba(255,206,84,.25);border-radius:100px;padding:2px 10px;color:#ffce54;font-size:10px">' + this._t('map.strongest', 'Δ strongest:') + ' ' + _topDeltaLabel + '</span>' : '') +
        '</div>';
    }
    container.innerHTML =
      '<div><div class="view-header"><h1>' + modeLabel + baselineInfo + '</h1>' +
      '<div class="row-gap"><span id="map-stats" style="font-size:11px;color:var(--muted)">' +
      allDevices.length + ' internal \u00B7 ' + extIPs.length + ' external' + (mcIPs.length ? ' \u00B7 ' + mcIPs.length + ' multicast' : '') + ' \u00B7 ' + this._fmtN(flows) + ' flows</span>' +
      '<button class="btn" id="map-reset-btn">' + this._t('map.reset', '↺ Reset') + '</button></div></div>' +
      '<div class="map-filter-bar" style="display:flex;justify-content:space-between;align-items:center">' +
        '<div style="display:flex;gap:4px">' + filterBtns + '</div>' +
        '<div style="display:flex;gap:4px">' + modeBtns + '</div>' +
      '</div>' +
      compareSummaryHtml +
      '<div class="map-wrap"><canvas id="hsa-map-canvas"></canvas>' +
      '<div class="map-tooltip" id="hsa-map-tip" style="display:none"></div>' +
      '<div class="map-legend">' +
        '<div class="legend-item"><div class="ldot" style="background:#8f86ff"></div>' + this._t('map.legend_scanned', 'Scanned') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#3ac5c9"></div>' + this._t('map.legend_flow_only', 'Flow only') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#88a7c7"></div>' + this._t('map.legend_baseline_edge', 'Baseline edge') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#ff5a32"></div>' + this._t('map.legend_missing', 'Missing') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#32ff78"></div>' + this._t('map.legend_new', 'New') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#ff4d6d"></div>' + this._t('map.legend_at_risk', 'At risk') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#6bffc8"></div>' + this._t('map.legend_gateway', 'Gateway') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#5a6a80"></div>' + this._t('map.legend_external', 'External') + '</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#d4a843"></div>' + this._t('map.legend_multicast', 'Multicast') + '</div>' +
      '</div></div></div>';
    var self = this;
    requestAnimationFrame(function() {
      var devices = self._applyMapFilter(allDevices);
      var showExt = (self._mapFilter === 'all' || self._mapFilter === 'external');
      self._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph);
      var btn = self.shadowRoot.getElementById('map-reset-btn');
      if (btn) btn.addEventListener('click', function() { self._stopMap(); self._mapZoom = 1; self._mapPanX = 0; self._mapPanY = 0; var d = self._applyMapFilter(allDevices); self._initMap(d, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph); });
    });
  }

  _mapAllDevices() {
    var _mapCutoff = Date.now() - 10 * 60 * 1000;
    var allDevices = ((this._data && this._data.devices) || []).filter(function(d) { return d.alive || (d.last_seen && new Date(d.last_seen).getTime() > _mapCutoff); });
    var baselineGraph = (this._data && this._data.baseline_graph) || null;
    var baselineHosts = (baselineGraph && baselineGraph.hosts) || [];
    var baselineByIp = {};
    for (var bi = 0; bi < baselineHosts.length; bi++) {
      var bh = baselineHosts[bi] || {};
      if (bh.ip) baselineByIp[bh.ip] = bh;
    }
    for (var di = 0; di < allDevices.length; di++) {
      var d = allDevices[di];
      var b = baselineByIp[d.ip];
      if (b) d.baseline_observation_count = b.observation_count || 0;
    }
    if (this._mapMode !== 'live' && baselineHosts.length) {
      for (var bh = 0; bh < baselineHosts.length; bh++) {
        var h = baselineHosts[bh] || {};
        if (!h.ip) continue;
        var exists = allDevices.some(function(d) { return d.ip === h.ip; });
        if (!exists) {
          allDevices.push({
            ip: h.ip,
            display_name: h.display_name || h.hostname || h.ip,
            hostname: h.hostname || '',
            probable_role: h.probable_role || 'unknown',
            alive: false,
            total_octets: 0,
            baseline_only: true,
            baseline_observation_count: h.observation_count || 0,
          });
        }
      }
    }
    return allDevices;
  }

  _mapEdgeKey(source, target) {
    return source + '|' + target;
  }

  _buildLiveEdgeIndex(connections) {
    var idx = {};
    for (var i = 0; i < connections.length; i++) {
      var c = connections[i] || {};
      var source = c.source;
      var target = c.target;
      if (!source || !target) continue;
      var key = this._mapEdgeKey(source, target);
      var entry = idx[key];
      if (!entry) {
        entry = idx[key] = {
          source: source,
          target: target,
          source_kind: c.source_kind || '',
          target_kind: c.target_kind || '',
          live_octets: 0,
          live_flows: 0,
        };
      }
      entry.live_octets += (c.octets || 0);
      entry.live_flows += (c.flows || 0);
    }
    return idx;
  }

  _buildBaselineEdgeIndex(baselineGraph) {
    var idx = {};
    var edges = (baselineGraph && baselineGraph.edges) || [];
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i] || {};
      var source = e.source;
      var target = e.target;
      if (!source || !target) continue;
      var key = this._mapEdgeKey(source, target);
      idx[key] = {
        source: source,
        target: target,
        source_kind: e.source_kind || '',
        target_kind: e.target_kind || '',
        active_probability: e.active_probability || 0,
        avg_octets: e.avg_octets_per_snapshot || 0,
        avg_flows: e.avg_flows_per_snapshot || 0,
      };
    }
    return idx;
  }

  _composeMapEdges(connections, baselineGraph) {
    var live = this._buildLiveEdgeIndex(connections || []);
    var base = this._buildBaselineEdgeIndex(baselineGraph);
    var keys = {};
    Object.keys(live).forEach(function(k) { keys[k] = true; });
    Object.keys(base).forEach(function(k) { keys[k] = true; });
    var list = [];
    for (var key in keys) {
      var le = live[key];
      var be = base[key];
      if (this._mapMode === 'live' && !le) continue;
      if (this._mapMode === 'baseline' && !be) continue;
      var source = (le && le.source) || (be && be.source);
      var target = (le && le.target) || (be && be.target);
      var sourceKind = (le && le.source_kind) || (be && be.source_kind) || '';
      var targetKind = (le && le.target_kind) || (be && be.target_kind) || '';
      var liveOctets = le ? le.live_octets : 0;
      var baselineOctets = be ? be.avg_octets : 0;
      var weight = this._mapMode === 'baseline' ? Math.max(1, baselineOctets) : Math.max(1, liveOctets || baselineOctets);
      var edgeMode = 'live';
      if (this._mapMode === 'baseline') edgeMode = 'baseline';
      else if (this._mapMode === 'compare') edgeMode = (le && be) ? 'both' : (le ? 'new' : 'missing');
      var liveFlows = le ? le.live_flows : 0;
      var baselineFlows = be ? be.avg_flows : 0;
      var deltaFlows = (le && be) ? (liveFlows - baselineFlows) : 0;
      var deltaRatio = 0;
      if (be && be.avg_octets > 0) deltaRatio = (liveOctets - be.avg_octets) / be.avg_octets;
      list.push({
        source: source,
        target: target,
        source_kind: sourceKind,
        target_kind: targetKind,
        weight: weight,
        edge_mode: edgeMode,
        live_octets: liveOctets,
        baseline_octets: baselineOctets,
        baseline_probability: be ? be.active_probability : 0,
        delta_ratio: deltaRatio,
        delta: deltaFlows,
      });
    }
    return list;
  }

  _applyMapFilter(devices) {
    var f = this._mapFilter;
    if (f === 'scanned') return devices.filter(function(d) { return d.alive; });
    if (f === 'flow')    return devices.filter(function(d) { return (d.total_octets || 0) > 0; });
    if (f === 'external') {
      var connections = (this._data && this._data.connections) || [];
      var baselineGraph = (this._data && this._data.baseline_graph) || {};
      var extPeers = {};
      for (var i = 0; i < connections.length; i++) {
        var c = connections[i];
        if (c.target_kind === 'external') extPeers[c.source] = true;
        if (c.source_kind === 'external') extPeers[c.target] = true;
      }
      if (this._mapMode !== 'live') {
        var bedges = baselineGraph.edges || [];
        for (var j = 0; j < bedges.length; j++) {
          var be = bedges[j];
          if (be.target_kind === 'external') extPeers[be.source] = true;
        }
      }
      return devices.filter(function(d) { return extPeers[d.ip]; });
    }
    return devices;
  }

  _setMapMode(mode) {
    if (mode === this._mapMode) return;
    var baselineGraph = (this._data && this._data.baseline_graph) || null;
    var hasBaseline = !!(baselineGraph && baselineGraph.edges && baselineGraph.edges.length);
    if (mode !== 'live' && !hasBaseline) return;
    this._mapMode = mode;
    if (this._view === 'map') this._render();
  }

  _setMapFilter(f) {
    if (f === this._mapFilter) return;
    this._mapFilter = f;
    // Update button active states
    var btns = this.shadowRoot.querySelectorAll('.map-fbtn');
    btns.forEach(function(b) { b.classList.toggle('active', b.dataset.mapfilter === f); });
    // Rebuild map with new filter
    if (!this._data) return;
    var allDevices = this._mapAllDevices();
    var devices = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
    var extIPs = this._data.external_ips || [];
    this._stopMap();
    var showExt = (f === 'all' || f === 'external');
    var mcIPs = this._data.multicast_ips || [];
    var baselineGraph = this._data.baseline_graph || null;
    this._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph);
  }

  _initMap(devices, connections, extIPs, mcIPs, baselineGraph) {
    var self = this;
    mcIPs = mcIPs || [];
    var canvas = this.shadowRoot.getElementById('hsa-map-canvas');
    if (!canvas) return;
    var wrap = canvas.parentElement;
    canvas.width  = wrap.clientWidth;
    canvas.height = wrap.clientHeight;
    var cx = canvas.width / 2, cy = canvas.height / 2;
    this._mapNodes = new Map();
    this._mapEdges = [];
    this._mapParticles = [];
    var slice = devices.slice(0, 80);
    for (var i = 0; i < slice.length; i++) {
      var d = slice[i];
      var theta = (i / Math.max(slice.length, 1)) * Math.PI * 2;
      var r = Math.min(cx, cy) * 0.28;
      var node = Object.assign({}, d, {
        ip: d.ip, type: 'internal',
        x: cx + Math.cos(theta) * r + (Math.random() - 0.5) * 30,
        y: cy + Math.sin(theta) * r + (Math.random() - 0.5) * 30,
        vx: 0, vy: 0, r: this._nr(d),
      });
      this._mapNodes.set(d.ip, node);
    }
    var extCount = {};
    var baselineEdges = (baselineGraph && baselineGraph.edges) || [];
    if (this._mapMode !== 'baseline') {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
      }
    }
    if (this._mapMode !== 'live') {
      for (var bc = 0; bc < baselineEdges.length; bc++) {
        var bce = baselineEdges[bc];
        if (bce.target_kind === 'external') extCount[bce.target] = (extCount[bce.target] || 0) + (bce.avg_flows_per_snapshot || 1);
      }
    }
    var topExt = Object.keys(extCount).sort(function(a, b) { return extCount[b] - extCount[a]; }).slice(0, 25);
    for (var j = 0; j < topExt.length; j++) {
      var ip = topExt[j];
      var ang = (j / topExt.length) * Math.PI * 2;
      var rExt = Math.min(cx, cy) * 0.52;
      var info = extIPs.find(function(e) { return e.ip === ip; }) || {};
      this._mapNodes.set(ip, {
        ip: ip, type: 'external',
        x: cx + Math.cos(ang) * rExt + (Math.random() - 0.5) * 20,
        y: cy + Math.sin(ang) * rExt + (Math.random() - 0.5) * 20,
        vx: 0, vy: 0, r: 4,
        label: info.hostname || info.org || ip,
        at_risk: info.blacklisted || false,
        blacklisted: info.blacklisted || false,
        country: info.country || '',
        country_name: info.country_name || '',
        hostname: info.hostname || '',
        org: info.org || '',
        asn: info.asn || '',
        city: info.city || '',
        rating: info.rating || '',
        vt_malicious: info.vt_malicious,
        abuse_confidence: info.abuse_confidence,
      });
    }
    // Add multicast nodes in a dedicated outer ring
    var mcCount = {};
    if (this._mapMode !== 'baseline') {
      for (var mc = 0; mc < connections.length; mc++) {
        var mconn = connections[mc];
        if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
      }
    }
    if (this._mapMode !== 'live') {
      for (var bmc = 0; bmc < baselineEdges.length; bmc++) {
        var bmce = baselineEdges[bmc];
        if (bmce.target_kind === 'multicast') mcCount[bmce.target] = (mcCount[bmce.target] || 0) + (bmce.avg_flows_per_snapshot || 1);
      }
    }
    var topMc = Object.keys(mcCount).sort(function(a, b) { return mcCount[b] - mcCount[a]; }).slice(0, 15);
    for (var mi = 0; mi < topMc.length; mi++) {
      var mip = topMc[mi];
      var mang = (mi / topMc.length) * Math.PI * 2 + Math.PI / 4;
      var rMc = Math.min(cx, cy) * 0.42;
      var minfo = mcIPs.find(function(e) { return e.ip === mip; }) || {};
      this._mapNodes.set(mip, {
        ip: mip, type: 'multicast',
        x: cx + Math.cos(mang) * rMc + (Math.random() - 0.5) * 15,
        y: cy + Math.sin(mang) * rMc + (Math.random() - 0.5) * 15,
        vx: 0, vy: 0, r: 4,
        label: minfo.label || mip,
        internal_sources: minfo.internal_sources || [],
      });
    }
    this._mapEdges = this._composeMapEdges(connections, baselineGraph).filter(function(c) {
      return this._mapNodes.has(c.source) && this._mapNodes.has(c.target);
    }.bind(this)).slice(0, 500);
    this._mapTick = 0;
    // Zoom and pan are intentionally NOT reset here so that switching map mode
    // or filter preserves the current view.  The Reset button resets explicitly.
    this._spawnParticles();
    this._startMap(canvas);
    canvas.addEventListener('mousemove', function(e) { self._mapHover(e, canvas); });
    canvas.addEventListener('mouseleave', function() {
      var t = self.shadowRoot.getElementById('hsa-map-tip');
      if (t) t.style.display = 'none';
    });
    canvas.addEventListener('wheel', function(e) {
      e.preventDefault();
      var rect = canvas.getBoundingClientRect();
      var mx = e.clientX - rect.left, my = e.clientY - rect.top;
      var oldZ = self._mapZoom;
      var delta = e.deltaY > 0 ? 0.9 : 1.1;
      self._mapZoom = Math.max(0.3, Math.min(8, oldZ * delta));
      self._mapPanX = mx - (mx - self._mapPanX) * (self._mapZoom / oldZ);
      self._mapPanY = my - (my - self._mapPanY) * (self._mapZoom / oldZ);
    }, { passive: false });
    canvas.addEventListener('mousedown', function(e) {
      if (e.button === 0) {
        self._mapDragging = true;
        self._mapDragMoved = false;
        self._mapDragLastX = e.clientX;
        self._mapDragLastY = e.clientY;
      }
    });
    canvas.addEventListener('mousemove', function(e) {
      if (self._mapDragging) {
        var dx = e.clientX - self._mapDragLastX, dy = e.clientY - self._mapDragLastY;
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) self._mapDragMoved = true;
        self._mapPanX += dx;
        self._mapPanY += dy;
        self._mapDragLastX = e.clientX;
        self._mapDragLastY = e.clientY;
      }
    });
    canvas.addEventListener('mouseup', function() { self._mapDragging = false; });
    canvas.addEventListener('mouseleave', function() { self._mapDragging = false; });

    // ── Touch support (pan + pinch-zoom) ──────────────────────────────────
    canvas.addEventListener('touchstart', function(e) {
      e.preventDefault();
      if (e.touches.length === 1) {
        self._mapDragging = true;
        self._mapDragMoved = false;
        self._mapDragLastX = e.touches[0].clientX;
        self._mapDragLastY = e.touches[0].clientY;
        self._mapPinchDist = null;
      } else if (e.touches.length === 2) {
        self._mapDragging = false;
        var dx = e.touches[0].clientX - e.touches[1].clientX;
        var dy = e.touches[0].clientY - e.touches[1].clientY;
        self._mapPinchDist = Math.sqrt(dx * dx + dy * dy);
        self._mapPinchMidX = (e.touches[0].clientX + e.touches[1].clientX) / 2;
        self._mapPinchMidY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      }
    }, { passive: false });
    canvas.addEventListener('touchmove', function(e) {
      e.preventDefault();
      if (e.touches.length === 1 && self._mapDragging) {
        var dx = e.touches[0].clientX - self._mapDragLastX;
        var dy = e.touches[0].clientY - self._mapDragLastY;
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) self._mapDragMoved = true;
        self._mapPanX += dx;
        self._mapPanY += dy;
        self._mapDragLastX = e.touches[0].clientX;
        self._mapDragLastY = e.touches[0].clientY;
      } else if (e.touches.length === 2 && self._mapPinchDist != null) {
        var dx2 = e.touches[0].clientX - e.touches[1].clientX;
        var dy2 = e.touches[0].clientY - e.touches[1].clientY;
        var newDist = Math.sqrt(dx2 * dx2 + dy2 * dy2);
        var rect = canvas.getBoundingClientRect();
        var mx = self._mapPinchMidX - rect.left;
        var my = self._mapPinchMidY - rect.top;
        var oldZ = self._mapZoom;
        self._mapZoom = Math.max(0.3, Math.min(8, oldZ * (newDist / self._mapPinchDist)));
        self._mapPanX = mx - (mx - self._mapPanX) * (self._mapZoom / oldZ);
        self._mapPanY = my - (my - self._mapPanY) * (self._mapZoom / oldZ);
        self._mapPinchDist = newDist;
        self._mapPinchMidX = (e.touches[0].clientX + e.touches[1].clientX) / 2;
        self._mapPinchMidY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      }
    }, { passive: false });
    canvas.addEventListener('touchend', function(e) {
      if (e.touches.length === 0) {
        if (self._mapDragging && !self._mapDragMoved) {
          // tap — find node under finger
          var rect = canvas.getBoundingClientRect();
          var tx = (e.changedTouches[0].clientX - rect.left - self._mapPanX) / self._mapZoom;
          var ty = (e.changedTouches[0].clientY - rect.top  - self._mapPanY) / self._mapZoom;
          for (var it = self._mapNodes.entries(), r2 = it.next(); !r2.done; r2 = it.next()) {
            var n = r2.value[1];
            if (n.type === 'external' && Math.sqrt((tx - n.x) * (tx - n.x) + (ty - n.y) * (ty - n.y)) <= n.r + 8) {
              self._setView('external');
              self._doLookup(n.ip);
              break;
            }
          }
        }
        self._mapDragging = false;
        self._mapPinchDist = null;
      } else if (e.touches.length === 1) {
        // went from pinch back to single finger — resume pan
        self._mapDragging = true;
        self._mapDragMoved = true;
        self._mapDragLastX = e.touches[0].clientX;
        self._mapDragLastY = e.touches[0].clientY;
        self._mapPinchDist = null;
      }
    }, { passive: false });

    canvas.addEventListener('click', function(e) {
      if (self._mapDragMoved) return;
      var rect = canvas.getBoundingClientRect();
      var mx = (e.clientX - rect.left - self._mapPanX) / self._mapZoom;
      var my = (e.clientY - rect.top - self._mapPanY) / self._mapZoom;
      for (var it = self._mapNodes.entries(), r2 = it.next(); !r2.done; r2 = it.next()) {
        var n = r2.value[1];
        if (n.type === 'external' && Math.sqrt((mx - n.x) * (mx - n.x) + (my - n.y) * (my - n.y)) <= n.r + 5) {
          self._setView('external');
          self._doLookup(n.ip);
          return;
        }
      }
    });
  }

  _startMap(canvas) {
    this._stopMap();
    var self = this;
    var isBaseline = this._mapMode === 'baseline';
    var loop = function() {
      try {
        if (!isBaseline) {
          self._mapStep(canvas.width, canvas.height);
          self._mapTick++;
          self._tickParticles();
        }
        self._drawMap(canvas);
      } catch (e) {
        console.error('[HomeSec] map loop error:', e);
      }
      self._mapAnim = requestAnimationFrame(loop);
    };
    this._mapAnim = requestAnimationFrame(loop);
  }

  _stopMap() {
    if (this._mapAnim) { cancelAnimationFrame(this._mapAnim); this._mapAnim = null; }
  }

  _spawnParticles() {
    this._mapParticles = [];
    if (this._mapMode === 'baseline') return;
    for (var i = 0; i < this._mapEdges.length; i++) {
      var e = this._mapEdges[i];
      if (e.edge_mode === 'missing') continue;
      var count = Math.min(3, Math.max(1, Math.ceil(Math.log10(e.weight + 1))));
      for (var p = 0; p < count; p++) {
        this._mapParticles.push({
          source: e.source, target: e.target,
          t: Math.random(),
          speed: 0.003 + Math.random() * 0.006,
          size: 1 + Math.random() * 1.2,
        });
      }
    }
  }

  _tickParticles() {
    for (var i = 0; i < this._mapParticles.length; i++) {
      var p = this._mapParticles[i];
      p.t += p.speed;
      if (p.t > 1) p.t -= 1;
    }
  }

  _liveUpdateMap() {
    if (!this._data) return;
    var allDevices = this._mapAllDevices();
    var devices    = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
    var baselineGraph = this._data.baseline_graph || null;
    var extIPs     = this._data.external_ips || [];
    var mcIPs      = this._data.multicast_ips || [];
    var showExt    = (this._mapFilter === 'all' || this._mapFilter === 'external');
    var canvas     = this.shadowRoot.getElementById('hsa-map-canvas');
    if (!canvas) return;
    var cx = canvas.width / 2, cy = canvas.height / 2;
    var hadNew = false;

    // Update / add internal nodes
    var slice = devices.slice(0, 80);
    for (var i = 0; i < slice.length; i++) {
      var d = slice[i];
      var existing = this._mapNodes.get(d.ip);
      if (existing) {
        existing.alive = d.alive;
        existing.total_octets = d.total_octets;
        existing.at_risk = d.at_risk;
        existing.probable_role = d.probable_role;
        existing.display_name = d.display_name;
        existing.hostname = d.hostname;
        existing.r = this._nr(d);
      } else {
        this._mapNodes.set(d.ip, Object.assign({}, d, {
          ip: d.ip, type: 'internal',
          x: cx + (Math.random() - 0.5) * 80,
          y: cy + (Math.random() - 0.5) * 80,
          vx: 0, vy: 0, r: this._nr(d),
        }));
        hadNew = true;
      }
    }

    // Update / add external nodes from connections
    var extCount = {};
    if (showExt && this._mapMode !== 'baseline') {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
      }
    }
    if (showExt && this._mapMode !== 'live') {
      var baselineEdges = (baselineGraph && baselineGraph.edges) || [];
      for (var bc = 0; bc < baselineEdges.length; bc++) {
        var bce = baselineEdges[bc];
        if (bce.target_kind === 'external') extCount[bce.target] = (extCount[bce.target] || 0) + (bce.avg_flows_per_snapshot || 1);
      }
    }
    var topExt = Object.keys(extCount).sort(function(a, b) { return extCount[b] - extCount[a]; }).slice(0, 25);
    for (var j = 0; j < topExt.length; j++) {
      var ip = topExt[j];
      var info = extIPs.find(function(e) { return e.ip === ip; }) || {};
      var extNode = this._mapNodes.get(ip);
      if (extNode) {
        extNode.label = info.hostname || info.org || ip;
        extNode.at_risk = info.blacklisted || false;
        extNode.blacklisted = info.blacklisted || false;
        extNode.country = info.country || '';
        extNode.country_name = info.country_name || '';
        extNode.hostname = info.hostname || '';
        extNode.org = info.org || '';
        extNode.asn = info.asn || '';
        extNode.city = info.city || '';
        extNode.rating = info.rating || '';
        extNode.vt_malicious = info.vt_malicious;
        extNode.abuse_confidence = info.abuse_confidence;
      } else {
        var ang = Math.random() * Math.PI * 2;
        var rExt = Math.min(cx, cy) * 0.52;
        this._mapNodes.set(ip, {
          ip: ip, type: 'external',
          x: cx + Math.cos(ang) * rExt,
          y: cy + Math.sin(ang) * rExt,
          vx: 0, vy: 0, r: 4,
          label: info.hostname || info.org || ip,
          at_risk: info.blacklisted || false,
          blacklisted: info.blacklisted || false,
          country: info.country || '',
          country_name: info.country_name || '',
          hostname: info.hostname || '',
          org: info.org || '',
          asn: info.asn || '',
          city: info.city || '',
          rating: info.rating || '',
          vt_malicious: info.vt_malicious,
          abuse_confidence: info.abuse_confidence,
        });
        hadNew = true;
      }
    }

    // Update / add multicast nodes from connections
    var mcCount = {};
    if (showExt && this._mapMode !== 'baseline') {
      for (var mc = 0; mc < connections.length; mc++) {
        var mconn = connections[mc];
        if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
      }
    }
    if (showExt && this._mapMode !== 'live') {
      var bmcEdges = (baselineGraph && baselineGraph.edges) || [];
      for (var bmc = 0; bmc < bmcEdges.length; bmc++) {
        var bmce = bmcEdges[bmc];
        if (bmce.target_kind === 'multicast') mcCount[bmce.target] = (mcCount[bmce.target] || 0) + (bmce.avg_flows_per_snapshot || 1);
      }
    }
    var topMc = Object.keys(mcCount).sort(function(a, b) { return mcCount[b] - mcCount[a]; }).slice(0, 15);
    for (var mi = 0; mi < topMc.length; mi++) {
      var mip = topMc[mi];
      var minfo = mcIPs.find(function(e) { return e.ip === mip; }) || {};
      var mcNode = this._mapNodes.get(mip);
      if (mcNode) {
        mcNode.label = minfo.label || mip;
        mcNode.internal_sources = minfo.internal_sources || [];
      } else {
        var mang = Math.random() * Math.PI * 2;
        var rMc = Math.min(cx, cy) * 0.42;
        this._mapNodes.set(mip, {
          ip: mip, type: 'multicast',
          x: cx + Math.cos(mang) * rMc,
          y: cy + Math.sin(mang) * rMc,
          vx: 0, vy: 0, r: 4,
          label: minfo.label || mip,
          internal_sources: minfo.internal_sources || [],
        });
        hadNew = true;
      }
    }

    // Rebuild edges from latest data (live / baseline / compare)
    this._mapEdges = this._composeMapEdges(connections, baselineGraph).filter(function(c) {
      return this._mapNodes.has(c.source) && this._mapNodes.has(c.target);
    }.bind(this)).slice(0, 500);

    // Respawn particles for new edges
    this._spawnParticles();

    // Briefly re-activate strong physics to settle new nodes
    if (hadNew) this._mapTick = Math.min(this._mapTick, 160);

    // Update stats overlay
    var statsEl = this.shadowRoot.getElementById('map-stats');
    if (statsEl) {
      var s = this._data.summary || {};
      statsEl.textContent = devices.length + ' internal \u00B7 ' + extIPs.length + ' external' + (mcIPs.length ? ' \u00B7 ' + mcIPs.length + ' multicast' : '') + ' \u00B7 ' + this._fmtN(s.total_flows || 0) + ' flows';
    }
  }

  _mapStep(W, H) {
    var nodes = Array.from(this._mapNodes.values());
    // Adaptive physics: strong early, gentle continuous drift after settling
    var settled = this._mapTick > 200;
    var R = settled ? 400 : 1400, A = settled ? 0.001 : 0.004;
    var DAMP = settled ? 0.55 : 0.72, MAX_V = settled ? 1.2 : 5;
    var CENTER_PULL = settled ? 0.00004 : 0.00015;
    // Jitter to keep things subtly alive
    var jitter = settled ? 0.08 : 0;
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var dx = nodes[i].x - nodes[j].x || 0.1, dy = nodes[i].y - nodes[j].y || 0.1;
        var d2 = Math.max(dx * dx + dy * dy, 1);
        var f  = R / d2, inv = 1 / Math.sqrt(d2);
        nodes[i].vx += dx * inv * f; nodes[i].vy += dy * inv * f;
        nodes[j].vx -= dx * inv * f; nodes[j].vy -= dy * inv * f;
      }
    }
    for (var ei = 0; ei < this._mapEdges.length; ei++) {
      var e = this._mapEdges[ei];
      var s = this._mapNodes.get(e.source), t = this._mapNodes.get(e.target);
      if (!s || !t) continue;
      var edx = t.x - s.x, edy = t.y - s.y;
      var dd = Math.max(Math.sqrt(edx * edx + edy * edy), 1);
      // Target edge length based on node types
      var ideal = (s.type === 'external' || t.type === 'external') ? 100 : 55;
      var ef = A * (dd - ideal);
      s.vx += (edx / dd) * ef; s.vy += (edy / dd) * ef;
      t.vx -= (edx / dd) * ef; t.vy -= (edy / dd) * ef;
    }
    var cx2 = W / 2, cy2 = H / 2;
    for (var ni = 0; ni < nodes.length; ni++) {
      var n = nodes[ni];
      n.vx += (cx2 - n.x) * CENTER_PULL; n.vy += (cy2 - n.y) * CENTER_PULL;
      if (jitter > 0) { n.vx += (Math.random() - 0.5) * jitter; n.vy += (Math.random() - 0.5) * jitter; }
      n.vx *= DAMP; n.vy *= DAMP;
      var spd = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      if (spd > MAX_V) { n.vx = (n.vx / spd) * MAX_V; n.vy = (n.vy / spd) * MAX_V; }
      n.x = Math.max(n.r + 2, Math.min(W - n.r - 2, n.x + n.vx));
      n.y = Math.max(n.r + 2, Math.min(H - n.r - 2, n.y + n.vy));
    }
  }

  _drawMap(canvas) {
    var ctx  = canvas.getContext('2d');
    var W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    var bg = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, Math.max(W, H) * 0.7);
    bg.addColorStop(0, 'rgba(10,18,40,.96)'); bg.addColorStop(1, 'rgba(4,8,18,.99)');
    ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);
    ctx.save();
    ctx.translate(this._mapPanX, this._mapPanY);
    ctx.scale(this._mapZoom, this._mapZoom);
    // Draw edges as curved lines
    for (var ei = 0; ei < this._mapEdges.length; ei++) {
      var e = this._mapEdges[ei];
      var s = this._mapNodes.get(e.source), t = this._mapNodes.get(e.target);
      if (!s || !t) continue;
      var a = Math.min(0.35, 0.03 + Math.log10(e.weight + 1) * 0.05);
      var mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
      var dx = t.x - s.x, dy = t.y - s.y;
      var curveOff = Math.min(18, Math.sqrt(dx * dx + dy * dy) * 0.08);
      var cpx = mx + dy * curveOff / Math.max(Math.sqrt(dx*dx+dy*dy), 1);
      var cpy = my - dx * curveOff / Math.max(Math.sqrt(dx*dx+dy*dy), 1);
      ctx.beginPath(); ctx.moveTo(s.x, s.y);
      ctx.quadraticCurveTo(cpx, cpy, t.x, t.y);
      ctx.setLineDash([]);
      if (this._mapMode === 'baseline') {
        ctx.strokeStyle = 'rgba(136,167,199,' + Math.min(0.55, a + 0.22) + ')';
        ctx.lineWidth = Math.min(1.8, 0.6 + Math.log10(e.weight + 1) * 0.18);
        ctx.setLineDash([6, 4]);
      } else if (this._mapMode === 'compare') {
        if (e.edge_mode === 'missing') {
          // vivid orange-red, thick dashed — clearly "gone"
          ctx.strokeStyle = 'rgba(255,90,50,' + Math.min(0.82, a + 0.55) + ')';
          ctx.lineWidth = Math.min(2.4, 0.8 + Math.log10(e.weight + 1) * 0.25);
          ctx.setLineDash([8, 5]);
        } else if (e.edge_mode === 'new') {
          // vivid green, solid — clearly "appeared"
          ctx.strokeStyle = 'rgba(50,255,120,' + Math.min(0.88, a + 0.58) + ')';
          ctx.lineWidth = Math.min(2.4, 0.8 + Math.log10(e.weight + 1) * 0.25);
        } else {
          // unchanged — cyan, semi-transparent
          ctx.strokeStyle = 'rgba(98,232,255,' + Math.min(0.45, a + 0.12) + ')';
          ctx.lineWidth = Math.min(1.6, 0.4 + Math.log10(e.weight + 1) * 0.16);
        }
      } else {
        ctx.strokeStyle = 'rgba(98,232,255,' + a + ')';
        ctx.lineWidth = Math.min(1.8, 0.3 + Math.log10(e.weight + 1) * 0.18);
      }
      ctx.stroke();
      ctx.setLineDash([]);
    }
    // Draw particles flowing along edges
    for (var pi = 0; pi < this._mapParticles.length; pi++) {
      var p = this._mapParticles[pi];
      var ps = this._mapNodes.get(p.source), pt = this._mapNodes.get(p.target);
      if (!ps || !pt) continue;
      var pmx = (ps.x + pt.x) / 2, pmy = (ps.y + pt.y) / 2;
      var pdx = pt.x - ps.x, pdy = pt.y - ps.y;
      var plen = Math.max(Math.sqrt(pdx*pdx+pdy*pdy), 1);
      var pcOff = Math.min(18, plen * 0.08);
      var pcpx = pmx + pdy * pcOff / plen, pcpy = pmy - pdx * pcOff / plen;
      var tt = p.t, it = 1 - tt;
      var px = it*it*ps.x + 2*it*tt*pcpx + tt*tt*pt.x;
      var py = it*it*ps.y + 2*it*tt*pcpy + tt*tt*pt.y;
      var pa = 0.5 + 0.5 * Math.sin(p.t * Math.PI);
      ctx.beginPath(); ctx.arc(px, py, p.size, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(98,232,255,' + (pa * 0.7) + ')';
      ctx.fill();
    }
    // Draw nodes
    var sorted = Array.from(this._mapNodes.values()).sort(function(a, b) { var order = { external: 0, multicast: 1, internal: 2 }; return (order[a.type] || 2) - (order[b.type] || 2); });
    var now = Date.now();
    var pulse = 0.7 + Math.sin(now * 0.004) * 0.3;
    for (var ni = 0; ni < sorted.length; ni++) {
      var n = sorted[ni];
      var col = this._nc(n);
      var nodeR = n.r;
      // Subtle breathing for active internal nodes
      if (n.type !== 'external' && n.type !== 'multicast' && (n.alive || (n.total_octets||0) > 0)) {
        var phase = (now * 0.003 + ni * 0.7) % (Math.PI * 2);
        nodeR = n.r * (0.92 + Math.sin(phase) * 0.08);
      }
      // Outer glow ring for at-risk
      if (n.at_risk) {
        var glowR = nodeR + 4 + Math.sin(now * 0.005) * 3;
        ctx.beginPath(); ctx.arc(n.x, n.y, glowR, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,77,109,' + (0.08 + Math.sin(now * 0.005) * 0.06) + ')';
        ctx.fill();
      }
      // Node body
      ctx.beginPath(); ctx.arc(n.x, n.y, nodeR, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.globalAlpha = (n.alive || n.type === 'external' || (n.total_octets||0) > 0) ? 1.0 : 0.45;
      ctx.fill();
      ctx.globalAlpha = 1.0;
      // Thin border
      ctx.strokeStyle = n.at_risk ? '#ff4d6d' : 'rgba(255,255,255,0.12)';
      ctx.lineWidth = n.at_risk ? 1.5 : 0.5;
      ctx.stroke();
      // Country flag for external nodes
      if (n.type === 'external' && n.country) {
        var flag = this._countryFlag(n.country);
        if (flag) {
          ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
          ctx.fillText(flag, n.x, n.y - nodeR - 3);
        }
      }
      // Label: always draw for all node types
      ctx.font = '8px IBM Plex Mono, monospace'; ctx.textAlign = 'center';
      if (n.type === 'internal') {
        // Line 1: IP address
        ctx.fillStyle = 'rgba(180,210,240,.6)';
        ctx.fillText((n.ip || '').substring(0, 18), n.x, n.y + nodeR + 9);
        // Line 2: tracker name (display_name or hostname), only if different from the IP
        var trackerName = (n.display_name || n.hostname || '').substring(0, 18);
        if (trackerName && trackerName !== (n.ip || '').substring(0, 18)) {
          ctx.fillStyle = n.at_risk ? '#ff9aae' : 'rgba(140,200,255,.85)';
          ctx.font = 'bold 8px IBM Plex Mono, monospace';
          ctx.fillText(trackerName, n.x, n.y + nodeR + 19);
        }
      } else if (n.type === 'external') {
        // Line 1: IP address
        ctx.fillStyle = n.at_risk ? '#ff9aae' : 'rgba(180,210,240,.55)';
        ctx.fillText((n.ip || '').substring(0, 16), n.x, n.y + nodeR + 9);
        // Line 2: org or hostname if available
        var extMeta = (n.org || n.hostname || '').substring(0, 16);
        if (extMeta) {
          ctx.fillStyle = n.at_risk ? 'rgba(255,154,174,.7)' : 'rgba(140,170,210,.45)';
          ctx.fillText(extMeta, n.x, n.y + nodeR + 18);
        }
      } else {
        var label = (n.label || n.ip || '').substring(0, 16);
        ctx.fillStyle = n.at_risk ? '#ff9aae' : (n.type === 'multicast' ? '#d4a843' : 'rgba(180,210,240,.6)');
        ctx.fillText(label, n.x, n.y + nodeR + 9);
      }
    }
    ctx.restore();
    // Zoom indicator
    var zPct = Math.round(this._mapZoom * 100);
    if (zPct !== 100) {
      ctx.fillStyle = 'rgba(98,232,255,.5)';
      ctx.font = '10px IBM Plex Mono, monospace';
      ctx.textAlign = 'right';
      ctx.fillText(zPct + '%', W - 10, 16);
    }
  }

  _mapHover(e, canvas) {
    if (this._mapDragging) return;
    var rect = canvas.getBoundingClientRect();
    var sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    var mx = (sx - this._mapPanX) / this._mapZoom;
    var my = (sy - this._mapPanY) / this._mapZoom;
    var tip = this.shadowRoot.getElementById('hsa-map-tip');
    if (!tip) return;
    for (var it = this._mapNodes.entries(), r2 = it.next(); !r2.done; r2 = it.next()) {
      var ip = r2.value[0], n = r2.value[1];
      if (Math.sqrt((mx - n.x) * (mx - n.x) + (my - n.y) * (my - n.y)) <= n.r + 5) {
        var lbl  = n.display_name || n.hostname || ip;
        var role = n.probable_role ? '<br><span style="color:#8a9dbf">' + n.probable_role + '</span>' : '';
        var risk = n.at_risk  ? '<br><span style="color:#ff4d6d">\u26A0 ' + this._t('map.at_risk', 'At risk') + '</span>' : '';
        var baselineStats = (this._data && this._data.baseline) || {};
        var baselineSnapshots = ((baselineStats.training_stats || {}).snapshots_seen || 0);
        var flagEmoji = n.country ? this._countryFlag(n.country) : '';
        var ctryLabel = n.country_name || n.country || '';
        var ctry = ctryLabel  ? '<br><span style="color:#8a9dbf">' + (flagEmoji ? flagEmoji + ' ' : '') + this._esc(ctryLabel) + (n.city ? ', ' + this._esc(n.city) : '') + '</span>' : '';
        var extra = '';
        if (n.type === 'multicast') {
          if (n.label && n.label !== ip) extra += '<br><span style="color:#d4a843;font-size:10px">' + this._esc(n.label) + '</span>';
          extra += '<br><span style="color:#8a9dbf;font-size:10px">' + this._t('map.multicast_note', 'Multicast · not internet-routed') + '</span>';
          if (n.internal_sources && n.internal_sources.length) extra += '<br><span style="color:#8a9dbf;font-size:9px">' + this._t('map.sources', 'Sources') + ': ' + n.internal_sources.join(', ') + '</span>';
        } else if (n.type === 'external') {
          if (n.org) extra += '<br><span style="color:#8a9dbf;font-size:10px">' + this._esc(n.org.substring(0, 40)) + '</span>';
          if (n.rating) extra += '<br>' + this._rating(n.rating);
          var vtLine = n.vt_malicious != null ? 'VT: ' + n.vt_malicious + ' malicious' : '';
          var abLine = n.abuse_confidence != null ? 'Abuse: ' + n.abuse_confidence + '%' : '';
          var intelParts = [vtLine, abLine].filter(Boolean).join(' \u00B7 ');
          if (intelParts) extra += '<br><span style="color:#8a9dbf;font-size:9px">' + intelParts + '</span>';
          extra += '<br><span style="color:var(--accent);font-size:9px;opacity:.6">' + this._t('map.click_full_lookup', 'Click for full lookup') + '</span>';
        } else {
          if (this._mapMode !== 'live') {
            var obs = n.baseline_observation_count || 0;
            var presence = baselineSnapshots > 0 ? Math.min(1, obs / baselineSnapshots) : 0;
            var presencePct = Math.round(presence * 100);
            var liveLoad = Math.min(1, Math.log10((n.total_octets || 0) + 1) / 8);
            var livePct = Math.round(liveLoad * 100);
            extra += '<br><span style="color:#8a9dbf;font-size:9px">' + this._t('map.baseline_presence', 'Baseline presence') + ': ' + presencePct + '%</span>';
            extra += '<div style="margin-top:2px;height:4px;background:rgba(136,167,199,.18);border-radius:3px;overflow:hidden"><div style="height:4px;width:' + presencePct + '%;background:#88a7c7"></div></div>';
            extra += '<br><span style="color:#8a9dbf;font-size:9px">' + this._t('map.live_load', 'Live load index') + ': ' + livePct + '%</span>';
            extra += '<div style="margin-top:2px;height:4px;background:rgba(0,224,255,.15);border-radius:3px;overflow:hidden"><div style="height:4px;width:' + livePct + '%;background:#00e0ff"></div></div>';
          }
        }
        tip.innerHTML = '<strong style="color:#62e8ff">' + this._esc(lbl) + '</strong><br><span class="ip">' + ip + '</span>' + role + ctry + extra + risk;
        var tipX = n.x * this._mapZoom + this._mapPanX + 14;
        var tipY = n.y * this._mapZoom + this._mapPanY - 14;
        tip.style.cssText = 'display:block;left:' + tipX + 'px;top:' + tipY + 'px';
        canvas.style.cursor = n.type === 'external' ? 'pointer' : 'grab';
        return;
      }
    }
    tip.style.display = 'none';
    canvas.style.cursor = 'grab';
  }

  _hostThead() {
    var self = this;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var cols = [
      { key: 'ip', label: 'IP' },
      { key: 'name', label: this._t('hosts.col_name', 'Name') },
      { key: 'os', label: 'OS' },
      { key: 'role', label: this._t('hosts.col_role', 'Role') },
      { key: null, label: this._t('hosts.col_open_ports', 'Open ports') },
      { key: 'cve', label: 'CVEs' },
      { key: 'ping', label: 'Ping' },
    ];
    if (netflowEnabled) cols.push({ key: 'traffic', label: this._t('hosts.col_traffic', 'Traffic') });
    return '<tr>' + cols.map(function(c) {
      if (!c.key) return '<th>' + c.label + '</th>';
      var arrow = self._hostSort === c.key ? (self._hostSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
      return '<th class="sortable-th" data-hostsort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
    }).join('') + '</tr>';
  }

  _viewHosts() {
    var aliveDevices = ((this._data && this._data.devices) || []).filter(function(d) { return d.alive; });
    var cnt = aliveDevices.length;
    return '<div>' +
      '<div class="view-header"><h1>' + this._t('hosts.page_title', 'Network Hosts') + ' <span class="dim">(' + cnt + ' ' + this._t('hosts.alive_suffix', 'alive') + ')</span></h1>' +
      '<input id="hsa-host-filter" class="search-bar" type="search" placeholder="' + this._esc(this._t('hosts.filter_placeholder', 'Filter by IP, name, role…')) + '" value="' + this._esc(this._hostFilter) + '"></div>' +
      '<div class="card table-card"><table class="data-table">' +
        '<thead id="hsa-host-thead">' + this._hostThead() + '</thead>' +
        '<tbody id="hsa-host-tbody">' + this._hostRows() + '</tbody>' +
      '</table></div></div>';
  }

  _hostRows() {
    var netflowEnabledRaw2 = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw2 === true || netflowEnabledRaw2 === 'true' || netflowEnabledRaw2 === 1 || netflowEnabledRaw2 === '1';
    var colCount = netflowEnabled ? 8 : 7;
    var q = this._hostFilter.toLowerCase();
    var devices = (this._data && this._data.devices || []).filter(function(d) {
      if (!d.alive) return false;
      return !q || (d.ip || '').indexOf(q) >= 0 ||
        (d.display_name || '').toLowerCase().indexOf(q) >= 0 ||
        (d.hostname || '').toLowerCase().indexOf(q) >= 0 ||
        (d.probable_role || '').indexOf(q) >= 0;
    });
    if (!devices.length) return '<tr><td colspan="' + colCount + '"><div class="empty-state"><div class="empty-icon">\uD83D\uDD0D</div><p>' + this._t('hosts.no_match', 'No hosts match the filter') + '</p></div></td></tr>';
    var sortKey = this._hostSort;
    var sortDir = this._hostSortDir;
    devices.sort(function(a, b) {
      var va, vb;
      if (sortKey === 'ip') {
        va = (a.ip || '').split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.');
        vb = (b.ip || '').split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.');
      } else if (sortKey === 'name') {
        va = (a.display_name || a.hostname || '').toLowerCase();
        vb = (b.display_name || b.hostname || '').toLowerCase();
      } else if (sortKey === 'os') {
        va = (a.os_guess || '').toLowerCase();
        vb = (b.os_guess || '').toLowerCase();
      } else if (sortKey === 'role') {
        va = (a.probable_role || '').toLowerCase();
        vb = (b.probable_role || '').toLowerCase();
      } else if (sortKey === 'cve') {
        va = (a.vulnerabilities || []).length;
        vb = (b.vulnerabilities || []).length;
      } else if (sortKey === 'ping') {
        // Hosts without a ping RTT sort to the end in ascending order.
        va = (a.ping_ms != null) ? a.ping_ms : Infinity;
        vb = (b.ping_ms != null) ? b.ping_ms : Infinity;
      } else if (sortKey === 'traffic') {
        va = a.total_octets || 0;
        vb = b.total_octets || 0;
      } else {
        return 0;
      }
      if (va < vb) return -1 * sortDir;
      if (va > vb) return 1 * sortDir;
      return 0;
    });
    var self = this;
    var builtInRoles = ['unknown','camera','printer','media_device','mobile_device','nas_or_desktop','dns_or_gateway','linux_host','web_service','iot_device'];
    var customRoleValues = Object.values((this._data && this._data.role_overrides) || {}).filter(function(r) {
      return builtInRoles.indexOf(r) === -1;
    });
    var knownCustomRoles = Array.from(new Set(customRoleValues));
    var overrides = (this._data && this._data.role_overrides) || {};
    var nameOverrides = (this._data && this._data.name_overrides) || {};
    return devices.map(function(d) {
      var name  = d.display_name || d.hostname || '';
      var vulns = (d.vulnerabilities || []).length;
      var alive = d.at_risk ? '#ff4d6d' : (d.alive ? '#6bffc8' : '#4a5a72');
      var ports = (d.scanned_services || []).map(function(s) { return s.port; }).join(', ') ||
                  (d.exposed_ports || []).slice(0, 6).join(', ') || '\u2014';
      var id = 'hsa-dr-' + d.ip.replace(/\./g, '-');
      var curRole = d.probable_role || 'unknown';
      var isOverride = d.ip in overrides;
      var isNameOverride = d.ip in nameOverrides;
      // If the current role isn't in the built-in list it's a custom role — include it as a selected option
      var isCustom = builtInRoles.indexOf(curRole) === -1;
      var roleOpts = builtInRoles.map(function(r) { return '<option value="' + r + '"' + (r === curRole ? ' selected' : '') + '>' + r.replace(/_/g, ' ') + '</option>'; }).join('');
      roleOpts += knownCustomRoles.map(function(r) { return '<option value="' + r + '"' + (r === curRole ? ' selected' : '') + '>' + r.replace(/_/g, ' ') + '</option>'; }).join('');
      if (isCustom && knownCustomRoles.indexOf(curRole) === -1) roleOpts += '<option value="' + curRole + '" selected>' + curRole.replace(/_/g, ' ') + '</option>';
      roleOpts += '<option value="__custom__">custom\u2026</option>';
      var roleSelect = '<select class="role-select" data-roleip="' + d.ip + '" title="Click to change role">' + roleOpts + '</select>' +
        (isOverride ? ' <span class="dim" style="font-size:9px">' + self._t('hosts.manual', '(manual)') + '</span>' : '');
      var nameCell = (name ? '<strong>' + self._esc(name) + '</strong>' : '<span class="dim">\u2014</span>') +
        ' <button class="btn" data-editname="' + d.ip + '">' + self._t('hosts.rename', 'Rename') + '</button>' +
        (isNameOverride ? ' <span class="dim" style="font-size:9px">' + self._t('hosts.manual', '(manual)') + '</span>' : '');
      return '<tr class="expandable" data-ip="' + d.ip + '">' +
        '<td><span style="color:' + alive + ';font-size:8px">\u25CF</span> <span class="ip">' + d.ip + '</span></td>' +
        '<td>' + nameCell + '</td>' +
        '<td><span style="font-size:11px">' + self._esc(d.os_guess || '\u2014') + '</span></td>' +
        '<td>' + roleSelect + '</td>' +
        '<td style="font-size:11px;font-family:monospace">' + ports + '</td>' +
        '<td>' + (vulns ? '<span class="badge badge-high">' + vulns + ' CVE' + (vulns > 1 ? 's' : '') + '</span>' : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-variant-numeric:tabular-nums">' + (d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : (d.alive ? 'alive' : '\u2014')) + '</td>' +
        (netflowEnabled ? '<td>' + self._bytes(d.total_octets) + '</td>' : '') +
        '</tr>' +
        '<tr class="detail-row" id="' + id + '" style="display:none">' +
        '<td colspan="' + colCount + '">' + self._hostDetail(d) + '</td>' +
        '</tr>';
    }).join('');
  }

  _hostDetail(d) {
    var svcs  = d.scanned_services || [];
    var vulns = d.vulnerabilities  || [];
    var self = this;
    // Build dismissed key → note map from global dismissed findings list
    var dismissedMap = {};
    ((this._data && this._data.dismissed_findings) || []).forEach(function(f) {
      if (f.key) dismissedMap[f.key] = f.dismiss_note || '';
    });
    var svcRows = svcs.map(function(s) {
      var techs = (s.technologies || []).join(', ');
      return '<tr><td><span class="chip">' + s.port + '/' + s.protocol + '</span></td>' +
        '<td>' + self._esc(s.service_name || '\u2014') + '</td>' +
        '<td class="mono dim">' + self._esc((s.banner || '').substring(0, 60) || '\u2014') + '</td>' +
        '<td>' + self._esc(s.version || '\u2014') + '</td>' +
        '<td>' + (techs ? self._esc(techs) : '\u2014') + '</td></tr>';
    }).join('');
    var vulnCards = vulns.map(function(v) {
      var key = 'vuln:' + d.ip + ':' + (v.port || 0) + ':' + (v.cve_id || '');
      var isDismissed = Object.prototype.hasOwnProperty.call(dismissedMap, key);
      var note = isDismissed ? dismissedMap[key] : '';
      var dismissedBadge = isDismissed
        ? ' <span class="chip" style="background:#444;color:#999;font-size:9px">' + self._t('findings.dismissed', 'dismissed') + '</span>'
        : '';
      var noteHtml = (isDismissed && note)
        ? '<div class="dim" style="font-size:10px;margin-top:4px;font-style:italic">' + self._t('hosts.note', 'Note') + ': ' + self._esc(note) + '</div>'
        : '';
      return '<div class="finding-card sev-' + v.severity + '" style="margin-bottom:6px;padding:10px' + (isDismissed ? ';opacity:0.45' : '') + '">' +
        '<div class="finding-header">' + self._sev(v.severity) +
        '<span class="finding-title">' + self._esc(v.cve_id) + ' \u00B7 ' + self._esc(v.service) + '</span>' +
        '<span class="dim" style="font-size:10px">CVSS ' + (v.cvss || '?') + '</span>' +
        dismissedBadge + '</div>' +
        '<div class="finding-body">' + self._esc(v.summary || '') + '</div>' +
        (v.remediation ? '<div class="fix-hint">' + self._t('hosts.fix', 'Fix') + ': ' + self._esc(v.remediation) + '</div>' : '') +
        noteHtml +
        '</div>';
    }).join('');
    return '<div class="host-detail-wrap">' +
      '<div>' +
        this._kv('IP', d.ip) + this._kv(this._t('hosts.kv_hostname', 'Hostname'), d.hostname || '\u2014') +
        this._kv('MAC', d.mac_address || '\u2014') + this._kv(this._t('hosts.kv_manufacturer', 'Manufacturer'), d.manufacturer || '\u2014') +
        this._kv('OS', d.os_guess ? d.os_guess + ' (' + d.os_confidence + ')' : '\u2014') +
        this._kv('Ping', d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : (d.alive ? 'alive' : 'no response')) +
        this._kv(this._t('hosts.kv_flows', 'Flows'), (d.total_flows || 0).toLocaleString()) +
        this._kv('Traffic', this._bytes(d.total_octets)) +
        this._kv(this._t('hosts.kv_external_peers', 'External peers'), (d.external_peers || []).length) +
        this._kv(this._t('hosts.kv_last_seen', 'Last seen'), this._ago(d.last_seen)) +
        (svcs.length ? '<div style="margin-top:12px"><div class="section-label">' + this._t('hosts.section_open_ports', 'Open Ports') + '</div>' +
          '<table class="data-table" style="font-size:11px"><thead><tr><th>' + this._t('hosts.port', 'Port') + '</th><th>' + this._t('hosts.service', 'Service') + '</th><th>' + this._t('hosts.banner', 'Banner') + '</th><th>' + this._t('hosts.version', 'Version') + '</th><th>' + this._t('hosts.technologies', 'Technologies') + '</th></tr></thead>' +
          '<tbody>' + svcRows + '</tbody></table></div>' : '') +
      '</div>' +
      '<div>' +
        (vulns.length
          ? '<div class="section-label" style="margin-bottom:8px">' + this._t('hosts.section_vulnerabilities', 'Vulnerabilities') + '</div>' + vulnCards
          : '<div class="empty-state" style="margin-top:20px"><div class="empty-icon">\u2713</div><p>' + this._t('hosts.no_vulnerabilities', 'No vulnerabilities detected') + '</p></div>') +
      '</div></div>';
  }

  _toggleRow(ip) {
    var row = this.shadowRoot.getElementById('hsa-dr-' + ip.replace(/\./g, '-'));
    if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
  }

  _viewFindings() {
    // Categories that belong exclusively to Baseline Anomalies
    var BASELINE_ONLY_CATS = {
      anomaly_new_host: true, anomaly_new_peer: true,
      anomaly_new_port: true, anomaly_new_dns_domain: true,
      anomaly_new_dns_category: true
    };
    var findings = ((this._data && this._data.findings) || []).filter(function(f) {
      return !BASELINE_ONLY_CATS[f.category];
    });
    var baselineAnomalies = (this._data && this._data.baseline_anomalies) || [];
    var allDismissed = (this._data && this._data.dismissed_findings) || [];
    // Tag every dismissed item so we know its origin; combine into one list
    var allDismissedList = allDismissed.map(function(f) {
      return Object.assign({}, f, { _isBaseline: !!BASELINE_ONLY_CATS[f.category] });
    });
    var findingsGroupMode  = this._findingsGroupMode  || 'category';
    var dismissedGroupMode = this._dismissedGroupMode || 'category';
    var baselineGroupMode = this._baselineGroupMode; // 'category' | 'host' | 'flat'
    var self = this;

    var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var _sevRank = function(s) { var r = SEV_ORDER[s]; return r != null ? r : 99; };

    // ── search helpers ───────────────────────────────────────────────
    var findingsQ  = (self._findingsSearch  || '').toLowerCase().trim();
    var baselineQ  = (self._baselineSearch  || '').toLowerCase().trim();
    var dismissedQ = (self._dismissedSearch || '').toLowerCase().trim();
    var _match = function(f, q) {
      if (!q) return true;
      return (f.summary   || '').toLowerCase().includes(q) ||
             (f.source_ip || '').toLowerCase().includes(q) ||
             (f.category  || '').toLowerCase().includes(q) ||
             ((f.details && f.details.cve_id) || '').toLowerCase().includes(q);
    };
    var filteredFindings  = findingsQ  ? findings.filter(function(f) { return _match(f, findingsQ);  }) : findings;
    var filteredBaseline  = baselineQ  ? baselineAnomalies.filter(function(f) { return _match(f, baselineQ);  }) : baselineAnomalies;
    var filteredDismissed = dismissedQ ? allDismissedList.filter(function(f) { return _match(f, dismissedQ); }) : allDismissedList;

    // ── Top toolbar (always at page top) ────────────────────────────
    var topBar =
      '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:14px">' +
        '<div class="page-header" style="margin:0"><h1 class="page-title">' + this._t('page.findings', 'Findings') + '</h1></div>' +
        '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">' +
          '<button class="btn" data-regex-dismiss-open title="Dismiss multiple findings by regex pattern">' + this._t('findings.pattern', '🗑 Pattern…') + '</button>' +
        '</div>' +
      '</div>';

    // ── individual card (flat mode / dismissed) ──────────────────────
    var renderCard = function(f, isDismissed, isBaseline) {
      var det = f.details || {};
      var cve = det.cve_id ? '<span class="chip">' + det.cve_id + '</span>' : '';
      var portChip = det.port ? '<span class="chip">port ' + det.port + '</span>' : '';
      var detRows = Object.keys(det).filter(function(k) { return k !== 'cve_id' && k !== 'port' && k !== 'remediation'; })
        .map(function(k) { return '<dt>' + k + ':</dt> <dd>' + self._esc(String(det[k])) + '</dd>'; }).join(' ');
      var noteHtml = (isDismissed && f.dismiss_note)
        ? '<div style="margin-top:5px;font-size:11px;color:var(--muted)"><strong>' + self._t('findings.note', 'Note') + ':</strong> ' + self._esc(f.dismiss_note) + '</div>'
        : '';
      var baselineBadge = isBaseline ? '<span class="chip" style="background:#3ac5c9;color:#fff;font-size:10px;margin-left:6px">' + self._t('findings.baseline_badge', 'Baseline') + '</span>' : '';
      return '<div class="finding-card sev-' + f.severity + '"' + (isDismissed ? ' style="opacity:.55"' : '') + '>' +
        '<div class="finding-header">' + self._sev(f.severity) + cve + portChip +
          '<span class="finding-title">' + self._esc(f.summary) + baselineBadge + '</span>' +
          (isDismissed
            ? '<button class="btn" data-undismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Restore finding">' + self._t('findings.restore', 'Restore') + '</button>'
            : '<button class="btn btn-dismiss" data-dismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Dismiss finding">' + self._t('findings.dismiss', 'Dismiss') + '</button>') +
        '</div>' +
        '<div class="finding-meta">' +
          '<span>' + self._t('findings.source', 'Source') + ': <span class="ip">' + f.source_ip + '</span></span>' +
          (det.port ? '<span>' + self._t('findings.port', 'Port') + ': <strong>' + det.port + '</strong></span>' : '') +
          '<span>' + self._t('findings.category', 'Category') + ': ' + self._esc(FINDING_CAT_LABELS[f.category] || f.category || '') + '</span>' +
          (f.count ? '<span>' + f.count + '\u00D7 ' + self._t('findings.seen', 'seen') + '</span>' : '') +
          '<span>' + self._ago(f.last_seen) + '</span>' +
        '</div>' +
        (detRows ? '<div class="finding-detail"><dl>' + detRows + '</dl></div>' : '') +
        (det.remediation ? '<div class="fix-hint">' + self._t('findings.remediation', 'Remediation') + ': ' + self._esc(det.remediation) + '</div>' : '') +
        noteHtml +
      '</div>';
    };

    // ── grouped by summary (security findings + dismissed) ──────────
    var renderGrouped = function(findingsList, isDismissed) {
      if (!findingsList.length) return '';
      var groupMap = {};
      findingsList.forEach(function(f) {
        var gkey = f.summary || f.category || 'Unknown';
        if (!groupMap[gkey]) {
          groupMap[gkey] = { summary: gkey, findings: [], severity: f.severity, category: f.category, isBaseline: !!f._isBaseline };
        } else if (_sevRank(f.severity) < _sevRank(groupMap[gkey].severity)) {
          groupMap[gkey].severity = f.severity;
        }
        groupMap[gkey].findings.push(f);
      });
      return Object.values(groupMap)
        .sort(function(a, b) {
          return _sevRank(a.severity) - _sevRank(b.severity);
        })
        .map(function(g) {
          var isExpanded = self._expandedFindingGroup === g.summary;
          var totalCount = g.findings.reduce(function(s, f) { return s + (f.count || 1); }, 0);
          var latestSeen = g.findings.reduce(function(lat, f) { return (!lat || f.last_seen > lat) ? f.last_seen : lat; }, '');
          var det0 = (g.findings[0] && g.findings[0].details) || {};
          var cve = det0.cve_id ? '<span class="chip">' + det0.cve_id + '</span>' : '';
          var portChip = det0.port ? '<span class="chip">port ' + det0.port + '</span>' : '';
          var countBadge = '<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">' +
            g.findings.length + (g.findings.length === 1 ? ' ' + self._t('findings.host_one', 'host') : ' ' + self._t('findings.host_many', 'hosts')) + '</span>';
          var blBadge = g.isBaseline ? '<span class="chip" style="background:#3ac5c9;color:#fff;font-size:9px">' + self._t('findings.baseline_badge', 'Baseline') + '</span>' : '';
          var chevron = '<span class="finding-group-chevron" style="transform:rotate(' + (isExpanded ? '90' : '0') + 'deg)">\u25B6</span>';
          var groupActionBtn = isDismissed
            ? '<button class="btn" data-undismiss-group="' + self._esc(g.summary) + '">' + self._t('findings.restore', 'Restore') + (g.findings.length > 1 ? ' ' + self._t('findings.restore_all', 'all') + '\u00A0' + g.findings.length : '') + '</button>'
            : '<button class="btn btn-dismiss" data-dismiss-group="' + self._esc(g.summary) + '">' + self._t('findings.dismiss', 'Dismiss') + (g.findings.length > 1 ? ' ' + self._t('findings.dismiss_all', 'all') + '\u00A0' + g.findings.length : '') + '</button>';
          var header = '<div class="finding-card sev-' + g.severity + ' finding-group-card" data-expand-group="' + self._esc(g.summary) + '">' +
            '<div class="finding-header">' + self._sev(g.severity) + cve + portChip + countBadge + blBadge +
              '<span class="finding-title">' + self._esc(g.summary) + '</span>' +
              groupActionBtn + chevron +
            '</div>' +
            '<div class="finding-meta">' +
              '<span>' + self._t('findings.category', 'Category') + ': ' + self._esc(g.category || '\u2014') + '</span>' +
              '<span>' + totalCount + '\u00D7 ' + self._t('findings.total', 'total') + '</span>' +
              '<span>' + self._t('findings.latest', 'Latest:') + ' ' + self._ago(latestSeen) + '</span>' +
            '</div>' +
          '</div>';
          var rows = '';
          if (isExpanded) {
            rows = '<div class="finding-group-rows">' +
              g.findings.map(function(f) {
                var det = f.details || {};
                var detRows = Object.keys(det).filter(function(k) { return k !== 'cve_id' && k !== 'port' && k !== 'remediation'; })
                  .map(function(k) { return '<dt>' + k + ':</dt><dd>' + self._esc(String(det[k])) + '</dd>'; }).join(' ');
                var rowActionBtn = isDismissed
                  ? '<button class="btn" data-undismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Restore this finding">' + self._t('findings.restore', 'Restore') + '</button>'
                  : '<button class="btn btn-dismiss" data-dismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Dismiss this finding">' + self._t('findings.dismiss', 'Dismiss') + '</button>';
                return '<div class="finding-row">' +
                  '<span class="ip">' + self._esc(f.source_ip || '') + '</span>' +
                  (det.port ? '<span class="chip">:' + det.port + '</span>' : '') +
                  '<span class="dim" style="font-size:10px">' + (f.count || 1) + '\u00D7\u00A0\u00B7\u00A0' + self._ago(f.last_seen) + '</span>' +
                  (det.remediation ? '<span style="font-size:10px;color:var(--success);flex:1">' + self._t('hosts.fix', 'Fix') + ': ' + self._esc(det.remediation) + '</span>' : '<span style="flex:1"></span>') +
                  (detRows ? '<div class="finding-detail" style="margin:4px 0;width:100%"><dl>' + detRows + '</dl></div>' : '') +
                  rowActionBtn +
                '</div>';
              }).join('') +
            '</div>';
          }
          return '<div class="finding-group-wrap">' + header + rows + '</div>';
        })
        .join('');
    };

    // ── baseline group renderers ─────────────────────────────────────
    // Shared expand-row builder for host/category groups
    var _baselineExpandRows = function(list) {
      return list.map(function(f) {
        var det = f.details || {};
        return '<div class="finding-row">' +
          self._sev(f.severity) +
          '<span style="flex:1;font-size:12px">' + self._esc(f.summary) + '</span>' +
          (det.port ? '<span class="chip" style="font-size:9px">:' + det.port + '</span>' : '') +
          '<span class="dim" style="font-size:10px;flex-shrink:0">' + self._ago(f.last_seen) + '</span>' +
          '<button class="btn btn-dismiss" data-dismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Dismiss">' + self._t('findings.dismiss', 'Dismiss') + '</button>' +
        '</div>';
      }).join('');
    };

    var renderBaselineByCategory = function(list) {
      if (!list.length) return '';
      var BL_CAT_LABELS = {
        anomaly_new_host: self._t('findings.cat_new_host', 'New Host Detected'),
        anomaly_new_peer: self._t('findings.cat_new_peer', 'New External Peer'),
        anomaly_new_port: self._t('findings.cat_new_port', 'New Open Port'),
        anomaly_new_dns_domain: self._t('findings.cat_new_dns_domain', 'New DNS Domain'),
        anomaly_new_dns_category: self._t('findings.cat_new_dns_category', 'New DNS Category'),
        anomaly_missing_host: self._t('findings.cat_missing_host', 'Known Host Missing'),
        anomaly_missing_peer: self._t('findings.cat_missing_peer', 'Known Peer Missing'),
      };
      var catMap = {};
      list.forEach(function(f) {
        var cat = f.category || 'unknown';
        if (!catMap[cat]) catMap[cat] = { category: cat, findings: [], maxSev: 'info' };
        if (_sevRank(f.severity) < _sevRank(catMap[cat].maxSev)) catMap[cat].maxSev = f.severity;
        catMap[cat].findings.push(f);
      });
      return Object.values(catMap)
        .sort(function(a, b) {
          var sd = _sevRank(a.maxSev) - _sevRank(b.maxSev);
          return sd !== 0 ? sd : a.category.localeCompare(b.category);
        })
        .map(function(c) {
          var gkey = 'bcat:' + c.category;
          var isExpanded = self._expandedBaselineGroup === gkey;
          var latestSeen = c.findings.reduce(function(lat, f) { return (!lat || f.last_seen > lat) ? f.last_seen : lat; }, '');
          var uniqueHosts = {};
          c.findings.forEach(function(f) { uniqueHosts[f.source_ip] = true; });
          var hostCount = Object.keys(uniqueHosts).length;
          var countBadge = '<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">' +
            c.findings.length + ' ' + (c.findings.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')) + ' \u00B7 ' + hostCount + ' ' + (hostCount === 1 ? self._t('findings.host_one', 'host') : self._t('findings.host_many', 'hosts')) + '</span>';
          var chevron = '<span class="finding-group-chevron" style="transform:rotate(' + (isExpanded ? '90' : '0') + 'deg)">\u25B6</span>';
          var dismissAllBtn = '<button class="btn btn-dismiss" data-dismiss-group="' + self._esc(gkey) + '">' + self._t('findings.dismiss_all', 'Dismiss all') + ' ' + c.findings.length + '</button>';
          var header = '<div class="finding-card sev-' + c.maxSev + ' finding-group-card" data-expand-baseline-group="' + self._esc(gkey) + '">' +
            '<div class="finding-header">' + self._sev(c.maxSev) + countBadge +
              '<span class="finding-title">' + self._esc(BL_CAT_LABELS[c.category] || c.category) + '</span>' +
              dismissAllBtn + chevron +
            '</div>' +
            '<div class="finding-meta"><span>' + self._t('findings.latest', 'Latest:') + ' ' + self._ago(latestSeen) + '</span></div>' +
          '</div>';
          var sortedByCategory = c.findings.slice().sort(function(a, b) {
            return _sevRank(a.severity) - _sevRank(b.severity);
          });
          var rows = isExpanded
            ? '<div class="finding-group-rows">' + _baselineExpandRows(sortedByCategory) + '</div>'
            : '';
          return '<div class="finding-group-wrap">' + header + rows + '</div>';
        }).join('');
    };

    var renderBaselineByHost = function(list) {
      if (!list.length) return '';
      var hostMap = {};
      list.forEach(function(f) {
        var ip = f.source_ip || 'unknown';
        if (!hostMap[ip]) hostMap[ip] = { ip: ip, findings: [], maxSev: 'info' };
        if (_sevRank(f.severity) < _sevRank(hostMap[ip].maxSev)) hostMap[ip].maxSev = f.severity;
        hostMap[ip].findings.push(f);
      });
      return Object.values(hostMap)
        .sort(function(a, b) {
          var sd = _sevRank(a.maxSev) - _sevRank(b.maxSev);
          if (sd !== 0) return sd;
          return a.ip.split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.')
            .localeCompare(b.ip.split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.'));
        })
        .map(function(h) {
          var gkey = 'bhost:' + h.ip;
          var isExpanded = self._expandedBaselineGroup === gkey;
          var latestSeen = h.findings.reduce(function(lat, f) { return (!lat || f.last_seen > lat) ? f.last_seen : lat; }, '');
          var catCounts = {};
          h.findings.forEach(function(f) { catCounts[f.category] = (catCounts[f.category] || 0) + 1; });
          var catChips = Object.keys(catCounts).slice(0, 5).map(function(c) {
            return '<span class="chip" style="font-size:9px">' + self._esc(c) + ' (' + catCounts[c] + ')</span>';
          }).join(' ');
          var countBadge = '<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">' +
            h.findings.length + ' ' + (h.findings.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')) + '</span>';
          var chevron = '<span class="finding-group-chevron" style="transform:rotate(' + (isExpanded ? '90' : '0') + 'deg)">\u25B6</span>';
          var dismissAllBtn = '<button class="btn btn-dismiss" data-dismiss-group="' + self._esc(gkey) + '">' + self._t('findings.dismiss_all', 'Dismiss all') + ' ' + h.findings.length + '</button>';
          var header = '<div class="finding-card sev-' + h.maxSev + ' finding-group-card" data-expand-baseline-group="' + self._esc(gkey) + '">' +
            '<div class="finding-header">' + self._sev(h.maxSev) + countBadge +
              '<span class="finding-title" style="font-family:monospace">' + self._esc(h.ip) + '</span>' +
              dismissAllBtn + chevron +
            '</div>' +
            '<div class="finding-meta">' + catChips + '<span style="flex-shrink:0">' + self._t('findings.latest', 'Latest:') + ' ' + self._ago(latestSeen) + '</span></div>' +
          '</div>';
          var rows = isExpanded
            ? '<div class="finding-group-rows">' + _baselineExpandRows(h.findings) + '</div>'
            : '';
          return '<div class="finding-group-wrap">' + header + rows + '</div>';
        }).join('');
    };

    // ── findings group renderers (by category / host / severity) ────
    var _mkFindingGroup = function(gkey, label, sev, itemList, isDismissed) {
      var expandKey = isDismissed ? 'dismissed:' + gkey : gkey;
      var isExpanded = self._expandedFindingGroup === expandKey;
      var totalCount = itemList.reduce(function(s, f) { return s + (f.count || 1); }, 0);
      var latestSeen = itemList.reduce(function(lat, f) { return (!lat || f.last_seen > lat) ? f.last_seen : lat; }, '');
      var countBadge = '<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">' +
        itemList.length + ' ' + (itemList.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')) + '</span>';
      var chevron = '<span class="finding-group-chevron" style="transform:rotate(' + (isExpanded ? '90' : '0') + 'deg)">\u25B6</span>';
      var actionBtn = isDismissed
        ? '<button class="btn" data-undismiss-group="' + self._esc(gkey) + '">' + self._t('findings.restore_all', 'Restore all') + '\u00A0' + itemList.length + '</button>'
        : '<button class="btn btn-dismiss" data-dismiss-group="' + self._esc(gkey) + '">' + self._t('findings.dismiss_all', 'Dismiss all') + '\u00A0' + itemList.length + '</button>';
      var header = '<div class="finding-card sev-' + sev + ' finding-group-card" data-expand-group="' + self._esc(expandKey) + '">' +
        '<div class="finding-header">' + self._sev(sev) + countBadge +
          '<span class="finding-title">' + label + '</span>' +
          actionBtn + chevron +
        '</div>' +
        '<div class="finding-meta">' +
          '<span>' + totalCount + '\u00D7 ' + self._t('findings.total', 'total') + '</span>' +
          '<span>' + self._t('findings.latest', 'Latest:') + ' ' + self._ago(latestSeen) + '</span>' +
        '</div>' +
      '</div>';
      var rows = '';
      if (isExpanded) {
        rows = '<div class="finding-group-rows">' +
          itemList.slice().sort(function(a, b) { return _sevRank(a.severity) - _sevRank(b.severity); })
            .map(function(f) {
              var det = f.details || {};
              var detRows = Object.keys(det).filter(function(k) { return k !== 'cve_id' && k !== 'port' && k !== 'remediation'; })
                .map(function(k) { return '<dt>' + k + ':</dt><dd>' + self._esc(String(det[k])) + '</dd>'; }).join(' ');
              var blBadge = f._isBaseline ? '<span class="chip" style="background:#3ac5c9;color:#fff;font-size:9px">' + self._t('findings.baseline_badge', 'Baseline') + '</span>' : '';
              var rowActionBtn = isDismissed
                ? '<button class="btn" data-undismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '">' + self._t('findings.restore', 'Restore') + '</button>'
                : '<button class="btn btn-dismiss" data-dismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '">' + self._t('findings.dismiss', 'Dismiss') + '</button>';
              return '<div class="finding-row">' +
                self._sev(f.severity) +
                '<span class="ip">' + self._esc(f.source_ip || '') + '</span>' +
                blBadge +
                (det.port ? '<span class="chip">:' + det.port + '</span>' : '') +
                '<span style="flex:1;font-size:11px">' + self._esc(f.summary || f.category || '') + '</span>' +
                '<span class="dim" style="font-size:10px">' + (f.count || 1) + '\u00D7\u00A0\u00B7\u00A0' + self._ago(f.last_seen) + '</span>' +
                (detRows ? '<div class="finding-detail" style="margin:4px 0;width:100%"><dl>' + detRows + '</dl></div>' : '') +
                rowActionBtn +
              '</div>';
            }).join('') +
        '</div>';
      }
      return '<div class="finding-group-wrap">' + header + rows + '</div>';
    };

    var FINDING_CAT_LABELS = {
      vulnerability:   self._t('findings.cat_vulnerability', 'Vulnerability / CVE'),
      port_scan:       self._t('findings.cat_port_scan', 'Port Scan'),
      suspicious_port: self._t('findings.cat_suspicious_port', 'Suspicious Open Port'),
      high_egress:     self._t('findings.cat_high_egress', 'High Egress Traffic'),
    };

    var renderFindingsByCategory = function(list, isDismissed) {
      if (!list.length) return '';
      var catMap = {};
      list.forEach(function(f) {
        var k = f.category || 'unknown';
        if (!catMap[k]) catMap[k] = { sev: f.severity, items: [] };
        else if (_sevRank(f.severity) < _sevRank(catMap[k].sev)) catMap[k].sev = f.severity;
        catMap[k].items.push(f);
      });
      return Object.values(catMap)
        .sort(function(a, b) { return _sevRank(a.sev) - _sevRank(b.sev); })
        .map(function(g) {
          var cat = g.items[0].category || 'unknown';
          var label = self._esc(FINDING_CAT_LABELS[cat] || cat);
          return _mkFindingGroup('fcat:' + cat, label, g.sev, g.items, isDismissed);
        }).join('');
    };

    var renderFindingsByHost = function(list, isDismissed) {
      if (!list.length) return '';
      var hostMap = {};
      list.forEach(function(f) {
        var ip = f.source_ip || 'unknown';
        if (!hostMap[ip]) hostMap[ip] = { sev: f.severity, items: [] };
        else if (_sevRank(f.severity) < _sevRank(hostMap[ip].sev)) hostMap[ip].sev = f.severity;
        hostMap[ip].items.push(f);
      });
      return Object.values(hostMap)
        .sort(function(a, b) {
          var sd = _sevRank(a.sev) - _sevRank(b.sev);
          if (sd !== 0) return sd;
          return a.items[0].source_ip.split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.')
            .localeCompare(b.items[0].source_ip.split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.'));
        })
        .map(function(g) {
          var ip = g.items[0].source_ip || 'unknown';
          var label = '<span style="font-family:monospace">' + self._esc(ip) + '</span>';
          return _mkFindingGroup('fhost:' + ip, label, g.sev, g.items, isDismissed);
        }).join('');
    };

    var SEV_LABELS = { critical: self._t('findings.sev_critical', 'Critical'), high: self._t('findings.sev_high', 'High'), medium: self._t('findings.sev_medium', 'Medium'), low: self._t('findings.sev_low', 'Low'), info: self._t('findings.sev_info', 'Info') };
    var renderFindingsBySeverity = function(list, isDismissed) {
      if (!list.length) return '';
      var sevMap = {};
      list.forEach(function(f) {
        var s = f.severity || 'info';
        if (!sevMap[s]) sevMap[s] = [];
        sevMap[s].push(f);
      });
      return ['critical', 'high', 'medium', 'low', 'info'].filter(function(s) { return sevMap[s]; })
        .map(function(s) {
          return _mkFindingGroup('fsev:' + s, SEV_LABELS[s] || s, s, sevMap[s], isDismissed);
        }).join('');
    };

    var _renderFindingCards = function(list, isDismissed, mode) {
      if (!list.length) return '';
      if (mode === 'host')     return renderFindingsByHost(list, isDismissed);
      if (mode === 'severity') return renderFindingsBySeverity(list, isDismissed);
      if (mode === 'flat')     return list.map(function(f) { return renderCard(f, isDismissed, !!f._isBaseline); }).join('');
      return renderFindingsByCategory(list, isDismissed); // 'category' (default)
    };

    // ── Baseline section ─────────────────────────────────────────────
    var baselineSection = '';
    if (baselineAnomalies.length) {
      var blModeBtn = function(mode, label) {
        var active = baselineGroupMode === mode;
        return '<button class="btn' + (active ? ' active' : '') + '" data-baseline-group-mode="' + mode + '">' + label + '</button>';
      };
      var blSearchInput = '<input type="search" data-baseline-search placeholder="Search + Enter" value="' + self._esc(self._baselineSearch || '') + '" ' +
        'style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none">';
      var blToolbar =
        '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">' +
          blModeBtn('category', self._t('findings.by_category', 'By Category')) +
          blModeBtn('host',     self._t('findings.by_host', 'By Host')) +
          blModeBtn('flat',     self._t('findings.flat', 'Flat')) +
          '<span style="flex:1"></span>' + blSearchInput +
        '</div>';

      var blCards;
      if (baselineGroupMode === 'host')         blCards = renderBaselineByHost(filteredBaseline);
      else if (baselineGroupMode === 'flat')    blCards = filteredBaseline.map(function(f) { return renderCard(f, false, true); }).join('');
      else                                      blCards = renderBaselineByCategory(filteredBaseline);

      var blContent = (baselineQ && !filteredBaseline.length)
        ? '<div class="empty-state card" style="height:100px"><p>' + self._t('findings.no_results', 'No results for') + ' &ldquo;' + self._esc(baselineQ) + '&rdquo;.</p></div>'
        : blCards;

      baselineSection =
        '<div style="margin-bottom:28px">' +
          '<div class="view-header"><h1>' + this._t('findings.baseline', 'Baseline Anomalies') + ' <span class="dim">(' + baselineAnomalies.length +
            (baselineQ && filteredBaseline.length !== baselineAnomalies.length ? ', ' + filteredBaseline.length + ' ' + this._t('findings.shown', 'shown') : '') +
          ')</span></h1></div>' +
          blToolbar + blContent +
        '</div>';
    }

    // ── Security findings section ────────────────────────────────────
    var cards = _renderFindingCards(filteredFindings, false, findingsGroupMode);

    var findingsHeader = findings.length
        ? this._t('findings.security', 'Security Findings') + ' <span class="dim">(' + findings.length + ' ' + this._t('findings.actionable', 'actionable') +
          (findingsQ && filteredFindings.length !== findings.length ? ', ' + filteredFindings.length + ' ' + this._t('findings.shown', 'shown') : '') +
          (allDismissedList.length ? ', ' + allDismissedList.length + ' ' + this._t('findings.dismissed', 'dismissed') : '') + ')</span>'
        : this._t('findings.security', 'Security Findings') + (allDismissedList.length ? ' <span class="dim">(' + allDismissedList.length + ' ' + this._t('findings.dismissed', 'dismissed') + ')</span>' : '');
    var _fModeBtn = function(mode, label) {
      return '<button class="btn' + (findingsGroupMode === mode ? ' active' : '') + '" data-findings-group-mode="' + mode + '" style="font-size:10px;padding:3px 8px">' + label + '</button>';
    };
    var findingsToggle =
      '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">' +
        _fModeBtn('category', this._t('findings.by_category', 'By Category')) +
        _fModeBtn('host',     this._t('findings.by_host', 'By Host')) +
        _fModeBtn('severity', this._t('findings.by_severity', 'By Severity')) +
        _fModeBtn('flat',     this._t('findings.flat', 'Flat')) +
        '<span style="flex:1"></span>' +
        '<input type="search" data-findings-search placeholder="' + self._esc(self._t('common.search_enter', 'Search + Enter')) + '" value="' + self._esc(self._findingsSearch || '') + '" ' +
          'style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none">' +
      '</div>';

    var activeSection = '<div>' +
        '<div class="view-header"><h1>' + findingsHeader + '</h1></div>' +
        findingsToggle +
        (findings.length
          ? (filteredFindings.length
              ? cards
                : '<div class="empty-state card" style="height:100px"><p>' + self._t('findings.no_results', 'No results for') + ' &ldquo;' + self._esc(findingsQ) + '&rdquo;.</p></div>')
              : '<div class="empty-state card" style="height:180px"><div class="empty-icon">\u2713</div><p>' + this._t('findings.no_active', 'No active high or critical findings.') + '</p></div>') +
      '</div>';

    // ── Dismissed section (security + baseline combined) ─────────────
    var dismissedCards = _renderFindingCards(filteredDismissed, true, dismissedGroupMode);
    var _dModeBtn = function(mode, label) {
      return '<button class="btn' + (dismissedGroupMode === mode ? ' active' : '') + '" data-dismissed-group-mode="' + mode + '" style="font-size:10px;padding:3px 8px">' + label + '</button>';
    };
    var dismissedToggle =
      '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">' +
        _dModeBtn('category', this._t('findings.by_category', 'By Category')) +
        _dModeBtn('host',     this._t('findings.by_host', 'By Host')) +
        _dModeBtn('severity', this._t('findings.by_severity', 'By Severity')) +
        _dModeBtn('flat',     this._t('findings.flat', 'Flat')) +
        '<span style="flex:1"></span>' +
        '<input type="search" data-dismissed-search placeholder="' + self._esc(self._t('common.search_enter', 'Search + Enter')) + '" value="' + self._esc(self._dismissedSearch || '') + '" ' +
          'style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none">' +
      '</div>';
    var dismissedSection = allDismissedList.length
      ? '<div style="margin-top:28px;opacity:.7">' +
          '<div class="view-header"><h1>' + this._t('findings.dismissed_title', 'Dismissed') + ' <span class="dim">(' + allDismissedList.length +
            (dismissedQ && filteredDismissed.length !== allDismissedList.length ? ', ' + filteredDismissed.length + ' ' + this._t('findings.shown', 'shown') : '') +
          ')</span></h1></div>' +
          dismissedToggle +
          (filteredDismissed.length
            ? dismissedCards
            : '<div class="empty-state card" style="height:100px"><p>' + self._t('findings.no_results', 'No results for') + ' &ldquo;' + self._esc(dismissedQ) + '&rdquo;.</p></div>') +
        '</div>'
      : '';

    return topBar + baselineSection + activeSection + dismissedSection;
  }

  _extThead() {
    var self = this;
    var cols = [
      { key: 'ip',       label: 'IP' },
      { key: 'hostname', label: this._t('external.col_hostname', 'Hostname') },
      { key: 'traffic_kb', label: this._t('external.col_traffic_kb', 'Traffic (KB)') },
      { key: 'country',  label: this._t('external.col_country', 'Country') },
      { key: 'org',      label: this._t('external.col_asn_org', 'ASN / Org') },
      { key: 'rating',   label: this._t('external.col_rating', 'Rating') },
      { key: 'vt',       label: this._t('external.col_vt_hits', 'VT hits') },
      { key: 'abuse',    label: this._t('external.col_abuse', 'Abuse%') },
      { key: null,        label: this._t('external.col_ports', 'Ports') },
      { key: 'direction',  label: this._t('external.col_direction', 'Direction') },
      { key: null,         label: this._t('external.col_internal_host', 'Internal host') },
      { key: 'last_seen',  label: this._t('external.col_last_seen', 'Last seen') },
    ];
    return '<tr>' + cols.map(function(c) {
      if (!c.key) return '<th>' + c.label + '</th>';
      var arrow = self._extSort === c.key ? (self._extSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
      return '<th class="sortable-th" data-extsort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
    }).join('') + '</tr>';
  }

  _extPreparedList() {
    var q = this._extFilter.toLowerCase();
    var sortKey = this._extSort;
    var sortDir = this._extSortDir;
    var extIPs = ((this._data && this._data.external_ips) || []).slice();
    if (q) {
      extIPs = extIPs.filter(function(e) {
        return (e.ip || '').indexOf(q) >= 0 ||
          (e.hostname || '').toLowerCase().indexOf(q) >= 0 ||
          (e.country_name || e.country || '').toLowerCase().indexOf(q) >= 0 ||
          (e.org || e.asn || '').toLowerCase().indexOf(q) >= 0 ||
          (e.rating || '').toLowerCase().indexOf(q) >= 0 ||
          (e.direction || '').toLowerCase().indexOf(q) >= 0 ||
          (e.internal_sources || []).some(function(s) { return s.indexOf(q) >= 0; }) ||
          (e.dst_ports || []).some(function(p) { return String(p).indexOf(q) >= 0; });
      });
    }
    extIPs.sort(function(a, b) {
      var va, vb;
      if (sortKey === 'ip') {
        va = (a.ip || '').split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.');
        vb = (b.ip || '').split('.').map(function(n) { return ('000' + n).slice(-3); }).join('.');
      } else if (sortKey === 'hostname') {
        va = (a.hostname || '').toLowerCase();
        vb = (b.hostname || '').toLowerCase();
      } else if (sortKey === 'traffic_kb') {
        va = (a.total_octets || 0);
        vb = (b.total_octets || 0);
        return (va - vb) * sortDir;
      } else if (sortKey === 'country') {
        va = (a.country_name || a.country || '').toLowerCase();
        vb = (b.country_name || b.country || '').toLowerCase();
      } else if (sortKey === 'org') {
        va = (a.org || a.asn || '').toLowerCase();
        vb = (b.org || b.asn || '').toLowerCase();
      } else if (sortKey === 'rating') {
        var rOrder = { malicious: 0, suspicious: 1, clean: 2, '': 3 };
        va = rOrder[a.rating || (a.blacklisted ? 'malicious' : '')] !== undefined ? rOrder[a.rating || (a.blacklisted ? 'malicious' : '')] : 3;
        vb = rOrder[b.rating || (b.blacklisted ? 'malicious' : '')] !== undefined ? rOrder[b.rating || (b.blacklisted ? 'malicious' : '')] : 3;
        return (va - vb) * sortDir;
      } else if (sortKey === 'vt') {
        va = (a.vt_malicious || 0) + (a.vt_suspicious || 0) * 0.1;
        vb = (b.vt_malicious || 0) + (b.vt_suspicious || 0) * 0.1;
        return (va - vb) * sortDir;
      } else if (sortKey === 'abuse') {
        va = a.abuse_confidence != null ? a.abuse_confidence : -1;
        vb = b.abuse_confidence != null ? b.abuse_confidence : -1;
        return (va - vb) * sortDir;
      } else if (sortKey === 'direction') {
        var dOrder = { outbound: 0, inbound: 1, both: 2 };
        va = dOrder[a.direction || 'outbound'] !== undefined ? dOrder[a.direction || 'outbound'] : 0;
        vb = dOrder[b.direction || 'outbound'] !== undefined ? dOrder[b.direction || 'outbound'] : 0;
        return (va - vb) * sortDir;
      } else if (sortKey === 'last_seen') {
        va = a.last_seen || '';
        vb = b.last_seen || '';
      } else {
        return 0;
      }
      if (va < vb) return -1 * sortDir;
      if (va > vb) return 1 * sortDir;
      return 0;
    });
    return extIPs;
  }

  _extPageBar() {
    var total = this._extPreparedList().length;
    var totalPages = Math.max(1, Math.ceil(total / this._extPageSize));
    var page = Math.min(this._extPage, totalPages);
    var start = total === 0 ? 0 : ((page - 1) * this._extPageSize + 1);
    var end = Math.min(total, page * this._extPageSize);
    return '<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap">' +
      '<div class="row-gap" style="font-size:11px;color:var(--muted)">' + this._t('external.showing', 'Showing') + ' ' + start + '-' + end + ' of ' + total + '</div>' +
      '<div class="row-gap" style="gap:6px">' +
        '<label class="dim" style="font-size:11px">' + this._t('common.rows', 'Rows') + '</label>' +
        '<select id="hsa-ext-pagesize" class="role-select">' +
          [10,25,50,100].map((n) => '<option value="' + n + '"' + (n === this._extPageSize ? ' selected' : '') + '>' + n + '</option>').join('') +
        '</select>' +
        '<button class="btn" data-extpage="prev"' + (page <= 1 ? ' disabled' : '') + '>' + this._t('common.previous', 'Previous') + '</button>' +
        '<span class="dim" style="font-size:11px;min-width:70px;text-align:center">' + page + ' / ' + totalPages + '</span>' +
        '<button class="btn" data-extpage="next"' + (page >= totalPages ? ' disabled' : '') + '>' + this._t('common.next', 'Next') + '</button>' +
      '</div>' +
    '</div>';
  }

  _extRows() {
    var extIPs = this._extPreparedList();
    var totalPages = Math.max(1, Math.ceil(extIPs.length / this._extPageSize));
    this._extPage = Math.min(Math.max(1, this._extPage), totalPages);
    var start = (this._extPage - 1) * this._extPageSize;
    extIPs = extIPs.slice(start, start + this._extPageSize);
    if (!extIPs.length) return '<tr><td colspan="12"><div class="empty-state"><div class="empty-icon">\uD83D\uDD0D</div><p>' + this._t('external.no_match', 'No external IPs match the filter') + '</p></div></td></tr>';
    var self = this;
    return extIPs.map(function(e) {
      var rating = e.rating || (e.blacklisted ? 'malicious' : '');
      var vt = e.vt_malicious != null
        ? (e.vt_malicious + '/' + ((e.vt_malicious||0)+(e.vt_suspicious||0)+(e.vt_harmless||0)))
        : '\u2014';
      var abuse = e.abuse_confidence != null ? e.abuse_confidence + '%' : '\u2014';
      var trafficKb = ((e.total_octets || 0) / 1024).toFixed(1);
      var host  = e.hostname || '';
      var dstPorts = (e.dst_ports || []).slice(0, 8);
      var portsHtml = dstPorts.length
        ? dstPorts.map(function(p) { return '<span class="chip">' + p + '</span>'; }).join(' ') + (e.dst_ports.length > 8 ? ' <span class="dim">+' + (e.dst_ports.length - 8) + '</span>' : '')
        : '<span class="dim">\u2014</span>';
      var dir = e.direction || 'outbound';
      var directionHtml = dir === 'both'
        ? '<span style="color:#a78bfa;font-size:11px">' + self._t('external.direction_both', '↕ Both') +
            (e.direction_alert
              ? ' <span title="Different internal hosts involved in each direction \u2014 an external IP contacted a server that did not initiate the outbound relationship. Review recommended." style="cursor:help;color:#f59e0b">\u26A0</span>'
              : '') +
            '</span>'
        : dir === 'inbound'
          ? '<span style="color:#fb923c;font-size:11px">' + self._t('external.direction_inbound', '↓ Inbound') + '</span>'
          : '<span style="color:#34d399;font-size:11px">' + self._t('external.direction_outbound', '↑ Outbound') + '</span>';
      var sources = e.internal_sources || e.sources || [];
      var sourcesHtml = sources.length
        ? sources.map(function(s) { return '<span class="ip-chip">' + s + '</span>'; }).join(' ')
        : '<span class="dim">\u2014</span>';
      var ratingHtml = rating ? self._ratingWithSource(rating, e.rating_source) : '<span class="dim">\u2014</span>';
      var countryFlag = self._countryFlag(e.country);
      var countryTitle = e.country_name || e.country || '';
      return '<tr style="cursor:pointer" data-ext-ip-row="' + self._esc(e.ip) + '">' +
        '<td>' + (e.blacklisted ? '<span style="color:#ff4d6d;margin-right:3px">\u26A0</span>' : '') + '<span class="ip">' + e.ip + '</span></td>' +
        '<td style="font-size:11px">' + (host ? self._esc(host) : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-family:monospace;font-size:11px;text-align:right">' + trafficKb + '</td>' +
        '<td style="font-size:11px">' + (countryFlag ? '<span title="' + self._esc(countryTitle) + '" style="font-size:15px;line-height:1">' + countryFlag + '</span>' : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-size:11px">' + self._esc(((e.org||'').substring(0,30))||e.asn||'\u2014') + '</td>' +
        '<td>' + ratingHtml + '</td>' +
        '<td style="font-family:monospace;font-size:11px">' + vt + '</td>' +
        '<td style="font-family:monospace;font-size:11px">' + abuse + '</td>' +
        '<td style="font-size:11px">' + portsHtml + '</td>' +
        '<td style="font-size:11px">' + directionHtml + '</td>' +
        '<td style="font-size:11px">' + sourcesHtml + '</td>' +
        '<td style="font-size:10px;color:var(--muted)">' + self._ago(e.last_seen) + '</td></tr>';
    }).join('');
  }

  _viewExternal() {
    var totalCount = ((this._data && this._data.external_ips) || []).length;
    return '<div>' +
      '<div class="view-header"><h1>' + this._t('external.page_title', 'External IPs') + ' <span class="dim">(' + totalCount + ')</span></h1>' +
      '<input id="hsa-ext-filter" class="search-bar" type="search" placeholder="' + this._esc(this._t('external.filter_placeholder', 'Filter by IP, hostname, country, org…')) + '" value="' + this._esc(this._extFilter) + '"></div>' +
      '<div id="hsa-ext-pagebar">' + this._extPageBar() + '</div>' +
      '<div class="card table-card"><table class="data-table">' +
        '<thead id="hsa-ext-thead">' + this._extThead() + '</thead>' +
        '<tbody id="hsa-ext-tbody">' + this._extRows() + '</tbody>' +
      '</table></div></div>';
  }

  _ipDetail(d, internalSources, direction) {
    var ip = d.ip || '';
    var self = this;
    var reportLinks = ip ? [
      ['ipwho.is', 'https://ipwho.is/' + encodeURIComponent(ip)],
      ['AbuseIPDB', 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip)],
      ['VirusTotal', 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip)],
    ] : [];
    var pairs = [
      [this._t('external.modal_hostname', 'Hostname'),   d.hostname],
      [this._t('external.modal_country', 'Country'),    d.country_name || d.country],
      [this._t('external.modal_asn', 'ASN'),        d.asn],
      [this._t('external.modal_org_isp', 'ISP / Org'),  d.org || d.isp],
      [this._t('external.modal_city', 'City'),       d.city],
      [this._t('external.modal_timezone', 'Timezone'),   d.timezone],
      [this._t('external.modal_vt', 'VirusTotal'), d.vt_malicious != null ? d.vt_malicious + ' ' + self._t('external.modal_malicious', 'malicious') + ', ' + d.vt_suspicious + ' ' + self._t('external.modal_suspicious', 'suspicious') + ', ' + d.vt_harmless + ' ' + self._t('external.modal_harmless', 'harmless') : null],
      [this._t('external.modal_vt_rep', 'VT Reputation'), d.vt_reputation != null ? String(d.vt_reputation) : null],
      [this._t('external.modal_abuse', 'Abuse score'),  d.abuse_confidence != null ? d.abuse_confidence + '% (' + d.abuse_total_reports + ' ' + self._t('external.modal_reports', 'reports') + ')' : null],
      [this._t('external.modal_rating_source', 'Rating source'), d.rating_source || null],
      [this._t('external.blacklisted', 'Blacklisted'),  d.blacklisted ? self._t('external.modal_yes', 'Yes') + ' \u2013 ' + ((d.blacklist_info && d.blacklist_info.source) || 'threat_intel') : self._t('external.modal_no', 'No')],
      [this._t('external.modal_direction', 'Direction'),    (function(dir) { return dir.charAt(0).toUpperCase() + dir.slice(1); })(direction || d.direction || 'outbound')],
      [this._t('external.modal_data_sources', 'Data sources'), (d.sources && d.sources.join(', ')) || '\u2014'],
      [this._t('external.modal_enriched_at', 'Enriched at'),  d.enriched_at ? this._ago(d.enriched_at) : null],
    ].filter(function(p) { return p[1] != null && p[1] !== ''; });
    var pairsHtml = pairs.map(function(p) {
      return '<div class="detail-pair"><span class="detail-key">' + p[0] + '</span><span class="detail-val">' + self._esc(String(p[1])) + '</span></div>';
    }).join('');
    var linksHtml = reportLinks.length
      ? '<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">' + this._t('external.modal_reports', 'Reports') + '</span><span class="detail-val">' +
          reportLinks.map(function(item) {
            return '<a class="ext-report-link" href="' + item[1] + '" target="_blank" rel="noopener noreferrer">' + self._esc(item[0]) + '</a>';
          }).join(' ') +
        '</span></div>'
      : '';
    var sources = internalSources || d.internal_sources || [];
    var sourcesHtml = sources.length
      ? '<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">' + this._t('external.modal_internal_host', 'Internal host') + '</span><span class="detail-val">'+
          sources.map(function(s) { return '<span class="ip-chip">' + s + '</span>'; }).join(' ') +
        '</span></div>'
      : '';

    return '<div class="ip-detail-panel"><h3>\uD83D\uDD0D ' + d.ip + ' ' + (d.rating ? this._rating(d.rating) : '') + '</h3>' +
      '<div class="detail-grid">' + pairsHtml + linksHtml + sourcesHtml + '</div>' +
        (d.error ? '<div style="color:var(--danger);margin-top:8px;font-size:11px">\u26A0 ' + this._t('external.modal_error', 'Enrichment error:') + ' ' + this._esc(d.error) + '</div>' : '') +
      '</div>';
  }

  async _doLookup(ip) {
    if (this._lookingUp) return;
    this._lookupIP     = ip;
    this._lookingUp    = true;
    this._lookupResult = null;
    this._render();
    try {
      this._lookupResult = await this._hass.callApi('GET', 'homesec/lookup?ip=' + encodeURIComponent(ip));
    } catch (e) {
      this._lookupResult = { ip: ip, error: e.message };
    } finally {
      this._lookingUp = false;
      this._render();
    }
  }

  _viewVulns() {
    var self = this;
    // Trigger async fetch on first visit or when stale
    if (!this._vulnData && !this._vulnLoading) {
      this._vulnLoading = true;
      this._hass.callApi('GET', 'homesec/vulnerabilities').then(function(d) {
        self._vulnData = d;
        self._vulnLoading = false;
        self._render();
      }).catch(function() {
        self._vulnLoading = false;
        self._vulnData = { vulnerabilities: [], total: 0, detected_cves: 0, kev_matches: 0, kev_total: 0 };
        self._render();
      });
      return '<div><div class="view-header"><h1>' + this._t('vuln.page_title', 'Vulnerability Browser') + '</h1></div>' +
        '<div class="state-box"><div class="loader"></div><p>' + this._t('vuln.loading', 'Loading vulnerabilities…') + '</p></div></div>';
    }
    if (this._vulnLoading) {
      return '<div><div class="view-header"><h1>' + this._t('vuln.page_title', 'Vulnerability Browser') + '</h1></div>' +
        '<div class="state-box"><div class="loader"></div><p>' + this._t('vuln.loading', 'Loading vulnerabilities…') + '</p></div></div>';
    }
    var d = this._vulnData || { vulnerabilities: [], total: 0, detected_cves: 0, kev_matches: 0, kev_total: 0 };
    var allVulns = d.vulnerabilities || [];
    var q = this._vulnFilter.toLowerCase().trim();
    var filtered = allVulns;
    if (q) {
      filtered = allVulns.filter(function(v) {
        return (v.cve_id || '').toLowerCase().indexOf(q) !== -1 ||
          (v.summary || '').toLowerCase().indexOf(q) !== -1 ||
          (v.severity || '').toLowerCase().indexOf(q) !== -1 ||
          (v.services || []).some(function(s) { return s.toLowerCase().indexOf(q) !== -1; }) ||
          (v.ports || []).some(function(p) { return String(p).indexOf(q) !== -1; }) ||
          (v.cpe_criteria || []).some(function(c) { return c.toLowerCase().indexOf(q) !== -1; }) ||
          (v.affected_hosts || []).some(function(h) { return h.indexOf(q) !== -1; }) ||
          (v.kev_vendor || '').toLowerCase().indexOf(q) !== -1 ||
          (v.kev_product || '').toLowerCase().indexOf(q) !== -1;
      });
    }
    // Sort
    var sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
    var sortKey = this._vulnSort;
    var sortDir = this._vulnSortDir;
    filtered = filtered.slice().sort(function(a, b) {
      var av, bv;
      if (sortKey === 'cvss') { av = a.cvss || 0; bv = b.cvss || 0; }
      else if (sortKey === 'severity') { av = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 99; bv = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 99; }
      else if (sortKey === 'published') { av = a.published || ''; bv = b.published || ''; }
      else if (sortKey === 'cve_id') { av = a.cve_id || ''; bv = b.cve_id || ''; }
      else if (sortKey === 'hosts') { av = (a.affected_hosts || []).length; bv = (b.affected_hosts || []).length; }
      else if (sortKey === 'kev') { av = a.in_kev ? 1 : 0; bv = b.in_kev ? 1 : 0; }
      else if (sortKey === 'services') { av = (a.services || []).join(','); bv = (b.services || []).join(','); }
      else if (sortKey === 'ports') { av = (a.ports || []).length; bv = (b.ports || []).length; }
      else { av = a.cve_id || ''; bv = b.cve_id || ''; }
      if (av < bv) return -sortDir;
      if (av > bv) return sortDir;
      return 0;
    });
    var total = filtered.length;
    var pages = Math.max(1, Math.ceil(total / this._vulnPageSize));
    if (this._vulnPage > pages) this._vulnPage = pages;
    var start = (this._vulnPage - 1) * this._vulnPageSize;
    var page = filtered.slice(start, start + this._vulnPageSize);

    function sevClass(cvss) {
      if (cvss >= 9) return 'critical';
      if (cvss >= 7) return 'high';
      if (cvss >= 4) return 'medium';
      return 'low';
    }

    var html = '<div>' +
      '<div class="view-header">' +
        '<h1>' + this._t('vuln.page_title', 'Vulnerability Browser') + '</h1>' +
        '<div class="row-gap">' +
          '<input class="search-bar" type="text" placeholder="' + self._esc(this._t('vuln.search_placeholder', 'Search CVE, port, service, CPE, keyword…')) + '" value="' + self._esc(this._vulnFilter) + '" data-vuln-search />' +
          '<button class="btn" data-vuln-refresh>' + this._t('vuln.refresh', '↻ Refresh') + '</button>' +
        '</div>' +
      '</div>' +
      '<div class="tldr-bar">' +
        '<span><strong>' + d.total + '</strong> ' + this._t('vuln.stat_cves_db', 'CVEs in database') + '</span>' +
        '<span><strong>' + (d.detected_cves || 0) + '</strong> ' + this._t('vuln.stat_detected_network', 'detected on network') + '</span>' +
        '<span><strong>' + d.kev_matches + '</strong> ' + this._t('vuln.stat_in_kev', 'in CISA KEV') + '</span>' +
        '<span><strong>' + total + '</strong> ' + this._t('vuln.stat_matching', 'matching results') + '</span>' +
      '</div>' +
      '<div class="card table-card">' +
        '<table class="data-table">' +
          '<thead><tr>' +
            (function() {
              var cols = [
                {key:'cve_id', label:self._t('vuln.col_cve_id', 'CVE ID')},
                {key:'published', label:self._t('vuln.col_published', 'Published')},
                {key:'cvss', label:self._t('vuln.col_cvss', 'CVSS')},
                {key:'severity', label:self._t('vuln.col_severity', 'Severity')},
                {key:'services', label:self._t('vuln.col_services', 'Services')},
                {key:'ports', label:self._t('vuln.col_ports', 'Ports')},
                {key:'hosts', label:self._t('vuln.col_hosts', 'Hosts')},
                {key:'kev', label:'KEV'},
              ];
              return cols.map(function(c) {
                var arrow = self._vulnSort === c.key ? (self._vulnSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
                return '<th class="sortable-th" data-vulnsort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
              }).join('') + '<th style="min-width:320px">' + self._t('vuln.col_summary', 'Summary') + '</th>';
            })() +
          '</tr></thead><tbody>';

    page.forEach(function(v) {
      var cid = self._esc(v.cve_id || '');
      var cvss = v.cvss || 0;
      var sc = sevClass(cvss);
      var kevBadge = v.in_kev ? '<span class="badge badge-critical" title="CISA Known Exploited Vulnerability">KEV</span>' : '';
      var services = (v.services || []).map(function(s) { return '<span class="chip">' + self._esc(s) + '</span>'; }).join('') || '\u2014';
      var ports = (v.ports || []).map(function(p) { return '<span class="chip">' + p + '</span>'; }).join('') || '\u2014';
      var hosts = (v.affected_hosts || []).length;
      var hostsStr = hosts > 0 ? '<span class="ip-chip">' + hosts + ' host' + (hosts > 1 ? 's' : '') + '</span>' : '<span class="dim" style="font-size:10px">' + self._t('vuln.not_detected', 'not detected') + '</span>';
      var summary = self._esc((v.summary || '').substring(0, 200));
      if ((v.summary || '').length > 200) summary += '\u2026';
      var cveBtn = cid ? '<a class="ext-report-link" style="cursor:pointer" data-vuln-detail="' + cid + '" title="View details">' + cid + '</a>' : cid;
      var published = v.published || '\u2014';
      html += '<tr>' +
        '<td>' + cveBtn + '</td>' +
        '<td style="font-size:10px;color:var(--muted);white-space:nowrap">' + published + '</td>' +
        '<td><span class="badge badge-' + sc + '">' + cvss.toFixed(1) + '</span></td>' +
        '<td>' + self._sev(v.severity || sc) + '</td>' +
        '<td>' + services + '</td>' +
        '<td>' + ports + '</td>' +
        '<td>' + hostsStr + '</td>' +
        '<td>' + kevBadge + '</td>' +
        '<td style="font-size:11px;color:var(--muted)">' + summary + '</td>' +
      '</tr>';
    });

    html += '</tbody></table></div>';

    // Pagination
    if (pages > 1) {
      html += '<div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-top:12px">';
      html += '<button class="btn" data-vuln-page="' + Math.max(1, this._vulnPage - 1) + '"' + (this._vulnPage <= 1 ? ' disabled' : '') + '>' + this._t('vuln.prev', '◀ Prev') + '</button>';
      html += '<span class="dim" style="font-size:12px">' + this._t('vuln.page', 'Page') + ' ' + this._vulnPage + ' ' + this._t('vuln.of', 'of') + ' ' + pages + '</span>';
      html += '<button class="btn" data-vuln-page="' + Math.min(pages, this._vulnPage + 1) + '"' + (this._vulnPage >= pages ? ' disabled' : '') + '>' + this._t('vuln.next', 'Next ▶') + '</button>';
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  _openVulnDetail(cveId) {
    if (!this._vulnData || !cveId) return;
    var v = (this._vulnData.vulnerabilities || []).find(function(x) { return x.cve_id === cveId; });
    if (!v) return;
    this._vulnDetail = v;
    this._render();
  }

  _vulnDetailModal() {
    var v = this._vulnDetail;
    if (!v) return '';
    var self = this;
    var cid = this._esc(v.cve_id || '');
    var cvss = v.cvss || 0;
    function sevClass(c) { return c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : 'low'; }
    var sc = sevClass(cvss);
    var services = (v.services || []).map(function(s) { return '<span class="chip">' + self._esc(s) + '</span>'; }).join(' ') || '\u2014';
    var ports = (v.ports || []).map(function(p) { return '<span class="chip">' + p + '</span>'; }).join(' ') || '\u2014';
    var hosts = (v.affected_hosts || []).map(function(h) { return '<span class="ip-chip">' + h + '</span>'; }).join(' ') || '<span class="dim">' + this._t('vuln.not_detected_network', 'Not detected on this network') + '</span>';
    var cpes = (v.cpe_criteria || []).slice(0, 10).map(function(c) { return '<div class="mono" style="font-size:10px;color:var(--muted);word-break:break-all">' + self._esc(c) + '</div>'; }).join('');
    if ((v.cpe_criteria || []).length > 10) cpes += '<div class="dim" style="font-size:10px">+' + (v.cpe_criteria.length - 10) + ' more</div>';
    if (!cpes) cpes = '<span class="dim">\u2014</span>';

    var kevSection = '';
    if (v.in_kev) {
      kevSection = '<div style="margin-top:12px;padding:10px;border-radius:8px;background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25)">' +
        '<div style="font-size:11px;font-weight:700;color:#ff4d6d;margin-bottom:6px">\u26A0 ' + this._t('vuln.kev_title', 'CISA Known Exploited Vulnerability') + '</div>' +
        (v.kev_name ? '<div style="font-size:11px;margin-bottom:4px"><strong>' + this._t('vuln.name', 'Name') + ':</strong> ' + self._esc(v.kev_name) + '</div>' : '') +
        (v.kev_vendor || v.kev_product ? '<div style="font-size:11px;margin-bottom:4px"><strong>' + this._t('vuln.product', 'Product') + ':</strong> ' + self._esc((v.kev_vendor || '') + (v.kev_vendor && v.kev_product ? ' / ' : '') + (v.kev_product || '')) + '</div>' : '') +
        (v.kev_date_added ? '<div style="font-size:11px;margin-bottom:4px"><strong>' + this._t('vuln.added_to_kev', 'Added to KEV') + ':</strong> ' + self._esc(v.kev_date_added) + '</div>' : '') +
        (v.kev_action ? '<div style="font-size:11px"><strong>' + this._t('vuln.required_action', 'Required action') + ':</strong> ' + self._esc(v.kev_action) + '</div>' : '') +
      '</div>';
    }

    return '<div id="hsa-vuln-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.68);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px" data-vuln-close="1">' +
      '<div class="card" style="width:min(680px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(98,232,255,.26)">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">' +
          '<h1 style="font-size:16px;color:var(--accent)">' + cid + '</h1>' +
          '<button class="btn" data-vuln-close="1">\u2715 ' + this._t('common.close', 'Close') + '</button>' +
        '</div>' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">' +
          '<span class="badge badge-' + sc + '" style="font-size:12px;padding:3px 10px">CVSS ' + cvss.toFixed(1) + '</span>' +
          this._sev(v.severity || sc) +
          (v.published ? '<span class="dim" style="font-size:11px">' + this._t('vuln.col_published', 'Published') + ': ' + self._esc(v.published) + '</span>' : '') +
          (v.in_kev ? '<span class="badge badge-critical">KEV</span>' : '') +
        '</div>' +
        '<div class="card-title">' + this._t('vuln.summary_title', 'Summary') + '</div>' +
        '<div style="font-size:12px;line-height:1.6;color:var(--text);margin-bottom:14px">' + this._esc(v.summary || this._t('vuln.no_description', 'No description available.')) + '</div>' +
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">' +
          '<div><div class="card-title">' + this._t('vuln.col_services', 'Services') + '</div><div>' + services + '</div></div>' +
          '<div><div class="card-title">' + this._t('vuln.col_ports', 'Ports') + '</div><div>' + ports + '</div></div>' +
        '</div>' +
        '<div class="card-title">' + this._t('vuln.affected_hosts', 'Affected Hosts') + '</div>' +
        '<div style="margin-bottom:14px;font-size:12px">' + hosts + '</div>' +
        '<div class="card-title">' + this._t('vuln.cpe_criteria', 'CPE Criteria') + '</div>' +
        '<div style="margin-bottom:14px">' + cpes + '</div>' +
        kevSection +
        '<div style="margin-top:14px;display:flex;gap:8px">' +
          '<a href="https://nvd.nist.gov/vuln/detail/' + cid + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">' + this._t('vuln.view_on_nvd', 'View on NVD') + '</a>' +
          '<a href="https://www.cvedetails.com/cve/' + cid + '/" target="_blank" rel="noopener noreferrer" class="ext-report-link">' + this._t('vuln.cve_details', 'CVE Details') + '</a>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  _suricataAlertDetailModal() {
    var a = this._suricataAlertDetail;
    if (!a) return '';
    var self = this;
    var SEV_COLORS = { 1:'rgba(255,77,109,1)', 2:'rgba(255,179,71,1)', 3:'rgba(107,255,200,1)' };
    var SEV_LABELS = { 1:this._t('suricata.sev_critical', 'Critical'), 2:this._t('suricata.sev_major', 'Major'), 3:this._t('suricata.sev_minor', 'Minor') };
    var sev = parseInt(a.severity) || 3;
    var sevColor = SEV_COLORS[sev] || 'rgba(90,106,128,1)';
    var sevLabel = SEV_LABELS[sev] || this._t('suricata.sev_unknown', 'Unknown');
    var sevBadge = '<span style="display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;background:' +
      sevColor.replace(',1)',',0.18)') + ';color:' + sevColor + ';border:1px solid ' + sevColor.replace(',1)',',0.4)') + '">' + sevLabel + '</span>';
    var action = (a.action || 'allowed').toLowerCase();
    var actionBadge = action === 'blocked'
      ? '<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">' + this._t('suricata.badge_blocked', '🚫 Blocked') + '</span>'
      : '<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">' + this._t('suricata.badge_allowed', '✓ Allowed') + '</span>';

    // Source host lookup
    var allHosts = (this._data && this._data.devices) || [];
    var srcHost = allHosts.find(function(h) { return h.ip === a.src_ip; });
    var destHost = allHosts.find(function(h) { return h.ip === a.dest_ip; });
    function hostInfo(h) {
      if (!h) return '<span class="dim">\u2014</span>';
      var parts = [];
      if (h.hostname) parts.push('<b>' + self._esc(h.hostname) + '</b>');
      if (h.vendor) parts.push(self._esc(h.vendor));
      if (h.os) parts.push(self._esc(h.os));
      return parts.join(' \u00B7 ') || '<span class="dim">\u2014</span>';
    }

    // Signature ID and rule links
    var sigId = a.signature_id;
    var sigLinks = '';
    if (sigId) {
      // Emerging Threats rules (SIDs typically 2000000+)
      var etLink = '<a href="https://doc.emergingthreats.net/bin/view/Main/SidFAQ?topic=' + sigId + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">Emerging Threats</a>';
      // Snort rule docs
      var snortLink = '<a href="https://www.snort.org/rule_docs/' + sigId + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">Snort Rule Docs</a>';
      // Generic search
      var searchLink = '<a href="https://www.google.com/search?q=suricata+rule+sid+' + sigId + '+' + encodeURIComponent(a.signature || '') + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">Search</a>';
      sigLinks = '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">' + etLink + snortLink + searchLink + '</div>';
    } else if (a.signature) {
      var searchLink2 = '<a href="https://www.google.com/search?q=suricata+alert+' + encodeURIComponent(a.signature) + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">Search rule</a>';
      sigLinks = '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">' + searchLink2 + '</div>';
    }

    function row(label, value) {
      return '<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05)">' +
        '<span style="font-size:11px;color:var(--muted);min-width:110px;flex-shrink:0">' + label + '</span>' +
        '<span style="font-size:12px;color:var(--fg);word-break:break-all">' + value + '</span>' +
      '</div>';
    }

    var ts = a.timestamp ? new Date(a.timestamp).toLocaleString() : '\u2014';
    var srcPort = a.src_port ? ':' + a.src_port : '';
    var destPort = a.dest_port ? ':' + a.dest_port : '';
    var flow = '<span class="mono" style="font-size:12px">' + self._esc((a.src_ip || '\u2014') + srcPort) + '</span>' +
      ' <span style="color:var(--muted)">\u2192</span> ' +
      '<span class="mono" style="font-size:12px">' + self._esc((a.dest_ip || '\u2014') + destPort) + '</span>';
    var proto = [a.proto, a.app_proto].filter(Boolean).map(function(p) {
      return '<span class="chip">' + self._esc(p) + '</span>';
    }).join(' ');

    return '<div id="hsa-suricata-detail-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px" data-suricata-close="1">' +
      '<div class="card" style="width:min(660px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(255,77,109,.26)">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">' +
          '<h1 style="font-size:15px;color:var(--accent);margin:0">' + this._t('suricata.detail_title', 'Alert Detail') + '</h1>' +
          '<button class="btn" data-suricata-close="1">\u2715 ' + this._t('common.close', 'Close') + '</button>' +
        '</div>' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">' +
          sevBadge + ' ' + actionBadge +
          (sigId ? '<span class="dim" style="font-size:11px">SID\u00a0' + sigId + '</span>' : '') +
        '</div>' +
        '<div class="card-title" style="margin-bottom:6px">' + this._t('suricata.alert_info', 'Alert Info') + '</div>' +
        row(this._t('suricata.timestamp', 'Timestamp'), self._esc(ts)) +
        row(this._t('suricata.flow', 'Flow'), flow) +
        row(this._t('suricata.protocol', 'Protocol'), proto || '\u2014') +
        row(this._t('suricata.interface', 'Interface'), self._esc(a.in_iface || '\u2014')) +
        row('Signature', '<span style="font-weight:600">' + self._esc(a.signature || '\u2014') + '</span>') +
        (sigId ? row(this._t('suricata.signature_id', 'Signature ID'), String(sigId)) : '') +
        row(this._t('suricata.col_category', 'Category'), self._esc(a.category || '\u2014')) +
        row(this._t('suricata.col_severity', 'Severity'), sevBadge) +
        row(this._t('suricata.col_action', 'Action'), actionBadge) +
        (a.flow_id ? row('Flow ID', self._esc(String(a.flow_id))) : '') +
        '<div class="card-title" style="margin-top:14px;margin-bottom:6px">' + this._t('suricata.source_host', 'Source Host') + '</div>' +
        row('IP', '<span class="mono">' + self._esc(a.src_ip || '\u2014') + '</span>') +
        row(this._t('suricata.host_info', 'Host info'), hostInfo(srcHost)) +
        '<div class="card-title" style="margin-top:14px;margin-bottom:6px">' + this._t('suricata.destination_host', 'Destination Host') + '</div>' +
        row('IP', '<span class="mono">' + self._esc(a.dest_ip || '\u2014') + '</span>') +
        row(this._t('suricata.host_info', 'Host info'), hostInfo(destHost)) +
        sigLinks +
      '</div>' +
    '</div>';
  }

  _extIPDetailModal() {
    var e = this._extIPDetail;
    if (!e) return '';
    var self = this;
    var ip = e.ip || '';
    var isLooking = self._lookupIP === ip && self._lookingUp;
    var enriched = (self._lookupResult && self._lookupIP === ip) ? self._lookupResult : null;

    function row(label, value) {
      return '<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05)">' +
        '<span style="font-size:11px;color:var(--muted);min-width:120px;flex-shrink:0">' + label + '</span>' +
        '<span style="font-size:12px;word-break:break-all">' + value + '</span>' +
      '</div>';
    }

    var rating = e.rating || (e.blacklisted ? 'malicious' : '');
    var ratingBadge = rating ? self._ratingWithSource(rating, e.rating_source) : '<span class="dim">\u2014</span>';

    var countryFlag = self._countryFlag(e.country);
    var countryDisplay = (countryFlag ? '<span style="font-size:15px">' + countryFlag + '</span> ' : '') + self._esc(e.country_name || e.country || '\u2014');

    var vtHtml = e.vt_malicious != null
      ? (e.vt_malicious + '/' + ((e.vt_malicious||0) + (e.vt_suspicious||0) + (e.vt_harmless||0)) + ' ' + self._t('external.modal_malicious', 'malicious'))
      : '\u2014';
    var abuseHtml = e.abuse_confidence != null
      ? (e.abuse_confidence + '%' + (e.abuse_total_reports ? ' (' + e.abuse_total_reports + ' ' + self._t('external.modal_reports', 'reports') + ')' : ''))
      : '\u2014';

    var blacklistHtml = e.blacklisted
      ? '<span style="color:#ff4d6d">\u26A0 ' + self._t('external.modal_yes', 'Yes') + (e.blacklist_info && e.blacklist_info.source ? ' \u2013 ' + self._esc(e.blacklist_info.source) : '') + '</span>'
      : '<span style="color:#6bffc8">' + self._t('external.modal_no', 'No') + '</span>';

    var dir = e.direction || 'outbound';
    var directionHtml = dir === 'both'
      ? '<span style="color:#a78bfa">\u2195 ' + self._t('external.direction_both', 'Both') + '</span>'
      : dir === 'inbound'
        ? '<span style="color:#fb923c">\u2193 ' + self._t('external.direction_inbound', 'Inbound') + '</span>'
        : '<span style="color:#34d399">\u2191 ' + self._t('external.direction_outbound', 'Outbound') + '</span>';

    var dstPorts = (e.dst_ports || []).slice(0, 16);
    var portsHtml = dstPorts.length
      ? dstPorts.map(function(p) { return '<span class="chip">' + p + '</span>'; }).join(' ') + (e.dst_ports.length > 16 ? ' <span class="dim">+' + (e.dst_ports.length - 16) + '</span>' : '')
      : '\u2014';

    var sources = e.internal_sources || e.sources || [];
    var sourcesHtml = sources.length
      ? sources.map(function(s) { return '<span class="ip-chip">' + s + '</span>'; }).join(' ')
      : '\u2014';

    var trafficKb = ((e.total_octets || 0) / 1024).toFixed(1) + ' KB';

    // Enrichment section
    var enrichSection = '';
    if (isLooking) {
      enrichSection = '<div style="display:flex;align-items:center;gap:8px;padding:12px 0;color:var(--muted);font-size:12px"><span class="spin"></span> ' + this._t('external.running_lookup', 'Running enrichment lookup…') + '</div>';
    } else if (enriched) {
      var enrichPairs = [
        [self._t('external.modal_city', 'City'),          enriched.city],
        [self._t('external.modal_timezone', 'Timezone'),   enriched.timezone],
        [self._t('external.modal_isp', 'ISP'),           enriched.isp],
        [self._t('external.modal_vt_rep', 'VT Reputation'), enriched.vt_reputation != null ? String(enriched.vt_reputation) : null],
        [self._t('external.modal_enriched_at', 'Enriched at'),   enriched.enriched_at ? self._ago(enriched.enriched_at) : null],
      ].filter(function(p) { return p[1] != null && p[1] !== ''; });
      if (enrichPairs.length || enriched.error) {
        enrichSection = '<div class="card-title" style="margin-top:14px;margin-bottom:6px">' + this._t('external.enrichment_details', 'Enrichment Details') + '</div>' +
          enrichPairs.map(function(p) { return row(p[0], self._esc(String(p[1]))); }).join('') +
          (enriched.error ? '<div style="color:var(--danger);font-size:11px;margin-top:6px">\u26A0 ' + self._esc(enriched.error) + '</div>' : '');
      }
    } else {
      enrichSection = '<div style="margin-top:10px"><button class="btn" data-ext-lookup="' + self._esc(ip) + '">' + this._t('external.run_full_lookup', '🔍 Run Full Lookup') + '</button></div>';
    }

    // External links
    var linksHtml = ip ? '<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">' +
      ['<a href="https://ipwho.is/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">ipwho.is</a>',
       '<a href="https://www.abuseipdb.com/check/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">AbuseIPDB</a>',
       '<a href="https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">VirusTotal</a>',
       '<a href="https://www.shodan.io/host/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">Shodan</a>',
      ].join('') + '</div>' : '';

    return '<div id="hsa-ext-ip-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px">' +
      '<div class="card" style="width:min(620px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(98,232,255,.26)">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">' +
          '<h1 style="font-size:15px;color:var(--accent);margin:0;font-family:monospace">' + self._esc(ip) + '</h1>' +
          '<button class="btn" data-ext-close="1">\u2715 ' + this._t('common.close', 'Close') + '</button>' +
        '</div>' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">' +
          ratingBadge +
          (e.blacklisted ? ' <span class="badge badge-critical">\u26A0 ' + this._t('external.blacklisted', 'Blacklisted') + '</span>' : '') +
        '</div>' +
        '<div class="card-title" style="margin-bottom:6px">' + this._t('external.ip_info', 'IP Info') + '</div>' +
        row(this._t('external.modal_hostname', 'Hostname'),    self._esc(e.hostname || '\u2014')) +
        row(this._t('external.modal_country', 'Country'),     countryDisplay) +
        row(this._t('external.modal_asn', 'ASN'),         self._esc(e.asn || '\u2014')) +
        row(this._t('external.modal_org_isp', 'Org / ISP'),   self._esc(e.org || e.isp || '\u2014')) +
        row(this._t('external.modal_vt', 'VirusTotal'),  vtHtml) +
        row(this._t('external.modal_abuse', 'Abuse score'), abuseHtml) +
        row(this._t('external.blacklisted', 'Blacklisted'), blacklistHtml) +
        '<div class="card-title" style="margin-top:14px;margin-bottom:6px">' + this._t('external.traffic', 'Traffic') + '</div>' +
        row(this._t('external.modal_direction', 'Direction'),       directionHtml) +
        row(this._t('external.ports_contacted', 'Ports contacted'), portsHtml) +
        row(this._t('external.internal_hosts', 'Internal hosts'),  sourcesHtml) +
        row(this._t('external.total_traffic', 'Total traffic'),   trafficKb) +
        row(this._t('external.modal_last_seen', 'Last seen'),       self._ago(e.last_seen)) +
        enrichSection +
        linksHtml +
      '</div>' +
    '</div>';
  }

  _viewDns() {
    var self    = this;
    var stats   = (this._data && this._data.dns_proxy_stats) || {};
    var log     = (this._data && this._data.dns_log) || [];
    var filteredLog = this._dnsFilteredLog(log);
    var sortedLog = this._dnsSortedLog(filteredLog);

    var CATEGORIES = ['malware','adult','gambling','ads','tracking','social','gaming','streaming','news','cdn','cloud','iot','tech','intel','override','other'];
    var CAT_COLORS = {
      malware:'rgba(255,77,109,1)', adult:'rgba(191,111,255,1)', gambling:'rgba(255,179,71,1)',
      ads:'rgba(255,209,102,1)', tracking:'rgba(107,140,186,1)', social:'rgba(91,170,236,1)',
      gaming:'rgba(107,255,200,1)', streaming:'rgba(58,197,201,1)', news:'rgba(245,158,11,1)',
      cdn:'rgba(72,199,142,1)', cloud:'rgba(59,178,255,1)', iot:'rgba(255,159,67,1)', tech:'rgba(155,135,245,1)',
      intel:'rgba(248,84,84,1)', override:'rgba(98,232,255,1)', other:'rgba(90,106,128,1)'
    };
    var CAT_LABELS = {
      malware:'Malware', adult:'Adult', gambling:'Gambling', ads:'Ads',
      tracking:'Tracking', social:'Social', gaming:'Gaming', streaming:'Streaming', news:'News',
      cdn:'CDN', cloud:'Cloud', iot:'IoT', tech:'Tech', intel:'Threat Intel',
      override:self._t('dns.cat.override', 'Override'), other:'Other'
    };

    var filterBar = '<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap">' +
      '<input class="search-bar" id="dns-search" placeholder="' + self._esc(self._t('dns.filter_placeholder', 'Filter by IP or domain…')) + '" style="width:220px" ' +
        'value="' + self._esc(this._dnsSearch) + '" onkeydown="if(event.key===\'Enter\')this.getRootNode().host._dnsFilter()" />' +
      '<select id="dns-cat-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" ' +
        'onchange="this.getRootNode().host._dnsFilter()">' +
        '<option value="">' + self._t('dns.all_categories', 'All categories') + '</option>' +
        CATEGORIES.map(function(c) { return '<option value="' + c + '"' + (self._dnsCategoryFilter === c ? ' selected' : '') + '>' + CAT_LABELS[c] + '</option>'; }).join('') +
      '</select>' +
      '<select id="dns-status-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" ' +
        'onchange="this.getRootNode().host._dnsFilter()">' +
        '<option value="">' + self._t('dns.all_status', 'All status') + '</option>' +
        '<option value="allowed"' + (self._dnsStatusFilter === 'allowed' ? ' selected' : '') + '>' + self._t('common.allowed', 'Allowed') + '</option>' +
        '<option value="blocked"' + (self._dnsStatusFilter === 'blocked' ? ' selected' : '') + '>' + self._t('common.blocked', 'Blocked') + '</option>' +
      '</select>' +
      '<label style="font-size:12px;display:flex;align-items:center;gap:5px;cursor:pointer">' +
        '<input type="checkbox" id="dns-malicious-only" onchange="this.getRootNode().host._dnsFilter()"' + (self._dnsMaliciousOnly ? ' checked' : '') + '> ' + self._t('dns.malicious_only', 'Malicious only') +
      '</label>' +
      '<span id="dns-count" style="font-size:11px;color:var(--muted);margin-left:auto">' + sortedLog.length + ' / ' + log.length + ' ' + self._t('dns.entries', 'entries') + '</span>' +
    '</div>';

    // Table
    var DNS_PAGE_SIZE = this._dnsPageSize || 25;
    var dnsPage = this._dnsPage || 0;
    var totalDnsPages = Math.max(1, Math.ceil(sortedLog.length / DNS_PAGE_SIZE));
    if (dnsPage >= totalDnsPages) dnsPage = totalDnsPages - 1;
    var pageLog = sortedLog.slice(dnsPage * DNS_PAGE_SIZE, (dnsPage + 1) * DNS_PAGE_SIZE);
    var dnsPageStart = sortedLog.length === 0 ? 0 : (dnsPage * DNS_PAGE_SIZE + 1);
    var dnsPageEnd = Math.min(sortedLog.length, (dnsPage + 1) * DNS_PAGE_SIZE);
    var topPaginationHtml =
      '<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap">' +
        '<div class="row-gap" style="font-size:11px;color:var(--muted)">' + self._t('dns.showing', 'Showing') + ' ' + dnsPageStart + '\u2013' + dnsPageEnd + ' of ' + sortedLog.length + '</div>' +
        '<div class="row-gap" style="gap:6px">' +
          '<label class="dim" style="font-size:11px">' + self._t('common.rows', 'Rows') + '</label>' +
          '<select id="hsa-dns-pagesize" class="role-select">' +
            [10,25,50,100].map(function(n) { return '<option value="' + n + '"' + (n === DNS_PAGE_SIZE ? ' selected' : '') + '>' + n + '</option>'; }).join('') +
          '</select>' +
          '<button class="btn" data-dns-page="' + (dnsPage - 1) + '"' + (dnsPage <= 0 ? ' disabled' : '') + '>' + self._t('common.previous', 'Previous') + '</button>' +
          '<span class="dim" style="font-size:11px;min-width:70px;text-align:center">' + (dnsPage + 1) + ' / ' + totalDnsPages + '</span>' +
          '<button class="btn" data-dns-page="' + (dnsPage + 1) + '"' + (dnsPage >= totalDnsPages - 1 ? ' disabled' : '') + '>' + self._t('common.next', 'Next') + '</button>' +
        '</div>' +
      '</div>';
    var maliciousCount = log.filter(function(e) { return e.malicious; }).length;
    var summaryBadge = maliciousCount > 0
      ? '<span class="badge badge-malicious" style="margin-left:8px">' + maliciousCount + ' ' + self._t('dns.malicious_badge', 'malicious') + '</span>'
      : '';

    var dnsSortCols = [
      { key: 'time', label: self._t('dns.col_time', 'Time') },
      { key: 'client_ip', label: self._t('dns.col_client_ip', 'Client IP') },
      { key: 'domain', label: self._t('dns.col_domain', 'Domain') },
      { key: 'type', label: self._t('dns.col_type', 'Type') },
      { key: 'category', label: self._t('dns.col_category', 'Category') },
    ];
    var tableHead = '<table class="data-table" id="dns-table" style="min-width:900px">' +
      '<thead><tr>' +
        dnsSortCols.map(function(c) {
          var arrow = self._dnsSort === c.key ? (self._dnsSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
          return '<th class="sortable-th" data-dnssort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
        }).join('') +
        '<th>' + self._t('dns.col_response', 'Response') + '</th><th>' + self._t('dns.col_answer', 'Answer') + '</th>' +
        (function() {
          var arrow = self._dnsSort === 'status' ? (self._dnsSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
          return '<th class="sortable-th" data-dnssort="status">' + self._t('dns.col_status', 'Status') + '<span class="sort-arrow">' + arrow + '</span></th>';
        })() +
      '</tr></thead><tbody>';

    var tableRows = pageLog.map(function(e) {
      var ts    = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
      var ip    = self._esc(e.src_ip || '—');
      var dom   = self._esc(e.domain || '—');
      var qtype = self._esc(e.qtype || 'A');
      var rcode = e.rcode || '…';
      var ans   = e.answer ? self._esc(e.answer) : '<span style="color:var(--muted)">—</span>';
      var mal   = e.malicious;
      var cat   = (e.category || 'other').toLowerCase();
      var status = (e.status || 'allowed').toLowerCase();

      var catColor = CAT_COLORS[cat] || CAT_COLORS['other'];
      var catLabel = CAT_LABELS[cat] || cat;
      var catBadge = '<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:' +
        catColor.replace(',1)', ',.18)').replace('rgba(','rgba(') + ';color:' + catColor + ';border:1px solid ' +
        catColor.replace(',1)', ',.4)') + '">' + catLabel + '</span>';

      var rcodeColor = rcode === 'NOERROR' ? 'var(--success)' : rcode === 'NXDOMAIN' ? 'var(--warn)' : rcode === '…' ? 'var(--muted)' : 'var(--danger)';

      var statusBadge;
      if (status === 'blocked') {
        statusBadge = '<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">🚫 ' + self._t('common.blocked', 'Blocked') + '</span>';
      } else {
        statusBadge = '<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">✓ ' + self._t('common.allowed', 'Allowed') + '</span>';
      }

      var rowBg = status === 'blocked' ? 'rgba(255,77,109,.06)' : mal ? 'rgba(255,77,109,.03)' : '';
      var rowStyle = rowBg ? ' style="background:' + rowBg + '"' : '';
      return '<tr' + rowStyle +
        ' data-malicious="' + (mal ? '1' : '0') +
        '" data-cat="' + cat +
        '" data-status="' + status +
        '" data-ip="' + ip.toLowerCase() +
        '" data-domain="' + dom.toLowerCase() + '">' +
        '<td class="mono" style="white-space:nowrap;font-size:11px">' + ts + '</td>' +
        '<td class="mono ip">' + ip + '</td>' +
        '<td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + dom + '">' + dom + '</td>' +
        '<td><span class="chip">' + qtype + '</span></td>' +
        '<td>' + catBadge + '</td>' +
        '<td class="mono" style="font-size:11px;color:' + rcodeColor + '">' + self._esc(rcode) + '</td>' +
        '<td class="mono" style="font-size:11px">' + ans + '</td>' +
        '<td>' + statusBadge + '</td>' +
      '</tr>';
    }).join('');

    var tableEnd = '</tbody></table>';

    var paginationHtml = ''; // kept for compat — pagination now at top

    return '<div>' +
      '<div class="view-header"><h1>' + this._t('page.dns_queries', 'DNS Queries') + ' ' + summaryBadge + '</h1></div>' +
      '<div class="card table-card">' +
        '<div style="padding:14px 14px 8px">' + filterBar + '</div>' +
        topPaginationHtml +
        '<div style="overflow-x:auto">' + tableHead + tableRows + tableEnd + '</div>' +
      '</div>' +
    '</div>';
  }

  _dnsFilter() {
    var root = this.shadowRoot;
    var prevSearch = this._dnsSearch;
    var prevMalOnly = this._dnsMaliciousOnly;
    var prevCat = this._dnsCategoryFilter;
    var prevStatus = this._dnsStatusFilter;

    this._dnsSearch = ((root.getElementById('dns-search') || { value: '' }).value || '').toLowerCase().trim();
    this._dnsMaliciousOnly = !!((root.getElementById('dns-malicious-only') || { checked: false }).checked);
    this._dnsCategoryFilter = (root.getElementById('dns-cat-filter') || { value: '' }).value || '';
    this._dnsStatusFilter = (root.getElementById('dns-status-filter') || { value: '' }).value || '';

    var searchChanged = this._dnsSearch !== prevSearch;
    var otherFiltersChanged =
      this._dnsMaliciousOnly !== prevMalOnly ||
      this._dnsCategoryFilter !== prevCat ||
      this._dnsStatusFilter !== prevStatus;

    // Keep current page when only search text changes; reset for other filter changes.
    if (otherFiltersChanged || !searchChanged) {
      this._dnsPage = 0;
    }

    this._render();
  }

  _dnsFilteredLog(log) {
    var search = (this._dnsSearch || '').toLowerCase().trim();
    var malOnly = !!this._dnsMaliciousOnly;
    var catFilter = this._dnsCategoryFilter || '';
    var statusFilter = this._dnsStatusFilter || '';
    return (log || []).filter(function(e) {
      var ip = String(e.src_ip || '').toLowerCase();
      var domain = String(e.domain || '').toLowerCase();
      var mal = !!e.malicious;
      var cat = String(e.category || 'other').toLowerCase();
      var status = String(e.status || 'allowed').toLowerCase();
      return (!malOnly || mal) &&
             (!search || ip.indexOf(search) >= 0 || domain.indexOf(search) >= 0) &&
             (!catFilter || cat === catFilter) &&
             (!statusFilter || status === statusFilter);
    });
  }

  _dnsSortedLog(log) {
    var self = this;
    var sortKey = this._dnsSort || 'time';
    var sortDir = this._dnsSortDir || -1;
    var out = (log || []).slice();
    out.sort(function(a, b) {
      var va;
      var vb;
      if (sortKey === 'time') {
        va = Date.parse(a.timestamp || '') || 0;
        vb = Date.parse(b.timestamp || '') || 0;
      } else if (sortKey === 'client_ip') {
        va = self._dnsIpSortKey(a.src_ip);
        vb = self._dnsIpSortKey(b.src_ip);
      } else if (sortKey === 'domain') {
        va = String(a.domain || '').toLowerCase();
        vb = String(b.domain || '').toLowerCase();
      } else if (sortKey === 'type') {
        va = String(a.qtype || '').toLowerCase();
        vb = String(b.qtype || '').toLowerCase();
      } else if (sortKey === 'category') {
        va = String(a.category || 'other').toLowerCase();
        vb = String(b.category || 'other').toLowerCase();
      } else if (sortKey === 'status') {
        va = String(a.status || 'allowed').toLowerCase();
        vb = String(b.status || 'allowed').toLowerCase();
      } else {
        va = '';
        vb = '';
      }
      if (va < vb) return -1 * sortDir;
      if (va > vb) return 1 * sortDir;
      var ta = Date.parse(a.timestamp || '') || 0;
      var tb = Date.parse(b.timestamp || '') || 0;
      if (ta > tb) return -1;
      if (ta < tb) return 1;
      return 0;
    });
    return out;
  }

  _clearBlockedDns(btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Clearing\u2026'; }
    var self = this;
    this._hass.callApi('POST', 'homesec/dns/log/clear_blocked')
      .then(function() {
        if (self._data && self._data.dns_log) {
          self._data.dns_log = self._data.dns_log.filter(function(e) { return !e.malicious && e.status !== 'blocked'; });
          self._dnsPage = 0;
          self._render();
        }
      })
      .catch(function() { if (btn) { btn.disabled = false; btn.textContent = '\u{1F6AB} Clear blocked'; } });
  }

  _viewRecs() {
    var recs = (this._data && this._data.recommendations) || [];
    if (!recs.length) return '<div><div class="view-header"><h1>' + this._t('recs.page_title', 'Security Recommendations') + '</h1></div>' +
      '<div class="empty-state card" style="height:180px"><div class="empty-icon">\u2713</div><p>' + this._t('recs.no_recommendations', 'No recommendations at this time.') + '</p></div></div>';
    var icons = { critical: '\uD83D\uDEA8', high: '\u26A0\uFE0F', medium: '\uD83D\uDCA1', low: '\u2139\uFE0F' };
    var self = this;

    function _formatTemplate(template, values) {
      return template.replace(/\{([a-zA-Z0-9_]+)\}/g, function(_, key) {
        return values[key] != null ? String(values[key]) : '';
      });
    }

    function _localizedRec(r) {
      var countHosts = (r.hosts && r.hosts.length) || 0;
      var countFindings = (r.findings_refs && r.findings_refs.length) || 0;
      switch (r.category) {
        case 'patch_vulnerable':
          return {
            title: self._t('recs.title_patch_vulnerable', 'Patch vulnerable devices'),
            detail: _formatTemplate(self._t('recs.detail_patch_vulnerable', '{n} device(s) have known high or critical CVE vulnerabilities. Update firmware/software or restrict network access immediately.'), { n: countHosts || 1 }),
          };
        case 'vulnerability':
          return {
            title: self._t('recs.title_review_vulnerability_findings', 'Review vulnerability findings'),
            detail: self._t('recs.detail_review_vulnerability_findings', 'Active scanning found services with known security issues. Check the findings tab for CVE details and remediation steps.'),
          };
        case 'no_exporter':
          return {
            title: self._t('recs.title_connect_exporter', 'Connect a flow exporter'),
            detail: self._t('recs.detail_connect_exporter', 'No NetFlow or IPFIX exporters have been observed yet. Configure your gateway, firewall, or switch to export flows to HomeSec.'),
          };
        case 'exporter_unreachable':
          return {
            title: self._t('recs.title_verify_exporter', 'Verify exporter reachability'),
            detail: self._t('recs.detail_verify_exporter', 'Exporters are configured but HomeSec has not received any datagrams yet. Check exporter target IP/port, firewall rules, and container networking.'),
          };
        case 'bad_flow_format':
          return {
            title: self._t('recs.title_check_flow_format', 'Check flow export format'),
            detail: self._t('recs.detail_check_flow_format', 'Datagrams are arriving but none produced records. Confirm exporter uses NetFlow v5/v9/IPFIX with IPv4 fields and valid templates.'),
          };
        case 'suspicious_port':
          return {
            title: self._t('recs.title_restrict_risky_ports', 'Restrict risky outbound ports'),
            detail: self._t('recs.detail_restrict_risky_ports', 'At least one device reached a commonly abused external port such as Telnet or RDP. Block or alert on these ports at the gateway and patch the source device.'),
          };
        case 'port_scan':
          return {
            title: self._t('recs.title_isolate_scanning_hosts', 'Isolate scanning hosts'),
            detail: self._t('recs.detail_isolate_scanning_hosts', 'A device is touching many ports in a short time window. Move it to an isolated VLAN or guest network until you confirm the behavior is expected.'),
          };
        case 'high_egress':
          return {
            title: self._t('recs.title_review_high_egress_devices', 'Review high egress devices'),
            detail: self._t('recs.detail_review_high_egress_devices', 'One or more devices exceeded the outbound data threshold. Confirm whether the traffic matches backups, cameras, or media uploads instead of malware or exfiltration.'),
          };
        case 'unknown_roles':
          return {
            title: self._t('recs.title_improve_device_identity_coverage', 'Improve device identity coverage'),
            detail: _formatTemplate(self._t('recs.detail_improve_device_identity_coverage', '{n} devices still have unknown roles. Add router, DHCP, or tracker integrations so HomeSec can correlate names, MAC addresses, and hostnames.'), { n: countHosts || 1 }),
          };
        case 'no_tracker':
          return {
            title: self._t('recs.title_enable_device_tracker_enrichment', 'Enable device tracker enrichment'),
            detail: self._t('recs.detail_enable_device_tracker_enrichment', 'HomeSec is seeing devices but none were enriched from Home Assistant trackers. Adding router or presence integrations will make the dashboard much more readable.'),
          };
        case 'dropped_datagrams':
          return {
            title: self._t('recs.title_stabilize_exporter_templates', 'Stabilize exporter templates'),
            detail: self._t('recs.detail_stabilize_exporter_templates', 'Some flow datagrams were dropped or arrived before their templates. Reduce exporter restarts or shorten template refresh intervals on the exporter.'),
          };
        default:
          return { title: r.title, detail: r.detail };
      }
    }

    function _recDetail(r) {
      var hosts = r.hosts || [];
      var frefs = r.findings_refs || [];
      if (!hosts.length && !frefs.length) return '';
      var html = '<div class="rec-expand-panel">';

      if (hosts.length) {
        html += '<div class="rec-expand-section"><div class="rec-expand-label">' + self._t('recs.affected_hosts', 'Affected hosts') + ' (' + hosts.length + ')</div><div class="rec-expand-rows">';
        hosts.forEach(function(h) {
          var nameHtml = (h.name && h.name !== h.ip)
            ? '<span style="color:rgba(140,200,255,.85);font-weight:600;margin-left:6px">' + self._esc(h.name) + '</span>' : '';
          var roleHtml = h.role && h.role !== 'unknown'
            ? '<span class="badge badge-dim" style="margin-left:6px">' + self._esc(h.role.replace(/_/g, ' ')) + '</span>' : '';
          var cvesHtml = '';
          if (h.cves && h.cves.length) {
            cvesHtml = '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">' +
              h.cves.map(function(c) {
                return '<a class="ext-report-link" style="cursor:pointer" data-vuln-detail="' + self._esc(c) + '">' + self._esc(c) + '</a>';
              }).join('') + '</div>';
          } else if (h.vuln_count > 0) {
            cvesHtml = '<span style="font-size:10px;color:var(--muted);margin-left:6px">' + h.vuln_count + ' CVE' + (h.vuln_count !== 1 ? 's' : '') + '</span>';
          }
          html += '<div class="rec-expand-row">' +
            '<span class="ip">' + self._esc(h.ip) + '</span>' + nameHtml + roleHtml + cvesHtml +
          '</div>';
        });
        html += '</div></div>';
      }

      if (frefs.length) {
        html += '<div class="rec-expand-section"><div class="rec-expand-label">' + self._t('recs.related_findings', 'Related findings') + ' (' + frefs.length + ')</div><div class="rec-expand-rows">';
        frefs.forEach(function(f) {
          var det = f.detail || {};
          var port = det.port ? '<span class="chip" style="margin-left:6px">port ' + det.port + '</span>' : '';
          var cve  = det.cve_id ? '<a class="ext-report-link" style="cursor:pointer;margin-left:6px" data-vuln-detail="' + self._esc(det.cve_id) + '">' + self._esc(det.cve_id) + '</a>' : '';
          var cnt  = f.count > 1 ? '<span style="font-size:10px;color:var(--muted);margin-left:6px">' + f.count + '\u00D7</span>' : '';
          html += '<div class="rec-expand-row">' +
            self._sev(f.severity) +
            '<span class="ip" style="margin-left:6px">' + self._esc(f.source_ip) + '</span>' + port + cve + cnt +
            '<span style="font-size:11px;color:var(--muted);margin-left:8px">' + self._esc(f.summary) + '</span>' +
          '</div>';
        });
        html += '</div></div>';
      }

      html += '</div>';
      return html;
    }

    return '<div><div class="view-header"><h1>' + this._t('recs.page_title', 'Security Recommendations') + '</h1></div>' +
      recs.map(function(r, idx) {
        var expanded = (self._expandedRec === idx);
        var hasDetail = (r.hosts && r.hosts.length) || (r.findings_refs && r.findings_refs.length);
        var text = _localizedRec(r);
        var chevron = hasDetail
          ? '<span style="margin-left:auto;font-size:11px;color:var(--muted);transition:transform .15s;display:inline-block;transform:rotate(' + (expanded ? '90' : '0') + 'deg)">\u25B6</span>'
          : '';
        return '<div class="rec-card' + (hasDetail ? ' rec-card-clickable' : '') + '" ' +
            (hasDetail ? 'data-rec-idx="' + idx + '"' : '') + '>' +
          '<div class="rec-icon">' + (icons[r.priority] || '\uD83D\uDCA1') + '</div>' +
          '<div style="flex:1;min-width:0">' +
            '<div class="rec-title">' + self._esc(text.title) + ' ' + self._sev(r.priority) + chevron + '</div>' +
            '<div class="rec-detail">' + self._esc(text.detail) + '</div>' +
            (expanded ? _recDetail(r) : '') +
          '</div>' +
        '</div>';
      }).join('') + '</div>';
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  _stat(v, label, type) { return '<div class="stat-card ' + type + '"><div class="stat-value">' + v + '</div><div class="stat-label">' + label + '</div></div>'; }
  _hrow(k, v, cls)      { return '<div class="health-row"><span class="health-label">' + k + '</span><span class="health-value ' + cls + '">' + this._esc(String(v)) + '</span></div>'; }
  _kv(k, v)             { return '<div class="health-row"><span class="health-label">' + k + '</span><span class="health-value">' + this._esc(String(v)) + '</span></div>'; }
  _sev(s)               { return s ? '<span class="badge badge-' + s + '">' + s + '</span>' : ''; }
  _rating(r)            { return r ? '<span class="badge badge-' + r + '">' + r + '</span>' : ''; }
  _ratingWithSource(r, src) {
    if (!r) return '';
    var title = src ? ' title="' + this._esc(src) + '"' : '';
    return '<span class="badge badge-' + r + '"' + title + '>' + r + '</span>';
  }
  _cdot(c) {
    var col = {high:'#6bffc8',medium:'#ffce54',low:'#5a6a80'}[c] || '#5a6a80';
    return c ? '<span title="' + c + '" style="color:' + col + ';font-size:8px">\u25CF</span>' : '';
  }
  _nc(n) {
    if (n.at_risk || n.blacklisted) return '#ff4d6d';
    if (n.type === 'multicast')             return '#d4a843';
    if (n.type === 'external')              return '#5a6a80';
    if (n.baseline_only) return '#88a7c7';
    if (n.probable_role === 'dns_or_gateway') return '#6bffc8';
    if (n.probable_role === 'camera')       return '#ffb347';
    if (!n.alive && (n.total_octets || 0) > 0) return '#3ac5c9';
    if (!n.alive) return '#3a4a62';
    return '#8f86ff';
  }
  _countryFlag(code) {
    if (!code || code.length !== 2) return '';
    var a = code.toUpperCase().charCodeAt(0) - 65 + 0x1F1E6;
    var b = code.toUpperCase().charCodeAt(1) - 65 + 0x1F1E6;
    return String.fromCodePoint(a, b);
  }
  _nr(n) { return Math.max(4, Math.min(14, 4 + Math.log10((n.total_octets || 0) + 1) * 0.9)); }
  _bytes(n) {
    if (!n) return '0 B';
    var u = ['B','KB','MB','GB','TB'];
    var i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
    return (n / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
  }
  _fmtN(n) {
    if (n >= 1e9) return (n/1e9).toFixed(1) + 'G';
    if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
    if (n >= 1e3) return Math.floor(n/1e3) + 'K';
    return String(n);
  }
  _uptime(iso) {
    if (!iso) return '—';
    var s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    var d = Math.floor(s / 86400);
    var h = Math.floor((s % 86400) / 3600);
    var m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm ' + (s % 60) + 's';
  }
  _ago(iso) {
    if (!iso) return 'never';
    var d = Date.now() - new Date(iso).getTime();
    if (d < 60000)    return this._t('time.just_now', 'just now');
    if (d < 3600000)  return this._t('time.minutes_ago', '{n}m ago').replace('{n}', Math.floor(d/60000));
    if (d < 86400000) return this._t('time.hours_ago', '{n}h ago').replace('{n}', Math.floor(d/3600000));
    return this._t('time.days_ago', '{n}d ago').replace('{n}', Math.floor(d/86400000));
  }
  _esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  _langCode() {
    var hass = this._hass || {};
    var lang = '';
    if (typeof hass.language === 'string') lang = hass.language;
    else if (typeof hass.selectedLanguage === 'string') lang = hass.selectedLanguage;
    else if (hass.locale && typeof hass.locale.language === 'string') lang = hass.locale.language;
    else if (typeof navigator !== 'undefined' && typeof navigator.language === 'string') lang = navigator.language;
    return String(lang || '').toLowerCase();
  }

  _activeLocale() {
    var lang = this._langCode();
    if (lang.indexOf('fr') === 0) return 'fr';
    if (lang.indexOf('de') === 0) return 'de';
    if (lang.indexOf('es') === 0) return 'es';
    if (lang.indexOf('it') === 0) return 'it';
    return 'en';
  }

  _t(key, fallback) {
    var locale = this._activeLocale();
    var dict = _UI_I18N[locale] || {};
    return Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : fallback;
  }

  _viewLabel(view) {
    return this._t('view.' + view, _VIEW_LABELS[view] || view);
  }

  _docsUrlForLanguage() {
    var lang = this._langCode();
    if (lang.indexOf('fr') === 0) return 'https://domotic.monster/homesec_fr.html';
    if (lang.indexOf('de') === 0) return 'https://domotic.monster/homesec_de.html';
    return 'https://domotic.monster/homesec.html';
  }

  // ── Settings view ────────────────────────────────────────────────────
  _viewSettings() {
    var self = this;
    var docsUrl = this._docsUrlForLanguage();
    var schemaLocale = _SETTINGS_SCHEMA_I18N[this._activeLocale()] || null;
    if (!this._settingsData && !this._settingsLoading) {
      this._settingsLoading = true;
      this._settingsRetries = (this._settingsRetries || 0);
      this._hass.callApi('GET', 'homesec/settings').then(function(d) {
        self._settingsData = d;
        self._settingsLoading = false;
        self._settingsRetries = 0;
        self._render();
      }).catch(function(e) {
        self._settingsLoading = false;
        var status = (e && typeof e === 'object') ? (e.status_code || e.status || 0) : 0;
        // During integration reload the endpoint briefly returns 404 — retry automatically
        if ((status === 404 || status === 0) && self._settingsRetries < 8) {
          self._settingsRetries++;
          setTimeout(function() {
            if (self._view === 'settings') {
              self._settingsLoading = false;
              self._settingsData = null;
              self._render();
            }
          }, 2000);
          return; // keep showing the loading spinner
        }
        self._settingsRetries = 0;
        var msg;
        if (typeof e === 'string') {
          msg = e;
        } else if (e instanceof Error) {
          msg = e.message;
        } else if (e && typeof e === 'object') {
          msg = e.message || e.error || e.body || e.detail ||
                (typeof e.status_code === 'number' ? 'HTTP ' + e.status_code : null) ||
                JSON.stringify(e);
        } else {
          msg = String(e);
        }
        self._settingsMsg = self._t('settings.failed_load', 'Failed to load settings: ') + msg;
        self._settingsMsgType = 'error';
        self._render();
      });
      return '<div><div class="view-header"><h1>' + this._t('settings.title', 'Settings') + '</h1></div><div class="state-box"><div class="loader"></div><p>' + this._t('settings.loading', 'Loading settings\u2026') + '</p></div></div>';
    }
    if (this._settingsLoading) {
      return '<div><div class="view-header"><h1>' + this._t('settings.title', 'Settings') + '</h1></div><div class="state-box"><div class="loader"></div><p>' + this._t('settings.loading_short', 'Loading\u2026') + '</p></div></div>';
    }
    var schema = (this._settingsData && this._settingsData.schema) || [];
    var config = (this._settingsData && this._settingsData.config) || {};
    this._settingsDraft = this._settingsDraft || {};
    var msgHtml = '';
    if (this._settingsMsg) {
      var msgColor = this._settingsMsgType === 'error' ? 'var(--danger)' : 'var(--success)';
      msgHtml = '<div style="background:rgba(0,0,0,.25);border:1px solid ' + msgColor + ';border-radius:8px;padding:10px 14px;margin-bottom:14px;color:' + msgColor + ';font-size:12px">' + this._esc(this._settingsMsg) + '</div>';
    }
    var dirtyHtml = this._settingsDirty
      ? '<div style="background:rgba(255,179,71,.09);border:1px solid rgba(255,179,71,.4);border-radius:8px;padding:10px 14px;margin-bottom:14px;color:var(--warn);font-size:12px">' + this._t('settings.unsaved', 'You have unsaved changes.') + '</div>'
      : '';
    var fieldsHtml = schema.map(function(section) {
      var rows = (section.fields || []).map(function(f) {
        var cfgVal = config[f.key] !== undefined ? config[f.key] : (f.default !== undefined ? f.default : '');
        var hasDraft = Object.prototype.hasOwnProperty.call(self._settingsDraft, f.key);
        var val = hasDraft ? self._settingsDraft[f.key] : cfgVal;
        var inputHtml = '';
        if (f.type === 'boolean' || f.type === 'bool') {
          var checked = (val === true || val === 'true' || val === 1 || val === '1');
          inputHtml = '<input type="checkbox" id="hsa-setting-' + f.key + '" ' + (checked ? 'checked' : '') + ' style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">';
        } else if (f.type === 'number') {
          inputHtml = '<input type="number" id="hsa-setting-' + f.key + '" value="' + self._esc(String(val)) + '"' +
            (f.min !== undefined ? ' min="' + f.min + '"' : '') + (f.max !== undefined ? ' max="' + f.max + '"' : '') +
            ' style="width:160px;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">';
        } else if (f.type === 'password') {
          inputHtml = '<input type="password" id="hsa-setting-' + f.key + '" value="' + self._esc(String(val)) + '" style="width:340px;max-width:100%;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">';
        } else {
          inputHtml = '<input type="text" id="hsa-setting-' + f.key + '" value="' + self._esc(String(val)) + '" style="width:340px;max-width:100%;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">';
        }
        return '<div style="display:flex;align-items:flex-start;gap:12px;padding:8px 0;border-bottom:1px solid rgba(98,232,255,.04)">' +
          '<div style="flex:0 0 240px;min-width:0">' +
            '<div style="font-size:12px;font-weight:600;color:var(--text)">' + self._esc((schemaLocale && schemaLocale.labels && schemaLocale.labels[f.key]) || f.label) + '</div>' +
            (f.help ? '<div style="font-size:10px;color:var(--muted);margin-top:2px;line-height:1.4">' + self._esc((schemaLocale && schemaLocale.helps && schemaLocale.helps[f.key]) || f.help) + '</div>' : '') +
          '</div>' +
          '<div style="flex:1;min-width:0">' + inputHtml + '</div>' +
        '</div>';
      }).join('');
      return '<div class="card" style="margin-bottom:12px">' +
        '<div class="card-title">' + self._esc((schemaLocale && schemaLocale.sections && schemaLocale.sections[section.section]) || section.section) + '</div>' +
        rows +
      '</div>';
    }).join('');
    var linksCard =
      '<div class="card" style="margin-top:14px">' +
        '<div class="card-title">' + this._t('settings.links', 'Links') + '</div>' +
        '<div style="font-size:12px;color:var(--text);line-height:1.7">' +
          this._t('settings.project', 'Project') + ': <a class="ext-report-link" href="https://github.com/domo-monster/HomeSecurityAssistant" target="_blank" rel="noopener noreferrer">' + this._t('settings.github_repo', 'GitHub Repository') + '</a><br>' +
          this._t('settings.documentation', 'Documentation') + ': <a class="ext-report-link" href="' + docsUrl + '" target="_blank" rel="noopener noreferrer">' + this._t('settings.open_documentation', 'Open Documentation') + '</a>' +
        '</div>' +
      '</div>';

    return '<div>' +
      '<div class="view-header"><h1>' + this._t('settings.title', 'Settings') + '</h1><div style="font-size:11px;color:var(--muted)">' + this._t('settings.subtitle', 'Changes take effect after reloading the integration.') + '</div></div>' +
      msgHtml +
      dirtyHtml +
      fieldsHtml +
      '<div style="margin-top:6px">' +
        '<button class="btn" data-settings-save style="padding:6px 18px;font-size:12px">' + this._t('settings.save', 'Save settings') + '</button>' +
        ' <button class="btn" data-settings-reset style="font-size:11px;opacity:.6">' + this._t('settings.reload_server', 'Reload from server') + '</button>' +
      '</div>' +
      linksCard +
    '</div>';
  }

  _onSettingsSave() {
    var self = this;
    var schema = (this._settingsData && this._settingsData.schema) || [];
    var payload = {};
    var root = this.shadowRoot;
    schema.forEach(function(section) {
      (section.fields || []).forEach(function(f) {
        var el = root && root.getElementById('hsa-setting-' + f.key);
        if (!el) return;
        if (f.type === 'boolean' || f.type === 'bool') {
          payload[f.key] = el.checked;
        } else if (f.type === 'number') {
          payload[f.key] = Number(el.value);
        } else {
          payload[f.key] = el.value;
        }
      });
    });
    this._hass.callApi('POST', 'homesec/settings/save', payload).then(function() {
      self._settingsMsg = self._t('settings.saved_reload', 'Settings saved. The integration will reload in a moment to apply changes.');
      self._settingsMsgType = 'ok';
      self._settingsDraft = {};
      self._settingsDirty = false;
      self._pendingView = null;
      self._unregisterBeforeUnload();
      // Patch local config with saved values so the form re-renders with the new values
      if (self._settingsData && self._settingsData.config) {
        Object.assign(self._settingsData.config, payload);
      }
      self._render();
    }).catch(function(e) {
      var msg;
      if (typeof e === 'string') {
        msg = e;
      } else if (e instanceof Error) {
        msg = e.message;
      } else if (e && typeof e === 'object') {
        msg = e.message || e.error || e.body || e.detail ||
              (typeof e.status_code === 'number' ? 'HTTP ' + e.status_code : null) ||
              JSON.stringify(e);
      } else {
        msg = String(e);
      }
      self._settingsMsg = self._t('settings.failed_save', 'Failed to save settings: ') + msg;
      self._settingsMsgType = 'error';
      self._render();
    });
  }
}

var _CSS = ':host{--bg:#070b12;--card:rgba(14,23,40,.92);--border:rgba(98,232,255,.14);--text:#eef7ff;--muted:#8a9dbf;--accent:#62e8ff;--success:#6bffc8;--danger:#ff4d6d;--warn:#ffb347;--violet:#9e96ff;--glow:0 0 28px rgba(98,232,255,.08);display:block;height:100vh;overflow:hidden;font-family:"IBM Plex Sans","Segoe UI",sans-serif;color:var(--text);background:var(--bg)}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}.app{display:flex;height:100vh;overflow:hidden}.sidebar{width:210px;min-width:210px;background:rgba(6,11,24,.98);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;z-index:10}.brand{padding:18px 14px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)}.brand-shield{font-size:26px;filter:drop-shadow(0 0 8px rgba(98,232,255,.5))}.brand-text{display:flex;flex-direction:column}.brand-name{font-size:12px;font-weight:700;color:var(--accent);letter-spacing:.04em;text-transform:uppercase}.brand-sub{font-size:10px;color:var(--muted);letter-spacing:.06em}.brand-tagline{font-size:9px;color:var(--muted);opacity:.7;margin-top:4px;line-height:1.3}.nav-list{list-style:none;padding:6px 0;flex:1}.nav-item{display:flex;align-items:center;gap:9px;padding:9px 14px;cursor:pointer;font-size:12px;font-weight:500;color:var(--muted);border-left:3px solid transparent;transition:all .12s ease;user-select:none}.nav-item:hover{background:rgba(98,232,255,.05);color:var(--text)}.nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(98,232,255,.07)}.nav-item svg{width:15px;height:15px;flex-shrink:0;opacity:.65}.nav-item.active svg{opacity:1}.nav-label{flex:1}.nav-badge{background:var(--danger);color:#fff;border-radius:10px;font-size:9px;font-weight:700;padding:1px 5px;min-width:16px;text-align:center}.sidebar-status{padding:10px 14px;border-top:1px solid var(--border);display:flex;align-items:center;gap:7px;font-size:10px;color:var(--muted)}.status-dot{width:6px;height:6px;border-radius:50%;background:var(--muted)}.sidebar-status.online .status-dot{background:var(--success);box-shadow:0 0 6px var(--success);animation:pulse 2s infinite}.content{flex:1;overflow-y:auto;padding:22px 24px;position:relative;background:var(--bg)}.content::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.12;background-image:linear-gradient(rgba(98,232,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(98,232,255,.07) 1px,transparent 1px);background-size:40px 40px}.content>*{position:relative;z-index:1}.page-header{margin-bottom:20px}.page-title{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:.01em;margin-bottom:3px}.page-subtitle{font-size:12px;color:var(--muted);letter-spacing:.02em}.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px}.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;box-shadow:var(--glow)}.stat-card.danger{border-color:rgba(255,77,109,.3)}.stat-card.warn{border-color:rgba(255,179,71,.28)}.stat-card.success{border-color:rgba(107,255,200,.2)}.stat-value{font-size:26px;font-weight:800;line-height:1;margin-bottom:3px}.stat-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--glow);margin-bottom:14px}.table-card{padding:0;overflow:hidden}.card-title{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}.health-row{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(98,232,255,.05);font-size:12px}.health-row:last-child{border-bottom:none}.health-label{color:var(--muted)}.health-value{color:var(--text);font-weight:600;font-variant-numeric:tabular-nums}.health-value.good{color:var(--success)}.health-value.warn{color:var(--warn)}.health-value.bad{color:var(--danger)}.alert-row{display:flex;gap:8px;align-items:flex-start;padding:7px 0;border-bottom:1px solid rgba(98,232,255,.05)}.alert-row:last-child{border-bottom:none}.alert-body{flex:1;min-width:0}.alert-sum{font-size:12px;font-weight:600}.alert-meta{font-size:10px;color:var(--muted);margin-top:2px}.view-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}.view-header h1{font-size:18px;font-weight:700}.dim{color:var(--muted);font-weight:400;font-size:13px}.row-gap{display:flex;gap:8px;align-items:center}.data-table{width:100%;border-collapse:collapse;font-size:12px}.data-table th{text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600}.data-table td{padding:7px 10px;border-bottom:1px solid rgba(98,232,255,.04);vertical-align:middle}.data-table tr.expandable{cursor:pointer}.data-table tr.expandable:hover td{background:rgba(98,232,255,.03)}.mono{font-family:"IBM Plex Mono",monospace}.ip{font-family:"IBM Plex Mono",monospace;font-size:11px}.host-detail-wrap{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:14px 16px;background:rgba(0,0,0,.25)}.section-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;font-weight:600}.detail-row{background:rgba(0,0,0,.2)}.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}.badge-critical{background:rgba(255,77,109,.2);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)}.badge-high{background:rgba(255,140,66,.18);color:#ff8c42;border:1px solid rgba(255,140,66,.35)}.badge-medium{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-low{background:rgba(107,255,200,.1);color:#6bffc8;border:1px solid rgba(107,255,200,.22)}.badge-clean{background:rgba(107,255,200,.1);color:#6bffc8;border:1px solid rgba(107,255,200,.22)}.badge-suspicious{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-malicious{background:rgba(255,77,109,.2);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)}.badge-ok{background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)}.badge-warn{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-dim{background:rgba(255,255,255,.06);color:var(--muted);border:1px solid rgba(255,255,255,.1)}.chip{display:inline-block;background:rgba(98,232,255,.08);border:1px solid rgba(98,232,255,.15);border-radius:100px;padding:1px 7px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:var(--accent);margin:1px}.ip-chip{display:inline-block;background:rgba(107,255,200,.08);border:1px solid rgba(107,255,200,.2);border-radius:100px;padding:1px 7px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:var(--success);margin:1px 2px 1px 0}.finding-card{background:var(--card);border:1px solid var(--border);border-left-width:3px;border-radius:0 10px 10px 0;padding:12px 14px;margin-bottom:10px}.finding-card.sev-critical{border-left-color:var(--danger)}.finding-card.sev-high{border-left-color:#ff8c42}.finding-header{display:flex;align-items:center;gap:8px;margin-bottom:5px}.finding-title{flex:1;font-size:12px;font-weight:600}.finding-meta{display:flex;gap:12px;font-size:10px;color:var(--muted);flex-wrap:wrap}.finding-body{font-size:11px;color:var(--muted);margin-top:5px;line-height:1.5}.finding-detail{margin-top:8px;background:rgba(0,0,0,.2);border-radius:5px;padding:8px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:#b0c8e0}.finding-detail dt{color:var(--muted);font-weight:600}.finding-detail dd{margin-left:4px;color:var(--text);margin-right:12px}.fix-hint{font-size:11px;color:var(--success);margin-top:5px}.finding-group-wrap{margin-bottom:10px}.finding-group-card{cursor:pointer;border-radius:0 10px 10px 0;margin-bottom:0;transition:border-color .12s}.finding-group-card:hover{border-color:rgba(98,232,255,.3)}.finding-group-chevron{font-size:10px;color:var(--muted);transition:transform .15s;display:inline-block;flex-shrink:0}.finding-group-rows{background:rgba(0,0,0,.18);border:1px solid var(--border);border-top:none;border-radius:0 0 10px 10px;padding:4px 0}.finding-row{display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding:7px 14px;border-bottom:1px solid rgba(98,232,255,.05);font-size:11px}.finding-row:last-child{border-bottom:none}.map-wrap{position:relative;height:calc(100vh - 120px);background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden}#hsa-map-canvas{width:100%;height:100%;display:block;cursor:grab;touch-action:none}#hsa-map-canvas:active{cursor:grabbing}.map-tooltip{position:absolute;background:rgba(6,11,24,.96);border:1px solid var(--border);border-radius:7px;padding:7px 11px;font-size:10px;pointer-events:none;z-index:10;min-width:130px;box-shadow:0 4px 18px rgba(0,0,0,.5)}.map-legend{position:absolute;bottom:10px;left:10px;background:rgba(6,11,24,.82);border:1px solid var(--border);border-radius:7px;padding:8px 12px;font-size:10px;display:flex;gap:12px}.legend-item{display:flex;align-items:center;gap:4px;color:var(--muted)}.ldot{width:9px;height:9px;border-radius:50%}.map-mbtn{padding:4px 12px}.map-mbtn.active{background:rgba(136,167,199,.2);border-color:#88a7c7;color:#fff}.map-filter-bar{display:flex;gap:6px;margin-bottom:10px}.map-fbtn{padding:4px 12px}.map-fbtn.active{background:rgba(98,232,255,.18);border-color:var(--accent);color:#fff}.tldr-bar{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px 16px;margin-bottom:12px;display:flex;gap:20px;flex-wrap:wrap;font-size:11px;color:var(--muted)}.tldr-bar strong{color:var(--accent)}.ip-detail-panel{background:rgba(6,11,24,.98);border:1px solid rgba(98,232,255,.3);border-radius:10px;padding:14px;font-size:12px}.ip-detail-panel h3{color:var(--accent);font-size:13px;margin-bottom:12px;display:flex;align-items:center;gap:8px}.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}.detail-pair{display:flex;flex-direction:column;gap:2px}.detail-key{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}.detail-val{font-size:12px;color:var(--text);word-break:break-all}.ext-report-link{display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;border-radius:999px;border:1px solid rgba(98,232,255,.25);background:rgba(98,232,255,.08);color:var(--accent);text-decoration:none;font-size:11px;font-weight:600}.ext-report-link:hover{background:rgba(98,232,255,.16);border-color:rgba(98,232,255,.45)}.rec-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:10px;display:flex;gap:12px;align-items:flex-start}.rec-card-clickable{cursor:pointer;transition:border-color .12s}.rec-card-clickable:hover{border-color:rgba(98,232,255,.35);background:rgba(14,23,40,.98)}.rec-icon{font-size:18px;line-height:1;flex-shrink:0;margin-top:1px}.rec-title{font-size:12px;font-weight:600;margin-bottom:3px;display:flex;align-items:center;gap:8px}.rec-detail{font-size:11px;color:var(--muted);line-height:1.55}.rec-expand-panel{margin-top:10px;border-top:1px solid var(--border);padding-top:10px}.rec-expand-section{margin-bottom:10px}.rec-expand-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600;margin-bottom:6px}.rec-expand-rows{display:flex;flex-direction:column;gap:5px}.rec-expand-row{display:flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:11px;padding:4px 0;border-bottom:1px solid rgba(98,232,255,.04)}.rec-expand-row:last-child{border-bottom:none}.btn{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:rgba(98,232,255,.05);color:var(--accent);font-size:11px;font-weight:600;cursor:pointer;transition:all .12s}.btn:hover{background:rgba(98,232,255,.12);border-color:var(--accent)}.btn:disabled{opacity:.4;cursor:default}.btn.active{background:rgba(98,232,255,.18);border-color:var(--accent);color:#fff}.search-bar{padding:5px 11px;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;width:210px}.search-bar:focus{outline:none;border-color:var(--accent)}.state-box{display:flex;flex-direction:column;align-items:center;justify-content:center;height:220px;gap:14px;color:var(--muted)}.state-icon{font-size:32px}.loader{width:26px;height:26px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;gap:10px;color:var(--muted);text-align:center}.empty-icon{font-size:28px}@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--success)}50%{opacity:.6;box-shadow:0 0 2px var(--success)}}@keyframes spin{to{transform:rotate(360deg)}}.role-select{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;padding:2px 4px;cursor:pointer;font-family:inherit}.role-select:focus{outline:none;border-color:var(--accent)}.role-select:hover{border-color:var(--accent);background:rgba(98,232,255,.08)}.sortable-th{cursor:pointer;user-select:none;white-space:nowrap}.sortable-th:hover{color:var(--accent)}.sort-arrow{font-size:8px;margin-left:3px;color:var(--accent)}@media(max-width:768px){.app{flex-direction:column}.sidebar{width:100%;min-width:0;flex-direction:row;overflow-x:auto;overflow-y:hidden;border-right:none;border-bottom:1px solid var(--border);align-items:center;gap:0}.brand{display:none}.brand-tagline{display:none}.nav-list{display:flex;flex-direction:row;padding:0;flex:1;overflow-x:auto;-webkit-overflow-scrolling:touch}.nav-item{flex-direction:column;gap:2px;padding:8px 12px;font-size:10px;border-left:none;border-bottom:3px solid transparent;white-space:nowrap;min-width:0}.nav-item.active{border-left-color:transparent;border-bottom-color:var(--accent)}.nav-item svg{width:14px;height:14px}.nav-label{font-size:9px}.sidebar-status{display:none}.content{padding:12px 10px;height:calc(100vh - 52px)}.content::before{display:none}.page-title{font-size:18px}.stat-grid{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:10px}.stat-value{font-size:20px}.stat-label{font-size:9px}.two-col{grid-template-columns:1fr}.host-detail-wrap{grid-template-columns:1fr}.table-card{overflow-x:auto;-webkit-overflow-scrolling:touch}.data-table{min-width:680px}.search-bar{width:100%}.view-header{flex-direction:column;align-items:flex-start;gap:8px}.view-header h1{font-size:16px}.map-wrap{height:calc(100vh - 160px)}.map-legend{flex-wrap:wrap;gap:6px;font-size:9px}.map-filter-bar{flex-wrap:wrap}.finding-meta{flex-direction:column;gap:4px}.detail-grid{grid-template-columns:1fr}.ip-detail-panel{font-size:11px}.rec-card{flex-direction:column;gap:6px}.tldr-bar{flex-direction:column;gap:6px}.card{padding:12px;border-radius:10px}.finding-card{padding:10px}.btn{font-size:10px;padding:4px 8px}}@media(max-width:480px){.stat-grid{grid-template-columns:1fr}.data-table{min-width:560px;font-size:11px}.content{padding:8px 6px}}';

_CSS += '.mobile-topbar{display:none}.mobile-backdrop{display:none}.stats-two-col>.card{min-width:0;width:100%;overflow:hidden}.stats-panel-card .data-table{min-width:0}.stats-chart-row{display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding-top:10px;width:100%;min-width:0}.stats-chart-legend{flex:1;min-width:0}.stats-chart-legend>div{max-width:100%}@media(max-width:768px){.mobile-topbar{display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid var(--border);background:rgba(6,11,24,.98);position:sticky;top:0;z-index:35}.mobile-menu-btn{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:8px;border:1px solid var(--border);background:rgba(98,232,255,.1);color:var(--text);font-size:18px;cursor:pointer}.mobile-topbar-title{font-size:13px;font-weight:700;color:var(--accent);letter-spacing:.04em;text-transform:uppercase}.sidebar{position:fixed;top:0;left:0;bottom:0;width:min(82vw,300px);min-width:0;max-width:300px;transform:translateX(-102%);transition:transform .2s ease;z-index:45;border-right:1px solid var(--border);border-bottom:none;display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden}.app.mobile-menu-open .sidebar{transform:translateX(0)}.mobile-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:40}.app.mobile-menu-open .mobile-backdrop{display:block}.sidebar .brand{display:flex}.sidebar .brand-tagline{display:block}.sidebar .nav-list{display:block;overflow:visible;padding:6px 0}.sidebar .nav-item{display:flex;flex-direction:row;gap:9px;padding:9px 14px;font-size:12px;border-bottom:none;border-left:3px solid transparent;white-space:normal}.sidebar .nav-item.active{border-bottom-color:transparent;border-left-color:var(--accent)}.sidebar .nav-label{font-size:12px}.sidebar .sidebar-status{display:flex}.content{height:auto;min-height:0;flex:1}.stats-chart-row{gap:12px}.stats-chart-row svg{max-width:100%}.stats-chart-legend{width:100%;max-height:none}.stats-two-col>.card{margin-bottom:0}.stats-panel-card .data-table{min-width:0}}';  
_CSS += '.sidebar-copy{padding:0 14px 10px;font-size:9px;color:var(--muted);opacity:.75}.sidebar-copy a{color:inherit;text-decoration:none}.sidebar-copy a:hover{color:var(--accent);text-decoration:underline}@media(max-width:768px){.sidebar-copy{display:block;padding:0 14px 12px;font-size:10px}}';

_CSS += '.nav-list{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden}.sidebar-status,.sidebar-copy{flex:0 0 auto}.sidebar-copy{border-top:1px solid rgba(98,232,255,.08);padding-top:8px}';

_CSS += '@media(max-width:420px){.mobile-topbar{padding:8px 10px;gap:8px}.mobile-menu-btn{width:30px;height:30px;font-size:16px;border-radius:7px}.mobile-topbar-title{font-size:12px;letter-spacing:.02em}.sidebar{width:min(90vw,280px);max-width:280px}.sidebar .brand{padding:14px 12px 10px}.sidebar .nav-item{padding:8px 12px;font-size:11px;gap:8px}.sidebar .nav-label{font-size:11px}.content{padding:8px 8px}.page-title{font-size:16px}.card{padding:10px;border-radius:9px}.card-title{font-size:10px;line-height:1.35;word-break:break-word}.stats-two-col{gap:10px!important}.stats-panel-card .data-table{font-size:10px}.stats-panel-card .data-table th,.stats-panel-card .data-table td{padding:6px 7px}.stats-chart-row{gap:10px}.stats-chart-legend{font-size:10px;line-height:1.4}.stats-chart-legend .row-gap{gap:6px;flex-wrap:wrap}.stats-chart-row svg{width:112px;height:112px}}@media(max-width:360px){.mobile-topbar{padding:7px 8px}.mobile-topbar-title{font-size:11px}.sidebar{width:min(92vw,260px);max-width:260px}.content{padding:7px 6px}.card{padding:9px}.stats-panel-card .data-table{font-size:9px}.stats-panel-card .data-table th,.stats-panel-card .data-table td{padding:5px 6px}}';

customElements.define('homesec-panel', HomeSecurityAssistantPanel);
