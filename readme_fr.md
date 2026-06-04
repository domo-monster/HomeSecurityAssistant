Security Assistant

Security Assistant est une intégration personnalisée Home Assistant pour la
surveillance de sécurité du réseau domestique. Elle combine l'analyse passive
du trafic NetFlow/IPFIX, le scan actif des hôtes, la vérification DNS via
listes de menace, l'enrichissement des IP externes et la visibilité CVE dans
un tableau de bord latéral unique.

Site web
- https://domotic.monster/homesec.html

Dépôt GitHub
- https://github.com/domo-monster/HomeSecurityAssistant

Documentation par langue
- Anglais : https://domotic.monster/homesec.html
- Français : https://domotic.monster/homesec_fr.html
- Allemand : https://domotic.monster/homesec_de.html

Version
- 0.9.1

Fonctionnalités principales
- Écoute NetFlow v5/v9/IPFIX avec classification du trafic interne/externe.
- Scanner actif (optionnel) : disponibilité des hôtes, ports ouverts,
  services détectés, empreintes légères.
- Renseignement IP externe via ipwho.is (par défaut), VirusTotal et AbuseIPDB
  en option.
- Fonctionnalités DNS proxy + blacklist avec journalisation des requêtes.
- Visibilité des vulnérabilités avec NVD et corrélation CISA KEV.
- Findings, recommandations et détection d'anomalies via baseline.
- Panneau frontend multi-vues : Overview, Network Map, Hosts, Findings,
  External IPs, Vulnerabilities, Statistics, DNS, Suricata,
  Recommendations, Settings.

Nouveautés 0.9.1
- Application des options en place (moins de rechargements complets perturbants).
- Enregistrement des paramètres en mode non bloquant.
- Journaux de timing démarrage/rechargement pour profiler les lenteurs.
- Carte de liens en bas de la page Settings (GitHub + documentation selon langue).
- Lien copyright latéral mis à jour vers https://domotic.monster.
- Correction du lien deep-link HACS dans le README principal.
- Ajout de visuels Suricata dans les sections de documentation.
- Ajout de l'option de visibilité du panneau sidebar pour les non-admins dans Settings.
- Localisation française du frontend (menu, page Settings, en-têtes de vues).

Visuels du baseline
- Comparaison Live vs Baseline :

  ![Live vs Baseline](custom_components/homesec/hsa_baseline_comparison.png)


  ![Deviation baseline](custom_components/homesec/hsa_baseline_deviation.png)

Suricata - Flux des alertes
- **Écouteur d'alertes Suricata EVE** - Home Security Assistant peut recevoir les alertes Suricata via TCP et les intégrer au tableau de bord latéral ainsi qu'au journal d'alertes.
- **Script d'envoi accompagné** - le script `suricata_pusher.py` fourni lit en continu le fichier JSON EVE de Suricata et envoie chaque ligne d'alerte au listener.
- **Visibilité des alertes** - les alertes Suricata apparaissent dans le tableau de bord latéral et sont conservées avec les autres journaux d'exécution après redémarrage.

Visuels Suricata
- Vue d'ensemble :

  ![Suricata overview](custom_components/homesec/hsa_suricata_ov.png)

- Liste d'alertes :

  ![Suricata alerts](custom_components/homesec/hsa_suricata_alerts.png)

- Statistiques :

  ![Suricata stats](custom_components/homesec/hsa_suricata_stats.png)

Installation (HACS)
1. Ouvrir HACS -> Integrations -> Custom Repositories.
2. Ajouter : https://github.com/domo-monster/HomeSecurityAssistant
3. Installer Security Assistant.
4. Redémarrer Home Assistant.
5. Ajouter l'intégration dans Settings -> Devices & Services.

Installation manuelle
1. Copier custom_components/homesec dans custom_components de Home Assistant.
2. Redémarrer Home Assistant.
3. Ajouter l'intégration dans Settings -> Devices & Services.

Services principaux
- homesec.trigger_scan
- homesec.nvd_refresh
- homesec.blacklist_refresh
- homesec.start_baseline_training
- homesec.stop_baseline_training
- homesec.retrain_baseline
- homesec.clear_baseline

Notes importantes
- L'analyse de flux repose sur des métadonnées (pas d'inspection complète du payload).
- Les empreintes et rôles sont heuristiques.
- La qualité d'enrichissement externe dépend des clés API optionnelles.

Fichiers persistants
L'intégration stocke état et configuration en YAML dans /config, notamment
homesec.yaml, homesec_hosts.yaml, homesec_dns_log.yaml, homesec_ext_ips.yaml,
homesec_baseline.yaml et fichiers associés.

Historique des versions
- Voir changelog.txt dans ce dépôt.