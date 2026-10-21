// Overview view and the baseline cards.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, nothing, svg } from "lit";
import { joinTemplates } from "../templates.js";

export const overviewMethods = {
  _viewOverview() {
    var _BL_ONLY_OV = {
      anomaly_new_host: 1,
      anomaly_new_peer: 1,
      anomaly_new_port: 1,
      anomaly_new_dns_domain: 1,
      anomaly_new_dns_category: 1
    };
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var baselineEnabledRaw = this._data && this._data.baseline_enabled;
    var baselineEnabled = baselineEnabledRaw === true || baselineEnabledRaw === 'true' || baselineEnabledRaw === 1 || baselineEnabledRaw === '1';
    var s = this._data && this._data.summary || {};
    var findings = (this._data && this._data.findings || []).filter(function (f) {
      return !_BL_ONLY_OV[f.category];
    });
    var dismissed = (this._data && this._data.dismissed_findings || []).filter(function (f) {
      return !_BL_ONLY_OV[f.category];
    });
    var dismissedVulns = dismissed.filter(function (f) {
      return f.category === 'vulnerability';
    }).length;
    var recent = findings.slice(0, 5);
    var exporters = s.exporters || [];
    var totalDatagrams = s.total_datagrams || 0;
    var parsed = s.parsed_datagrams || 0;
    var dropped = s.dropped_datagrams || 0;
    var pct = totalDatagrams > 0 ? Math.round(parsed / totalDatagrams * 100) : 0;
    var self = this;
    var findingsLabel = html`${this._t('overview.active_findings', 'Active Findings')}${dismissed.length ? html` <span class="dim" style="font-size:10px;text-transform:none">(${dismissed.length} ${this._t('overview.dismissed', 'dismissed')})</span>` : ''}`;
    var cvesLabel = html`${this._t('overview.active_cves', 'Active CVEs')}${dismissedVulns ? html` <span class="dim" style="font-size:10px;text-transform:none">(${dismissedVulns} ${this._t('overview.dismissed', 'dismissed')})</span>` : ''}`;
    var nvdTs = this._data && this._data.nvd_last_updated;
    var nvdTtl = this._data && this._data.nvd_ttl_hours != null ? this._data.nvd_ttl_hours + '\u00a0h' : '\u2014';
    var nvdTotalCves = this._data && this._data.nvd_total_cves != null ? this._data.nvd_total_cves : 0;
    var nvdMinYear = this._data && this._data.nvd_min_year != null ? this._data.nvd_min_year : null;
    var nvdAge = nvdTs ? this._ago(nvdTs) : this._t('overview.never_fetched', 'never fetched');
    var nvdStatus = nvdTs ? Date.now() - new Date(nvdTs).getTime() < 26 * 3600 * 1000 ? 'good' : 'warn' : 'warn';
  
    // Suricata stats for overview cards
    var suricataEnabledOv = this._data && this._data.suricata_stats && this._data.suricata_stats.running || false;
    var suricataStatsOv = this._data && this._data.suricata_stats || {};
    var suricataLogOv = this._data && this._data.suricata_log || [];
    var suricataTotalOv = suricataLogOv.length;
    var suricataCritOv = suricataLogOv.filter(function (e) {
      return e.severity === 1;
    }).length;
  
    // Baseline card
    var baseline = this._data && this._data.baseline || {};
    var baselineMode = baseline.mode || 'disabled';
    var baselineModeLabel = baselineMode === 'training' ? this._t('overview.baseline_learning', 'Learning') : baselineMode === 'active' ? this._t('overview.baseline_active', 'Active') : this._t('overview.baseline_disabled', 'Disabled');
    var baselineIcon = baselineMode === 'training' ? '🧠' : baselineMode === 'active' ? '✅' : '⏸';
    var sinceStr = baseline.baseline_completed_at ? self._ago(baseline.baseline_completed_at) : '';
    var trainingElapsed = '';
    if (baselineMode === 'training') {
      var started = baseline.training_started_at;
      var ends = baseline.training_ends_at;
      var now = Date.now();
      var startMs = started ? new Date(started).getTime() : null;
      var endMs = ends ? new Date(ends).getTime() : null;
      var elapsed = startMs ? Math.max(0, Math.min(now, endMs || now) - startMs) : 0;
      var trainingTotalMs = endMs && startMs ? endMs - startMs : null;
      var trainingPct = trainingTotalMs ? Math.round(elapsed / trainingTotalMs * 100) : 0;
      trainingElapsed = html`<div><span style="font-size:13px">${self._t('overview.elapsed', 'Elapsed')}: <b>${self._ago(started)}</b></span>${trainingTotalMs ? html` &nbsp; <span style="font-size:13px">${self._t('overview.progress', 'Progress')}: <b>${trainingPct}%</b></span>` : ''}</div>`;
    }
    // Action buttons
    var btns = [];
    btns.push(html`<button class="btn" data-baseline-action="start">${this._t('overview.btn_start_training', 'Start Training')}</button>`);
    btns.push(html`<button class="btn" data-baseline-action="stop">${this._t('overview.btn_stop_training', 'Stop Training')}</button>`);
    btns.push(html`<button class="btn" data-baseline-action="retrain">${this._t('overview.btn_retrain', 'Retrain')}</button>`);
    btns.push(html`<button class="btn" data-baseline-action="clear">${this._t('overview.btn_clear', 'Clear')}</button>`);
    var baselineCard = html`<div class="card" id="baseline-card" style="margin-bottom:12px${this._baselineWorking ? ';position:relative' : ''}">${this._baselineWorking ? html`<div id="baseline-working-overlay" style="position:absolute;inset:0;background:rgba(0,0,0,0.45);border-radius:inherit;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;z-index:10"><div style="width:32px;height:32px;border:3px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite"></div><div style="color:#fff;font-size:13px;font-weight:600">${this._baselineWorking}…</div></div>` : nothing}<div class="card-title">${this._t('overview.baseline_title', 'Baseline')} <span style="font-size:18px;margin-left:6px">${baselineIcon}</span></div><div style="margin-bottom:6px"><b>${this._t('overview.mode_label', 'Mode')}:</b> ${baselineModeLabel}</div>${baselineMode === 'training' ? trainingElapsed : ''}${baselineMode === 'active' && sinceStr ? html`<div><b>${this._t('overview.baseline_created_label', 'Baseline created')}:</b> ${sinceStr}</div>` : ''}<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">${btns}</div></div>`;
    return html`<div><div class="page-header"><h1 class="page-title">${this._t('page.overview', 'Overview')}</h1></div><div class="stat-grid">${this._stat(s.devices || 0, this._t('overview.stat_devices', 'Devices'), 'success')}${this._stat((this._data && this._data.scan_hosts_found) != null ? this._data.scan_hosts_found : s.scanned_devices || 0, this._t('overview.stat_scanned', 'Scanned'), '')}${this._stat(s.findings || 0, findingsLabel, (s.findings || 0) > 0 ? 'danger' : '')}${this._stat(s.vulnerability_count || 0, cvesLabel, (s.vulnerability_count || 0) > 0 ? 'warn' : '')}${this._stat(nvdTotalCves, html`${this._t('overview.stat_nvd_cves', 'NVD CVEs')}${nvdMinYear ? html` <span class="dim" style="font-size:10px;text-transform:none">(≥ ${nvdMinYear})</span>` : ''}`, '')}${this._stat(this._data && this._data.kev_total || 0, this._t('overview.stat_cisa_kev', 'CISA KEV'), '')}${this._stat(this._fmtN(s.total_flows || 0), this._t('overview.stat_flows', 'Flows'), '')}${this._stat(exporters.length, this._t('overview.stat_exporters', 'Exporters'), exporters.length > 0 ? 'success' : 'warn')}${suricataEnabledOv ? [this._stat(suricataTotalOv, this._t('overview.stat_suricata_alerts', 'Suricata Alerts'), suricataTotalOv > 0 ? 'warn' : ''), this._stat(suricataCritOv, this._t('overview.stat_critical_alerts', 'Critical Alerts'), suricataCritOv > 0 ? 'danger' : '')] : ''}</div><div class="two-col">${netflowEnabled ? html`<div class="card"><div class="card-title">${this._t('overview.netflow_title', 'NetFlow Listener Health')}</div>${this._hrow(this._t('overview.status_label', 'Status'), function () {
      var lf = s.last_flow_at;
      if (!lf) return self._t('overview.no_flows_seen', 'No flows seen');
      var age = Date.now() - new Date(lf).getTime();
      return age < 90000 ? self._t('overview.receiving_flows', 'Receiving flows') : self._t('overview.no_flows_idle_prefix', 'No flows (idle ') + (age < 3600000 ? Math.floor(age / 60000) + 'm' : Math.floor(age / 3600000) + 'h') + ')';
    }(), function () {
      var lf = s.last_flow_at;
      return lf && Date.now() - new Date(lf).getTime() < 90000 ? 'good' : 'warn';
    }())}${this._hrow(this._t('overview.uptime_label', 'Uptime'), this._uptime(s.collector_started_at), '')}${this._hrow(this._t('overview.exporters_label', 'Exporters'), exporters.join(', ') || '\u2014', '')}${this._hrow(this._t('overview.flow_versions', 'Flow versions'), (s.versions_seen || []).join(', ') || '\u2014', '')}${this._hrow(this._t('overview.total_datagrams', 'Total datagrams'), totalDatagrams.toLocaleString(), '')}${this._hrow(this._t('overview.parsed', 'Parsed'), parsed.toLocaleString() + ' (' + pct + '%)', pct > 90 ? 'good' : pct > 50 ? 'warn' : 'bad')}${this._hrow(this._t('overview.dropped', 'Dropped'), dropped.toLocaleString(), dropped > 0 ? 'warn' : 'good')}${this._hrow(this._t('overview.last_flow', 'Last flow'), this._ago(s.last_flow_at), '')}${s.last_parser_error ? this._hrow(this._t('overview.last_error', 'Last error'), s.last_parser_error, 'bad') : ''}<div style="margin-top:10px"><button class="btn" data-view="statistics">${this._t('overview.view_statistics', 'View Statistics \u2192')}</button></div></div>` : ''}<div class="card" style=${!netflowEnabled ? 'grid-column:1/-1' : nothing}><div class="card-title">${this._t('overview.recent_alerts', 'Recent Alerts')}</div>${recent.length === 0 ? html`<div class="empty-state"><div class="empty-icon">✓</div><p>${self._t('overview.no_active_findings', 'No active high/critical findings')}</p></div>` : recent.map(function (f) {
      return html`<div class="alert-row">${self._sev(f.severity)}<div class="alert-body"><div class="alert-sum">${f.summary}</div><div class="alert-meta"><span class="ip">${f.source_ip}</span> · ${self._ago(f.last_seen)}</div></div></div>`;
    })}${findings.length > 5 ? html`<button class="btn" style="margin-top:10px" data-view="findings">${self._t('overview.view_all_findings', 'View all findings \u2192')}</button>` : ''}</div></div>${function () {
      var scanAt = self._data && self._data.scan_last_at;
      var scanDur = self._data && self._data.scan_duration;
      var scanHosts = self._data && self._data.scan_hosts_found;
      var scanInterval = self._data && self._data.scan_interval;
      var scanResult = self._data && self._data.scan_last_status;
      var scanTargets = self._data && self._data.scan_last_targets;
      var scanAge = scanAt ? self._ago(scanAt) : self._t('overview.never', 'never');
      var scanStatus = scanAt ? Date.now() - new Date(scanAt).getTime() < (scanInterval || 300) * 2 * 1000 ? 'good' : 'warn' : 'warn';
      var durStr = scanDur != null ? scanDur < 60 ? scanDur.toFixed(1) + '\u00a0s' : (scanDur / 60).toFixed(1) + '\u00a0min' : '\u2014';
      var hostsStr = scanHosts != null ? scanHosts.toLocaleString() : '\u2014';
      var intervalStr = scanInterval != null ? scanInterval < 60 ? scanInterval + '\u00a0s' : Math.round(scanInterval / 60) + '\u00a0min' : '\u2014';
      var targetsStr = scanTargets != null ? scanTargets.toLocaleString() : '\u2014';
      var resultText = '\u2014',
        resultTone = '';
      if (scanResult === 'ok') {
        resultText = self._t('overview.scan_completed', 'Completed');
        resultTone = 'good';
      } else if (scanResult === 'no_targets') {
        resultText = self._t('overview.scan_skipped', 'Skipped \u2014 no targets discovered yet');
        resultTone = 'warn';
      }
      return html`<div class="card" style="margin-top:12px"><div class="card-title">${self._t('overview.active_scan_title', 'Active Scan')}</div>${self._hrow(self._t('overview.last_scan', 'Last scan'), scanAge, scanStatus)}${self._hrow(self._t('overview.last_result', 'Last result'), resultText, resultTone)}${self._hrow(self._t('overview.duration', 'Duration'), durStr, '')}${self._hrow(self._t('overview.hosts_found', 'Hosts found'), hostsStr, scanHosts > 0 ? '' : 'warn')}${self._hrow(self._t('overview.targets_scanned', 'Targets scanned'), targetsStr, scanTargets != null && scanTargets > 0 ? '' : 'warn')}${self._hrow(self._t('overview.scan_interval', 'Scan interval'), intervalStr, '')}<div style="margin-top:10px"><button class="btn" data-service-action="trigger_scan">${self._t('overview.force_scan_btn', 'Force hosts scan \u21bb')}</button></div></div>`;
    }()}<div class="card" style="margin-top:12px"><div class="card-title">${this._t('overview.nvd_title', 'Vulnerability Intelligence (NVD)')}</div>${this._hrow(this._t('overview.last_db_fetch', 'Last database fetch'), nvdAge, nvdStatus)}${this._hrow(this._t('overview.cache_ttl', 'Cache TTL'), nvdTtl, '')}${this._hrow(this._t('overview.cves_in_db', 'CVEs in database'), nvdTotalCves.toLocaleString(), '')}${this._hrow(this._t('overview.min_pub_year', 'Min publication year'), nvdMinYear ? nvdMinYear : this._t('overview.all_years', 'All years'), '')}${function () {
      var kws = self._data && self._data.nvd_keywords || [];
      if (!kws.length) return self._hrow(self._t('overview.keywords_label', 'Keywords'), self._t('overview.none_loaded', 'None loaded yet'), 'warn');
      var configured = kws.filter(function (k) {
        return k.source === 'custom';
      });
      var dynamic = kws.filter(function (k) {
        return k.source !== 'custom';
      });
      var cfgStyle = 'background:rgba(158,150,255,.22);border-color:rgba(158,150,255,.5);color:#c4bfff';
      var dynStyle = 'background:rgba(107,255,200,.18);border-color:rgba(107,255,200,.45);color:#6bffc8';
      function renderChips(list, style) {
        return joinTemplates(list.map(function (k) {
          return html`<span class="chip" style="${style}" title="${k.keyword} · ${k.cve_count} CVEs · source: ${k.source}">${k.keyword} <span style="opacity:.55;font-size:9px">(${k.cve_count})</span></span>`;
        }), ' ');
      }
      var legend = html`<div style="display:flex;gap:14px;align-items:center;font-size:10px;color:var(--muted);margin-bottom:6px"><span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(158,150,255,.7);background:rgba(158,150,255,.35)"></span> ${self._t('overview.kw_configured', 'Configured')}</span><span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(107,255,200,.6);background:rgba(107,255,200,.3)"></span> ${self._t('overview.kw_from_scans', 'From scans')}</span></div>`;
      return html`<div class="section-label" style="margin-top:10px;margin-bottom:4px">NVD ${self._t('overview.keywords_label', 'Keywords')} (${kws.length})</div>${legend}<div style="line-height:2">${configured.length ? renderChips(configured, cfgStyle) : ''}${configured.length && dynamic.length ? ' ' : ''}${dynamic.length ? renderChips(dynamic, dynStyle) : ''}</div>`;
    }()}<div style="margin-top:10px"><button class="btn" data-view="vulnerabilities">${this._t('overview.browse_vulns_btn', 'Browse all vulnerabilities \u2192')}</button> <button class="btn" data-service-action="nvd_refresh">${this._t('overview.force_nvd_refresh_btn', 'Force intelligence refresh \u21bb')}</button></div></div>${function () {
      var kevTotal = self._data && self._data.kev_total != null ? self._data.kev_total : 0;
      var kevTs = self._data && self._data.kev_last_updated;
      var kevTtl = self._data && self._data.kev_ttl_hours != null ? self._data.kev_ttl_hours + '\u00a0h' : '\u2014';
      var kevAge = kevTs ? self._ago(kevTs) : self._t('overview.never_fetched', 'never fetched');
      var kevStatus = kevTs ? Date.now() - new Date(kevTs).getTime() < 26 * 3600 * 1000 ? 'good' : 'warn' : 'warn';
      return html`<div class="card"><div class="card-title">${self._t('overview.kev_title', 'CISA Known Exploited Vulnerabilities (KEV)')}</div>${self._hrow(self._t('overview.last_catalog_fetch', 'Last catalog fetch'), kevAge, kevStatus)}${self._hrow(self._t('overview.cache_ttl', 'Cache TTL'), kevTtl, '')}${self._hrow(self._t('overview.catalog_size', 'Catalog size'), kevTotal.toLocaleString(), kevTotal > 0 ? '' : 'warn')}</div>`;
    }()}${function () {
      var dnsStats = self._data && self._data.dns_proxy_stats || {};
      var dnsLog = self._data && self._data.dns_log || [];
      var bs = self._data && self._data.blacklist_stats || {};
      var dnsRunning = dnsStats.running || false;
      if (!dnsRunning) return '';
      var dnsMal = dnsLog.filter(function (e) {
        return e.malicious;
      }).length;
      var dnsTotal = dnsStats.total_queries != null ? dnsStats.total_queries : dnsLog.length;
      var blDomains = bs.bad_domains || 0;
      var blIPs = bs.bad_ips || 0;
      var blTotal = blDomains + blIPs;
      var blLoaded = blTotal > 0;
      var blParts = [];
      if (blDomains > 0) blParts.push(blDomains.toLocaleString() + ' ' + self._t('overview.dns_domains', 'domains'));
      if (blIPs > 0) blParts.push(blIPs.toLocaleString() + ' IPs');
      var blLabel = blLoaded ? blParts.join(' + ') + ' ' + self._t('overview.dns_blocked_suffix', 'blocked') : bs.last_refresh ? self._t('overview.dns_bl_empty', '0 entries \u2014 check URLs') : self._t('overview.dns_bl_downloading', 'Downloading\u2026');
      var blStatus = blLoaded ? 'good' : bs.last_refresh ? 'bad' : '';
      return html`<div class="card" style="margin-top:12px"><div class="card-title">${self._t('overview.dns_proxy_title', 'DNS Proxy')}</div>${self._hrow(self._t('overview.status_label', 'Status'), self._t('overview.dns_running', 'Running'), 'good')}${self._hrow(self._t('overview.port_label', 'Port'), String(dnsStats.port || '\u2014'), '')}${self._hrow(self._t('overview.upstream_label', 'Upstream'), String(dnsStats.upstream || '\u2014'), '')}${self._hrow(self._t('overview.blocklist_label', 'Blocklist'), blLabel, blStatus)}${bs.last_refresh ? self._hrow(self._t('overview.last_refreshed', 'Last refreshed'), self._ago(bs.last_refresh), '') : ''}${self._hrow(self._t('overview.queries_in_log', 'Queries in log'), dnsLog.length.toLocaleString(), '')}${self._hrow(self._t('overview.malicious_queries', 'Malicious queries'), dnsMal.toLocaleString(), dnsMal > 0 ? 'bad' : 'good')}${function () {
        var dnsBlocked = dnsLog.filter(function (e) {
          return e.status === 'blocked';
        }).length;
        return dnsBlocked > 0 ? self._hrow(self._t('overview.blocked_queries', 'Blocked queries'), dnsBlocked.toLocaleString(), 'bad') : '';
      }()}<div style="margin-top:10px"><button class="btn" data-view="dns">${self._t('overview.view_dns_btn', 'View DNS Queries \u2192')}</button></div></div>`;
    }()}${function () {
      if (!suricataEnabledOv) return '';
      var sStats = suricataStatsOv;
      var sLog = suricataLogOv;
      var sRunning = sStats.running || false;
      var sPort = sStats.port || '\u2014';
      var sUptime = sStats.started_at ? self._uptime(sStats.started_at) : '\u2014';
      var sExporters = sStats.exporter_ips && sStats.exporter_ips.length ? sStats.exporter_ips.join(', ') : '\u2014';
      var sTotal = sLog.length;
      var sCrit = sLog.filter(function (e) {
        return e.severity === 1;
      }).length;
      var sConns = sStats.active_connections != null ? sStats.active_connections : 0;
      return html`<div class="card" style="margin-top:12px"><div class="card-title">${self._t('overview.suricata_listener_title', 'Suricata Alert Listener')}</div>${self._hrow(self._t('overview.status_label', 'Status'), sRunning ? self._t('overview.suricata_active', 'Active') : self._t('overview.suricata_inactive', 'Inactive'), sRunning ? 'good' : 'warn')}${self._hrow(self._t('overview.port_label', 'Port'), String(sPort), '')}${self._hrow(self._t('overview.uptime_label', 'Uptime'), sUptime, '')}${self._hrow(self._t('overview.exporter_ips_label', 'Exporter IP(s)'), sExporters, sConns > 0 ? 'good' : '')}${self._hrow(self._t('overview.active_connections', 'Active connections'), String(sConns), sConns > 0 ? 'good' : '')}${self._hrow(self._t('overview.alerts_in_log', 'Alerts in log'), sTotal.toLocaleString(), sTotal > 0 ? 'warn' : 'good')}${self._hrow(self._t('overview.critical_alerts_label', 'Critical alerts'), sCrit.toLocaleString(), sCrit > 0 ? 'bad' : 'good')}<div style="margin-top:10px"><button class="btn" data-view="suricata">${self._t('overview.view_suricata_btn', 'View Suricata Alerts \u2192')}</button></div></div>`;
    }()}${baselineEnabled ? [baselineCard, self._baselineDevianceCard()] : ''}</div>`;
  },

  // ── Baseline deviance score card ─────────────────────────────────────
  _baselineDevianceCard() {
    var self = this;
    var baseline = this._data && this._data.baseline || {};
    if ((baseline.mode || 'disabled') !== 'active') return '';
    var baselineGraph = this._data && this._data.baseline_graph || null;
    if (!baselineGraph || !(baselineGraph.edges && baselineGraph.edges.length)) return '';
    var connections = this._data && this._data.connections || [];
  
    // Build edge indices (same logic as _composeMapEdges but mode-neutral)
    var live = this._buildLiveEdgeIndex(connections);
    var base = this._buildBaselineEdgeIndex(baselineGraph);
    var keys = {};
    Object.keys(live).forEach(function (k) {
      keys[k] = true;
    });
    Object.keys(base).forEach(function (k) {
      keys[k] = true;
    });
    var cntNew = 0,
      cntMissing = 0,
      cntBoth = 0;
    var topDelta = null,
      topDeltaAbs = 0;
    for (var key in keys) {
      var le = live[key];
      var be = base[key];
      if (le && be) {
        cntBoth++;
        var d = (le.live_flows || 0) - (be.avg_flows || 0);
        if (Math.abs(d) > topDeltaAbs) {
          topDeltaAbs = Math.abs(d);
          topDelta = {
            source: le.source,
            target: le.target,
            delta: d
          };
        }
      } else if (le && !be) {
        cntNew++;
      } else {
        cntMissing++;
      }
    }
  
    // ── Score (0-100) ────────────────────────────────────────────────
    // New connections are the primary security signal (weight 80%).
    // Missing connections are expected in any snapshot vs. the full training
    // period, so they only contribute 20% to keep the score fair.
    var activeLive = cntNew + cntBoth;
    var totalKnown = cntBoth + cntMissing;
    var newRatio = activeLive > 0 ? cntNew / activeLive : 0;
    var missingRatio = totalKnown > 0 ? cntMissing / totalKnown : 0;
    var score = Math.min(100, Math.round(newRatio * 80 + missingRatio * 20));
  
    // ── Band ─────────────────────────────────────────────────────────
    var band, bandColor, bandBg, bandBorder, bandDesc;
    if (score <= 20) {
      band = this._t('overview.band_normal', 'Normal');
      bandColor = '#3ddc84';
      bandBg = 'rgba(61,220,132,.10)';
      bandBorder = 'rgba(61,220,132,.35)';
      bandDesc = this._t('overview.band_desc_normal', 'Traffic closely matches your baseline. No action needed.');
    } else if (score <= 50) {
      band = this._t('overview.band_review', 'Review');
      bandColor = '#ffce54';
      bandBg = 'rgba(255,206,84,.10)';
      bandBorder = 'rgba(255,206,84,.35)';
      bandDesc = this._t('overview.band_desc_review', 'Some deviation from baseline detected. Worth a quick look.');
    } else if (score <= 75) {
      band = this._t('overview.band_investigate', 'Investigate');
      bandColor = '#ff9640';
      bandBg = 'rgba(255,150,64,.10)';
      bandBorder = 'rgba(255,150,64,.35)';
      bandDesc = this._t('overview.band_desc_investigate', 'Noticeable deviation from baseline. Review unexpected connections.');
    } else {
      band = this._t('overview.band_critical', 'Critical');
      bandColor = '#ff5a32';
      bandBg = 'rgba(255,90,50,.10)';
      bandBorder = 'rgba(255,90,50,.40)';
      bandDesc = this._t('overview.band_desc_critical', 'Significant deviation from baseline. Investigate immediately.');
    }
  
    // ── Progress bar ─────────────────────────────────────────────────
    var barFill = score <= 20 ? '#3ddc84' : score <= 50 ? '#ffce54' : score <= 75 ? '#ff9640' : '#ff5a32';
  
    // ── Row helpers ──────────────────────────────────────────────────
    function row(icon, count, label, note, iconColor) {
      return html`<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span style="font-size:16px;line-height:1.2;flex-shrink:0;color:${iconColor}">${icon}</span><div style="flex:1;min-width:0"><span style="font-size:14px;font-weight:600;color:${iconColor}">${count}</span> <span style="font-size:12px;color:var(--fg)">${label}</span><div style="font-size:11px;color:var(--muted);margin-top:1px">${note}</div></div></div>`;
    }
  
    // ── Top-delta plain English ──────────────────────────────────────
    var topDeltaHtml = '';
    if (topDelta) {
      var d = topDelta.delta;
      var abs = Math.abs(d);
      var dirKey = d > 0 ? 'busier' : 'quieter';
      var magKey = abs > 10000 ? 'far' : abs > 1000 ? 'noticeably' : abs > 100 ? 'somewhat' : 'slightly';
      var trafficMagDir = self._t('overview.traffic_' + magKey + '_' + dirKey, magKey + ' ' + dirKey);
      var sign = d > 0 ? '+' : '';
      topDeltaHtml = html`<div style="margin-top:10px;padding:8px 10px;border-radius:8px;background:rgba(255,206,84,.07);border:1px solid rgba(255,206,84,.22);font-size:11px"><span style="color:#ffce54;font-weight:600">${self._t('overview.biggest_traffic_change', '\u0394 Biggest traffic change')}</span><div style="margin-top:3px;color:var(--fg)"><span style="font-family:monospace;font-size:11px">${topDelta.source} → ${topDelta.target}</span></div><div style="color:var(--muted);margin-top:2px">${self._t('overview.traffic_change_pre', 'This known connection is')} <b style="color:var(--fg)">${trafficMagDir}</b> ${self._t('overview.traffic_change_mid', 'than usual')} (${sign}${Math.round(d)} ${self._t('overview.traffic_change_post', 'flows/snapshot).')}${abs > 1000 ? ' ' + self._t('overview.traffic_change_file_hint', 'Could be a file transfer, backup, or update in progress.') : ''}</div></div>`;
    }
    return html`<div class="card" style="margin-top:12px"><div class="card-title">${this._t('overview.network_behaviour_title', 'Network Behaviour')}</div><div style="display:flex;align-items:center;gap:14px;margin-bottom:10px"><div style="position:relative;flex-shrink:0"><svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="26" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="7"/><circle cx="32" cy="32" r="26" fill="none" stroke="${barFill}" stroke-width="7" stroke-dasharray="163.4" stroke-dashoffset="${(163.4 * (1 - score / 100)).toFixed(1)}" stroke-linecap="round" transform="rotate(-90 32 32)"/><text x="32" y="37" text-anchor="middle" font-size="14" font-weight="700" fill="${barFill}">${score}</text></svg></div><div style="flex:1"><div style="display:inline-block;padding:3px 12px;border-radius:100px;background:${bandBg};border:1px solid ${bandBorder};color:${bandColor};font-size:12px;font-weight:600;margin-bottom:5px">${band}</div><div style="font-size:12px;color:var(--muted)">${bandDesc}</div></div></div>${
    // Breakdown rows
    row('\u2191', cntNew, cntNew === 1 ? self._t('overview.new_conn_single', 'unexpected new connection') : self._t('overview.new_conn_plural', 'unexpected new connections'), cntNew === 0 ? self._t('overview.new_conn_note_none', 'No unknown activity \u2014 all current traffic was seen during training.') : self._t('overview.new_conn_note_some', 'These connections were not present during baseline training.') + ' ' + (cntNew > 5 ? self._t('overview.new_conn_note_investigate', 'This is the main driver of your score \u2014 investigate.') : self._t('overview.new_conn_note_review', 'Review to confirm they are expected.')), cntNew === 0 ? '#3ddc84' : cntNew <= 3 ? '#ffce54' : '#ff5a32')}${row('\u2193', cntMissing, cntMissing === 1 ? self._t('overview.missing_conn_single', 'baseline connection not active now') : self._t('overview.missing_conn_plural', 'baseline connections not active now'), self._t('overview.missing_conn_note', 'Connections seen during training that are quiet right now. This is usually normal \u2014 devices don\u2019t maintain all connections at all times.') + ' ' + (cntMissing > totalKnown * 0.9 ? self._t('overview.missing_conn_note_high', 'The count is very high, but your baseline likely captured many short-lived flows over a long training window.') : ''), '#88a7c7')}${row('=', cntBoth, cntBoth === 1 ? self._t('overview.both_conn_single', 'connection matches baseline exactly') : self._t('overview.both_conn_plural', 'connections match baseline exactly'), cntBoth > 0 ? self._t('overview.both_conn_note_some', 'These connections are active now and were seen during training \u2014 your expected, normal traffic.') : self._t('overview.both_conn_note_none', 'No currently active connections were seen in the baseline yet.'), '#3ac5c9')}${topDeltaHtml}<div style="margin-top:10px"><button class="btn" data-view="map" data-map-mode="compare">${self._t('overview.view_map_btn', 'View on Network Map \u2192')}</button></div></div>`;
  }
};
