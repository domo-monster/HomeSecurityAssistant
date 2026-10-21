// Findings view, dismiss actions and the regex-dismiss modal.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, nothing } from "lit";
import { joinTemplates } from "../templates.js";

export const findingsMethods = {
  _viewFindings() {
    // Categories that belong exclusively to Baseline Anomalies
    var BASELINE_ONLY_CATS = {
      anomaly_new_host: true,
      anomaly_new_peer: true,
      anomaly_new_port: true,
      anomaly_new_dns_domain: true,
      anomaly_new_dns_category: true
    };
    var findings = (this._data && this._data.findings || []).filter(function (f) {
      return !BASELINE_ONLY_CATS[f.category];
    });
    var baselineAnomalies = this._data && this._data.baseline_anomalies || [];
    var allDismissed = this._data && this._data.dismissed_findings || [];
    // Tag every dismissed item so we know its origin; combine into one list
    var allDismissedList = allDismissed.map(function (f) {
      return Object.assign({}, f, {
        _isBaseline: !!BASELINE_ONLY_CATS[f.category]
      });
    });
    var findingsGroupMode = this._findingsGroupMode || 'category';
    var dismissedGroupMode = this._dismissedGroupMode || 'category';
    var baselineGroupMode = this._baselineGroupMode; // 'category' | 'host' | 'flat'
    var self = this;
    var SEV_ORDER = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    var _sevRank = function (s) {
      var r = SEV_ORDER[s];
      return r != null ? r : 99;
    };
  
    // ── search helpers ───────────────────────────────────────────────
    var findingsQ = (self._findingsSearch || '').toLowerCase().trim();
    var baselineQ = (self._baselineSearch || '').toLowerCase().trim();
    var dismissedQ = (self._dismissedSearch || '').toLowerCase().trim();
    var _match = function (f, q) {
      if (!q) return true;
      return (f.summary || '').toLowerCase().includes(q) || (f.source_ip || '').toLowerCase().includes(q) || (f.category || '').toLowerCase().includes(q) || (f.details && f.details.cve_id || '').toLowerCase().includes(q);
    };
    var filteredFindings = findingsQ ? findings.filter(function (f) {
      return _match(f, findingsQ);
    }) : findings;
    var filteredBaseline = baselineQ ? baselineAnomalies.filter(function (f) {
      return _match(f, baselineQ);
    }) : baselineAnomalies;
    var filteredDismissed = dismissedQ ? allDismissedList.filter(function (f) {
      return _match(f, dismissedQ);
    }) : allDismissedList;
  
    // ── Top toolbar (always at page top) ────────────────────────────
    var topBar = html`<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:14px"><div class="page-header" style="margin:0"><h1 class="page-title">${this._t('page.findings', 'Findings')}</h1></div><div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"><button class="btn" data-regex-dismiss-open title="Dismiss multiple findings by regex pattern">${this._t('findings.pattern', '🗑 Pattern…')}</button></div></div>`;
  
    // ── individual card (flat mode / dismissed) ──────────────────────
    var renderCard = function (f, isDismissed, isBaseline) {
      var det = f.details || {};
      var cve = det.cve_id ? html`<span class="chip">${det.cve_id}</span>` : '';
      var portChip = det.port ? html`<span class="chip">port ${det.port}</span>` : '';
      var detRows = joinTemplates(Object.keys(det).filter(function (k) {
        return k !== 'cve_id' && k !== 'port' && k !== 'remediation';
      }).map(function (k) {
        return html`<dt>${k}:</dt> <dd>${String(det[k])}</dd>`;
      }), ' ');
      var noteHtml = isDismissed && f.dismiss_note ? html`<div style="margin-top:5px;font-size:11px;color:var(--muted)"><strong>${self._t('findings.note', 'Note')}:</strong> ${f.dismiss_note}</div>` : '';
      var baselineBadge = isBaseline ? html`<span class="chip" style="background:#3ac5c9;color:#fff;font-size:10px;margin-left:6px">${self._t('findings.baseline_badge', 'Baseline')}</span>` : '';
      return html`<div class="finding-card sev-${f.severity}" style=${isDismissed ? 'opacity:.55' : nothing}><div class="finding-header">${self._sev(f.severity)}${cve}${portChip}<span class="finding-title">${f.summary}${baselineBadge}</span>${isDismissed ? html`<button class="btn" data-undismiss="${f.key || f.source_ip + ':' + f.category}" title="Restore finding">${self._t('findings.restore', 'Restore')}</button>` : html`<button class="btn btn-dismiss" data-dismiss="${f.key || f.source_ip + ':' + f.category}" title="Dismiss finding">${self._t('findings.dismiss', 'Dismiss')}</button>`}</div><div class="finding-meta"><span>${self._t('findings.source', 'Source')}: <span class="ip">${f.source_ip}</span></span>${det.port ? html`<span>${self._t('findings.port', 'Port')}: <strong>${det.port}</strong></span>` : ''}<span>${self._t('findings.category', 'Category')}: ${FINDING_CAT_LABELS[f.category] || f.category || ''}</span>${f.count ? html`<span>${f.count}× ${self._t('findings.seen', 'seen')}</span>` : ''}<span>${self._ago(f.last_seen)}</span></div>${detRows ? html`<div class="finding-detail"><dl>${detRows}</dl></div>` : ''}${det.remediation ? html`<div class="fix-hint">${self._t('findings.remediation', 'Remediation')}: ${det.remediation}</div>` : ''}${noteHtml}</div>`;
    };
  
    // ── grouped by summary (security findings + dismissed) ──────────
    var renderGrouped = function (findingsList, isDismissed) {
      if (!findingsList.length) return '';
      var groupMap = {};
      findingsList.forEach(function (f) {
        var gkey = f.summary || f.category || 'Unknown';
        if (!groupMap[gkey]) {
          groupMap[gkey] = {
            summary: gkey,
            findings: [],
            severity: f.severity,
            category: f.category,
            isBaseline: !!f._isBaseline
          };
        } else if (_sevRank(f.severity) < _sevRank(groupMap[gkey].severity)) {
          groupMap[gkey].severity = f.severity;
        }
        groupMap[gkey].findings.push(f);
      });
      return Object.values(groupMap).sort(function (a, b) {
        return _sevRank(a.severity) - _sevRank(b.severity);
      }).map(function (g) {
        var isExpanded = self._expandedFindingGroup === g.summary;
        var totalCount = g.findings.reduce(function (s, f) {
          return s + (f.count || 1);
        }, 0);
        var latestSeen = g.findings.reduce(function (lat, f) {
          return !lat || f.last_seen > lat ? f.last_seen : lat;
        }, '');
        var det0 = g.findings[0] && g.findings[0].details || {};
        var cve = det0.cve_id ? html`<span class="chip">${det0.cve_id}</span>` : '';
        var portChip = det0.port ? html`<span class="chip">port ${det0.port}</span>` : '';
        var countBadge = html`<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">${g.findings.length}${g.findings.length === 1 ? ' ' + self._t('findings.host_one', 'host') : ' ' + self._t('findings.host_many', 'hosts')}</span>`;
        var blBadge = g.isBaseline ? html`<span class="chip" style="background:#3ac5c9;color:#fff;font-size:9px">${self._t('findings.baseline_badge', 'Baseline')}</span>` : '';
        var chevron = html`<span class="finding-group-chevron" style="transform:rotate(${isExpanded ? '90' : '0'}deg)">▶</span>`;
        var groupActionBtn = isDismissed ? html`<button class="btn" data-undismiss-group="${g.summary}">${self._t('findings.restore', 'Restore')}${g.findings.length > 1 ? ' ' + self._t('findings.restore_all', 'all') + '\u00A0' + g.findings.length : ''}</button>` : html`<button class="btn btn-dismiss" data-dismiss-group="${g.summary}">${self._t('findings.dismiss', 'Dismiss')}${g.findings.length > 1 ? ' ' + self._t('findings.dismiss_all', 'all') + '\u00A0' + g.findings.length : ''}</button>`;
        var header = html`<div class="finding-card sev-${g.severity} finding-group-card" data-expand-group="${g.summary}"><div class="finding-header">${self._sev(g.severity)}${cve}${portChip}${countBadge}${blBadge}<span class="finding-title">${g.summary}</span>${groupActionBtn}${chevron}</div><div class="finding-meta"><span>${self._t('findings.category', 'Category')}: ${g.category || '\u2014'}</span><span>${totalCount}× ${self._t('findings.total', 'total')}</span><span>${self._t('findings.latest', 'Latest:')} ${self._ago(latestSeen)}</span></div></div>`;
        var rows = '';
        if (isExpanded) {
          rows = html`<div class="finding-group-rows">${g.findings.map(function (f) {
            var det = f.details || {};
            var detRows = joinTemplates(Object.keys(det).filter(function (k) {
              return k !== 'cve_id' && k !== 'port' && k !== 'remediation';
            }).map(function (k) {
              return html`<dt>${k}:</dt><dd>${String(det[k])}</dd>`;
            }), ' ');
            var rowActionBtn = isDismissed ? html`<button class="btn" data-undismiss="${f.key || f.source_ip + ':' + f.category}" title="Restore this finding">${self._t('findings.restore', 'Restore')}</button>` : html`<button class="btn btn-dismiss" data-dismiss="${f.key || f.source_ip + ':' + f.category}" title="Dismiss this finding">${self._t('findings.dismiss', 'Dismiss')}</button>`;
            return html`<div class="finding-row"><span class="ip">${f.source_ip || ''}</span>${det.port ? html`<span class="chip">:${det.port}</span>` : ''}<span class="dim" style="font-size:10px">${f.count || 1}× · ${self._ago(f.last_seen)}</span>${det.remediation ? html`<span style="font-size:10px;color:var(--success);flex:1">${self._t('hosts.fix', 'Fix')}: ${det.remediation}</span>` : html`<span style="flex:1"></span>`}${detRows ? html`<div class="finding-detail" style="margin:4px 0;width:100%"><dl>${detRows}</dl></div>` : ''}${rowActionBtn}</div>`;
          })}</div>`;
        }
        return html`<div class="finding-group-wrap">${header}${rows}</div>`;
      });
    };
  
    // ── baseline group renderers ─────────────────────────────────────
    // Shared expand-row builder for host/category groups
    var _baselineExpandRows = function (list) {
      return list.map(function (f) {
        var det = f.details || {};
        return html`<div class="finding-row">${self._sev(f.severity)}<span style="flex:1;font-size:12px">${f.summary}</span>${det.port ? html`<span class="chip" style="font-size:9px">:${det.port}</span>` : ''}<span class="dim" style="font-size:10px;flex-shrink:0">${self._ago(f.last_seen)}</span><button class="btn btn-dismiss" data-dismiss="${f.key || f.source_ip + ':' + f.category}" title="Dismiss">${self._t('findings.dismiss', 'Dismiss')}</button></div>`;
      });
    };
    var renderBaselineByCategory = function (list) {
      if (!list.length) return '';
      var BL_CAT_LABELS = {
        anomaly_new_host: self._t('findings.cat_new_host', 'New Host Detected'),
        anomaly_new_peer: self._t('findings.cat_new_peer', 'New External Peer'),
        anomaly_new_port: self._t('findings.cat_new_port', 'New Open Port'),
        anomaly_new_dns_domain: self._t('findings.cat_new_dns_domain', 'New DNS Domain'),
        anomaly_new_dns_category: self._t('findings.cat_new_dns_category', 'New DNS Category'),
        anomaly_missing_host: self._t('findings.cat_missing_host', 'Known Host Missing'),
        anomaly_missing_peer: self._t('findings.cat_missing_peer', 'Known Peer Missing')
      };
      var catMap = {};
      list.forEach(function (f) {
        var cat = f.category || 'unknown';
        if (!catMap[cat]) catMap[cat] = {
          category: cat,
          findings: [],
          maxSev: 'info'
        };
        if (_sevRank(f.severity) < _sevRank(catMap[cat].maxSev)) catMap[cat].maxSev = f.severity;
        catMap[cat].findings.push(f);
      });
      return Object.values(catMap).sort(function (a, b) {
        var sd = _sevRank(a.maxSev) - _sevRank(b.maxSev);
        return sd !== 0 ? sd : a.category.localeCompare(b.category);
      }).map(function (c) {
        var gkey = 'bcat:' + c.category;
        var isExpanded = self._expandedBaselineGroup === gkey;
        var latestSeen = c.findings.reduce(function (lat, f) {
          return !lat || f.last_seen > lat ? f.last_seen : lat;
        }, '');
        var uniqueHosts = {};
        c.findings.forEach(function (f) {
          uniqueHosts[f.source_ip] = true;
        });
        var hostCount = Object.keys(uniqueHosts).length;
        var countBadge = html`<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">${c.findings.length} ${c.findings.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')} · ${hostCount} ${hostCount === 1 ? self._t('findings.host_one', 'host') : self._t('findings.host_many', 'hosts')}</span>`;
        var chevron = html`<span class="finding-group-chevron" style="transform:rotate(${isExpanded ? '90' : '0'}deg)">▶</span>`;
        var dismissAllBtn = html`<button class="btn btn-dismiss" data-dismiss-group="${gkey}">${self._t('findings.dismiss_all', 'Dismiss all')} ${c.findings.length}</button>`;
        var header = html`<div class="finding-card sev-${c.maxSev} finding-group-card" data-expand-baseline-group="${gkey}"><div class="finding-header">${self._sev(c.maxSev)}${countBadge}<span class="finding-title">${BL_CAT_LABELS[c.category] || c.category}</span>${dismissAllBtn}${chevron}</div><div class="finding-meta"><span>${self._t('findings.latest', 'Latest:')} ${self._ago(latestSeen)}</span></div></div>`;
        var sortedByCategory = c.findings.slice().sort(function (a, b) {
          return _sevRank(a.severity) - _sevRank(b.severity);
        });
        var rows = isExpanded ? html`<div class="finding-group-rows">${_baselineExpandRows(sortedByCategory)}</div>` : '';
        return html`<div class="finding-group-wrap">${header}${rows}</div>`;
      });
    };
    var renderBaselineByHost = function (list) {
      if (!list.length) return '';
      var hostMap = {};
      list.forEach(function (f) {
        var ip = f.source_ip || 'unknown';
        if (!hostMap[ip]) hostMap[ip] = {
          ip: ip,
          findings: [],
          maxSev: 'info'
        };
        if (_sevRank(f.severity) < _sevRank(hostMap[ip].maxSev)) hostMap[ip].maxSev = f.severity;
        hostMap[ip].findings.push(f);
      });
      return Object.values(hostMap).sort(function (a, b) {
        var sd = _sevRank(a.maxSev) - _sevRank(b.maxSev);
        if (sd !== 0) return sd;
        return a.ip.split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.').localeCompare(b.ip.split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.'));
      }).map(function (h) {
        var gkey = 'bhost:' + h.ip;
        var isExpanded = self._expandedBaselineGroup === gkey;
        var latestSeen = h.findings.reduce(function (lat, f) {
          return !lat || f.last_seen > lat ? f.last_seen : lat;
        }, '');
        var catCounts = {};
        h.findings.forEach(function (f) {
          catCounts[f.category] = (catCounts[f.category] || 0) + 1;
        });
        var catChips = joinTemplates(Object.keys(catCounts).slice(0, 5).map(function (c) {
          return html`<span class="chip" style="font-size:9px">${c} (${catCounts[c]})</span>`;
        }), ' ');
        var countBadge = html`<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">${h.findings.length} ${h.findings.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')}</span>`;
        var chevron = html`<span class="finding-group-chevron" style="transform:rotate(${isExpanded ? '90' : '0'}deg)">▶</span>`;
        var dismissAllBtn = html`<button class="btn btn-dismiss" data-dismiss-group="${gkey}">${self._t('findings.dismiss_all', 'Dismiss all')} ${h.findings.length}</button>`;
        var header = html`<div class="finding-card sev-${h.maxSev} finding-group-card" data-expand-baseline-group="${gkey}"><div class="finding-header">${self._sev(h.maxSev)}${countBadge}<span class="finding-title" style="font-family:monospace">${h.ip}</span>${dismissAllBtn}${chevron}</div><div class="finding-meta">${catChips}<span style="flex-shrink:0">${self._t('findings.latest', 'Latest:')} ${self._ago(latestSeen)}</span></div></div>`;
        var rows = isExpanded ? html`<div class="finding-group-rows">${_baselineExpandRows(h.findings)}</div>` : '';
        return html`<div class="finding-group-wrap">${header}${rows}</div>`;
      });
    };
  
    // ── findings group renderers (by category / host / severity) ────
    var _mkFindingGroup = function (gkey, label, sev, itemList, isDismissed) {
      var expandKey = isDismissed ? 'dismissed:' + gkey : gkey;
      var isExpanded = self._expandedFindingGroup === expandKey;
      var totalCount = itemList.reduce(function (s, f) {
        return s + (f.count || 1);
      }, 0);
      var latestSeen = itemList.reduce(function (lat, f) {
        return !lat || f.last_seen > lat ? f.last_seen : lat;
      }, '');
      var countBadge = html`<span class="badge" style="background:rgba(98,232,255,.1);border:1px solid rgba(98,232,255,.2);padding:1px 8px;font-size:10px;border-radius:100px">${itemList.length} ${itemList.length === 1 ? self._t('findings.finding_one', 'finding') : self._t('findings.finding_many', 'findings')}</span>`;
      var chevron = html`<span class="finding-group-chevron" style="transform:rotate(${isExpanded ? '90' : '0'}deg)">▶</span>`;
      var actionBtn = isDismissed ? html`<button class="btn" data-undismiss-group="${gkey}">${self._t('findings.restore_all', 'Restore all')} ${itemList.length}</button>` : html`<button class="btn btn-dismiss" data-dismiss-group="${gkey}">${self._t('findings.dismiss_all', 'Dismiss all')} ${itemList.length}</button>`;
      var header = html`<div class="finding-card sev-${sev} finding-group-card" data-expand-group="${expandKey}"><div class="finding-header">${self._sev(sev)}${countBadge}<span class="finding-title">${label}</span>${actionBtn}${chevron}</div><div class="finding-meta"><span>${totalCount}× ${self._t('findings.total', 'total')}</span><span>${self._t('findings.latest', 'Latest:')} ${self._ago(latestSeen)}</span></div></div>`;
      var rows = '';
      if (isExpanded) {
        rows = html`<div class="finding-group-rows">${itemList.slice().sort(function (a, b) {
          return _sevRank(a.severity) - _sevRank(b.severity);
        }).map(function (f) {
          var det = f.details || {};
          var detRows = joinTemplates(Object.keys(det).filter(function (k) {
            return k !== 'cve_id' && k !== 'port' && k !== 'remediation';
          }).map(function (k) {
            return html`<dt>${k}:</dt><dd>${String(det[k])}</dd>`;
          }), ' ');
          var blBadge = f._isBaseline ? html`<span class="chip" style="background:#3ac5c9;color:#fff;font-size:9px">${self._t('findings.baseline_badge', 'Baseline')}</span>` : '';
          var rowActionBtn = isDismissed ? html`<button class="btn" data-undismiss="${f.key || f.source_ip + ':' + f.category}">${self._t('findings.restore', 'Restore')}</button>` : html`<button class="btn btn-dismiss" data-dismiss="${f.key || f.source_ip + ':' + f.category}">${self._t('findings.dismiss', 'Dismiss')}</button>`;
          return html`<div class="finding-row">${self._sev(f.severity)}<span class="ip">${f.source_ip || ''}</span>${blBadge}${det.cve_id ? html`<span class="chip">${det.cve_id}</span>` : ''}${det.port ? html`<span class="chip">:${det.port}</span>` : ''}<span style="flex:1;font-size:11px">${f.summary || f.category || ''}</span><span class="dim" style="font-size:10px">${f.count || 1}× · ${self._ago(f.last_seen)}</span>${detRows ? html`<div class="finding-detail" style="margin:4px 0;width:100%"><dl>${detRows}</dl></div>` : ''}${rowActionBtn}</div>`;
        })}</div>`;
      }
      return html`<div class="finding-group-wrap">${header}${rows}</div>`;
    };
    var FINDING_CAT_LABELS = {
      vulnerability: self._t('findings.cat_vulnerability', 'Vulnerability / CVE'),
      port_scan: self._t('findings.cat_port_scan', 'Port Scan'),
      suspicious_port: self._t('findings.cat_suspicious_port', 'Suspicious Open Port'),
      high_egress: self._t('findings.cat_high_egress', 'High Egress Traffic')
    };
    var renderFindingsByCategory = function (list, isDismissed) {
      if (!list.length) return '';
      var catMap = {};
      list.forEach(function (f) {
        var k = f.category || 'unknown';
        if (!catMap[k]) catMap[k] = {
          sev: f.severity,
          items: []
        };else if (_sevRank(f.severity) < _sevRank(catMap[k].sev)) catMap[k].sev = f.severity;
        catMap[k].items.push(f);
      });
      return Object.values(catMap).sort(function (a, b) {
        return _sevRank(a.sev) - _sevRank(b.sev);
      }).map(function (g) {
        var cat = g.items[0].category || 'unknown';
        var label = FINDING_CAT_LABELS[cat] || cat;
        return _mkFindingGroup('fcat:' + cat, label, g.sev, g.items, isDismissed);
      });
    };
    var renderFindingsByHost = function (list, isDismissed) {
      if (!list.length) return '';
      var hostMap = {};
      list.forEach(function (f) {
        var ip = f.source_ip || 'unknown';
        if (!hostMap[ip]) hostMap[ip] = {
          sev: f.severity,
          items: []
        };else if (_sevRank(f.severity) < _sevRank(hostMap[ip].sev)) hostMap[ip].sev = f.severity;
        hostMap[ip].items.push(f);
      });
      return Object.values(hostMap).sort(function (a, b) {
        var sd = _sevRank(a.sev) - _sevRank(b.sev);
        if (sd !== 0) return sd;
        return a.items[0].source_ip.split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.').localeCompare(b.items[0].source_ip.split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.'));
      }).map(function (g) {
        var ip = g.items[0].source_ip || 'unknown';
        var label = html`<span style="font-family:monospace">${ip}</span>`;
        return _mkFindingGroup('fhost:' + ip, label, g.sev, g.items, isDismissed);
      });
    };
    var SEV_LABELS = {
      critical: self._t('findings.sev_critical', 'Critical'),
      high: self._t('findings.sev_high', 'High'),
      medium: self._t('findings.sev_medium', 'Medium'),
      low: self._t('findings.sev_low', 'Low'),
      info: self._t('findings.sev_info', 'Info')
    };
    var renderFindingsBySeverity = function (list, isDismissed) {
      if (!list.length) return '';
      var sevMap = {};
      list.forEach(function (f) {
        var s = f.severity || 'info';
        if (!sevMap[s]) sevMap[s] = [];
        sevMap[s].push(f);
      });
      return ['critical', 'high', 'medium', 'low', 'info'].filter(function (s) {
        return sevMap[s];
      }).map(function (s) {
        return _mkFindingGroup('fsev:' + s, SEV_LABELS[s] || s, s, sevMap[s], isDismissed);
      });
    };
    var _renderFindingCards = function (list, isDismissed, mode) {
      if (!list.length) return '';
      if (mode === 'host') return renderFindingsByHost(list, isDismissed);
      if (mode === 'severity') return renderFindingsBySeverity(list, isDismissed);
      if (mode === 'flat') return list.map(function (f) {
        return renderCard(f, isDismissed, !!f._isBaseline);
      });
      return renderFindingsByCategory(list, isDismissed); // 'category' (default)
    };
  
    // ── Baseline section ─────────────────────────────────────────────
    var baselineSection = '';
    if (baselineAnomalies.length) {
      var blModeBtn = function (mode, label) {
        var active = baselineGroupMode === mode;
        return html`<button class="btn${active ? ' active' : ''}" data-baseline-group-mode="${mode}">${label}</button>`;
      };
      var blSearchInput = html`<input type="search" data-baseline-search placeholder="Search + Enter" value="${self._baselineSearch || ''}" style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none">`;
      var blToolbar = html`<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">${blModeBtn('category', self._t('findings.by_category', 'By Category'))}${blModeBtn('host', self._t('findings.by_host', 'By Host'))}${blModeBtn('flat', self._t('findings.flat', 'Flat'))}<span style="flex:1"></span>${blSearchInput}</div>`;
      var blCards;
      if (baselineGroupMode === 'host') blCards = renderBaselineByHost(filteredBaseline);else if (baselineGroupMode === 'flat') blCards = filteredBaseline.map(function (f) {
        return renderCard(f, false, true);
      });else blCards = renderBaselineByCategory(filteredBaseline);
      var blContent = baselineQ && !filteredBaseline.length ? html`<div class="empty-state card" style="height:100px"><p>${self._t('findings.no_results', 'No results for')} &ldquo;${baselineQ}&rdquo;.</p></div>` : blCards;
      baselineSection = html`<div style="margin-bottom:28px"><div class="view-header"><h1>${this._t('findings.baseline', 'Baseline Anomalies')} <span class="dim">(${baselineAnomalies.length}${baselineQ && filteredBaseline.length !== baselineAnomalies.length ? ', ' + filteredBaseline.length + ' ' + this._t('findings.shown', 'shown') : ''})</span></h1></div>${blToolbar}${blContent}</div>`;
    }
  
    // ── Security findings section ────────────────────────────────────
    var cards = _renderFindingCards(filteredFindings, false, findingsGroupMode);
    var findingsHeader = findings.length ? html`${this._t('findings.security', 'Security Findings')} <span class="dim">(${findings.length} ${this._t('findings.actionable', 'actionable')}${findingsQ && filteredFindings.length !== findings.length ? ', ' + filteredFindings.length + ' ' + this._t('findings.shown', 'shown') : ''}${allDismissedList.length ? ', ' + allDismissedList.length + ' ' + this._t('findings.dismissed', 'dismissed') : ''})</span>` : html`${this._t('findings.security', 'Security Findings')}${allDismissedList.length ? html` <span class="dim">(${allDismissedList.length} ${this._t('findings.dismissed', 'dismissed')})</span>` : ''}`;
    var _fModeBtn = function (mode, label) {
      return html`<button class="btn${findingsGroupMode === mode ? ' active' : ''}" data-findings-group-mode="${mode}" style="font-size:10px;padding:3px 8px">${label}</button>`;
    };
    var findingsToggle = html`<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">${_fModeBtn('category', this._t('findings.by_category', 'By Category'))}${_fModeBtn('host', this._t('findings.by_host', 'By Host'))}${_fModeBtn('severity', this._t('findings.by_severity', 'By Severity'))}${_fModeBtn('flat', this._t('findings.flat', 'Flat'))}<span style="flex:1"></span><input type="search" data-findings-search placeholder="${self._t('common.search_enter', 'Search + Enter')}" value="${self._findingsSearch || ''}" style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none"></div>`;
    var activeSection = html`<div><div class="view-header"><h1>${findingsHeader}</h1></div>${findingsToggle}${findings.some(function (f) {
      return f.category === 'vulnerability';
    }) ? this._bannerDisclaimer('margin:0 2px 10px') : ''}${findings.length ? filteredFindings.length ? cards : html`<div class="empty-state card" style="height:100px"><p>${self._t('findings.no_results', 'No results for')} &ldquo;${findingsQ}&rdquo;.</p></div>` : html`<div class="empty-state card" style="height:180px"><div class="empty-icon">✓</div><p>${this._t('findings.no_active', 'No active high or critical findings.')}</p></div>`}</div>`;
  
    // ── Dismissed section (security + baseline combined) ─────────────
    var dismissedCards = _renderFindingCards(filteredDismissed, true, dismissedGroupMode);
    var _dModeBtn = function (mode, label) {
      return html`<button class="btn${dismissedGroupMode === mode ? ' active' : ''}" data-dismissed-group-mode="${mode}" style="font-size:10px;padding:3px 8px">${label}</button>`;
    };
    var dismissedToggle = html`<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:8px">${_dModeBtn('category', this._t('findings.by_category', 'By Category'))}${_dModeBtn('host', this._t('findings.by_host', 'By Host'))}${_dModeBtn('severity', this._t('findings.by_severity', 'By Severity'))}${_dModeBtn('flat', this._t('findings.flat', 'Flat'))}<span style="flex:1"></span><input type="search" data-dismissed-search placeholder="${self._t('common.search_enter', 'Search + Enter')}" value="${self._dismissedSearch || ''}" style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:#fff;padding:3px 8px;font-size:11px;width:160px;outline:none"></div>`;
    var dismissedSection = allDismissedList.length ? html`<div style="margin-top:28px;opacity:.7"><div class="view-header"><h1>${this._t('findings.dismissed_title', 'Dismissed')} <span class="dim">(${allDismissedList.length}${dismissedQ && filteredDismissed.length !== allDismissedList.length ? ', ' + filteredDismissed.length + ' ' + this._t('findings.shown', 'shown') : ''})</span></h1></div>${dismissedToggle}${filteredDismissed.length ? dismissedCards : html`<div class="empty-state card" style="height:100px"><p>${self._t('findings.no_results', 'No results for')} &ldquo;${dismissedQ}&rdquo;.</p></div>`}</div>` : '';
    return html`${topBar}${baselineSection}${activeSection}${dismissedSection}`;
  },

  _dismissFinding(key) {
    if (!key) return;
    this._openEditor({
      mode: 'dismiss',
      ip: key,
      title: 'Dismiss Finding',
      help: 'Optionally add a note explaining why this finding is dismissed (e.g. "false positive", "patched", "accepted risk"). Leave blank to dismiss without a note.',
      placeholder: 'Reason for dismissing (optional)',
      value: ''
    });
  },

  _regexPreviewHtml() {
    var pattern = this._regexDismissPattern;
    if (!pattern) return html`<div style="font-size:11px;color:var(--muted)">Enter a regex above to preview matches.</div>`;
    var rx = null;
    var rxErr = '';
    try {
      rx = new RegExp(pattern, 'i');
    } catch (e) {
      rxErr = e.message;
    }
    if (rxErr) return html`<div style="font-size:11px;color:var(--danger)">⚠ Invalid regex: ${rxErr}</div>`;
    var findings = this._data && this._data.findings || [];
    var matched = findings.filter(function (f) {
      return rx.test(f.summary || '') || rx.test(f.key || '');
    });
    if (!matched.length) return html`<div style="font-size:11px;color:var(--muted)">No active findings match this pattern.</div>`;
    var self = this;
    return html`<div style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:6px">Would dismiss ${matched.length} finding${matched.length !== 1 ? 's' : ''}:</div>${matched.map(function (f) {
      return html`<div style="display:flex;gap:8px;align-items:center;padding:3px 0;border-bottom:1px solid rgba(98,232,255,.06);flex-wrap:wrap">${self._sev(f.severity)}<span class="ip" style="font-size:11px">${f.source_ip || ''}</span><span style="font-size:11px;color:var(--text);flex:1">${f.summary || ''}</span></div>`;
    })}`;
  },

  _regexDismissModal() {
    var self = this;
    return html`<div id="hsa-regex-dismiss-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px"><div class="card" style="width:min(640px,96vw);margin:0;border:1px solid rgba(98,232,255,.26)"><div class="view-header" style="margin-bottom:10px"><h1 style="font-size:16px">🗑 Dismiss by Pattern</h1></div><div class="dim" style="font-size:11px;margin-bottom:12px">Enter a regular expression to match against finding summaries or keys. All matching <strong>active</strong> findings will be dismissed.</div><label class="dim" style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;display:block;margin-bottom:4px">Regex pattern</label><input id="hsa-regex-pattern" class="search-bar" style="width:100%;font-family:monospace" type="text" maxlength="200" placeholder="e.g. port.scan|high.egress" value="${self._regexDismissPattern}" autocomplete="off" spellcheck="false"><label class="dim" style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;display:block;margin-top:10px;margin-bottom:4px">Dismiss note (optional)</label><input id="hsa-regex-note" class="search-bar" style="width:100%" type="text" maxlength="500" placeholder="e.g. accepted risk, false positive" value="${self._regexDismissNote}"><div id="hsa-regex-preview" style="margin-top:12px;padding:10px;background:rgba(0,0,0,.25);border-radius:6px;max-height:200px;overflow-y:auto">${self._regexPreviewHtml()}</div><div class="row-gap" style="justify-content:flex-end;margin-top:14px;gap:8px"><button class="btn" data-regex-dismiss-close>Cancel</button><button class="btn" style="background:rgba(255,77,109,.12);border-color:rgba(255,77,109,.4);color:#ff4d6d" data-regex-dismiss-confirm>Dismiss matching</button></div></div></div>`;
  }
};
