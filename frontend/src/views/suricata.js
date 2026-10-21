// Suricata alerts view and alert detail modal.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, render } from "lit";
import { joinTemplates } from "../templates.js";

export const suricataMethods = {
  // ── Suricata view ────────────────────────────────────────────────────────────
  
  _viewSuricata() {
    var self = this;
    var stats = this._data && this._data.suricata_stats || {};
    var log = this._data && this._data.suricata_log || [];
    var filteredLog = this._suricataFilteredLog(log);
    var sortedLog = this._suricataSortedLog(filteredLog);
  
    // Severity colour helpers
    var SEV_COLORS = {
      1: 'rgba(255,77,109,1)',
      2: 'rgba(255,179,71,1)',
      3: 'rgba(107,255,200,1)'
    };
    var SEV_LABELS = {
      1: self._t('suricata.sev_critical', 'Critical'),
      2: self._t('suricata.sev_major', 'Major'),
      3: self._t('suricata.sev_minor', 'Minor')
    };
    function sevColor(s) {
      return SEV_COLORS[s] || 'rgba(90,106,128,1)';
    }
    function sevLabel(s) {
      return SEV_LABELS[s] || self._t('suricata.sev_unknown', 'Unknown');
    }
    function sevBadge(s) {
      var c = sevColor(s);
      var l = sevLabel(s);
      return html`<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:${c.replace(',1)', ',0.18)')};color:${c};border:1px solid ${c.replace(',1)', ',0.4)')}">${l}</span>`;
    }
    var critCount = log.filter(function (e) {
      return e.severity === 1;
    }).length;
  
    // ── filter bar ────────────────────────────────────────────────────────────
    var filterBar = html`<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap"><input class="search-bar" id="suricata-search" placeholder="${self._t('suricata.filter_placeholder', 'Filter by IP, signature…')}" style="width:230px" value="${this._suricataSearch}" @keydown=${function (e) { if (e.key === 'Enter') this._suricataFilter(); }} /><select id="suricata-sev-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" @change=${function () { this._suricataFilter(); }}><option value="">${self._t('suricata.all_severities', 'All severities')}</option>${[1, 2, 3].map(function (s) {
      return html`<option value="${s}" ?selected=${self._suricataSeverityFilter === String(s)}>${sevLabel(s)}</option>`;
    })}</select><select id="suricata-action-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" @change=${function () { this._suricataFilter(); }}><option value="">${self._t('suricata.all_actions', 'All actions')}</option><option value="allowed" ?selected=${self._suricataActionFilter === 'allowed'}>${self._t('common.allowed', 'Allowed')}</option><option value="blocked" ?selected=${self._suricataActionFilter === 'blocked'}>${self._t('common.blocked', 'Blocked')}</option></select><span style="font-size:11px;color:var(--muted);margin-left:auto">${sortedLog.length} / ${Math.max(log.length, self._data && self._data.suricata_log_total || 0)} ${self._t('suricata.entries', 'entries')}</span></div>`;
  
    // ── table ─────────────────────────────────────────────────────────────────
    var PAGE_SIZE = this._suricataPageSize || 25;
    var page = this._suricataPage || 0;
    var totalPages = Math.max(1, Math.ceil(sortedLog.length / PAGE_SIZE));
    if (page >= totalPages) page = totalPages - 1;
    var pageLog = sortedLog.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    var pageStart = sortedLog.length === 0 ? 0 : page * PAGE_SIZE + 1;
    var pageEnd = Math.min(sortedLog.length, (page + 1) * PAGE_SIZE);
    var topPagination = html`<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap"><div class="row-gap" style="font-size:11px;color:var(--muted)">${self._t('suricata.showing', 'Showing')} ${pageStart}–${pageEnd} of ${sortedLog.length}</div><div class="row-gap" style="gap:6px"><label class="dim" style="font-size:11px">${self._t('common.rows', 'Rows')}</label><select id="hsa-suricata-pagesize" class="role-select">${[10, 25, 50, 100].map(function (n) {
      return html`<option value="${n}" ?selected=${n === PAGE_SIZE}>${n}</option>`;
    })}</select><button class="btn" data-suricata-page="${page - 1}" ?disabled=${page <= 0}>${self._t('common.previous', 'Previous')}</button><span class="dim" style="font-size:11px;min-width:70px;text-align:center">${page + 1} / ${totalPages}</span><button class="btn" data-suricata-page="${page + 1}" ?disabled=${page >= totalPages - 1}>${self._t('common.next', 'Next')}</button></div></div>`;
    var SORT_COLS = [{
      key: 'time',
      label: self._t('suricata.col_time', 'Time')
    }, {
      key: 'src_ip',
      label: self._t('suricata.col_src_ip', 'Src IP')
    }, {
      key: 'dest_ip',
      label: self._t('suricata.col_dest_ip', 'Dest IP')
    }, {
      key: 'proto',
      label: self._t('suricata.col_proto', 'Proto')
    }, {
      key: 'signature',
      label: self._t('suricata.col_signature', 'Signature')
    }, {
      key: 'category',
      label: self._t('suricata.col_category', 'Category')
    }, {
      key: 'severity',
      label: self._t('suricata.col_severity', 'Severity')
    }, {
      key: 'action',
      label: self._t('suricata.col_action', 'Action')
    }];
    var thead = html`<thead><tr>${SORT_COLS.map(function (c) {
      var arrow = self._suricataSort === c.key ? self._suricataSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
      return html`<th class="sortable-th" data-suricatasort="${c.key}">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
    })}</tr></thead>`;
    var rows = pageLog.map(function (e, rowIdx) {
      var ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
      var sip = e.src_ip || '—';
      var dip = e.dest_ip || '—';
      var sproto = e.proto || '';
      var sig = e.signature || '—';
      var cat = e.category || '—';
      var sev = parseInt(e.severity) || 3;
      var action = (e.action || 'allowed').toLowerCase();
      var actionBadge = action === 'blocked' ? html`<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">${self._t('suricata.badge_blocked', '🚫 Blocked')}</span>` : html`<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">${self._t('suricata.badge_allowed', '✓ Allowed')}</span>`;
      var rowBg = sev === 1 ? 'rgba(255,77,109,.06)' : sev === 2 ? 'rgba(255,179,71,.04)' : '';
      var rowStyle = 'cursor:pointer' + (rowBg ? ';background:' + rowBg : '');
      return html`<tr style="${rowStyle}" data-suricata-alert-idx="${rowIdx}" title="${self._t('suricata.click_details', 'Click for details')}"><td class="mono" style="white-space:nowrap;font-size:11px">${ts}</td><td class="mono ip">${sip}</td><td class="mono ip">${dip}</td><td><span class="chip">${sproto}</span></td><td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${sig}">${sig}</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--muted)" title="${cat}">${cat}</td><td>${sevBadge(sev)}</td><td>${actionBadge}</td></tr>`;
    });
    var critBadge = critCount > 0 ? html`<span class="badge badge-malicious" style="margin-left:8px">${critCount} ${self._t('suricata.critical_badge', 'critical')}</span>` : '';
    return html`<div><div class="view-header"><h1>${this._t('page.suricata_alerts', 'Suricata Alerts')} ${critBadge}</h1></div><div class="card table-card"><div style="padding:14px 14px 8px">${filterBar}</div>${topPagination}<div style="overflow-x:auto"><table class="data-table" style="min-width:960px">${thead}<tbody>${rows}</tbody></table></div></div></div>`;
  },

  _suricataFilter() {
    this._suricataSearch = ((this.shadowRoot.getElementById('suricata-search') || {}).value || '').toLowerCase().trim();
    this._suricataSeverityFilter = (this.shadowRoot.getElementById('suricata-sev-filter') || {}).value || '';
    this._suricataActionFilter = (this.shadowRoot.getElementById('suricata-action-filter') || {}).value || '';
    this._suricataPage = 0;
    this._render();
  },

  _suricataFilteredLog(log) {
    var search = this._suricataSearch || '';
    var sevF = this._suricataSeverityFilter || '';
    var actF = this._suricataActionFilter || '';
    return (log || []).filter(function (e) {
      if (sevF && String(e.severity) !== sevF) return false;
      if (actF && (e.action || 'allowed').toLowerCase() !== actF) return false;
      if (search) {
        var hay = [e.src_ip, e.dest_ip, e.signature, e.category, e.proto, e.app_proto].join(' ').toLowerCase();
        if (hay.indexOf(search) < 0) return false;
      }
      return true;
    });
  },

  _suricataSortedLog(log) {
    var self = this;
    var key = this._suricataSort || 'time';
    var dir = this._suricataSortDir || -1;
    var out = (log || []).slice();
    out.sort(function (a, b) {
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
  },

  _setSuricataSort(col) {
    if (this._suricataSort === col) {
      this._suricataSortDir *= -1;
    } else {
      this._suricataSort = col;
      this._suricataSortDir = col === 'time' ? -1 : 1;
    }
    this._suricataPage = 0;
    this._render();
  },

  _suricataAlertDetailModal() {
    var a = this._suricataAlertDetail;
    if (!a) return '';
    var self = this;
    var SEV_COLORS = {
      1: 'rgba(255,77,109,1)',
      2: 'rgba(255,179,71,1)',
      3: 'rgba(107,255,200,1)'
    };
    var SEV_LABELS = {
      1: this._t('suricata.sev_critical', 'Critical'),
      2: this._t('suricata.sev_major', 'Major'),
      3: this._t('suricata.sev_minor', 'Minor')
    };
    var sev = parseInt(a.severity) || 3;
    var sevColor = SEV_COLORS[sev] || 'rgba(90,106,128,1)';
    var sevLabel = SEV_LABELS[sev] || this._t('suricata.sev_unknown', 'Unknown');
    var sevBadge = html`<span style="display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;background:${sevColor.replace(',1)', ',0.18)')};color:${sevColor};border:1px solid ${sevColor.replace(',1)', ',0.4)')}">${sevLabel}</span>`;
    var action = (a.action || 'allowed').toLowerCase();
    var actionBadge = action === 'blocked' ? html`<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">${this._t('suricata.badge_blocked', '🚫 Blocked')}</span>` : html`<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">${this._t('suricata.badge_allowed', '✓ Allowed')}</span>`;
  
    // Source host lookup
    var allHosts = this._data && this._data.devices || [];
    var srcHost = allHosts.find(function (h) {
      return h.ip === a.src_ip;
    });
    var destHost = allHosts.find(function (h) {
      return h.ip === a.dest_ip;
    });
    function hostInfo(h) {
      if (!h) return html`<span class="dim">—</span>`;
      var parts = [];
      if (h.hostname) parts.push(html`<b>${h.hostname}</b>`);
      if (h.vendor) parts.push(h.vendor);
      if (h.os) parts.push(h.os);
      return parts.length ? joinTemplates(parts, ' \u00B7 ') : html`<span class="dim">—</span>`;
    }
  
    // Signature ID and rule links
    // signature_id is untrusted input: only ever render it as a plain number
    var sigId = /^[0-9]{1,10}$/.test(String(a.signature_id == null ? '' : a.signature_id)) ? String(a.signature_id) : '';
    var sigLinks = '';
    if (sigId) {
      // Emerging Threats rules (SIDs typically 2000000+)
      var etLink = html`<a href="https://doc.emergingthreats.net/bin/view/Main/SidFAQ?topic=${encodeURIComponent(sigId)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">Emerging Threats</a>`;
      // Snort rule docs
      var snortLink = html`<a href="https://www.snort.org/rule_docs/${encodeURIComponent(sigId)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">Snort Rule Docs</a>`;
      // Generic search
      var searchLink = html`<a href="https://www.google.com/search?q=suricata+rule+sid+${encodeURIComponent(sigId)}+${encodeURIComponent(a.signature || '')}" target="_blank" rel="noopener noreferrer" class="ext-report-link">Search</a>`;
      sigLinks = html`<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">${etLink}${snortLink}${searchLink}</div>`;
    } else if (a.signature) {
      var searchLink2 = html`<a href="https://www.google.com/search?q=suricata+alert+${encodeURIComponent(a.signature)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">Search rule</a>`;
      sigLinks = html`<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">${searchLink2}</div>`;
    }
    function row(label, value) {
      return html`<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span style="font-size:11px;color:var(--muted);min-width:110px;flex-shrink:0">${label}</span><span style="font-size:12px;color:var(--fg);word-break:break-all">${value}</span></div>`;
    }
    var ts = a.timestamp ? new Date(a.timestamp).toLocaleString() : '\u2014';
    var srcPort = a.src_port ? ':' + a.src_port : '';
    var destPort = a.dest_port ? ':' + a.dest_port : '';
    var flow = html`<span class="mono" style="font-size:12px">${(a.src_ip || '\u2014') + srcPort}</span> <span style="color:var(--muted)">→</span> <span class="mono" style="font-size:12px">${(a.dest_ip || '\u2014') + destPort}</span>`;
    var proto = joinTemplates([a.proto, a.app_proto].filter(Boolean).map(function (p) {
      return html`<span class="chip">${p}</span>`;
    }), ' ');
    return html`<div id="hsa-suricata-detail-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px" data-suricata-close="1"><div class="card" style="width:min(660px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(255,77,109,.26)"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px"><h1 style="font-size:15px;color:var(--accent);margin:0">${this._t('suricata.detail_title', 'Alert Detail')}</h1><button class="btn" data-suricata-close="1">✕ ${this._t('common.close', 'Close')}</button></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">${sevBadge} ${actionBadge}${sigId ? html`<span class="dim" style="font-size:11px">SID ${sigId}</span>` : ''}</div><div class="card-title" style="margin-bottom:6px">${this._t('suricata.alert_info', 'Alert Info')}</div>${row(this._t('suricata.timestamp', 'Timestamp'), ts)}${row(this._t('suricata.flow', 'Flow'), flow)}${row(this._t('suricata.protocol', 'Protocol'), proto || '\u2014')}${row(this._t('suricata.interface', 'Interface'), a.in_iface || '\u2014')}${row('Signature', html`<span style="font-weight:600">${a.signature || '\u2014'}</span>`)}${sigId ? row(this._t('suricata.signature_id', 'Signature ID'), String(sigId)) : ''}${row(this._t('suricata.col_category', 'Category'), a.category || '\u2014')}${row(this._t('suricata.col_severity', 'Severity'), sevBadge)}${row(this._t('suricata.col_action', 'Action'), actionBadge)}${a.flow_id ? row('Flow ID', String(a.flow_id)) : ''}<div class="card-title" style="margin-top:14px;margin-bottom:6px">${this._t('suricata.source_host', 'Source Host')}</div>${row('IP', html`<span class="mono">${a.src_ip || '\u2014'}</span>`)}${row(this._t('suricata.host_info', 'Host info'), hostInfo(srcHost))}<div class="card-title" style="margin-top:14px;margin-bottom:6px">${this._t('suricata.destination_host', 'Destination Host')}</div>${row('IP', html`<span class="mono">${a.dest_ip || '\u2014'}</span>`)}${row(this._t('suricata.host_info', 'Host info'), hostInfo(destHost))}${sigLinks}</div></div>`;
  }
};
