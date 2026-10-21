// DNS queries view.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, nothing } from "lit";

export const dnsMethods = {
  _viewDns() {
    var self = this;
    var stats = this._data && this._data.dns_proxy_stats || {};
    var log = this._data && this._data.dns_log || [];
    var filteredLog = this._dnsFilteredLog(log);
    var sortedLog = this._dnsSortedLog(filteredLog);
    var CATEGORIES = ['malware', 'adult', 'gambling', 'ads', 'tracking', 'social', 'gaming', 'streaming', 'news', 'cdn', 'cloud', 'iot', 'tech', 'intel', 'override', 'other'];
    var CAT_COLORS = {
      malware: 'rgba(255,77,109,1)',
      adult: 'rgba(191,111,255,1)',
      gambling: 'rgba(255,179,71,1)',
      ads: 'rgba(255,209,102,1)',
      tracking: 'rgba(107,140,186,1)',
      social: 'rgba(91,170,236,1)',
      gaming: 'rgba(107,255,200,1)',
      streaming: 'rgba(58,197,201,1)',
      news: 'rgba(245,158,11,1)',
      cdn: 'rgba(72,199,142,1)',
      cloud: 'rgba(59,178,255,1)',
      iot: 'rgba(255,159,67,1)',
      tech: 'rgba(155,135,245,1)',
      intel: 'rgba(248,84,84,1)',
      override: 'rgba(98,232,255,1)',
      other: 'rgba(90,106,128,1)'
    };
    var CAT_LABELS = {
      malware: 'Malware',
      adult: 'Adult',
      gambling: 'Gambling',
      ads: 'Ads',
      tracking: 'Tracking',
      social: 'Social',
      gaming: 'Gaming',
      streaming: 'Streaming',
      news: 'News',
      cdn: 'CDN',
      cloud: 'Cloud',
      iot: 'IoT',
      tech: 'Tech',
      intel: 'Threat Intel',
      override: self._t('dns.cat.override', 'Override'),
      other: 'Other'
    };
    var filterBar = html`<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap"><input class="search-bar" id="dns-search" placeholder="${self._t('dns.filter_placeholder', 'Filter by IP or domain…')}" style="width:220px" value="${this._dnsSearch}" onkeydown="if(event.key==='Enter')this.getRootNode().host._dnsFilter()" /><select id="dns-cat-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" onchange="this.getRootNode().host._dnsFilter()"><option value="">${self._t('dns.all_categories', 'All categories')}</option>${CATEGORIES.map(function (c) {
      return html`<option value="${c}" ?selected=${self._dnsCategoryFilter === c}>${CAT_LABELS[c]}</option>`;
    })}</select><select id="dns-status-filter" style="font-size:12px;padding:4px 6px;background:var(--surface2);color:var(--fg);border:1px solid var(--border);border-radius:4px;cursor:pointer" onchange="this.getRootNode().host._dnsFilter()"><option value="">${self._t('dns.all_status', 'All status')}</option><option value="allowed" ?selected=${self._dnsStatusFilter === 'allowed'}>${self._t('common.allowed', 'Allowed')}</option><option value="blocked" ?selected=${self._dnsStatusFilter === 'blocked'}>${self._t('common.blocked', 'Blocked')}</option></select><label style="font-size:12px;display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="dns-malicious-only" onchange="this.getRootNode().host._dnsFilter()" ?checked=${self._dnsMaliciousOnly}> ${self._t('dns.malicious_only', 'Malicious only')}</label><span id="dns-count" style="font-size:11px;color:var(--muted);margin-left:auto">${sortedLog.length} / ${Math.max(log.length, self._data && self._data.dns_log_total || 0)} ${self._t('dns.entries', 'entries')}</span></div>`;
  
    // Table
    var DNS_PAGE_SIZE = this._dnsPageSize || 25;
    var dnsPage = this._dnsPage || 0;
    var totalDnsPages = Math.max(1, Math.ceil(sortedLog.length / DNS_PAGE_SIZE));
    if (dnsPage >= totalDnsPages) dnsPage = totalDnsPages - 1;
    var pageLog = sortedLog.slice(dnsPage * DNS_PAGE_SIZE, (dnsPage + 1) * DNS_PAGE_SIZE);
    var dnsPageStart = sortedLog.length === 0 ? 0 : dnsPage * DNS_PAGE_SIZE + 1;
    var dnsPageEnd = Math.min(sortedLog.length, (dnsPage + 1) * DNS_PAGE_SIZE);
    var topPaginationHtml = html`<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap"><div class="row-gap" style="font-size:11px;color:var(--muted)">${self._t('dns.showing', 'Showing')} ${dnsPageStart}–${dnsPageEnd} of ${sortedLog.length}</div><div class="row-gap" style="gap:6px"><label class="dim" style="font-size:11px">${self._t('common.rows', 'Rows')}</label><select id="hsa-dns-pagesize" class="role-select">${[10, 25, 50, 100].map(function (n) {
      return html`<option value="${n}" ?selected=${n === DNS_PAGE_SIZE}>${n}</option>`;
    })}</select><button class="btn" data-dns-page="${dnsPage - 1}" ?disabled=${dnsPage <= 0}>${self._t('common.previous', 'Previous')}</button><span class="dim" style="font-size:11px;min-width:70px;text-align:center">${dnsPage + 1} / ${totalDnsPages}</span><button class="btn" data-dns-page="${dnsPage + 1}" ?disabled=${dnsPage >= totalDnsPages - 1}>${self._t('common.next', 'Next')}</button></div></div>`;
    var maliciousCount = log.filter(function (e) {
      return e.malicious;
    }).length;
    var summaryBadge = maliciousCount > 0 ? html`<span class="badge badge-malicious" style="margin-left:8px">${maliciousCount} ${self._t('dns.malicious_badge', 'malicious')}</span>` : '';
    var dnsSortCols = [{
      key: 'time',
      label: self._t('dns.col_time', 'Time')
    }, {
      key: 'client_ip',
      label: self._t('dns.col_client_ip', 'Client IP')
    }, {
      key: 'domain',
      label: self._t('dns.col_domain', 'Domain')
    }, {
      key: 'type',
      label: self._t('dns.col_type', 'Type')
    }, {
      key: 'category',
      label: self._t('dns.col_category', 'Category')
    }];
    var tableHead = html`<thead><tr>${dnsSortCols.map(function (c) {
      var arrow = self._dnsSort === c.key ? self._dnsSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
      return html`<th class="sortable-th" data-dnssort="${c.key}">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
    })}<th>${self._t('dns.col_response', 'Response')}</th><th>${self._t('dns.col_answer', 'Answer')}</th>${function () {
      var arrow = self._dnsSort === 'status' ? self._dnsSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
      return html`<th class="sortable-th" data-dnssort="status">${self._t('dns.col_status', 'Status')}<span class="sort-arrow">${arrow}</span></th>`;
    }()}</tr></thead>`;
    var tableRows = pageLog.map(function (e) {
      var ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
      var ip = e.src_ip || '—';
      var dom = e.domain || '—';
      var qtype = e.qtype || 'A';
      var rcode = e.rcode || '…';
      var ans = e.answer ? e.answer : html`<span style="color:var(--muted)">—</span>`;
      var mal = e.malicious;
      var cat = (e.category || 'other').toLowerCase();
      var status = (e.status || 'allowed').toLowerCase();
      var catColor = CAT_COLORS[cat] || CAT_COLORS['other'];
      var catLabel = CAT_LABELS[cat] || cat;
      var catBadge = html`<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:${catColor.replace(',1)', ',.18)').replace('rgba(', 'rgba(')};color:${catColor};border:1px solid ${catColor.replace(',1)', ',.4)')}">${catLabel}</span>`;
      var rcodeColor = rcode === 'NOERROR' ? 'var(--success)' : rcode === 'NXDOMAIN' ? 'var(--warn)' : rcode === '…' ? 'var(--muted)' : 'var(--danger)';
      var statusBadge;
      if (status === 'blocked') {
        statusBadge = html`<span class="badge" style="background:rgba(255,77,109,.15);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)">🚫 ${self._t('common.blocked', 'Blocked')}</span>`;
      } else {
        statusBadge = html`<span class="badge" style="background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)">✓ ${self._t('common.allowed', 'Allowed')}</span>`;
      }
      var rowBg = status === 'blocked' ? 'rgba(255,77,109,.06)' : mal ? 'rgba(255,77,109,.03)' : '';
      return html`<tr style=${rowBg ? 'background:' + rowBg : nothing} data-malicious="${mal ? '1' : '0'}" data-cat="${cat}" data-status="${status}" data-ip="${ip.toLowerCase()}" data-domain="${dom.toLowerCase()}"><td class="mono" style="white-space:nowrap;font-size:11px">${ts}</td><td class="mono ip">${ip}</td><td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${dom}">${dom}</td><td><span class="chip">${qtype}</span></td><td>${catBadge}</td><td class="mono" style="font-size:11px;color:${rcodeColor}">${rcode}</td><td class="mono" style="font-size:11px">${ans}</td><td>${statusBadge}</td></tr>`;
    });
    var paginationHtml = ''; // kept for compat — pagination now at top
  
    return html`<div><div class="view-header"><h1>${this._t('page.dns_queries', 'DNS Queries')} ${summaryBadge}</h1></div><div class="card table-card"><div style="padding:14px 14px 8px">${filterBar}</div>${topPaginationHtml}<div style="overflow-x:auto"><table class="data-table" id="dns-table" style="min-width:900px">${tableHead}<tbody>${tableRows}</tbody></table></div></div></div>`;
  },

  _dnsFilter() {
    var root = this.shadowRoot;
    var prevSearch = this._dnsSearch;
    var prevMalOnly = this._dnsMaliciousOnly;
    var prevCat = this._dnsCategoryFilter;
    var prevStatus = this._dnsStatusFilter;
    this._dnsSearch = ((root.getElementById('dns-search') || {
      value: ''
    }).value || '').toLowerCase().trim();
    this._dnsMaliciousOnly = !!(root.getElementById('dns-malicious-only') || {
      checked: false
    }).checked;
    this._dnsCategoryFilter = (root.getElementById('dns-cat-filter') || {
      value: ''
    }).value || '';
    this._dnsStatusFilter = (root.getElementById('dns-status-filter') || {
      value: ''
    }).value || '';
    var searchChanged = this._dnsSearch !== prevSearch;
    var otherFiltersChanged = this._dnsMaliciousOnly !== prevMalOnly || this._dnsCategoryFilter !== prevCat || this._dnsStatusFilter !== prevStatus;
  
    // Keep current page when only search text changes; reset for other filter changes.
    if (otherFiltersChanged || !searchChanged) {
      this._dnsPage = 0;
    }
    this._render();
  },

  _dnsFilteredLog(log) {
    var search = (this._dnsSearch || '').toLowerCase().trim();
    var malOnly = !!this._dnsMaliciousOnly;
    var catFilter = this._dnsCategoryFilter || '';
    var statusFilter = this._dnsStatusFilter || '';
    return (log || []).filter(function (e) {
      var ip = String(e.src_ip || '').toLowerCase();
      var domain = String(e.domain || '').toLowerCase();
      var mal = !!e.malicious;
      var cat = String(e.category || 'other').toLowerCase();
      var status = String(e.status || 'allowed').toLowerCase();
      return (!malOnly || mal) && (!search || ip.indexOf(search) >= 0 || domain.indexOf(search) >= 0) && (!catFilter || cat === catFilter) && (!statusFilter || status === statusFilter);
    });
  },

  _dnsSortedLog(log) {
    var self = this;
    var sortKey = this._dnsSort || 'time';
    var sortDir = this._dnsSortDir || -1;
    var out = (log || []).slice();
    out.sort(function (a, b) {
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
  },

  _clearBlockedDns(btn) {
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Clearing\u2026';
    }
    var self = this;
    this._hass.callApi('POST', 'homesec/dns/log/clear_blocked').then(function () {
      if (self._data && self._data.dns_log) {
        self._data.dns_log = self._data.dns_log.filter(function (e) {
          return !e.malicious && e.status !== 'blocked';
        });
        self._dnsPage = 0;
        self._render();
      }
    }).catch(function () {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '\u{1F6AB} Clear blocked';
      }
    });
  },

  _setDnsSort(col) {
    if (this._dnsSort === col) {
      this._dnsSortDir *= -1;
    } else {
      this._dnsSort = col;
      this._dnsSortDir = col === 'time' ? -1 : 1;
    }
    this._dnsPage = 0;
    this._render();
  },

  _dnsIpSortKey(ip) {
    var raw = String(ip || '').trim();
    if (raw.indexOf(':') >= 0) return '1:' + raw.toLowerCase();
    var parts = raw.split('.');
    if (parts.length !== 4) return '0:' + raw.toLowerCase();
    for (var i = 0; i < parts.length; i++) {
      if (!/^\d+$/.test(parts[i])) return '0:' + raw.toLowerCase();
    }
    return '0:' + parts.map(function (p) {
      var n = Math.max(0, Math.min(255, parseInt(p, 10)));
      return ('000' + n).slice(-3);
    }).join('.');
  }
};
