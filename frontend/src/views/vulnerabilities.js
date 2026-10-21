// Vulnerability browser and CVE detail modal.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html } from "lit";
import { joinTemplates } from "../templates.js";

export const vulnerabilitiesMethods = {
  _viewVulns() {
    var self = this;
    // Trigger async fetch on first visit or when stale
    if (!this._vulnData && !this._vulnLoading) {
      this._vulnLoading = true;
      this._hass.callApi('GET', 'homesec/vulnerabilities').then(function (d) {
        self._vulnData = d;
        self._vulnLoading = false;
        self._render();
      }).catch(function () {
        self._vulnLoading = false;
        self._vulnData = {
          vulnerabilities: [],
          total: 0,
          detected_cves: 0,
          kev_matches: 0,
          kev_total: 0
        };
        self._render();
      });
      return html`<div><div class="view-header"><h1>${this._t('vuln.page_title', 'Vulnerability Browser')}</h1></div><div class="state-box"><div class="loader"></div><p>${this._t('vuln.loading', 'Loading vulnerabilities…')}</p></div></div>`;
    }
    if (this._vulnLoading) {
      return html`<div><div class="view-header"><h1>${this._t('vuln.page_title', 'Vulnerability Browser')}</h1></div><div class="state-box"><div class="loader"></div><p>${this._t('vuln.loading', 'Loading vulnerabilities…')}</p></div></div>`;
    }
    var d = this._vulnData || {
      vulnerabilities: [],
      total: 0,
      detected_cves: 0,
      kev_matches: 0,
      kev_total: 0
    };
    var allVulns = d.vulnerabilities || [];
    var q = this._vulnFilter.toLowerCase().trim();
    var filtered = allVulns;
    if (q) {
      filtered = allVulns.filter(function (v) {
        return (v.cve_id || '').toLowerCase().indexOf(q) !== -1 || (v.summary || '').toLowerCase().indexOf(q) !== -1 || (v.severity || '').toLowerCase().indexOf(q) !== -1 || (v.services || []).some(function (s) {
          return s.toLowerCase().indexOf(q) !== -1;
        }) || (v.ports || []).some(function (p) {
          return String(p).indexOf(q) !== -1;
        }) || (v.cpe_criteria || []).some(function (c) {
          return c.toLowerCase().indexOf(q) !== -1;
        }) || (v.affected_hosts || []).some(function (h) {
          return h.indexOf(q) !== -1;
        }) || (v.kev_vendor || '').toLowerCase().indexOf(q) !== -1 || (v.kev_product || '').toLowerCase().indexOf(q) !== -1;
      });
    }
    // Sort
    var sevOrder = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    var sortKey = this._vulnSort;
    var sortDir = this._vulnSortDir;
    filtered = filtered.slice().sort(function (a, b) {
      var av, bv;
      if (sortKey === 'cvss') {
        av = a.cvss || 0;
        bv = b.cvss || 0;
      } else if (sortKey === 'severity') {
        av = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 99;
        bv = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 99;
      } else if (sortKey === 'published') {
        av = a.published || '';
        bv = b.published || '';
      } else if (sortKey === 'cve_id') {
        av = a.cve_id || '';
        bv = b.cve_id || '';
      } else if (sortKey === 'hosts') {
        av = (a.affected_hosts || []).length;
        bv = (b.affected_hosts || []).length;
      } else if (sortKey === 'kev') {
        av = a.in_kev ? 1 : 0;
        bv = b.in_kev ? 1 : 0;
      } else if (sortKey === 'services') {
        av = (a.services || []).join(',');
        bv = (b.services || []).join(',');
      } else if (sortKey === 'ports') {
        av = (a.ports || []).length;
        bv = (b.ports || []).length;
      } else {
        av = a.cve_id || '';
        bv = b.cve_id || '';
      }
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
    var header = html`<div class="view-header"><h1>${this._t('vuln.page_title', 'Vulnerability Browser')}</h1><div class="row-gap"><input class="search-bar" type="text" placeholder="${this._t('vuln.search_placeholder', 'Search CVE, port, service, CPE, keyword…')}" value="${this._vulnFilter}" data-vuln-search /><button class="btn" data-vuln-refresh>${this._t('vuln.refresh', '↻ Refresh')}</button></div></div><div class="tldr-bar"><span><strong>${d.total}</strong> ${this._t('vuln.stat_cves_db', 'CVEs in database')}</span><span><strong>${d.detected_cves || 0}</strong> ${this._t('vuln.stat_detected_network', 'detected on network')}</span><span><strong>${d.kev_matches}</strong> ${this._t('vuln.stat_in_kev', 'in CISA KEV')}</span><span><strong>${total}</strong> ${this._t('vuln.stat_matching', 'matching results')}</span></div>${this._bannerDisclaimer('margin:-4px 2px 12px')}`;
    var thead = html`<thead><tr>${function () {
      var cols = [{
        key: 'cve_id',
        label: self._t('vuln.col_cve_id', 'CVE ID')
      }, {
        key: 'published',
        label: self._t('vuln.col_published', 'Published')
      }, {
        key: 'cvss',
        label: self._t('vuln.col_cvss', 'CVSS')
      }, {
        key: 'severity',
        label: self._t('vuln.col_severity', 'Severity')
      }, {
        key: 'services',
        label: self._t('vuln.col_services', 'Services')
      }, {
        key: 'ports',
        label: self._t('vuln.col_ports', 'Ports')
      }, {
        key: 'hosts',
        label: self._t('vuln.col_hosts', 'Hosts')
      }, {
        key: 'kev',
        label: 'KEV'
      }];
      return html`${cols.map(function (c) {
        var arrow = self._vulnSort === c.key ? self._vulnSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
        return html`<th class="sortable-th" data-vulnsort="${c.key}">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
      })}<th style="min-width:320px">${self._t('vuln.col_summary', 'Summary')}</th>`;
    }()}</tr></thead>`;
    var rows = [];
    page.forEach(function (v) {
      var cid = v.cve_id || '';
      var cvss = v.cvss || 0;
      var sc = sevClass(cvss);
      var kevBadge = v.in_kev ? html`<span class="badge badge-critical" title="CISA Known Exploited Vulnerability">KEV</span>` : '';
      var services = (v.services || []).map(function (s) {
        return html`<span class="chip">${s}</span>`;
      });
      if (!services.length) services = '\u2014';
      var ports = (v.ports || []).map(function (p) {
        return html`<span class="chip">${p}</span>`;
      });
      if (!ports.length) ports = '\u2014';
      var hosts = (v.affected_hosts || []).length;
      var hostsStr = hosts > 0 ? html`<span class="ip-chip">${hosts} host${hosts > 1 ? 's' : ''}</span>` : html`<span class="dim" style="font-size:10px">${self._t('vuln.not_detected', 'not detected')}</span>`;
      var summary = (v.summary || '').substring(0, 200);
      if ((v.summary || '').length > 200) summary += '\u2026';
      var cveBtn = cid ? html`<a class="ext-report-link" style="cursor:pointer" data-vuln-detail="${cid}" title="View details">${cid}</a>` : cid;
      var published = v.published || '\u2014';
      rows.push(html`<tr><td>${cveBtn}</td><td style="font-size:10px;color:var(--muted);white-space:nowrap">${published}</td><td><span class="badge badge-${sc}">${cvss.toFixed(1)}</span></td><td>${self._sev(v.severity || sc)}</td><td>${services}</td><td>${ports}</td><td>${hostsStr}</td><td>${kevBadge}</td><td style="font-size:11px;color:var(--muted)">${summary}</td></tr>`);
    });
    var pagination = pages > 1 ? html`<div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-top:12px"><button class="btn" data-vuln-page="${Math.max(1, this._vulnPage - 1)}" ?disabled=${this._vulnPage <= 1}>${this._t('vuln.prev', '◀ Prev')}</button><span class="dim" style="font-size:12px">${this._t('vuln.page', 'Page')} ${this._vulnPage} ${this._t('vuln.of', 'of')} ${pages}</span><button class="btn" data-vuln-page="${Math.min(pages, this._vulnPage + 1)}" ?disabled=${this._vulnPage >= pages}>${this._t('vuln.next', 'Next ▶')}</button></div>` : '';
    return html`<div>${header}<div class="card table-card"><table class="data-table">${thead}<tbody>${rows}</tbody></table></div>${pagination}</div>`;
  },

  _openVulnDetail(cveId) {
    if (!this._vulnData || !cveId) return;
    var v = (this._vulnData.vulnerabilities || []).find(function (x) {
      return x.cve_id === cveId;
    });
    if (!v) return;
    this._vulnDetail = v;
    this._render();
  },

  _bannerDisclaimer(style) {
    return html`<div class="dim" style="font-size:11px;line-height:1.5;${style || ''}">⚠️ ${this._t('vuln.banner_disclaimer', 'CVE matches are based on the product and version reported in service banners. Distributions such as Ubuntu, Debian or RHEL often backport security fixes without changing the upstream version, so a match may be a false positive. Check your vendor\u2019s security tracker and dismiss findings that do not apply.')}</div>`;
  },

  _vulnDetailModal() {
    var v = this._vulnDetail;
    if (!v) return '';
    var self = this;
    var cid = v.cve_id || '';
    var cvss = v.cvss || 0;
    function sevClass(c) {
      return c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : 'low';
    }
    var sc = sevClass(cvss);
    var services = joinTemplates((v.services || []).map(function (s) {
      return html`<span class="chip">${s}</span>`;
    }), ' ') || '\u2014';
    var ports = joinTemplates((v.ports || []).map(function (p) {
      return html`<span class="chip">${p}</span>`;
    }), ' ') || '\u2014';
    var hosts = joinTemplates((v.affected_hosts || []).map(function (h) {
      return html`<span class="ip-chip">${h}</span>`;
    }), ' ') || html`<span class="dim">${this._t('vuln.not_detected_network', 'Not detected on this network')}</span>`;
    var cpes = (v.cpe_criteria || []).slice(0, 10).map(function (c) {
      return html`<div class="mono" style="font-size:10px;color:var(--muted);word-break:break-all">${c}</div>`;
    });
    if ((v.cpe_criteria || []).length > 10) cpes.push(html`<div class="dim" style="font-size:10px">+${v.cpe_criteria.length - 10} more</div>`);
    if (!cpes.length) cpes = html`<span class="dim">—</span>`;
    var kevSection = '';
    if (v.in_kev) {
      kevSection = html`<div style="margin-top:12px;padding:10px;border-radius:8px;background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25)"><div style="font-size:11px;font-weight:700;color:#ff4d6d;margin-bottom:6px">⚠ ${this._t('vuln.kev_title', 'CISA Known Exploited Vulnerability')}</div>${v.kev_name ? html`<div style="font-size:11px;margin-bottom:4px"><strong>${this._t('vuln.name', 'Name')}:</strong> ${v.kev_name}</div>` : ''}${v.kev_vendor || v.kev_product ? html`<div style="font-size:11px;margin-bottom:4px"><strong>${this._t('vuln.product', 'Product')}:</strong> ${(v.kev_vendor || '') + (v.kev_vendor && v.kev_product ? ' / ' : '') + (v.kev_product || '')}</div>` : ''}${v.kev_date_added ? html`<div style="font-size:11px;margin-bottom:4px"><strong>${this._t('vuln.added_to_kev', 'Added to KEV')}:</strong> ${v.kev_date_added}</div>` : ''}${v.kev_action ? html`<div style="font-size:11px"><strong>${this._t('vuln.required_action', 'Required action')}:</strong> ${v.kev_action}</div>` : ''}</div>`;
    }
    return html`<div id="hsa-vuln-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.68);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px" data-vuln-close="1"><div class="card" style="width:min(680px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(98,232,255,.26)"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px"><h1 style="font-size:16px;color:var(--accent)">${cid}</h1><button class="btn" data-vuln-close="1">✕ ${this._t('common.close', 'Close')}</button></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px"><span class="badge badge-${sc}" style="font-size:12px;padding:3px 10px">CVSS ${cvss.toFixed(1)}</span>${this._sev(v.severity || sc)}${v.published ? html`<span class="dim" style="font-size:11px">${this._t('vuln.col_published', 'Published')}: ${v.published}</span>` : ''}${v.in_kev ? html`<span class="badge badge-critical">KEV</span>` : ''}</div><div class="card-title">${this._t('vuln.summary_title', 'Summary')}</div><div style="font-size:12px;line-height:1.6;color:var(--text);margin-bottom:14px">${v.summary || this._t('vuln.no_description', 'No description available.')}</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px"><div><div class="card-title">${this._t('vuln.col_services', 'Services')}</div><div>${services}</div></div><div><div class="card-title">${this._t('vuln.col_ports', 'Ports')}</div><div>${ports}</div></div></div><div class="card-title">${this._t('vuln.affected_hosts', 'Affected Hosts')}</div><div style="margin-bottom:14px;font-size:12px">${hosts}</div>${this._bannerDisclaimer('margin-bottom:14px')}<div class="card-title">${this._t('vuln.cpe_criteria', 'CPE Criteria')}</div><div style="margin-bottom:14px">${cpes}</div>${kevSection}<div style="margin-top:14px;display:flex;gap:8px"><a href="https://nvd.nist.gov/vuln/detail/${cid}" target="_blank" rel="noopener noreferrer" class="ext-report-link">${this._t('vuln.view_on_nvd', 'View on NVD')}</a><a href="https://www.cvedetails.com/cve/${cid}/" target="_blank" rel="noopener noreferrer" class="ext-report-link">${this._t('vuln.cve_details', 'CVE Details')}</a></div></div></div>`;
  },

  _setVulnSort(col) {
    if (this._vulnSort === col) {
      this._vulnSortDir *= -1;
    } else {
      this._vulnSort = col;
      this._vulnSortDir = col === 'cve_id' || col === 'severity' || col === 'published' ? 1 : -1;
    }
    this._render();
  }
};
