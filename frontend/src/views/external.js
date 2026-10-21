// External IPs view and its detail modal.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html } from "lit";
import { joinTemplates } from "../templates.js";

export const externalMethods = {
  _extThead() {
    var self = this;
    var cols = [{
      key: 'ip',
      label: 'IP'
    }, {
      key: 'hostname',
      label: this._t('external.col_hostname', 'Hostname')
    }, {
      key: 'traffic_kb',
      label: this._t('external.col_traffic_kb', 'Traffic (KB)')
    }, {
      key: 'country',
      label: this._t('external.col_country', 'Country')
    }, {
      key: 'org',
      label: this._t('external.col_asn_org', 'ASN / Org')
    }, {
      key: 'rating',
      label: this._t('external.col_rating', 'Rating')
    }, {
      key: 'vt',
      label: this._t('external.col_vt_hits', 'VT hits')
    }, {
      key: 'abuse',
      label: this._t('external.col_abuse', 'Abuse%')
    }, {
      key: null,
      label: this._t('external.col_ports', 'Ports')
    }, {
      key: 'direction',
      label: this._t('external.col_direction', 'Direction')
    }, {
      key: 'internal_host',
      label: this._t('external.col_internal_host', 'Internal host')
    }, {
      key: 'last_seen',
      label: this._t('external.col_last_seen', 'Last seen')
    }];
    return html`<tr>${cols.map(function (c) {
      if (!c.key) return html`<th>${c.label}</th>`;
      var arrow = self._extSort === c.key ? self._extSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
      return html`<th class="sortable-th" data-extsort="${c.key}">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
    })}</tr>`;
  },

  _extPreparedList() {
    var q = this._extFilter.toLowerCase();
    var sortKey = this._extSort;
    var sortDir = this._extSortDir;
    var extIPs = (this._data && this._data.external_ips || []).slice();
    var nameMap = {};
    (this._data && this._data.devices || []).forEach(function (d) {
      nameMap[d.ip] = d.display_name || d.hostname || d.ip;
    });
    if (q) {
      extIPs = extIPs.filter(function (e) {
        return (e.ip || '').indexOf(q) >= 0 || (e.hostname || '').toLowerCase().indexOf(q) >= 0 || (e.country_name || e.country || '').toLowerCase().indexOf(q) >= 0 || (e.org || e.asn || '').toLowerCase().indexOf(q) >= 0 || (e.rating || '').toLowerCase().indexOf(q) >= 0 || (e.direction || '').toLowerCase().indexOf(q) >= 0 || (e.internal_sources || []).some(function (s) {
          return s.indexOf(q) >= 0 || nameMap[s] && nameMap[s].toLowerCase().indexOf(q) >= 0;
        }) || (e.dst_ports || []).some(function (p) {
          return String(p).indexOf(q) >= 0;
        });
      });
    }
    extIPs.sort(function (a, b) {
      var va, vb;
      if (sortKey === 'ip') {
        va = (a.ip || '').split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.');
        vb = (b.ip || '').split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.');
      } else if (sortKey === 'hostname') {
        va = (a.hostname || '').toLowerCase();
        vb = (b.hostname || '').toLowerCase();
      } else if (sortKey === 'traffic_kb') {
        va = a.total_octets || 0;
        vb = b.total_octets || 0;
        return (va - vb) * sortDir;
      } else if (sortKey === 'country') {
        va = (a.country_name || a.country || '').toLowerCase();
        vb = (b.country_name || b.country || '').toLowerCase();
      } else if (sortKey === 'org') {
        va = (a.org || a.asn || '').toLowerCase();
        vb = (b.org || b.asn || '').toLowerCase();
      } else if (sortKey === 'rating') {
        var rOrder = {
          malicious: 0,
          suspicious: 1,
          clean: 2,
          '': 3
        };
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
        var dOrder = {
          outbound: 0,
          inbound: 1,
          both: 2
        };
        va = dOrder[a.direction || 'outbound'] !== undefined ? dOrder[a.direction || 'outbound'] : 0;
        vb = dOrder[b.direction || 'outbound'] !== undefined ? dOrder[b.direction || 'outbound'] : 0;
        return (va - vb) * sortDir;
      } else if (sortKey === 'internal_host') {
        va = (a.internal_sources || a.sources || []).map(function (s) {
          return nameMap[s] || s;
        }).sort().join(',').toLowerCase();
        vb = (b.internal_sources || b.sources || []).map(function (s) {
          return nameMap[s] || s;
        }).sort().join(',').toLowerCase();
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
  },

  _extPageBar() {
    var total = this._extPreparedList().length;
    var totalPages = Math.max(1, Math.ceil(total / this._extPageSize));
    var page = Math.min(this._extPage, totalPages);
    var start = total === 0 ? 0 : (page - 1) * this._extPageSize + 1;
    var end = Math.min(total, page * this._extPageSize);
    return html`<div class="row-gap" style="justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);flex-wrap:wrap"><div class="row-gap" style="font-size:11px;color:var(--muted)">${this._t('external.showing', 'Showing')} ${start}-${end} of ${total}</div><div class="row-gap" style="gap:6px"><label class="dim" style="font-size:11px">${this._t('common.rows', 'Rows')}</label><select id="hsa-ext-pagesize" class="role-select">${[10, 25, 50, 100].map(n => html`<option value="${n}" ?selected=${n === this._extPageSize}>${n}</option>`)}</select><button class="btn" data-extpage="prev" ?disabled=${page <= 1}>${this._t('common.previous', 'Previous')}</button><span class="dim" style="font-size:11px;min-width:70px;text-align:center">${page} / ${totalPages}</span><button class="btn" data-extpage="next" ?disabled=${page >= totalPages}>${this._t('common.next', 'Next')}</button></div></div>`;
  },

  _extRows() {
    var extIPs = this._extPreparedList();
    var totalPages = Math.max(1, Math.ceil(extIPs.length / this._extPageSize));
    this._extPage = Math.min(Math.max(1, this._extPage), totalPages);
    var start = (this._extPage - 1) * this._extPageSize;
    extIPs = extIPs.slice(start, start + this._extPageSize);
    if (!extIPs.length) return html`<tr><td colspan="12"><div class="empty-state"><div class="empty-icon">🔍</div><p>${this._t('external.no_match', 'No external IPs match the filter')}</p></div></td></tr>`;
    var self = this;
    var nameMap = {};
    (this._data && this._data.devices || []).forEach(function (d) {
      nameMap[d.ip] = d.display_name || d.hostname || d.ip;
    });
    return extIPs.map(function (e) {
      var rating = e.rating || (e.blacklisted ? 'malicious' : '');
      var vt = e.vt_malicious != null ? e.vt_malicious + '/' + ((e.vt_malicious || 0) + (e.vt_suspicious || 0) + (e.vt_harmless || 0)) : '\u2014';
      var abuse = e.abuse_confidence != null ? e.abuse_confidence + '%' : '\u2014';
      var trafficKb = ((e.total_octets || 0) / 1024).toFixed(1);
      var host = e.hostname || '';
      var dstPorts = (e.dst_ports || []).slice(0, 8);
      var portsHtml = dstPorts.length ? html`${joinTemplates(dstPorts.map(function (p) {
        return html`<span class="chip">${p}</span>`;
      }), ' ')}${e.dst_ports.length > 8 ? html` <span class="dim">+${e.dst_ports.length - 8}</span>` : ''}` : html`<span class="dim">—</span>`;
      var dir = e.direction || 'outbound';
      var directionHtml = dir === 'both' ? html`<span style="color:#a78bfa;font-size:11px">${self._t('external.direction_both', '↕ Both')}${e.direction_alert ? html` <span title="Different internal hosts involved in each direction — an external IP contacted a server that did not initiate the outbound relationship. Review recommended." style="cursor:help;color:#f59e0b">⚠</span>` : ''}</span>` : dir === 'inbound' ? html`<span style="color:#fb923c;font-size:11px">${self._t('external.direction_inbound', '↓ Inbound')}</span>` : html`<span style="color:#34d399;font-size:11px">${self._t('external.direction_outbound', '↑ Outbound')}</span>`;
      var sources = e.internal_sources || e.sources || [];
      var sourcesHtml = sources.length ? joinTemplates(sources.map(function (s) {
        var name = nameMap[s] || s;
        return html`<span class="ip-chip" title="${s}">${name}</span>`;
      }), ' ') : html`<span class="dim">—</span>`;
      var ratingHtml = rating ? self._ratingWithSource(rating, e.rating_source) : html`<span class="dim">—</span>`;
      var countryFlag = self._countryFlag(e.country);
      var countryTitle = e.country_name || e.country || '';
      return html`<tr style="cursor:pointer" data-ext-ip-row="${e.ip}"><td>${e.blacklisted ? html`<span style="color:#ff4d6d;margin-right:3px">⚠</span>` : ''}<span class="ip">${e.ip}</span></td><td style="font-size:11px">${host ? host : html`<span class="dim">—</span>`}</td><td style="font-family:monospace;font-size:11px;text-align:right">${trafficKb}</td><td style="font-size:11px">${countryFlag ? html`<span title="${countryTitle}" style="font-size:15px;line-height:1">${countryFlag}</span>` : html`<span class="dim">—</span>`}</td><td style="font-size:11px">${(e.org || '').substring(0, 30) || e.asn || '\u2014'}</td><td>${ratingHtml}</td><td style="font-family:monospace;font-size:11px">${vt}</td><td style="font-family:monospace;font-size:11px">${abuse}</td><td style="font-size:11px">${portsHtml}</td><td style="font-size:11px">${directionHtml}</td><td style="font-size:11px">${sourcesHtml}</td><td style="font-size:10px;color:var(--muted)">${self._ago(e.last_seen)}</td></tr>`;
    });
  },

  _viewExternal() {
    var totalCount = (this._data && this._data.external_ips || []).length;
    return html`<div><div class="view-header"><h1>${this._t('external.page_title', 'External IPs')} <span class="dim">(${totalCount})</span></h1><input id="hsa-ext-filter" class="search-bar" type="search" placeholder="${this._t('external.filter_placeholder', 'Filter by IP, hostname, country, org…')}" value="${this._extFilter}"></div><div id="hsa-ext-pagebar">${this._extPageBar()}</div><div class="card table-card"><table class="data-table"><thead id="hsa-ext-thead">${this._extThead()}</thead><tbody id="hsa-ext-tbody">${this._extRows()}</tbody></table></div></div>`;
  },

  _ipDetail(d, internalSources, direction) {
    var ip = d.ip || '';
    var self = this;
    var reportLinks = ip ? [['ipwho.is', 'https://ipwho.is/' + encodeURIComponent(ip)], ['AbuseIPDB', 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip)], ['VirusTotal', 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip)]] : [];
    var pairs = [[this._t('external.modal_hostname', 'Hostname'), d.hostname], [this._t('external.modal_country', 'Country'), d.country_name || d.country], [this._t('external.modal_asn', 'ASN'), d.asn], [this._t('external.modal_org_isp', 'ISP / Org'), d.org || d.isp], [this._t('external.modal_city', 'City'), d.city], [this._t('external.modal_timezone', 'Timezone'), d.timezone], [this._t('external.modal_vt', 'VirusTotal'), d.vt_malicious != null ? d.vt_malicious + ' ' + self._t('external.modal_malicious', 'malicious') + ', ' + d.vt_suspicious + ' ' + self._t('external.modal_suspicious', 'suspicious') + ', ' + d.vt_harmless + ' ' + self._t('external.modal_harmless', 'harmless') : null], [this._t('external.modal_vt_rep', 'VT Reputation'), d.vt_reputation != null ? String(d.vt_reputation) : null], [this._t('external.modal_abuse', 'Abuse score'), d.abuse_confidence != null ? d.abuse_confidence + '% (' + d.abuse_total_reports + ' ' + self._t('external.modal_reports', 'reports') + ')' : null], [this._t('external.modal_rating_source', 'Rating source'), d.rating_source || null], [this._t('external.blacklisted', 'Blacklisted'), d.blacklisted ? self._t('external.modal_yes', 'Yes') + ' \u2013 ' + (d.blacklist_info && d.blacklist_info.source || 'threat_intel') : self._t('external.modal_no', 'No')], [this._t('external.modal_direction', 'Direction'), function (dir) {
      return dir.charAt(0).toUpperCase() + dir.slice(1);
    }(direction || d.direction || 'outbound')], [this._t('external.modal_data_sources', 'Data sources'), d.sources && d.sources.join(', ') || '\u2014'], [this._t('external.modal_enriched_at', 'Enriched at'), d.enriched_at ? this._ago(d.enriched_at) : null]].filter(function (p) {
      return p[1] != null && p[1] !== '';
    });
    var pairsHtml = pairs.map(function (p) {
      return html`<div class="detail-pair"><span class="detail-key">${p[0]}</span><span class="detail-val">${String(p[1])}</span></div>`;
    });
    var linksHtml = reportLinks.length ? html`<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">${this._t('external.modal_reports', 'Reports')}</span><span class="detail-val">${joinTemplates(reportLinks.map(function (item) {
      return html`<a class="ext-report-link" href="${item[1]}" target="_blank" rel="noopener noreferrer">${item[0]}</a>`;
    }), ' ')}</span></div>` : '';
    var sources = internalSources || d.internal_sources || [];
    var sourcesHtml = sources.length ? html`<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">${this._t('external.modal_internal_host', 'Internal host')}</span><span class="detail-val">${joinTemplates(sources.map(function (s) {
      return html`<span class="ip-chip">${s}</span>`;
    }), ' ')}</span></div>` : '';
    return html`<div class="ip-detail-panel"><h3>🔍 ${d.ip} ${d.rating ? this._rating(d.rating) : ''}</h3><div class="detail-grid">${pairsHtml}${linksHtml}${sourcesHtml}</div>${d.error ? html`<div style="color:var(--danger);margin-top:8px;font-size:11px">⚠ ${this._t('external.modal_error', 'Enrichment error:')} ${d.error}</div>` : ''}</div>`;
  },

  _extIPDetailModal() {
    var e = this._extIPDetail;
    if (!e) return '';
    var self = this;
    var nameMap = {};
    (this._data && this._data.devices || []).forEach(function (d) {
      nameMap[d.ip] = d.display_name || d.hostname || d.ip;
    });
    var ip = e.ip || '';
    var isLooking = self._lookupIP === ip && self._lookingUp;
    var enriched = self._lookupResult && self._lookupIP === ip ? self._lookupResult : null;
    function row(label, value) {
      return html`<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span style="font-size:11px;color:var(--muted);min-width:120px;flex-shrink:0">${label}</span><span style="font-size:12px;word-break:break-all">${value}</span></div>`;
    }
    var rating = e.rating || (e.blacklisted ? 'malicious' : '');
    var ratingBadge = rating ? self._ratingWithSource(rating, e.rating_source) : html`<span class="dim">—</span>`;
    var countryFlag = self._countryFlag(e.country);
    var countryDisplay = html`${countryFlag ? html`<span style="font-size:15px">${countryFlag}</span> ` : ''}${e.country_name || e.country || '\u2014'}`;
    var vtHtml = e.vt_malicious != null ? e.vt_malicious + '/' + ((e.vt_malicious || 0) + (e.vt_suspicious || 0) + (e.vt_harmless || 0)) + ' ' + self._t('external.modal_malicious', 'malicious') : '\u2014';
    var abuseHtml = e.abuse_confidence != null ? e.abuse_confidence + '%' + (e.abuse_total_reports ? ' (' + e.abuse_total_reports + ' ' + self._t('external.modal_reports', 'reports') + ')' : '') : '\u2014';
    var blacklistHtml = e.blacklisted ? html`<span style="color:#ff4d6d">⚠ ${self._t('external.modal_yes', 'Yes')}${e.blacklist_info && e.blacklist_info.source ? ' \u2013 ' + e.blacklist_info.source : ''}</span>` : html`<span style="color:#6bffc8">${self._t('external.modal_no', 'No')}</span>`;
    var dir = e.direction || 'outbound';
    var directionHtml = dir === 'both' ? html`<span style="color:#a78bfa">↕ ${self._t('external.direction_both', 'Both')}</span>` : dir === 'inbound' ? html`<span style="color:#fb923c">↓ ${self._t('external.direction_inbound', 'Inbound')}</span>` : html`<span style="color:#34d399">↑ ${self._t('external.direction_outbound', 'Outbound')}</span>`;
    var dstPorts = (e.dst_ports || []).slice(0, 16);
    var portsHtml = dstPorts.length ? html`${joinTemplates(dstPorts.map(function (p) {
      return html`<span class="chip">${p}</span>`;
    }), ' ')}${e.dst_ports.length > 16 ? html` <span class="dim">+${e.dst_ports.length - 16}</span>` : ''}` : '\u2014';
    var sources = e.internal_sources || e.sources || [];
    var sourcesHtml = sources.length ? joinTemplates(sources.map(function (s) {
      var name = nameMap[s] || s;
      return html`<span class="ip-chip" title="${s}">${name}</span>`;
    }), ' ') : '\u2014';
    var trafficKb = ((e.total_octets || 0) / 1024).toFixed(1) + ' KB';
  
    // Enrichment section
    var enrichSection = '';
    if (isLooking) {
      enrichSection = html`<div style="display:flex;align-items:center;gap:8px;padding:12px 0;color:var(--muted);font-size:12px"><span class="spin"></span> ${this._t('external.running_lookup', 'Running enrichment lookup…')}</div>`;
    } else if (enriched) {
      var enrichPairs = [[self._t('external.modal_city', 'City'), enriched.city], [self._t('external.modal_timezone', 'Timezone'), enriched.timezone], [self._t('external.modal_isp', 'ISP'), enriched.isp], [self._t('external.modal_vt_rep', 'VT Reputation'), enriched.vt_reputation != null ? String(enriched.vt_reputation) : null], [self._t('external.modal_enriched_at', 'Enriched at'), enriched.enriched_at ? self._ago(enriched.enriched_at) : null]].filter(function (p) {
        return p[1] != null && p[1] !== '';
      });
      if (enrichPairs.length || enriched.error) {
        enrichSection = html`<div class="card-title" style="margin-top:14px;margin-bottom:6px">${this._t('external.enrichment_details', 'Enrichment Details')}</div>${enrichPairs.map(function (p) {
          return row(p[0], String(p[1]));
        })}${enriched.error ? html`<div style="color:var(--danger);font-size:11px;margin-top:6px">⚠ ${enriched.error}</div>` : ''}`;
      }
    } else {
      enrichSection = html`<div style="margin-top:10px"><button class="btn" data-ext-lookup="${ip}">${this._t('external.run_full_lookup', '🔍 Run Full Lookup')}</button></div>`;
    }
  
    // External links
    var linksHtml = ip ? html`<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">${[html`<a href="https://ipwho.is/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">ipwho.is</a>`, html`<a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">AbuseIPDB</a>`, html`<a href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">VirusTotal</a>`, html`<a href="https://www.shodan.io/host/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer" class="ext-report-link">Shodan</a>`]}</div>` : '';
    return html`<div id="hsa-ext-ip-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px"><div class="card" style="width:min(620px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(98,232,255,.26)"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px"><h1 style="font-size:15px;color:var(--accent);margin:0;font-family:monospace">${ip}</h1><button class="btn" data-ext-close="1">✕ ${this._t('common.close', 'Close')}</button></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">${ratingBadge}${e.blacklisted ? html` <span class="badge badge-critical">⚠ ${this._t('external.blacklisted', 'Blacklisted')}</span>` : ''}</div><div class="card-title" style="margin-bottom:6px">${this._t('external.ip_info', 'IP Info')}</div>${row(this._t('external.modal_hostname', 'Hostname'), e.hostname || '\u2014')}${row(this._t('external.modal_country', 'Country'), countryDisplay)}${row(this._t('external.modal_asn', 'ASN'), e.asn || '\u2014')}${row(this._t('external.modal_org_isp', 'Org / ISP'), e.org || e.isp || '\u2014')}${row(this._t('external.modal_vt', 'VirusTotal'), vtHtml)}${row(this._t('external.modal_abuse', 'Abuse score'), abuseHtml)}${row(this._t('external.blacklisted', 'Blacklisted'), blacklistHtml)}<div class="card-title" style="margin-top:14px;margin-bottom:6px">${this._t('external.traffic', 'Traffic')}</div>${row(this._t('external.modal_direction', 'Direction'), directionHtml)}${row(this._t('external.ports_contacted', 'Ports contacted'), portsHtml)}${row(this._t('external.internal_hosts', 'Internal hosts'), sourcesHtml)}${row(this._t('external.total_traffic', 'Total traffic'), trafficKb)}${row(this._t('external.modal_last_seen', 'Last seen'), self._ago(e.last_seen))}${enrichSection}${linksHtml}</div></div>`;
  },

  _setExtSort(col) {
    if (this._extSort === col) {
      this._extSortDir *= -1;
    } else {
      this._extSort = col;
      // Numeric/threat columns: default descending (highest first)
      var descFirst = {
        vt: 1,
        abuse: 1,
        traffic_kb: 1,
        rating: 1
      };
      this._extSortDir = descFirst[col] ? -1 : 1;
    }
    this._extPage = 1;
    this._render();
  }
};
