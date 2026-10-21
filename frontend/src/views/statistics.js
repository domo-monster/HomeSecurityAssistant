// Statistics view.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, svg } from "lit";

export const statisticsMethods = {
  // ── Statistics view ──────────────────────────────────────────────────
  _viewStatistics() {
    var self = this;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var dnsProxyEnabledRaw = this._data && this._data.dns_proxy_enabled;
    var dnsProxyEnabled = dnsProxyEnabledRaw === true || dnsProxyEnabledRaw === 'true' || dnsProxyEnabledRaw === 1 || dnsProxyEnabledRaw === '1';
    var suricataEnabledStats = this._data && this._data.suricata_stats && this._data.suricata_stats.running || false;
    var modes = this._statsViewModes;
    var topN = this._data && this._data.stats_top_n || 10;
    var COLORS = ['#8f86ff', '#3ac5c9', '#6bffc8', '#ffc107', '#ff8c42', '#ff4d6d', '#7fb3f5', '#d4a843', '#a8e063', '#f472b6', '#60a5fa', '#34d399', '#fb923c', '#a78bfa', '#22d3ee'];
  
    // ── Suricata pie data ─────────────────────────────────────────────
    // Counts are computed by the server over the full logs (not just the
    // entries the dashboard sends).
    var sucStats = this._data && this._data.suricata_log_stats || {};
    var SUC_SEV_COLORS = ['rgba(255,77,109,1)', 'rgba(255,179,71,1)', 'rgba(107,255,200,1)'];
    var SUC_CAT_PALETTE = ['rgba(255,77,109,1)', 'rgba(255,179,71,1)', 'rgba(107,255,200,1)', 'rgba(98,232,255,1)', 'rgba(191,111,255,1)', 'rgba(59,178,255,1)', 'rgba(72,199,142,1)', 'rgba(255,159,67,1)'];
    var SUC_SRC_PALETTE = ['rgba(98,232,255,1)', 'rgba(59,178,255,1)', 'rgba(72,199,142,1)', 'rgba(191,111,255,1)', 'rgba(255,179,71,1)', 'rgba(255,77,109,1)', 'rgba(107,255,200,1)', 'rgba(155,135,245,1)'];
    var sucSevLabels = {
      1: this._t('suricata.sev_critical', 'Critical'),
      2: this._t('suricata.sev_major', 'Major'),
      3: this._t('suricata.sev_minor', 'Minor')
    };
    var sucBySeverity = sucStats.by_severity || {};
    var sucSevData = [1, 2, 3].filter(function (s) {
      return sucBySeverity[s] > 0;
    }).map(function (s) {
      return {
        label: sucSevLabels[s],
        value: sucBySeverity[s]
      };
    });
    var sucCatColors = [];
    var nameMap = {};
    (this._data && this._data.devices || []).forEach(function (d) {
      nameMap[d.ip] = d.display_name || d.hostname || d.ip;
    });
    var sucCatData = (sucStats.by_category || []).map(function (x, i) {
      sucCatColors.push(SUC_CAT_PALETTE[i % SUC_CAT_PALETTE.length]);
      return {
        label: x.category,
        value: x.count
      };
    });
    var sucSrcData = (sucStats.top_sources || []).slice(0, topN).map(function (x) {
      var name = nameMap[x.ip] || x.ip;
      var label = name === x.ip ? x.ip : name + ' (' + x.ip + ')';
      return {
        label: label,
        value: x.count
      };
    });
  
    // ── Timeline ─────────────────────────────────────────────────────
    var allPoints = this._data && this._data.timeseries || [];
  
    // Public IPs per period — derived from last_seen on each external IP entry
    var _extIpsList = this._data && this._data.external_ips || [];
    var _now = Date.now();
    var extIps1h = _extIpsList.filter(function (e) {
      return e.last_seen && _now - new Date(e.last_seen).getTime() <= 3600000;
    }).length;
    var extIps24h = _extIpsList.filter(function (e) {
      return e.last_seen && _now - new Date(e.last_seen).getTime() <= 86400000;
    }).length;
    var extIps7d = _extIpsList.filter(function (e) {
      return e.last_seen && _now - new Date(e.last_seen).getTime() <= 604800000;
    }).length;
    var extIpsTotal = _extIpsList.length;
    var extIpsBadges = html`<span style="font-size:10px;color:var(--muted)">1h <strong style="color:var(--fg)">${extIps1h}</strong> · 24h <strong style="color:var(--fg)">${extIps24h}</strong> · 7d <strong style="color:var(--fg)">${extIps7d}</strong> · all <strong style="color:var(--fg)">${extIpsTotal}</strong></span>`;
    var timelineHtml = html`<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><span class="card-title" style="margin-bottom:0">${this._t('stats.activity_timeline', 'ACTIVITY TIMELINE')}</span></div><div style="margin-bottom:16px"><div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px"><span style="font-size:10px;color:var(--muted)">${this._t('stats.public_ips_per_hour', 'Public IPs seen per hour (last 24h)')}</span>${extIpsBadges}</div>${function () {
      var EXT_H = 24,
        BAR_W = 18,
        BAR_GAP = 3,
        CHART_H = 60,
        LABEL_H = 16;
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
      var bars = extBuckets.map(function (cnt, i) {
        var x = i * (BAR_W + BAR_GAP);
        var bh = Math.max(2, Math.round(cnt / maxExt * CHART_H));
        var lhour = new Date(nowMs - (EXT_H - 1 - i) * 3600000).getHours();
        var tip = lhour + 'h \u2014 ' + cnt + ' IP' + (cnt !== 1 ? 's' : '');
        return svg`<rect x="${x}" y="${CHART_H - bh}" width="${BAR_W}" height="${bh}" fill="#8f86ff" opacity="0.75" rx="2"><title>${tip}</title></rect>`;
      });
      var labels = [];
      for (var li = 0; li < EXT_H; li += 4) {
        var lx = li * (BAR_W + BAR_GAP) + BAR_W / 2;
        var lhour = new Date(nowMs - (EXT_H - 1 - li) * 3600000).getHours();
        labels.push(svg`<text x="${lx}" y="${CHART_H + LABEL_H - 3}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${lhour}h</text>`);
      }
      if (!_extIpsList.length) return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">${self._t('stats.no_public_ips', 'No public IPs tracked yet')}</div>`;
      return html`<svg viewBox="0 0 ${svgW} ${CHART_H + LABEL_H}" width="100%" height="${CHART_H + LABEL_H}" preserveAspectRatio="none" style="display:block">${bars}${labels}</svg>`;
    }()}</div><div style="margin-top:16px"><div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px"><span style="font-size:10px;color:var(--muted)">${this._t('stats.hosts_per_hour', 'Hosts per hour (last 24h)')}</span></div>${function () {
      var H_HOURS = 24,
        H_BAR_W = 18,
        H_BAR_GAP = 3,
        H_CHART = 60,
        H_LABEL = 16;
      var nowMs2 = Date.now();
      var hostBkts = [],
        scannedBkts = [];
      for (var hbi = 0; hbi < H_HOURS; hbi++) {
        var hbEnd = nowMs2 - hbi * 3600000,
          hbStart = hbEnd - 3600000;
        var mxH = 0,
          mxS = 0;
        for (var hpi = 0; hpi < allPoints.length; hpi++) {
          var hpt = new Date(allPoints[hpi].ts).getTime();
          if (hpt >= hbStart && hpt < hbEnd) {
            var hv = Number(allPoints[hpi].hosts || 0),
              sv = Number(allPoints[hpi].scanned || 0);
            if (hv > mxH) mxH = hv;
            if (sv > mxS) mxS = sv;
          }
        }
        hostBkts.unshift(mxH);
        scannedBkts.unshift(mxS);
      }
      if (!allPoints.length) return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">${self._t('stats.no_host_data', 'No host data yet')}</div>`;
      var mxAll = Math.max.apply(null, hostBkts) || 1;
      var hSvgW = H_HOURS * (H_BAR_W + H_BAR_GAP);
      var hBars = hostBkts.map(function (h, i) {
        var s = scannedBkts[i];
        var x = i * (H_BAR_W + H_BAR_GAP);
        var bh = Math.max(2, Math.round(h / mxAll * H_CHART));
        var sh = s > 0 ? Math.max(2, Math.round(s / mxAll * H_CHART)) : 0;
        var lhour = new Date(nowMs2 - (H_HOURS - 1 - i) * 3600000).getHours();
        var tip = lhour + 'h \u2014 ' + h + ' host' + (h !== 1 ? 's' : '') + (s > 0 ? ' (' + s + ' scanned)' : '');
        return svg`<rect x="${x}" y="${H_CHART - bh}" width="${H_BAR_W}" height="${bh}" fill="rgba(58,197,201,.45)" rx="2"><title>${tip}</title></rect>${sh > 0 ? svg`<rect x="${x}" y="${H_CHART - sh}" width="${H_BAR_W}" height="${sh}" fill="rgba(107,255,200,.75)" rx="2"><title>${tip}</title></rect>` : ''}`;
      });
      var hLabels = [];
      for (var hl = 0; hl < H_HOURS; hl += 4) {
        var hlx = hl * (H_BAR_W + H_BAR_GAP) + H_BAR_W / 2;
        var hlHour = new Date(nowMs2 - (H_HOURS - 1 - hl) * 3600000).getHours();
        hLabels.push(svg`<text x="${hlx}" y="${H_CHART + H_LABEL - 3}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${hlHour}h</text>`);
      }
      return html`<svg viewBox="0 0 ${hSvgW} ${H_CHART + H_LABEL}" width="100%" height="${H_CHART + H_LABEL}" preserveAspectRatio="none" style="display:block">${hBars}${hLabels}</svg><div style="display:flex;gap:12px;margin-top:4px;font-size:10px"><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(58,197,201,.45);display:inline-block;border-radius:2px"></span>${self._t('stats.hosts_seen', 'Hosts seen')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(107,255,200,.75);display:inline-block;border-radius:2px"></span>${self._t('stats.scanned_alive', 'Scanned alive')}</span></div>`;
    }()}</div>`;
    // stat-card outer </div> is appended in the return after the DNS Activity section
  
    function toggleBtns(id, current) {
      return html`<span style="display:flex;gap:4px;flex-shrink:0"><button class="btn${current === 'pie' ? ' active' : ''}" style="padding:3px 8px;font-size:10px" data-statstoggle="${id}:pie"><svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M7 1.07A7 7 0 1 0 15 9H7V1.07z"/><path d="M8.5.5v7h7A7.5 7.5 0 0 0 8.5.5z"/></svg>${self._t('stats.pie', 'Pie')}</button><button class="btn${current === 'list' ? ' active' : ''}" style="padding:3px 8px;font-size:10px" data-statstoggle="${id}:list"><svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5z"/></svg>${self._t('stats.list', 'List')}</button></span>`;
    }
    function chartSection(svgHtml, legendHtml) {
      return html`<div class="stats-chart-row">${svgHtml}<div class="stats-chart-legend">${legendHtml}</div></div>`;
    }
  
    // ── Top public IPs ────────────────────────────────────────────────
    var topIPs = this._data && this._data.top_public_ips || [];
    var ipsSection;
    if (!topIPs.length) {
      ipsSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_external_flow_data', 'No external flow data yet')}</p></div>`;
    } else if (modes.public_ips === 'pie') {
      ipsSection = chartSection(self._pieSvg(topIPs, function (e) {
        return e.flows;
      }, function (e) {
        return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : '');
      }, COLORS), html`${self._statsLegend(topIPs, function (e) {
        return e.flows;
      }, function (e) {
        return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : '') + (e.blacklisted ? ' \u26a0' : '');
      }, COLORS)}<div style="margin-top:8px;font-size:10px;color:var(--muted)">${this._t('stats.ranked_by_flow_count', 'Ranked by flow count')}</div><button class="btn" style="margin-top:8px" data-view="external">${this._t('stats.view_all_external_ips', 'View all external IPs →')}</button>`);
    } else {
      ipsSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th></tr></thead><tbody>${topIPs.map(function (e, i) {
        var label = e.hostname || e.org || e.ip;
        var country = e.country_name || e.country || '';
        var countryFlag = self._countryFlag(e.country);
        var bc = e.blacklisted ? 'badge-critical' : e.rating === 'suspicious' ? 'badge-warn' : 'badge-ok';
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${e.ip}</span></td><td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${label}</td><td>${countryFlag ? html`<span title="${country}" style="font-size:15px;line-height:1">${countryFlag}</span>` : html`<span class="dim">${country || '—'}</span>`}</td><td style="text-align:right">${e.flows.toLocaleString()}</td><td><span class="badge ${bc}">${e.blacklisted ? 'malicious' : e.rating || 'ok'}</span></td></tr>`;
      })}</tbody></table><button class="btn" style="margin-top:8px" data-view="external">${this._t('stats.view_all_external_ips', 'View all external IPs →')}</button>`;
    }
  
    // ── Top countries ─────────────────────────────────────────────────
    var topC = this._data && this._data.top_countries || [];
    var countriesSection;
    if (!topC.length) {
      countriesSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_country_data', 'No country data yet')}</p></div>`;
    } else if (modes.countries === 'pie') {
      countriesSection = chartSection(self._pieSvg(topC, function (c) {
        return c.flow_count;
      }, function (c) {
        return (c.country_name || c.country) + ' (' + c.ip_count + ' IPs)';
      }, COLORS), html`${self._statsLegend(topC, function (c) {
        return c.flow_count;
      }, function (c) {
        return (c.country_name || c.country || '\u2014') + ' (' + c.ip_count + ' IPs)';
      }, COLORS)}<div style="margin-top:8px;font-size:10px;color:var(--muted)">${this._t('stats.ranked_by_flow_count', 'Ranked by flow count')}</div>`);
    } else {
      var maxFlows = topC[0] ? topC[0].flow_count : 1;
      countriesSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>CC</th><th>Country</th><th style="text-align:right">Unique IPs</th><th style="text-align:right">Flows</th><th>Share</th></tr></thead><tbody>${topC.map(function (c, i) {
        var pct = maxFlows > 0 ? Math.round(c.flow_count / maxFlows * 100) : 0;
        var ccFlag = self._countryFlag(c.country);
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><b>${ccFlag ? html`<span title="${c.country || '—'}" style="font-size:15px;line-height:1">${ccFlag}</span>` : c.country || '\u2014'}</b></td><td>${c.country_name || c.country || '\u2014'}</td><td style="text-align:right">${c.ip_count.toLocaleString()}</td><td style="text-align:right">${c.flow_count.toLocaleString()}</td><td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:${pct}%;background:var(--accent,#8f86ff);border-radius:3px;height:8px"></div></div></td></tr>`;
      })}</tbody></table>`;
    }
  
    // ── Top internal talkers ──────────────────────────────────────────
    var topT = this._data && this._data.top_internal_talkers || [];
    var talkersSection;
    if (!topT.length) {
      talkersSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_traffic_data', 'No traffic data yet')}</p></div>`;
    } else if (modes.talkers === 'pie') {
      talkersSection = chartSection(self._pieSvg(topT, function (d) {
        return d.total_octets;
      }, function (d) {
        return d.display_name || d.ip;
      }, COLORS), html`${self._statsLegend(topT, function (d) {
        return d.total_octets;
      }, function (d) {
        return (d.display_name || d.ip) + ' \u00b7 ' + self._bytes(d.total_octets);
      }, COLORS)}<div style="margin-top:8px;font-size:10px;color:var(--muted)">${this._t('stats.ranked_by_total_traffic', 'Ranked by total traffic')}</div><button class="btn" style="margin-top:8px" data-view="hosts">${this._t('stats.view_all_hosts', 'View all hosts →')}</button>`);
    } else {
      var maxOct = topT[0] ? topT[0].total_octets : 1;
      talkersSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>IP</th><th>Name</th><th>Role</th><th style="text-align:right">Traffic</th><th>Share</th></tr></thead><tbody>${topT.map(function (d, i) {
        var pct = maxOct > 0 ? Math.round(d.total_octets / maxOct * 100) : 0;
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${d.ip}</span></td><td>${d.display_name}</td><td>${d.probable_role || '\u2014'}</td><td style="text-align:right">${self._bytes(d.total_octets)}</td><td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:${pct}%;background:#3ac5c9;border-radius:3px;height:8px"></div></div></td></tr>`;
      })}</tbody></table><button class="btn" style="margin-top:8px" data-view="hosts">${this._t('stats.view_all_hosts', 'View all hosts →')}</button>`;
    }
  
    // ── Enrichment budget (table only) ────────────────────────────────
    var eStats = this._data && this._data.enrichment_stats || [];
    var enrichSection;
    if (!eStats.length) {
      enrichSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_enrichment_data', 'No enrichment data')}</p></div>`;
    } else {
      enrichSection = html`<div style="overflow-x:auto"><table class="data-table" style="width:100%;min-width:480px"><thead><tr><th>${this._t('stats.provider', 'Provider')}</th><th style="width:80px;text-align:right">${this._t('stats.used_today', 'Used today')}</th><th style="width:90px;text-align:right">${this._t('stats.daily_budget', 'Daily budget')}</th><th style="width:110px">${this._t('stats.usage', 'Usage')}</th><th style="width:80px">${this._t('stats.status', 'Status')}</th><th>${this._t('stats.errors_notes', 'Errors / Notes')}</th></tr></thead><tbody>${eStats.map(function (s) {
        var PROV_LABELS = {
          ipwho: 'ipwho.is',
          virustotal: 'VirusTotal',
          abuseipdb: 'AbuseIPDB'
        };
        var provLabel = (PROV_LABELS[s.provider] || s.provider) + (s.variant ? ' (' + s.variant + ')' : '');
        var unlimited = s.budget === null || s.budget === undefined;
        var pct = !unlimited && s.budget > 0 ? Math.min(100, Math.round(s.used / s.budget * 100)) : 0;
        var barColor = s.exhausted ? '#ff4d6d' : unlimited || pct <= 80 ? '#6bffc8' : '#ffc107';
        var badge = !s.configured ? html`<span class="badge badge-dim">${self._t('stats.not_configured', 'not configured')}</span>` : s.exhausted ? html`<span class="badge badge-critical">${self._t('stats.exhausted', 'exhausted')}</span>` : unlimited ? html`<span class="badge badge-ok">${self._t('stats.unlimited', '∞ unlimited')}</span>` : pct > 80 ? html`<span class="badge badge-warn">${self._t('stats.high', 'high')}</span>` : html`<span class="badge badge-ok">${self._t('stats.ok', 'ok')}</span>`;
        var errCell = '';
        if (s.last_error) {
          var errStr = String(s.last_error);
          // Auth errors (401/403) in orange; server errors (5xx) in red
          var errColor = errStr.indexOf('401') !== -1 || errStr.indexOf('403') !== -1 ? '#ffc107' : '#ff4d6d';
          errCell = html`<span style="color:${errColor};font-size:11px;font-weight:600">⚠️ ${errStr}</span>`;
        }
        return html`<tr><td><b>${provLabel}</b></td><td style="text-align:right">${s.used.toLocaleString()}</td><td style="text-align:right">${unlimited ? '\u221e' : s.budget.toLocaleString()}</td><td style="width:120px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:${unlimited ? 100 : pct}%;background:${barColor};border-radius:3px;height:8px"></div></div></td><td>${badge}</td><td>${errCell}</td></tr>`;
      })}</tbody></table></div>`;
    }
  
    // ── Top suspicious / malicious IPs ────────────────────────────────
    var THREAT_COLORS = ['#ff4d6d', '#ff8c42', '#ffc107', '#f472b6', '#fb923c', '#ff6b6b', '#e879f9', '#facc15', '#fd8dac', '#ffb347'];
    var topThr = this._data && this._data.top_threat_ips || [];
    var threatSection;
    if (!topThr.length) {
      threatSection = html`<div class="empty-state"><div class="empty-icon" style="font-size:24px">✅</div><p style="margin:8px 0">${this._t('stats.no_threat_ips', 'No suspicious or malicious IPs detected')}</p></div>`;
    } else if (modes.threat_ips === 'pie') {
      threatSection = chartSection(self._pieSvg(topThr, function (e) {
        return Math.max(e.flows, 1);
      }, function (e) {
        return e.ip + (e.hostname ? ' (' + e.hostname + ')' : '') + ' — ' + e.rating;
      }, THREAT_COLORS), html`${self._statsLegend(topThr, function (e) {
        return Math.max(e.flows, 1);
      }, function (e) {
        var label = e.hostname || e.org || e.ip;
        return label + ' · ' + e.rating + (e.flows ? ' · ' + e.flows.toLocaleString() + ' flows' : '');
      }, THREAT_COLORS)}<div style="margin-top:8px;font-size:10px;color:var(--muted)">${this._t('stats.malicious_first', 'Malicious first, then by flow count')}</div><button class="btn" style="margin-top:8px" data-view="external">${this._t('stats.view_all_external_ips', 'View all external IPs →')}</button>`);
    } else {
      threatSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th><th>Details</th></tr></thead><tbody>${topThr.map(function (e, i) {
        var label = e.hostname || e.org || e.ip;
        var country = e.country_name || e.country || '';
        var countryFlag = self._countryFlag(e.country);
        var bc = e.rating === 'malicious' ? 'badge-critical' : 'badge-warn';
        var details = [];
        if (e.vt_malicious != null && e.vt_malicious > 0) details.push('VT ' + e.vt_malicious);
        if (e.abuse_confidence != null && e.abuse_confidence > 0) details.push('Abuse ' + e.abuse_confidence + '%');
        if (e.blacklist_info && typeof e.blacklist_info === 'object' && e.blacklist_info.source) details.push(e.blacklist_info.source);
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${e.ip}</span></td><td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${label}</td><td>${countryFlag ? html`<span title="${country}" style="font-size:15px;line-height:1">${countryFlag}</span>` : html`<span class="dim">${country || '—'}</span>`}</td><td style="text-align:right">${(e.flows || 0).toLocaleString()}</td><td><span class="badge ${bc}">${e.rating}</span></td><td style="font-size:10px;color:var(--muted)">${details.join(', ')}</td></tr>`;
      })}</tbody></table><button class="btn" style="margin-top:8px" data-view="external">${this._t('stats.view_all_external_ips', 'View all external IPs →')}</button>`;
    }
  
    // ── DNS activity ──────────────────────────────────────────────────
    var dnsLog = this._data && this._data.dns_log || [];
    var dnsStats = this._data && this._data.dns_proxy_stats || {};
    var dnsLogStats = this._data && this._data.dns_log_stats || {};
  
    // Hourly stacked bar chart — built from timeseries points so data persists
    // beyond the raw-log retention window.
    var dnsChartHtml = function () {
      var D_HOURS = 24,
        D_BAR_W = 18,
        D_BAR_GAP = 3,
        D_CHART = 60,
        D_LABEL = 16;
      var nowMs = Date.now();
      var dnsBuckets = new Array(D_HOURS).fill(null).map(function () {
        return {
          total: 0,
          blocked: 0,
          mal: 0
        };
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
        dnsBuckets[tbi].total += tpt.dns_total || 0;
        dnsBuckets[tbi].blocked += tpt.dns_blocked || 0;
        dnsBuckets[tbi].mal += tpt.dns_malicious || 0;
        hasTsData = true;
      }
      // Fall back to raw dns_log entries when no timeseries dns data exists yet
      // (e.g. first start before any interval has elapsed).
      if (!hasTsData) {
        for (var di = 0; di < dnsLog.length; di++) {
          var row = dnsLog[di] || {};
          var rawTs = row.timestamp;
          var et = rawTs == null ? NaN : typeof rawTs === 'number' ? rawTs < 1e12 ? rawTs * 1000 : rawTs : function () {
            var txt = String(rawTs).trim();
            var n = Number(txt);
            if (!isNaN(n)) return n < 1e12 ? n * 1000 : n;
            var m = new Date(txt).getTime();
            return isNaN(m) ? new Date(txt.replace(' ', 'T')).getTime() : m;
          }();
          if (isNaN(et)) continue;
          var ago = Math.floor((nowMs - et) / 3600000);
          if (ago < 0 || ago >= D_HOURS) continue;
          var bi = D_HOURS - 1 - ago;
          dnsBuckets[bi].total++;
          if (row.malicious) dnsBuckets[bi].mal++;
          if (row.status === 'blocked') dnsBuckets[bi].blocked++;
        }
      }
      var hasAny = dnsBuckets.some(function (b) {
        return b.total > 0;
      });
      if (!hasAny) return html`<div class="empty-state"><p style="margin:12px 0">${self._t('stats.no_dns_queries', 'No DNS queries recorded')}</p></div>`;
      var maxDns = 1;
      for (var mi = 0; mi < dnsBuckets.length; mi++) {
        if (dnsBuckets[mi].total > maxDns) maxDns = dnsBuckets[mi].total;
      }
      var dSvgW = D_HOURS * (D_BAR_W + D_BAR_GAP);
      var dBars = dnsBuckets.map(function (b, i) {
        var x = i * (D_BAR_W + D_BAR_GAP);
        var th = Math.max(2, Math.round(b.total / maxDns * D_CHART));
        var bkh = b.blocked > 0 ? Math.max(2, Math.round(b.blocked / maxDns * D_CHART)) : 0;
        var mh = b.mal > 0 ? Math.max(2, Math.round(b.mal / maxDns * D_CHART)) : 0;
        var lhour = new Date(nowMs - (D_HOURS - 1 - i) * 3600000).getHours();
        var tip = lhour + 'h \u2014 ' + b.total + ' total' + (b.blocked > 0 ? ', ' + b.blocked + ' blocked' : '') + (b.mal > 0 ? ', ' + b.mal + ' malicious' : '');
        return svg`<rect x="${x}" y="${D_CHART - th}" width="${D_BAR_W}" height="${th}" fill="rgba(98,232,255,.35)"  rx="2"><title>${tip}</title></rect>${bkh > 0 ? svg`<rect x="${x}" y="${D_CHART - bkh}" width="${D_BAR_W}" height="${bkh}" fill="rgba(191,111,255,.7)"  rx="2"><title>${tip}</title></rect>` : ''}${mh > 0 ? svg`<rect x="${x}" y="${D_CHART - mh}" width="${D_BAR_W}" height="${mh}" fill="rgba(255,77,109,.7)"   rx="2"><title>${tip}</title></rect>` : ''}`;
      });
      var dLabels = [];
      for (var dl = 0; dl < D_HOURS; dl += 4) {
        var dlx = dl * (D_BAR_W + D_BAR_GAP) + D_BAR_W / 2;
        var dlHour = new Date(nowMs - (D_HOURS - 1 - dl) * 3600000).getHours();
        dLabels.push(svg`<text x="${dlx}" y="${D_CHART + D_LABEL - 3}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${dlHour}h</text>`);
      }
      return html`<svg viewBox="0 0 ${dSvgW} ${D_CHART + D_LABEL}" width="100%" height="${D_CHART + D_LABEL}" preserveAspectRatio="none" style="display:block">${dBars}${dLabels}</svg><div style="display:flex;gap:12px;margin-top:4px;font-size:10px"><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(98,232,255,.35);display:inline-block;border-radius:2px"></span>${self._t('stats.total', 'Total')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(191,111,255,.7);display:inline-block;border-radius:2px"></span>${self._t('stats.blocked', 'Blocked')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:rgba(255,77,109,.7);display:inline-block;border-radius:2px"></span>${self._t('stats.malicious', 'Malicious')}</span></div>`;
    }();
  
    // Top N malicious/blocked domains (uses configured statistics topN)
    var topMalDomains = (dnsLogStats.top_blocked_domains || []).slice(0, topN);
    var dnsTopMalHtml;
    if (!topMalDomains.length) {
      dnsTopMalHtml = html`<div class="empty-state"><div class="empty-icon" style="font-size:22px">✅</div><p style="margin:8px 0">${this._t('stats.no_dns_detected', 'No malicious or blocked DNS queries detected')}</p></div>`;
    } else {
      var DNS_CAT_COLORS_STAT = {
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
      dnsTopMalHtml = html`<table class="data-table" style="width:100%;margin-top:8px;table-layout:fixed"><thead><tr><th style="width:26px">#</th><th>Domain</th><th style="width:88px">Category</th><th style="width:64px;text-align:right">Queries</th></tr></thead><tbody>${topMalDomains.map(function (d, i) {
        var cc = DNS_CAT_COLORS_STAT[d.category] || DNS_CAT_COLORS_STAT['other'];
        var catPill = html`<span style="font-size:10px;padding:1px 6px;border-radius:8px;background:${cc.replace(',1)', ',.15)')};color:${cc};border:1px solid ${cc.replace(',1)', ',.35)')}">${d.category || 'other'}</span>`;
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${d.domain}</td><td>${catPill}</td><td style="text-align:right"><span class="badge badge-malicious">${d.count}</span></td></tr>`;
      })}</tbody></table><button class="btn" style="margin-top:8px" data-view="dns">${this._t('stats.view_dns_log', 'View DNS log →')}</button>`;
    }
  
    // ── DNS blocked-by-category pie chart ────────────────────────────
    var _STAT_CAT_COLORS = {
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
    var _STAT_CAT_LABELS = {
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
      override: 'Override',
      other: 'Other'
    };
    var _dnsCatItems = dnsLogStats.blocked_by_category || [];
    var _dnsCatTotal = _dnsCatItems.reduce(function (s, x) {
      return s + x.count;
    }, 0);
    var dnsCatSection;
    if (!_dnsCatTotal) {
      dnsCatSection = html`<div class="empty-state"><div class="empty-icon" style="font-size:22px">✅</div><p style="margin:8px 0">${this._t('stats.no_blocked_yet', 'No blocked or malicious DNS queries yet')}</p></div>`;
    } else if (modes.dns_categories === 'pie') {
      var _dnsCatPieColors = _dnsCatItems.map(function (x) {
        return _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other'];
      });
      var _dnsCatPieSvg = self._pieSvg(_dnsCatItems, function (x) {
        return x.count;
      }, function (x) {
        return (_STAT_CAT_LABELS[x.cat] || x.cat) + ': ' + x.count;
      }, _dnsCatPieColors);
      var _dnsCatLegend = html`<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">${_dnsCatItems.map(function (x) {
        var col = _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other'];
        var pct = Math.round(x.count / _dnsCatTotal * 100);
        return html`<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:${col}"></span><span style="flex:1;color:var(--fg)">${_STAT_CAT_LABELS[x.cat] || x.cat}</span><span style="color:var(--muted);font-variant-numeric:tabular-nums">${x.count} (${pct}%)</span></div>`;
      })}</div>`;
      dnsCatSection = html`<div class="stats-chart-row">${_dnsCatPieSvg}<div class="stats-chart-legend">${_dnsCatLegend}</div></div>`;
    } else {
      var _dnsCatMax = _dnsCatItems[0] ? _dnsCatItems[0].count : 1;
      dnsCatSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>Category</th><th style="text-align:right">Queries</th><th>Share</th></tr></thead><tbody>${_dnsCatItems.map(function (x, i) {
        var col = _STAT_CAT_COLORS[x.cat] || _STAT_CAT_COLORS['other'];
        var pct = _dnsCatMax > 0 ? Math.round(x.count / _dnsCatMax * 100) : 0;
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span style="font-size:10px;padding:1px 6px;border-radius:8px;background:${col.replace(',1)', ',.15)')};color:${col};border:1px solid ${col.replace(',1)', ',.35)')}">${_STAT_CAT_LABELS[x.cat] || x.cat}</span></td><td style="text-align:right">${x.count}</td><td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:${pct}%;background:${col};border-radius:3px;height:8px"></div></div></td></tr>`;
      })}</tbody></table>`;
    }
  
    // ── Top blocked/malicious DNS queries by client (pie) ───────────
    var _dnsClientItems = (dnsLogStats.blocked_by_client || []).slice(0, topN);
    var _dnsClientTotal = _dnsClientItems.reduce(function (s, x) {
      return s + x.count;
    }, 0);
    var dnsClientSection;
    if (!_dnsClientTotal) {
      dnsClientSection = html`<div class="empty-state"><div class="empty-icon" style="font-size:22px">✅</div><p style="margin:8px 0">${this._t('stats.no_blocked_clients', 'No blocked or malicious client queries yet')}</p></div>`;
    } else if (modes.dns_clients === 'pie') {
      var _dnsClientColors = ['#ff4d6d', '#ff8c42', '#ffc107', '#f472b6', '#fb923c', '#ff6b6b', '#e879f9', '#facc15', '#fd8dac', '#ffb347', '#6bffc8', '#5baaec'];
      var _dnsClientPieSvg = self._pieSvg(_dnsClientItems, function (x) {
        return x.count;
      }, function (x) {
        var name = nameMap[x.ip] || x.ip;
        return name + ': ' + x.count + ' blocked/malicious queries';
      }, _dnsClientColors);
      var _dnsClientLegend = html`<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">${_dnsClientItems.map(function (x, i) {
        var col = _dnsClientColors[i % _dnsClientColors.length];
        var pct = Math.round(x.count / _dnsClientTotal * 100);
        var name = nameMap[x.ip] || x.ip;
        return html`<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:${col}"></span><span class="ip" style="flex:1;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${x.ip}">${name}</span><span style="color:var(--muted);font-variant-numeric:tabular-nums">${x.count} (${pct}%)</span></div>`;
      })}</div>`;
      dnsClientSection = html`<div class="stats-chart-row">${_dnsClientPieSvg}<div class="stats-chart-legend">${_dnsClientLegend}</div></div>`;
    } else {
      var _dnsClientMax = _dnsClientItems[0] ? _dnsClientItems[0].count : 1;
      dnsClientSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>Client IP</th><th style="text-align:right">Blocked/Malicious</th><th>Share</th></tr></thead><tbody>${_dnsClientItems.map(function (x, i) {
        var pct = _dnsClientMax > 0 ? Math.round(x.count / _dnsClientMax * 100) : 0;
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${x.ip}</span></td><td style="text-align:right">${x.count}</td><td style="width:100px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:${pct}%;background:#ff4d6d;border-radius:3px;height:8px"></div></div></td></tr>`;
      })}</tbody></table>`;
    }
  
    // ── Baseline deviance timeline bar chart (last 24 h) ─────────────
    var blInfo = self._data && self._data.baseline || {};
    var devianceChartHtml = function () {
      if ((blInfo.mode || 'disabled') !== 'active') {
        return '';
      }
      var DV_H = 24,
        DV_BAR_W = 18,
        DV_GAP = 3,
        DV_CHART = 60,
        DV_LABEL = 16;
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
      if (!dvBkts.some(function (v) {
        return v !== null;
      })) {
        return html`<div style="text-align:center;padding:14px;color:var(--muted);font-size:11px">${self._t('stats.no_deviance', 'No deviance data yet — data accumulates every 5 min')}</div>`;
      }
      var dvSvgW = DV_H * (DV_BAR_W + DV_GAP);
      var dvGuides = [25, 50, 75].map(function (g) {
        var gy = DV_CHART - Math.round(g / 100 * DV_CHART);
        return svg`<line x1="0" y1="${gy}" x2="${dvSvgW}" y2="${gy}" stroke="rgba(255,255,255,.07)" stroke-width="1"/>`;
      });
      var dvBars = dvBkts.map(function (v, i) {
        var x = i * (DV_BAR_W + DV_GAP);
        if (v === null) return svg`<rect x="${x}" y="${DV_CHART - 2}" width="${DV_BAR_W}" height="2" fill="rgba(255,255,255,.06)" rx="1"><title>No data</title></rect>`;
        var clr = v <= 20 ? '#6bffc8' : v <= 50 ? '#ffc107' : v <= 75 ? '#ff8c42' : '#ff4d6d';
        var bh = Math.max(2, Math.round(v / 100 * DV_CHART));
        var tip = new Date(dvNow - (DV_H - 1 - i) * 3600000).getHours() + 'h \u2014 deviance\u00a0' + v + '%';
        return svg`<rect x="${x}" y="${DV_CHART - bh}" width="${DV_BAR_W}" height="${bh}" fill="${clr}" opacity="0.85" rx="2"><title>${tip}</title></rect>`;
      });
      var dvLabels = [];
      for (var dl = 0; dl < DV_H; dl += 4) {
        var dlx = dl * (DV_BAR_W + DV_GAP) + DV_BAR_W / 2;
        dvLabels.push(svg`<text x="${dlx}" y="${DV_CHART + DV_LABEL - 3}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${new Date(dvNow - (DV_H - 1 - dl) * 3600000).getHours()}h</text>`);
      }
      return html`<svg viewBox="0 0 ${dvSvgW} ${DV_CHART + DV_LABEL}" width="100%" height="${DV_CHART + DV_LABEL}" preserveAspectRatio="none" style="display:block">${dvGuides}${dvBars}${dvLabels}</svg><div style="display:flex;gap:12px;margin-top:4px;font-size:10px;flex-wrap:wrap"><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#6bffc8;display:inline-block;border-radius:2px"></span>${self._t('stats.normal', '≤20% Normal')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ffc107;display:inline-block;border-radius:2px"></span>${self._t('stats.review', '≤50% Review')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ff8c42;display:inline-block;border-radius:2px"></span>${self._t('stats.investigate', '≤75% Investigate')}</span><span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ff4d6d;display:inline-block;border-radius:2px"></span>${self._t('stats.critical', '>75% Critical')}</span></div>`;
    }();
  
    // ── Top N hosts with most findings (security + baseline) ─────────
    var _allFindings = (this._data && this._data.findings || []).concat(this._data && this._data.baseline_anomalies || []);
    var _hostFindCounts = {};
    for (var _hfi = 0; _hfi < _allFindings.length; _hfi++) {
      var _hfip = String(_allFindings[_hfi].source_ip || '').trim();
      if (_hfip) _hostFindCounts[_hfip] = (_hostFindCounts[_hfip] || 0) + 1;
    }
    var _hostFindItems = Object.keys(_hostFindCounts).map(function (ip) {
      return {
        ip: ip,
        count: _hostFindCounts[ip]
      };
    }).sort(function (a, b) {
      return b.count - a.count;
    }).slice(0, topN);
    var _hostFindTotal = _hostFindItems.reduce(function (s, x) {
      return s + x.count;
    }, 0);
    var _devicesMap = {};
    (this._data && this._data.devices || []).forEach(function (d) {
      if (d.ip) _devicesMap[d.ip] = d;
    });
    var _hfColors = ['#ff8c42', '#ffc107', '#ff4d6d', '#8f86ff', '#3ac5c9', '#6bffc8', '#f472b6', '#fb923c', '#a78bfa', '#22d3ee'];
    var hostFindingsSection;
    if (!_hostFindTotal) {
      hostFindingsSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_findings', 'No findings recorded yet')}</p></div>`;
    } else if (modes.host_findings === 'pie') {
      var _hfPieSvg = self._pieSvg(_hostFindItems, function (x) {
        return x.count;
      }, function (x) {
        var name = nameMap[x.ip] || x.ip;
        return name + ': ' + x.count;
      }, _hfColors);
      var _hfLegend = html`<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">${_hostFindItems.map(function (x, i) {
        var col = _hfColors[i % _hfColors.length];
        var name = nameMap[x.ip] || x.ip;
        return html`<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:${col}"></span><span class="ip" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${x.ip}">${name}</span><span style="color:var(--muted)">${x.count} (${Math.round(x.count / _hostFindTotal * 100)}%)</span></div>`;
      })}</div>`;
      hostFindingsSection = html`<div class="stats-chart-row">${_hfPieSvg}<div class="stats-chart-legend">${_hfLegend}</div></div>`;
    } else {
      hostFindingsSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>IP</th><th>Name / Hostname</th><th style="text-align:right">Deviations</th></tr></thead><tbody>${_hostFindItems.map(function (x, i) {
        var d = _devicesMap[x.ip];
        var name = d && (d.display_name || d.hostname) || '';
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${x.ip}</span></td><td>${name}</td><td style="text-align:right">${x.count}</td></tr>`;
      })}</tbody></table>`;
    }
  
    // ── Top N external IPs appearing in new-peer baseline deviations ──
    var _blAnoms = this._data && this._data.baseline_anomalies || [];
    var _extDevCounts = {};
    for (var _edi = 0; _edi < _blAnoms.length; _edi++) {
      var _editem = _blAnoms[_edi];
      if (_editem.category === 'anomaly_new_peer' && _editem.details && _editem.details.peer) {
        var _peer = String(_editem.details.peer).trim();
        if (_peer) _extDevCounts[_peer] = (_extDevCounts[_peer] || 0) + 1;
      }
    }
    var _extDevItems = Object.keys(_extDevCounts).map(function (ip) {
      return {
        ip: ip,
        count: _extDevCounts[ip]
      };
    }).sort(function (a, b) {
      return b.count - a.count;
    }).slice(0, topN);
    var _extDevTotal = _extDevItems.reduce(function (s, x) {
      return s + x.count;
    }, 0);
    var _extIpEnrich = {};
    (this._data && this._data.external_ips || []).forEach(function (e) {
      if (e.ip) _extIpEnrich[e.ip] = e;
    });
    var _edColors = ['#ff4d6d', '#ff8c42', '#ffc107', '#f472b6', '#fb923c', '#ff6b6b', '#e879f9', '#facc15', '#fd8dac', '#ffb347'];
    var extIpDeviationSection;
    if (!_extDevTotal) {
      extIpDeviationSection = html`<div class="empty-state"><p style="margin:12px 0">${this._t('stats.no_ext_peers', 'No new external peers in baseline deviations')}</p></div>`;
    } else if (modes.ext_deviations === 'pie') {
      var _edPieSvg = self._pieSvg(_extDevItems, function (x) {
        return x.count;
      }, function (x) {
        var enr = _extIpEnrich[x.ip];
        return x.ip + (enr && enr.org ? ' \u2014 ' + enr.org : '') + (enr && enr.country ? ' [' + enr.country + ']' : '') + ': ' + x.count;
      }, _edColors);
      var _edLegend = html`<div style="display:flex;flex-direction:column;gap:5px;font-size:11px;overflow-y:auto;max-height:180px;justify-content:center">${_extDevItems.map(function (x, i) {
        var col = _edColors[i % _edColors.length];
        var enr = _extIpEnrich[x.ip];
        var label = x.ip + (enr && enr.org ? ' \u2014 ' + enr.org : '') + (enr && enr.country ? ' [' + enr.country + ']' : '');
        return html`<div style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:${col}"></span><span class="ip" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${x.ip}">${label}</span><span style="color:var(--muted)">${x.count} (${Math.round(x.count / _extDevTotal * 100)}%)</span></div>`;
      })}</div>`;
      extIpDeviationSection = html`<div class="stats-chart-row">${_edPieSvg}<div class="stats-chart-legend">${_edLegend}</div></div>`;
    } else {
      extIpDeviationSection = html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>IP</th><th>Org / Hostname</th><th>Country</th><th style="text-align:right">Deviations</th></tr></thead><tbody>${_extDevItems.map(function (x, i) {
        var enr = _extIpEnrich[x.ip];
        var org = enr && (enr.org || enr.hostname) || '';
        var country = enr && (enr.country_name || enr.country) || '';
        return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span class="ip">${x.ip}</span></td><td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${org}</td><td>${country}</td><td style="text-align:right">${x.count}</td></tr>`;
      })}</tbody></table>`;
    }
    return html`<div><div class="page-header"><h1 class="page-title">${this._t('page.statistics', 'Statistics')} <span class="dim" style="font-size:12px;font-weight:400;text-transform:none">— top ${topN}</span></h1></div><div class="stat-card" style="grid-column:1/-1">${timelineHtml}${devianceChartHtml ? html`<div style="margin-top:16px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">${this._t('stats.baseline_deviance_hourly', 'Baseline Deviance per hour (last 24 h)')}</div>${devianceChartHtml}</div>` : ''}${dnsProxyEnabled ? html`<div style="margin-top:16px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">${this._t('stats.dns_queries_hourly', 'DNS Queries per hour (last 24 h)')}</div>${dnsChartHtml}</div>` : ''}</div><div class="two-col stats-two-col" style="margin-top:12px"><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${this._t('stats.top_public_ips', 'Top {n} Public IPs').replace('{n}', topN)}${toggleBtns('public_ips', modes.public_ips)}</div>${ipsSection}</div><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${this._t('stats.top_countries', 'Top {n} Countries').replace('{n}', topN)}${toggleBtns('countries', modes.countries)}</div>${countriesSection}</div></div><div class="two-col stats-two-col" style="margin-top:12px"><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${this._t('stats.top_internal_talkers', 'Top {n} Internal Talkers').replace('{n}', topN)}${toggleBtns('talkers', modes.talkers)}</div>${talkersSection}</div><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">${topThr.length ? html`<span style="display:flex;align-items:center;gap:6px">${this._t('stats.top_threat_ips', 'Top {n} Threat IPs').replace('{n}', topN)} <span class="badge badge-critical" style="font-size:9px">${topThr.length}</span></span>` : this._t('stats.top_threat_ips', 'Top {n} Threat IPs').replace('{n}', topN)}${toggleBtns('threat_ips', modes.threat_ips)}</div>${threatSection}</div></div>${dnsProxyEnabled ? html`<div class="two-col stats-two-col" style="margin-top:12px"><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${this._t('stats.blocked_dns_by_category', 'Blocked DNS Queries by Category')}${toggleBtns('dns_categories', modes.dns_categories)}</div>${dnsCatSection}</div><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${this._t('stats.top_blocked_by_client', 'Top {n} Blocked Queries by Client').replace('{n}', topN)}${toggleBtns('dns_clients', modes.dns_clients)}</div>${dnsClientSection}</div></div>` : ''}<div class="two-col stats-two-col" style="margin-top:12px">${function () {
      var blMode = self._data && self._data.baseline && self._data.baseline.mode || 'disabled';
      if (blMode !== 'active') return '';
      return html`<div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${self._t('stats.top_hosts_deviations', 'Top {n} Hosts in Deviations').replace('{n}', topN)}${toggleBtns('host_findings', modes.host_findings)}</div>${hostFindingsSection}</div><div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${self._t('stats.top_ext_deviations', 'Top {n} External IPs in Deviations').replace('{n}', topN)}${toggleBtns('ext_deviations', modes.ext_deviations)}</div>${extIpDeviationSection}</div>`;
    }()}</div>${suricataEnabledStats ? function () {
      function _sucPie(data, colors, key, title, noDataMsg) {
        var mode = modes[key] || 'pie';
        var total = data.reduce(function (s, d) {
          return s + d.value;
        }, 0);
        var SIZE = 130;
        var CX = SIZE / 2;
        var CY = SIZE / 2;
        var R = 52;
        var IR = 28;
        var pieSvg = [];
        if (total > 0) {
          var startAngle = -Math.PI / 2;
          for (var i = 0; i < data.length; i++) {
            var frac = data[i].value / total;
            var end = startAngle + frac * 2 * Math.PI;
            var x1 = CX + R * Math.cos(startAngle),
              y1 = CY + R * Math.sin(startAngle);
            var x2 = CX + R * Math.cos(end),
              y2 = CY + R * Math.sin(end);
            var ix1 = CX + IR * Math.cos(startAngle),
              iy1 = CY + IR * Math.sin(startAngle);
            var ix2 = CX + IR * Math.cos(end),
              iy2 = CY + IR * Math.sin(end);
            var lg = frac > 0.5 ? 1 : 0;
            var d = 'M ' + ix1 + ' ' + iy1 + ' L ' + x1 + ' ' + y1 + ' A ' + R + ' ' + R + ' 0 ' + lg + ' 1 ' + x2 + ' ' + y2 + ' L ' + ix2 + ' ' + iy2 + ' A ' + IR + ' ' + IR + ' 0 ' + lg + ' 0 ' + ix1 + ' ' + iy1;
            pieSvg.push(svg`<path d="${d}" fill="${colors[i % colors.length]}" opacity="0.92"/>`);
            startAngle = end;
          }
        }
        var legend = data.slice(0, 8).map(function (item, i) {
          return html`<div class="row-gap" style="font-size:10px;gap:5px;margin-bottom:3px"><span style="width:9px;height:9px;border-radius:2px;background:${colors[i % colors.length]};flex-shrink:0;display:inline-block"></span><span style="color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.label}</span><span style="color:var(--text);font-weight:600;font-variant-numeric:tabular-nums">${item.value}</span></div>`;
        });
        var tableHtml = total === 0 ? html`<div style="color:var(--muted);font-size:12px;padding:12px 0">${noDataMsg || 'No data'}</div>` : html`<table class="data-table" style="width:100%;margin-top:8px"><thead><tr><th>#</th><th>Label</th><th style="text-align:right">Count</th></tr></thead><tbody>${data.map(function (item, i) {
          return html`<tr><td style="color:var(--muted)">${i + 1}</td><td><span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${colors[i % colors.length]};margin-right:5px;vertical-align:middle"></span>${item.label}</td><td style="text-align:right">${item.value}</td></tr>`;
        })}</tbody></table>`;
        var toggleHtml = html`<div style="display:flex;gap:4px"><button class="btn${mode === 'pie' ? ' active' : ''}" style="padding:2px 8px;font-size:10px" data-statstoggle="${key}:pie">${self._t('stats.pie', 'Pie')}</button><button class="btn${mode === 'bar' ? ' active' : ''}" style="padding:2px 8px;font-size:10px" data-statstoggle="${key}:bar">${self._t('stats.list', 'List')}</button></div>`;
        var content = mode === 'pie' && total > 0 ? html`<div class="stats-chart-row"><svg width="${SIZE}" height="${SIZE}" viewBox="0 0 ${SIZE} ${SIZE}" style="flex-shrink:0">${pieSvg}</svg><div class="stats-chart-legend" style="min-width:0;flex:1">${legend}</div></div>` : tableHtml;
        return html`<div class="card stats-panel-card"><div class="card-title" style="display:flex;justify-content:space-between;align-items:center">${title}${toggleHtml}</div>${total === 0 ? html`<div style="color:var(--muted);font-size:12px;padding:8px 0">${noDataMsg || self._t('stats.no_data', 'No data')}</div>` : content}</div>`;
      }
      return html`<div class="two-col stats-two-col" style="margin-top:12px">${_sucPie(sucSevData, SUC_SEV_COLORS, 'suricata_severity', self._t('stats.suricata_by_severity', 'Suricata Alerts — By Severity'), self._t('stats.no_alerts', 'No alerts yet'))}${_sucPie(sucCatData, sucCatColors.length ? sucCatColors : SUC_CAT_PALETTE, 'suricata_category', self._t('stats.suricata_by_category', 'Suricata Alerts — By Category'), self._t('stats.no_alerts', 'No alerts yet'))}</div><div class="two-col stats-two-col" style="margin-top:12px">${_sucPie(sucSrcData, SUC_SRC_PALETTE, 'suricata_src', self._t('stats.suricata_top_source', 'Suricata Alerts — Top {n} Source IPs').replace('{n}', topN), self._t('stats.no_alerts', 'No alerts yet'))}</div>`;
    }() : ''}${dnsProxyEnabled ? html`<div class="card" style="margin-top:12px"><div class="card-title" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">${topMalDomains.length ? html`<span style="display:flex;align-items:center;gap:6px">${this._t('stats.top_blocked_domains', 'Top {n} Blocked / Malicious Domains').replace('{n}', topN)} <span class="badge badge-critical" style="font-size:9px">${topMalDomains.length}</span></span>` : this._t('stats.top_blocked_domains', 'Top {n} Blocked / Malicious Domains').replace('{n}', topN)}</div>${dnsTopMalHtml}</div>` : ''}<div class="card" style="margin-top:12px"><div class="card-title">${this._t('stats.enrichment_budget', 'Enrichment Budget (Today)')}</div>${enrichSection}</div></div>`;
  }
};
