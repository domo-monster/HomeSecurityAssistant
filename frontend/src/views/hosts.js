// Hosts view.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html } from "lit";

export const hostsMethods = {
  _hostThead() {
    var self = this;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var cols = [{
      key: 'ip',
      label: 'IP'
    }, {
      key: 'name',
      label: this._t('hosts.col_name', 'Name')
    }, {
      key: 'os',
      label: 'OS'
    }, {
      key: 'role',
      label: this._t('hosts.col_role', 'Role')
    }, {
      key: null,
      label: this._t('hosts.col_open_ports', 'Open ports')
    }, {
      key: 'cve',
      label: 'CVEs'
    }, {
      key: 'ping',
      label: 'Ping'
    }];
    if (netflowEnabled) cols.push({
      key: 'traffic',
      label: this._t('hosts.col_traffic', 'Traffic')
    });
    return html`<tr>${cols.map(function (c) {
      if (!c.key) return html`<th>${c.label}</th>`;
      var arrow = self._hostSort === c.key ? self._hostSortDir > 0 ? ' \u25B2' : ' \u25BC' : '';
      return html`<th class="sortable-th" data-hostsort="${c.key}">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
    })}</tr>`;
  },

  _viewHosts() {
    var displayDevices = (this._data && this._data.devices || []).filter(function (d) {
      return d.alive || d.enriched;
    });
    var cnt = displayDevices.length;
    return html`<div><div class="view-header"><h1>${this._t('hosts.page_title', 'Network Hosts')} <span class="dim">(${cnt} ${this._t('hosts.alive_suffix', 'alive')})</span></h1><input id="hsa-host-filter" class="search-bar" type="search" placeholder="${this._t('hosts.filter_placeholder', 'Filter by IP, name, role…')}" value="${this._hostFilter}"></div><div class="card table-card"><table class="data-table"><thead id="hsa-host-thead">${this._hostThead()}</thead><tbody id="hsa-host-tbody">${this._hostRows()}</tbody></table></div></div>`;
  },

  _hostRows() {
    var netflowEnabledRaw2 = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw2 === true || netflowEnabledRaw2 === 'true' || netflowEnabledRaw2 === 1 || netflowEnabledRaw2 === '1';
    var colCount = netflowEnabled ? 8 : 7;
    var q = this._hostFilter.toLowerCase();
    var devices = (this._data && this._data.devices || []).filter(function (d) {
      if (!d.alive && !d.enriched) return false;
      return !q || (d.ip || '').indexOf(q) >= 0 || (d.display_name || '').toLowerCase().indexOf(q) >= 0 || (d.hostname || '').toLowerCase().indexOf(q) >= 0 || (d.probable_role || '').indexOf(q) >= 0;
    });
    if (!devices.length) return html`<tr><td colspan="${colCount}"><div class="empty-state"><div class="empty-icon">🔍</div><p>${this._t('hosts.no_match', 'No hosts match the filter')}</p></div></td></tr>`;
    var sortKey = this._hostSort;
    var sortDir = this._hostSortDir;
    devices.sort(function (a, b) {
      var va, vb;
      if (sortKey === 'ip') {
        va = (a.ip || '').split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.');
        vb = (b.ip || '').split('.').map(function (n) {
          return ('000' + n).slice(-3);
        }).join('.');
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
        va = a.ping_ms != null ? a.ping_ms : Infinity;
        vb = b.ping_ms != null ? b.ping_ms : Infinity;
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
    var builtInRoles = ['unknown', 'camera', 'printer', 'media_device', 'mobile_device', 'nas_or_desktop', 'dns_or_gateway', 'linux_host', 'web_service', 'iot_device'];
    var customRoleValues = Object.values(this._data && this._data.role_overrides || {}).filter(function (r) {
      return builtInRoles.indexOf(r) === -1;
    });
    var knownCustomRoles = Array.from(new Set(customRoleValues));
    var overrides = this._data && this._data.role_overrides || {};
    var nameOverrides = this._data && this._data.name_overrides || {};
    return devices.map(function (d) {
      var name = d.display_name || d.hostname || '';
      var vulns = (d.vulnerabilities || []).length;
      var alive = d.at_risk ? '#ff4d6d' : d.alive ? '#6bffc8' : '#4a5a72';
      var ports = (d.scanned_services || []).map(function (s) {
        return s.port;
      }).join(', ') || (d.exposed_ports || []).slice(0, 6).join(', ') || '\u2014';
      var id = 'hsa-dr-' + d.ip.replace(/\./g, '-');
      var curRole = d.probable_role || 'unknown';
      var isOverride = d.ip in overrides;
      var isNameOverride = d.ip in nameOverrides;
      // If the current role isn't in the built-in list it's a custom role — include it as a selected option
      var isCustom = builtInRoles.indexOf(curRole) === -1;
      var roleOpts = builtInRoles.map(function (r) {
        return html`<option value="${r}" ?selected=${r === curRole}>${r.replace(/_/g, ' ')}</option>`;
      });
      roleOpts = roleOpts.concat(knownCustomRoles.map(function (r) {
        return html`<option value="${r}" ?selected=${r === curRole}>${r.replace(/_/g, ' ')}</option>`;
      }));
      if (isCustom && knownCustomRoles.indexOf(curRole) === -1) roleOpts.push(html`<option value="${curRole}" selected>${curRole.replace(/_/g, ' ')}</option>`);
      roleOpts.push(html`<option value="__custom__">custom…</option>`);
      var roleSelect = html`<select class="role-select" data-roleip="${d.ip}" title="Click to change role">${roleOpts}</select>${isOverride ? html` <span class="dim" style="font-size:9px">${self._t('hosts.manual', '(manual)')}</span>` : ''}`;
      var nameCell = html`${name ? html`<strong>${name}</strong>` : html`<span class="dim">—</span>`} <button class="btn" data-editname="${d.ip}">${self._t('hosts.rename', 'Rename')}</button>${isNameOverride ? html` <span class="dim" style="font-size:9px">${self._t('hosts.manual', '(manual)')}</span>` : ''}`;
      return html`<tr class="expandable" data-ip="${d.ip}"><td><span style="color:${alive};font-size:8px">●</span> <span class="ip">${d.ip}</span></td><td>${nameCell}</td><td><span style="font-size:11px">${d.os_guess || '\u2014'}</span></td><td>${roleSelect}</td><td style="font-size:11px;font-family:monospace">${ports}</td><td>${vulns ? html`<span class="badge badge-high">${vulns} CVE${vulns > 1 ? 's' : ''}</span>` : html`<span class="dim">—</span>`}</td><td style="font-variant-numeric:tabular-nums">${d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : d.alive ? 'alive' : '\u2014'}</td>${netflowEnabled ? html`<td>${self._bytes(d.total_octets)}</td>` : ''}</tr><tr class="detail-row" id="${id}" style="display:none"><td colspan="${colCount}">${self._hostDetail(d)}</td></tr>`;
    });
  },

  _hostDetail(d) {
    var svcs = d.scanned_services || [];
    var vulns = d.vulnerabilities || [];
    var self = this;
    // Build dismissed key → note map from global dismissed findings list
    var dismissedMap = {};
    (this._data && this._data.dismissed_findings || []).forEach(function (f) {
      if (f.key) dismissedMap[f.key] = f.dismiss_note || '';
    });
    var svcRows = svcs.map(function (s) {
      var techs = (s.technologies || []).join(', ');
      return html`<tr><td><span class="chip">${s.port}/${s.protocol}</span></td><td>${s.service_name || '\u2014'}</td><td class="mono dim">${(s.banner || '').substring(0, 60) || '\u2014'}</td><td>${s.version || '\u2014'}</td><td>${techs ? techs : '\u2014'}</td></tr>`;
    });
    var vulnCards = vulns.map(function (v) {
      var key = 'vuln:' + d.ip + ':' + (v.port || 0) + ':' + (v.cve_id || '');
      var isDismissed = Object.prototype.hasOwnProperty.call(dismissedMap, key);
      var note = isDismissed ? dismissedMap[key] : '';
      var dismissedBadge = isDismissed ? html` <span class="chip" style="background:#444;color:#999;font-size:9px">${self._t('findings.dismissed', 'dismissed')}</span>` : '';
      var noteHtml = isDismissed && note ? html`<div class="dim" style="font-size:10px;margin-top:4px;font-style:italic">${self._t('hosts.note', 'Note')}: ${note}</div>` : '';
      return html`<div class="finding-card sev-${v.severity}" style="margin-bottom:6px;padding:10px${isDismissed ? ';opacity:0.45' : ''}"><div class="finding-header">${self._sev(v.severity)}<span class="finding-title">${v.cve_id} · ${v.service}</span><span class="dim" style="font-size:10px">CVSS ${v.cvss || '?'}</span>${dismissedBadge}</div><div class="finding-body">${v.summary || ''}</div>${v.remediation ? html`<div class="fix-hint">${self._t('hosts.fix', 'Fix')}: ${v.remediation}</div>` : ''}${noteHtml}</div>`;
    });
    return html`<div class="host-detail-wrap"><div>${this._kv('IP', d.ip)}${this._kv(this._t('hosts.kv_hostname', 'Hostname'), d.hostname || '\u2014')}${this._kv('MAC', d.mac_address || '\u2014')}${this._kv(this._t('hosts.kv_manufacturer', 'Manufacturer'), d.manufacturer || '\u2014')}${this._kv('OS', d.os_guess ? d.os_guess + ' (' + d.os_confidence + ')' : '\u2014')}${this._kv('Ping', d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : d.alive ? 'alive' : 'no response')}${this._kv(this._t('hosts.kv_flows', 'Flows'), (d.total_flows || 0).toLocaleString())}${this._kv('Traffic', this._bytes(d.total_octets))}${this._kv(this._t('hosts.kv_external_peers', 'External peers'), (d.external_peers || []).length)}${this._kv(this._t('hosts.kv_last_seen', 'Last seen'), this._ago(d.last_seen))}${svcs.length ? html`<div style="margin-top:12px"><div class="section-label">${this._t('hosts.section_open_ports', 'Open Ports')}</div><table class="data-table" style="font-size:11px"><thead><tr><th>${this._t('hosts.port', 'Port')}</th><th>${this._t('hosts.service', 'Service')}</th><th>${this._t('hosts.banner', 'Banner')}</th><th>${this._t('hosts.version', 'Version')}</th><th>${this._t('hosts.technologies', 'Technologies')}</th></tr></thead><tbody>${svcRows}</tbody></table></div>` : ''}</div><div>${vulns.length ? html`<div class="section-label" style="margin-bottom:8px">${this._t('hosts.section_vulnerabilities', 'Vulnerabilities')}</div>${vulnCards}` : html`<div class="empty-state" style="margin-top:20px"><div class="empty-icon">✓</div><p>${this._t('hosts.no_vulnerabilities', 'No vulnerabilities detected')}</p></div>`}</div></div>`;
  },

  _toggleRow(ip) {
    var row = this.shadowRoot.getElementById('hsa-dr-' + ip.replace(/\./g, '-'));
    if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
  },

  _setHostSort(col) {
    if (this._hostSort === col) {
      this._hostSortDir *= -1;
    } else {
      this._hostSort = col;
      this._hostSortDir = 1;
    }
    this._render();
  }
};
