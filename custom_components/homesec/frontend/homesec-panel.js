// ── Home Security Assistant · Panel ─────────────────────────────────────────
// Multi-view web-component for the Home Security Assistant HA integration.
// Views: Overview · Network Map · Hosts · Findings · External IPs · Recommendations
// ─────────────────────────────────────────────────────────────────────────────

const _VIEWS = ['overview', 'map', 'hosts', 'findings', 'external', 'vulnerabilities', 'statistics', 'recommendations'];
const _VIEW_LABELS = {
  overview:        'Overview',
  map:             'Network Map',
  hosts:           'Hosts',
  findings:        'Findings',
  external:        'External IPs',
  vulnerabilities:  'Vulnerabilities',
  statistics:      'Statistics',
  recommendations: 'Recommendations',
};
const _VIEW_ICONS = {
  overview:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>`,
  map:             `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.5 3l-.16.03L15 5.1 9 3 3.36 4.9c-.21.07-.36.25-.36.48V20.5c0 .28.22.5.5.5l.16-.03L9 18.9l6 2.1 5.64-1.9c.21-.07.36-.25.36-.48V3.5c0-.28-.22-.5-.5-.5zM15 19l-6-2.11V5l6 2.11V19z"/></svg>`,
  hosts:           `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 3H4v10c0 2.21 1.79 4 4 4h6c2.21 0 4-1.79 4-4v-3h2c1.11 0 2-.89 2-2V5c0-1.11-.89-2-2-2zm0 5h-2V5h2v3zM4 19h16v2H4z"/></svg>`,
  findings:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z"/></svg>`,
  external:        `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`,
  vulnerabilities:  `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14.4 6L14 4H5v17h2v-7h5.6l.4 2h7V6h-5.6z"/></svg>`,
  statistics:      `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11 2v20c-5.07-.5-9-4.79-9-10s3.93-9.5 9-10zm2.03 0v8.99H22c-.47-4.74-4.24-8.52-8.97-8.99zm0 11.01V22c4.74-.47 8.5-4.25 8.97-8.99h-8.97z"/></svg>`,
  recommendations: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>`,
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
    this._extSort      = 'last_seen';
    this._extSortDir   = -1;
    this._extPage      = 1;
    this._extPageSize  = 25;
    this._editorOpen   = false;
    this._editorMode   = '';
    this._editorIP     = '';
    this._editorTitle  = '';
    this._editorHelp   = '';
    this._editorValue  = '';
    this._editorPlaceholder = '';
    this._vulnDetail   = null;
    this._mapFilter    = 'all';
    this._mapParticles = [];
    this._statsViewModes = { public_ips: 'pie', countries: 'pie', talkers: 'pie', threat_ips: 'pie' };
  }

  set hass(v) {
    this._hass = v;
    if (!this._data && !this._loading) this._fetch();
  }

  connectedCallback()    { this._startRefresh(); }
  disconnectedCallback() { this._stopRefresh(); this._stopMap(); }

  _startRefresh() {
    if (this._refreshTimer) return;
    this._fetch();
    this._refreshTimer = setInterval(() => this._fetch(), 30000);
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
    if (v === this._view) return;
    this._stopMap();
    this._lookupResult = null;
    this._lookupIP     = null;
    if (this._view === 'vulnerabilities') this._vulnData = null;
    this._view = v;
    this._render();
  }

  _render() {
    const root = this.shadowRoot;
    if (!root.querySelector('.app')) {
      root.innerHTML = '<style>' + _CSS + '</style><div class="app"><nav class="sidebar" id="hsa-sidebar"></nav><main class="content" id="hsa-content"></main></div>';
      root.querySelector('.app').addEventListener('click', e => this._onClick(e));
      root.querySelector('.app').addEventListener('input', e => this._onInput(e));
      root.querySelector('.app').addEventListener('change', e => this._onChange(e));
    }
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
        case 'overview':        content.innerHTML = this._viewOverview();  break;
        case 'map':             this._viewMap(content);                    break;
        case 'hosts':           content.innerHTML = this._viewHosts();     break;
        case 'findings':        content.innerHTML = this._viewFindings();  break;
        case 'external':        content.innerHTML = this._viewExternal();  break;
        case 'vulnerabilities':  content.innerHTML = this._viewVulns();        break;
        case 'statistics':       content.innerHTML = this._viewStatistics();   break;
        case 'recommendations': content.innerHTML = this._viewRecs();      break;
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
  }

  _onClick(e) {
    var editorClose = e.target.closest('[data-editor-close]');
    if (editorClose) { this._closeEditor(); return; }
    var editorSave = e.target.closest('[data-editor-save]');
    if (editorSave) { this._saveEditor(); return; }
    var nav = e.target.closest('[data-view]');
    if (nav) { this._setView(nav.dataset.view); return; }
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
    var lu = e.target.closest('[data-lookup]');
    if (lu) { this._doLookup(lu.dataset.lookup); return; }
    var hr = e.target.closest('tr[data-ip]');
    if (hr && !e.target.closest('select')) { this._toggleRow(hr.dataset.ip); return; }
    var dismiss = e.target.closest('[data-dismiss]');
    if (dismiss) { this._dismissFinding(dismiss.dataset.dismiss); return; }
    var undismiss = e.target.closest('[data-undismiss]');
    if (undismiss) { this._undismissFinding(undismiss.dataset.undismiss); return; }
    var mf = e.target.closest('[data-mapfilter]');
    if (mf) { this._setMapFilter(mf.dataset.mapfilter); return; }
    var hs = e.target.closest('[data-hostsort]');
    if (hs) { this._setHostSort(hs.dataset.hostsort); return; }
    var es = e.target.closest('[data-extsort]');
    if (es) { this._setExtSort(es.dataset.extsort); return; }
    var vs = e.target.closest('[data-vulnsort]');
    if (vs) { this._setVulnSort(vs.dataset.vulnsort); return; }
    var vp = e.target.closest('[data-vuln-page]');
    if (vp) { this._vulnPage = parseInt(vp.dataset.vulnPage, 10) || 1; this._render(); return; }
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
  }

  _onInput(e) {
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
      this._extSortDir = 1;
    }
    this._extPage = 1;
    var tbody = this.shadowRoot.getElementById('hsa-ext-tbody');
    if (tbody) tbody.innerHTML = this._extRows();
    var thead = this.shadowRoot.getElementById('hsa-ext-thead');
    if (thead) thead.innerHTML = this._extThead();
    var pg = this.shadowRoot.getElementById('hsa-ext-pagebar');
    if (pg) pg.innerHTML = this._extPageBar();
  }

  _onChange(e) {
    if (e.target.id === 'hsa-ext-pagesize') {
      this._extPageSize = Math.max(5, Math.min(200, parseInt(e.target.value, 10) || 25));
      this._extPage = 1;
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

  async _undismissFinding(key) {
    if (!key) return;
    try {
      await this._hass.callApi('POST', 'homesec/findings/undismiss', { key: key });
      this._fetch();
    } catch (err) {
      alert('Failed to restore finding: ' + (err.message || String(err)));
    }
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
    var findings   = (this._data && this._data.findings && this._data.findings.length) || 0;
    var ext_threat = (this._data && this._data.external_ips || []).filter(function(e) { return e.blacklisted; }).length;
    var self = this;
    var items = _VIEWS.map(function(v) {
      var badge = '';
      if (v === 'findings' && findings > 0)   badge = '<span class="nav-badge">' + findings + '</span>';
      if (v === 'external' && ext_threat > 0) badge = '<span class="nav-badge danger">' + ext_threat + '</span>';
      return '<li class="nav-item ' + (self._view === v ? 'active' : '') + '" data-view="' + v + '">' +
        _VIEW_ICONS[v] + '<span class="nav-label">' + _VIEW_LABELS[v] + '</span>' + badge + '</li>';
    }).join('');
    var exporters = (this._data && this._data.summary && this._data.summary.exporters) || [];
    var status = exporters.length > 0 ? 'online' : 'waiting';
    return '<div class="brand"><img src="/api/homesec/frontend/hsa-logo.svg" alt="logo" style="height:32px;width:32px;margin-right:10px;border-radius:8px;box-shadow:0 0 8px #62e8ff55;vertical-align:middle">' +
      '<div class="brand-text"><span class="brand-name">Home Security</span><span class="brand-sub">Assistant</span><span class="brand-tagline">Network security telemetry with live flow context</span></div></div>' +
      '<ul class="nav-list">' + items + '</ul>' +
      '<div class="sidebar-status ' + status + '"><div class="status-dot"></div><span>' +
      (status === 'online' ? 'Collector active' : 'Awaiting flows') + '</span></div>';
  }

  _viewOverview() {
    var s       = (this._data && this._data.summary) || {};
    var findings = (this._data && this._data.findings) || [];
    var dismissed = (this._data && this._data.dismissed_findings) || [];
    var dismissedVulns = dismissed.filter(function(f) { return f.category === 'vulnerability'; }).length;
    var recent   = findings.slice(0, 5);
    var exporters = s.exporters || [];
    var total    = s.total_datagrams || 0;
    var parsed   = s.parsed_datagrams || 0;
    var dropped  = s.dropped_datagrams || 0;
    var pct      = total > 0 ? Math.round((parsed / total) * 100) : 0;
    var self = this;
    var findingsLabel = 'Active Findings' + (dismissed.length ? ' <span class="dim" style="font-size:10px;text-transform:none">(' + dismissed.length + ' dismissed)</span>' : '');
    var cvesLabel = 'Active CVEs' + (dismissedVulns ? ' <span class="dim" style="font-size:10px;text-transform:none">(' + dismissedVulns + ' dismissed)</span>' : '');
    var nvdTs = this._data && this._data.nvd_last_updated;
    var nvdTtl = (this._data && this._data.nvd_ttl_hours != null) ? this._data.nvd_ttl_hours + '\u00a0h' : '\u2014';
    var nvdTotalCves = (this._data && this._data.nvd_total_cves != null) ? this._data.nvd_total_cves : 0;
    var nvdMinYear = (this._data && this._data.nvd_min_year != null) ? this._data.nvd_min_year : null;
    var nvdAge = nvdTs ? this._ago(nvdTs) : 'never fetched';
    var nvdStatus = nvdTs ? ((Date.now() - new Date(nvdTs).getTime()) < 26 * 3600 * 1000 ? 'good' : 'warn') : 'warn';
    return '<div>' +
      '<div class="page-header"><h1 class="page-title">Overview</h1></div>' +
      '<div class="stat-grid">' +
        this._stat(s.devices || 0, 'Devices', 'success') +
        this._stat((this._data && this._data.scan_hosts_found) != null ? this._data.scan_hosts_found : (s.scanned_devices || 0), 'Scanned', '') +
        this._stat(s.findings || 0, findingsLabel, (s.findings || 0) > 0 ? 'danger' : '') +
        this._stat(s.vulnerability_count || 0, cvesLabel, (s.vulnerability_count || 0) > 0 ? 'warn' : '') +
        this._stat(nvdTotalCves, 'NVD CVEs' + (nvdMinYear ? ' <span class="dim" style="font-size:10px;text-transform:none">(\u2265\u00a0' + nvdMinYear + ')</span>' : ''), '') +
        this._stat((this._data && this._data.kev_total) || 0, 'CISA KEV', '') +
        this._stat(this._fmtN(s.total_flows || 0), 'Flows', '') +
        this._stat(exporters.length, 'Exporters', exporters.length > 0 ? 'success' : 'warn') +
      '</div>' +
      '<div class="two-col">' +
        '<div class="card">' +
          '<div class="card-title">NetFlow Listener Health</div>' +
          this._hrow('Status', (function(){ var lf = s.last_flow_at; if (!lf) return 'No flows seen'; var age = Date.now() - new Date(lf).getTime(); return age < 90000 ? 'Receiving flows' : 'No flows (idle ' + (age < 3600000 ? Math.floor(age/60000) + 'm' : Math.floor(age/3600000) + 'h') + ')'; })(), (function(){ var lf = s.last_flow_at; return lf && (Date.now() - new Date(lf).getTime()) < 90000 ? 'good' : 'warn'; })()) +
          this._hrow('Uptime', this._uptime(s.collector_started_at), '') +
          this._hrow('Exporters', exporters.join(', ') || '\u2014', '') +
          this._hrow('Flow versions', (s.versions_seen || []).join(', ') || '\u2014', '') +
          this._hrow('Total datagrams', total.toLocaleString(), '') +
          this._hrow('Parsed', parsed.toLocaleString() + ' (' + pct + '%)', pct > 90 ? 'good' : pct > 50 ? 'warn' : 'bad') +
          this._hrow('Dropped', dropped.toLocaleString(), dropped > 0 ? 'warn' : 'good') +
          this._hrow('Last flow', this._ago(s.last_flow_at), '') +
          (s.last_parser_error ? this._hrow('Last error', s.last_parser_error, 'bad') : '') +
        '</div>' +
        '<div class="card">' +
          '<div class="card-title">Recent Alerts</div>' +
          (recent.length === 0
            ? '<div class="empty-state"><div class="empty-icon">\u2713</div><p>No active high/critical findings</p></div>'
            : recent.map(function(f) {
                return '<div class="alert-row">' + self._sev(f.severity) +
                  '<div class="alert-body"><div class="alert-sum">' + self._esc(f.summary) + '</div>' +
                  '<div class="alert-meta"><span class="ip">' + f.source_ip + '</span> \u00B7 ' + self._ago(f.last_seen) + '</div></div></div>';
              }).join('')
          ) +
          (findings.length > 5 ? '<button class="btn" style="margin-top:10px" data-view="findings">View all findings \u2192</button>' : '') +
        '</div>' +
      '</div>' +
      (function() {
        var scanAt = self._data && self._data.scan_last_at;
        var scanDur = self._data && self._data.scan_duration;
        var scanHosts = self._data && self._data.scan_hosts_found;
        var scanInterval = self._data && self._data.scan_interval;
        var scanAge = scanAt ? self._ago(scanAt) : 'never';
        var scanStatus = scanAt ? ((Date.now() - new Date(scanAt).getTime()) < (scanInterval || 300) * 2 * 1000 ? 'good' : 'warn') : 'warn';
        var durStr = scanDur != null ? (scanDur < 60 ? scanDur.toFixed(1) + '\u00a0s' : (scanDur / 60).toFixed(1) + '\u00a0min') : '\u2014';
        var hostsStr = scanHosts != null ? scanHosts.toLocaleString() : '\u2014';
        var intervalStr = scanInterval != null ? (scanInterval < 60 ? scanInterval + '\u00a0s' : Math.round(scanInterval / 60) + '\u00a0min') : '\u2014';
        return '<div class="card" style="margin-top:12px">' +
          '<div class="card-title">Active Scan</div>' +
          self._hrow('Last scan', scanAge, scanStatus) +
          self._hrow('Duration', durStr, '') +
          self._hrow('Hosts found', hostsStr, scanHosts > 0 ? '' : 'warn') +
          self._hrow('Scan interval', intervalStr, '') +
        '</div>';
      })() +
      '<div class="card" style="margin-top:12px">' +
        '<div class="card-title">Vulnerability Intelligence (NVD)</div>' +
        this._hrow('Last database fetch', nvdAge, nvdStatus) +
        this._hrow('Cache TTL', nvdTtl, '') +
        this._hrow('CVEs in database', nvdTotalCves.toLocaleString(), '') +
        this._hrow('Min publication year', nvdMinYear ? nvdMinYear : 'All years', '') +
        (function() {
          var kws = (self._data && self._data.nvd_keywords) || [];
          if (!kws.length) return self._hrow('Keywords', 'None loaded yet', 'warn');
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
          var html = '<div class="section-label" style="margin-top:10px;margin-bottom:4px">NVD Keywords (' + kws.length + ')</div>';
          html += '<div style="display:flex;gap:14px;align-items:center;font-size:10px;color:var(--muted);margin-bottom:6px">' +
            '<span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(158,150,255,.7);background:rgba(158,150,255,.35)"></span> Configured</span>' +
            '<span style="display:inline-flex;align-items:center;gap:5px"><span style="display:inline-block;width:12px;height:12px;border-radius:3px;border:1.5px solid rgba(107,255,200,.6);background:rgba(107,255,200,.3)"></span> From scans</span>' +
          '</div>';
          html += '<div style="line-height:2">';
          if (configured.length) html += renderChips(configured, cfgStyle);
          if (configured.length && dynamic.length) html += ' ';
          if (dynamic.length) html += renderChips(dynamic, dynStyle);
          html += '</div>';
          return html;
        })() +
      '</div>' +
      (function() {
        var kevTotal = (self._data && self._data.kev_total != null) ? self._data.kev_total : 0;
        var kevTs = self._data && self._data.kev_last_updated;
        var kevTtl = (self._data && self._data.kev_ttl_hours != null) ? self._data.kev_ttl_hours + '\u00a0h' : '\u2014';
        var kevAge = kevTs ? self._ago(kevTs) : 'never fetched';
        var kevStatus = kevTs ? ((Date.now() - new Date(kevTs).getTime()) < 26 * 3600 * 1000 ? 'good' : 'warn') : 'warn';
        return '<div class="card">' +
          '<div class="card-title">CISA Known Exploited Vulnerabilities (KEV)</div>' +
          self._hrow('Last catalog fetch', kevAge, kevStatus) +
          self._hrow('Cache TTL', kevTtl, '') +
          self._hrow('Catalog size', kevTotal.toLocaleString(), kevTotal > 0 ? '' : 'warn') +
        '</div>';
      })() +
      '<button class="btn" style="margin-top:6px" data-view="vulnerabilities">Browse all vulnerabilities \u2192</button>' +
      '<button class="btn" style="margin-top:6px;margin-left:6px" data-view="statistics">View Statistics \u2192</button>' +
    '</div>';
  }

  // ── SVG donut-pie chart helper ───────────────────────────────────────
  _pieSvg(items, getVal, getLabel, colors) {
    var total = items.reduce(function(s, it) { return s + getVal(it); }, 0);
    if (!total) return '<div style="text-align:center;color:var(--muted);padding:20px;font-size:11px">No data</div>';
    var size = 180, cx = 90, cy = 90, r = 72, ri = 32;
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

  // ── Statistics view ──────────────────────────────────────────────────
  _viewStatistics() {
    var self = this;
    var modes = this._statsViewModes;
    var topN = (this._data && this._data.stats_top_n) || 10;
    var COLORS = ['#8f86ff','#3ac5c9','#6bffc8','#ffc107','#ff8c42','#ff4d6d','#7fb3f5','#d4a843','#a8e063','#f472b6','#60a5fa','#34d399','#fb923c','#a78bfa','#22d3ee'];

    function toggleBtns(id, current) {
      return '<span style="display:flex;gap:4px;flex-shrink:0">' +
        '<button class="btn' + (current === 'pie' ? ' active' : '') + '" style="padding:3px 8px;font-size:10px" data-statstoggle="' + id + ':pie">' +
        '<svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M7 1.07A7 7 0 1 0 15 9H7V1.07z"/><path d="M8.5.5v7h7A7.5 7.5 0 0 0 8.5.5z"/></svg>Pie</button>' +
        '<button class="btn' + (current === 'list' ? ' active' : '') + '" style="padding:3px 8px;font-size:10px" data-statstoggle="' + id + ':list">' +
        '<svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" style="vertical-align:-1px;margin-right:3px"><path d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5z"/></svg>List</button>' +
      '</span>';
    }

    function chartSection(svgHtml, legendHtml) {
      return '<div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding-top:10px">' +
        svgHtml + '<div style="flex:1;min-width:160px">' + legendHtml + '</div>' +
      '</div>';
    }

    // ── Top public IPs ────────────────────────────────────────────────
    var topIPs = (this._data && this._data.top_public_ips) || [];
    var ipsSection;
    if (!topIPs.length) {
      ipsSection = '<div class="empty-state"><p style="margin:12px 0">No external flow data yet</p></div>';
    } else if (modes.public_ips === 'pie') {
      ipsSection = chartSection(
        self._pieSvg(topIPs, function(e) { return e.flows; }, function(e) { return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : ''); }, COLORS),
        self._statsLegend(topIPs, function(e) { return e.flows; }, function(e) {
          return (e.hostname || e.org || e.ip) + (e.country ? ' [' + e.country + ']' : '') + (e.blacklisted ? ' \u26a0' : '');
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">Ranked by flow count</div>' +
        '<button class="btn" style="margin-top:8px" data-view="external">View all external IPs \u2192</button>'
      );
    } else {
      ipsSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th>' +
        '</tr></thead><tbody>' +
        topIPs.map(function(e, i) {
          var label = e.hostname || e.org || e.ip;
          var country = e.country_name || e.country || '';
          var bc = e.blacklisted ? 'badge-critical' : (e.rating === 'suspicious' ? 'badge-warn' : 'badge-ok');
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(e.ip) + '</span></td>' +
            '<td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(label) + '</td>' +
            '<td>' + self._esc(country) + '</td>' +
            '<td style="text-align:right">' + e.flows.toLocaleString() + '</td>' +
            '<td><span class="badge ' + bc + '">' + self._esc(e.blacklisted ? 'malicious' : (e.rating || 'ok')) + '</span></td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="external">View all external IPs \u2192</button>';
    }

    // ── Top countries ─────────────────────────────────────────────────
    var topC = (this._data && this._data.top_countries) || [];
    var countriesSection;
    if (!topC.length) {
      countriesSection = '<div class="empty-state"><p style="margin:12px 0">No country data yet</p></div>';
    } else if (modes.countries === 'pie') {
      countriesSection = chartSection(
        self._pieSvg(topC, function(c) { return c.flow_count; }, function(c) { return (c.country_name || c.country) + ' (' + c.ip_count + ' IPs)'; }, COLORS),
        self._statsLegend(topC, function(c) { return c.flow_count; }, function(c) {
          return (c.country_name || c.country || '\u2014') + ' (' + c.ip_count + ' IPs)';
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">Ranked by flow count</div>'
      );
    } else {
      var maxFlows = topC[0] ? topC[0].flow_count : 1;
      countriesSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>CC</th><th>Country</th><th style="text-align:right">Unique IPs</th><th style="text-align:right">Flows</th><th>Share</th>' +
        '</tr></thead><tbody>' +
        topC.map(function(c, i) {
          var pct = maxFlows > 0 ? Math.round((c.flow_count / maxFlows) * 100) : 0;
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><b>' + self._esc(c.country || '\u2014') + '</b></td>' +
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
      talkersSection = '<div class="empty-state"><p style="margin:12px 0">No traffic data yet</p></div>';
    } else if (modes.talkers === 'pie') {
      talkersSection = chartSection(
        self._pieSvg(topT, function(d) { return d.total_octets; }, function(d) { return d.display_name || d.ip; }, COLORS),
        self._statsLegend(topT, function(d) { return d.total_octets; }, function(d) {
          return (d.display_name || d.ip) + ' \u00b7 ' + self._bytes(d.total_octets);
        }, COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">Ranked by total traffic</div>' +
        '<button class="btn" style="margin-top:8px" data-view="hosts">View all hosts \u2192</button>'
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
        '<button class="btn" style="margin-top:8px" data-view="hosts">View all hosts \u2192</button>';
    }

    // ── Enrichment budget (table only) ────────────────────────────────
    var eStats = (this._data && this._data.enrichment_stats) || [];
    var enrichSection;
    if (!eStats.length) {
      enrichSection = '<div class="empty-state"><p style="margin:12px 0">No enrichment data</p></div>';
    } else {
      enrichSection = '<table class="data-table" style="width:100%"><thead><tr>' +
        '<th>Provider</th><th style="text-align:right">Used today</th><th style="text-align:right">Daily budget</th><th>Usage</th><th>Status</th>' +
        '</tr></thead><tbody>' +
        eStats.map(function(s) {
          var pct = s.budget > 0 ? Math.min(100, Math.round((s.used / s.budget) * 100)) : 0;
          var barColor = s.exhausted ? '#ff4d6d' : (pct > 80 ? '#ffc107' : '#6bffc8');
          var badge = !s.configured ? '<span class="badge badge-dim">not configured</span>' :
            (s.exhausted ? '<span class="badge badge-critical">exhausted</span>' :
            (pct > 80 ? '<span class="badge badge-warn">high</span>' : '<span class="badge badge-ok">ok</span>'));
          return '<tr><td><b>' + self._esc(s.provider) + '</b></td>' +
            '<td style="text-align:right">' + s.used.toLocaleString() + '</td>' +
            '<td style="text-align:right">' + s.budget.toLocaleString() + '</td>' +
            '<td style="width:120px"><div style="background:rgba(255,255,255,.08);border-radius:3px;height:8px"><div style="width:' + pct + '%;background:' + barColor + ';border-radius:3px;height:8px"></div></div></td>' +
            '<td>' + badge + '</td></tr>';
        }).join('') +
        '</tbody></table>';
    }

    // ── Top suspicious / malicious IPs ────────────────────────────────
    var THREAT_COLORS = ['#ff4d6d','#ff8c42','#ffc107','#f472b6','#fb923c','#ff6b6b','#e879f9','#facc15','#fd8dac','#ffb347'];
    var topThr = (this._data && this._data.top_threat_ips) || [];
    var threatSection;
    if (!topThr.length) {
      threatSection = '<div class="empty-state"><div class="empty-icon" style="font-size:24px">✅</div><p style="margin:8px 0">No suspicious or malicious IPs detected</p></div>';
    } else if (modes.threat_ips === 'pie') {
      threatSection = chartSection(
        self._pieSvg(topThr, function(e) { return Math.max(e.flows, 1); }, function(e) {
          return e.ip + (e.hostname ? ' (' + e.hostname + ')' : '') + ' — ' + e.rating;
        }, THREAT_COLORS),
        self._statsLegend(topThr, function(e) { return Math.max(e.flows, 1); }, function(e) {
          var label = e.hostname || e.org || e.ip;
          return label + ' · ' + e.rating + (e.flows ? ' · ' + e.flows.toLocaleString() + ' flows' : '');
        }, THREAT_COLORS) +
        '<div style="margin-top:8px;font-size:10px;color:var(--muted)">Malicious first, then by flow count</div>' +
        '<button class="btn" style="margin-top:8px" data-view="external">View all external IPs →</button>'
      );
    } else {
      threatSection = '<table class="data-table" style="width:100%;margin-top:8px"><thead><tr>' +
        '<th>#</th><th>IP</th><th>Hostname / Org</th><th>Country</th><th style="text-align:right">Flows</th><th>Rating</th><th>Details</th>' +
        '</tr></thead><tbody>' +
        topThr.map(function(e, i) {
          var label = e.hostname || e.org || e.ip;
          var country = e.country_name || e.country || '';
          var bc = e.rating === 'malicious' ? 'badge-critical' : 'badge-warn';
          var details = [];
          if (e.vt_malicious != null && e.vt_malicious > 0) details.push('VT ' + e.vt_malicious);
          if (e.abuse_confidence != null && e.abuse_confidence > 0) details.push('Abuse ' + e.abuse_confidence + '%');
          if (e.blacklist_info && typeof e.blacklist_info === 'object' && e.blacklist_info.source) details.push(self._esc(e.blacklist_info.source));
          return '<tr><td style="color:var(--muted)">' + (i + 1) + '</td>' +
            '<td><span class="ip">' + self._esc(e.ip) + '</span></td>' +
            '<td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + self._esc(label) + '</td>' +
            '<td>' + self._esc(country) + '</td>' +
            '<td style="text-align:right">' + (e.flows || 0).toLocaleString() + '</td>' +
            '<td><span class="badge ' + bc + '">' + self._esc(e.rating) + '</span></td>' +
            '<td style="font-size:10px;color:var(--muted)">' + details.join(', ') + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button class="btn" style="margin-top:8px" data-view="external">View all external IPs →</button>';
    }

    return '<div>' +
      '<div class="page-header"><h1 class="page-title">Statistics <span class="dim" style="font-size:12px;font-weight:400;text-transform:none">\u2014 top\u00a0' + topN + '</span></h1></div>' +
      '<div class="two-col">' +
        '<div class="card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">Top\u00a0' + topN + ' Public IPs' + toggleBtns('public_ips', modes.public_ips) + '</div>' +
          ipsSection +
        '</div>' +
        '<div class="card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">Top\u00a0' + topN + ' Countries' + toggleBtns('countries', modes.countries) + '</div>' +
          countriesSection +
        '</div>' +
      '</div>' +
      '<div class="two-col" style="margin-top:12px">' +
        '<div class="card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">Top\u00a0' + topN + ' Internal Talkers' + toggleBtns('talkers', modes.talkers) + '</div>' +
          talkersSection +
        '</div>' +
        '<div class="card">' +
          '<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">' +
          (topThr.length ? '<span style="display:flex;align-items:center;gap:6px">Top\u00a0' + topN + ' Threat IPs <span class="badge badge-critical" style="font-size:9px">' + topThr.length + '</span></span>' : 'Top\u00a0' + topN + ' Threat IPs') +
          toggleBtns('threat_ips', modes.threat_ips) + '</div>' +
          threatSection +
        '</div>' +
      '</div>' +
      '<div class="card" style="margin-top:12px">' +
        '<div class="card-title">Enrichment Budget (Today)</div>' +
        enrichSection +
      '</div>' +
    '</div>';
  }

  _viewMap(container) {
    var _mapCutoff = Date.now() - 10 * 60 * 1000;
    var allDevices = ((this._data && this._data.devices) || []).filter(function(d) { return d.alive || (d.last_seen && new Date(d.last_seen).getTime() > _mapCutoff); });
    var connections = (this._data && this._data.connections) || [];
    var extIPs     = (this._data && this._data.external_ips) || [];
    var mcIPs      = (this._data && this._data.multicast_ips) || [];
    var flows      = (this._data && this._data.summary && this._data.summary.total_flows) || 0;
    var f = this._mapFilter;
    var filters = [
      { id: 'all',      label: 'All' },
      { id: 'scanned',  label: 'Scanned' },
      { id: 'flow',     label: 'Flow only' },
      { id: 'external', label: 'External' },
    ];
    var filterBtns = filters.map(function(b) {
      return '<button class="btn map-fbtn' + (f === b.id ? ' active' : '') + '" data-mapfilter="' + b.id + '">' + b.label + '</button>';
    }).join('');
    container.innerHTML =
      '<div><div class="view-header"><h1>Live Network Map</h1>' +
      '<div class="row-gap"><span id="map-stats" style="font-size:11px;color:var(--muted)">' +
      allDevices.length + ' internal \u00B7 ' + extIPs.length + ' external' + (mcIPs.length ? ' \u00B7 ' + mcIPs.length + ' multicast' : '') + ' \u00B7 ' + this._fmtN(flows) + ' flows</span>' +
      '<button class="btn" id="map-reset-btn">\u21BA Reset</button></div></div>' +
      '<div class="map-filter-bar">' + filterBtns + '</div>' +
      '<div class="map-wrap"><canvas id="hsa-map-canvas"></canvas>' +
      '<div class="map-tooltip" id="hsa-map-tip" style="display:none"></div>' +
      '<div class="map-legend">' +
        '<div class="legend-item"><div class="ldot" style="background:#8f86ff"></div>Scanned</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#3ac5c9"></div>Flow only</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#ff4d6d"></div>At risk</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#6bffc8"></div>Gateway</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#5a6a80"></div>External</div>' +
        '<div class="legend-item"><div class="ldot" style="background:#d4a843"></div>Multicast</div>' +
      '</div></div></div>';
    var self = this;
    requestAnimationFrame(function() {
      var devices = self._applyMapFilter(allDevices);
      var showExt = (self._mapFilter === 'all' || self._mapFilter === 'external');
      self._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : []);
      var btn = self.shadowRoot.getElementById('map-reset-btn');
      if (btn) btn.addEventListener('click', function() { self._stopMap(); self._mapZoom = 1; self._mapPanX = 0; self._mapPanY = 0; var d = self._applyMapFilter(allDevices); self._initMap(d, connections, showExt ? extIPs : [], showExt ? mcIPs : []); });
    });
  }

  _applyMapFilter(devices) {
    var f = this._mapFilter;
    if (f === 'scanned') return devices.filter(function(d) { return d.alive; });
    if (f === 'flow')    return devices.filter(function(d) { return (d.total_octets || 0) > 0; });
    if (f === 'external') {
      var connections = (this._data && this._data.connections) || [];
      var extPeers = {};
      for (var i = 0; i < connections.length; i++) {
        var c = connections[i];
        if (c.target_kind === 'external') extPeers[c.source] = true;
        if (c.source_kind === 'external') extPeers[c.target] = true;
      }
      return devices.filter(function(d) { return extPeers[d.ip]; });
    }
    return devices;
  }

  _setMapFilter(f) {
    if (f === this._mapFilter) return;
    this._mapFilter = f;
    // Update button active states
    var btns = this.shadowRoot.querySelectorAll('.map-fbtn');
    btns.forEach(function(b) { b.classList.toggle('active', b.dataset.mapfilter === f); });
    // Rebuild map with new filter
    if (!this._data) return;
    var _mapCutoff = Date.now() - 10 * 60 * 1000;
    var allDevices = (this._data.devices || []).filter(function(d) { return d.alive || (d.last_seen && new Date(d.last_seen).getTime() > _mapCutoff); });
    var devices = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
    var extIPs = this._data.external_ips || [];
    this._stopMap();
    var showExt = (f === 'all' || f === 'external');
    var mcIPs = this._data.multicast_ips || [];
    this._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : []);
  }

  _initMap(devices, connections, extIPs, mcIPs) {
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
    if (extIPs.length > 0) {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
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
    for (var mc = 0; mc < connections.length; mc++) {
      var mconn = connections[mc];
      if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
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
    var self = this;
    this._mapEdges = connections.filter(function(c) {
      return self._mapNodes.has(c.source) && self._mapNodes.has(c.target);
    }).slice(0, 400).map(function(c) {
      return { source: c.source, target: c.target, weight: c.octets || 1 };
    });
    this._mapTick = 0;
    this._mapZoom = 1;
    this._mapPanX = 0;
    this._mapPanY = 0;
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
    var loop = function() {
      try {
        self._mapStep(canvas.width, canvas.height);
        self._mapTick++;
        self._tickParticles();
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
    for (var i = 0; i < this._mapEdges.length; i++) {
      var e = this._mapEdges[i];
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
    var _mapCutoff = Date.now() - 10 * 60 * 1000;
    var allDevices = (this._data.devices || []).filter(function(d) { return d.alive || (d.last_seen && new Date(d.last_seen).getTime() > _mapCutoff); });
    var devices    = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
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
    if (showExt) {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
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
    if (showExt) {
      for (var mc = 0; mc < connections.length; mc++) {
        var mconn = connections[mc];
        if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
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

    // Rebuild edges from latest connections
    var self = this;
    this._mapEdges = connections.filter(function(c) {
      return self._mapNodes.has(c.source) && self._mapNodes.has(c.target);
    }).slice(0, 400).map(function(c) {
      return { source: c.source, target: c.target, weight: c.octets || 1 };
    });

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
      ctx.strokeStyle = 'rgba(98,232,255,' + a + ')';
      ctx.lineWidth = Math.min(1.8, 0.3 + Math.log10(e.weight + 1) * 0.18);
      ctx.stroke();
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
      // Label: show for internal nodes, multicast, and at-risk externals only
      if (n.type === 'multicast' || n.type !== 'external' || n.at_risk) {
        var label = ((n.type === 'multicast' ? (n.label || n.ip) : (n.display_name || n.hostname || n.ip || '')) + '').substring(0, 16);
        ctx.fillStyle = n.at_risk ? '#ff9aae' : (n.type === 'multicast' ? '#d4a843' : 'rgba(180,210,240,.6)');
        ctx.font = '8px IBM Plex Mono, monospace'; ctx.textAlign = 'center';
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
        var risk = n.at_risk  ? '<br><span style="color:#ff4d6d">\u26A0 At risk</span>' : '';
        var flagEmoji = n.country ? this._countryFlag(n.country) : '';
        var ctryLabel = n.country_name || n.country || '';
        var ctry = ctryLabel  ? '<br><span style="color:#8a9dbf">' + (flagEmoji ? flagEmoji + ' ' : '') + this._esc(ctryLabel) + (n.city ? ', ' + this._esc(n.city) : '') + '</span>' : '';
        var extra = '';
        if (n.type === 'multicast') {
          if (n.label && n.label !== ip) extra += '<br><span style="color:#d4a843;font-size:10px">' + this._esc(n.label) + '</span>';
          extra += '<br><span style="color:#8a9dbf;font-size:10px">Multicast \u00B7 not internet-routed</span>';
          if (n.internal_sources && n.internal_sources.length) extra += '<br><span style="color:#8a9dbf;font-size:9px">Sources: ' + n.internal_sources.join(', ') + '</span>';
        } else if (n.type === 'external') {
          if (n.org) extra += '<br><span style="color:#8a9dbf;font-size:10px">' + this._esc(n.org.substring(0, 40)) + '</span>';
          if (n.rating) extra += '<br>' + this._rating(n.rating);
          var vtLine = n.vt_malicious != null ? 'VT: ' + n.vt_malicious + ' malicious' : '';
          var abLine = n.abuse_confidence != null ? 'Abuse: ' + n.abuse_confidence + '%' : '';
          var intelParts = [vtLine, abLine].filter(Boolean).join(' \u00B7 ');
          if (intelParts) extra += '<br><span style="color:#8a9dbf;font-size:9px">' + intelParts + '</span>';
          extra += '<br><span style="color:var(--accent);font-size:9px;opacity:.6">Click for full lookup</span>';
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
    var cols = [
      { key: 'ip', label: 'IP' },
      { key: 'name', label: 'Name' },
      { key: 'os', label: 'OS' },
      { key: 'role', label: 'Role' },
      { key: null, label: 'Open ports' },
      { key: 'cve', label: 'CVEs' },
      { key: 'ping', label: 'Ping' },
      { key: 'traffic', label: 'Traffic' }
    ];
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
      '<div class="view-header"><h1>Network Hosts <span class="dim">(' + cnt + ' alive)</span></h1>' +
      '<input id="hsa-host-filter" class="search-bar" type="search" placeholder="Filter by IP, name, role\u2026" value="' + this._esc(this._hostFilter) + '"></div>' +
      '<div class="card table-card"><table class="data-table">' +
        '<thead id="hsa-host-thead">' + this._hostThead() + '</thead>' +
        '<tbody id="hsa-host-tbody">' + this._hostRows() + '</tbody>' +
      '</table></div></div>';
  }

  _hostRows() {
    var q = this._hostFilter.toLowerCase();
    var devices = (this._data && this._data.devices || []).filter(function(d) {
      if (!d.alive) return false;
      return !q || (d.ip || '').indexOf(q) >= 0 ||
        (d.display_name || '').toLowerCase().indexOf(q) >= 0 ||
        (d.hostname || '').toLowerCase().indexOf(q) >= 0 ||
        (d.probable_role || '').indexOf(q) >= 0;
    });
    if (!devices.length) return '<tr><td colspan="8"><div class="empty-state"><div class="empty-icon">\uD83D\uDD0D</div><p>No hosts match the filter</p></div></td></tr>';
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
        (isOverride ? ' <span class="dim" style="font-size:9px">(manual)</span>' : '');
      var nameCell = (name ? '<strong>' + self._esc(name) + '</strong>' : '<span class="dim">\u2014</span>') +
        ' <button class="btn" data-editname="' + d.ip + '">Rename</button>' +
        (isNameOverride ? ' <span class="dim" style="font-size:9px">(manual)</span>' : '');
      return '<tr class="expandable" data-ip="' + d.ip + '">' +
        '<td><span style="color:' + alive + ';font-size:8px">\u25CF</span> <span class="ip">' + d.ip + '</span></td>' +
        '<td>' + nameCell + '</td>' +
        '<td><span style="font-size:11px">' + self._esc(d.os_guess || '\u2014') + '</span></td>' +
        '<td>' + roleSelect + '</td>' +
        '<td style="font-size:11px;font-family:monospace">' + ports + '</td>' +
        '<td>' + (vulns ? '<span class="badge badge-high">' + vulns + ' CVE' + (vulns > 1 ? 's' : '') + '</span>' : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-variant-numeric:tabular-nums">' + (d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : (d.alive ? 'alive' : '\u2014')) + '</td>' +
        '<td>' + self._bytes(d.total_octets) + '</td>' +
        '</tr>' +
        '<tr class="detail-row" id="' + id + '" style="display:none">' +
        '<td colspan="8">' + self._hostDetail(d) + '</td>' +
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
        ? ' <span class="chip" style="background:#444;color:#999;font-size:9px">dismissed</span>'
        : '';
      var noteHtml = (isDismissed && note)
        ? '<div class="dim" style="font-size:10px;margin-top:4px;font-style:italic">Note: ' + self._esc(note) + '</div>'
        : '';
      return '<div class="finding-card sev-' + v.severity + '" style="margin-bottom:6px;padding:10px' + (isDismissed ? ';opacity:0.45' : '') + '">' +
        '<div class="finding-header">' + self._sev(v.severity) +
        '<span class="finding-title">' + self._esc(v.cve_id) + ' \u00B7 ' + self._esc(v.service) + '</span>' +
        '<span class="dim" style="font-size:10px">CVSS ' + (v.cvss || '?') + '</span>' +
        dismissedBadge + '</div>' +
        '<div class="finding-body">' + self._esc(v.summary || '') + '</div>' +
        (v.remediation ? '<div class="fix-hint">Fix: ' + self._esc(v.remediation) + '</div>' : '') +
        noteHtml +
        '</div>';
    }).join('');
    return '<div class="host-detail-wrap">' +
      '<div>' +
        this._kv('IP', d.ip) + this._kv('Hostname', d.hostname || '\u2014') +
        this._kv('MAC', d.mac_address || '\u2014') + this._kv('Manufacturer', d.manufacturer || '\u2014') +
        this._kv('OS', d.os_guess ? d.os_guess + ' (' + d.os_confidence + ')' : '\u2014') +
        this._kv('Ping', d.ping_ms != null ? d.ping_ms.toFixed(1) + ' ms' : (d.alive ? 'alive' : 'no response')) +
        this._kv('Flows', (d.total_flows || 0).toLocaleString()) +
        this._kv('Traffic', this._bytes(d.total_octets)) +
        this._kv('External peers', (d.external_peers || []).length) +
        this._kv('Last seen', this._ago(d.last_seen)) +
        (svcs.length ? '<div style="margin-top:12px"><div class="section-label">Open Ports</div>' +
          '<table class="data-table" style="font-size:11px"><thead><tr><th>Port</th><th>Service</th><th>Banner</th><th>Version</th><th>Technologies</th></tr></thead>' +
          '<tbody>' + svcRows + '</tbody></table></div>' : '') +
      '</div>' +
      '<div>' +
        (vulns.length
          ? '<div class="section-label" style="margin-bottom:8px">Vulnerabilities</div>' + vulnCards
          : '<div class="empty-state" style="margin-top:20px"><div class="empty-icon">\u2713</div><p>No vulnerabilities detected</p></div>') +
      '</div></div>';
  }

  _toggleRow(ip) {
    var row = this.shadowRoot.getElementById('hsa-dr-' + ip.replace(/\./g, '-'));
    if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
  }

  _viewFindings() {
    var findings = (this._data && this._data.findings) || [];
    var dismissed = (this._data && this._data.dismissed_findings) || [];
    var self = this;
    var renderCard = function(f, isDismissed) {
      var det = f.details || {};
      var cve = det.cve_id ? '<span class="chip">' + det.cve_id + '</span>' : '';
      var portChip = det.port ? '<span class="chip">port ' + det.port + '</span>' : '';
      var detRows = Object.keys(det).filter(function(k) { return k !== 'cve_id' && k !== 'port' && k !== 'remediation'; })
        .map(function(k) { return '<dt>' + k + ':</dt> <dd>' + self._esc(String(det[k])) + '</dd>'; }).join(' ');
      var noteHtml = (isDismissed && f.dismiss_note)
        ? '<div style="margin-top:5px;font-size:11px;color:var(--muted)"><strong>Note:</strong> ' + self._esc(f.dismiss_note) + '</div>'
        : '';
      return '<div class="finding-card sev-' + f.severity + '"' + (isDismissed ? ' style="opacity:.55"' : '') + '>' +
        '<div class="finding-header">' + self._sev(f.severity) + cve + portChip +
        '<span class="finding-title">' + self._esc(f.summary) + '</span>' +
        (isDismissed
          ? '<button class="btn" data-undismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Restore finding">Restore</button>'
          : '<button class="btn btn-dismiss" data-dismiss="' + self._esc(f.key || f.source_ip + ':' + f.category) + '" title="Dismiss finding">Dismiss</button>') +
        '</div>' +
        '<div class="finding-meta">' +
          '<span>Source: <span class="ip">' + f.source_ip + '</span></span>' +
          (det.port ? '<span>Port: <strong>' + det.port + '</strong></span>' : '') +
          '<span>Category: ' + f.category + '</span>' +
          '<span>' + f.count + '\u00D7 seen</span>' +
          '<span>' + self._ago(f.last_seen) + '</span>' +
        '</div>' +
        (detRows ? '<div class="finding-detail"><dl>' + detRows + '</dl></div>' : '') +
        (det.remediation ? '<div class="fix-hint">Remediation: ' + self._esc(det.remediation) + '</div>' : '') +
        noteHtml +
        '</div>';
    };
    var cards = findings.map(function(f) { return renderCard(f, false); }).join('');
    var dismissedCards = dismissed.map(function(f) { return renderCard(f, true); }).join('');
    var activeSection = findings.length
      ? '<div><div class="view-header"><h1>Security Findings <span class="dim">(' + findings.length + ' actionable' + (dismissed.length ? ', ' + dismissed.length + ' dismissed' : '') + ')</span></h1></div>' + cards + '</div>'
      : '<div><div class="view-header"><h1>Security Findings' + (dismissed.length ? ' <span class="dim">(' + dismissed.length + ' dismissed)</span>' : '') + '</h1></div>' +
        '<div class="empty-state card" style="height:180px"><div class="empty-icon">\u2713</div><p>No active high or critical findings.</p></div></div>';
    var dismissedSection = dismissed.length
      ? '<div style="margin-top:28px"><div class="view-header"><h1>Dismissed <span class="dim">(' + dismissed.length + ')</span></h1></div>' + dismissedCards + '</div>'
      : '';
    return activeSection + dismissedSection;
  }

  _extThead() {
    var self = this;
    var cols = [
      { key: 'ip',       label: 'IP' },
      { key: 'hostname', label: 'Hostname' },
      { key: 'country',  label: 'Country' },
      { key: 'org',      label: 'ASN / Org' },
      { key: 'rating',   label: 'Rating' },
      { key: 'vt',       label: 'VT hits' },
      { key: 'abuse',    label: 'Abuse%' },
      { key: null,       label: 'Ports' },
      { key: null,       label: 'Contacted by' },
      { key: 'last_seen',label: 'Last seen' },
      { key: null,       label: 'Action' },
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
          (e.hostname || e.hostname_ipinfo || '').toLowerCase().indexOf(q) >= 0 ||
          (e.country_name || e.country || '').toLowerCase().indexOf(q) >= 0 ||
          (e.org || e.asn || '').toLowerCase().indexOf(q) >= 0 ||
          (e.rating || '').toLowerCase().indexOf(q) >= 0 ||
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
        va = (a.hostname || a.hostname_ipinfo || '').toLowerCase();
        vb = (b.hostname || b.hostname_ipinfo || '').toLowerCase();
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
      '<div class="row-gap" style="font-size:11px;color:var(--muted)">Showing ' + start + '-' + end + ' of ' + total + '</div>' +
      '<div class="row-gap" style="gap:6px">' +
        '<label class="dim" style="font-size:11px">Rows</label>' +
        '<select id="hsa-ext-pagesize" class="role-select">' +
          [10,25,50,100].map((n) => '<option value="' + n + '"' + (n === this._extPageSize ? ' selected' : '') + '>' + n + '</option>').join('') +
        '</select>' +
        '<button class="btn" data-extpage="prev"' + (page <= 1 ? ' disabled' : '') + '>Previous</button>' +
        '<span class="dim" style="font-size:11px;min-width:70px;text-align:center">' + page + ' / ' + totalPages + '</span>' +
        '<button class="btn" data-extpage="next"' + (page >= totalPages ? ' disabled' : '') + '>Next</button>' +
      '</div>' +
    '</div>';
  }

  _extRows() {
    var extIPs = this._extPreparedList();
    var totalPages = Math.max(1, Math.ceil(extIPs.length / this._extPageSize));
    this._extPage = Math.min(Math.max(1, this._extPage), totalPages);
    var start = (this._extPage - 1) * this._extPageSize;
    extIPs = extIPs.slice(start, start + this._extPageSize);
    if (!extIPs.length) return '<tr><td colspan="11"><div class="empty-state"><div class="empty-icon">\uD83D\uDD0D</div><p>No external IPs match the filter</p></div></td></tr>';
    var self = this;
    return extIPs.map(function(e) {
      var rating = e.rating || (e.blacklisted ? 'malicious' : '');
      var vt = e.vt_malicious != null
        ? (e.vt_malicious + '/' + ((e.vt_malicious||0)+(e.vt_suspicious||0)+(e.vt_harmless||0)))
        : '\u2014';
      var abuse = e.abuse_confidence != null ? e.abuse_confidence + '%' : '\u2014';
      var host  = e.hostname || e.hostname_ipinfo || '';
      var isLooking = self._lookupIP === e.ip && self._lookingUp;
      var dstPorts = (e.dst_ports || []).slice(0, 8);
      var portsHtml = dstPorts.length
        ? dstPorts.map(function(p) { return '<span class="chip">' + p + '</span>'; }).join(' ') + (e.dst_ports.length > 8 ? ' <span class="dim">+' + (e.dst_ports.length - 8) + '</span>' : '')
        : '<span class="dim">\u2014</span>';
      var detail = (self._lookupResult && self._lookupIP === e.ip)
        ? '<tr class="detail-row"><td colspan="11">' + self._ipDetail(self._lookupResult, e.internal_sources) + '</td></tr>' : '';
      var sources = e.internal_sources || [];
      var sourcesHtml = sources.length
        ? sources.map(function(s) { return '<span class="ip-chip">' + s + '</span>'; }).join(' ')
        : '<span class="dim">\u2014</span>';
      var ratingHtml = rating ? self._ratingWithSource(rating, e.rating_source) : '<span class="dim">\u2014</span>';
      return '<tr>' +
        '<td>' + (e.blacklisted ? '<span style="color:#ff4d6d;margin-right:3px">\u26A0</span>' : '') + '<span class="ip">' + e.ip + '</span></td>' +
        '<td style="font-size:11px">' + (host ? self._esc(host) : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-size:11px">' + (e.country ? '<span title="' + self._esc(e.country_name||e.country) + '">' + e.country + '</span>' : '<span class="dim">\u2014</span>') + '</td>' +
        '<td style="font-size:11px">' + self._esc(((e.org||'').substring(0,30))||e.asn||'\u2014') + '</td>' +
        '<td>' + ratingHtml + '</td>' +
        '<td style="font-family:monospace;font-size:11px">' + vt + '</td>' +
        '<td style="font-family:monospace;font-size:11px">' + abuse + '</td>' +
        '<td style="font-size:11px">' + portsHtml + '</td>' +
        '<td style="font-size:11px">' + sourcesHtml + '</td>' +
        '<td style="font-size:10px;color:var(--muted)">' + self._ago(e.last_seen) + '</td>' +
        '<td><button class="btn" data-lookup="' + e.ip + '" ' + (isLooking ? 'disabled' : '') + '>' +
          (isLooking ? '<span class="spin"></span>' : '\uD83D\uDD0D Lookup') + '</button></td></tr>' + detail;
    }).join('');
  }

  _viewExternal() {
    var totalCount = ((this._data && this._data.external_ips) || []).length;
    var bs   = (this._data && this._data.blacklist_stats) || {};
    return '<div>' +
      '<div class="view-header"><h1>External IPs <span class="dim">(' + totalCount + ')</span></h1>' +
      '<input id="hsa-ext-filter" class="search-bar" type="search" placeholder="Filter by IP, hostname, country, org\u2026" value="' + this._esc(this._extFilter) + '"></div>' +
      (bs.bad_ips != null ? '<div class="tldr-bar">' +
        '<span><strong>' + (bs.bad_ips||0).toLocaleString() + '</strong> blocked IPs</span>' +
        '<span><strong>' + (bs.bad_domains||0).toLocaleString() + '</strong> blocked domains</span>' +
        '<span>Refreshed: ' + this._ago(bs.last_refresh) + '</span>' +
        '<span>' + (bs.sources||0) + ' source' + ((bs.sources||0)!==1?'s':'') + '</span>' +
      '</div>' : '') +
      '<div id="hsa-ext-pagebar">' + this._extPageBar() + '</div>' +
      '<div class="card table-card"><table class="data-table">' +
        '<thead id="hsa-ext-thead">' + this._extThead() + '</thead>' +
        '<tbody id="hsa-ext-tbody">' + this._extRows() + '</tbody>' +
      '</table></div></div>';
  }

  _ipDetail(d, internalSources) {
    var ip = d.ip || '';
    var reportLinks = ip ? [
      ['IPInfo', 'https://ipinfo.io/' + encodeURIComponent(ip)],
      ['AbuseIPDB', 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip)],
      ['Shodan', 'https://www.shodan.io/host/' + encodeURIComponent(ip)],
      ['VirusTotal', 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip)],
    ] : [];
    var pairs = [
      ['Hostname',   d.hostname],
      ['Country',    d.country_name || d.country],
      ['ASN',        d.asn],
      ['ISP / Org',  d.org || d.isp],
      ['City',       d.city],
      ['Timezone',   d.timezone],
      ['VirusTotal', d.vt_malicious != null ? d.vt_malicious + ' malicious, ' + d.vt_suspicious + ' suspicious, ' + d.vt_harmless + ' harmless' : null],
      ['VT Reputation', d.vt_reputation != null ? String(d.vt_reputation) : null],
      ['Shodan ports', (d.shodan_ports && d.shodan_ports.length) ? d.shodan_ports.join(', ') : null],
      ['Shodan vulns', (d.shodan_vulns && d.shodan_vulns.length) ? d.shodan_vulns.join(', ') : null],
      ['Shodan org',   d.shodan_org || null],
      ['Shodan tags',  (d.shodan_tags && d.shodan_tags.length) ? d.shodan_tags.join(', ') : null],
      ['Abuse score',  d.abuse_confidence != null ? d.abuse_confidence + '% (' + d.abuse_total_reports + ' reports)' : null],
      ['Rating source', d.rating_source || null],
      ['Blacklisted',  d.blacklisted ? 'Yes \u2013 ' + ((d.blacklist_info && d.blacklist_info.source) || 'threat_intel') : 'No'],
      ['Data sources', (d.sources && d.sources.join(', ')) || '\u2014'],
      ['Enriched at',  d.enriched_at ? this._ago(d.enriched_at) : null],
    ].filter(function(p) { return p[1] != null && p[1] !== ''; });
    var self = this;
    var pairsHtml = pairs.map(function(p) {
      return '<div class="detail-pair"><span class="detail-key">' + p[0] + '</span><span class="detail-val">' + self._esc(String(p[1])) + '</span></div>';
    }).join('');
    var linksHtml = reportLinks.length
      ? '<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">Reports</span><span class="detail-val">' +
          reportLinks.map(function(item) {
            return '<a class="ext-report-link" href="' + item[1] + '" target="_blank" rel="noopener noreferrer">' + self._esc(item[0]) + '</a>';
          }).join(' ') +
        '</span></div>'
      : '';
    var sources = internalSources || d.internal_sources || [];
    var sourcesHtml = sources.length
      ? '<div class="detail-pair" style="grid-column:1/-1"><span class="detail-key">Contacted by</span><span class="detail-val">' +
          sources.map(function(s) { return '<span class="ip-chip">' + s + '</span>'; }).join(' ') +
        '</span></div>'
      : '';
    return '<div class="ip-detail-panel"><h3>\uD83D\uDD0D ' + d.ip + ' ' + (d.rating ? this._rating(d.rating) : '') + '</h3>' +
      '<div class="detail-grid">' + pairsHtml + linksHtml + sourcesHtml + '</div>' +
      (d.error ? '<div style="color:var(--danger);margin-top:8px;font-size:11px">\u26A0 Enrichment error: ' + this._esc(d.error) + '</div>' : '') +
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
      return '<div><div class="view-header"><h1>Vulnerability Browser</h1></div>' +
        '<div class="state-box"><div class="loader"></div><p>Loading vulnerabilities\u2026</p></div></div>';
    }
    if (this._vulnLoading) {
      return '<div><div class="view-header"><h1>Vulnerability Browser</h1></div>' +
        '<div class="state-box"><div class="loader"></div><p>Loading vulnerabilities\u2026</p></div></div>';
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
        '<h1>Vulnerability Browser</h1>' +
        '<div class="row-gap">' +
          '<input class="search-bar" type="text" placeholder="Search CVE, port, service, CPE, keyword\u2026" value="' + self._esc(this._vulnFilter) + '" data-vuln-search />' +
          '<button class="btn" data-vuln-refresh>\u21BB Refresh</button>' +
        '</div>' +
      '</div>' +
      '<div class="tldr-bar">' +
        '<span><strong>' + d.total + '</strong> CVEs in database</span>' +
        '<span><strong>' + (d.detected_cves || 0) + '</strong> detected on network</span>' +
        '<span><strong>' + d.kev_matches + '</strong> in CISA KEV</span>' +
        '<span><strong>' + total + '</strong> matching results</span>' +
      '</div>' +
      '<div class="card table-card">' +
        '<table class="data-table">' +
          '<thead><tr>' +
            (function() {
              var cols = [
                {key:'cve_id', label:'CVE ID'},
                {key:'published', label:'Published'},
                {key:'cvss', label:'CVSS'},
                {key:'severity', label:'Severity'},
                {key:'services', label:'Services'},
                {key:'ports', label:'Ports'},
                {key:'hosts', label:'Hosts'},
                {key:'kev', label:'KEV'},
              ];
              return cols.map(function(c) {
                var arrow = self._vulnSort === c.key ? (self._vulnSortDir > 0 ? ' \u25B2' : ' \u25BC') : '';
                return '<th class="sortable-th" data-vulnsort="' + c.key + '">' + c.label + '<span class="sort-arrow">' + arrow + '</span></th>';
              }).join('') + '<th style="min-width:320px">Summary</th>';
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
      var hostsStr = hosts > 0 ? '<span class="ip-chip">' + hosts + ' host' + (hosts > 1 ? 's' : '') + '</span>' : '<span class="dim" style="font-size:10px">not detected</span>';
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
      html += '<button class="btn" data-vuln-page="' + Math.max(1, this._vulnPage - 1) + '"' + (this._vulnPage <= 1 ? ' disabled' : '') + '>\u25C0 Prev</button>';
      html += '<span class="dim" style="font-size:12px">Page ' + this._vulnPage + ' of ' + pages + '</span>';
      html += '<button class="btn" data-vuln-page="' + Math.min(pages, this._vulnPage + 1) + '"' + (this._vulnPage >= pages ? ' disabled' : '') + '>Next \u25B6</button>';
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
    var hosts = (v.affected_hosts || []).map(function(h) { return '<span class="ip-chip">' + h + '</span>'; }).join(' ') || '<span class="dim">Not detected on this network</span>';
    var cpes = (v.cpe_criteria || []).slice(0, 10).map(function(c) { return '<div class="mono" style="font-size:10px;color:var(--muted);word-break:break-all">' + self._esc(c) + '</div>'; }).join('');
    if ((v.cpe_criteria || []).length > 10) cpes += '<div class="dim" style="font-size:10px">+' + (v.cpe_criteria.length - 10) + ' more</div>';
    if (!cpes) cpes = '<span class="dim">\u2014</span>';

    var kevSection = '';
    if (v.in_kev) {
      kevSection = '<div style="margin-top:12px;padding:10px;border-radius:8px;background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25)">' +
        '<div style="font-size:11px;font-weight:700;color:#ff4d6d;margin-bottom:6px">\u26A0 CISA Known Exploited Vulnerability</div>' +
        (v.kev_name ? '<div style="font-size:11px;margin-bottom:4px"><strong>Name:</strong> ' + self._esc(v.kev_name) + '</div>' : '') +
        (v.kev_vendor || v.kev_product ? '<div style="font-size:11px;margin-bottom:4px"><strong>Product:</strong> ' + self._esc((v.kev_vendor || '') + (v.kev_vendor && v.kev_product ? ' / ' : '') + (v.kev_product || '')) + '</div>' : '') +
        (v.kev_date_added ? '<div style="font-size:11px;margin-bottom:4px"><strong>Added to KEV:</strong> ' + self._esc(v.kev_date_added) + '</div>' : '') +
        (v.kev_action ? '<div style="font-size:11px"><strong>Required action:</strong> ' + self._esc(v.kev_action) + '</div>' : '') +
      '</div>';
    }

    return '<div id="hsa-vuln-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.68);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px" data-vuln-close="1">' +
      '<div class="card" style="width:min(680px,96vw);max-height:88vh;overflow-y:auto;margin:0;border:1px solid rgba(98,232,255,.26)">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">' +
          '<h1 style="font-size:16px;color:var(--accent)">' + cid + '</h1>' +
          '<button class="btn" data-vuln-close="1">\u2715 Close</button>' +
        '</div>' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">' +
          '<span class="badge badge-' + sc + '" style="font-size:12px;padding:3px 10px">CVSS ' + cvss.toFixed(1) + '</span>' +
          this._sev(v.severity || sc) +
          (v.published ? '<span class="dim" style="font-size:11px">Published: ' + self._esc(v.published) + '</span>' : '') +
          (v.in_kev ? '<span class="badge badge-critical">KEV</span>' : '') +
        '</div>' +
        '<div class="card-title">Summary</div>' +
        '<div style="font-size:12px;line-height:1.6;color:var(--text);margin-bottom:14px">' + this._esc(v.summary || 'No description available.') + '</div>' +
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">' +
          '<div><div class="card-title">Services</div><div>' + services + '</div></div>' +
          '<div><div class="card-title">Ports</div><div>' + ports + '</div></div>' +
        '</div>' +
        '<div class="card-title">Affected Hosts</div>' +
        '<div style="margin-bottom:14px;font-size:12px">' + hosts + '</div>' +
        '<div class="card-title">CPE Criteria</div>' +
        '<div style="margin-bottom:14px">' + cpes + '</div>' +
        kevSection +
        '<div style="margin-top:14px;display:flex;gap:8px">' +
          '<a href="https://nvd.nist.gov/vuln/detail/' + cid + '" target="_blank" rel="noopener noreferrer" class="ext-report-link">View on NVD</a>' +
          '<a href="https://www.cvedetails.com/cve/' + cid + '/" target="_blank" rel="noopener noreferrer" class="ext-report-link">CVE Details</a>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  _viewRecs() {
    var recs = (this._data && this._data.recommendations) || [];
    if (!recs.length) return '<div><div class="view-header"><h1>Security Recommendations</h1></div>' +
      '<div class="empty-state card" style="height:180px"><div class="empty-icon">\u2713</div><p>No recommendations at this time.</p></div></div>';
    var icons = { critical: '\uD83D\uDEA8', high: '\u26A0\uFE0F', medium: '\uD83D\uDCA1', low: '\u2139\uFE0F' };
    var self = this;
    return '<div><div class="view-header"><h1>Security Recommendations</h1></div>' +
      recs.map(function(r) {
        return '<div class="rec-card">' +
          '<div class="rec-icon">' + (icons[r.priority] || '\uD83D\uDCA1') + '</div>' +
          '<div><div class="rec-title">' + self._esc(r.title) + ' ' + self._sev(r.priority) + '</div>' +
          '<div class="rec-detail">' + self._esc(r.detail) + '</div></div></div>';
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
    if (d < 60000)    return 'just now';
    if (d < 3600000)  return Math.floor(d/60000) + 'm ago';
    if (d < 86400000) return Math.floor(d/3600000) + 'h ago';
    return Math.floor(d/86400000) + 'd ago';
  }
  _esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
}

// ─── CSS ─────────────────────────────────────────────────────────────────────
var _CSS = ':host{--bg:#070b12;--card:rgba(14,23,40,.92);--border:rgba(98,232,255,.14);--text:#eef7ff;--muted:#8a9dbf;--accent:#62e8ff;--success:#6bffc8;--danger:#ff4d6d;--warn:#ffb347;--violet:#9e96ff;--glow:0 0 28px rgba(98,232,255,.08);display:block;height:100vh;overflow:hidden;font-family:"IBM Plex Sans","Segoe UI",sans-serif;color:var(--text);background:var(--bg)}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}.app{display:flex;height:100vh;overflow:hidden}.sidebar{width:210px;min-width:210px;background:rgba(6,11,24,.98);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;z-index:10}.brand{padding:18px 14px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)}.brand-shield{font-size:26px;filter:drop-shadow(0 0 8px rgba(98,232,255,.5))}.brand-text{display:flex;flex-direction:column}.brand-name{font-size:12px;font-weight:700;color:var(--accent);letter-spacing:.04em;text-transform:uppercase}.brand-sub{font-size:10px;color:var(--muted);letter-spacing:.06em}.brand-tagline{font-size:9px;color:var(--muted);opacity:.7;margin-top:4px;line-height:1.3}.nav-list{list-style:none;padding:6px 0;flex:1}.nav-item{display:flex;align-items:center;gap:9px;padding:9px 14px;cursor:pointer;font-size:12px;font-weight:500;color:var(--muted);border-left:3px solid transparent;transition:all .12s ease;user-select:none}.nav-item:hover{background:rgba(98,232,255,.05);color:var(--text)}.nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(98,232,255,.07)}.nav-item svg{width:15px;height:15px;flex-shrink:0;opacity:.65}.nav-item.active svg{opacity:1}.nav-label{flex:1}.nav-badge{background:var(--danger);color:#fff;border-radius:10px;font-size:9px;font-weight:700;padding:1px 5px;min-width:16px;text-align:center}.sidebar-status{padding:10px 14px;border-top:1px solid var(--border);display:flex;align-items:center;gap:7px;font-size:10px;color:var(--muted)}.status-dot{width:6px;height:6px;border-radius:50%;background:var(--muted)}.sidebar-status.online .status-dot{background:var(--success);box-shadow:0 0 6px var(--success);animation:pulse 2s infinite}.content{flex:1;overflow-y:auto;padding:22px 24px;position:relative;background:var(--bg)}.content::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.12;background-image:linear-gradient(rgba(98,232,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(98,232,255,.07) 1px,transparent 1px);background-size:40px 40px}.content>*{position:relative;z-index:1}.page-header{margin-bottom:20px}.page-title{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:.01em;margin-bottom:3px}.page-subtitle{font-size:12px;color:var(--muted);letter-spacing:.02em}.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px}.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;box-shadow:var(--glow)}.stat-card.danger{border-color:rgba(255,77,109,.3)}.stat-card.warn{border-color:rgba(255,179,71,.28)}.stat-card.success{border-color:rgba(107,255,200,.2)}.stat-value{font-size:26px;font-weight:800;line-height:1;margin-bottom:3px}.stat-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--glow);margin-bottom:14px}.table-card{padding:0;overflow:hidden}.card-title{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}.health-row{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(98,232,255,.05);font-size:12px}.health-row:last-child{border-bottom:none}.health-label{color:var(--muted)}.health-value{color:var(--text);font-weight:600;font-variant-numeric:tabular-nums}.health-value.good{color:var(--success)}.health-value.warn{color:var(--warn)}.health-value.bad{color:var(--danger)}.alert-row{display:flex;gap:8px;align-items:flex-start;padding:7px 0;border-bottom:1px solid rgba(98,232,255,.05)}.alert-row:last-child{border-bottom:none}.alert-body{flex:1;min-width:0}.alert-sum{font-size:12px;font-weight:600}.alert-meta{font-size:10px;color:var(--muted);margin-top:2px}.view-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}.view-header h1{font-size:18px;font-weight:700}.dim{color:var(--muted);font-weight:400;font-size:13px}.row-gap{display:flex;gap:8px;align-items:center}.data-table{width:100%;border-collapse:collapse;font-size:12px}.data-table th{text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600}.data-table td{padding:7px 10px;border-bottom:1px solid rgba(98,232,255,.04);vertical-align:middle}.data-table tr.expandable{cursor:pointer}.data-table tr.expandable:hover td{background:rgba(98,232,255,.03)}.mono{font-family:"IBM Plex Mono",monospace}.ip{font-family:"IBM Plex Mono",monospace;font-size:11px}.host-detail-wrap{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:14px 16px;background:rgba(0,0,0,.25)}.section-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:6px;font-weight:600}.detail-row{background:rgba(0,0,0,.2)}.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}.badge-critical{background:rgba(255,77,109,.2);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)}.badge-high{background:rgba(255,140,66,.18);color:#ff8c42;border:1px solid rgba(255,140,66,.35)}.badge-medium{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-low{background:rgba(107,255,200,.1);color:#6bffc8;border:1px solid rgba(107,255,200,.22)}.badge-clean{background:rgba(107,255,200,.1);color:#6bffc8;border:1px solid rgba(107,255,200,.22)}.badge-suspicious{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-malicious{background:rgba(255,77,109,.2);color:#ff4d6d;border:1px solid rgba(255,77,109,.35)}.badge-ok{background:rgba(107,255,200,.12);color:#6bffc8;border:1px solid rgba(107,255,200,.3)}.badge-warn{background:rgba(255,206,84,.15);color:#ffce54;border:1px solid rgba(255,206,84,.28)}.badge-dim{background:rgba(255,255,255,.06);color:var(--muted);border:1px solid rgba(255,255,255,.1)}.chip{display:inline-block;background:rgba(98,232,255,.08);border:1px solid rgba(98,232,255,.15);border-radius:100px;padding:1px 7px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:var(--accent);margin:1px}.ip-chip{display:inline-block;background:rgba(107,255,200,.08);border:1px solid rgba(107,255,200,.2);border-radius:100px;padding:1px 7px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:var(--success);margin:1px 2px 1px 0}.finding-card{background:var(--card);border:1px solid var(--border);border-left-width:3px;border-radius:0 10px 10px 0;padding:12px 14px;margin-bottom:10px}.finding-card.sev-critical{border-left-color:var(--danger)}.finding-card.sev-high{border-left-color:#ff8c42}.finding-header{display:flex;align-items:center;gap:8px;margin-bottom:5px}.finding-title{flex:1;font-size:12px;font-weight:600}.finding-meta{display:flex;gap:12px;font-size:10px;color:var(--muted);flex-wrap:wrap}.finding-body{font-size:11px;color:var(--muted);margin-top:5px;line-height:1.5}.finding-detail{margin-top:8px;background:rgba(0,0,0,.2);border-radius:5px;padding:8px;font-size:10px;font-family:"IBM Plex Mono",monospace;color:#b0c8e0}.finding-detail dt{color:var(--muted);font-weight:600}.finding-detail dd{margin-left:4px;color:var(--text);margin-right:12px}.fix-hint{font-size:11px;color:var(--success);margin-top:5px}.map-wrap{position:relative;height:calc(100vh - 120px);background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden}#hsa-map-canvas{width:100%;height:100%;display:block;cursor:grab;touch-action:none}#hsa-map-canvas:active{cursor:grabbing}.map-tooltip{position:absolute;background:rgba(6,11,24,.96);border:1px solid var(--border);border-radius:7px;padding:7px 11px;font-size:10px;pointer-events:none;z-index:10;min-width:130px;box-shadow:0 4px 18px rgba(0,0,0,.5)}.map-legend{position:absolute;bottom:10px;left:10px;background:rgba(6,11,24,.82);border:1px solid var(--border);border-radius:7px;padding:8px 12px;font-size:10px;display:flex;gap:12px}.legend-item{display:flex;align-items:center;gap:4px;color:var(--muted)}.ldot{width:9px;height:9px;border-radius:50%}.map-filter-bar{display:flex;gap:6px;margin-bottom:10px}.map-fbtn{padding:4px 12px}.map-fbtn.active{background:rgba(98,232,255,.18);border-color:var(--accent);color:#fff}.tldr-bar{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px 16px;margin-bottom:12px;display:flex;gap:20px;flex-wrap:wrap;font-size:11px;color:var(--muted)}.tldr-bar strong{color:var(--accent)}.ip-detail-panel{background:rgba(6,11,24,.98);border:1px solid rgba(98,232,255,.3);border-radius:10px;padding:14px;font-size:12px}.ip-detail-panel h3{color:var(--accent);font-size:13px;margin-bottom:12px;display:flex;align-items:center;gap:8px}.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}.detail-pair{display:flex;flex-direction:column;gap:2px}.detail-key{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}.detail-val{font-size:12px;color:var(--text);word-break:break-all}.ext-report-link{display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;border-radius:999px;border:1px solid rgba(98,232,255,.25);background:rgba(98,232,255,.08);color:var(--accent);text-decoration:none;font-size:11px;font-weight:600}.ext-report-link:hover{background:rgba(98,232,255,.16);border-color:rgba(98,232,255,.45)}.rec-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:10px;display:flex;gap:12px;align-items:flex-start}.rec-icon{font-size:18px;line-height:1;flex-shrink:0;margin-top:1px}.rec-title{font-size:12px;font-weight:600;margin-bottom:3px;display:flex;align-items:center;gap:8px}.rec-detail{font-size:11px;color:var(--muted);line-height:1.55}.btn{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;border:1px solid var(--border);background:rgba(98,232,255,.05);color:var(--accent);font-size:11px;font-weight:600;cursor:pointer;transition:all .12s}.btn:hover{background:rgba(98,232,255,.12);border-color:var(--accent)}.btn:disabled{opacity:.4;cursor:default}.search-bar{padding:5px 11px;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;width:210px}.search-bar:focus{outline:none;border-color:var(--accent)}.state-box{display:flex;flex-direction:column;align-items:center;justify-content:center;height:220px;gap:14px;color:var(--muted)}.state-icon{font-size:32px}.loader{width:26px;height:26px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;gap:10px;color:var(--muted);text-align:center}.empty-icon{font-size:28px}@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--success)}50%{opacity:.6;box-shadow:0 0 2px var(--success)}}@keyframes spin{to{transform:rotate(360deg)}}.role-select{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;padding:2px 4px;cursor:pointer;font-family:inherit}.role-select:focus{outline:none;border-color:var(--accent)}.role-select:hover{border-color:var(--accent);background:rgba(98,232,255,.08)}.sortable-th{cursor:pointer;user-select:none;white-space:nowrap}.sortable-th:hover{color:var(--accent)}.sort-arrow{font-size:8px;margin-left:3px;color:var(--accent)}@media(max-width:768px){.app{flex-direction:column}.sidebar{width:100%;min-width:0;flex-direction:row;overflow-x:auto;overflow-y:hidden;border-right:none;border-bottom:1px solid var(--border);align-items:center;gap:0}.brand{display:none}.brand-tagline{display:none}.nav-list{display:flex;flex-direction:row;padding:0;flex:1;overflow-x:auto;-webkit-overflow-scrolling:touch}.nav-item{flex-direction:column;gap:2px;padding:8px 12px;font-size:10px;border-left:none;border-bottom:3px solid transparent;white-space:nowrap;min-width:0}.nav-item.active{border-left-color:transparent;border-bottom-color:var(--accent)}.nav-item svg{width:14px;height:14px}.nav-label{font-size:9px}.sidebar-status{display:none}.content{padding:12px 10px;height:calc(100vh - 52px)}.content::before{display:none}.page-title{font-size:18px}.stat-grid{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:10px}.stat-value{font-size:20px}.stat-label{font-size:9px}.two-col{grid-template-columns:1fr}.host-detail-wrap{grid-template-columns:1fr}.table-card{overflow-x:auto;-webkit-overflow-scrolling:touch}.data-table{min-width:680px}.search-bar{width:100%}.view-header{flex-direction:column;align-items:flex-start;gap:8px}.view-header h1{font-size:16px}.map-wrap{height:calc(100vh - 160px)}.map-legend{flex-wrap:wrap;gap:6px;font-size:9px}.map-filter-bar{flex-wrap:wrap}.finding-meta{flex-direction:column;gap:4px}.detail-grid{grid-template-columns:1fr}.ip-detail-panel{font-size:11px}.rec-card{flex-direction:column;gap:6px}.tldr-bar{flex-direction:column;gap:6px}.card{padding:12px;border-radius:10px}.finding-card{padding:10px}.btn{font-size:10px;padding:4px 8px}}@media(max-width:480px){.stat-grid{grid-template-columns:1fr}.data-table{min-width:560px;font-size:11px}.content{padding:8px 6px}}';

customElements.define('homesec-panel', HomeSecurityAssistantPanel);
