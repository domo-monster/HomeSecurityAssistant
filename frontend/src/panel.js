// Security Assistant sidebar panel.
import { adoptStyles, html, nothing, render, unsafeCSS } from "lit";
import { CSS as _CSS } from "./styles.js";
import { overviewMethods } from "./views/overview.js";
import { chartsMethods } from "./views/charts.js";
import { statisticsMethods } from "./views/statistics.js";
import { mapMethods } from "./views/map.js";
import { hostsMethods } from "./views/hosts.js";
import { findingsMethods } from "./views/findings.js";
import { externalMethods } from "./views/external.js";
import { vulnerabilitiesMethods } from "./views/vulnerabilities.js";
import { suricataMethods } from "./views/suricata.js";
import { dnsMethods } from "./views/dns.js";
import { recommendationsMethods } from "./views/recommendations.js";
import { settingsMethods } from "./views/settings.js";
import { editorMethods } from "./views/editor.js";
import { VIEWS as _VIEWS, VIEW_LABELS as _VIEW_LABELS } from "./constants.js";
import { UI_I18N as _UI_I18N } from "./i18n/index.js";
import { VIEW_ICONS as _VIEW_ICONS } from "./icons.js";

class HomeSecurityAssistantPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({
      mode: 'open'
    });
    this._view = 'overview';
    this._data = null;
    this._hass = null;
    this._loading = false;
    this._error = null;
    this._refreshTimer = null;
    this._mapNodes = new Map();
    this._mapEdges = [];
    this._mapAnim = null;
    this._mapTick = 0;
    this._mapZoom = 1;
    this._mapPanX = 0;
    this._mapPanY = 0;
    this._mapDragging = false;
    this._mapDragLastX = 0;
    this._mapDragLastY = 0;
    this._mapPinchDist = null;
    this._mapPinchMidX = 0;
    this._mapPinchMidY = 0;
    this._lookupIP = null;
    this._lookingUp = false;
    this._lookupResult = null;
    this._vulnData = null;
    this._vulnLoading = false;
    this._vulnFilter = '';
    this._vulnPage = 1;
    this._vulnPageSize = 25;
    this._vulnSort = 'cvss';
    this._vulnSortDir = -1;
    this._hostFilter = '';
    this._hostSort = 'ip';
    this._hostSortDir = 1;
    this._extFilter = '';
    this._extSort = 'rating';
    this._extSortDir = 1;
    this._extPage = 1;
    this._extPageSize = 25;
    this._extIPDetail = null;
    this._editorOpen = false;
    this._editorMode = '';
    this._editorIP = '';
    this._editorTitle = '';
    this._editorHelp = '';
    this._editorValue = '';
    this._editorPlaceholder = '';
    this._vulnDetail = null;
    this._expandedRec = null;
    this._findingsGroupMode = 'category'; // 'category' | 'host' | 'severity' | 'flat'
    this._dismissedGroupMode = 'category'; // 'category' | 'host' | 'severity' | 'flat'
    this._findingsSearch = '';
    this._baselineSearch = '';
    this._dismissedSearch = '';
    this._expandedFindingGroup = null;
    this._showBaselineFindings = true;
    this._baselineGroupMode = 'category'; // 'category' | 'host' | 'flat'
    this._expandedBaselineGroup = null;
    this._regexDismissOpen = false;
    this._regexDismissPattern = '';
    this._regexDismissNote = '';
    this._mapFilter = 'all';
    this._mapMode = 'live';
    this._mapBaselineGraph = null;
    this._mapParticles = [];
    this._statsViewModes = {
      public_ips: 'pie',
      countries: 'pie',
      talkers: 'pie',
      threat_ips: 'pie',
      dns_categories: 'pie',
      dns_clients: 'pie',
      host_findings: 'pie',
      ext_deviations: 'pie',
      suricata_severity: 'pie',
      suricata_category: 'pie',
      suricata_src: 'pie'
    };
    this._dnsSearch = '';
    this._dnsCategoryFilter = '';
    this._dnsStatusFilter = '';
    this._dnsMaliciousOnly = false;
    this._dnsSort = 'time';
    this._dnsSortDir = -1;
    this._suricataSearch = '';
    this._suricataSeverityFilter = '';
    this._suricataActionFilter = '';
    this._suricataSort = 'time';
    this._suricataSortDir = -1;
    this._suricataPage = 0;
    this._suricataPageSize = 25;
    this._suricataAlertDetail = null;
    this._mobileMenuOpen = false;
    this._settingsData = null;
    this._settingsLoading = false;
    this._settingsMsg = '';
    this._settingsMsgType = '';
    this._settingsDraft = null;
    this._settingsDirty = false;
    this._pendingView = null;
    this._beforeUnloadHandler = null;
  }
  set hass(v) {
    this._hass = v;
    if (!this._data && !this._loading) this._fetch();
  }
  connectedCallback() {
    this._startRefresh();
  }
  disconnectedCallback() {
    this._stopRefresh();
    this._stopMap();
    this._unregisterBeforeUnload();
  }
  _registerBeforeUnload() {
    if (this._beforeUnloadHandler) return;
    this._beforeUnloadHandler = e => {
      if (this._settingsDirty) {
        e.preventDefault();
        e.returnValue = this._t('settings.beforeunload', 'You have unsaved Settings changes. Leave and discard them?');
        return e.returnValue;
      }
    };
    window.addEventListener('beforeunload', this._beforeUnloadHandler);
  }
  _unregisterBeforeUnload() {
    if (this._beforeUnloadHandler) {
      window.removeEventListener('beforeunload', this._beforeUnloadHandler);
      this._beforeUnloadHandler = null;
    }
  }
  _startRefresh() {
    if (this._refreshTimer) return;
    this._fetch();
    this._refreshTimer = setInterval(() => {
      // Skip polls while the browser tab is hidden or on the settings form
      if (this._view === 'settings' || document.hidden) return;
      this._fetch();
    }, 30000);
    if (!this._onVisibility) {
      this._onVisibility = () => {
        if (!document.hidden && this._refreshTimer && this._view !== 'settings') this._fetch();
      };
      document.addEventListener('visibilitychange', this._onVisibility);
    }
  }
  _stopRefresh() {
    clearInterval(this._refreshTimer);
    this._refreshTimer = null;
    if (this._onVisibility) {
      document.removeEventListener('visibilitychange', this._onVisibility);
      this._onVisibility = null;
    }
  }
  async _fetch() {
    if (this._loading || !this._hass) return;
    this._loading = true;
    // Show loading spinner immediately on initial load before awaiting
    if (!this._data) this._render();
    try {
      this._data = await this._hass.callApi('GET', 'homesec/dashboard');
      this._baselineWorking = null;
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
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    if (!netflowEnabled && (v === 'map' || v === 'external')) v = 'overview';
    var suricataEnabled = this._data && this._data.suricata_stats && this._data.suricata_stats.running || false;
    if (!suricataEnabled && v === 'suricata') v = 'overview';
    if (v === this._view) return;
    if (this._view === 'settings' && v !== 'settings' && this._settingsDirty) {
      this._pendingView = v;
      this._render();
      return;
    }
    if (v === 'settings') this._registerBeforeUnload();else this._unregisterBeforeUnload();
    this._stopMap();
    this._mobileMenuOpen = false;
    this._lookupResult = null;
    this._lookupIP = null;
    this._extIPDetail = null;
    if (this._view === 'vulnerabilities') this._vulnData = null;
    if (v === 'settings') {
      this._settingsData = null;
      this._settingsMsg = '';
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._settingsRetries = 0;
    }
    this._dnsPage = 0;
    this._dnsPageSize = 25;
    this._suricataPage = 0;
    this._suricataPageSize = 25;
    this._view = v;
    this._render();
  }
  _render() {
    const root = this.shadowRoot;
    if (!this._stylesAdopted) {
      adoptStyles(root, [unsafeCSS(_CSS)]);
      this._stylesAdopted = true;
    }
    this._afterRender = null;
    var content;
    if (this._error && !this._data) {
      content = html`<div class="state-box"><div class="state-icon">⚠</div><p>${this._error}</p></div>`;
    } else if (!this._data) {
      content = html`<div class="state-box"><div class="loader"></div><p>Loading…</p></div>`;
    } else {
      try {
        content = this._viewContent();
      } catch (err) {
        console.error('[HomeSec] render error in view \'' + this._view + '\':', err);
        content = html`<div class="state-box"><div class="state-icon">⚠</div><p>Display error — <button class="btn" data-reload>Reload</button></p></div>`;
      }
    }
    var title = this._viewLabel(this._view) || this._t('app.title', 'Security Assistant');
    render(html`<div class="app${this._mobileMenuOpen ? ' mobile-menu-open' : ''}" @click=${this._onClick} @input=${this._onInput} @change=${this._onChange} @keydown=${this._onKeyDown}><header class="mobile-topbar"><button class="mobile-menu-btn" data-mobile-menu-toggle aria-label="Open menu">☰</button><div class="mobile-topbar-title" id="hsa-mobile-title">${title}</div></header><div class="mobile-backdrop" data-mobile-menu-close></div><nav class="sidebar" id="hsa-sidebar">${this._sidebar()}</nav><main class="content" id="hsa-content">${content}</main>${this._editorOpen ? this._editorModal() : nothing}${this._vulnDetail ? this._vulnDetailModal() : nothing}${this._suricataAlertDetail !== null ? this._suricataAlertDetailModal() : nothing}${this._extIPDetail !== null ? this._extIPDetailModal() : nothing}${this._regexDismissOpen ? this._regexDismissModal() : nothing}${this._pendingView ? this._unsavedConfirmModal() : nothing}</div>`, root, {
      host: this
    });
    if (this._afterRender) {
      var after = this._afterRender;
      this._afterRender = null;
      after();
    }
  }
  _viewContent() {
    switch (this._view) {
      case 'overview':
        return this._viewOverview();
      case 'map':
        return this._viewMap();
      case 'hosts':
        return this._viewHosts();
      case 'findings':
        return this._viewFindings();
      case 'external':
        return this._viewExternal();
      case 'vulnerabilities':
        return this._viewVulns();
      case 'statistics':
        return this._viewStatistics();
      case 'dns':
        return this._viewDns();
      case 'suricata':
        return this._viewSuricata();
      case 'recommendations':
        return this._viewRecs();
      case 'settings':
        return this._viewSettings();
    }
    return nothing;
  }
  _onClick(e) {
    var mToggle = e.target.closest('[data-mobile-menu-toggle]');
    if (mToggle) {
      this._mobileMenuOpen = !this._mobileMenuOpen;
      this._render();
      return;
    }
    var mClose = e.target.closest('[data-mobile-menu-close]');
    if (mClose) {
      this._mobileMenuOpen = false;
      this._render();
      return;
    }
    var editorClose = e.target.closest('[data-editor-close]');
    if (editorClose) {
      this._closeEditor();
      return;
    }
    var editorSave = e.target.closest('[data-editor-save]');
    if (editorSave) {
      this._saveEditor();
      return;
    }
    var nav = e.target.closest('[data-view]');
    if (nav) {
      if (nav.dataset.mapMode) this._mapMode = nav.dataset.mapMode;
      this._setView(nav.dataset.view);
      return;
    }
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
    if (en) {
      this._editHostName(en.dataset.editname);
      return;
    }
    var extClose = e.target.closest('[data-ext-close]');
    if (extClose) {
      this._extIPDetail = null;
      this._lookupResult = null;
      this._lookupIP = null;
      this._render();
      return;
    }
    if (e.target.id === 'hsa-ext-ip-modal') {
      this._extIPDetail = null;
      this._lookupResult = null;
      this._lookupIP = null;
      this._render();
      return;
    }
    var extLookup = e.target.closest('[data-ext-lookup]');
    if (extLookup) {
      this._doLookup(extLookup.dataset.extLookup);
      return;
    }
    var extRow = e.target.closest('[data-ext-ip-row]');
    if (extRow && !e.target.closest('[data-ext-close]')) {
      var _extAllIPs = this._data && this._data.external_ips || [];
      var _extEntry = _extAllIPs.find(function (x) {
        return x.ip === extRow.dataset.extIpRow;
      });
      if (_extEntry) {
        this._extIPDetail = _extEntry;
        this._lookupResult = null;
        this._lookupIP = null;
        this._render();
        this._doLookup(_extEntry.ip);
      }
      return;
    }
    var hr = e.target.closest('tr[data-ip]');
    if (hr && !e.target.closest('select')) {
      this._toggleRow(hr.dataset.ip);
      return;
    }
    var dismiss = e.target.closest('[data-dismiss]');
    if (dismiss) {
      this._dismissFinding(dismiss.dataset.dismiss);
      return;
    }
    var undismiss = e.target.closest('[data-undismiss]');
    if (undismiss) {
      this._undismissFinding(undismiss.dataset.undismiss);
      return;
    }
    var undismissGroup = e.target.closest('[data-undismiss-group]');
    if (undismissGroup) {
      this._undismissGroup(undismissGroup.dataset.undismissGroup);
      return;
    }
    // Findings: grouped view toggle
    if (e.target.closest('[data-findings-group-mode]')) {
      var _fgm = e.target.closest('[data-findings-group-mode]');
      this._findingsGroupMode = _fgm.dataset.findingsGroupMode;
      this._expandedFindingGroup = null;
      this._render();
      return;
    }
    if (e.target.closest('[data-dismissed-group-mode]')) {
      var _dgm = e.target.closest('[data-dismissed-group-mode]');
      this._dismissedGroupMode = _dgm.dataset.dismissedGroupMode;
      this._expandedFindingGroup = null;
      this._render();
      return;
    }
    // Findings: show/hide baseline anomalies
    if (e.target.closest('[data-baseline-findings-toggle]')) {
      this._showBaselineFindings = !this._showBaselineFindings;
      this._expandedFindingGroup = null;
      this._expandedBaselineGroup = null;
      this._render();
      return;
    }
    // Findings: baseline group mode switcher
    var bgm = e.target.closest('[data-baseline-group-mode]');
    if (bgm) {
      this._baselineGroupMode = bgm.dataset.baselineGroupMode;
      this._expandedBaselineGroup = null;
      this._render();
      return;
    }
    // Findings: expand/collapse a baseline group
    var fbge = e.target.closest('[data-expand-baseline-group]');
    if (fbge && !e.target.closest('[data-dismiss-group]') && !e.target.closest('[data-undismiss-group]')) {
      var bgk = fbge.dataset.expandBaselineGroup;
      this._expandedBaselineGroup = this._expandedBaselineGroup === bgk ? null : bgk;
      this._render();
      return;
    }
    // Findings: expand/collapse a finding group
    var fge = e.target.closest('[data-expand-group]');
    if (fge && !e.target.closest('[data-dismiss-group]') && !e.target.closest('[data-undismiss-group]')) {
      var gk = fge.dataset.expandGroup;
      this._expandedFindingGroup = this._expandedFindingGroup === gk ? null : gk;
      this._render();
      return;
    }
    // Findings: dismiss all findings in a group
    var fdg = e.target.closest('[data-dismiss-group]');
    if (fdg && !e.target.closest('[data-undismiss-group]')) {
      this._dismissGroup(fdg.dataset.dismissGroup);
      return;
    }
    // Findings: open regex dismiss modal
    if (e.target.closest('[data-regex-dismiss-open]')) {
      this._regexDismissOpen = true;
      this._regexDismissPattern = '';
      this._regexDismissNote = '';
      this._render();
      return;
    }
    // Findings: close regex dismiss modal
    if (e.target.closest('[data-regex-dismiss-close]')) {
      this._regexDismissOpen = false;
      this._render();
      return;
    }
    // Findings: confirm regex dismiss
    if (e.target.closest('[data-regex-dismiss-confirm]')) {
      this._applyRegexDismiss();
      return;
    }
    if (e.target.closest('[data-unsaved-stay]')) {
      this._pendingView = null;
      this._render();
      return;
    }
    if (e.target.closest('[data-unsaved-leave]')) {
      var dest = this._pendingView;
      this._pendingView = null;
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._unregisterBeforeUnload();
      this._setView(dest);
      return;
    }
    var mf = e.target.closest('[data-mapfilter]');
    if (mf) {
      this._setMapFilter(mf.dataset.mapfilter);
      return;
    }
    var mm = e.target.closest('[data-mapmode]');
    if (mm) {
      this._setMapMode(mm.dataset.mapmode);
      return;
    }
    var hs = e.target.closest('[data-hostsort]');
    if (hs) {
      this._setHostSort(hs.dataset.hostsort);
      return;
    }
    var es = e.target.closest('[data-extsort]');
    if (es) {
      this._setExtSort(es.dataset.extsort);
      return;
    }
    var vs = e.target.closest('[data-vulnsort]');
    if (vs) {
      this._setVulnSort(vs.dataset.vulnsort);
      return;
    }
    var vp = e.target.closest('[data-vuln-page]');
    if (vp) {
      this._vulnPage = parseInt(vp.dataset.vulnPage, 10) || 1;
      this._render();
      return;
    }
    var dnsPager = e.target.closest('[data-dns-page]');
    if (dnsPager) {
      var pg = parseInt(dnsPager.dataset.dnsPage, 10);
      if (!isNaN(pg)) {
        this._dnsPage = pg;
        this._render();
      }
      return;
    }
    var ds = e.target.closest('[data-dnssort]');
    if (ds) {
      this._setDnsSort(ds.dataset.dnssort);
      return;
    }
    var suricataPager = e.target.closest('[data-suricata-page]');
    if (suricataPager) {
      var spg = parseInt(suricataPager.dataset.suricataPage, 10);
      if (!isNaN(spg)) {
        this._suricataPage = spg;
        this._render();
      }
      return;
    }
    var ss = e.target.closest('[data-suricatasort]');
    if (ss) {
      this._setSuricataSort(ss.dataset.suricatasort);
      return;
    }
    var sc = e.target.closest('[data-suricata-close]');
    if (sc) {
      this._suricataAlertDetail = null;
      this._render();
      return;
    }
    var sad = e.target.closest('[data-suricata-alert-idx]');
    if (sad && !e.target.closest('[data-suricata-close]')) {
      var idx = parseInt(sad.dataset.suricataAlertIdx, 10);
      var _log = this._data && this._data.suricata_log || [];
      var _filtered = this._suricataFilteredLog(_log);
      var _sorted = this._suricataSortedLog(_filtered);
      var _PAGE_SIZE = this._suricataPageSize || 25;
      var _page = this._suricataPage || 0;
      var _absIdx = _page * _PAGE_SIZE + idx;
      if (_sorted[_absIdx]) {
        this._suricataAlertDetail = _sorted[_absIdx];
        this._render();
      }
      return;
    }
    var vr = e.target.closest('[data-vuln-refresh]');
    if (vr) {
      this._vulnData = null;
      this._vulnLoading = false;
      this._render();
      return;
    }
    var vc = e.target.closest('[data-vuln-close]');
    if (vc) {
      // Only close if clicking the backdrop directly or the close button, not card contents
      if (e.target.hasAttribute('data-vuln-close') || e.target.closest('button[data-vuln-close]')) {
        this._vulnDetail = null;
        this._render();
        return;
      }
    }
    var vd = e.target.closest('[data-vuln-detail]');
    if (vd) {
      this._openVulnDetail(vd.dataset.vulnDetail);
      return;
    }
    var st = e.target.closest('[data-statstoggle]');
    if (st) {
      var _sp = st.dataset.statstoggle.split(':');
      this._statsViewModes[_sp[0]] = _sp[1];
      this._render();
      return;
    }
    var ri = e.target.closest('[data-rec-idx]');
    if (ri) {
      var idx = parseInt(ri.dataset.recIdx, 10);
      this._expandedRec = this._expandedRec === idx ? null : idx;
      this._render();
      return;
    }
    var ba = e.target.closest('[data-baseline-action]');
    if (ba) {
      var action = ba.getAttribute('data-baseline-action');
      var svc = null;
      var actionLabel = ba.textContent.trim();
      if (action === 'start') svc = 'start_baseline_training';else if (action === 'stop') svc = 'stop_baseline_training';else if (action === 'retrain') svc = 'retrain_baseline';else if (action === 'clear') svc = 'clear_baseline';
      if (svc && this._hass) {
        // Show an immediate "working" overlay on the baseline card until the
        // next data refresh (or an error) clears it
        this._baselineWorking = actionLabel;
        this._render();
        console.log('[HomeSec] Calling service:', svc);
        this._hass.callService('homesec', svc, {}).then(() => {
          setTimeout(() => this._fetch(), 800);
        }).catch(() => {
          // Remove overlay on error so user can try again
          this._baselineWorking = null;
          this._render();
        });
      }
      return;
    }
    var sa = e.target.closest('[data-service-action]');
    if (sa && this._hass) {
      var svc = sa.getAttribute('data-service-action');
      var btn = sa;
      var origText = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Working\u2026';
      console.log('[HomeSec] Calling service:', svc);
      this._hass.callService('homesec', svc, {}).then(resp => {
        if (svc === 'trigger_scan' && resp && resp.scan && resp.scan.status === 'no_targets') {
          btn.textContent = 'No targets';
        } else {
          btn.textContent = 'Done \u2713';
        }
        setTimeout(() => {
          btn.disabled = false;
          btn.textContent = origText;
        }, 2000);
        setTimeout(() => this._fetch(), 1500);
      }).catch(err => {
        btn.textContent = 'Error \u2717';
        btn.style.borderColor = 'var(--danger, #ff4e4e)';
        console.error('[HomeSec] Service action failed:', svc, err);
        setTimeout(() => {
          btn.disabled = false;
          btn.textContent = origText;
          btn.style.borderColor = '';
        }, 3000);
      });
      return;
    }
    if (e.target.closest('[data-settings-save]')) {
      this._onSettingsSave();
      return;
    }
    if (e.target.closest('[data-settings-reset]')) {
      this._settingsDraft = {};
      this._settingsDirty = false;
      this._settingsData = null;
      this._settingsMsg = '';
      this._unregisterBeforeUnload();
      this._registerBeforeUnload();
      this._render();
      return;
    }
  }
  _onInput(e) {
    if (e.target && e.target.id && e.target.id.indexOf('hsa-setting-') === 0) {
      if (e.target.type === 'checkbox') return;
      var key = e.target.id.slice('hsa-setting-'.length);
      this._settingsDraft = this._settingsDraft || {};
      this._settingsDraft[key] = e.target.value;
      this._settingsDirty = true;
      this._registerBeforeUnload();
      return;
    }
    if (e.target.id === 'hsa-host-filter') {
      this._hostFilter = e.target.value;
      this._render();
    }
    if (e.target.id === 'hsa-ext-filter') {
      this._extFilter = e.target.value;
      this._extPage = 1;
      this._render();
    }
    if (e.target.hasAttribute('data-vuln-search')) {
      this._vulnFilter = e.target.value;
      this._vulnPage = 1;
      this._render();
    }
    if (e.target.id === 'hsa-regex-pattern') {
      this._regexDismissPattern = e.target.value;
      this._render();
    }
    if (e.target.id === 'hsa-regex-note') {
      this._regexDismissNote = e.target.value;
    }
  }
  _onKeyDown(e) {
    if (e.key !== 'Enter') return;
    if (e.target.hasAttribute('data-findings-search')) {
      this._findingsSearch = e.target.value;
      this._render();
    } else if (e.target.hasAttribute('data-baseline-search')) {
      this._baselineSearch = e.target.value;
      this._render();
    } else if (e.target.hasAttribute('data-dismissed-search')) {
      this._dismissedSearch = e.target.value;
      this._render();
    }
  }
  _onChange(e) {
    if (e.target && e.target.id && e.target.id.indexOf('hsa-setting-') === 0) {
      var key = e.target.id.slice('hsa-setting-'.length);
      this._settingsDraft = this._settingsDraft || {};
      this._settingsDraft[key] = e.target.type === 'checkbox' ? !!e.target.checked : e.target.value;
      this._settingsDirty = true;
      this._registerBeforeUnload();
      return;
    }
    if (e.target.id === 'hsa-ext-pagesize') {
      this._extPageSize = Math.max(5, Math.min(200, parseInt(e.target.value, 10) || 25));
      this._extPage = 1;
      this._render();
      return;
    }
    if (e.target.id === 'hsa-dns-pagesize') {
      this._dnsPageSize = Math.max(10, Math.min(100, parseInt(e.target.value, 10) || 25));
      this._dnsPage = 0;
      this._render();
      return;
    }
    if (e.target.id === 'hsa-suricata-pagesize') {
      this._suricataPageSize = Math.max(10, Math.min(100, parseInt(e.target.value, 10) || 25));
      this._suricataPage = 0;
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
  async _undismissGroup(groupKey) {
    var dismissed = this._data && this._data.dismissed_findings || [];
    var BASELINE_ONLY_CATS = {
      anomaly_new_host: 1,
      anomaly_new_peer: 1,
      anomaly_new_port: 1,
      anomaly_new_dns_domain: 1,
      anomaly_new_dns_category: 1
    };
    var toMatch;
    if (groupKey.startsWith('fcat:')) {
      var cat = groupKey.slice(5);
      toMatch = dismissed.filter(function (f) {
        return (f.category || 'unknown') === cat;
      });
    } else if (groupKey.startsWith('fhost:')) {
      var ip = groupKey.slice(6);
      toMatch = dismissed.filter(function (f) {
        return (f.source_ip || 'unknown') === ip;
      });
    } else if (groupKey.startsWith('fsev:')) {
      var sev = groupKey.slice(5);
      toMatch = dismissed.filter(function (f) {
        return (f.severity || 'info') === sev;
      });
    } else {
      // legacy: match by summary (renderGrouped path)
      toMatch = dismissed.filter(function (f) {
        return (f.summary || f.category || 'Unknown') === groupKey;
      });
    }
    if (!toMatch.length) return;
    try {
      await Promise.all(toMatch.map(f => this._hass.callApi('POST', 'homesec/findings/undismiss', {
        key: f.key || f.source_ip + ':' + f.category
      })));
      this._expandedFindingGroup = null;
      this._fetch();
    } catch (err) {
      alert('Failed to restore group: ' + (err.message || String(err)));
    }
  }
  async _undismissFinding(key) {
    if (!key) return;
    try {
      await this._hass.callApi('POST', 'homesec/findings/undismiss', {
        key: key
      });
      this._fetch();
    } catch (err) {
      alert('Failed to restore finding: ' + (err.message || String(err)));
    }
  }
  async _dismissGroup(summary) {
    var findings = this._data && this._data.findings || [];
    var baselineAnomalies = this._data && this._data.baseline_anomalies || [];
    var toMatch;
    if (summary.startsWith('bhost:')) {
      var ip = summary.slice(6);
      toMatch = baselineAnomalies.filter(function (f) {
        return f.source_ip === ip;
      });
    } else if (summary.startsWith('bcat:')) {
      var cat = summary.slice(5);
      toMatch = baselineAnomalies.filter(function (f) {
        return f.category === cat;
      });
    } else if (summary.startsWith('fcat:')) {
      var fcat = summary.slice(5);
      toMatch = findings.filter(function (f) {
        return (f.category || 'unknown') === fcat;
      });
    } else if (summary.startsWith('fhost:')) {
      var fip = summary.slice(6);
      toMatch = findings.filter(function (f) {
        return (f.source_ip || 'unknown') === fip;
      });
    } else if (summary.startsWith('fsev:')) {
      var fsev = summary.slice(5);
      toMatch = findings.filter(function (f) {
        return (f.severity || 'info') === fsev;
      });
    } else {
      toMatch = findings.filter(function (f) {
        return f.summary === summary;
      });
      if (!toMatch.length) toMatch = baselineAnomalies.filter(function (f) {
        return f.summary === summary;
      });
    }
    if (!toMatch.length) return;
    try {
      await Promise.all(toMatch.map(f => this._hass.callApi('POST', 'homesec/findings/dismiss', {
        key: f.key || f.source_ip + ':' + f.category,
        note: 'Dismissed as group'
      })));
      this._expandedFindingGroup = null;
      this._fetch();
    } catch (err) {
      alert('Failed to dismiss group: ' + (err.message || String(err)));
    }
  }
  async _applyRegexDismiss() {
    var pattern = this._regexDismissPattern.trim();
    var note = this._regexDismissNote.trim();
    if (!pattern) return;
    var rx;
    try {
      rx = new RegExp(pattern, 'i');
    } catch (e) {
      alert('Invalid regex: ' + e.message);
      return;
    }
    var findings = this._data && this._data.findings || [];
    var matched = findings.filter(function (f) {
      return rx.test(f.summary || '') || rx.test(f.key || '');
    });
    if (!matched.length) {
      alert('No active findings match this pattern.');
      return;
    }
    this._regexDismissOpen = false;
    this._render();
    var autoNote = (note || 'Regex dismiss: ' + pattern).slice(0, 500);
    try {
      await Promise.all(matched.map(f => this._hass.callApi('POST', 'homesec/findings/dismiss', {
        key: f.key || f.source_ip + ':' + f.category,
        note: autoNote
      })));
      this._fetch();
    } catch (err) {
      alert('Failed to dismiss findings: ' + (err.message || String(err)));
    }
  }
  async _saveRole(ip, role) {
    try {
      await this._hass.callApi('POST', 'homesec/device/role', {
        ip: ip,
        role: role
      });
      this._fetch();
    } catch (err) {
      alert('Failed to save role: ' + (err.message || String(err)));
    }
  }
  async _saveHostName(ip, name) {
    try {
      await this._hass.callApi('POST', 'homesec/device/name', {
        ip: ip,
        name: name
      });
      this._fetch();
    } catch (err) {
      alert('Failed to save name: ' + (err.message || String(err)));
    }
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
        await this._hass.callApi('POST', 'homesec/findings/dismiss', {
          key: ip,
          note: raw.slice(0, 500)
        });
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
  _sidebar() {
    var _BL_ONLY = {
      anomaly_new_host: 1,
      anomaly_new_peer: 1,
      anomaly_new_port: 1,
      anomaly_new_dns_domain: 1,
      anomaly_new_dns_category: 1
    };
    var secFindings = (this._data && this._data.findings || []).filter(function (f) {
      return !_BL_ONLY[f.category];
    });
    var findingGroups = {};
    secFindings.forEach(function (f) {
      findingGroups[f.summary || f.category || 'Unknown'] = true;
    });
    var blAnoms = this._data && this._data.baseline_anomalies || [];
    var blCats = {};
    blAnoms.forEach(function (a) {
      blCats[a.category || 'unknown'] = true;
    });
    var totalFindings = Object.keys(findingGroups).length + Object.keys(blCats).length;
    var ext_threat = (this._data && this._data.external_ips || []).filter(function (e) {
      return e.blacklisted;
    }).length;
    var dnsEnabled = this._data && this._data.dns_proxy_stats && this._data.dns_proxy_stats.running || false;
    var suricataEnabled = this._data && this._data.suricata_stats && this._data.suricata_stats.running || false;
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    var self = this;
    var views = dnsEnabled ? _VIEWS.slice() : _VIEWS.filter(function (v) {
      return v !== 'dns';
    });
    if (!netflowEnabled) {
      views = views.filter(function (v) {
        return v !== 'map' && v !== 'external';
      });
    }
    if (!suricataEnabled) {
      views = views.filter(function (v) {
        return v !== 'suricata';
      });
    }
    var items = views.map(function (v) {
      var badge = '';
      if (v === 'findings' && totalFindings > 0) badge = html`<span class="nav-badge">${totalFindings}</span>`;
      if (v === 'external' && ext_threat > 0) badge = html`<span class="nav-badge danger">${ext_threat}</span>`;
      return html`<li class="nav-item ${self._view === v ? 'active' : ''}" data-view="${v}">${_VIEW_ICONS[v]}<span class="nav-label">${self._viewLabel(v)}</span>${badge}</li>`;
    });
    var exporters = this._data && this._data.summary && this._data.summary.exporters || [];
    var status = exporters.length > 0 ? 'online' : 'waiting';
    return html`<div class="brand"><img src="/api/homesec/frontend/hsa-logo.svg" alt="logo" style="height:32px;width:32px;margin-right:10px;border-radius:8px;box-shadow:0 0 8px #62e8ff55;vertical-align:middle"><div class="brand-text"><span class="brand-name">Security</span><span class="brand-sub">Assistant</span><span class="brand-tagline">${this._t('sidebar.tagline', 'Network security telemetry with live flow context')}</span></div></div><ul class="nav-list">${items}</ul><div class="sidebar-status ${status}"><div class="status-dot"></div><span>${status === 'online' ? this._t('sidebar.collector_active', 'Collector active') : this._t('sidebar.awaiting_flows', 'Awaiting flows')}</span><span style="margin-left:auto;opacity:.45;font-size:9px">v${this._data && this._data.summary && this._data.summary.version || '…'}</span></div><div class="sidebar-copy"><a href="https://domotic.monster" target="_blank" rel="noopener noreferrer">© 2026 domotic.monster</a></div>`;
  }
  async _doLookup(ip) {
    if (this._lookingUp) return;
    this._lookupIP = ip;
    this._lookingUp = true;
    this._lookupResult = null;
    this._render();
    try {
      this._lookupResult = await this._hass.callApi('GET', 'homesec/lookup?ip=' + encodeURIComponent(ip));
    } catch (e) {
      this._lookupResult = {
        ip: ip,
        error: e.message
      };
    } finally {
      this._lookingUp = false;
      this._render();
    }
  }
  // ── Helpers ────────────────────────────────────────────────────────────────
  _stat(v, label, type) {
    return html`<div class="stat-card ${type}"><div class="stat-value">${v}</div><div class="stat-label">${label}</div></div>`;
  }
  _hrow(k, v, cls) {
    return html`<div class="health-row"><span class="health-label">${k}</span><span class="health-value ${cls}">${String(v)}</span></div>`;
  }
  _kv(k, v) {
    return html`<div class="health-row"><span class="health-label">${k}</span><span class="health-value">${String(v)}</span></div>`;
  }
  _sev(s) {
    return s ? html`<span class="badge badge-${s}">${s}</span>` : '';
  }
  _rating(r) {
    return r ? html`<span class="badge badge-${r}">${r}</span>` : '';
  }
  _ratingWithSource(r, src) {
    if (!r) return '';
    return html`<span class="badge badge-${r}" title=${src ? src : nothing}>${r}</span>`;
  }
  _cdot(c) {
    var col = {
      high: '#6bffc8',
      medium: '#ffce54',
      low: '#5a6a80'
    }[c] || '#5a6a80';
    return c ? html`<span title="${c}" style="color:${col};font-size:8px">●</span>` : '';
  }
  _nc(n) {
    if (n.at_risk || n.blacklisted) return '#ff4d6d';
    if (n.type === 'multicast') return '#d4a843';
    if (n.type === 'external') return '#5a6a80';
    if (n.baseline_only) return '#88a7c7';
    if (n.probable_role === 'dns_or_gateway') return '#6bffc8';
    if (n.probable_role === 'camera') return '#ffb347';
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
  _nr(n) {
    return Math.max(4, Math.min(14, 4 + Math.log10((n.total_octets || 0) + 1) * 0.9));
  }
  _bytes(n) {
    if (!n) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
    return (n / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
  }
  _fmtN(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return Math.floor(n / 1e3) + 'K';
    return String(n);
  }
  _uptime(iso) {
    if (!iso) return '—';
    var s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    var d = Math.floor(s / 86400);
    var h = Math.floor(s % 86400 / 3600);
    var m = Math.floor(s % 3600 / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm ' + s % 60 + 's';
  }
  _ago(iso) {
    if (!iso) return 'never';
    var d = Date.now() - new Date(iso).getTime();
    if (d < 60000) return this._t('time.just_now', 'just now');
    if (d < 3600000) return this._t('time.minutes_ago', '{n}m ago').replace('{n}', Math.floor(d / 60000));
    if (d < 86400000) return this._t('time.hours_ago', '{n}h ago').replace('{n}', Math.floor(d / 3600000));
    return this._t('time.days_ago', '{n}d ago').replace('{n}', Math.floor(d / 86400000));
  }
  _langCode() {
    var hass = this._hass || {};
    var lang = '';
    if (typeof hass.language === 'string') lang = hass.language;else if (typeof hass.selectedLanguage === 'string') lang = hass.selectedLanguage;else if (hass.locale && typeof hass.locale.language === 'string') lang = hass.locale.language;else if (typeof navigator !== 'undefined' && typeof navigator.language === 'string') lang = navigator.language;
    return String(lang || '').toLowerCase();
  }
  _activeLocale() {
    var lang = this._langCode();
    if (lang.indexOf('fr') === 0) return 'fr';
    if (lang.indexOf('de') === 0) return 'de';
    if (lang.indexOf('es') === 0) return 'es';
    if (lang.indexOf('it') === 0) return 'it';
    return 'en';
  }
  _t(key, fallback) {
    var locale = this._activeLocale();
    var dict = _UI_I18N[locale] || {};
    return Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : fallback;
  }
  _viewLabel(view) {
    return this._t('view.' + view, _VIEW_LABELS[view] || view);
  }
}
Object.assign(
  HomeSecurityAssistantPanel.prototype,
  overviewMethods,
  chartsMethods,
  statisticsMethods,
  mapMethods,
  hostsMethods,
  findingsMethods,
  externalMethods,
  vulnerabilitiesMethods,
  suricataMethods,
  dnsMethods,
  recommendationsMethods,
  settingsMethods,
  editorMethods,
);

if (!customElements.get("homesec-panel")) {
  customElements.define("homesec-panel", HomeSecurityAssistantPanel);
}