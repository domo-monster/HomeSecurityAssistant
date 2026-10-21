// Network map: canvas layout, animation, filters and hover tooltip.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, render } from "lit";

export const mapMethods = {
  _viewMap() {
    var netflowEnabledRaw = this._data && this._data.netflow_listener_enabled;
    var netflowEnabled = netflowEnabledRaw === true || netflowEnabledRaw === 'true' || netflowEnabledRaw === 1 || netflowEnabledRaw === '1';
    if (!netflowEnabled) {
      return html`<div class="state-box"><div class="state-icon">⏸</div><p>${this._t('map.disabled', 'NetFlow listener is disabled.')} ${this._t('map.enable_in', 'Enable it in')} <button class="btn" style="display:inline;padding:2px 10px;font-size:11px" data-view="settings">${this._t('view.settings', 'Settings')}</button> ${this._t('map.to_use', 'to use the Network Map.')}</p></div>`;
      return;
    }
    var baselineEnabledRaw = this._data && this._data.baseline_enabled;
    var baselineEnabled = baselineEnabledRaw === true || baselineEnabledRaw === 'true' || baselineEnabledRaw === 1 || baselineEnabledRaw === '1';
    var allDevices = this._mapAllDevices();
    var connections = this._data && this._data.connections || [];
    var baselineGraph = this._data && this._data.baseline_graph || null;
    this._mapBaselineGraph = baselineGraph;
    var extIPs = this._data && this._data.external_ips || [];
    var mcIPs = this._data && this._data.multicast_ips || [];
    var flows = this._data && this._data.summary && this._data.summary.total_flows || 0;
    var f = this._mapFilter;
    var m = this._mapMode;
    var hasBaselineGraph = !!(baselineGraph && baselineGraph.edges && baselineGraph.edges.length);
    if (!baselineEnabled) m = 'live';
    if (m !== 'live' && !hasBaselineGraph) m = 'live';
    this._mapMode = m;
    var filters = [{
      id: 'all',
      label: this._t('map.filter_all', 'All')
    }, {
      id: 'scanned',
      label: this._t('map.filter_scanned', 'Scanned')
    }, {
      id: 'flow',
      label: this._t('map.filter_flow_only', 'Flow only')
    }, {
      id: 'external',
      label: this._t('map.filter_external', 'External'),
      hide: !netflowEnabled
    }].filter(function (b) {
      return !b.hide;
    });
    var filterBtns = filters.map(function (b) {
      return html`<button class="btn map-fbtn${f === b.id ? ' active' : ''}" data-mapfilter="${b.id}">${b.label}</button>`;
    });
    var mapModes = [{
      id: 'live',
      label: this._t('map.mode_live', 'Live')
    }, {
      id: 'baseline',
      label: this._t('map.mode_baseline', 'Baseline'),
      disabled: !hasBaselineGraph || !baselineEnabled
    }, {
      id: 'compare',
      label: this._t('map.mode_compare', 'Compare'),
      disabled: !hasBaselineGraph || !baselineEnabled
    }];
    var modeBtns = baselineEnabled ? mapModes.map(function (mm) {
      return html`<button class="btn map-mbtn${m === mm.id ? ' active' : ''}" data-mapmode="${mm.id}" ?disabled=${mm.disabled}>${mm.label}</button>`;
    }) : '';
    var modeLabel = m === 'baseline' ? this._t('map.label_baseline_snapshot', 'Baseline Snapshot') : m === 'compare' ? this._t('map.label_live_vs_baseline', 'Live vs Baseline') : this._t('map.label_live_network', 'Live Network Map');
    var baselineInfo = '';
    if (hasBaselineGraph) {
      var edgeCount = (baselineGraph.edges || []).length;
      var hostCount = (baselineGraph.hosts || []).length;
      baselineInfo = html`<span class="chip" style="margin-left:6px">${this._t('map.baseline_chip', 'Baseline')} ${hostCount} ${this._t('map.hosts', 'hosts')} · ${edgeCount} ${this._t('map.edges', 'edges')}</span>`;
    }
    // ── Compare summary chips ─────────────────────────────────────────
    var compareSummaryHtml = '';
    if (m === 'compare' && hasBaselineGraph) {
      var _compEdges = this._composeMapEdges(connections, baselineGraph);
      var _cntNew = 0,
        _cntMissing = 0,
        _cntBoth = 0;
      var _topDelta = [],
        _topDeltaLabel = '';
      for (var _ci = 0; _ci < _compEdges.length; _ci++) {
        var _ce = _compEdges[_ci];
        if (_ce.edge_mode === 'new') _cntNew++;else if (_ce.edge_mode === 'missing') _cntMissing++;else if (_ce.edge_mode === 'both') _cntBoth++;
        if (_ce.edge_mode === 'both' && _ce.delta != null) _topDelta.push(_ce);
      }
      _topDelta.sort(function (a, b) {
        return Math.abs(b.delta) - Math.abs(a.delta);
      });
      if (_topDelta.length) {
        var _td = _topDelta[0];
        var _sign = _td.delta > 0 ? '+' : '';
        _topDeltaLabel = _td.source + ' \u2192 ' + _td.target + ' (' + _sign + Math.round(_td.delta * 100) / 100 + ' flows/snap)';
      }
      compareSummaryHtml = html`<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;font-size:11px"><span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em">${this._t('map.compare', 'Compare:')}</span><span style="background:rgba(50,255,120,.12);border:1px solid rgba(50,255,120,.35);border-radius:100px;padding:2px 10px;color:#32ff78">↑ ${_cntNew} ${this._t(_cntNew === 1 ? 'map.new_edge_one' : 'map.new_edge_many', _cntNew === 1 ? 'new edge' : 'new edges')}</span><span style="background:rgba(255,90,50,.12);border:1px solid rgba(255,90,50,.35);border-radius:100px;padding:2px 10px;color:#ff5a32">↓ ${_cntMissing} ${this._t(_cntMissing === 1 ? 'map.missing_edge_one' : 'map.missing_edge_many', _cntMissing === 1 ? 'missing edge' : 'missing edges')}</span><span style="background:rgba(98,232,255,.08);border:1px solid rgba(98,232,255,.2);border-radius:100px;padding:2px 10px;color:var(--accent)">${_cntBoth} ${this._t('map.unchanged', 'unchanged')}</span>${_topDeltaLabel ? html`<span style="background:rgba(255,206,84,.08);border:1px solid rgba(255,206,84,.25);border-radius:100px;padding:2px 10px;color:#ffce54;font-size:10px">${this._t('map.strongest', 'Δ strongest:')} ${_topDeltaLabel}</span>` : ''}</div>`;
    }
    var template = html`<div><div class="view-header"><h1>${modeLabel}${baselineInfo}</h1><div class="row-gap"><span id="map-stats" style="font-size:11px;color:var(--muted)">${allDevices.length} internal · ${extIPs.length} external${mcIPs.length ? ' \u00B7 ' + mcIPs.length + ' multicast' : ''} · ${this._fmtN(flows)} flows</span><button class="btn" id="map-reset-btn">${this._t('map.reset', '↺ Reset')}</button></div></div><div class="map-filter-bar" style="display:flex;justify-content:space-between;align-items:center"><div style="display:flex;gap:4px">${filterBtns}</div><div style="display:flex;gap:4px">${modeBtns}</div></div>${compareSummaryHtml}<div class="map-wrap"><canvas id="hsa-map-canvas"></canvas><div class="map-tooltip" id="hsa-map-tip" style="display:none"></div><div class="map-legend"><div class="legend-item"><div class="ldot" style="background:#8f86ff"></div>${this._t('map.legend_scanned', 'Scanned')}</div><div class="legend-item"><div class="ldot" style="background:#3ac5c9"></div>${this._t('map.legend_flow_only', 'Flow only')}</div><div class="legend-item"><div class="ldot" style="background:#88a7c7"></div>${this._t('map.legend_baseline_edge', 'Baseline edge')}</div><div class="legend-item"><div class="ldot" style="background:#ff5a32"></div>${this._t('map.legend_missing', 'Missing')}</div><div class="legend-item"><div class="ldot" style="background:#32ff78"></div>${this._t('map.legend_new', 'New')}</div><div class="legend-item"><div class="ldot" style="background:#ff4d6d"></div>${this._t('map.legend_at_risk', 'At risk')}</div><div class="legend-item"><div class="ldot" style="background:#6bffc8"></div>${this._t('map.legend_gateway', 'Gateway')}</div><div class="legend-item"><div class="ldot" style="background:#5a6a80"></div>${this._t('map.legend_external', 'External')}</div><div class="legend-item"><div class="ldot" style="background:#d4a843"></div>${this._t('map.legend_multicast', 'Multicast')}</div></div></div></div>`;
    var self = this;
    // Start the canvas once Lit has committed the DOM (same timing as before)
    this._afterRender = () => requestAnimationFrame(function () {
      var devices = self._applyMapFilter(allDevices);
      var showExt = self._mapFilter === 'all' || self._mapFilter === 'external';
      self._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph);
      var btn = self.shadowRoot.getElementById('map-reset-btn');
      // Property assignment: re-renders keep the same button, so never stack listeners
      if (btn) btn.onclick = function () {
        self._stopMap();
        self._mapZoom = 1;
        self._mapPanX = 0;
        self._mapPanY = 0;
        var d = self._applyMapFilter(allDevices);
        self._initMap(d, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph);
      };
    });
    return template;
  },

  _mapAllDevices() {
    var _mapCutoff = Date.now() - 10 * 60 * 1000;
    var allDevices = (this._data && this._data.devices || []).filter(function (d) {
      return d.alive || d.last_seen && new Date(d.last_seen).getTime() > _mapCutoff;
    });
    var baselineGraph = this._data && this._data.baseline_graph || null;
    var baselineHosts = baselineGraph && baselineGraph.hosts || [];
    var baselineByIp = {};
    for (var bi = 0; bi < baselineHosts.length; bi++) {
      var bh = baselineHosts[bi] || {};
      if (bh.ip) baselineByIp[bh.ip] = bh;
    }
    for (var di = 0; di < allDevices.length; di++) {
      var d = allDevices[di];
      var b = baselineByIp[d.ip];
      if (b) d.baseline_observation_count = b.observation_count || 0;
    }
    if (this._mapMode !== 'live' && baselineHosts.length) {
      for (var bh = 0; bh < baselineHosts.length; bh++) {
        var h = baselineHosts[bh] || {};
        if (!h.ip) continue;
        var exists = allDevices.some(function (d) {
          return d.ip === h.ip;
        });
        if (!exists) {
          allDevices.push({
            ip: h.ip,
            display_name: h.display_name || h.hostname || h.ip,
            hostname: h.hostname || '',
            probable_role: h.probable_role || 'unknown',
            alive: false,
            total_octets: 0,
            baseline_only: true,
            baseline_observation_count: h.observation_count || 0
          });
        }
      }
    }
    return allDevices;
  },

  _mapEdgeKey(source, target) {
    return source + '|' + target;
  },

  _buildLiveEdgeIndex(connections) {
    var idx = {};
    for (var i = 0; i < connections.length; i++) {
      var c = connections[i] || {};
      var source = c.source;
      var target = c.target;
      if (!source || !target) continue;
      var key = this._mapEdgeKey(source, target);
      var entry = idx[key];
      if (!entry) {
        entry = idx[key] = {
          source: source,
          target: target,
          source_kind: c.source_kind || '',
          target_kind: c.target_kind || '',
          live_octets: 0,
          live_flows: 0
        };
      }
      entry.live_octets += c.octets || 0;
      entry.live_flows += c.flows || 0;
    }
    return idx;
  },

  _buildBaselineEdgeIndex(baselineGraph) {
    var idx = {};
    var edges = baselineGraph && baselineGraph.edges || [];
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i] || {};
      var source = e.source;
      var target = e.target;
      if (!source || !target) continue;
      var key = this._mapEdgeKey(source, target);
      idx[key] = {
        source: source,
        target: target,
        source_kind: e.source_kind || '',
        target_kind: e.target_kind || '',
        active_probability: e.active_probability || 0,
        avg_octets: e.avg_octets_per_snapshot || 0,
        avg_flows: e.avg_flows_per_snapshot || 0
      };
    }
    return idx;
  },

  _composeMapEdges(connections, baselineGraph) {
    var live = this._buildLiveEdgeIndex(connections || []);
    var base = this._buildBaselineEdgeIndex(baselineGraph);
    var keys = {};
    Object.keys(live).forEach(function (k) {
      keys[k] = true;
    });
    Object.keys(base).forEach(function (k) {
      keys[k] = true;
    });
    var list = [];
    for (var key in keys) {
      var le = live[key];
      var be = base[key];
      if (this._mapMode === 'live' && !le) continue;
      if (this._mapMode === 'baseline' && !be) continue;
      var source = le && le.source || be && be.source;
      var target = le && le.target || be && be.target;
      var sourceKind = le && le.source_kind || be && be.source_kind || '';
      var targetKind = le && le.target_kind || be && be.target_kind || '';
      var liveOctets = le ? le.live_octets : 0;
      var baselineOctets = be ? be.avg_octets : 0;
      var weight = this._mapMode === 'baseline' ? Math.max(1, baselineOctets) : Math.max(1, liveOctets || baselineOctets);
      var edgeMode = 'live';
      if (this._mapMode === 'baseline') edgeMode = 'baseline';else if (this._mapMode === 'compare') edgeMode = le && be ? 'both' : le ? 'new' : 'missing';
      var liveFlows = le ? le.live_flows : 0;
      var baselineFlows = be ? be.avg_flows : 0;
      var deltaFlows = le && be ? liveFlows - baselineFlows : 0;
      var deltaRatio = 0;
      if (be && be.avg_octets > 0) deltaRatio = (liveOctets - be.avg_octets) / be.avg_octets;
      list.push({
        source: source,
        target: target,
        source_kind: sourceKind,
        target_kind: targetKind,
        weight: weight,
        edge_mode: edgeMode,
        live_octets: liveOctets,
        baseline_octets: baselineOctets,
        baseline_probability: be ? be.active_probability : 0,
        delta_ratio: deltaRatio,
        delta: deltaFlows
      });
    }
    return list;
  },

  _applyMapFilter(devices) {
    var f = this._mapFilter;
    if (f === 'scanned') return devices.filter(function (d) {
      return d.alive;
    });
    if (f === 'flow') return devices.filter(function (d) {
      return (d.total_octets || 0) > 0;
    });
    if (f === 'external') {
      var connections = this._data && this._data.connections || [];
      var baselineGraph = this._data && this._data.baseline_graph || {};
      var extPeers = {};
      for (var i = 0; i < connections.length; i++) {
        var c = connections[i];
        if (c.target_kind === 'external') extPeers[c.source] = true;
        if (c.source_kind === 'external') extPeers[c.target] = true;
      }
      if (this._mapMode !== 'live') {
        var bedges = baselineGraph.edges || [];
        for (var j = 0; j < bedges.length; j++) {
          var be = bedges[j];
          if (be.target_kind === 'external') extPeers[be.source] = true;
        }
      }
      return devices.filter(function (d) {
        return extPeers[d.ip];
      });
    }
    return devices;
  },

  _setMapMode(mode) {
    if (mode === this._mapMode) return;
    var baselineGraph = this._data && this._data.baseline_graph || null;
    var hasBaseline = !!(baselineGraph && baselineGraph.edges && baselineGraph.edges.length);
    if (mode !== 'live' && !hasBaseline) return;
    this._mapMode = mode;
    if (this._view === 'map') this._render();
  },

  _setMapFilter(f) {
    if (f === this._mapFilter) return;
    this._mapFilter = f;
    // Update button active states
    var btns = this.shadowRoot.querySelectorAll('.map-fbtn');
    btns.forEach(function (b) {
      b.classList.toggle('active', b.dataset.mapfilter === f);
    });
    // Rebuild map with new filter
    if (!this._data) return;
    var allDevices = this._mapAllDevices();
    var devices = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
    var extIPs = this._data.external_ips || [];
    this._stopMap();
    var showExt = f === 'all' || f === 'external';
    var mcIPs = this._data.multicast_ips || [];
    var baselineGraph = this._data.baseline_graph || null;
    this._initMap(devices, connections, showExt ? extIPs : [], showExt ? mcIPs : [], baselineGraph);
  },

  _initMap(devices, connections, extIPs, mcIPs, baselineGraph) {
    var self = this;
    mcIPs = mcIPs || [];
    var canvas = this.shadowRoot.getElementById('hsa-map-canvas');
    if (!canvas) return;
    var wrap = canvas.parentElement;
    canvas.width = wrap.clientWidth;
    canvas.height = wrap.clientHeight;
    var cx = canvas.width / 2,
      cy = canvas.height / 2;
    this._mapNodes = new Map();
    this._mapEdges = [];
    this._mapParticles = [];
    var slice = devices.slice(0, 80);
    for (var i = 0; i < slice.length; i++) {
      var d = slice[i];
      var theta = i / Math.max(slice.length, 1) * Math.PI * 2;
      var r = Math.min(cx, cy) * 0.28;
      var node = Object.assign({}, d, {
        ip: d.ip,
        type: 'internal',
        x: cx + Math.cos(theta) * r + (Math.random() - 0.5) * 30,
        y: cy + Math.sin(theta) * r + (Math.random() - 0.5) * 30,
        vx: 0,
        vy: 0,
        r: this._nr(d)
      });
      this._mapNodes.set(d.ip, node);
    }
    var extCount = {};
    var baselineEdges = baselineGraph && baselineGraph.edges || [];
    if (this._mapMode !== 'baseline') {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
      }
    }
    if (this._mapMode !== 'live') {
      for (var bc = 0; bc < baselineEdges.length; bc++) {
        var bce = baselineEdges[bc];
        if (bce.target_kind === 'external') extCount[bce.target] = (extCount[bce.target] || 0) + (bce.avg_flows_per_snapshot || 1);
      }
    }
    var topExt = Object.keys(extCount).sort(function (a, b) {
      return extCount[b] - extCount[a];
    }).slice(0, 25);
    for (var j = 0; j < topExt.length; j++) {
      var ip = topExt[j];
      var ang = j / topExt.length * Math.PI * 2;
      var rExt = Math.min(cx, cy) * 0.52;
      var info = extIPs.find(function (e) {
        return e.ip === ip;
      }) || {};
      this._mapNodes.set(ip, {
        ip: ip,
        type: 'external',
        x: cx + Math.cos(ang) * rExt + (Math.random() - 0.5) * 20,
        y: cy + Math.sin(ang) * rExt + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0,
        r: 4,
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
        abuse_confidence: info.abuse_confidence
      });
    }
    // Add multicast nodes in a dedicated outer ring
    var mcCount = {};
    if (this._mapMode !== 'baseline') {
      for (var mc = 0; mc < connections.length; mc++) {
        var mconn = connections[mc];
        if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
      }
    }
    if (this._mapMode !== 'live') {
      for (var bmc = 0; bmc < baselineEdges.length; bmc++) {
        var bmce = baselineEdges[bmc];
        if (bmce.target_kind === 'multicast') mcCount[bmce.target] = (mcCount[bmce.target] || 0) + (bmce.avg_flows_per_snapshot || 1);
      }
    }
    var topMc = Object.keys(mcCount).sort(function (a, b) {
      return mcCount[b] - mcCount[a];
    }).slice(0, 15);
    for (var mi = 0; mi < topMc.length; mi++) {
      var mip = topMc[mi];
      var mang = mi / topMc.length * Math.PI * 2 + Math.PI / 4;
      var rMc = Math.min(cx, cy) * 0.42;
      var minfo = mcIPs.find(function (e) {
        return e.ip === mip;
      }) || {};
      this._mapNodes.set(mip, {
        ip: mip,
        type: 'multicast',
        x: cx + Math.cos(mang) * rMc + (Math.random() - 0.5) * 15,
        y: cy + Math.sin(mang) * rMc + (Math.random() - 0.5) * 15,
        vx: 0,
        vy: 0,
        r: 4,
        label: minfo.label || mip,
        internal_sources: minfo.internal_sources || []
      });
    }
    this._mapEdges = this._composeMapEdges(connections, baselineGraph).filter(function (c) {
      return this._mapNodes.has(c.source) && this._mapNodes.has(c.target);
    }.bind(this)).slice(0, 500);
    this._mapTick = 0;
    // Zoom and pan are intentionally NOT reset here so that switching map mode
    // or filter preserves the current view.  The Reset button resets explicitly.
    this._spawnParticles();
    this._startMap(canvas);
    canvas.addEventListener('mousemove', function (e) {
      self._mapHover(e, canvas);
    });
    canvas.addEventListener('mouseleave', function () {
      var t = self.shadowRoot.getElementById('hsa-map-tip');
      if (t) t.style.display = 'none';
    });
    canvas.addEventListener('wheel', function (e) {
      e.preventDefault();
      var rect = canvas.getBoundingClientRect();
      var mx = e.clientX - rect.left,
        my = e.clientY - rect.top;
      var oldZ = self._mapZoom;
      var delta = e.deltaY > 0 ? 0.9 : 1.1;
      self._mapZoom = Math.max(0.3, Math.min(8, oldZ * delta));
      self._mapPanX = mx - (mx - self._mapPanX) * (self._mapZoom / oldZ);
      self._mapPanY = my - (my - self._mapPanY) * (self._mapZoom / oldZ);
    }, {
      passive: false
    });
    canvas.addEventListener('mousedown', function (e) {
      if (e.button === 0) {
        self._mapDragging = true;
        self._mapDragMoved = false;
        self._mapDragLastX = e.clientX;
        self._mapDragLastY = e.clientY;
      }
    });
    canvas.addEventListener('mousemove', function (e) {
      if (self._mapDragging) {
        var dx = e.clientX - self._mapDragLastX,
          dy = e.clientY - self._mapDragLastY;
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) self._mapDragMoved = true;
        self._mapPanX += dx;
        self._mapPanY += dy;
        self._mapDragLastX = e.clientX;
        self._mapDragLastY = e.clientY;
      }
    });
    canvas.addEventListener('mouseup', function () {
      self._mapDragging = false;
    });
    canvas.addEventListener('mouseleave', function () {
      self._mapDragging = false;
    });
  
    // ── Touch support (pan + pinch-zoom) ──────────────────────────────────
    canvas.addEventListener('touchstart', function (e) {
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
    }, {
      passive: false
    });
    canvas.addEventListener('touchmove', function (e) {
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
    }, {
      passive: false
    });
    canvas.addEventListener('touchend', function (e) {
      if (e.touches.length === 0) {
        if (self._mapDragging && !self._mapDragMoved) {
          // tap — find node under finger
          var rect = canvas.getBoundingClientRect();
          var tx = (e.changedTouches[0].clientX - rect.left - self._mapPanX) / self._mapZoom;
          var ty = (e.changedTouches[0].clientY - rect.top - self._mapPanY) / self._mapZoom;
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
    }, {
      passive: false
    });
    canvas.addEventListener('click', function (e) {
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
  },

  _startMap(canvas) {
    this._stopMap();
    var self = this;
    var isBaseline = this._mapMode === 'baseline';
    var loop = function () {
      try {
        if (!isBaseline) {
          self._mapStep(canvas.width, canvas.height);
          self._mapTick++;
          self._tickParticles();
        }
        self._drawMap(canvas);
      } catch (e) {
        console.error('[HomeSec] map loop error:', e);
      }
      self._mapAnim = requestAnimationFrame(loop);
    };
    this._mapAnim = requestAnimationFrame(loop);
  },

  _stopMap() {
    if (this._mapAnim) {
      cancelAnimationFrame(this._mapAnim);
      this._mapAnim = null;
    }
  },

  _spawnParticles() {
    this._mapParticles = [];
    if (this._mapMode === 'baseline') return;
    for (var i = 0; i < this._mapEdges.length; i++) {
      var e = this._mapEdges[i];
      if (e.edge_mode === 'missing') continue;
      var count = Math.min(3, Math.max(1, Math.ceil(Math.log10(e.weight + 1))));
      for (var p = 0; p < count; p++) {
        this._mapParticles.push({
          source: e.source,
          target: e.target,
          t: Math.random(),
          speed: 0.003 + Math.random() * 0.006,
          size: 1 + Math.random() * 1.2
        });
      }
    }
  },

  _tickParticles() {
    for (var i = 0; i < this._mapParticles.length; i++) {
      var p = this._mapParticles[i];
      p.t += p.speed;
      if (p.t > 1) p.t -= 1;
    }
  },

  _liveUpdateMap() {
    if (!this._data) return;
    var allDevices = this._mapAllDevices();
    var devices = this._applyMapFilter(allDevices);
    var connections = this._data.connections || [];
    var baselineGraph = this._data.baseline_graph || null;
    var extIPs = this._data.external_ips || [];
    var mcIPs = this._data.multicast_ips || [];
    var showExt = this._mapFilter === 'all' || this._mapFilter === 'external';
    var canvas = this.shadowRoot.getElementById('hsa-map-canvas');
    if (!canvas) return;
    var cx = canvas.width / 2,
      cy = canvas.height / 2;
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
          ip: d.ip,
          type: 'internal',
          x: cx + (Math.random() - 0.5) * 80,
          y: cy + (Math.random() - 0.5) * 80,
          vx: 0,
          vy: 0,
          r: this._nr(d)
        }));
        hadNew = true;
      }
    }
  
    // Update / add external nodes from connections
    var extCount = {};
    if (showExt && this._mapMode !== 'baseline') {
      for (var c = 0; c < connections.length; c++) {
        var conn = connections[c];
        if (conn.target_kind === 'external') extCount[conn.target] = (extCount[conn.target] || 0) + (conn.flows || 1);
      }
    }
    if (showExt && this._mapMode !== 'live') {
      var baselineEdges = baselineGraph && baselineGraph.edges || [];
      for (var bc = 0; bc < baselineEdges.length; bc++) {
        var bce = baselineEdges[bc];
        if (bce.target_kind === 'external') extCount[bce.target] = (extCount[bce.target] || 0) + (bce.avg_flows_per_snapshot || 1);
      }
    }
    var topExt = Object.keys(extCount).sort(function (a, b) {
      return extCount[b] - extCount[a];
    }).slice(0, 25);
    for (var j = 0; j < topExt.length; j++) {
      var ip = topExt[j];
      var info = extIPs.find(function (e) {
        return e.ip === ip;
      }) || {};
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
          ip: ip,
          type: 'external',
          x: cx + Math.cos(ang) * rExt,
          y: cy + Math.sin(ang) * rExt,
          vx: 0,
          vy: 0,
          r: 4,
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
          abuse_confidence: info.abuse_confidence
        });
        hadNew = true;
      }
    }
  
    // Update / add multicast nodes from connections
    var mcCount = {};
    if (showExt && this._mapMode !== 'baseline') {
      for (var mc = 0; mc < connections.length; mc++) {
        var mconn = connections[mc];
        if (mconn.target_kind === 'multicast') mcCount[mconn.target] = (mcCount[mconn.target] || 0) + (mconn.flows || 1);
      }
    }
    if (showExt && this._mapMode !== 'live') {
      var bmcEdges = baselineGraph && baselineGraph.edges || [];
      for (var bmc = 0; bmc < bmcEdges.length; bmc++) {
        var bmce = bmcEdges[bmc];
        if (bmce.target_kind === 'multicast') mcCount[bmce.target] = (mcCount[bmce.target] || 0) + (bmce.avg_flows_per_snapshot || 1);
      }
    }
    var topMc = Object.keys(mcCount).sort(function (a, b) {
      return mcCount[b] - mcCount[a];
    }).slice(0, 15);
    for (var mi = 0; mi < topMc.length; mi++) {
      var mip = topMc[mi];
      var minfo = mcIPs.find(function (e) {
        return e.ip === mip;
      }) || {};
      var mcNode = this._mapNodes.get(mip);
      if (mcNode) {
        mcNode.label = minfo.label || mip;
        mcNode.internal_sources = minfo.internal_sources || [];
      } else {
        var mang = Math.random() * Math.PI * 2;
        var rMc = Math.min(cx, cy) * 0.42;
        this._mapNodes.set(mip, {
          ip: mip,
          type: 'multicast',
          x: cx + Math.cos(mang) * rMc,
          y: cy + Math.sin(mang) * rMc,
          vx: 0,
          vy: 0,
          r: 4,
          label: minfo.label || mip,
          internal_sources: minfo.internal_sources || []
        });
        hadNew = true;
      }
    }
  
    // Rebuild edges from latest data (live / baseline / compare)
    this._mapEdges = this._composeMapEdges(connections, baselineGraph).filter(function (c) {
      return this._mapNodes.has(c.source) && this._mapNodes.has(c.target);
    }.bind(this)).slice(0, 500);
  
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
  },

  _mapStep(W, H) {
    var nodes = Array.from(this._mapNodes.values());
    // Adaptive physics: strong early, gentle continuous drift after settling
    var settled = this._mapTick > 200;
    var R = settled ? 400 : 1400,
      A = settled ? 0.001 : 0.004;
    var DAMP = settled ? 0.55 : 0.72,
      MAX_V = settled ? 1.2 : 5;
    var CENTER_PULL = settled ? 0.00004 : 0.00015;
    // Jitter to keep things subtly alive
    var jitter = settled ? 0.08 : 0;
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var dx = nodes[i].x - nodes[j].x || 0.1,
          dy = nodes[i].y - nodes[j].y || 0.1;
        var d2 = Math.max(dx * dx + dy * dy, 1);
        var f = R / d2,
          inv = 1 / Math.sqrt(d2);
        nodes[i].vx += dx * inv * f;
        nodes[i].vy += dy * inv * f;
        nodes[j].vx -= dx * inv * f;
        nodes[j].vy -= dy * inv * f;
      }
    }
    for (var ei = 0; ei < this._mapEdges.length; ei++) {
      var e = this._mapEdges[ei];
      var s = this._mapNodes.get(e.source),
        t = this._mapNodes.get(e.target);
      if (!s || !t) continue;
      var edx = t.x - s.x,
        edy = t.y - s.y;
      var dd = Math.max(Math.sqrt(edx * edx + edy * edy), 1);
      // Target edge length based on node types
      var ideal = s.type === 'external' || t.type === 'external' ? 100 : 55;
      var ef = A * (dd - ideal);
      s.vx += edx / dd * ef;
      s.vy += edy / dd * ef;
      t.vx -= edx / dd * ef;
      t.vy -= edy / dd * ef;
    }
    var cx2 = W / 2,
      cy2 = H / 2;
    for (var ni = 0; ni < nodes.length; ni++) {
      var n = nodes[ni];
      n.vx += (cx2 - n.x) * CENTER_PULL;
      n.vy += (cy2 - n.y) * CENTER_PULL;
      if (jitter > 0) {
        n.vx += (Math.random() - 0.5) * jitter;
        n.vy += (Math.random() - 0.5) * jitter;
      }
      n.vx *= DAMP;
      n.vy *= DAMP;
      var spd = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      if (spd > MAX_V) {
        n.vx = n.vx / spd * MAX_V;
        n.vy = n.vy / spd * MAX_V;
      }
      n.x = Math.max(n.r + 2, Math.min(W - n.r - 2, n.x + n.vx));
      n.y = Math.max(n.r + 2, Math.min(H - n.r - 2, n.y + n.vy));
    }
  },

  _drawMap(canvas) {
    var ctx = canvas.getContext('2d');
    var W = canvas.width,
      H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    var bg = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.7);
    bg.addColorStop(0, 'rgba(10,18,40,.96)');
    bg.addColorStop(1, 'rgba(4,8,18,.99)');
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, W, H);
    ctx.save();
    ctx.translate(this._mapPanX, this._mapPanY);
    ctx.scale(this._mapZoom, this._mapZoom);
    // Draw edges as curved lines
    for (var ei = 0; ei < this._mapEdges.length; ei++) {
      var e = this._mapEdges[ei];
      var s = this._mapNodes.get(e.source),
        t = this._mapNodes.get(e.target);
      if (!s || !t) continue;
      var a = Math.min(0.35, 0.03 + Math.log10(e.weight + 1) * 0.05);
      var mx = (s.x + t.x) / 2,
        my = (s.y + t.y) / 2;
      var dx = t.x - s.x,
        dy = t.y - s.y;
      var curveOff = Math.min(18, Math.sqrt(dx * dx + dy * dy) * 0.08);
      var cpx = mx + dy * curveOff / Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      var cpy = my - dx * curveOff / Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.quadraticCurveTo(cpx, cpy, t.x, t.y);
      ctx.setLineDash([]);
      if (this._mapMode === 'baseline') {
        ctx.strokeStyle = 'rgba(136,167,199,' + Math.min(0.55, a + 0.22) + ')';
        ctx.lineWidth = Math.min(1.8, 0.6 + Math.log10(e.weight + 1) * 0.18);
        ctx.setLineDash([6, 4]);
      } else if (this._mapMode === 'compare') {
        if (e.edge_mode === 'missing') {
          // vivid orange-red, thick dashed — clearly "gone"
          ctx.strokeStyle = 'rgba(255,90,50,' + Math.min(0.82, a + 0.55) + ')';
          ctx.lineWidth = Math.min(2.4, 0.8 + Math.log10(e.weight + 1) * 0.25);
          ctx.setLineDash([8, 5]);
        } else if (e.edge_mode === 'new') {
          // vivid green, solid — clearly "appeared"
          ctx.strokeStyle = 'rgba(50,255,120,' + Math.min(0.88, a + 0.58) + ')';
          ctx.lineWidth = Math.min(2.4, 0.8 + Math.log10(e.weight + 1) * 0.25);
        } else {
          // unchanged — cyan, semi-transparent
          ctx.strokeStyle = 'rgba(98,232,255,' + Math.min(0.45, a + 0.12) + ')';
          ctx.lineWidth = Math.min(1.6, 0.4 + Math.log10(e.weight + 1) * 0.16);
        }
      } else {
        ctx.strokeStyle = 'rgba(98,232,255,' + a + ')';
        ctx.lineWidth = Math.min(1.8, 0.3 + Math.log10(e.weight + 1) * 0.18);
      }
      ctx.stroke();
      ctx.setLineDash([]);
    }
    // Draw particles flowing along edges
    for (var pi = 0; pi < this._mapParticles.length; pi++) {
      var p = this._mapParticles[pi];
      var ps = this._mapNodes.get(p.source),
        pt = this._mapNodes.get(p.target);
      if (!ps || !pt) continue;
      var pmx = (ps.x + pt.x) / 2,
        pmy = (ps.y + pt.y) / 2;
      var pdx = pt.x - ps.x,
        pdy = pt.y - ps.y;
      var plen = Math.max(Math.sqrt(pdx * pdx + pdy * pdy), 1);
      var pcOff = Math.min(18, plen * 0.08);
      var pcpx = pmx + pdy * pcOff / plen,
        pcpy = pmy - pdx * pcOff / plen;
      var tt = p.t,
        it = 1 - tt;
      var px = it * it * ps.x + 2 * it * tt * pcpx + tt * tt * pt.x;
      var py = it * it * ps.y + 2 * it * tt * pcpy + tt * tt * pt.y;
      var pa = 0.5 + 0.5 * Math.sin(p.t * Math.PI);
      ctx.beginPath();
      ctx.arc(px, py, p.size, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(98,232,255,' + pa * 0.7 + ')';
      ctx.fill();
    }
    // Draw nodes
    var sorted = Array.from(this._mapNodes.values()).sort(function (a, b) {
      var order = {
        external: 0,
        multicast: 1,
        internal: 2
      };
      return (order[a.type] || 2) - (order[b.type] || 2);
    });
    var now = Date.now();
    var pulse = 0.7 + Math.sin(now * 0.004) * 0.3;
    for (var ni = 0; ni < sorted.length; ni++) {
      var n = sorted[ni];
      var col = this._nc(n);
      var nodeR = n.r;
      // Subtle breathing for active internal nodes
      if (n.type !== 'external' && n.type !== 'multicast' && (n.alive || (n.total_octets || 0) > 0)) {
        var phase = (now * 0.003 + ni * 0.7) % (Math.PI * 2);
        nodeR = n.r * (0.92 + Math.sin(phase) * 0.08);
      }
      // Outer glow ring for at-risk
      if (n.at_risk) {
        var glowR = nodeR + 4 + Math.sin(now * 0.005) * 3;
        ctx.beginPath();
        ctx.arc(n.x, n.y, glowR, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,77,109,' + (0.08 + Math.sin(now * 0.005) * 0.06) + ')';
        ctx.fill();
      }
      // Node body
      ctx.beginPath();
      ctx.arc(n.x, n.y, nodeR, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.globalAlpha = n.alive || n.type === 'external' || (n.total_octets || 0) > 0 ? 1.0 : 0.45;
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
          ctx.font = '10px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(flag, n.x, n.y - nodeR - 3);
        }
      }
      // Label: always draw for all node types
      ctx.font = '8px IBM Plex Mono, monospace';
      ctx.textAlign = 'center';
      if (n.type === 'internal') {
        // Line 1: IP address
        ctx.fillStyle = 'rgba(180,210,240,.6)';
        ctx.fillText((n.ip || '').substring(0, 18), n.x, n.y + nodeR + 9);
        // Line 2: tracker name (display_name or hostname), only if different from the IP
        var trackerName = (n.display_name || n.hostname || '').substring(0, 18);
        if (trackerName && trackerName !== (n.ip || '').substring(0, 18)) {
          ctx.fillStyle = n.at_risk ? '#ff9aae' : 'rgba(140,200,255,.85)';
          ctx.font = 'bold 8px IBM Plex Mono, monospace';
          ctx.fillText(trackerName, n.x, n.y + nodeR + 19);
        }
      } else if (n.type === 'external') {
        // Line 1: IP address
        ctx.fillStyle = n.at_risk ? '#ff9aae' : 'rgba(180,210,240,.55)';
        ctx.fillText((n.ip || '').substring(0, 16), n.x, n.y + nodeR + 9);
        // Line 2: org or hostname if available
        var extMeta = (n.org || n.hostname || '').substring(0, 16);
        if (extMeta) {
          ctx.fillStyle = n.at_risk ? 'rgba(255,154,174,.7)' : 'rgba(140,170,210,.45)';
          ctx.fillText(extMeta, n.x, n.y + nodeR + 18);
        }
      } else {
        var label = (n.label || n.ip || '').substring(0, 16);
        ctx.fillStyle = n.at_risk ? '#ff9aae' : n.type === 'multicast' ? '#d4a843' : 'rgba(180,210,240,.6)';
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
  },

  _mapHover(e, canvas) {
    if (this._mapDragging) return;
    var rect = canvas.getBoundingClientRect();
    var sx = e.clientX - rect.left,
      sy = e.clientY - rect.top;
    var mx = (sx - this._mapPanX) / this._mapZoom;
    var my = (sy - this._mapPanY) / this._mapZoom;
    var tip = this.shadowRoot.getElementById('hsa-map-tip');
    if (!tip) return;
    for (var it = this._mapNodes.entries(), r2 = it.next(); !r2.done; r2 = it.next()) {
      var ip = r2.value[0],
        n = r2.value[1];
      if (Math.sqrt((mx - n.x) * (mx - n.x) + (my - n.y) * (my - n.y)) <= n.r + 5) {
        var lbl = n.display_name || n.hostname || ip;
        var role = n.probable_role ? html`<br><span style="color:#8a9dbf">${n.probable_role}</span>` : '';
        var risk = n.at_risk ? html`<br><span style="color:#ff4d6d">⚠ ${this._t('map.at_risk', 'At risk')}</span>` : '';
        var baselineStats = this._data && this._data.baseline || {};
        var baselineSnapshots = (baselineStats.training_stats || {}).snapshots_seen || 0;
        var flagEmoji = n.country ? this._countryFlag(n.country) : '';
        var ctryLabel = n.country_name || n.country || '';
        var ctry = ctryLabel ? html`<br><span style="color:#8a9dbf">${flagEmoji ? flagEmoji + ' ' : ''}${ctryLabel}${n.city ? ', ' + n.city : ''}</span>` : '';
        var extra = [];
        if (n.type === 'multicast') {
          if (n.label && n.label !== ip) extra.push(html`<br><span style="color:#d4a843;font-size:10px">${n.label}</span>`);
          extra.push(html`<br><span style="color:#8a9dbf;font-size:10px">${this._t('map.multicast_note', 'Multicast · not internet-routed')}</span>`);
          if (n.internal_sources && n.internal_sources.length) extra.push(html`<br><span style="color:#8a9dbf;font-size:9px">${this._t('map.sources', 'Sources')}: ${n.internal_sources.join(', ')}</span>`);
        } else if (n.type === 'external') {
          if (n.org) extra.push(html`<br><span style="color:#8a9dbf;font-size:10px">${n.org.substring(0, 40)}</span>`);
          if (n.rating) extra.push(html`<br>${this._rating(n.rating)}`);
          var vtLine = n.vt_malicious != null ? 'VT: ' + n.vt_malicious + ' malicious' : '';
          var abLine = n.abuse_confidence != null ? 'Abuse: ' + n.abuse_confidence + '%' : '';
          var intelParts = [vtLine, abLine].filter(Boolean).join(' \u00B7 ');
          if (intelParts) extra.push(html`<br><span style="color:#8a9dbf;font-size:9px">${intelParts}</span>`);
          extra.push(html`<br><span style="color:var(--accent);font-size:9px;opacity:.6">${this._t('map.click_full_lookup', 'Click for full lookup')}</span>`);
        } else {
          if (this._mapMode !== 'live') {
            var obs = n.baseline_observation_count || 0;
            var presence = baselineSnapshots > 0 ? Math.min(1, obs / baselineSnapshots) : 0;
            var presencePct = Math.round(presence * 100);
            var liveLoad = Math.min(1, Math.log10((n.total_octets || 0) + 1) / 8);
            var livePct = Math.round(liveLoad * 100);
            extra.push(html`<br><span style="color:#8a9dbf;font-size:9px">${this._t('map.baseline_presence', 'Baseline presence')}: ${presencePct}%</span>`);
            extra.push(html`<div style="margin-top:2px;height:4px;background:rgba(136,167,199,.18);border-radius:3px;overflow:hidden"><div style="height:4px;width:${presencePct}%;background:#88a7c7"></div></div>`);
            extra.push(html`<br><span style="color:#8a9dbf;font-size:9px">${this._t('map.live_load', 'Live load index')}: ${livePct}%</span>`);
            extra.push(html`<div style="margin-top:2px;height:4px;background:rgba(0,224,255,.15);border-radius:3px;overflow:hidden"><div style="height:4px;width:${livePct}%;background:#00e0ff"></div></div>`);
          }
        }
        render(html`<strong style="color:#62e8ff">${lbl}</strong><br><span class="ip">${ip}</span>${role}${ctry}${extra}${risk}`, tip);
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
};
