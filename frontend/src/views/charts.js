// SVG chart helpers shared by the overview and statistics views.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, svg } from "lit";

export const chartsMethods = {
  // ── SVG donut-pie chart helper ───────────────────────────────────────
  _pieSvg(items, getVal, getLabel, colors) {
    var self = this;
    var total = items.reduce(function (s, it) {
      return s + getVal(it);
    }, 0);
    if (!total) return html`<div style="text-align:center;color:var(--muted);padding:20px;font-size:11px">No data</div>`;
    var size = 130,
      cx = 65,
      cy = 65,
      r = 52,
      ri = 28;
    var TAU = Math.PI * 2;
    var angle = -Math.PI / 2;
    var GAP = 0.018;
    var paths = [];
    items.forEach(function (it, i) {
      var val = getVal(it);
      if (!val) return;
      var sweep = val / total * TAU;
      if (sweep < 0.004) return;
      var a1 = angle + GAP / 2;
      var a2 = angle + sweep - GAP / 2;
      var x1 = (cx + r * Math.cos(a1)).toFixed(2),
        y1 = (cy + r * Math.sin(a1)).toFixed(2);
      var x2 = (cx + r * Math.cos(a2)).toFixed(2),
        y2 = (cy + r * Math.sin(a2)).toFixed(2);
      var xi1 = (cx + ri * Math.cos(a1)).toFixed(2),
        yi1 = (cy + ri * Math.sin(a1)).toFixed(2);
      var xi2 = (cx + ri * Math.cos(a2)).toFixed(2),
        yi2 = (cy + ri * Math.sin(a2)).toFixed(2);
      var large = a2 - a1 > Math.PI ? 1 : 0;
      var d = 'M ' + x1 + ' ' + y1 + ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + x2 + ' ' + y2 + ' L ' + xi2 + ' ' + yi2 + ' A ' + ri + ' ' + ri + ' 0 ' + large + ' 0 ' + xi1 + ' ' + yi1 + ' Z';
      paths.push(svg`<path d="${d}" fill="${colors[i % colors.length]}" opacity="0.88"><title>${getLabel(it)}</title></path>`);
      angle += sweep;
    });
    return html`<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" style="flex-shrink:0">${paths}</svg>`;
  },

  // ── Pie chart legend helper ──────────────────────────────────────────
  _statsLegend(items, getVal, getLabel, colors) {
    var self = this;
    var total = items.reduce(function (s, it) {
      return s + getVal(it);
    }, 0);
    return items.map(function (it, i) {
      var val = getVal(it);
      var pct = total > 0 ? Math.round(val / total * 100) : 0;
      return html`<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;font-size:11px"><div style="width:10px;height:10px;border-radius:2px;flex-shrink:0;background:${colors[i % colors.length]};opacity:.88"></div><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${getLabel(it)}</span><span style="color:var(--muted);white-space:nowrap;margin-left:4px">${pct}%</span></div>`;
    });
  },

  // ── SVG line/area chart helper ───────────────────────────────────────
  // series: [{key, label, color}]  points: array of timeseries objects with a "ts" field
  _lineChart(points, series) {
    var W = 560,
      H = 120,
      ML = 42,
      MR = 14,
      MT = 8,
      MB = 28;
    var PW = W - ML - MR,
      PH = H - MT - MB;
    if (!points || points.length < 2) {
      return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">Not enough data yet — check back after a few minutes</div>`;
    }
    var parsed = [];
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (!isNaN(t)) parsed.push({
        t: t,
        d: points[i]
      });
    }
    if (parsed.length < 2) return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">No data for this period</div>`;
    var tMin = parsed[0].t,
      tMax = parsed[parsed.length - 1].t,
      tRange = tMax - tMin || 1;
    function xp(t) {
      return (ML + (t - tMin) / tRange * PW).toFixed(1);
    }
    var svgOut = [];
    // Border + horizontal gridlines
    svgOut.push(svg`<rect x="${ML}" y="${MT}" width="${PW}" height="${PH}" fill="none" stroke="rgba(255,255,255,.08)" rx="2"/>`);
    [0.25, 0.5, 0.75].forEach(function (f) {
      var gy = (MT + PH * f).toFixed(1);
      svgOut.push(svg`<line x1="${ML}" y1="${gy}" x2="${ML + PW}" y2="${gy}" stroke="rgba(255,255,255,.05)"/>`);
    });
    // X-axis ticks
    var xRangeH = tRange / 3600000;
    for (var ti = 0; ti <= 5; ti++) {
      var tt = tMin + tRange * ti / 5;
      var tx = xp(tt);
      var dd = new Date(tt);
      var lbl = xRangeH <= 48 ? dd.getHours().toString().padStart(2, '0') + ':' + dd.getMinutes().toString().padStart(2, '0') : dd.getMonth() + 1 + '/' + dd.getDate();
      svgOut.push(svg`<line x1="${tx}" y1="${MT + PH}" x2="${tx}" y2="${MT + PH + 4}" stroke="rgba(255,255,255,.15)"/>`);
      svgOut.push(svg`<text x="${tx}" y="${MT + PH + 14}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${lbl}</text>`);
      if (ti > 0 && ti < 5) svgOut.push(svg`<line x1="${tx}" y1="${MT}" x2="${tx}" y2="${MT + PH}" stroke="rgba(255,255,255,.04)"/>`);
    }
    // Compute overall Y max across all series for a shared scale
    var yMaxAll = 1;
    series.forEach(function (s) {
      parsed.forEach(function (p) {
        var v = Number(p.d[s.key] || 0);
        if (v > yMaxAll) yMaxAll = v;
      });
    });
    // Y-axis labels (left side)
    [0, 0.5, 1].forEach(function (f) {
      var yv = Math.round(yMaxAll * f);
      var yy = (MT + PH - f * PH).toFixed(1);
      svgOut.push(svg`<text x="${ML - 4}" y="${yy}" dy="0.35em" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="end">${yv}</text>`);
    });
    // Series lines + area fills
    series.forEach(function (s, si) {
      var gradId = 'tlg-' + s.key;
      svgOut.push(svg`<defs><linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${s.color}" stop-opacity="0.28"/><stop offset="100%" stop-color="${s.color}" stop-opacity="0.02"/></linearGradient></defs>`);
      function yp(v) {
        return (MT + PH - Math.min(v, yMaxAll) / yMaxAll * PH).toFixed(1);
      }
      var lineD = parsed.map(function (p, i) {
        return (i === 0 ? 'M' : 'L') + xp(p.t) + ',' + yp(Number(p.d[s.key] || 0));
      }).join(' ');
      var areaD = lineD + ' L' + xp(parsed[parsed.length - 1].t) + ',' + (MT + PH) + ' L' + xp(parsed[0].t) + ',' + (MT + PH) + ' Z';
      svgOut.push(svg`<path d="${areaD}" fill="url(#${gradId})"/>`);
      svgOut.push(svg`<path d="${lineD}" fill="none" stroke="${s.color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>`);
    });
    var legend = series.map(function (s) {
      return html`<span style="color:${s.color};font-size:10px;margin-right:10px"><svg width="14" height="2" style="vertical-align:middle;margin-right:3px;overflow:visible"><line x1="0" y1="1" x2="14" y2="1" stroke="${s.color}" stroke-width="2"/></svg>${s.label}</span>`;
    });
    return html`<div style="width:100%;height:${H}px"><svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" preserveAspectRatio="none">${svgOut}</svg></div><div style="text-align:right;margin-top:3px">${legend}</div>`;
  },

  // ── Hourly bar chart (max value per 1-hour bucket) ────────────────────
  _hourlyBarChart(points, key, color) {
    var W = 560,
      H = 120,
      ML = 42,
      MR = 14,
      MT = 8,
      MB = 28;
    var PW = W - ML - MR,
      PH = H - MT - MB;
    if (!points || points.length < 2) {
      return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">Not enough data yet — check back after a few minutes</div>`;
    }
    // Determine time range from the points
    var tMin = Infinity,
      tMax = -Infinity;
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (!isNaN(t)) {
        if (t < tMin) tMin = t;
        if (t > tMax) tMax = t;
      }
    }
    if (!isFinite(tMin)) return html`<div style="text-align:center;padding:20px;color:var(--muted);font-size:11px">No data for this period</div>`;
    // Snap tMin back to the start of its hour so buckets align to clock hours
    var tMinHour = Math.floor(tMin / 3600000) * 3600000;
    var numBuckets = Math.max(1, Math.ceil((tMax - tMinHour) / 3600000));
    // Limit to a reasonable display maximum
    if (numBuckets > 168) numBuckets = 168; // cap at 7 days of hours
    var buckets = new Array(numBuckets).fill(0);
    for (var i = 0; i < points.length; i++) {
      var t = new Date(points[i].ts).getTime();
      if (isNaN(t)) continue;
      var bi = Math.floor((t - tMinHour) / 3600000);
      if (bi < 0) bi = 0;
      if (bi >= numBuckets) bi = numBuckets - 1;
      var v = Number(points[i][key] || 0);
      if (v > buckets[bi]) buckets[bi] = v;
    }
    var yMax = 1;
    for (var i = 0; i < buckets.length; i++) {
      if (buckets[i] > yMax) yMax = buckets[i];
    }
    var barW = Math.max(1, PW / numBuckets - 1);
    var svgOut = [];
    // Border
    svgOut.push(svg`<rect x="${ML}" y="${MT}" width="${PW}" height="${PH}" fill="none" stroke="rgba(255,255,255,.08)" rx="2"/>`);
    // Horizontal gridlines
    [0.25, 0.5, 0.75].forEach(function (f) {
      var gy = (MT + PH * f).toFixed(1);
      svgOut.push(svg`<line x1="${ML}" y1="${gy}" x2="${ML + PW}" y2="${gy}" stroke="rgba(255,255,255,.05)"/>`);
    });
    // Bars
    for (var i = 0; i < numBuckets; i++) {
      var bh = buckets[i] / yMax * PH;
      var bx = (ML + i * (PW / numBuckets)).toFixed(1);
      var by = (MT + PH - bh).toFixed(1);
      svgOut.push(svg`<rect x="${bx}" y="${by}" width="${barW.toFixed(1)}" height="${bh.toFixed(1)}" fill="${color}" opacity="0.75" rx="1"/>`);
    }
    // X-axis ticks — show up to 6 labels
    var tickCount = Math.min(6, numBuckets);
    for (var ti = 0; ti <= tickCount; ti++) {
      var frac = ti / tickCount;
      var tx = (ML + frac * PW).toFixed(1);
      var tt = tMinHour + frac * (numBuckets * 3600000);
      var dd = new Date(tt);
      var lbl = numBuckets <= 48 ? dd.getHours().toString().padStart(2, '0') + ':00' : dd.getMonth() + 1 + '/' + dd.getDate();
      svgOut.push(svg`<line x1="${tx}" y1="${MT + PH}" x2="${tx}" y2="${MT + PH + 4}" stroke="rgba(255,255,255,.15)"/>`);
      svgOut.push(svg`<text x="${tx}" y="${MT + PH + 14}" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="middle">${lbl}</text>`);
    }
    // Y-axis labels
    [0, 0.5, 1].forEach(function (f) {
      var yv = Math.round(yMax * f);
      var yy = (MT + PH - f * PH).toFixed(1);
      svgOut.push(svg`<text x="${ML - 4}" y="${yy}" dy="0.35em" font-size="9" fill="rgba(255,255,255,.4)" text-anchor="end">${yv}</text>`);
    });
    return html`<div style="width:100%;height:${H}px"><svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" preserveAspectRatio="none">${svgOut}</svg></div>`;
  }
};
