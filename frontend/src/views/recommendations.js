// Recommendations view.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html, nothing } from "lit";

export const recommendationsMethods = {
  _viewRecs() {
    var recs = this._data && this._data.recommendations || [];
    if (!recs.length) return html`<div><div class="view-header"><h1>${this._t('recs.page_title', 'Security Recommendations')}</h1></div><div class="empty-state card" style="height:180px"><div class="empty-icon">✓</div><p>${this._t('recs.no_recommendations', 'No recommendations at this time.')}</p></div></div>`;
    var icons = {
      critical: '\uD83D\uDEA8',
      high: '\u26A0\uFE0F',
      medium: '\uD83D\uDCA1',
      low: '\u2139\uFE0F'
    };
    var self = this;
    function _formatTemplate(template, values) {
      return template.replace(/\{([a-zA-Z0-9_]+)\}/g, function (_, key) {
        return values[key] != null ? String(values[key]) : '';
      });
    }
    function _localizedRec(r) {
      var countHosts = r.hosts && r.hosts.length || 0;
      var countFindings = r.findings_refs && r.findings_refs.length || 0;
      switch (r.category) {
        case 'patch_vulnerable':
          return {
            title: self._t('recs.title_patch_vulnerable', 'Patch vulnerable devices'),
            detail: _formatTemplate(self._t('recs.detail_patch_vulnerable', '{n} device(s) have known high or critical CVE vulnerabilities. Update firmware/software or restrict network access immediately.'), {
              n: countHosts || 1
            })
          };
        case 'vulnerability':
          return {
            title: self._t('recs.title_review_vulnerability_findings', 'Review vulnerability findings'),
            detail: self._t('recs.detail_review_vulnerability_findings', 'Active scanning found services with known security issues. Check the findings tab for CVE details and remediation steps.')
          };
        case 'no_exporter':
          return {
            title: self._t('recs.title_connect_exporter', 'Connect a flow exporter'),
            detail: self._t('recs.detail_connect_exporter', 'No NetFlow or IPFIX exporters have been observed yet. Configure your gateway, firewall, or switch to export flows to HomeSec.')
          };
        case 'exporter_unreachable':
          return {
            title: self._t('recs.title_verify_exporter', 'Verify exporter reachability'),
            detail: self._t('recs.detail_verify_exporter', 'Exporters are configured but HomeSec has not received any datagrams yet. Check exporter target IP/port, firewall rules, and container networking.')
          };
        case 'bad_flow_format':
          return {
            title: self._t('recs.title_check_flow_format', 'Check flow export format'),
            detail: self._t('recs.detail_check_flow_format', 'Datagrams are arriving but none produced records. Confirm exporter uses NetFlow v5/v9/IPFIX with IPv4 fields and valid templates.')
          };
        case 'suspicious_port':
          return {
            title: self._t('recs.title_restrict_risky_ports', 'Restrict risky outbound ports'),
            detail: self._t('recs.detail_restrict_risky_ports', 'At least one device reached a commonly abused external port such as Telnet or RDP. Block or alert on these ports at the gateway and patch the source device.')
          };
        case 'port_scan':
          return {
            title: self._t('recs.title_isolate_scanning_hosts', 'Isolate scanning hosts'),
            detail: self._t('recs.detail_isolate_scanning_hosts', 'A device is touching many ports in a short time window. Move it to an isolated VLAN or guest network until you confirm the behavior is expected.')
          };
        case 'high_egress':
          return {
            title: self._t('recs.title_review_high_egress_devices', 'Review high egress devices'),
            detail: self._t('recs.detail_review_high_egress_devices', 'One or more devices exceeded the outbound data threshold. Confirm whether the traffic matches backups, cameras, or media uploads instead of malware or exfiltration.')
          };
        case 'unknown_roles':
          return {
            title: self._t('recs.title_improve_device_identity_coverage', 'Improve device identity coverage'),
            detail: _formatTemplate(self._t('recs.detail_improve_device_identity_coverage', '{n} devices still have unknown roles. Add router, DHCP, or tracker integrations so HomeSec can correlate names, MAC addresses, and hostnames.'), {
              n: countHosts || 1
            })
          };
        case 'no_tracker':
          return {
            title: self._t('recs.title_enable_device_tracker_enrichment', 'Enable device tracker enrichment'),
            detail: self._t('recs.detail_enable_device_tracker_enrichment', 'HomeSec is seeing devices but none were enriched from Home Assistant trackers. Adding router or presence integrations will make the dashboard much more readable.')
          };
        case 'dropped_datagrams':
          return {
            title: self._t('recs.title_stabilize_exporter_templates', 'Stabilize exporter templates'),
            detail: self._t('recs.detail_stabilize_exporter_templates', 'Some flow datagrams were dropped or arrived before their templates. Reduce exporter restarts or shorten template refresh intervals on the exporter.')
          };
        default:
          return {
            title: r.title,
            detail: r.detail
          };
      }
    }
    function _recDetail(r) {
      var hosts = r.hosts || [];
      var frefs = r.findings_refs || [];
      if (!hosts.length && !frefs.length) return '';
      var hostRows = hosts.map(function (h) {
        var nameHtml = h.name && h.name !== h.ip ? html`<span style="color:rgba(140,200,255,.85);font-weight:600;margin-left:6px">${h.name}</span>` : '';
        var roleHtml = h.role && h.role !== 'unknown' ? html`<span class="badge badge-dim" style="margin-left:6px">${h.role.replace(/_/g, ' ')}</span>` : '';
        var cvesHtml = '';
        if (h.cves && h.cves.length) {
          cvesHtml = html`<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">${h.cves.map(function (c) {
            return html`<a class="ext-report-link" style="cursor:pointer" data-vuln-detail="${c}">${c}</a>`;
          })}</div>`;
        } else if (h.vuln_count > 0) {
          cvesHtml = html`<span style="font-size:10px;color:var(--muted);margin-left:6px">${h.vuln_count} CVE${h.vuln_count !== 1 ? 's' : ''}</span>`;
        }
        return html`<div class="rec-expand-row"><span class="ip">${h.ip}</span>${nameHtml}${roleHtml}${cvesHtml}</div>`;
      });
      var findingRows = frefs.map(function (f) {
        var det = f.detail || {};
        var port = det.port ? html`<span class="chip" style="margin-left:6px">port ${det.port}</span>` : '';
        var cve = det.cve_id ? html`<a class="ext-report-link" style="cursor:pointer;margin-left:6px" data-vuln-detail="${det.cve_id}">${det.cve_id}</a>` : '';
        var cnt = f.count > 1 ? html`<span style="font-size:10px;color:var(--muted);margin-left:6px">${f.count}×</span>` : '';
        return html`<div class="rec-expand-row">${self._sev(f.severity)}<span class="ip" style="margin-left:6px">${f.source_ip}</span>${port}${cve}${cnt}<span style="font-size:11px;color:var(--muted);margin-left:8px">${f.summary}</span></div>`;
      });
      return html`<div class="rec-expand-panel">${hosts.length ? html`<div class="rec-expand-section"><div class="rec-expand-label">${self._t('recs.affected_hosts', 'Affected hosts')} (${hosts.length})</div><div class="rec-expand-rows">${hostRows}</div></div>` : ''}${frefs.length ? html`<div class="rec-expand-section"><div class="rec-expand-label">${self._t('recs.related_findings', 'Related findings')} (${frefs.length})</div><div class="rec-expand-rows">${findingRows}</div></div>` : ''}</div>`;
    }
    return html`<div><div class="view-header"><h1>${this._t('recs.page_title', 'Security Recommendations')}</h1></div>${recs.map(function (r, idx) {
      var expanded = self._expandedRec === idx;
      var hasDetail = r.hosts && r.hosts.length || r.findings_refs && r.findings_refs.length;
      var text = _localizedRec(r);
      var chevron = hasDetail ? html`<span style="margin-left:auto;font-size:11px;color:var(--muted);transition:transform .15s;display:inline-block;transform:rotate(${expanded ? '90' : '0'}deg)">▶</span>` : '';
      return html`<div class="rec-card${hasDetail ? ' rec-card-clickable' : ''}" data-rec-idx=${hasDetail ? idx : nothing}><div class="rec-icon">${icons[r.priority] || '\uD83D\uDCA1'}</div><div style="flex:1;min-width:0"><div class="rec-title">${text.title} ${self._sev(r.priority)}${chevron}</div><div class="rec-detail">${text.detail}</div>${expanded ? _recDetail(r) : ''}</div></div>`;
    })}</div>`;
  }
};
