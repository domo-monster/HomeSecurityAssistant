// Settings view, save flow and unsaved-changes guard.
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html } from "lit";
import { ifDefined } from "lit/directives/if-defined.js";
import { SETTINGS_SCHEMA_I18N as _SETTINGS_SCHEMA_I18N, UI_I18N as _UI_I18N } from "../i18n/index.js";

export const settingsMethods = {
  // ── Settings view ────────────────────────────────────────────────────
  _viewSettings() {
    var self = this;
    var docsUrl = this._docsUrlForLanguage();
    var schemaLocale = _SETTINGS_SCHEMA_I18N[this._activeLocale()] || null;
    if (!this._settingsData && !this._settingsLoading) {
      this._settingsLoading = true;
      this._settingsRetries = this._settingsRetries || 0;
      this._hass.callApi('GET', 'homesec/settings').then(function (d) {
        self._settingsData = d;
        self._settingsLoading = false;
        self._settingsRetries = 0;
        self._render();
      }).catch(function (e) {
        self._settingsLoading = false;
        var status = e && typeof e === 'object' ? e.status_code || e.status || 0 : 0;
        // During integration reload the endpoint briefly returns 404 — retry automatically
        if ((status === 404 || status === 0) && self._settingsRetries < 8) {
          self._settingsRetries++;
          setTimeout(function () {
            if (self._view === 'settings') {
              self._settingsLoading = false;
              self._settingsData = null;
              self._render();
            }
          }, 2000);
          return; // keep showing the loading spinner
        }
        self._settingsRetries = 0;
        var msg;
        if (typeof e === 'string') {
          msg = e;
        } else if (e instanceof Error) {
          msg = e.message;
        } else if (e && typeof e === 'object') {
          msg = e.message || e.error || e.body || e.detail || (typeof e.status_code === 'number' ? 'HTTP ' + e.status_code : null) || JSON.stringify(e);
        } else {
          msg = String(e);
        }
        self._settingsMsg = self._t('settings.failed_load', 'Failed to load settings: ') + msg;
        self._settingsMsgType = 'error';
        self._render();
      });
      return html`<div><div class="view-header"><h1>${this._t('settings.title', 'Settings')}</h1></div><div class="state-box"><div class="loader"></div><p>${this._t('settings.loading', 'Loading settings\u2026')}</p></div></div>`;
    }
    if (this._settingsLoading) {
      return html`<div><div class="view-header"><h1>${this._t('settings.title', 'Settings')}</h1></div><div class="state-box"><div class="loader"></div><p>${this._t('settings.loading_short', 'Loading\u2026')}</p></div></div>`;
    }
    var schema = this._settingsData && this._settingsData.schema || [];
    var config = this._settingsData && this._settingsData.config || {};
    this._settingsDraft = this._settingsDraft || {};
    var msgHtml = '';
    if (this._settingsMsg) {
      var msgColor = this._settingsMsgType === 'error' ? 'var(--danger)' : 'var(--success)';
      msgHtml = html`<div style="background:rgba(0,0,0,.25);border:1px solid ${msgColor};border-radius:8px;padding:10px 14px;margin-bottom:14px;color:${msgColor};font-size:12px">${this._settingsMsg}</div>`;
    }
    var dirtyHtml = this._settingsDirty ? html`<div style="background:rgba(255,179,71,.09);border:1px solid rgba(255,179,71,.4);border-radius:8px;padding:10px 14px;margin-bottom:14px;color:var(--warn);font-size:12px">${this._t('settings.unsaved', 'You have unsaved changes.')}</div>` : '';
    var fieldsHtml = schema.map(function (section) {
      var rows = (section.fields || []).map(function (f) {
        var cfgVal = config[f.key] !== undefined ? config[f.key] : f.default !== undefined ? f.default : '';
        var hasDraft = Object.prototype.hasOwnProperty.call(self._settingsDraft, f.key);
        var val = hasDraft ? self._settingsDraft[f.key] : cfgVal;
        var inputHtml = '';
        if (f.type === 'boolean' || f.type === 'bool') {
          var checked = val === true || val === 'true' || val === 1 || val === '1';
          inputHtml = html`<input type="checkbox" id="hsa-setting-${f.key}"  ?checked=${checked} style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">`;
        } else if (f.type === 'number') {
          inputHtml = html`<input type="number" id="hsa-setting-${f.key}" value="${String(val)}" min=${ifDefined(f.min)} max=${ifDefined(f.max)} style="width:160px;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">`;
        } else if (f.type === 'password') {
          inputHtml = html`<input type="password" id="hsa-setting-${f.key}" value="${String(val)}" style="width:340px;max-width:100%;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">`;
        } else {
          inputHtml = html`<input type="text" id="hsa-setting-${f.key}" value="${String(val)}" style="width:340px;max-width:100%;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px;padding:4px 8px;font-family:inherit">`;
        }
        return html`<div style="display:flex;align-items:flex-start;gap:12px;padding:8px 0;border-bottom:1px solid rgba(98,232,255,.04)"><div style="flex:0 0 240px;min-width:0"><div style="font-size:12px;font-weight:600;color:var(--text)">${schemaLocale && schemaLocale.labels && schemaLocale.labels[f.key] || f.label}</div>${f.help ? html`<div style="font-size:10px;color:var(--muted);margin-top:2px;line-height:1.4">${schemaLocale && schemaLocale.helps && schemaLocale.helps[f.key] || f.help}</div>` : ''}</div><div style="flex:1;min-width:0">${inputHtml}</div></div>`;
      });
      return html`<div class="card" style="margin-bottom:12px"><div class="card-title">${schemaLocale && schemaLocale.sections && schemaLocale.sections[section.section] || section.section}</div>${rows}</div>`;
    });
    var linksCard = html`<div class="card" style="margin-top:14px"><div class="card-title">${this._t('settings.links', 'Links')}</div><div style="font-size:12px;color:var(--text);line-height:1.7">${this._t('settings.project', 'Project')}: <a class="ext-report-link" href="https://github.com/domo-monster/HomeSecurityAssistant" target="_blank" rel="noopener noreferrer">${this._t('settings.github_repo', 'GitHub Repository')}</a><br>${this._t('settings.documentation', 'Documentation')}: <a class="ext-report-link" href="${docsUrl}" target="_blank" rel="noopener noreferrer">${this._t('settings.open_documentation', 'Open Documentation')}</a></div></div>`;
    return html`<div><div class="view-header"><h1>${this._t('settings.title', 'Settings')}</h1><div style="font-size:11px;color:var(--muted)">${this._t('settings.subtitle', 'Changes take effect after reloading the integration.')}</div></div>${msgHtml}${dirtyHtml}${fieldsHtml}<div style="margin-top:6px"><button class="btn" data-settings-save style="padding:6px 18px;font-size:12px">${this._t('settings.save', 'Save settings')}</button> <button class="btn" data-settings-reset style="font-size:11px;opacity:.6">${this._t('settings.reload_server', 'Reload from server')}</button></div>${linksCard}</div>`;
  },

  _onSettingsSave() {
    var self = this;
    var schema = this._settingsData && this._settingsData.schema || [];
    var payload = {};
    var root = this.shadowRoot;
    schema.forEach(function (section) {
      (section.fields || []).forEach(function (f) {
        var el = root && root.getElementById('hsa-setting-' + f.key);
        if (!el) return;
        if (f.type === 'boolean' || f.type === 'bool') {
          payload[f.key] = el.checked;
        } else if (f.type === 'number') {
          payload[f.key] = Number(el.value);
        } else {
          payload[f.key] = el.value;
        }
      });
    });
    this._hass.callApi('POST', 'homesec/settings/save', payload).then(function () {
      self._settingsMsg = self._t('settings.saved_reload', 'Settings saved. Changes are applied in a moment (some require a short integration reload).');
      self._settingsMsgType = 'ok';
      self._settingsDraft = {};
      self._settingsDirty = false;
      self._pendingView = null;
      self._unregisterBeforeUnload();
      // Patch local config with saved values so the form re-renders with the new values
      if (self._settingsData && self._settingsData.config) {
        Object.assign(self._settingsData.config, payload);
      }
      self._render();
    }).catch(function (e) {
      var msg;
      if (typeof e === 'string') {
        msg = e;
      } else if (e instanceof Error) {
        msg = e.message;
      } else if (e && typeof e === 'object') {
        // Validation errors come back as HTTP 400 with {error, errors} in the body
        msg = e.body && typeof e.body === 'object' && e.body.error || e.message || e.error || (typeof e.body === 'string' ? e.body : null) || e.detail || (typeof e.status_code === 'number' ? 'HTTP ' + e.status_code : null) || JSON.stringify(e);
      } else {
        msg = String(e);
      }
      self._settingsMsg = self._t('settings.failed_save', 'Failed to save settings: ') + msg;
      self._settingsMsgType = 'error';
      self._render();
    });
  },

  _docsUrlForLanguage() {
    var lang = this._langCode();
    if (lang.indexOf('fr') === 0) return 'https://domotic.monster/homesec_fr.html';
    if (lang.indexOf('de') === 0) return 'https://domotic.monster/homesec_de.html';
    return 'https://domotic.monster/homesec.html';
  },

  _unsavedConfirmModal() {
    return html`<div id="hsa-unsaved-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.72);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px"><div class="card" style="width:min(420px,94vw);margin:0;border:1px solid rgba(255,180,0,.3)"><div class="view-header" style="margin-bottom:10px"><h1 style="font-size:16px">⚠️ ${this._t('settings.unsaved_title', 'Unsaved Changes')}</h1></div><p class="dim" style="font-size:13px;margin:0 0 18px">${this._t('settings.unsaved_body', 'You have unsaved settings changes. If you leave now they will be discarded.')}</p><div class="row-gap" style="justify-content:flex-end;gap:8px"><button class="btn" data-unsaved-stay>${this._t('settings.stay', 'Stay on Settings')}</button><button class="btn" style="background:rgba(255,77,109,.12);border-color:rgba(255,77,109,.4);color:#ff4d6d" data-unsaved-leave>${this._t('settings.discard_leave', 'Discard &amp; Leave')}</button></div></div></div>`;
  }
};
