// Small text-editor modal (rename host, dismiss note).
// Mixed into HomeSecurityAssistantPanel.prototype (see ../panel.js).
import { html } from "lit";

export const editorMethods = {
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
    requestAnimationFrame(function () {
      var input = self.shadowRoot && self.shadowRoot.getElementById('hsa-editor-input');
      if (input) input.focus();
    });
  },

  _closeEditor() {
    this._editorOpen = false;
    this._editorMode = '';
    this._editorIP = '';
    this._editorTitle = '';
    this._editorHelp = '';
    this._editorValue = '';
    this._editorPlaceholder = '';
    this._render();
  },

  _editorModal() {
    return html`<div id="hsa-editor-modal" style="position:fixed;inset:0;background:rgba(4,8,18,.68);backdrop-filter:blur(2px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px"><div class="card" style="width:min(560px,96vw);margin:0;border:1px solid rgba(98,232,255,.26)"><div class="view-header" style="margin-bottom:10px"><h1 style="font-size:16px">${this._editorTitle}</h1></div>${this._editorHelp ? html`<div class="dim" style="font-size:11px;margin-bottom:8px">${this._editorHelp}</div>` : ''}<input id="hsa-editor-input" class="search-bar" style="width:100%" type="text" maxlength="${this._editorMode === 'dismiss' ? '500' : '64'}" placeholder="${this._editorPlaceholder || ''}" value="${this._editorValue || ''}"><div class="row-gap" style="justify-content:flex-end;margin-top:12px"><button class="btn" data-editor-close="1">Cancel</button><button class="btn" data-editor-save="1">${this._editorMode === 'dismiss' ? 'Dismiss' : 'Save'}</button></div></div></div>`;
  },

  _editHostName(ip) {
    if (!this._data || !ip) return;
    var devices = this._data.devices || [];
    var d = devices.find(function (x) {
      return x.ip === ip;
    }) || {};
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
};
