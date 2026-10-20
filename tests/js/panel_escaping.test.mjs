// Regression test: hostile server data must never become live HTML in the panel.
// Run with: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const panelPath = fileURLToPath(
  new URL("../../custom_components/homesec/frontend/homesec-panel.js", import.meta.url),
);

function loadPanelClass() {
  const registry = {};
  const sandbox = {
    HTMLElement: class {},
    customElements: { define: (name, cls) => { registry[name] = cls; }, get: () => undefined },
    window: { addEventListener() {}, removeEventListener() {} },
    document: { addEventListener() {}, removeEventListener() {}, createElement: () => ({}) },
    navigator: { language: "en" },
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(readFileSync(panelPath, "utf8"), sandbox, { filename: panelPath });
  const Panel = registry["homesec-panel"];
  assert.ok(Panel, "panel registered");
  // Skip the DOM-dependent constructor; render helpers only need prototype methods.
  const panel = Object.create(Panel.prototype);
  panel._activeLocale = () => "en";
  return panel;
}

const XSS = '"><img src=x onerror=alert(1)>';

function assertInert(html) {
  assert.ok(!/<img\b/i.test(html), `live <img> tag in: ${html.slice(0, 200)}`);
  assert.ok(!/<svg[^>]*onload/i.test(html), "live onload handler");
  assert.ok(!/"\s*onerror=/i.test(html), "attribute breakout");
}

test("_esc neutralises markup and quotes", () => {
  const panel = loadPanelClass();
  assert.equal(panel._esc(`<a href='x'>"`), "&lt;a href=&#39;x&#39;&gt;&quot;");
  assert.equal(panel._esc(null), "");
});

test("statistics chart labels are escaped", () => {
  const panel = loadPanelClass();
  const items = [{ flows: 5, hostname: XSS }];
  const label = (e) => e.hostname;
  assertInert(panel._pieSvg(items, (e) => e.flows, label, ["#fff"]));
  assertInert(panel._statsLegend(items, (e) => e.flows, label, ["#fff"]));
});

test("suricata detail modal never renders an injected signature id", () => {
  const panel = loadPanelClass();
  panel._data = { devices: [] };
  panel._suricataAlertDetail = {
    timestamp: "2026-01-01T00:00:00Z",
    src_ip: XSS,
    dest_ip: "8.8.8.8",
    signature: XSS,
    signature_id: XSS,
    category: XSS,
    severity: 1,
    action: "allowed",
  };
  const html = panel._suricataAlertDetailModal();
  assertInert(html);
  assert.ok(!html.includes("emergingthreats"), "no rule links for a non-numeric SID");

  panel._suricataAlertDetail.signature_id = 2010935;
  assert.ok(panel._suricataAlertDetailModal().includes("rule_docs/2010935"));
});
