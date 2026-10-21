// Browser regression tests for the Security Assistant panel.
//
// The panel is rendered in Chromium against fixtures generated from the real
// backend (tests/fixtures/generate_fixture.py). Every view and the main
// interactions are exercised, and each state is checked for:
//   - page / console errors,
//   - script injected through hostile fixture strings actually running,
//   - raw markup or double-escaped entities leaking into visible text,
//   - visual changes (screenshots taken from the reviewed baseline).
import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

const fixtures = JSON.parse(readFileSync(new URL("./fixtures/api.json", import.meta.url)));
const XSS_TEXT = '<img src=x onerror="window.__xss=1">';
const PANEL = process.env.PANEL_URL || "/panel/homesec-panel.js";

async function openPanel(page, { lang = "en", view = null } = {}) {
  const errors = [];
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(`console: ${msg.text()}`);
  });
  // Freeze time at fixture generation so "x minutes ago" texts are stable,
  // and make Math.random deterministic (map layout and particles).
  await page.clock.install({ time: new Date(fixtures.generated_at) });
  await page.addInitScript(() => {
    let seed = 42;
    Math.random = () => {
      seed = (seed * 16807) % 2147483647;
      return (seed - 1) / 2147483646;
    };
  });
  await page.goto(`/tests/harness.html?lang=${lang}&panel=${encodeURIComponent(PANEL)}`);
  const panel = page.locator("homesec-panel");
  await expect(panel.locator(".nav-item").first()).toBeVisible();
  await expect(panel.locator(".loader")).toHaveCount(0);
  if (view) await goTo(page, view);
  return { panel, errors };
}

async function goTo(page, view) {
  const panel = page.locator("homesec-panel");
  await panel.locator(`.nav-item[data-view="${view}"]`).click();
  await expect(panel.locator(`.nav-item.active[data-view="${view}"]`)).toBeVisible();
}

async function checkClean(page, errors) {
  expect(errors, "page errors").toEqual([]);
  expect(await page.evaluate(() => window.__xss), "injected script ran").toBeUndefined();
  const text = await page.locator("homesec-panel").evaluate((el) => el.shadowRoot.querySelector(".app").innerText);
  const visible = text.split(XSS_TEXT).join("").split('<img src=x onerror="window.__xss=1"').join("");
  expect(visible, "raw markup visible as text").not.toMatch(/<\/?(div|span|td|tr|th|table|svg|path|button|a|img|b|strong|li|ul|input|select|option|h\d|p|br)\b[^>]*>/i);
  expect(visible, "double-escaped entities visible").not.toMatch(/&(lt|gt|amp|quot|#39);/);
  expect(visible, "template objects rendered as text").not.toContain("[object Object]");
}

// Normalised DOM: tags, sorted attributes and whitespace-collapsed text,
// ignoring Lit's comment markers. Independent of fonts and platform.
async function domSnapshot(page) {
  return page.locator("homesec-panel").evaluate((el) => {
    const out = [];
    const walk = (node, depth) => {
      let text = "";
      const flush = () => {
        const t = text.replace(/\s+/g, " ");
        if (t.trim()) out.push("  ".repeat(depth) + "#" + t);
        text = "";
      };
      for (const c of node.childNodes) {
        if (c.nodeType === 8) continue;
        if (c.nodeType === 3) { text += c.textContent; continue; }
        if (c.nodeType !== 1 || c.tagName === "STYLE") continue;
        flush();
        // Inline styles use the browser's canonical form: Playwright's caret
        // hiding rewrites (or empties) the style of a focused input.
        const attrs = [...c.attributes]
          .map((a) => [a.name, a.name === "style" ? c.style.cssText : a.value])
          .filter(([name, value]) => !(name === "style" && !value.trim()))
          .map(([name, value]) => `${name}=${value.replace(/\s+/g, " ").trim()}`)
          .sort()
          .join(" ");
        out.push("  ".repeat(depth) + "<" + c.tagName.toLowerCase() + (attrs ? " " + attrs : "") + ">");
        walk(c, depth + 1);
      }
      flush();
    };
    walk(el.shadowRoot.querySelector(".app"), 0);
    return out.join("\n") + "\n";
  });
}

async function snap(page, name) {
  expect(await domSnapshot(page)).toMatchSnapshot(`${name}.dom.txt`);
  // Pixel comparison depends on installed fonts: run it where the baselines
  // were made (developer machines), skip it on CI runners.
  if (process.env.SKIP_SCREENSHOTS) return;
  await page.evaluate(() => document.fonts && document.fonts.ready);
  await expect(page.locator("homesec-panel")).toHaveScreenshot(`${name}.png`, { fullPage: false });
}

const SIMPLE_VIEWS = ["overview", "hosts", "findings", "external", "vulnerabilities", "statistics", "dns", "suricata", "recommendations"];

for (const view of SIMPLE_VIEWS) {
  test(`view ${view}`, async ({ page }) => {
    const { errors } = await openPanel(page, { view });
    if (view === "vulnerabilities") {
      await expect(page.locator("homesec-panel").locator("[data-vuln-detail]").first()).toBeVisible();
    }
    await checkClean(page, errors);
    await snap(page, `view-${view}`);
  });
}

test("view map renders a canvas", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "map" });
  await expect(panel.locator("canvas")).toBeVisible();
  for (const mode of ["baseline", "compare", "live"]) {
    const button = panel.locator(`[data-mapmode="${mode}"]`);
    if (await button.count()) await button.first().click();
  }
  const filters = panel.locator("[data-mapfilter]");
  for (let i = 0; i < (await filters.count()); i++) await filters.nth(i).click();
  await checkClean(page, errors);
});

test("map: dragging a host pulls its linked hosts along", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "map" });
  await expect(panel.locator("canvas")).toBeVisible();
  await page.waitForTimeout(1500); // let the layout run
  const start = await page.evaluate(() => {
    const p = window.__panel;
    const links = new Map();
    for (const e of p._mapEdges) {
      links.set(e.source, [...(links.get(e.source) || []), e.target]);
      links.set(e.target, [...(links.get(e.target) || []), e.source]);
    }
    const node = [...p._mapNodes.values()]
      .filter((n) => n.type === "internal" && links.has(n.ip))
      .sort((a, b) => links.get(b.ip).length - links.get(a.ip).length)[0];
    const neighbour = p._mapNodes.get(links.get(node.ip)[0]);
    const rect = p.shadowRoot.getElementById("hsa-map-canvas").getBoundingClientRect();
    return {
      ip: node.ip,
      neighbour: neighbour.ip,
      neighbourAt: [neighbour.x, neighbour.y],
      x: rect.left + p._mapPanX + node.x * p._mapZoom,
      y: rect.top + p._mapPanY + node.y * p._mapZoom,
      pan: [p._mapPanX, p._mapPanY],
    };
  });
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  for (let i = 1; i <= 20; i++) {
    await page.mouse.move(start.x - i * 10, start.y - i * 4);
    await page.waitForTimeout(16);
  }
  await page.waitForTimeout(500);
  const held = await page.evaluate(({ ip, neighbour }) => {
    const p = window.__panel;
    const n = p._mapNodes.get(ip), m = p._mapNodes.get(neighbour);
    return { dragging: !!p._mapDrag, at: [n.x, n.y], neighbourAt: [m.x, m.y], pan: [p._mapPanX, p._mapPanY], zoom: p._mapZoom };
  }, start);
  expect(held.dragging).toBe(true);
  expect(held.pan).toEqual(start.pan); // dragging a node does not pan the map
  const zoom = held.zoom;
  const moved = Math.hypot(held.neighbourAt[0] - start.neighbourAt[0], held.neighbourAt[1] - start.neighbourAt[1]);
  expect(moved).toBeGreaterThan(20 / zoom); // the linked host followed
  await page.mouse.up();
  expect(await page.evaluate(() => window.__panel._mapDrag)).toBeNull();
  await expect(panel.locator("#hsa-mobile-title")).toHaveText("Network Map"); // no lookup opened
  await checkClean(page, errors);
});

test("map: zooming out scales the layout to fill the screen", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "map" });
  await expect(panel.locator("canvas")).toBeVisible();
  // Past the energetic start-up phase, so the layout is no longer growing
  await page.waitForFunction(() => window.__panel._mapTick > 400, null, { timeout: 15000 });
  const width = () =>
    page.evaluate(() => {
      const xs = [...window.__panel._mapNodes.values()].map((n) => n.x);
      return Math.max(...xs) - Math.min(...xs);
    });
  const before = await width();
  await page.evaluate(() => {
    const p = window.__panel;
    const c = p.shadowRoot.getElementById("hsa-map-canvas");
    p._mapZoom = 0.5;
    p._mapPanX = c.width / 4;
    p._mapPanY = c.height / 4;
  });
  await page.waitForTimeout(1000);
  const zoomedOut = await width();
  expect(zoomedOut / before).toBeGreaterThan(1.7);
  expect(zoomedOut / before).toBeLessThan(2.3);
  await page.evaluate(() => {
    const p = window.__panel;
    p._mapZoom = 1;
    p._mapPanX = 0;
    p._mapPanY = 0;
  });
  await page.waitForTimeout(1000);
  const back = await width();
  expect(back / before).toBeGreaterThan(0.8);
  expect(back / before).toBeLessThan(1.25);
  await checkClean(page, errors);
});

test("hosts: expand a row and open the rename editor", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "hosts" });
  await panel.locator('tr.expandable[data-ip="192.168.1.10"]').click();
  await expect(panel.locator(".host-detail-wrap").first()).toBeVisible();
  await snap(page, "hosts-expanded");
  await panel.locator('[data-editname="192.168.1.12"]').click();
  await expect(panel.locator("#hsa-editor-modal")).toBeVisible();
  await snap(page, "hosts-rename-modal");
  await panel.locator("#hsa-editor-modal input, #hsa-editor-modal textarea").first().fill("Front door camera");
  await panel.locator("[data-editor-save]").click();
  await expect.poll(() => page.evaluate(() => window.__calls.some((c) => c.path === "homesec/device/name" && c.body.name === "Front door camera"))).toBe(true);
  await checkClean(page, errors);
});

test("findings: group modes, expand a group, dismiss", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "findings" });
  for (const mode of ["host", "severity", "flat", "category"]) {
    await panel.locator(`[data-findings-group-mode="${mode}"]`).click();
    await snap(page, `findings-group-${mode}`);
  }
  await panel.locator("[data-expand-group]").first().click();
  await snap(page, "findings-group-expanded");
  await panel.locator("[data-dismiss]").first().click();
  const editor = panel.locator("#hsa-editor-modal");
  if (await editor.count()) await panel.locator("[data-editor-save]").click();
  await expect.poll(() => page.evaluate(() => window.__calls.some((c) => c.path === "homesec/findings/dismiss"))).toBe(true);
  await checkClean(page, errors);
});

test("findings: regex dismiss preview", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "findings" });
  await panel.locator("[data-regex-dismiss-open]").first().click();
  await expect(panel.locator("#hsa-regex-dismiss-modal")).toBeVisible();
  await panel.locator("#hsa-regex-dismiss-modal input").first().fill("vulnerab");
  await snap(page, "findings-regex-modal");
  await checkClean(page, errors);
});

test("external IPs: detail modal and lookup", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "external" });
  await panel.locator("[data-ext-ip-row]").first().click();
  await expect(panel.locator("#hsa-ext-ip-modal")).toBeVisible();
  await snap(page, "external-ip-modal");
  await panel.locator("[data-ext-close]").first().click();
  await expect(panel.locator("#hsa-ext-ip-modal")).toHaveCount(0);
  await checkClean(page, errors);
});

test("vulnerabilities: detail modal, sort and search", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "vulnerabilities" });
  await panel.locator("[data-vuln-detail]").first().click();
  await expect(panel.locator("#hsa-vuln-modal")).toBeVisible();
  await snap(page, "vulnerability-modal");
  await panel.locator("#hsa-vuln-modal button[data-vuln-close]").first().click();
  await expect(panel.locator("#hsa-vuln-modal")).toHaveCount(0);
  await panel.locator("[data-vulnsort]").first().click();
  const search = panel.locator("[data-vuln-search]").first();
  await search.fill("openssh");
  await search.press("Enter");
  await snap(page, "vulnerabilities-search");
  await checkClean(page, errors);
});

test("statistics: switch charts to list mode", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "statistics" });
  const toggles = panel.locator('[data-statstoggle$=":bar"], [data-statstoggle$=":list"]');
  const count = await toggles.count();
  for (let i = 0; i < count; i++) await toggles.nth(i).click();
  await snap(page, "statistics-list-mode");
  await checkClean(page, errors);
});

test("dns: search, sort and malicious filter", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "dns" });
  const search = panel.locator("#dns-search, input.search-bar").first();
  await search.fill("example");
  await search.press("Enter");
  await panel.locator("[data-dnssort]").first().click();
  await snap(page, "dns-filtered");
  await checkClean(page, errors);
});

test("suricata: alert detail modal escapes hostile signature", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "suricata" });
  await panel.locator("[data-suricata-alert-idx]").first().click();
  await expect(panel.locator("#hsa-suricata-detail-modal")).toBeVisible();
  await snap(page, "suricata-modal");
  await checkClean(page, errors);
});

test("recommendations: expand a card", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "recommendations" });
  await panel.locator("[data-rec-idx]").first().click();
  await snap(page, "recommendations-expanded");
  await checkClean(page, errors);
});

test("settings: edit, save and unsaved-changes guard", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "settings" });
  await expect(panel.locator("#hsa-setting-stats_top_n")).toBeVisible();
  await snap(page, "view-settings");
  await panel.locator("#hsa-setting-stats_top_n").fill("7");
  await panel.locator(".nav-item[data-view=\"overview\"]").click();
  await expect(panel.locator("#hsa-unsaved-modal")).toBeVisible();
  await panel.locator("[data-unsaved-stay]").click();
  await panel.locator("[data-settings-save]").first().click();
  await expect.poll(() => page.evaluate(() => {
    const call = window.__calls.find((c) => c.path === "homesec/settings/save");
    return call && call.body.stats_top_n;
  })).toBe(7);
  await checkClean(page, errors);
});

test("mobile layout and menu", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const { panel, errors } = await openPanel(page);
  await snap(page, "mobile-overview");
  await panel.locator("[data-mobile-menu-toggle]").click();
  await snap(page, "mobile-menu-open");
  await checkClean(page, errors);
});

test("french locale", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { lang: "fr", view: "findings" });
  await expect(panel.locator(".nav-item.active")).toContainText("Constats");
  await snap(page, "fr-findings");
  await checkClean(page, errors);
});

test("hostile values injected client-side render inert", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "suricata" });
  // Bypass the server-side sanitizer: feed a raw hostile record to the modal
  await page.evaluate((xss) => {
    const p = window.__panel;
    p._suricataAlertDetail = {
      timestamp: "2026-10-20T12:00:00Z", src_ip: xss, dest_ip: xss, proto: xss, app_proto: xss,
      signature: xss, signature_id: '"><svg onload=window.__xss=1>', category: xss, severity: 1,
      action: "allowed", in_iface: xss,
    };
    p._render();
  }, XSS_TEXT);
  const modal = panel.locator("#hsa-suricata-detail-modal");
  await expect(modal).toBeVisible();
  await expect(modal.locator("img, svg[onload]")).toHaveCount(0);
  await expect(modal.locator('a[href*="emergingthreats"]')).toHaveCount(0);
  await checkClean(page, errors);
});

test("suricata: search and severity filter", async ({ page }) => {
  const { panel, errors } = await openPanel(page, { view: "suricata" });
  const search = panel.locator("#suricata-search");
  await search.fill("SSH Scan 29");
  await search.press("Enter");
  await expect(panel.locator("[data-suricata-alert-idx]")).toHaveCount(1);
  await search.fill("");
  await search.press("Enter");
  await panel.locator("#suricata-sev-filter").selectOption("1");
  const rows = await panel.locator("[data-suricata-alert-idx]").count();
  expect(rows).toBeGreaterThan(0);
  expect(rows).toBeLessThan(25);
  await checkClean(page, errors);
});

test("live updates: pushed changes re-render, actions request a push", async ({ page }) => {
  const { panel, errors } = await openPanel(page);
  expect(await page.evaluate(() => window.__calls.filter((c) => c.path === "homesec/dashboard").length)).toBe(0);
  await page.evaluate(() => window.__push({ summary: { ...window.__panel._data.summary, devices: 99 } }));
  await expect(panel.locator(".stat-card").first()).toContainText("99");
  await goTo(page, "findings");
  await panel.locator('[data-findings-group-mode="flat"]').click();
  await panel.locator("[data-dismiss]").first().click();
  const editor = panel.locator("#hsa-editor-modal");
  if (await editor.count()) await panel.locator("[data-editor-save]").click();
  await expect.poll(() => page.evaluate(() => window.__calls.some((c) => c.path === "homesec/refresh_dashboard"))).toBe(true);
  // No full HTTP fetch while live
  expect(await page.evaluate(() => window.__calls.filter((c) => c.path === "homesec/dashboard").length)).toBe(0);
  await checkClean(page, errors);
});

test("live updates fall back to polling without a websocket", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  await page.goto(`/tests/harness.html?transport=poll&panel=${encodeURIComponent(PANEL)}`);
  const panel = page.locator("homesec-panel");
  await expect(panel.locator(".nav-item").first()).toBeVisible();
  await expect(panel.locator(".stat-card").first()).toBeVisible();
  expect(await page.evaluate(() => window.__calls.some((c) => c.path === "homesec/dashboard"))).toBe(true);
  expect(errors).toEqual([]);
});

test("state changes in one task are rendered once", async ({ page }) => {
  const { panel, errors } = await openPanel(page);
  const renders = await page.evaluate(async () => {
    const p = window.__panel;
    let count = 0;
    const render = p.render;
    p.render = function () {
      count++;
      return render.call(this);
    };
    p._hostFilter = "192.168";
    p._render();
    p._setView("hosts");
    p._data = { ...p._data };
    p._render();
    await p.updateComplete;
    p.render = render;
    return count;
  });
  expect(renders).toBe(1);
  await expect(panel.locator("#hsa-mobile-title")).toHaveText("Hosts");
  await checkClean(page, errors);
});

test("overview lists configured NVD keywords that are not downloaded yet", async ({ page }) => {
  const { panel, errors } = await openPanel(page);
  await page.evaluate(() =>
    window.__push({
      nvd_keywords: [
        { keyword: "OpenSSH", cve_count: 32, fetched_at: "2026-10-20T11:00:00+00:00", source: "custom", status: "ok" },
        { keyword: "MySQL", cve_count: null, fetched_at: null, source: "custom", status: "fetching" },
        { keyword: "Samba", cve_count: null, fetched_at: null, source: "custom", status: "pending" },
        { keyword: "nginx", cve_count: null, fetched_at: null, source: "custom", status: "failed" },
      ],
    }),
  );
  await expect(panel.locator('[data-kw-state="fetching"]')).toContainText("MySQL");
  await expect(panel.locator('[data-kw-state="pending"]')).toContainText("Samba");
  await expect(panel.locator('[data-kw-state="failed"]')).toHaveAttribute("title", /nginx · download failed/);
  await expect(panel.getByText("OpenSSH (32)")).toBeVisible();
  await checkClean(page, errors);
});
