import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  testMatch: /.*\.spec\.mjs/,
  timeout: 30_000,
  fullyParallel: true,
  reporter: [["list"]],
  snapshotPathTemplate: "{testDir}/__screenshots__/{arg}{ext}",
  expect: {
    // Text antialiasing differs slightly between runs; layout changes do not hide in 1 %.
    toHaveScreenshot: { maxDiffPixelRatio: 0.01, animations: "disabled", caret: "hide" },
  },
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1400, height: 1000 },
    deviceScaleFactor: 1,
    timezoneId: "UTC",
    locale: "en-US",
  },
  webServer: {
    command: "node tests/server.mjs",
    url: "http://127.0.0.1:4173/tests/harness.html",
    reuseExistingServer: !process.env.CI,
  },
});
