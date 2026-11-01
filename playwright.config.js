const { defineConfig } = require("@playwright/test");
module.exports = defineConfig({
  testDir: "./tests/browser",
  timeout: 20000,
  workers: 1,
  reporter: [["list"], ["json", { outputFile: "audit/evidence/management-browser-results.json" }]],
  use: {
    baseURL: "http://127.0.0.1:18765",
    browserName: "chromium",
    channel: process.platform === "win32" ? "msedge" : undefined,
    viewport: { width: 1440, height: 1000 },
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node tests/browser/server.cjs",
    url: "http://127.0.0.1:18765/",
    timeout: 20000,
    reuseExistingServer: false
  }
});
