const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "cryptowarden-browser-"));
const configuration = path.join(directory, "config.yaml");
fs.writeFileSync(configuration, JSON.stringify({
  monitoring: { directories: [directory] },
  storage: { directory: path.join(directory, "runtime") },
  dashboard: { port: 18765 },
}));
const localPython = process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python";
const python = process.env.CRYPTOWARDEN_TEST_PYTHON || (fs.existsSync(localPython) ? localPython : "python");
const child = spawn(python, ["-m", "src.main", "demo", "--config", configuration], {
  stdio: "inherit",
  env: { ...process.env, USERPROFILE: process.env.USERPROFILE || os.homedir(), CRYPTOWARDEN_DASHBOARD_TOKEN: "browser-test-key-never-use-in-production-12345" },
  windowsHide: true,
});
child.on("exit", code => process.exit(code || 0));
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => {
  child.kill("SIGTERM");
});
// Unique temporary demo directory contains only test-owned artifacts.
process.on("exit", () => {
  const resolved = path.resolve(directory);
  if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith("cryptowarden-browser-")) return;
  try { fs.rmSync(resolved, { recursive: true, force: true }); } catch {}
});
