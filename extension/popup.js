import {
  describeStatus,
  kancaOrigin,
  parseBypass,
  validate,
} from "./lib/proxy-config.js";
import {
  applySettings,
  controlLevel,
  loadSettings,
  probeStatus,
  saveSettings,
} from "./lib/browser.js";

const $ = (id) => document.getElementById(id);
const el = {
  enabled: $("enabled"),
  status: $("status"),
  statusText: $("status-text"),
  conflict: $("conflict"),
  openCert: $("open-cert"),
  settings: $("settings"),
  host: $("host"),
  port: $("port"),
  includeLocalhost: $("includeLocalhost"),
  bypass: $("bypass"),
  error: $("error"),
  shortcut: $("shortcut"),
};

let settings;

function render() {
  el.enabled.checked = settings.enabled;
  el.host.value = settings.host;
  el.port.value = settings.port;
  el.includeLocalhost.checked = settings.includeLocalhost;
  el.bypass.value = settings.bypass.join("\n");
}

function showError(msg) {
  el.error.textContent = msg;
  el.error.hidden = !msg;
  if (msg) el.settings.open = true;
}

async function refreshStatus() {
  let probe = await probeStatus(settings);
  if (!probe && settings.enabled) {
    // A just-applied proxy setting can take a moment to reach new requests.
    await new Promise((r) => setTimeout(r, 500));
    probe = await probeStatus(settings);
  }
  const { level, text } = describeStatus(settings, probe);
  el.status.className = `status ${level}`;
  el.statusText.textContent = text;
}

async function refreshConflict() {
  const level = await controlLevel();
  let msg = "";
  if (level === "controlled_by_other_extensions") {
    msg = "Another extension (e.g. a VPN or proxy switcher) controls the browser proxy, so Kanca can't take effect. Disable it to use Kanca.";
  } else if (level === "not_controllable") {
    msg = "This browser's proxy is managed by policy and can't be changed by extensions.";
  }
  el.conflict.textContent = msg;
  el.conflict.hidden = !msg;
}

// commit validates, persists and applies the current settings.
async function commit() {
  const err = validate(settings);
  showError(err);
  if (err) return false;
  await saveSettings(settings);
  await applySettings(settings);
  await refreshConflict();
  await refreshStatus();
  return true;
}

el.enabled.addEventListener("change", async () => {
  settings.enabled = el.enabled.checked;
  if (!(await commit())) {
    settings.enabled = false;
    el.enabled.checked = false;
  }
});

for (const input of [el.host, el.port, el.includeLocalhost, el.bypass]) {
  input.addEventListener("change", async () => {
    settings.host = el.host.value.trim();
    settings.port = Number.parseInt(el.port.value, 10);
    settings.includeLocalhost = el.includeLocalhost.checked;
    settings.bypass = parseBypass(el.bypass.value);
    el.bypass.value = settings.bypass.join("\n");
    await commit();
  });
}

el.openCert.addEventListener("click", () => {
  chrome.tabs.create({ url: `${kancaOrigin(settings)}/` });
});

async function init() {
  settings = await loadSettings();
  render();
  const cmd = (await chrome.commands.getAll()).find((c) => c.name === "toggle-proxy");
  if (cmd?.shortcut) el.shortcut.textContent = `${cmd.shortcut} toggles`;
  await refreshConflict();
  await refreshStatus();
  // Keep the status fresh while the popup is open (e.g. Kanca gets started).
  setInterval(refreshStatus, 3000);
}

init();
