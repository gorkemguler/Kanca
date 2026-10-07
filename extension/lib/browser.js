// Browser-facing operations (chrome.* APIs) shared by the popup and background.
import { buildProxyValue, kancaOrigin, normalizeSettings } from "./proxy-config.js";

const ICONS = {
  on: { 16: "icons/on-16.png", 32: "icons/on-32.png" },
  off: { 16: "icons/off-16.png", 32: "icons/off-32.png" },
};

export async function loadSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return normalizeSettings(settings);
}

export async function saveSettings(s) {
  await chrome.storage.local.set({ settings: s });
}

// applySettings makes the browser's proxy match s and updates the toolbar.
export async function applySettings(s) {
  if (s.enabled) {
    await chrome.proxy.settings.set({ value: buildProxyValue(s), scope: "regular" });
  } else {
    await chrome.proxy.settings.clear({ scope: "regular" });
  }
  await syncAction(s.enabled);
}

export async function syncAction(enabled) {
  await chrome.action.setIcon({ path: enabled ? ICONS.on : ICONS.off });
  await chrome.action.setBadgeBackgroundColor({ color: "#e8792b" });
  await chrome.action.setBadgeText({ text: enabled ? "ON" : "" });
  await chrome.action.setTitle({
    title: enabled ? "Kanca: this browser is routed through Kanca" : "Kanca: off",
  });
}

// controlLevel reports who controls the browser proxy. Another extension (e.g. a
// VPN or proxy switcher) or an enterprise policy can override ours.
export async function controlLevel() {
  const details = await chrome.proxy.settings.get({});
  return details.levelOfControl;
}

// probeStatus asks Kanca whether it is reachable (and, when routing is on,
// whether this browser's traffic actually reaches it). Returns the JSON body or
// null on any failure.
export async function probeStatus(s, timeoutMs = 1500) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(`${kancaOrigin(s)}/status`, { signal: ctrl.signal, cache: "no-store" });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
