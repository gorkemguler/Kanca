import { applySettings, loadSettings, saveSettings, syncAction } from "./lib/browser.js";

// Re-assert the saved state when the browser or extension starts, so the
// proxy and toolbar icon always agree with what the popup shows.
async function restore() {
  await applySettings(await loadSettings());
}

chrome.runtime.onInstalled.addListener(restore);
chrome.runtime.onStartup.addListener(restore);

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "toggle-proxy") return;
  const s = await loadSettings();
  s.enabled = !s.enabled;
  await saveSettings(s);
  await applySettings(s);
});

// If the proxy can't be reached, flag it on the toolbar instead of failing
// silently; the popup explains what's wrong.
chrome.proxy.onProxyError.addListener(async () => {
  const s = await loadSettings();
  if (!s.enabled) return;
  await chrome.action.setBadgeBackgroundColor({ color: "#e05561" });
  await chrome.action.setBadgeText({ text: "ERR" });
});

// Clear an error badge once the user reopens or retoggles.
chrome.storage.onChanged.addListener(async (changes) => {
  if (changes.settings) await syncAction(Boolean(changes.settings.newValue?.enabled));
});
