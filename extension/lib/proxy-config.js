// Pure helpers shared by the popup and the background worker. No browser APIs
// here, so the logic can be unit-tested with plain Node.

export const DEFAULTS = Object.freeze({
  enabled: false,
  host: "127.0.0.1",
  port: 8080,
  includeLocalhost: false,
  bypass: [],
});

// The proxy answers http://kanca/ itself (status page, CA download).
export const BUILTIN_ORIGIN = "http://kanca";

export function normalizeSettings(raw) {
  const s = { ...DEFAULTS, ...(raw || {}) };
  return {
    enabled: Boolean(s.enabled),
    host: String(s.host ?? DEFAULTS.host).trim() || DEFAULTS.host,
    port: Number.parseInt(s.port, 10) || DEFAULTS.port,
    includeLocalhost: Boolean(s.includeLocalhost),
    bypass: Array.isArray(s.bypass) ? parseBypass(s.bypass.join("\n")) : [],
  };
}

// parseBypass turns free text (one entry per line or comma-separated) into a
// clean, de-duplicated list of bypass rules.
export function parseBypass(text) {
  const seen = new Set();
  const out = [];
  for (const part of String(text || "").split(/[\n,]/)) {
    const entry = part.trim();
    if (entry && !seen.has(entry)) {
      seen.add(entry);
      out.push(entry);
    }
  }
  return out;
}

// validate returns an error message, or "" when the settings are usable.
export function validate(s) {
  if (!s.host || /[\s/]/.test(s.host) || s.host.includes("://")) {
    return "Host must be a bare hostname or IP, e.g. 127.0.0.1";
  }
  if (!Number.isInteger(s.port) || s.port < 1 || s.port > 65535) {
    return "Port must be a number between 1 and 65535";
  }
  return "";
}

// buildProxyValue renders settings into a chrome.proxy "fixed_servers" config.
// Chromium never proxies loopback addresses by default; the special
// "<-loopback>" rule removes that implicit bypass so local targets are captured.
export function buildProxyValue(s) {
  const bypassList = [...s.bypass];
  if (s.includeLocalhost) bypassList.push("<-loopback>");
  return {
    mode: "fixed_servers",
    rules: {
      singleProxy: { scheme: "http", host: s.host, port: s.port },
      bypassList,
    },
  };
}

// hostForUrl brackets bare IPv6 literals so they can sit in a URL.
export function hostForUrl(host) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

// kancaOrigin is where Kanca's own pages are reachable: through the proxy via
// the http://kanca name when routing is on, otherwise directly on the listener.
export function kancaOrigin(s) {
  return s.enabled ? BUILTIN_ORIGIN : `http://${hostForUrl(s.host)}:${s.port}`;
}

// describeStatus maps a probe of {kancaOrigin}/status to what the popup shows.
// probe is null when the request failed, else the parsed JSON body.
export function describeStatus(s, probe) {
  const addr = `${s.host}:${s.port}`;
  if (s.enabled) {
    if (probe && probe.kanca && probe.proxied) {
      return { level: "ok", text: "Connected — this browser's traffic flows through Kanca." };
    }
    return {
      level: "err",
      text: `Routing is on, but Kanca isn't answering on ${addr}. Start Kanca and press "Start proxy".`,
    };
  }
  if (probe && probe.kanca) {
    return { level: "idle", text: `Kanca is running on ${addr}. Switch on to route this browser through it.` };
  }
  return { level: "off", text: "Off — the browser connects directly." };
}
