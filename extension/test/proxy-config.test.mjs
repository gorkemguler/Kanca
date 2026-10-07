import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULTS,
  buildProxyValue,
  describeStatus,
  kancaOrigin,
  normalizeSettings,
  parseBypass,
  validate,
} from "../lib/proxy-config.js";

test("normalizeSettings fills defaults and coerces types", () => {
  assert.deepEqual(normalizeSettings(undefined), { ...DEFAULTS, bypass: [] });
  const s = normalizeSettings({ enabled: 1, host: "  10.0.0.2 ", port: "9090", bypass: ["a", "a", " b "] });
  assert.equal(s.enabled, true);
  assert.equal(s.host, "10.0.0.2");
  assert.equal(s.port, 9090);
  assert.deepEqual(s.bypass, ["a", "b"]);
});

test("parseBypass accepts newlines and commas, trims and de-duplicates", () => {
  assert.deepEqual(parseBypass("*.google.com\n\n updates.example.com ,*.google.com"), [
    "*.google.com",
    "updates.example.com",
  ]);
});

test("validate rejects schemes, paths, spaces and bad ports", () => {
  const ok = normalizeSettings({});
  assert.equal(validate(ok), "");
  assert.match(validate({ ...ok, host: "http://127.0.0.1" }), /bare hostname/);
  assert.match(validate({ ...ok, host: "127.0.0.1/x" }), /bare hostname/);
  assert.match(validate({ ...ok, host: "my host" }), /bare hostname/);
  assert.match(validate({ ...ok, port: 0 }), /Port/);
  assert.match(validate({ ...ok, port: 70000 }), /Port/);
  assert.match(validate({ ...ok, port: Number.NaN }), /Port/);
});

test("buildProxyValue routes through a single HTTP proxy", () => {
  const v = buildProxyValue(normalizeSettings({ host: "127.0.0.1", port: 8080, bypass: ["*.google.com"] }));
  assert.deepEqual(v, {
    mode: "fixed_servers",
    rules: {
      singleProxy: { scheme: "http", host: "127.0.0.1", port: 8080 },
      bypassList: ["*.google.com"],
    },
  });
});

test("includeLocalhost removes Chromium's implicit loopback bypass", () => {
  const v = buildProxyValue(normalizeSettings({ includeLocalhost: true }));
  assert.deepEqual(v.rules.bypassList, ["<-loopback>"]);
});

test("kancaOrigin uses http://kanca when routing, the listener otherwise", () => {
  assert.equal(kancaOrigin(normalizeSettings({ enabled: true })), "http://kanca");
  assert.equal(kancaOrigin(normalizeSettings({ port: 8081 })), "http://127.0.0.1:8081");
  assert.equal(kancaOrigin(normalizeSettings({ host: "::1" })), "http://[::1]:8080");
});

test("describeStatus covers connected, unreachable, idle and off", () => {
  const on = normalizeSettings({ enabled: true });
  const off = normalizeSettings({});
  assert.equal(describeStatus(on, { kanca: true, proxied: true }).level, "ok");
  assert.equal(describeStatus(on, null).level, "err");
  assert.equal(describeStatus(on, { kanca: true, proxied: false }).level, "err");
  assert.equal(describeStatus(off, { kanca: true, proxied: false }).level, "idle");
  assert.equal(describeStatus(off, null).level, "off");
});
