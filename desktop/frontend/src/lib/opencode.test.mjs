// Unit tests for the Opencode helpers, run with Node's built-in test runner
// (`npm test`). Node strips the TypeScript types from opencode.ts itself, so
// no test framework is needed.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildOpencodeLocal,
  buildOpencodeRemote,
  hideToken,
  OPENCODE_DEBUG_CMD,
  OPENCODE_EXPORT_CMD,
  OPENCODE_EXPORT_WIN_CMD,
  OPENCODE_LIST_CMD,
  resolveOpencodeExport,
  resolveOpencodeExportWin,
  resolveOpencodeLocal,
  resolveOpencodeRemote,
  usesEnvPlaceholder,
} from "./opencode.ts";

const HEX_SECRET = /[0-9a-f]{32,}/;

describe("buildOpencodeRemote", () => {
  it("mirrors the Claude HTTP endpoint with env placeholder and oauth:false", () => {
    const url = "http://127.0.0.1:8765/mcp";
    const cfg = buildOpencodeRemote(url);
    assert.equal(cfg.$schema, "https://opencode.ai/config.json");
    assert.equal(cfg.mcp.kanca.type, "remote");
    assert.equal(cfg.mcp.kanca.url, url);
    assert.equal(cfg.mcp.kanca.headers.Authorization, "Bearer {env:KANCA_MCP_TOKEN}");
    assert.equal(cfg.mcp.kanca.oauth, false);
    assert.equal(cfg.mcp.kanca.enabled, true);
  });

  it("serialises to JSON with mcp.kanca and never embeds a real token", () => {
    const raw = JSON.stringify(buildOpencodeRemote("http://127.0.0.1:8765/mcp"));
    assert.ok(raw.includes('"kanca"'));
    assert.equal(usesEnvPlaceholder(raw), true);
    // A 64-hex bearer must not appear in the checked-in snippet shape.
    assert.equal(HEX_SECRET.test(raw), false);
  });
});

describe("buildOpencodeLocal", () => {
  it("uses a single command array ending in mcp-stdio", () => {
    const cfg = buildOpencodeLocal("/usr/local/bin/kanca");
    assert.equal(cfg.mcp.kanca.type, "local");
    assert.deepEqual(cfg.mcp.kanca.command, ["/usr/local/bin/kanca", "mcp-stdio"]);
    assert.equal(cfg.mcp.kanca.enabled, true);
  });

  it("falls back to PATH binary when exe is empty", () => {
    assert.deepEqual(buildOpencodeLocal("").mcp.kanca.command, ["kanca", "mcp-stdio"]);
  });
});

describe("hideToken", () => {
  it("shortens a 64-hex bearer for display but keeps head/tail", () => {
    const token = "a".repeat(60) + "1234";
    const cmd = `claude mcp add --transport http kanca http://127.0.0.1:8765/mcp --header "Authorization: Bearer ${token}"`;
    const shown = hideToken(cmd);
    assert.ok(!shown.includes(token));
    assert.ok(shown.includes("Bearer aaaaaa…1234"));
  });

  it("also masks a long non-hex bearer (format-proof)", () => {
    const token = "x".repeat(40) + "!@#$".repeat(6);
    const shown = hideToken(`cmd --header "Authorization: Bearer ${token}"`);
    assert.ok(!shown.includes(token));
    assert.ok(shown.includes("…"));
  });

  it("leaves commands without a bearer untouched", () => {
    assert.equal(hideToken("opencode mcp list"), "opencode mcp list");
  });
});

describe("opencode command constants", () => {
  it("exports the token without printing it and documents verify cmds", () => {
    assert.ok(OPENCODE_EXPORT_CMD.includes("KANCA_MCP_TOKEN"));
    assert.ok(OPENCODE_EXPORT_CMD.includes("jq -r .token"));
    assert.equal(OPENCODE_LIST_CMD, "opencode mcp list");
    assert.equal(OPENCODE_DEBUG_CMD, "opencode mcp debug kanca");
  });

  it("rejects wrong placeholder shapes", () => {
    assert.equal(usesEnvPlaceholder(JSON.stringify(buildOpencodeRemote("http://127.0.0.1:8765/mcp"))), true);
    assert.equal(usesEnvPlaceholder('{"Authorization":"Bearer $KANCA_MCP_TOKEN"}'), false);
    assert.equal(usesEnvPlaceholder('{"Authorization":"Bearer ${KANCA_MCP_TOKEN}"}'), false);
  });

  it("does not mask a non-hex/short token (documents hideToken limit)", () => {
    const cmd = `claude mcp add --transport http kanca http://127.0.0.1:8765/mcp --header "Authorization: Bearer SHORT"`;
    assert.equal(hideToken(cmd), cmd);
  });
});

describe("edge cases", () => {
  it("buildOpencodeRemote keeps an empty url (key present, valid JSON)", () => {
    const cfg = buildOpencodeRemote("");
    assert.equal(cfg.mcp.kanca.url, "");
    assert.doesNotThrow(() => JSON.stringify(cfg));
  });

  it("buildOpencodeLocal preserves unicode exe paths", () => {
    const exe = "/yol/kanca üñï";
    assert.deepEqual(buildOpencodeLocal(exe).mcp.kanca.command, [exe, "mcp-stdio"]);
  });
});

describe("resolvers (old-backend fallback)", () => {
  it("prefers the stored backend value when present", () => {
    assert.equal(resolveOpencodeRemote("STORED", "http://x"), "STORED");
    assert.equal(resolveOpencodeLocal("STORED"), "STORED");
    assert.equal(resolveOpencodeExport("STORED"), "STORED");
    assert.equal(resolveOpencodeExportWin("STORED"), "STORED");
  });

  it("builds a copyable fallback when the backend field is missing", () => {
    const url = "http://127.0.0.1:8765/mcp";
    const remote = resolveOpencodeRemote(undefined, url);
    assert.equal(usesEnvPlaceholder(remote), true);
    assert.equal(JSON.parse(remote).mcp.kanca.url, url);
    assert.deepEqual(JSON.parse(resolveOpencodeLocal(undefined)).mcp.kanca.command, ["kanca", "mcp-stdio"]);
    assert.equal(resolveOpencodeExport(undefined), OPENCODE_EXPORT_CMD);
    assert.equal(resolveOpencodeExportWin(undefined), OPENCODE_EXPORT_WIN_CMD);
  });

  it("treats empty string like missing", () => {
    assert.ok(resolveOpencodeRemote("", "http://x").includes("http://x"));
    assert.equal(resolveOpencodeExport(""), OPENCODE_EXPORT_CMD);
  });

  it("windows export needs no jq and carries no secret", () => {
    assert.ok(OPENCODE_EXPORT_WIN_CMD.includes("$env:KANCA_MCP_TOKEN"));
    assert.ok(!OPENCODE_EXPORT_WIN_CMD.includes("jq"));
    assert.equal(HEX_SECRET.test(OPENCODE_EXPORT_WIN_CMD), false);
  });
});
