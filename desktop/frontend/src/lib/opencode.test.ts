import { describe, expect, it } from "vitest";
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
} from "./opencode";

describe("buildOpencodeRemote", () => {
  it("mirrors the Claude HTTP endpoint with env placeholder and oauth:false", () => {
    const url = "http://127.0.0.1:8765/mcp";
    const cfg = buildOpencodeRemote(url);
    expect(cfg.$schema).toBe("https://opencode.ai/config.json");
    expect(cfg.mcp.kanca.type).toBe("remote");
    expect(cfg.mcp.kanca.url).toBe(url);
    expect(cfg.mcp.kanca.headers.Authorization).toBe(
      "Bearer {env:KANCA_MCP_TOKEN}",
    );
    expect(cfg.mcp.kanca.oauth).toBe(false);
    expect(cfg.mcp.kanca.enabled).toBe(true);
  });

  it("serialises to JSON with mcp.kanca and never embeds a real token", () => {
    const raw = JSON.stringify(buildOpencodeRemote("http://127.0.0.1:8765/mcp"));
    expect(raw).toContain('"kanca"');
    expect(usesEnvPlaceholder(raw)).toBe(true);
    // A 64-hex bearer must not appear in the checked-in snippet shape.
    expect(/[0-9a-f]{32,}/.test(raw)).toBe(false);
  });
});

describe("buildOpencodeLocal", () => {
  it("uses a single command array ending in mcp-stdio", () => {
    const cfg = buildOpencodeLocal("/usr/local/bin/kanca");
    expect(cfg.mcp.kanca.type).toBe("local");
    expect(cfg.mcp.kanca.command).toEqual([
      "/usr/local/bin/kanca",
      "mcp-stdio",
    ]);
    expect(cfg.mcp.kanca.enabled).toBe(true);
  });

  it("falls back to PATH binary when exe is empty", () => {
    expect(buildOpencodeLocal("").mcp.kanca.command).toEqual([
      "kanca",
      "mcp-stdio",
    ]);
  });
});

describe("hideToken", () => {
  it("shortens a 64-hex bearer for display but keeps head/tail", () => {
    const token = "a".repeat(60) + "1234";
    const cmd = `claude mcp add --transport http kanca http://127.0.0.1:8765/mcp --header "Authorization: Bearer ${token}"`;
    const shown = hideToken(cmd);
    expect(shown).not.toContain(token);
    expect(shown).toContain("Bearer aaaaaa…1234");
  });

  it("also masks a long non-hex bearer (format-proof)", () => {
    const token = "x".repeat(40) + "!@#$".repeat(6);
    const cmd = `cmd --header "Authorization: Bearer ${token}"`;
    const shown = hideToken(cmd);
    expect(shown).not.toContain(token);
    expect(shown).toContain("…");
  });

  it("leaves commands without a bearer untouched", () => {
    const cmd = "opencode mcp list";
    expect(hideToken(cmd)).toBe(cmd);
  });
});

describe("opencode command constants", () => {
  it("exports the token without printing it and documents verify cmds", () => {
    expect(OPENCODE_EXPORT_CMD).toContain("KANCA_MCP_TOKEN");
    expect(OPENCODE_EXPORT_CMD).toContain("jq -r .token");
    expect(OPENCODE_LIST_CMD).toBe("opencode mcp list");
    expect(OPENCODE_DEBUG_CMD).toBe("opencode mcp debug kanca");
  });

  it("rejects wrong placeholder shapes", () => {
    expect(
      usesEnvPlaceholder(
        JSON.stringify(buildOpencodeRemote("http://127.0.0.1:8765/mcp")),
      ),
    ).toBe(true);
    expect(
      usesEnvPlaceholder('{"Authorization":"Bearer $KANCA_MCP_TOKEN"}'),
    ).toBe(false);
    expect(
      usesEnvPlaceholder('{"Authorization":"Bearer ${KANCA_MCP_TOKEN}"}'),
    ).toBe(false);
  });

  it("does not mask a non-hex/short token (documents hideToken limit)", () => {
    const cmd = `claude mcp add --transport http kanca http://127.0.0.1:8765/mcp --header "Authorization: Bearer SHORT"`;
    expect(hideToken(cmd)).toBe(cmd);
  });
});

describe("edge cases", () => {
  it("buildOpencodeRemote keeps an empty url (key present, valid JSON)", () => {
    const cfg = buildOpencodeRemote("");
    expect(cfg.mcp.kanca.url).toBe("");
    expect(() => JSON.stringify(cfg)).not.toThrow();
  });

  it("buildOpencodeLocal preserves unicode exe paths", () => {
    const exe = "/yol/kanca üñï";
    expect(buildOpencodeLocal(exe).mcp.kanca.command).toEqual([
      exe,
      "mcp-stdio",
    ]);
  });
});

describe("resolvers (old-backend fallback)", () => {
  it("prefers the stored backend value when present", () => {
    expect(resolveOpencodeRemote("STORED", "http://x")).toBe("STORED");
    expect(resolveOpencodeLocal("STORED")).toBe("STORED");
    expect(resolveOpencodeExport("STORED")).toBe("STORED");
    expect(resolveOpencodeExportWin("STORED")).toBe("STORED");
  });

  it("builds a copyable fallback when the backend field is missing", () => {
    const url = "http://127.0.0.1:8765/mcp";
    const remote = resolveOpencodeRemote(undefined, url);
    expect(usesEnvPlaceholder(remote)).toBe(true);
    expect(JSON.parse(remote).mcp.kanca.url).toBe(url);
    const local = resolveOpencodeLocal(undefined);
    expect(JSON.parse(local).mcp.kanca.command).toEqual([
      "kanca",
      "mcp-stdio",
    ]);
    expect(resolveOpencodeExport(undefined)).toBe(OPENCODE_EXPORT_CMD);
    expect(resolveOpencodeExportWin(undefined)).toBe(OPENCODE_EXPORT_WIN_CMD);
  });

  it("treats empty string like missing", () => {
    expect(resolveOpencodeRemote("", "http://x")).toContain("http://x");
    expect(resolveOpencodeExport("")).toBe(OPENCODE_EXPORT_CMD);
  });

  it("windows export needs no jq and carries no secret", () => {
    expect(OPENCODE_EXPORT_WIN_CMD).toContain("$env:KANCA_MCP_TOKEN");
    expect(OPENCODE_EXPORT_WIN_CMD).not.toContain("jq");
    expect(/[0-9a-f]{32,}/.test(OPENCODE_EXPORT_WIN_CMD)).toBe(false);
  });
});
