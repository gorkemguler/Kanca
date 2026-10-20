// Pure, DOM-free helpers for the Opencode integration, unit-tested with
// Node's built-in test runner (opencode.test.mjs), no Wails runtime needed.

/** Token export command: fills KANCA_MCP_TOKEN without printing the secret. */
export const OPENCODE_EXPORT_CMD =
  `export KANCA_MCP_TOKEN="$(jq -r .token ~/.kanca/mcp.json)"`;

/** Same for Windows PowerShell (no jq or ~ expansion there). */
export const OPENCODE_EXPORT_WIN_CMD =
  `$env:KANCA_MCP_TOKEN = (Get-Content $HOME/.kanca/mcp.json | ConvertFrom-Json).token`;

/** Verify commands shown next to the Opencode cards. */
export const OPENCODE_LIST_CMD = "opencode mcp list";
export const OPENCODE_DEBUG_CMD = "opencode mcp debug kanca";

export interface OpencodeRemoteEntry {
  $schema: string;
  mcp: {
    kanca: {
      type: "remote";
      url: string;
      headers: { Authorization: string };
      oauth: false;
      enabled: boolean;
    };
  };
}

export interface OpencodeLocalEntry {
  $schema: string;
  mcp: {
    kanca: {
      type: "local";
      command: string[];
      enabled: boolean;
    };
  };
}

/** Mirrors desktop/ai.go opencodeRemoteEntry: secret stays out via {env:...}. */
export function buildOpencodeRemote(url: string): OpencodeRemoteEntry {
  return {
    $schema: "https://opencode.ai/config.json",
    mcp: {
      kanca: {
        type: "remote",
        url,
        headers: { Authorization: "Bearer {env:KANCA_MCP_TOKEN}" },
        oauth: false,
        enabled: true,
      },
    },
  };
}

/** Mirrors desktop/ai.go opencodeLocalEntry: command is one array. */
export function buildOpencodeLocal(exe: string): OpencodeLocalEntry {
  return {
    $schema: "https://opencode.ai/config.json",
    mcp: {
      kanca: {
        type: "local",
        command: [exe || "kanca", "mcp-stdio"],
        enabled: true,
      },
    },
  };
}

/** Shortens a Bearer token for display (screenshots get shared).
 * Matches any long bearer (>=11 chars, quotes excluded so the surrounding
 * `"..."` stays intact), not just hex, so a future token format stays masked.
 * Short values pass through untouched. */
export function hideToken(cmd: string): string {
  return cmd.replace(/(Bearer [^\s"]{6})[^\s"]+([^\s"]{4})/, "$1…$2");
}

/** True when an opencode.json remote snippet uses the env placeholder. */
export function usesEnvPlaceholder(snippet: string): boolean {
  return snippet.includes("{env:KANCA_MCP_TOKEN}");
}

/** Resolve the remote snippet: backend value wins, else build it locally so
 * old backends (without opencode* fields) still yield a copyable config
 * instead of "undefined". */
export function resolveOpencodeRemote(
  stored: string | undefined,
  url: string,
): string {
  return stored || JSON.stringify(buildOpencodeRemote(url), null, 2);
}

/** Same for the local/stdio snippet. */
export function resolveOpencodeLocal(
  stored: string | undefined,
  exe = "kanca",
): string {
  return stored || JSON.stringify(buildOpencodeLocal(exe), null, 2);
}

/** Same for the POSIX token-export command. */
export function resolveOpencodeExport(stored: string | undefined): string {
  return stored || OPENCODE_EXPORT_CMD;
}

/** Same for the Windows PowerShell token-export command. */
export function resolveOpencodeExportWin(stored: string | undefined): string {
  return stored || OPENCODE_EXPORT_WIN_CMD;
}
