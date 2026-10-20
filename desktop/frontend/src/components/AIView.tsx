import { useEffect, useState } from "react";
import { api, copyText, on, MCPActivity, MCPLevel, MCPStatus, ScopeConfig } from "../lib/api";
import { hideToken, OPENCODE_DEBUG_CMD, OPENCODE_LIST_CMD, resolveOpencodeExport, resolveOpencodeExportWin, resolveOpencodeLocal, resolveOpencodeRemote } from "../lib/opencode";

const PROMPTS = [
  "Use Kanca to review the traffic I captured and list the most interesting endpoints to test.",
  "Check the API requests in Kanca for IDOR and broken access control, and verify anything you suspect.",
  "Look for injection points (SQLi, XSS, SSTI) in what I browsed and run Kanca's active scan where it makes sense.",
];

interface Props {
  onStatus: (s: MCPStatus) => void;
  onOpenTargets: () => void;
}

type Msg = { ok: boolean; text: string } | null;

// hideToken lives in lib/opencode.ts (unit-tested); re-exported here so
// existing imports keep working.
export { hideToken } from "../lib/opencode";

function errText(e: any): string {
  return String(e?.message ?? e);
}

export default function AIView({ onStatus, onOpenTargets }: Props) {
  const [st, setSt] = useState<MCPStatus | null>(null);
  const [scope, setScope] = useState<ScopeConfig | null>(null);
  const [activity, setActivity] = useState<MCPActivity[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Msg>(null);
  const [desktopMsg, setDesktopMsg] = useState<Msg>(null);
  const [copied, setCopied] = useState("");

  const apply = (s: MCPStatus) => {
    setSt(s);
    onStatus(s);
  };

  useEffect(() => {
    api.getMCPStatus().then(apply).catch((e) => setMsg({ ok: false, text: errText(e) }));
    api.getMCPActivity().then((a) => setActivity(a ?? [])).catch(() => {});
    api.getScope().then(setScope).catch(() => {});
    return on("mcp:activity", (a: MCPActivity) => {
      setActivity((list) => [...list.slice(-199), a]);
      // Keeps the request counter current.
      api.getMCPStatus().then(apply).catch(() => {});
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const change = async (
    enabled: boolean,
    level: MCPLevel,
    mask: boolean,
    allowDelete: boolean
  ) => {
    setMsg(null);
    setBusy(true);
    try {
      const s = await api.setMCPSettings(enabled, level, mask, allowDelete);
      apply(s);
      if (enabled !== st?.enabled) setActivity([]);
    } catch (e) {
      setMsg({ ok: false, text: errText(e) });
    } finally {
      setBusy(false);
    }
  };

  const newToken = async () => {
    if (
      !confirm(
        "Connected assistants stop working until they use the new token: run the Claude Code command again and re-export KANCA_MCP_TOKEN for Opencode remote. Claude Desktop and Opencode local pick it up by itself.\n\nCreate a new token?"
      )
    )
      return;
    setMsg(null);
    try {
      apply(await api.regenerateMCPToken());
      setActivity([]);
      setMsg({ ok: true, text: "New token created. Run the Claude Code command below again (Opencode remote: re-export KANCA_MCP_TOKEN)." });
    } catch (e) {
      setMsg({ ok: false, text: errText(e) });
    }
  };

  const addToDesktop = async () => {
    setDesktopMsg(null);
    try {
      const path = await api.addToClaudeDesktop();
      setDesktopMsg({
        ok: true,
        text: `Added to ${path} (the previous file was kept as .bak). Quit and reopen Claude Desktop to load Kanca.`,
      });
    } catch (e) {
      setDesktopMsg({ ok: false, text: errText(e) });
    }
  };

  const copy = async (key: string, text: string) => {
    if (!text) {
      setMsg({ ok: false, text: "Nothing to copy yet, wait for the backend status to load." });
      return;
    }
    if (await copyText(text)) {
      setCopied(key);
      setTimeout(() => setCopied((k) => (k === key ? "" : k)), 1500);
    } else {
      setMsg({ ok: false, text: "Copy failed in this browser — select the text manually." });
    }
  };

  if (!st) {
    return (
      <div className="pane pad col">
        {msg ? <p className="err-text">{msg.text}</p> : <p className="dim">Loading…</p>}
      </div>
    );
  }

  const scopeHosts = scope?.hosts ?? [];
  const canTest = st.level === "readwrite";
  // Old backends lack opencode* fields; resolvers build the same snippets
  // locally so Copy never writes "undefined".
  const opRemote = resolveOpencodeRemote(st.opencodeRemote, st.url);
  const opLocal = resolveOpencodeLocal(st.opencodeLocal);
  const opExport = resolveOpencodeExport(st.opencodeExport);
  const opExportWin = resolveOpencodeExportWin(st.opencodeExportWin);

  return (
    <div className="pane pad col" style={{ maxWidth: 980 }}>
      <h3>AI assistant</h3>
      <div className="callout">
        Let Claude or Opencode work alongside you. You browse the target through Kanca;
        the assistant, in Claude Code, Claude Desktop or Opencode, reads what you captured, looks
        for vulnerabilities, checks them with its own requests and reports what
        it finds to the Scanner tab. Kanca serves assistants over MCP on this
        computer only (<span className="mono">127.0.0.1</span>), and every
        remote client needs a secret token.
      </div>

      <div className="ai-switch">
        <label className="row">
          <input
            type="checkbox"
            checked={st.enabled}
            disabled={busy}
            onChange={(e) => change(e.target.checked, st.level, st.mask, st.allowDelete)}
          />
          <b>Allow AI assistants to use Kanca</b>
        </label>
        <span className="grow" />
        <span className={"status-dot" + (st.running ? " on" : "")} />
        <span className={st.error ? "err-text" : "dim"}>
          {st.error
            ? `Couldn't start: ${st.error}`
            : st.running
              ? `Listening on ${st.url}`
              : "Off"}
        </span>
      </div>
      {st.running && canTest && (
        <p className="dim" style={{ margin: 0 }}>
          Requests sent by the assistant this session: <b>{st.sent}</b> of {st.budget}.
          Turning access off and on starts a new session.
        </p>
      )}
      {msg && <p className={msg.ok ? "ok-text" : "err-text"}>{msg.text}</p>}

      <h4>What the assistant may do</h4>
      <label className="ai-option">
        <input
          type="radio"
          name="ai-level"
          checked={st.level === "read"}
          disabled={busy}
          onChange={() => change(st.enabled, "read", st.mask, st.allowDelete)}
        />
        <span>
          <b>Read only</b>
          <span className="dim">
            {" "}
            Browse the history, site map and findings, and report findings. It
            can't send anything to the target.
          </span>
        </span>
      </label>
      <label className="ai-option">
        <input
          type="radio"
          name="ai-level"
          checked={st.level === "readwrite"}
          disabled={busy}
          onChange={() => change(st.enabled, "readwrite", st.mask, st.allowDelete)}
        />
        <span>
          <b>Read and test</b>
          <span className="dim">
            {" "}
            Also send requests and run active scans, only against your targets
            and at most {st.budget} requests per session. Every
            request it sends shows up in Proxy History marked{" "}
            <span className="ai-tag">AI</span>.
          </span>
        </span>
      </label>
      {canTest &&
        (scopeHosts.length === 0 ? (
          <div className="ai-warn row">
            <span className="grow">
              No targets are set, so the assistant can read traffic but can't
              send requests or scan yet.
            </span>
            <button onClick={onOpenTargets}>Set targets</button>
          </div>
        ) : (
          <p className="dim" style={{ margin: 0 }}>
            Targets: <span className="mono">{scopeHosts.join(", ")}</span>{" "}
            <a href="#" onClick={(e) => (e.preventDefault(), onOpenTargets())}>
              change
            </a>
          </p>
        ))}

      <label className="ai-option" style={{ marginTop: 6 }}>
        <input
          type="checkbox"
          checked={st.mask}
          disabled={busy}
          onChange={(e) => change(st.enabled, st.level, e.target.checked, st.allowDelete)}
        />
        <span>
          <b>Mask secrets</b>
          <span className="dim">
            {" "}
            Cookies, tokens, passwords and API keys reach the assistant as
            placeholders like <span className="mono">[[KANCA_SECRET_1]]</span>;
            Kanca puts the real values back when it sends a request.
          </span>
        </span>
      </label>
      <label className="ai-option">
        <input
          type="checkbox"
          checked={st.allowDelete}
          disabled={busy}
          onChange={(e) =>
            change(st.enabled, st.level, st.mask, e.target.checked)
          }
        />
        <span>
          <b>Allow DELETE requests</b>
          <span className="dim">
            {" "}
            Let the assistant send DELETE requests and active-scan captured
            DELETEs. Off by default, because running a scan repeats the
            deletion and may remove real data.
          </span>
        </span>
      </label>
      {!st.mask && (
        <p className="err-text" style={{ margin: 0 }}>
          Unmasked: session cookies, tokens and passwords are sent to your AI
          provider along with the traffic.
        </p>
      )}
      <p className="dim" style={{ margin: 0 }}>
        Whatever the assistant reads is sent to your AI provider. Use it only on
        targets you're allowed to test.
      </p>

      <h4>Connect Claude</h4>
      <div className="setup-grid">
        <div className="setup-card">
          <b>Claude Code</b>
          <p className="dim">Run this once in a terminal:</p>
          <pre className="code-box">{hideToken(st.claudeCode)}</pre>
          <div className="row">
            <button className="primary" onClick={() => copy("code", st.claudeCode)}>
              {copied === "code" ? "Copied!" : "Copy command"}
            </button>
            <button onClick={newToken}>New token</button>
          </div>
          <p className="dim">
            Check it with <span className="mono">claude mcp list</span>, then
            start <span className="mono">claude</span> and ask away.
          </p>
        </div>
        <div className="setup-card">
          <b>Claude Desktop</b>
          <p className="dim">
            Adds Kanca to Claude Desktop's settings, keeping your other servers
            and a backup of the file. Quit and reopen Claude Desktop afterwards.
            Kanca must be running with AI access on.
          </p>
          <div className="row">
            <button
              className="primary"
              disabled={!st.claudeDesktopPath}
              onClick={addToDesktop}
            >
              Add to Claude Desktop
            </button>
            <button onClick={() => copy("desktop", st.claudeDesktop)}>
              {copied === "desktop" ? "Copied!" : "Copy config"}
            </button>
          </div>
          {desktopMsg && (
            <p className={desktopMsg.ok ? "ok-text" : "err-text"}>{desktopMsg.text}</p>
          )}
          <details>
            <summary className="dim">Show config</summary>
            <pre className="code-box">{st.claudeDesktop}</pre>
            {st.claudeDesktopPath && (
              <p className="dim">
                File: <span className="mono">{st.claudeDesktopPath}</span>
              </p>
            )}
          </details>
        </div>
      </div>

      <h4>Connect Opencode</h4>
      <p className="dim" style={{ margin: 0 }}>
        Same Kanca endpoint, two routes. Remote keeps the secret out of the
        file via <span className="mono">{"{env:KANCA_MCP_TOKEN}"}</span>; local
        runs <span className="mono">kanca mcp-stdio</span> like Claude Desktop
        and needs no secret. Save under{" "}
        <span className="mono">mcp.kanca</span> in your project{" "}
        <span className="mono">opencode.json</span> or{" "}
        <span className="mono">~/.config/opencode/opencode.json</span>.
      </p>
      <div className="setup-grid">
        <div className="setup-card">
          <b>Opencode (remote)</b>
          <p className="dim">
            First fill the token once in this terminal (never stored in the file):
          </p>
          <pre className="code-box">{opExport}</pre>
          <div className="row">
            <button className="primary" onClick={() => copy("op-export", opExport)}>
              {copied === "op-export" ? "Copied!" : "Copy export"}
            </button>
          </div>
          <p className="dim">Windows PowerShell instead:</p>
          <pre className="code-box">{opExportWin}</pre>
          <div className="row">
            <button className="primary" onClick={() => copy("op-export-win", opExportWin)}>
              {copied === "op-export-win" ? "Copied!" : "Copy export"}
            </button>
          </div>
          <p className="dim">Then add this to opencode.json:</p>
          <pre className="code-box">{opRemote}</pre>
          <div className="row">
            <button className="primary" onClick={() => copy("op-remote", opRemote)}>
              {copied === "op-remote" ? "Copied!" : "Copy config"}
            </button>
          </div>
        </div>
        <div className="setup-card">
          <b>Opencode (local)</b>
          <p className="dim">
            No secret needed, the bridge reads{" "}
            <span className="mono">~/.kanca/mcp.json</span> itself. Use an
            absolute binary path if <span className="mono">kanca</span> is not
            on PATH.
          </p>
          <pre className="code-box">{opLocal}</pre>
          <div className="row">
            <button className="primary" onClick={() => copy("op-local", opLocal)}>
              {copied === "op-local" ? "Copied!" : "Copy config"}
            </button>
          </div>
          <p className="dim">
            Check with <span className="mono">{OPENCODE_LIST_CMD}</span>; on
            401/OAuth trouble run{" "}
            <span className="mono">{OPENCODE_DEBUG_CMD}</span>.
          </p>
        </div>
      </div>

      <h4>Try asking</h4>
      <div className="col" style={{ gap: 6 }}>
        {PROMPTS.map((p, i) => (
          <div key={i} className="ai-prompt row">
            <span className="grow">{p}</span>
            <button onClick={() => copy(`p${i}`, p)}>
              {copied === `p${i}` ? "Copied!" : "Copy"}
            </button>
          </div>
        ))}
      </div>

      <div className="row" style={{ marginTop: 12 }}>
        <h4 style={{ margin: 0 }}>Activity</h4>
        <span className="pill">{activity.length}</span>
        <span className="dim">every step the assistant takes in Kanca, newest first</span>
      </div>
      <table className="results-table">
        <thead>
          <tr>
            <th style={{ width: 80 }}>Time</th>
            <th style={{ width: "45%" }}>Action</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {[...activity].reverse().map((a, i) => (
            <tr key={activity.length - i}>
              <td className="dim mono">{new Date(a.at).toLocaleTimeString()}</td>
              <td className="ai-cell">{a.action}</td>
              <td className={"ai-cell " + (a.error ? "err-text" : "dim")}>{a.result}</td>
            </tr>
          ))}
          {activity.length === 0 && (
            <tr>
              <td colSpan={3} className="empty">
                {st.running
                  ? "Nothing yet. When the assistant uses Kanca, each step appears here."
                  : "Turn on AI access and connect Claude or Opencode to get started."}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
