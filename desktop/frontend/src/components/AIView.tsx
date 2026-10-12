import { useEffect, useState } from "react";
import { api, on, MCPActivity, MCPLevel, MCPStatus, ScopeConfig } from "../lib/api";

const PROMPTS = [
  "Use Kanca to review the traffic I captured and list the most interesting endpoints to test.",
  "Check the API requests in Kanca for IDOR and broken access control, and verify anything you suspect.",
  "Look for injection points (SQLi, XSS, SSTI) in what I browsed and run Kanca's active scan where it makes sense.",
];

interface Props {
  onStatus: (s: MCPStatus) => void;
  onOpenSettings: () => void;
}

type Msg = { ok: boolean; text: string } | null;

// The token is a secret: show it shortened (screenshots get shared) and copy
// it in full.
function hideToken(cmd: string): string {
  return cmd.replace(/(Bearer [0-9a-f]{6})[0-9a-f]+([0-9a-f]{4})/, "$1…$2");
}

function errText(e: any): string {
  return String(e?.message ?? e);
}

export default function AIView({ onStatus, onOpenSettings }: Props) {
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

  const change = async (enabled: boolean, level: MCPLevel, mask: boolean) => {
    setMsg(null);
    setBusy(true);
    try {
      const s = await api.setMCPSettings(enabled, level, mask);
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
        "Connected assistants stop working until they use the new token: run the Claude Code command again. Claude Desktop picks it up by itself.\n\nCreate a new token?"
      )
    )
      return;
    setMsg(null);
    try {
      apply(await api.regenerateMCPToken());
      setActivity([]);
      setMsg({ ok: true, text: "New token created. Run the Claude Code command below again." });
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
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied((k) => (k === key ? "" : k)), 1500);
    } catch {
      /* clipboard may be unavailable */
    }
  };

  if (!st) {
    return (
      <div className="pane pad col">
        {msg ? <p className="err-text">{msg.text}</p> : <p className="dim">Loading…</p>}
      </div>
    );
  }

  const scopeHosts = scope?.enabled ? scope.hosts ?? [] : [];
  const canTest = st.level === "readwrite";

  return (
    <div className="pane pad col" style={{ maxWidth: 980 }}>
      <h3>AI assistant</h3>
      <div className="callout">
        Let Claude work alongside you. You browse the target through Kanca;
        Claude, in Claude Code or Claude Desktop, reads what you captured, looks
        for vulnerabilities, checks them with its own requests and reports what
        it finds to the Findings tab. Kanca serves Claude over MCP on this
        computer only (<span className="mono">127.0.0.1</span>), and every
        client needs a secret token.
      </div>

      <div className="ai-switch">
        <label className="row">
          <input
            type="checkbox"
            checked={st.enabled}
            disabled={busy}
            onChange={(e) => change(e.target.checked, st.level, st.mask)}
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
          onChange={() => change(st.enabled, "read", st.mask)}
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
          onChange={() => change(st.enabled, "readwrite", st.mask)}
        />
        <span>
          <b>Read and test</b>
          <span className="dim">
            {" "}
            Also send requests and run active scans, only against hosts in your
            target scope and at most {st.budget} requests per session. Every
            request it sends shows up in Proxy History marked{" "}
            <span className="ai-tag">AI</span>.
          </span>
        </span>
      </label>
      {canTest &&
        (scopeHosts.length === 0 ? (
          <div className="ai-warn row">
            <span className="grow">
              No target scope is set, so the assistant can read traffic but
              can't send requests yet.
            </span>
            <button onClick={onOpenSettings}>Set target scope</button>
          </div>
        ) : (
          <p className="dim" style={{ margin: 0 }}>
            In scope: <span className="mono">{scopeHosts.join(", ")}</span>{" "}
            <a href="#" onClick={(e) => (e.preventDefault(), onOpenSettings())}>
              change
            </a>
          </p>
        ))}

      <label className="ai-option" style={{ marginTop: 6 }}>
        <input
          type="checkbox"
          checked={st.mask}
          disabled={busy}
          onChange={(e) => change(st.enabled, st.level, e.target.checked)}
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
                  ? "Nothing yet. When Claude uses Kanca, each step appears here."
                  : "Turn on AI access and connect Claude to get started."}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
