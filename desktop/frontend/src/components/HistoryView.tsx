import { useEffect, useRef, useState } from "react";
import { api, copyText, hostOf, isNotTarget, on, Entry, FlowView } from "../lib/api";
import RawMessage from "./RawMessage";
import { useCoalescedRefresh } from "../lib/coalesce";

function statusClass(code: number): string {
  if (code >= 500) return "status-5";
  if (code >= 400) return "status-4";
  if (code >= 300) return "status-3";
  if (code >= 200) return "status-2";
  return "";
}

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const HIGHLIGHTS = ["red", "orange", "yellow", "green", "blue", "purple"];

function highlightColor(h?: string): string | undefined {
  return h && (HIGHLIGHTS as string[]).includes(h) ? h : undefined;
}

interface FilterPreset {
  name: string;
  filter: string;
  method: string;
  searchBodies: boolean;
  hideStatus: string;
}

const PRESETS_KEY = "kanca.filterPresets";
const PRESETS_VERSION = 1;

function isPreset(p: any): p is FilterPreset {
  return (
    p != null &&
    typeof p.name === "string" &&
    typeof p.filter === "string" &&
    typeof p.method === "string" &&
    typeof p.searchBodies === "boolean" &&
    typeof p.hideStatus === "string"
  );
}

function loadPresets(): FilterPreset[] {
  try {
    const raw = localStorage.getItem(PRESETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    // Current shape {v, presets}; legacy bare arrays migrate silently.
    const list = Array.isArray(parsed) ? parsed : parsed.presets;
    if (!Array.isArray(list)) return [];
    return list.filter(isPreset);
  } catch {
    return [];
  }
}

function storePresets(next: FilterPreset[]) {
  try {
    localStorage.setItem(PRESETS_KEY, JSON.stringify({ v: PRESETS_VERSION, presets: next }));
  } catch {
    /* storage full or unavailable: presets stay memory-only */
  }
}

const PLUS_KEY = "kanca.activeScanPlus";

function loadPlus(): boolean {
  try {
    return localStorage.getItem(PLUS_KEY) === "1";
  } catch {
    return false;
  }
}

interface Props {
  onSendToRepeater: (flowId: number) => void;
  onSendToIntruder: (flow: FlowView) => void;
  focusFlow?: number | null;
  clearFocus?: () => void;
}

export default function HistoryView({
  onSendToRepeater,
  onSendToIntruder,
  focusFlow,
  clearFocus,
}: Props) {
  const [rows, setRows] = useState<Entry[]>([]);
  const [filter, setFilter] = useState("");
  const [searchBodies, setSearchBodies] = useState(false);
  const [method, setMethod] = useState("");
  const [hideStatus, setHideStatus] = useState("");
  const [presets, setPresets] = useState<FilterPreset[]>(loadPresets);
  const [scanning, setScanning] = useState<Set<number>>(new Set());
  const [scanErr, setScanErr] = useState("");
  const [plus, setPlus] = useState(loadPlus);
  const [comment, setComment] = useState("");
  const [highlight, setHighlight] = useState("");
  const [poc, setPoc] = useState<string | null>(null);
  const [pocErr, setPocErr] = useState("");
  const [selected, setSelected] = useState<FlowView | null>(null);
  const [selId, setSelId] = useState<number | null>(null);
  const filterRef = useRef(filter);
  filterRef.current = filter;
  const bodiesRef = useRef(searchBodies);
  bodiesRef.current = searchBodies;
  const methodRef = useRef(method);
  methodRef.current = method;
  const hideRef = useRef(hideStatus);
  hideRef.current = hideStatus;

  const parseHideStatus = (s: string): number[] =>
    s
      .split(",")
      .map((x) => Number(x.trim()))
      .filter((n) => Number.isFinite(n) && n > 0);

  const refresh = useCoalescedRefresh(async () => {
    setRows(
      await api.listHistory(
        filterRef.current,
        methodRef.current ? [methodRef.current] : [],
        bodiesRef.current,
        parseHideStatus(hideRef.current)
      )
    );
  });

  useEffect(() => {
    refresh();
    // Live-append on each new captured flow, and after a project load.
    const offFlow = on("proxy:flow", () => refresh());
    const offProj = on("project:loaded", () => refresh());
    const offScan = on("activescan:done", (d: { flowId?: number; message?: string }) => {
      setScanning((prev) => {
        const next = new Set(prev);
        if (d && typeof d.flowId === "number") next.delete(d.flowId);
        else next.clear(); // legacy string payload: clear conservatively
        return next;
      });
      if (d && d.message) setScanErr(d.message);
    });
    return () => {
      offFlow();
      offProj();
      offScan();
    };
  }, []);

  useEffect(() => {
    refresh();
  }, [filter, searchBodies, method, hideStatus]);

  const select = async (id: number) => {
    setSelId(id);
    setPoc(null);
    try {
      const f = await api.getFlow(id);
      setSelected(f);
      const row = rows.find((r) => r.id === id);
      setComment(row?.comment ?? "");
      setHighlight(row?.highlight && row.highlight !== "ai" ? row.highlight : "");
    } catch {
      setSelected(null);
    }
  };

  // When another tab asks to focus a flow (e.g. Findings → View), open it.
  useEffect(() => {
    if (focusFlow != null) {
      select(focusFlow);
      clearFocus?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusFlow]);

  const view = selected;

  // Only targets may be scanned; offer to add this request's host.
  const activeScan = async (flow: FlowView, aggressive: boolean) => {
    setScanErr("");
    setScanning((prev) => new Set(prev).add(flow.id));
    const drop = () =>
      setScanning((prev) => {
        const next = new Set(prev);
        next.delete(flow.id);
        return next;
      });
    try {
      await api.activeScan(flow.id, aggressive, plus);
    } catch (e) {
      drop();
      if (!isNotTarget(e)) {
        setScanErr("Active scan failed: " + ((e as any)?.message ?? e));
        return;
      }
      const host = hostOf(flow.host);
      if (!confirm(`${host} isn't one of your targets, and Kanca only scans targets.\n\nAdd ${host} as a target and scan? Only do this for sites you're allowed to test.`)) {
        return;
      }
      try {
        await api.addTarget(host);
      } catch (err: any) {
        setScanErr("Add target failed: " + (err?.message ?? err));
        return;
      }
      setScanning((prev) => new Set(prev).add(flow.id));
      try {
        await api.activeScan(flow.id, aggressive, plus);
      } catch (err: any) {
        drop();
        setScanErr("Active scan failed: " + (err?.message ?? err));
      }
    }
  };

  const togglePlus = (on: boolean) => {
    setPlus(on);
    try {
      localStorage.setItem(PLUS_KEY, on ? "1" : "0");
    } catch {
      /* storage unavailable: the choice lasts until reload */
    }
  };

  const savePreset = () => {
    const name = prompt("Name this filter preset:");
    if (!name?.trim()) return;
    const next = [
      ...presets.filter((p) => p.name !== name.trim()),
      { name: name.trim(), filter, method, searchBodies, hideStatus },
    ];
    setPresets(next);
    storePresets(next);
  };

  const applyPreset = (p: FilterPreset) => {
    setFilter(p.filter);
    setMethod(p.method);
    setSearchBodies(p.searchBodies);
    setHideStatus(p.hideStatus);
  };

  const deletePreset = (name: string) => {
    const next = presets.filter((p) => p.name !== name);
    setPresets(next);
    storePresets(next);
  };

  const saveAnnotation = async () => {
    if (view == null) return;
    setScanErr("");
    try {
      await api.annotateFlow(view.id, comment, highlight);
      refresh();
    } catch (e: any) {
      setScanErr("Save note failed: " + (e?.message ?? e));
    }
  };

  const buildCSRFPoC = (f: FlowView): string => {
    const esc = (s: string) =>
      s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
    const fields: Array<[string, string]> = [];
    const pushPairs = (qs: string) => {
      for (const part of qs.split("&")) {
        if (!part) continue;
        const i = part.indexOf("=");
        let k: string, v: string;
        try {
          k = decodeURIComponent((i < 0 ? part : part.slice(0, i)).replace(/\+/g, " "));
          v = decodeURIComponent(((i < 0 ? "" : part.slice(i + 1)) || "").replace(/\+/g, " "));
        } catch {
          continue; // lone % or %ZZ: skip the broken pair, keep the rest
        }
        fields.push([k, v]);
      }
    };
    const q = f.url.indexOf("?");
    if (f.method.toUpperCase() === "GET" && q >= 0) {
      pushPairs(f.url.slice(q + 1));
    } else {
      const sep = f.requestRaw.indexOf("\r\n\r\n");
      const body = (sep >= 0 ? f.requestRaw.slice(sep + 4) : "").trim();
      if (body) pushPairs(body);
    }
    const inputs = fields
      .map(([k, v]) => `      <input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
      .join("\n");
    // The comment is escaped too: a URL containing "-->" must not break out.
    const head = `<!-- CSRF PoC for ${esc(f.method)} ${esc(f.url)} — generated by Kanca, authorised targets only -->`;
    // GET submits its params both in action and as inputs; strip the query
    // from action so each param goes exactly once.
    const action = f.method.toUpperCase() === "GET" ? f.url.split("?")[0] : f.url;
    return `${head}\n<html>\n  <body>\n    <form action="${esc(action)}" method="${esc(f.method.toUpperCase())}">\n${inputs}\n      <input type="submit" value="Submit request">\n    </form>\n    <script>document.forms[0].submit();</script>\n  </body>\n</html>\n`;
  };

  return (
    <div className="split-v">
      <div className="toolbar">
        <input
          className="grow"
          placeholder={
            searchBodies
              ? "Filter method/host/path and bodies…"
              : "Filter by method, host or path…"
          }
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <select
          title="Method"
          value={method}
          onChange={(e) => setMethod(e.target.value)}
        >
          <option value="">any method</option>
          {METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          style={{ width: 130 }}
          title="Hide status codes, comma separated (e.g. 404,304)"
          placeholder="hide status…"
          value={hideStatus}
          onChange={(e) => setHideStatus(e.target.value)}
        />
        <label className="row" title="Also search request/response bodies">
          <input
            type="checkbox"
            checked={searchBodies}
            onChange={(e) => setSearchBodies(e.target.checked)}
          />
          <span className="dim">bodies</span>
        </label>
        {presets.length > 0 && (
          <select
            title="Saved filter presets"
            value=""
            onChange={(e) => {
              const p = presets.find((x) => x.name === e.target.value);
              if (p) applyPreset(p);
            }}
          >
            <option value="">presets…</option>
            {presets.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        )}
        <button title="Save the current filter as a preset" onClick={savePreset}>
          Save filter
        </button>
        <span className="pill">{rows.length} flows</span>
        <button onClick={() => api.clearHistory().then(refresh)}>Clear</button>
      </div>
      {presets.length > 0 && (
        <div className="toolbar" style={{ paddingTop: 0 }}>
          <span className="dim">presets:</span>
          {presets.map((p) => (
            <span key={p.name} className="pill">
              {p.name}
              <button title={`Delete preset ${p.name}`} onClick={() => deletePreset(p.name)}>
                ×
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="split-h">
        <div className="pane" style={{ flex: "0 0 45%" }}>
          <table className="hist-table">
            <thead>
              <tr>
                <th style={{ width: 40 }}>#</th>
                <th style={{ width: 84 }}>Method</th>
                <th>Host</th>
                <th>Path</th>
                <th style={{ width: 60 }}>Status</th>
                <th style={{ width: 70 }}>Length</th>
                <th style={{ width: 60 }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.id}
                  className={selId === r.id ? "sel" : ""}
                  onClick={() => select(r.id)}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") select(r.id);
                  }}
                  title={r.comment || `${r.method} ${r.host}${r.path}`}
                >
                  <td className="dim">{r.id}</td>
                  <td className="method">
                    {r.method}
                    {r.highlight === "ai" ? (
                      <span className="ai-tag" title={r.comment || "Sent by an AI assistant"}>
                        AI
                      </span>
                    ) : (
                      highlightColor(r.highlight) && (
                        <span
                          title={r.comment || r.highlight}
                          style={{
                            display: "inline-block",
                            width: 10,
                            height: 10,
                            borderRadius: 5,
                            marginLeft: 6,
                            background: highlightColor(r.highlight),
                            verticalAlign: "baseline",
                          }}
                        />
                      )
                    )}
                    {r.comment && r.highlight !== "ai" && (
                      <span className="dim" title={r.comment}>
                        {" *"}
                      </span>
                    )}
                  </td>
                  <td>{r.host}</td>
                  <td title={r.path}>{r.path}</td>
                  <td className={statusClass(r.statusCode)}>
                    {r.error ? "ERR" : r.statusCode || "—"}
                  </td>
                  <td className="dim">{r.length}</td>
                  <td className="dim">{r.durationMs}ms</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty">
                    No traffic yet. Start the proxy and route a browser through it.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="divider" />
        <div className="split-v" style={{ flex: 1 }}>
          {view ? (
            <>
              <div className="toolbar">
                <span className="mono grow" title={view.url}>
                  {view.method} {view.url}
                </span>
                <button onClick={() => onSendToRepeater(view.id)}>→ Repeater</button>
                <button onClick={() => onSendToIntruder(view)}>→ Intruder</button>
                <button
                  onClick={() => setPoc((p) => (p == null ? buildCSRFPoC(view) : null))}
                  title="Generate an auto-submitting HTML form PoC for this request"
                >
                  CSRF PoC
                </button>
                {view && scanning.has(view.id) ? (
                  <button
                    onClick={async () => {
                      try {
                        await api.stopActiveScan(view.id);
                      } catch (e: any) {
                        setScanErr("Stop scan failed: " + (e?.message ?? e));
                      }
                      setScanning((prev) => {
                        const next = new Set(prev);
                        next.delete(view.id);
                        return next;
                      });
                    }}
                    title="Stop the running active scan for this request"
                  >
                    Stop scan
                  </button>
                ) : (
                  <>
                    <button
                      title="Run non-destructive active probes (reflection/XSS, SQLi error, path traversal, open redirect, SSTI, CRLF) against this request; targets only. Results appear in Findings."
                      onClick={() => activeScan(view, false)}
                    >
                      Active scan
                    </button>
                    <button
                      className="danger"
                      title="Also run boolean/time-based SQLi and time-based command-injection probes. These make the target do observable work (e.g. a bounded sleep). Authorised targets only."
                      onClick={() => {
                        if (
                          !confirm(
                            "Aggressive scan also sends boolean/time-based SQLi and command-injection probes, which make the target do real work (e.g. deliberate delays). Only run this against systems you are authorised to test.\n\nContinue?"
                          )
                        )
                          return;
                        activeScan(view, true);
                      }}
                    >
                      Active scan+
                    </button>
                    <label
                      className="row"
                      title="Also run the checks ported from ActiveScan++: Host header poisoning, Edge Side Includes, suspicious input transformations, XML and SAML handling, exposed files (.git/config, server-status…) and known CVEs (Rails, Next.js, PHP, GitLab). Sends more requests."
                    >
                      <input
                        type="checkbox"
                        checked={plus}
                        onChange={(e) => togglePlus(e.target.checked)}
                      />
                      <span>ActiveScan++</span>
                    </label>
                  </>
                )}
                {scanErr && (
                  <span className="err-text" title={scanErr}>
                    {scanErr.length > 80 ? scanErr.slice(0, 80) + "…" : scanErr}
                  </span>
                )}
              </div>
              <div className="toolbar" style={{ paddingTop: 0 }}>
                <input
                  className="grow"
                  placeholder="Note on this request…"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                />
                <select
                  title="Highlight colour"
                  value={highlight}
                  onChange={(e) => setHighlight(e.target.value)}
                >
                  <option value="">no highlight</option>
                  <option value="red">red</option>
                  <option value="orange">orange</option>
                  <option value="yellow">yellow</option>
                  <option value="green">green</option>
                  <option value="blue">blue</option>
                  <option value="purple">purple</option>
                </select>
                <button onClick={saveAnnotation} title="Save the note/highlight (kept in project files)">
                  Tag
                </button>
              </div>
              {poc != null && (
                <div className="split-v">
                  <div className="toolbar">
                    <b>CSRF PoC</b>
                    <span className="dim">auto-submitting form — authorised targets only</span>
                    <span className="grow" />
                    {pocErr && <span className="err-text">{pocErr}</span>}
                    <button
                      onClick={async () => {
                        if (await copyText(poc)) setPocErr("");
                        else setPocErr("Copy failed — select the HTML manually.");
                      }}
                    >
                      Copy HTML
                    </button>
                    <button onClick={() => setPoc(null)}>Close</button>
                  </div>
                  <textarea
                    className="pane msg"
                    style={{ minHeight: 180, resize: "vertical" }}
                    spellCheck={false}
                    readOnly
                    value={poc}
                  />
                </div>
              )}
              <div className="split-h">
                <RawMessage title="Request" value={view.requestRaw} />
                <div className="divider" />
                <RawMessage
                  title={
                    view.error
                      ? "Response — error"
                      : `Response — ${view.statusCode}` +
                        (view.respEncoding ? ` · decoded ${view.respEncoding}` : "")
                  }
                  value={view.error ? view.error : view.responseRaw}
                />
              </div>
            </>
          ) : (
            <div className="empty">Select a flow to inspect its request and response.</div>
          )}
        </div>
      </div>
    </div>
  );
}
