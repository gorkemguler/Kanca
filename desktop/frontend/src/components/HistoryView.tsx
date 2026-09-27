import { useEffect, useMemo, useRef, useState } from "react";
import { api, on, Entry, FlowView } from "../lib/api";
import RawMessage from "./RawMessage";

function statusClass(code: number): string {
  if (code >= 500) return "status-5";
  if (code >= 400) return "status-4";
  if (code >= 300) return "status-3";
  if (code >= 200) return "status-2";
  return "";
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
  const [selected, setSelected] = useState<FlowView | null>(null);
  const [selId, setSelId] = useState<number | null>(null);
  const filterRef = useRef(filter);
  filterRef.current = filter;
  const bodiesRef = useRef(searchBodies);
  bodiesRef.current = searchBodies;

  const refresh = async () => {
    setRows(await api.listHistory(filterRef.current, [], bodiesRef.current));
  };

  useEffect(() => {
    refresh();
    // Live-append on each new captured flow, and after a project load.
    const offFlow = on("proxy:flow", () => refresh());
    const offProj = on("project:loaded", () => refresh());
    return () => {
      offFlow();
      offProj();
    };
  }, []);

  useEffect(() => {
    refresh();
  }, [filter, searchBodies]);

  const select = async (id: number) => {
    setSelId(id);
    try {
      setSelected(await api.getFlow(id));
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

  const view = useMemo(() => selected, [selected]);

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
        <label className="row" title="Also search request/response bodies">
          <input
            type="checkbox"
            checked={searchBodies}
            onChange={(e) => setSearchBodies(e.target.checked)}
          />
          <span className="dim">bodies</span>
        </label>
        <span className="pill">{rows.length} flows</span>
        <button onClick={() => api.clearHistory().then(refresh)}>Clear</button>
      </div>
      <div className="split-h">
        <div className="pane" style={{ flex: "0 0 45%" }}>
          <table className="hist-table">
            <thead>
              <tr>
                <th style={{ width: 40 }}>#</th>
                <th style={{ width: 60 }}>Method</th>
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
                >
                  <td className="dim">{r.id}</td>
                  <td className="method">{r.method}</td>
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
                  title="Run non-destructive active probes against this request (in-scope hosts only); results appear in Findings"
                  onClick={() =>
                    api
                      .activeScan(view.id)
                      .catch((e: any) => alert("Active scan failed: " + (e?.message ?? e)))
                  }
                >
                  Active scan
                </button>
              </div>
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
