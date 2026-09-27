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
}

export default function HistoryView({ onSendToRepeater, onSendToIntruder }: Props) {
  const [rows, setRows] = useState<Entry[]>([]);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<FlowView | null>(null);
  const [selId, setSelId] = useState<number | null>(null);
  const filterRef = useRef(filter);
  filterRef.current = filter;

  const refresh = async () => {
    setRows(await api.listHistory(filterRef.current, []));
  };

  useEffect(() => {
    refresh();
    // Live-append on each new captured flow.
    const off = on("proxy:flow", () => refresh());
    return off;
  }, []);

  useEffect(() => {
    refresh();
  }, [filter]);

  const select = async (id: number) => {
    setSelId(id);
    try {
      setSelected(await api.getFlow(id));
    } catch {
      setSelected(null);
    }
  };

  const view = useMemo(() => selected, [selected]);

  return (
    <div className="split-v">
      <div className="toolbar">
        <input
          className="grow"
          placeholder="Filter by method, host or path…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
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
              </div>
              <div className="split-h">
                <RawMessage title="Request" value={view.requestRaw} />
                <div className="divider" />
                <RawMessage
                  title={
                    view.error
                      ? "Response — error"
                      : `Response — ${view.statusCode}`
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
