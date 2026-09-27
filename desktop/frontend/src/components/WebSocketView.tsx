import { useEffect, useState } from "react";
import { api, on, WSSession } from "../lib/api";

export default function WebSocketView() {
  const [sessions, setSessions] = useState<WSSession[]>([]);
  const [selId, setSelId] = useState<number | null>(null);

  const refresh = async () => {
    const list = await api.getWSSessions();
    setSessions(list);
  };

  useEffect(() => {
    refresh();
    // Any open/frame/close event means the session list (or its frame log)
    // changed; a full refresh is simplest and cheap at this scale.
    const offs = ["ws:open", "ws:frame", "ws:close"].map((ev) =>
      on(ev, () => refresh())
    );
    const offProj = on("project:loaded", () => refresh());
    return () => {
      offs.forEach((off) => off());
      offProj();
    };
  }, []);

  const sel = sessions.find((s) => s.id === selId) ?? null;

  return (
    <div className="split-h">
      <div className="pane" style={{ flex: "0 0 320px" }}>
        <div className="toolbar">
          <b>WebSocket connections</b>
          <span className="grow" />
          <button onClick={() => api.clearWSSessions().then(refresh)}>Clear</button>
        </div>
        <table className="hist-table">
          <thead>
            <tr>
              <th>Host</th>
              <th style={{ width: 60 }}>State</th>
              <th style={{ width: 60 }}>Frames</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr
                key={s.id}
                className={selId === s.id ? "sel" : ""}
                onClick={() => setSelId(s.id)}
              >
                <td title={s.url}>{s.host}</td>
                <td className={s.open ? "status-2" : "dim"}>
                  {s.open ? "open" : "closed"}
                </td>
                <td className="dim">{s.frames?.length ?? 0}</td>
              </tr>
            ))}
            {sessions.length === 0 && (
              <tr>
                <td colSpan={3} className="empty">
                  No WebSocket traffic captured yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="divider" />
      <div className="split-v" style={{ flex: 1 }}>
        {sel ? (
          <>
            <div className="toolbar">
              <span className="mono grow" title={sel.url}>
                {sel.url}
              </span>
              <span className={sel.open ? "pill status-2" : "pill dim"}>
                {sel.open ? "open" : "closed"}
              </span>
            </div>
            <div className="pane">
              <table className="results-table">
                <thead>
                  <tr>
                    <th style={{ width: 130 }}>Direction</th>
                    <th style={{ width: 90 }}>Opcode</th>
                    <th style={{ width: 70 }}>Bytes</th>
                    <th>Payload</th>
                  </tr>
                </thead>
                <tbody>
                  {(sel.frames ?? []).map((f, i) => (
                    <tr key={i}>
                      <td className={f.direction === "client->server" ? "" : "dim"}>
                        {f.direction === "client->server" ? "→ server" : "← client"}
                      </td>
                      <td>{f.opcode}</td>
                      <td className="dim">{f.length}</td>
                      <td className="mono">
                        {f.isText ? f.text : <span className="dim">(binary)</span>}
                      </td>
                    </tr>
                  ))}
                  {(sel.frames ?? []).length === 0 && (
                    <tr>
                      <td colSpan={4} className="empty">
                        No frames yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="empty">Select a connection to see its frame log.</div>
        )}
      </div>
    </div>
  );
}
