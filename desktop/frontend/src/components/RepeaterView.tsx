import { useEffect, useState } from "react";
import { api, FlowView, RepeaterTab } from "../lib/api";
import RawMessage from "./RawMessage";

interface LocalTab {
  id: number;
  name: string;
  scheme: string;
  host: string;
  raw: string;
  response: FlowView | null;
  sending: boolean;
}

interface Props {
  // pending flow ids queued from the History view to open as new tabs.
  pending: number[];
  clearPending: () => void;
}

export default function RepeaterView({ pending, clearPending }: Props) {
  const [tabs, setTabs] = useState<LocalTab[]>([]);
  const [active, setActive] = useState<number | null>(null);

  useEffect(() => {
    if (pending.length === 0) return;
    (async () => {
      const created: LocalTab[] = [];
      for (const flowId of pending) {
        const t: RepeaterTab = await api.repeaterFromFlow(flowId);
        created.push({
          id: t.id,
          name: t.name,
          scheme: t.scheme,
          host: t.host,
          raw: t.raw,
          response: null,
          sending: false,
        });
      }
      setTabs((prev) => [...prev, ...created]);
      if (created.length) setActive(created[created.length - 1].id);
      clearPending();
    })();
  }, [pending, clearPending]);

  const newTab = async () => {
    const t = await api.repeaterNewTab(
      "https",
      "example.com",
      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    const lt: LocalTab = {
      id: t.id,
      name: t.name,
      scheme: t.scheme,
      host: t.host,
      raw: t.raw,
      response: null,
      sending: false,
    };
    setTabs((prev) => [...prev, lt]);
    setActive(t.id);
  };

  const patch = (id: number, p: Partial<LocalTab>) =>
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...p } : t)));

  const close = (id: number) => {
    api.repeaterClose(id);
    setTabs((prev) => prev.filter((t) => t.id !== id));
    if (active === id) setActive(null);
  };

  const send = async (t: LocalTab) => {
    patch(t.id, { sending: true });
    await api.repeaterUpdate(t.id, t.scheme, t.host, t.raw);
    try {
      const resp = await api.repeaterSend(t.id);
      patch(t.id, { response: resp, sending: false });
    } catch {
      patch(t.id, { sending: false });
    }
  };

  const cur = tabs.find((t) => t.id === active) ?? null;

  return (
    <div className="split-v">
      <div className="rep-tabs">
        {tabs.map((t) => (
          <div
            key={t.id}
            className={"rep-tab" + (active === t.id ? " active" : "")}
            onClick={() => setActive(t.id)}
          >
            {t.name}
            <span
              style={{ marginLeft: 8 }}
              onClick={(e) => {
                e.stopPropagation();
                close(t.id);
              }}
            >
              ✕
            </span>
          </div>
        ))}
        <div className="rep-tab" onClick={newTab}>
          + New
        </div>
      </div>
      {cur ? (
        <div className="split-v">
          <div className="toolbar">
            <button className="primary" onClick={() => send(cur)} disabled={cur.sending}>
              {cur.sending ? "Sending…" : "Send"}
            </button>
            <label className="field">
              Scheme
              <select
                value={cur.scheme}
                onChange={(e) => patch(cur.id, { scheme: e.target.value })}
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </label>
            <label className="field grow">
              Host
              <input
                value={cur.host}
                onChange={(e) => patch(cur.id, { host: e.target.value })}
              />
            </label>
            {cur.response && (
              <span className="pill">
                {cur.response.error
                  ? "error"
                  : `${cur.response.statusCode} · ${cur.response.respLength}B · ${cur.response.durationMs}ms`}
              </span>
            )}
          </div>
          <div className="split-h">
            <RawMessage
              title="Request"
              value={cur.raw}
              editable
              onChange={(v) => patch(cur.id, { raw: v })}
            />
            <div className="divider" />
            <RawMessage
              title="Response"
              value={
                cur.response
                  ? cur.response.error || cur.response.responseRaw
                  : ""
              }
              placeholder="Send the request to see the response."
            />
          </div>
        </div>
      ) : (
        <div className="empty">
          Open a request from History with “→ Repeater”, or create a new tab.
        </div>
      )}
    </div>
  );
}
