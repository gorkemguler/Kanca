import { useState } from "react";
import { api, DiffResult } from "../lib/api";
import DiffLines from "./DiffLines";

/** Load a side of the comparison from a history flow's raw response. */
async function loadFlowResponse(id: string): Promise<string> {
  const n = Number(id);
  if (!id.trim() || !Number.isFinite(n)) throw new Error(`not a flow id: ${id}`);
  const f = await api.getFlow(n);
  return f.error ? f.error : f.responseRaw;
}

/** Global Comparer: word on any two texts — two responses, two requests,
 *  pasted payloads — using the same line diff as the Repeater. */
export default function ComparerView() {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [flowA, setFlowA] = useState("");
  const [flowB, setFlowB] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const loadA = async () => {
    try {
      setA(await loadFlowResponse(flowA));
      setErr("");
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  };

  const loadB = async () => {
    try {
      setB(await loadFlowResponse(flowB));
      setErr("");
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  };

  const runDiff = async () => {
    setBusy(true);
    try {
      setDiff(await api.diffText(a, b));
      setErr("");
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Comparer</b>
        <span className="dim">compare any two texts: responses, requests, payloads</span>
        <span className="grow" />
        <button onClick={runDiff} disabled={busy || (!a && !b)} className="primary">
          {busy ? "Diffing…" : "Compare A ↔ B"}
        </button>
        <button
          onClick={() => {
            const t = a;
            setA(b);
            setB(t);
            setDiff(null);
          }}
        >
          Swap
        </button>
      </div>
      {err && <div className="err-text" style={{ padding: "0 12px" }}>{err}</div>}
      <div className="split-h" style={{ flex: "0 0 38%" }}>
        <div className="split-v" style={{ flex: 1 }}>
          <div className="toolbar">
            <b>A</b>
            <label className="dim" title="History flow id whose response fills A">
              flow #
              <input
                style={{ width: 90, marginLeft: 4 }}
                placeholder="flow #"
                value={flowA}
                onChange={(e) => setFlowA(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && loadA()}
              />
            </label>
            <button onClick={loadA} title="Load this history flow's response into A">
              Load flow
            </button>
            <span className="grow" />
            <span className="dim">{a.length} chars</span>
          </div>
          <textarea
            className="pane msg"
            style={{ flex: 1, resize: "none" }}
            spellCheck={false}
            value={a}
            onChange={(e) => setA(e.target.value)}
          />
        </div>
        <div className="divider" />
        <div className="split-v" style={{ flex: 1 }}>
          <div className="toolbar">
            <b>B</b>
            <label className="dim" title="History flow id whose response fills B">
              flow #
              <input
                style={{ width: 90, marginLeft: 4 }}
                placeholder="flow #"
                value={flowB}
                onChange={(e) => setFlowB(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && loadB()}
              />
            </label>
            <button onClick={loadB} title="Load this history flow's response into B">
              Load flow
            </button>
            <span className="grow" />
            <span className="dim">{b.length} chars</span>
          </div>
          <textarea
            className="pane msg"
            style={{ flex: 1, resize: "none" }}
            spellCheck={false}
            value={b}
            onChange={(e) => setB(e.target.value)}
          />
        </div>
      </div>
      <div className="divider" />
      {diff ? (
        <div className="split-v" style={{ flex: 1 }}>
          <DiffLines diff={diff} caption="A → B" onClose={() => setDiff(null)} />
        </div>
      ) : (
        <div className="empty">
          Paste two texts above — or load two history flows — then Compare.
        </div>
      )}
    </div>
  );
}
