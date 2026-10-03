import { useEffect, useRef, useState } from "react";
import {
  api,
  on,
  AttackType,
  FlowView,
  IntruderConfig,
  IntruderPreview,
  IntruderResult,
  PayloadSpec,
  Processor,
} from "../lib/api";

interface Props {
  // A flow sent from History to seed the template/target.
  seed: FlowView | null;
  clearSeed: () => void;
}

// PSet is the editor state for one payload set: either a literal list or a
// generated numeric range, plus optional processors applied to each value.
interface PSet {
  mode: "list" | "numbers";
  list: string;
  from: number;
  to: number;
  step: number;
  pad: number;
  processors: Processor[];
}

const newPSet = (list = ""): PSet => ({
  mode: "list",
  list,
  from: 1,
  to: 100,
  step: 1,
  pad: 0,
  processors: [],
});

const ALL_PROCESSORS: Processor[] = [
  "url",
  "base64",
  "lower",
  "upper",
  "md5",
  "sha1",
  "sha256",
];

function toSpec(p: PSet): PayloadSpec {
  const processors = p.processors.length ? p.processors : undefined;
  if (p.mode === "numbers") {
    return { list: [], numbers: { from: p.from, to: p.to, step: p.step, pad: p.pad }, processors };
  }
  return {
    list: p.list.split("\n").filter((x) => x.length > 0),
    processors,
  };
}

const ATTACKS: { value: AttackType; label: string; hint: string }[] = [
  { value: "sniper", label: "Sniper", hint: "one set, one position at a time" },
  { value: "battering_ram", label: "Battering ram", hint: "same payload in all positions" },
  { value: "pitchfork", label: "Pitchfork", hint: "sets advance in lockstep" },
  { value: "cluster_bomb", label: "Cluster bomb", hint: "every combination" },
];

export default function IntruderView({ seed, clearSeed }: Props) {
  const [scheme, setScheme] = useState("https");
  const [host, setHost] = useState("example.com");
  const [template, setTemplate] = useState(
    "GET /?q=§test§ HTTP/1.1\r\nHost: example.com\r\n\r\n"
  );
  const [marker, setMarker] = useState("§");
  const [type, setType] = useState<AttackType>("sniper");
  const [threads, setThreads] = useState(10);
  const [grep, setGrep] = useState("");
  const [payloadSets, setPayloadSets] = useState<PSet[]>([
    newPSet("admin\nroot\ntest\nguest"),
  ]);
  const [preview, setPreview] = useState<IntruderPreview | null>(null);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<IntruderResult[]>([]);
  const [error, setError] = useState("");
  const bufRef = useRef<IntruderResult[]>([]);

  useEffect(() => {
    if (seed) {
      setScheme(seed.scheme);
      setHost(seed.host);
      setTemplate(seed.requestRaw);
      clearSeed();
    }
  }, [seed, clearSeed]);

  useEffect(() => {
    const offR = on("intruder:result", (r: IntruderResult) => {
      bufRef.current.push(r);
    });
    const offD = on("intruder:done", () => {
      // Take the batch now: the updater runs later, after the reset below.
      const batch = bufRef.current;
      bufRef.current = [];
      setResults((prev) =>
        [...prev, ...batch].sort((a, b) => a.index - b.index)
      );
      setRunning(false);
    });
    // Flush the buffer periodically so a large attack stays responsive.
    const timer = setInterval(() => {
      if (bufRef.current.length) {
        const batch = bufRef.current;
        bufRef.current = [];
        setResults((prev) =>
          [...prev, ...batch].sort((a, b) => a.index - b.index)
        );
      }
    }, 250);
    return () => {
      offR();
      offD();
      clearInterval(timer);
    };
  }, []);

  const cfg = (): IntruderConfig => {
    const sets = multiSet ? payloadSets : payloadSets.slice(0, 1);
    return {
      type,
      scheme,
      host,
      template,
      marker,
      grepMatch: grep,
      threads,
      payloads: [],
      specs: sets.map(toSpec),
    };
  };

  const doPreview = async () => {
    setError("");
    try {
      setPreview(await api.previewIntruder(cfg()));
    } catch (e: any) {
      setPreview(null);
      setError(String(e?.message ?? e));
    }
  };

  const start = async () => {
    setError("");
    setResults([]);
    bufRef.current = [];
    // Set before awaiting: a short attack can emit "intruder:done" before the call returns.
    setRunning(true);
    try {
      await api.startIntruder(cfg());
    } catch (e: any) {
      setRunning(false);
      setError(String(e?.message ?? e));
    }
  };

  const stop = async () => {
    await api.stopIntruder();
    setRunning(false);
  };

  const multiSet = type === "pitchfork" || type === "cluster_bomb";
  const patchSet = (i: number, p: Partial<PSet>) =>
    setPayloadSets((prev) => prev.map((s, j) => (j === i ? { ...s, ...p } : s)));
  const toggleProc = (i: number, proc: Processor) =>
    setPayloadSets((prev) =>
      prev.map((s, j) => {
        if (j !== i) return s;
        const has = s.processors.includes(proc);
        return {
          ...s,
          processors: has
            ? s.processors.filter((p) => p !== proc)
            : [...s.processors, proc],
        };
      })
    );

  return (
    <div className="split-h">
      <div className="pane pad col" style={{ flex: "0 0 42%" }}>
        <div className="callout">
          Mark positions by wrapping a value in the <b>{marker}</b> marker, e.g.{" "}
          <span className="mono">id={marker}1{marker}</span>. Run only against
          systems you are authorised to test.
        </div>
        <div className="row">
          <label className="field">
            Scheme
            <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
          </label>
          <label className="field grow">
            Host
            <input value={host} onChange={(e) => setHost(e.target.value)} />
          </label>
          <label className="field" style={{ width: 60 }}>
            Marker
            <input value={marker} onChange={(e) => setMarker(e.target.value)} />
          </label>
        </div>
        <label className="field grow">
          Request template
          <textarea
            className="payloads"
            style={{ minHeight: 160 }}
            spellCheck={false}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
          />
        </label>
        <div className="row">
          <label className="field grow">
            Attack type
            <select
              value={type}
              onChange={(e) => setType(e.target.value as AttackType)}
            >
              {ATTACKS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label} — {a.hint}
                </option>
              ))}
            </select>
          </label>
          <label className="field" style={{ width: 80 }}>
            Threads
            <input
              type="number"
              min={1}
              value={threads}
              onChange={(e) => setThreads(Number(e.target.value) || 1)}
            />
          </label>
        </div>
        <label className="field">
          Grep-match (regexp, flags matching responses)
          <input value={grep} onChange={(e) => setGrep(e.target.value)} />
        </label>

        <div className="col">
          <div className="row">
            <b>Payload sets</b>
            {multiSet && (
              <button
                onClick={() => setPayloadSets((p) => [...p, newPSet()])}
                style={{ marginLeft: "auto" }}
              >
                + Set
              </button>
            )}
          </div>
          {(multiSet ? payloadSets : payloadSets.slice(0, 1)).map((s, i) => (
            <div className="col" key={i} style={{ borderTop: "1px solid var(--border)", paddingTop: 8 }}>
              <div className="row">
                <span className="dim">
                  {multiSet ? `Set ${i + 1} (position ${i + 1})` : "Payloads"}
                </span>
                <select
                  value={s.mode}
                  onChange={(e) => patchSet(i, { mode: e.target.value as PSet["mode"] })}
                >
                  <option value="list">List</option>
                  <option value="numbers">Numbers</option>
                </select>
                {multiSet && payloadSets.length > 1 && (
                  <button
                    className="danger"
                    style={{ marginLeft: "auto" }}
                    onClick={() =>
                      setPayloadSets((prev) => prev.filter((_, j) => j !== i))
                    }
                  >
                    ✕
                  </button>
                )}
              </div>
              {s.mode === "list" ? (
                <textarea
                  className="payloads"
                  spellCheck={false}
                  placeholder="one payload per line"
                  value={s.list}
                  onChange={(e) => patchSet(i, { list: e.target.value })}
                />
              ) : (
                <div className="row">
                  <label className="field" style={{ width: 70 }}>
                    From
                    <input type="number" value={s.from} onChange={(e) => patchSet(i, { from: Number(e.target.value) })} />
                  </label>
                  <label className="field" style={{ width: 70 }}>
                    To
                    <input type="number" value={s.to} onChange={(e) => patchSet(i, { to: Number(e.target.value) })} />
                  </label>
                  <label className="field" style={{ width: 60 }}>
                    Step
                    <input type="number" value={s.step} onChange={(e) => patchSet(i, { step: Number(e.target.value) })} />
                  </label>
                  <label className="field" style={{ width: 60 }}>
                    Pad
                    <input type="number" value={s.pad} onChange={(e) => patchSet(i, { pad: Number(e.target.value) })} />
                  </label>
                </div>
              )}
              <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
                <span className="dim">Process:</span>
                {ALL_PROCESSORS.map((proc) => (
                  <label key={proc} className="row" style={{ gap: 3 }} title={`apply ${proc} to each payload`}>
                    <input
                      type="checkbox"
                      checked={s.processors.includes(proc)}
                      onChange={() => toggleProc(i, proc)}
                    />
                    <span className="dim">{proc}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="row">
          <button onClick={doPreview}>Preview</button>
          {!running ? (
            <button className="primary" onClick={start}>
              Start attack
            </button>
          ) : (
            <button className="danger" onClick={stop}>
              Stop
            </button>
          )}
          {preview && (
            <span className="pill">
              {preview.positions} positions · {preview.requests} requests
            </span>
          )}
        </div>
        {error && <div className="callout" style={{ borderLeftColor: "var(--err)" }}>{error}</div>}
      </div>

      <div className="divider" />
      <div className="split-v" style={{ flex: 1 }}>
        <div className="toolbar">
          <b>Results</b>
          <span className="pill">{results.length}</span>
          {running && <span className="dim">running…</span>}
          <span className="grow" />
          <button onClick={() => setResults([])} disabled={running}>
            Clear
          </button>
        </div>
        <div className="pane">
          <table className="results-table">
            <thead>
              <tr>
                <th style={{ width: 50 }}>#</th>
                <th>Payload</th>
                <th style={{ width: 70 }}>Status</th>
                <th style={{ width: 80 }}>Length</th>
                <th style={{ width: 70 }}>Time</th>
                <th style={{ width: 70 }}>Match</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.index}>
                  <td className="dim">{r.index}</td>
                  <td className="mono">{r.payloads.join(" · ")}</td>
                  <td>{r.error ? "ERR" : r.statusCode}</td>
                  <td className="dim">{r.length}</td>
                  <td className="dim">{r.durationMs}ms</td>
                  <td className={r.matched ? "matched" : "dim"}>
                    {r.matched ? "✓" : ""}
                  </td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty">
                    Configure an attack and press Start.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
