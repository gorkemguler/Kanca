import { useEffect, useState } from "react";
import { api, on, Finding, Severity } from "../lib/api";

const SEV_ORDER: Record<Severity, number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
};

const sevColor: Record<Severity, string> = {
  high: "var(--err)",
  medium: "var(--warn)",
  low: "var(--accent-2)",
  info: "var(--text-dim)",
};

interface Props {
  onOpenFlow: (flowId: number) => void;
}

export default function FindingsView({ onOpenFlow }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);

  const refresh = async () => {
    const list = await api.getFindings();
    list.sort(
      (a, b) =>
        SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.host.localeCompare(b.host)
    );
    setFindings(list);
  };

  useEffect(() => {
    refresh();
    const offFind = on("scanner:finding", () => refresh());
    const offProj = on("project:loaded", () => refresh());
    return () => {
      offFind();
      offProj();
    };
  }, []);

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Passive findings</b>
        {(["high", "medium", "low", "info"] as Severity[]).map((s) =>
          counts[s] ? (
            <span key={s} className="pill" style={{ color: sevColor[s] }}>
              {counts[s]} {s}
            </span>
          ) : null
        )}
        <span className="dim">
          detected from observed traffic — no extra requests are sent
        </span>
        <span className="grow" />
        <button onClick={() => api.clearFindings().then(refresh)}>Clear</button>
      </div>
      <div className="pane">
        <table className="results-table">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Severity</th>
              <th style={{ width: 240 }}>Issue</th>
              <th style={{ width: 200 }}>Host</th>
              <th>Detail</th>
              <th style={{ width: 90 }} />
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td style={{ color: sevColor[f.severity], fontWeight: 700 }}>
                  {f.severity.toUpperCase()}
                </td>
                <td>{f.title}</td>
                <td className="mono">{f.host}</td>
                <td className="dim">{f.detail}</td>
                <td>
                  <button onClick={() => onOpenFlow(f.flowId)}>View</button>
                </td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  No findings yet. Browse the target through the proxy and
                  passive checks will appear here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
