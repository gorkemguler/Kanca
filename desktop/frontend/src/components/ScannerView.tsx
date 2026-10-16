import { useEffect, useState } from "react";
import { api, hostOf, matchesTarget, on, Finding, FindingStatus, ScopeConfig, Severity } from "../lib/api";
import { ScanPlanPanel, ScanStatusBar, useSiteScan } from "./SiteScan";

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

const STATUS_LABEL: Record<string, string> = {
  new: "new",
  confirmed: "confirmed",
  resolved: "resolved",
  "false-positive": "false positive",
};

function statusOf(f: Finding): FindingStatus {
  return f.status ?? "new";
}

interface Props {
  onOpenFlow: (flowId: number) => void;
}

export default function ScannerView({ onOpenFlow }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scope, setScope] = useState<ScopeConfig>({ enabled: false, hosts: [] });
  const [newTarget, setNewTarget] = useState("");
  const [planOpen, setPlanOpen] = useState(false);
  const [onlyTargets, setOnlyTargets] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("open");
  const [statusErr, setStatusErr] = useState("");
  const { progress } = useSiteScan();
  const targets = scope.hosts ?? [];

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
    api.getScope().then(setScope).catch(() => {});
    const offs = [
      on("scanner:finding", () => refresh()),
      on("project:loaded", () => refresh()),
      // Targets added from the site map or history show up here too.
      on("scope:changed", (s: ScopeConfig) => setScope(s)),
    ];
    return () => offs.forEach((off) => off());
  }, []);

  const addTarget = async () => {
    const t = newTarget.trim();
    if (!t) return;
    setScope(await api.addTarget(t));
    setNewTarget("");
  };

  const saveScope = async (cfg: ScopeConfig) => {
    await api.setScope(cfg);
    setScope(await api.getScope());
  };

  const shown =
    onlyTargets && targets.length > 0
      ? findings.filter((f) => matchesTarget(hostOf(f.host), targets))
      : findings;
  const visible =
    statusFilter === "all"
      ? shown
      : statusFilter === "open"
        ? shown.filter((f) => statusOf(f) === "new" || statusOf(f) === "confirmed")
        : shown.filter((f) => statusOf(f) === statusFilter);
  const counts = visible.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const setStatus = async (f: Finding, status: FindingStatus) => {
    setStatusErr("");
    try {
      await api.setFindingStatus(f.id, status);
      refresh();
    } catch (e: any) {
      setStatusErr("Set status failed: " + (e?.message ?? e));
    }
  };

  return (
    <div className="split-v">
      <div className="scanner-targets">
        <div className="row wrap">
          <b>Targets</b>
          {targets.length === 0 ? (
            <span className="dim">
              Add the sites you're allowed to test. Kanca only scans targets, and a
              domain covers its subdomains.
            </span>
          ) : (
            targets.map((h) => (
              <span key={h} className="target-chip">
                <span className="mono">{h}</span>
                <button
                  title={`Remove ${h}`}
                  onClick={() => saveScope({ ...scope, hosts: targets.filter((x) => x !== h) })}
                >
                  ×
                </button>
              </span>
            ))
          )}
        </div>
        <div className="row">
          <input
            className="grow"
            placeholder="Add a target: example.com, *.example.com or a URL"
            spellCheck={false}
            value={newTarget}
            onChange={(e) => setNewTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addTarget()}
          />
          <button disabled={!newTarget.trim()} onClick={addTarget}>
            Add target
          </button>
          <button
            className="primary"
            disabled={targets.length === 0 || !!progress}
            title="Actively scan every captured request with parameters on your targets"
            onClick={() => setPlanOpen(true)}
          >
            Scan targets
          </button>
        </div>
        <label className="row dim">
          <input
            type="checkbox"
            checked={scope.enabled}
            onChange={(e) => saveScope({ ...scope, enabled: e.target.checked })}
          />
          <span>Only record traffic to targets (other sites are still proxied, just not logged)</span>
        </label>
      </div>

      <ScanStatusBar />
      {planOpen && <ScanPlanPanel host="" onClose={() => setPlanOpen(false)} />}

      <div className="toolbar">
        <b>Findings</b>
        {(["high", "medium", "low", "info"] as Severity[]).map((s) =>
          counts[s] ? (
            <span key={s} className="pill" style={{ color: sevColor[s] }}>
              {counts[s]} {s}
            </span>
          ) : null
        )}
        <span className="dim">
          passive checks run on everything you browse; scans add active results
        </span>
        <span className="grow" />
        {statusErr && <span className="err-text">{statusErr}</span>}
        <select
          title="Filter by triage status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="open">open (new + confirmed)</option>
          <option value="all">all statuses</option>
          <option value="new">new</option>
          <option value="confirmed">confirmed</option>
          <option value="resolved">resolved</option>
          <option value="false-positive">false positive</option>
        </select>
        {targets.length > 0 && (
          <label className="row" title="Hide findings for sites that aren't targets">
            <input
              type="checkbox"
              checked={onlyTargets}
              onChange={(e) => setOnlyTargets(e.target.checked)}
            />
            <span className="dim">only targets</span>
          </label>
        )}
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
              <th style={{ width: 130 }}>Status</th>
              <th style={{ width: 90 }} />
            </tr>
          </thead>
          <tbody>
            {visible.map((f) => (
              <tr key={f.id}>
                <td style={{ color: sevColor[f.severity], fontWeight: 700 }}>
                  {f.severity.toUpperCase()}
                </td>
                <td>
                  {f.source === "ai" && (
                    <span className="ai-tag" title="Reported by an AI assistant">
                      AI
                    </span>
                  )}
                  {f.title}
                </td>
                <td className="mono">{f.host}</td>
                <td className="dim">{f.detail}</td>
                <td>
                  <select
                    title="Triage status"
                    value={statusOf(f)}
                    onChange={(e) => setStatus(f, e.target.value as FindingStatus)}
                  >
                    {(["new", "confirmed", "resolved", "false-positive"] as FindingStatus[]).map(
                      (s) => (
                        <option key={s} value={s}>
                          {STATUS_LABEL[s]}
                        </option>
                      )
                    )}
                  </select>
                </td>
                <td>
                  {f.flowId > 0 && <button onClick={() => onOpenFlow(f.flowId)}>View</button>}
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  {targets.length === 0
                    ? "No findings yet. Add your target above, browse it through Kanca, then click Scan targets."
                    : "No findings for your targets yet. Browse them through Kanca, then click Scan targets."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
