import { useEffect, useState } from "react";
import {
  api,
  hostOf,
  isNotTarget,
  on,
  SiteMapNode,
  SiteScanDone,
  SiteScanPlan,
  SiteScanProgress,
} from "../lib/api";
import { useCoalescedRefresh } from "../lib/coalesce";

function statusClass(code?: number): string {
  if (!code) return "dim";
  if (code >= 500) return "status-5";
  if (code >= 400) return "status-4";
  if (code >= 300) return "status-3";
  if (code >= 200) return "status-2";
  return "";
}

function TreeNode({
  node,
  depth,
  onScan,
}: {
  node: SiteMapNode;
  depth: number;
  onScan?: (host: string) => void;
}) {
  const kids = node.children ?? [];
  const [open, setOpen] = useState(depth < 1);
  const hasKids = kids.length > 0;

  return (
    <div>
      <div
        className="row"
        style={{
          padding: "3px 8px",
          paddingLeft: 8 + depth * 16,
          cursor: hasKids ? "pointer" : "default",
          borderBottom: "1px solid var(--bg-elev)",
        }}
        onClick={() => hasKids && setOpen(!open)}
      >
        <span className="dim" style={{ width: 12, display: "inline-block" }}>
          {hasKids ? (open ? "▾" : "▸") : ""}
        </span>
        {node.method && (
          <span className="method" style={{ minWidth: 44 }}>
            {node.method}
          </span>
        )}
        <span className="mono grow" title={node.url || node.path}>
          {depth === 0 ? node.name : "/" + node.name}
        </span>
        {node.statusCode ? (
          <span className={"pill " + statusClass(node.statusCode)}>
            {node.statusCode}
          </span>
        ) : null}
        <span className="pill dim">{node.count}</span>
        {onScan && (
          <button
            className="scan-site"
            title="Actively scan every captured request with parameters on this site"
            onClick={(e) => {
              e.stopPropagation();
              onScan(node.name);
            }}
          >
            Scan site
          </button>
        )}
      </div>
      {open &&
        kids.map((c, i) => <TreeNode key={i} node={c} depth={depth + 1} />)}
    </div>
  );
}

interface Props {
  onOpenFindings: () => void;
}

function errText(e: unknown): string {
  return String((e as any)?.message ?? e);
}

export default function SiteMapView({ onOpenFindings }: Props) {
  const [roots, setRoots] = useState<SiteMapNode[]>([]);
  const [scanHost, setScanHost] = useState<string | null>(null);
  const [plan, setPlan] = useState<SiteScanPlan | null>(null);
  const [planErr, setPlanErr] = useState("");
  const [includeUnsafe, setIncludeUnsafe] = useState(false);
  const [aggressive, setAggressive] = useState(false);
  const [progress, setProgress] = useState<SiteScanProgress | null>(null);
  const [done, setDone] = useState<SiteScanDone | null>(null);

  const refresh = useCoalescedRefresh(async () => setRoots(await api.getSiteMap()));

  useEffect(() => {
    refresh();
    // A scan started earlier keeps running while other tabs are open.
    api.siteScanStatus().then((p) => p && setProgress(p)).catch(() => {});
    const offs = [
      on("proxy:flow", () => refresh()),
      on("project:loaded", () => refresh()),
      on("sitescan:progress", (p: SiteScanProgress) => setProgress(p)),
      on("sitescan:done", (d: SiteScanDone) => {
        setProgress(null);
        setDone(d);
      }),
    ];
    return () => offs.forEach((off) => off());
  }, []);

  const openScan = async (host: string) => {
    setScanHost(host);
    setPlan(null);
    setPlanErr("");
    setDone(null);
    setIncludeUnsafe(false);
    setAggressive(false);
    try {
      setPlan(await api.planSiteScan(host));
    } catch (e) {
      setPlanErr(errText(e));
    }
  };

  const addTarget = async () => {
    if (!scanHost) return;
    await api.addTarget(scanHost);
    openScan(scanHost);
  };

  const start = async () => {
    if (!scanHost || !plan) return;
    try {
      await api.scanSite(scanHost, includeUnsafe, aggressive);
      setProgress({
        host: scanHost,
        done: 0,
        total: plan.safe + (includeUnsafe ? plan.unsafe : 0),
        current: "",
        found: 0,
      });
      setScanHost(null);
    } catch (e) {
      setPlanErr(errText(e));
    }
  };

  const toScan = plan ? plan.safe + (includeUnsafe ? plan.unsafe : 0) : 0;

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Site map</b>
        <span className="dim">endpoints observed through the proxy, by host</span>
        <span className="grow" />
        <button onClick={refresh}>Refresh</button>
      </div>

      {progress && (
        <div className="scan-status">
          <span>
            Scanning <b>{hostOf(progress.host)}</b>: {progress.done} of {progress.total}
            {progress.found > 0 && <> · {progress.found} found</>}
          </span>
          <span className="scan-bar">
            <span style={{ width: `${(100 * progress.done) / Math.max(progress.total, 1)}%` }} />
          </span>
          <span className="dim mono grow scan-current" title={progress.current}>
            {progress.current}
          </span>
          <button onClick={() => api.stopSiteScan()}>Stop</button>
        </div>
      )}

      {done && !progress && (
        <div className="scan-status">
          <span className="grow">
            {done.stopped ? "Stopped" : "Finished"} scanning <b>{hostOf(done.host)}</b>:{" "}
            {done.scanned} request{done.scanned === 1 ? "" : "s"} probed,{" "}
            {done.found === 0 ? "nothing new found." : <b>{done.found} new finding{done.found === 1 ? "" : "s"}.</b>}
          </span>
          <button className="primary" onClick={onOpenFindings}>
            Open Findings
          </button>
          <button onClick={() => setDone(null)}>Dismiss</button>
        </div>
      )}

      {scanHost && (
        <div className="scan-panel">
          <b>Scan {hostOf(scanHost)}</b>
          {planErr && isNotTarget(planErr) ? (
            <>
              <p>
                <span className="mono">{hostOf(scanHost)}</span> isn't one of your
                targets yet. Kanca only scans targets; add it if you're allowed to
                test this site.
              </p>
              <div className="row">
                <button className="primary" onClick={addTarget}>
                  Add as target
                </button>
                <button onClick={() => setScanHost(null)}>Cancel</button>
              </div>
            </>
          ) : planErr ? (
            <>
              <p className="err-text">{planErr}</p>
              <div className="row">
                <button onClick={() => setScanHost(null)}>Close</button>
              </div>
            </>
          ) : !plan ? (
            <p className="dim">Looking at the captured requests…</p>
          ) : plan.safe + plan.unsafe === 0 ? (
            <>
              <p>
                Kanca hasn't captured any requests with parameters on this site
                yet. Browse it through Kanca (search, filters, links with{" "}
                <span className="mono">?id=</span>, forms) and try again.
              </p>
              <div className="row">
                <button onClick={() => setScanHost(null)}>Close</button>
              </div>
            </>
          ) : (
            <>
              <p>
                Kanca will probe <b>{plan.safe}</b> captured GET request
                {plan.safe === 1 ? "" : "s"} with parameters for reflected XSS, SQL
                injection, path traversal, open redirect, template injection and
                CRLF injection, one at a time. Findings appear in the Findings tab.
              </p>
              {plan.unsafe > 0 && (
                <label className="ai-option">
                  <input
                    type="checkbox"
                    checked={includeUnsafe}
                    onChange={(e) => setIncludeUnsafe(e.target.checked)}
                  />
                  <span>
                    Also scan {plan.unsafe} form or API submission
                    {plan.unsafe === 1 ? "" : "s"} (POST, PUT, PATCH){" "}
                    <span className="dim">
                      — every probe submits it again, e.g. sends a contact form
                      dozens of times.
                    </span>
                  </span>
                </label>
              )}
              <label className="ai-option">
                <input
                  type="checkbox"
                  checked={aggressive}
                  onChange={(e) => setAggressive(e.target.checked)}
                />
                <span>
                  Aggressive checks{" "}
                  <span className="dim">
                    — boolean/time-based SQL injection and command injection, which
                    make the server do real work (e.g. deliberate delays).
                  </span>
                </span>
              </label>
              <div className="row">
                <button className="primary" disabled={toScan === 0} onClick={start}>
                  Scan {toScan} request{toScan === 1 ? "" : "s"}
                </button>
                <button onClick={() => setScanHost(null)}>Cancel</button>
              </div>
            </>
          )}
        </div>
      )}

      <div className="pane">
        {roots.length === 0 ? (
          <div className="empty">
            No traffic yet. Browse a target through the proxy to build its map.
          </div>
        ) : (
          roots.map((r, i) => (
            <TreeNode key={i} node={r} depth={0} onScan={progress ? undefined : openScan} />
          ))
        )}
      </div>
    </div>
  );
}
