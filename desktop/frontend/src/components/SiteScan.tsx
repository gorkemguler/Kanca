import { useEffect, useState } from "react";
import {
  api,
  hostOf,
  isNotTarget,
  on,
  SiteScanDone,
  SiteScanPlan,
  SiteScanProgress,
} from "../lib/api";

function errText(e: unknown): string {
  return String((e as any)?.message ?? e);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** What a scan covers: one site, or every target when host is "". */
function scanLabel(host: string): string {
  return host ? hostOf(host) : "your targets";
}

interface PanelProps {
  /** host:port as the site map shows it, or "" for every target. */
  host: string;
  onClose: () => void;
}

/** ScanPlanPanel shows what a scan would probe and starts it. */
export function ScanPlanPanel({ host, onClose }: PanelProps) {
  const [plan, setPlan] = useState<SiteScanPlan | null>(null);
  const [err, setErr] = useState("");
  const [includeUnsafe, setIncludeUnsafe] = useState(false);
  const [includeDelete, setIncludeDelete] = useState(false);
  const [aggressive, setAggressive] = useState(false);
  const [plus, setPlus] = useState(false);
  const [skipQuery, setSkipQuery] = useState(false);
  const [skipBody, setSkipBody] = useState(false);
  const [skipJson, setSkipJson] = useState(false);

  const opts = {
    includeUnsafe,
    includeDelete,
    aggressive,
    plus,
    skipQuery,
    skipBody,
    skipJson,
  };

  const load = async () => {
    setPlan(null);
    setErr("");
    try {
      setPlan(await api.planSiteScan(host, opts));
    } catch (e) {
      setErr(errText(e));
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host, includeDelete, plus, skipQuery, skipBody, skipJson]);

  const addTarget = async () => {
    await api.addTarget(host);
    load();
  };

  const start = async () => {
    try {
      await api.scanSite(host, opts);
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };

  const toScan = plan ? plan.safe + (includeUnsafe ? plan.unsafe : 0) : 0;

  return (
    <div className="scan-panel">
      <b>Scan {scanLabel(host)}</b>
      {err && host && isNotTarget(err) ? (
        <>
          <p>
            <span className="mono">{hostOf(host)}</span> isn't one of your targets
            yet. Kanca only scans targets; add it if you're allowed to test this
            site.
          </p>
          <div className="row">
            <button className="primary" onClick={addTarget}>
              Add as target
            </button>
            <button onClick={onClose}>Cancel</button>
          </div>
        </>
      ) : err ? (
        <>
          <p className="err-text">{err}</p>
          <div className="row">
            <button onClick={onClose}>Close</button>
          </div>
        </>
      ) : !plan ? (
        <p className="dim">Looking at the captured requests…</p>
      ) : plan.safe + plan.unsafe === 0 ? (
        <>
          <p>
            Kanca hasn't captured any requests with parameters on{" "}
            {scanLabel(host)} yet, so there is nothing to probe. Browse the site
            through Kanca first: search, filters, links with{" "}
            <span className="mono">?id=</span>, forms. Kanca's passive checks
            (below) still run on everything you browse.
          </p>
          <div className="row">
            <button onClick={onClose}>Close</button>
          </div>
        </>
      ) : (
        <>
          <p>
            Kanca will probe <b>{plural(plan.safe, "captured GET request")}</b>
            {plus ? "" : " with parameters"} for reflected XSS, SQL injection, path
            traversal, open redirect, template injection and CRLF injection
            {plus && <>, plus the ActiveScan++ checks</>}, one at a time.
          </p>
          {plan.unsafe > 0 && (
            <label className="ai-option">
              <input
                type="checkbox"
                checked={includeUnsafe}
                onChange={(e) => setIncludeUnsafe(e.target.checked)}
              />
              <span>
                Also scan {plural(plan.unsafe, "form or API submission")} (POST, PUT,
                PATCH{includeDelete ? ", DELETE" : ""}){" "}
                <span className="dim">
                  — every probe submits it again, e.g. sends a contact form dozens
                  of times.
                </span>
              </span>
            </label>
          )}
          <label className="ai-option">
            <input
              type="checkbox"
              checked={includeDelete}
              onChange={(e) => setIncludeDelete(e.target.checked)}
            />
            <span>
              Include DELETE requests{" "}
              <span className="dim">— probes never delete without this opt-in.</span>
            </span>
          </label>
          <div className="row dim" style={{ gap: 12 }}>
            <span>Probe:</span>
            <label className="row">
              <input
                type="checkbox"
                checked={!skipQuery}
                onChange={(e) => setSkipQuery(!e.target.checked)}
              />
              <span>query</span>
            </label>
            <label className="row">
              <input
                type="checkbox"
                checked={!skipBody}
                onChange={(e) => setSkipBody(!e.target.checked)}
              />
              <span>form body</span>
            </label>
            <label className="row">
              <input
                type="checkbox"
                checked={!skipJson}
                onChange={(e) => setSkipJson(!e.target.checked)}
              />
              <span>JSON body</span>
            </label>
          </div>
          <label className="ai-option">
            <input
              type="checkbox"
              checked={aggressive}
              onChange={(e) => setAggressive(e.target.checked)}
            />
            <span>
              Aggressive checks{" "}
              <span className="dim">
                — boolean/time-based SQL injection and command injection, which make
                the server do real work (e.g. deliberate delays).
              </span>
            </span>
          </label>
          <label className="ai-option">
            <input
              type="checkbox"
              checked={plus}
              onChange={(e) => setPlus(e.target.checked)}
            />
            <span>
              ActiveScan++ checks{" "}
              <span className="dim">
                — Host header poisoning, Edge Side Includes, suspicious input
                transformations, XML and SAML handling, exposed files and known CVEs
                (Rails, Next.js, PHP). Requests without parameters are scanned too.
              </span>
            </span>
          </label>
          <div className="row">
            <button className="primary" disabled={toScan === 0} onClick={start}>
              Scan {plural(toScan, "request")}
            </button>
            <button onClick={onClose}>Cancel</button>
          </div>
        </>
      )}
    </div>
  );
}

interface StatusProps {
  /** Shown after a scan finishes when the findings live elsewhere. */
  onOpenFindings?: () => void;
}

/** useSiteScan follows the running site scan, if any. */
export function useSiteScan() {
  const [progress, setProgress] = useState<SiteScanProgress | null>(null);
  const [done, setDone] = useState<SiteScanDone | null>(null);
  useEffect(() => {
    // A scan started earlier keeps running while other tabs are open.
    api.siteScanStatus().then((p) => p && setProgress(p)).catch(() => {});
    const offs = [
      on("sitescan:progress", (p: SiteScanProgress) => {
        setDone(null);
        setProgress(p);
      }),
      on("sitescan:done", (d: SiteScanDone) => {
        setProgress(null);
        setDone(d);
      }),
    ];
    return () => offs.forEach((off) => off());
  }, []);
  return { progress, done, clearDone: () => setDone(null) };
}

/** ScanStatusBar shows a running scan's progress, then its result. */
export function ScanStatusBar({ onOpenFindings }: StatusProps) {
  const { progress, done, clearDone } = useSiteScan();
  if (progress) {
    return (
      <div className="scan-status">
        <span>
          Scanning <b>{scanLabel(progress.host)}</b>: {progress.done} of {progress.total}
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
    );
  }
  if (!done) return null;
  return (
    <div className="scan-status">
      <span className="grow">
        {done.stopped ? "Stopped" : "Finished"} scanning <b>{scanLabel(done.host)}</b>:{" "}
        {plural(done.scanned, "request")} probed,{" "}
        {done.found === 0 ? "nothing new found." : <b>{plural(done.found, "new finding")}.</b>}
        {done.errors > 0 && (
          <span className="err-text" title={done.errorSample}>
            {" "}{plural(done.errors, "request")} failed to probe.
          </span>
        )}
      </span>
      {onOpenFindings && (
        <button className="primary" onClick={onOpenFindings}>
          Open Scanner
        </button>
      )}
      <button onClick={clearDone}>Dismiss</button>
    </div>
  );
}
