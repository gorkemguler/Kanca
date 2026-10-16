import { useCallback, useEffect, useState } from "react";
import { api, on, FlowView, MCPStatus, ProxyStatus, TrustStatus } from "./lib/api";
import HistoryView from "./components/HistoryView";
import InterceptView from "./components/InterceptView";
import RepeaterView from "./components/RepeaterView";
import IntruderView from "./components/IntruderView";
import RulesView from "./components/RulesView";
import ScannerView from "./components/ScannerView";
import WebSocketView from "./components/WebSocketView";
import SiteMapView from "./components/SiteMapView";
import SettingsView from "./components/SettingsView";
import AIView from "./components/AIView";

type TabKey =
  | "history"
  | "sitemap"
  | "intercept"
  | "repeater"
  | "intruder"
  | "rules"
  | "findings"
  | "websocket"
  | "ai"
  | "settings";

export default function App() {
  const [tab, setTab] = useState<TabKey>("history");
  const [status, setStatus] = useState<ProxyStatus>({ running: false, addr: "127.0.0.1:8080" });
  const [addr, setAddr] = useState("127.0.0.1:8080");
  const [intercepting, setIntercepting] = useState(false);
  const [queueCount, setQueueCount] = useState(0);
  const [busy, setBusy] = useState("");
  const [ai, setAi] = useState<MCPStatus | null>(null);
  const [trust, setTrust] = useState<TrustStatus | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [trustErr, setTrustErr] = useState("");
  const [trustLater, setTrustLater] = useState(false);

  // Cross-tab hand-offs from History / Findings.
  const [repeaterQueue, setRepeaterQueue] = useState<number[]>([]);
  const [intruderSeed, setIntruderSeed] = useState<FlowView | null>(null);
  const [focusFlow, setFocusFlow] = useState<number | null>(null);

  useEffect(() => {
    api.getMCPStatus().then(setAi).catch(() => {});
    api.getTrustStatus().then(setTrust).catch(() => {});
    // Installing or removing the certificate in CA / Settings updates the banner.
    return on("trust:status", (t: TrustStatus) => setTrust(t));
  }, []);

  const trustCA = async () => {
    setTrustErr("");
    setTrustBusy(true);
    try {
      setTrust(await api.installCA());
    } catch (e: any) {
      setTrustErr(String(e?.message ?? e));
    } finally {
      setTrustBusy(false);
    }
  };

  useEffect(() => {
    api.getStatus().then((s) => {
      setStatus(s);
      setAddr(s.addr);
    });
    // Opening the Kanca browser starts the proxy if it isn't running yet.
    return on("proxy:status", (s: ProxyStatus) => {
      setStatus(s);
      setAddr(s.addr);
    });
  }, []);

  const toggleProxy = async () => {
    if (status.running) {
      await api.stopProxy();
      setStatus({ running: false, addr });
    } else {
      const s = await api.startProxy(addr);
      setStatus(s);
      setAddr(s.addr);
    }
  };

  const sendToRepeater = useCallback((flowId: number) => {
    setRepeaterQueue((q) => [...q, flowId]);
    setTab("repeater");
  }, []);
  const sendToIntruder = useCallback((flow: FlowView) => {
    setIntruderSeed(flow);
    setTab("intruder");
  }, []);
  const openFlow = useCallback((flowId: number) => {
    setFocusFlow(flowId);
    setTab("history");
  }, []);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    try {
      await fn();
    } catch (e: any) {
      // Surface backend errors without a modal dependency.
      console.error(e);
      alert(`${label} failed: ${e?.message ?? e}`);
    } finally {
      setBusy("");
    }
  };

  const tabs: { key: TabKey; label: string; badge?: number }[] = [
    { key: "history", label: "Proxy History" },
    { key: "sitemap", label: "Site Map" },
    { key: "intercept", label: "Intercept", badge: queueCount || undefined },
    { key: "repeater", label: "Repeater" },
    { key: "intruder", label: "Intruder" },
    { key: "rules", label: "Match/Replace" },
    { key: "findings", label: "Scanner" },
    { key: "websocket", label: "WebSocket" },
    { key: "ai", label: "AI Assistant" },
    { key: "settings", label: "CA / Settings" },
  ];

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <svg
            className="brand-mark"
            viewBox="0 0 256 256"
            width="22"
            height="22"
            aria-hidden="true"
          >
            <g
              fill="none"
              stroke="currentColor"
              strokeWidth={22}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="150" cy="58" r="18" />
              <path d="M150 76 L150 150 C150 182 150 198 126 198 C100 198 86 178 86 154 C86 138 95 128 108 124" />
              <path d="M108 124 L96 140" />
            </g>
            <rect
              x="120"
              y="150"
              width="22"
              height="22"
              rx="5"
              transform="rotate(45 131 161)"
              fill="var(--accent-2)"
            />
          </svg>
          KANCA <span>intercepting proxy</span>
        </div>
        <span className={"status-dot" + (status.running ? " on" : "")} />
        <span className="dim status-text">
          {status.running ? (
            <>
              listening<span className="wide-only"> on {status.addr}</span>
            </>
          ) : (
            "stopped"
          )}
        </span>
        <input
          className="addr-input"
          value={addr}
          disabled={status.running}
          onChange={(e) => setAddr(e.target.value)}
        />
        <button className={status.running ? "danger" : "primary"} onClick={toggleProxy}>
          {status.running ? "Stop proxy" : "Start proxy"}
        </button>
        <button
          disabled={!!busy}
          title="Open Chrome, Edge or Brave in a separate profile that is already routed through Kanca. HTTPS works without installing the certificate."
          onClick={() => run("Open browser", async () => void (await api.openBrowser()))}
        >
          Open browser
        </button>
        <span className="grow" />
        {ai?.running && (
          <button
            className="ai-on"
            title={`AI assistants can use Kanca (${ai.level === "read" ? "read only" : "read and test"}${ai.mask ? ", secrets masked" : ""})`}
            onClick={() => setTab("ai")}
          >
            <span className="status-dot on" />
            AI on
          </button>
        )}
        <button disabled={!!busy} onClick={() => run("Open project", api.loadProject)}>
          Open
        </button>
        <button disabled={!!busy} onClick={() => run("Save project", api.saveProject)}>
          Save
        </button>
        <button disabled={!!busy} onClick={() => run("Import HAR", api.importHAR)}>
          Import HAR
        </button>
        <button disabled={!!busy} onClick={() => run("Export HAR", api.exportHAR)}>
          Export HAR
        </button>
      </div>

      {trust?.supported && !trust.trusted && !trustLater && (
        <div className="trust-banner">
          <span className="grow">
            <b>HTTPS isn't trusted yet.</b> Your own browser shows certificate warnings
            until this Mac trusts Kanca's certificate. (Open browser works without it.)
            {trustErr && <span className="err-text"> {trustErr}</span>}
          </span>
          <button className="primary" disabled={trustBusy} onClick={trustCA}>
            {trustBusy ? "Waiting for macOS…" : "Trust certificate"}
          </button>
          <button disabled={trustBusy} onClick={() => setTrustLater(true)}>
            Not now
          </button>
        </div>
      )}

      <div className="tabs">
        {tabs.map((t) => (
          <div
            key={t.key}
            className={"tab" + (tab === t.key ? " active" : "")}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            {t.badge ? <span className="badge">{t.badge}</span> : null}
          </div>
        ))}
      </div>

      <div className="content">
        {tab === "history" && (
          <HistoryView
            onSendToRepeater={sendToRepeater}
            onSendToIntruder={sendToIntruder}
            focusFlow={focusFlow}
            clearFocus={() => setFocusFlow(null)}
          />
        )}
        {tab === "intercept" && (
          <InterceptView
            intercepting={intercepting}
            setIntercepting={setIntercepting}
            onQueueChange={setQueueCount}
          />
        )}
        {tab === "repeater" && (
          <RepeaterView
            pending={repeaterQueue}
            clearPending={() => setRepeaterQueue([])}
          />
        )}
        {tab === "intruder" && (
          <IntruderView seed={intruderSeed} clearSeed={() => setIntruderSeed(null)} />
        )}
        {tab === "rules" && <RulesView />}
        {tab === "findings" && <ScannerView onOpenFlow={openFlow} />}
        {tab === "websocket" && <WebSocketView />}
        {tab === "sitemap" && <SiteMapView onOpenFindings={() => setTab("findings")} />}
        {tab === "ai" && <AIView onStatus={setAi} onOpenTargets={() => setTab("findings")} />}
        {tab === "settings" && <SettingsView />}
      </div>
    </div>
  );
}
