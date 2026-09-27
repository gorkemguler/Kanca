import { useCallback, useEffect, useState } from "react";
import { api, FlowView, ProxyStatus } from "./lib/api";
import HistoryView from "./components/HistoryView";
import InterceptView from "./components/InterceptView";
import RepeaterView from "./components/RepeaterView";
import IntruderView from "./components/IntruderView";
import SettingsView from "./components/SettingsView";

type TabKey = "history" | "intercept" | "repeater" | "intruder" | "settings";

export default function App() {
  const [tab, setTab] = useState<TabKey>("history");
  const [status, setStatus] = useState<ProxyStatus>({ running: false, addr: "127.0.0.1:8080" });
  const [addr, setAddr] = useState("127.0.0.1:8080");
  const [intercepting, setIntercepting] = useState(false);
  const [queueCount, setQueueCount] = useState(0);

  // Cross-tab hand-offs from History.
  const [repeaterQueue, setRepeaterQueue] = useState<number[]>([]);
  const [intruderSeed, setIntruderSeed] = useState<FlowView | null>(null);

  useEffect(() => {
    api.getStatus().then((s) => {
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

  const tabs: { key: TabKey; label: string; badge?: number }[] = [
    { key: "history", label: "Proxy History" },
    { key: "intercept", label: "Intercept", badge: queueCount || undefined },
    { key: "repeater", label: "Repeater" },
    { key: "intruder", label: "Intruder" },
    { key: "settings", label: "CA / Settings" },
  ];

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          MIMLEC <span>intercepting proxy</span>
        </div>
        <span className={"status-dot" + (status.running ? " on" : "")} />
        <span className="dim">
          {status.running ? `listening on ${status.addr}` : "stopped"}
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
        <span className="spacer" />
      </div>

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
        {tab === "settings" && <SettingsView />}
      </div>
    </div>
  );
}
