import { useEffect, useState } from "react";
import { api } from "../lib/api";

export default function SettingsView() {
  const [ca, setCa] = useState("");
  const [copied, setCopied] = useState(false);
  const [scopeEnabled, setScopeEnabled] = useState(false);
  const [scopeHosts, setScopeHosts] = useState("");
  const [scopeSaved, setScopeSaved] = useState(false);
  const [browserMsg, setBrowserMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [extDir, setExtDir] = useState("");
  const [extErr, setExtErr] = useState("");

  const openBrowser = async () => {
    setBrowserMsg(null);
    try {
      const name = await api.openBrowser();
      setBrowserMsg({ ok: true, text: `Opened ${name}. It starts on http://kanca/, which confirms the routing.` });
    } catch (e: any) {
      setBrowserMsg({ ok: false, text: String(e?.message ?? e) });
    }
  };

  const getExtension = async () => {
    setExtErr("");
    try {
      setExtDir(await api.exportExtension());
    } catch (e: any) {
      setExtErr(String(e?.message ?? e));
    }
  };

  useEffect(() => {
    api.getRootCA().then(setCa).catch(() => setCa(""));
    api
      .getScope()
      .then((s) => {
        setScopeEnabled(s.enabled);
        setScopeHosts((s.hosts ?? []).join("\n"));
      })
      .catch(() => {});
  }, []);

  const saveScope = async () => {
    const hosts = scopeHosts
      .split("\n")
      .map((h) => h.trim())
      .filter((h) => h.length > 0);
    await api.setScope({ enabled: scopeEnabled, hosts });
    setScopeSaved(true);
    setTimeout(() => setScopeSaved(false), 1500);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ca);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable */
    }
  };

  return (
    <div className="pane pad col" style={{ maxWidth: 820 }}>
      <h3>Browser setup</h3>
      <div className="setup-grid">
        <div className="setup-card">
          <div className="row">
            <b>Kanca browser</b>
            <span className="pill">easiest</span>
          </div>
          <p className="dim">
            Opens Chrome, Edge or Brave in a separate profile that is already
            routed through Kanca. HTTPS works straight away: nothing is added to
            your OS trust store and your everyday browser is untouched.
          </p>
          <div className="row">
            <button className="primary" onClick={openBrowser}>
              Open browser
            </button>
          </div>
          {browserMsg && <p className={browserMsg.ok ? "ok-text" : "err-text"}>{browserMsg.text}</p>}
        </div>
        <div className="setup-card">
          <b>Your own browser</b>
          <p className="dim">
            Add the Kanca extension to Chrome, Edge, Brave or Opera to switch
            the proxy on and off with one click.
          </p>
          <div className="row">
            <button onClick={getExtension}>Get the extension</button>
          </div>
          {extErr && <p className="err-text">{extErr}</p>}
          {extDir && (
            <ol className="steps">
              <li>
                Open <span className="mono">chrome://extensions</span> (Edge:{" "}
                <span className="mono">edge://extensions</span>).
              </li>
              <li>
                Turn on <b>Developer mode</b>.
              </li>
              <li>
                Click <b>Load unpacked</b> and choose{" "}
                <span className="mono">{extDir}</span> (opened for you).
              </li>
              <li>
                To intercept HTTPS, open <span className="mono">http://kanca/</span>{" "}
                through the proxy and trust the certificate.
              </li>
            </ol>
          )}
        </div>
      </div>

      <h3 style={{ marginTop: 24 }}>Root certificate authority</h3>
      <div className="callout">
        To intercept HTTPS, import this certificate into your browser or OS
        trust store, then set your browser's proxy to the address shown in the
        title bar. The private key stays on this machine in{" "}
        <span className="mono">~/.kanca</span>. Remove the certificate from your
        trust store when you are done testing.
      </div>
      <div className="row">
        <button onClick={copy}>{copied ? "Copied!" : "Copy PEM"}</button>
        <button
          onClick={() => api.exportRootCA("kanca-ca.pem")}
          title="Writes kanca-ca.pem next to the app's working directory"
        >
          Export to file
        </button>
      </div>
      <textarea
        className="payloads mono"
        style={{ minHeight: 220 }}
        readOnly
        value={ca}
      />

      <h3 style={{ marginTop: 24 }}>Target scope</h3>
      <div className="callout">
        When scope is on, only traffic to these hosts is recorded to the
        history; everything else is still proxied but not logged. One host per
        line. A bare domain covers its subdomains (<span className="mono">example.com</span>{" "}
        matches <span className="mono">api.example.com</span>); use{" "}
        <span className="mono">*.example.com</span> for subdomains only.
      </div>
      <label className="row">
        <input
          type="checkbox"
          checked={scopeEnabled}
          onChange={(e) => setScopeEnabled(e.target.checked)}
        />
        <span>Restrict recording to in-scope hosts</span>
      </label>
      <textarea
        className="payloads mono"
        style={{ minHeight: 120 }}
        spellCheck={false}
        placeholder={"example.com\n*.internal.test\n10.0.0.5"}
        value={scopeHosts}
        onChange={(e) => setScopeHosts(e.target.value)}
      />
      <div className="row">
        <button className="primary" onClick={saveScope}>
          {scopeSaved ? "Saved!" : "Save scope"}
        </button>
      </div>
    </div>
  );
}
