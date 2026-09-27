import { useEffect, useState } from "react";
import { api } from "../lib/api";

export default function SettingsView() {
  const [ca, setCa] = useState("");
  const [copied, setCopied] = useState(false);
  const [scopeEnabled, setScopeEnabled] = useState(false);
  const [scopeHosts, setScopeHosts] = useState("");
  const [scopeSaved, setScopeSaved] = useState(false);

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
      <h3>Root certificate authority</h3>
      <div className="callout">
        To intercept HTTPS, import this certificate into your browser or OS
        trust store, then set your browser's proxy to the address shown in the
        title bar. The private key stays on this machine in{" "}
        <span className="mono">~/.mimlec</span>. Remove the certificate from your
        trust store when you are done testing.
      </div>
      <div className="row">
        <button onClick={copy}>{copied ? "Copied!" : "Copy PEM"}</button>
        <button
          onClick={() => api.exportRootCA("mimlec-ca.pem")}
          title="Writes mimlec-ca.pem next to the app's working directory"
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
