import { useEffect, useState } from "react";
import { api } from "../lib/api";

export default function SettingsView() {
  const [ca, setCa] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.getRootCA().then(setCa).catch(() => setCa(""));
  }, []);

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
        style={{ minHeight: 260 }}
        readOnly
        value={ca}
      />
    </div>
  );
}
