import { useEffect, useState } from "react";
import { api, TrustStatus } from "../lib/api";

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

  const [trust, setTrust] = useState<TrustStatus | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [caMsg, setCaMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const changeTrust = async (install: boolean) => {
    setCaMsg(null);
    setTrustBusy(true);
    try {
      setTrust(install ? await api.installCA() : await api.removeCA());
      setCaMsg({ ok: true, text: install ? "Installed and trusted." : "Removed from this Mac." });
    } catch (e: any) {
      setCaMsg({ ok: false, text: String(e?.message ?? e) });
      api.getTrustStatus().then(setTrust).catch(() => {});
    } finally {
      setTrustBusy(false);
    }
  };

  const exportCA = async () => {
    setCaMsg(null);
    try {
      const path = await api.exportRootCA();
      if (path) setCaMsg({ ok: true, text: `Saved to ${path}` });
    } catch (e: any) {
      setCaMsg({ ok: false, text: String(e?.message ?? e) });
    }
  };

  useEffect(() => {
    api.getTrustStatus().then(setTrust).catch(() => setTrust(null));
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
        Your own browser needs to trust this certificate to intercept HTTPS (the
        Kanca browser above doesn't). The private key stays on this machine in{" "}
        <span className="mono">~/.kanca</span>. Remove the certificate when you
        are done testing. Firefox keeps its own list: <i>Settings → Privacy &amp;
        Security → View Certificates → Authorities → Import</i>.
      </div>
      {trust && (
        <p className={`trust-status ${trust.trusted ? "ok-text" : ""}`}>
          <span className={`status-dot${trust.trusted ? " on" : ""}`} />
          {trust.trusted
            ? "This computer trusts Kanca's certificates: HTTPS works in Safari, Chrome and Edge."
            : "Not trusted by this computer yet, so HTTPS sites show certificate errors in your own browser."}
        </p>
      )}
      <div className="row">
        {trust?.supported &&
          (trust.trusted ? (
            <button disabled={trustBusy} onClick={() => changeTrust(false)}>
              {trustBusy ? "Waiting for macOS…" : "Remove from this Mac"}
            </button>
          ) : (
            <button className="primary" disabled={trustBusy} onClick={() => changeTrust(true)}>
              {trustBusy ? "Waiting for macOS…" : "Install on this Mac"}
            </button>
          ))}
        <button onClick={exportCA}>Export to file…</button>
        <button onClick={copy}>{copied ? "Copied!" : "Copy PEM"}</button>
      </div>
      {trust?.supported && !trust.trusted && (
        <p className="dim">
          macOS will ask for your password or Touch ID to trust the certificate.
        </p>
      )}
      {caMsg && <p className={caMsg.ok ? "ok-text" : "err-text"}>{caMsg.text}</p>}
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
