import { useState } from "react";
import { api, copyText, JwtToken } from "../lib/api";

/** JWT workbench: decode, edit the payload, re-sign (HMAC) or strip to
 *  "none", and verify against a secret. For authorised testing only. */
export default function JwtView() {
  const [token, setToken] = useState("");
  const [decoded, setDecoded] = useState<JwtToken | null>(null);
  const [payloadText, setPayloadText] = useState("");
  const [alg, setAlg] = useState("HS256");
  const [secret, setSecret] = useState("");
  const [output, setOutput] = useState("");
  const [verdict, setVerdict] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [copied, setCopied] = useState(false);

  const decode = async (raw?: string) => {
    const input = (raw ?? token).trim();
    setErr("");
    setVerdict("");
    setOutput("");
    setBusy("decode");
    try {
      const t = await api.decodeJWT(input);
      setDecoded(t);
      // The raw segment, not the number-coerced map: JSON.parse in the
      // webview rounds integers above 2^53.
      setPayloadText(t.payloadJson);
      setAlg(t.alg);
    } catch (e: any) {
      setDecoded(null);
      setErr(e?.message ?? String(e));
    } finally {
      setBusy("");
    }
  };

  const sign = async () => {
    setErr("");
    setVerdict("");
    setBusy("sign");
    try {
      // Keep the decoded header fields (e.g. kid) and let the backend write
      // the selected alg into the signed header.
      const header = decoded?.headerJson || "{}";
      const out = await api.signJWT(header, payloadText, alg, secret);
      setOutput(out);
      setToken(out);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy("");
    }
  };

  const verify = async () => {
    setErr("");
    setBusy("verify");
    try {
      const ok = await api.verifyJWT(token.trim(), secret);
      setVerdict(ok ? "signature valid for this secret" : "signature INVALID for this secret");
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy("");
    }
  };

  const copyOut = async () => {
    if (!output) return;
    if (await copyText(output)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } else {
      setErr("Copy failed in this browser — select the token manually.");
    }
  };

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>JWT</b>
        <span className="dim">decode · edit · sign · verify (HMAC + none)</span>
        <span className="grow" />
        <button className="primary" onClick={() => decode()} disabled={!token.trim() || !!busy}>
          {busy === "decode" ? "Decoding…" : "Decode"}
        </button>
      </div>
      {err && <div className="err-text" style={{ padding: "4px 12px" }}>{err}</div>}
      <div className="split-h" style={{ flex: "0 0 44%" }}>
        <div className="split-v" style={{ flex: 1 }}>
          <div className="toolbar">
            <b>Token</b>
            <span className="grow" />
            <button
              onClick={() => setToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")}
              title="Load the jwt.io example token"
            >
              Sample
            </button>
          </div>
          <textarea
            className="pane msg"
            style={{ flex: 1, resize: "none" }}
            spellCheck={false}
            aria-label="JWT token"
            placeholder="paste a JWT here…"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </div>
        <div className="divider" />
        <div className="split-v" style={{ flex: 1 }}>
          <div className="toolbar">
            <b>Header</b>
            {decoded && (
              <span className="pill" title={decoded.unsigned ? "no signature part" : "signed"}>
                {decoded.alg}
                {decoded.unsigned ? " · unsigned" : ""}
              </span>
            )}
          </div>
          <div className="pane msg" style={{ flex: "0 0 32%", overflow: "auto" }}>
            <pre style={{ margin: 0 }}>{decoded ? decoded.headerJson : "—"}</pre>
          </div>
          <div className="toolbar">
            <b>Payload (editable)</b>
          </div>
          <textarea
            className="pane msg"
            style={{ flex: 1, resize: "none" }}
            spellCheck={false}
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            placeholder="decode a token first…"
          />
        </div>
      </div>
      <div className="divider" />
      <div className="toolbar">
        <label className="row" title="HS256/HS384/HS512 need the secret; none strips the signature">
          <span className="dim">alg</span>
          <select value={alg} onChange={(e) => setAlg(e.target.value)}>
            <option value="HS256">HS256</option>
            <option value="HS384">HS384</option>
            <option value="HS512">HS512</option>
            <option value="none">none (unsigned)</option>
          </select>
        </label>
        <input
          className="grow"
          type="password"
          aria-label="HMAC secret"
          placeholder="HMAC secret (empty is allowed)"
          title="An empty secret signs a trivially forgeable token — only useful for testing empty-secret acceptance"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
        />
        {secret === "" && alg !== "none" && (
          <span className="dim" title="The forged token will verify against an empty secret only">
            empty secret
          </span>
        )}
        <button className="primary" onClick={sign} disabled={!payloadText || !!busy} title="Rebuild the token from the edited payload">
          {busy === "sign" ? "Signing…" : "Sign"}
        </button>
        <button onClick={verify} disabled={!token.trim() || !!busy} title="Check the token against the secret">
          {busy === "verify" ? "Checking…" : "Verify"}
        </button>
      </div>
      {(output || verdict) && (
        <div className="toolbar" style={{ borderTop: "1px solid var(--border)" }}>
          {verdict && <b style={{ color: verdict.startsWith("signature valid") ? "var(--ok)" : "var(--err)" }}>{verdict}</b>}
          {output && (
            <>
              <span className="mono dim grow" title={output}>
                {output.length > 90 ? output.slice(0, 90) + "…" : output}
              </span>
              <button onClick={copyOut}>{copied ? "Copied ✓" : "Copy token"}</button>
              <button
                onClick={() => {
                  const out = output;
                  setToken(out);
                  void decode(out);
                }}
              >
                Load back
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
