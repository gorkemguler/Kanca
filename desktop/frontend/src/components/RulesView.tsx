import { useEffect, useState } from "react";
import { api, Rule, RulePart, RulePhase } from "../lib/api";

const emptyRule = (): Rule => ({
  id: 0,
  name: "New rule",
  enabled: true,
  phase: "request",
  part: "headers",
  match: "",
  replace: "",
  host: "",
});

export default function RulesView() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getRules().then(setRules).catch(() => setRules([]));
  }, []);

  const patch = (i: number, p: Partial<Rule>) =>
    setRules((prev) => prev.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const remove = (i: number) =>
    setRules((prev) => prev.filter((_, j) => j !== i));

  const save = async () => {
    setError("");
    try {
      await api.setRules(rules);
      const fresh = await api.getRules();
      setRules(fresh);
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e: any) {
      setError(String(e?.message ?? e));
    }
  };

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Match &amp; replace</b>
        <span className="dim">
          regex substitutions applied on the wire (request out, response in)
        </span>
        <span className="grow" />
        <button onClick={() => setRules((p) => [...p, emptyRule()])}>+ Rule</button>
        <button className="primary" onClick={save}>
          {saved ? "Saved!" : "Save rules"}
        </button>
      </div>
      {error && (
        <div className="pad">
          <div className="callout" style={{ borderLeftColor: "var(--err)" }}>
            {error}
          </div>
        </div>
      )}
      <div className="pane">
        <table className="results-table">
          <thead>
            <tr>
              <th style={{ width: 40 }}>On</th>
              <th style={{ width: 140 }}>Name</th>
              <th style={{ width: 90 }}>Phase</th>
              <th style={{ width: 100 }}>Part</th>
              <th>Match (regex)</th>
              <th>Replace</th>
              <th style={{ width: 140 }}>Host (optional)</th>
              <th style={{ width: 40 }} />
            </tr>
          </thead>
          <tbody>
            {rules.map((r, i) => (
              <tr key={i}>
                <td>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={(e) => patch(i, { enabled: e.target.checked })}
                  />
                </td>
                <td>
                  <input
                    style={{ width: "100%" }}
                    value={r.name}
                    onChange={(e) => patch(i, { name: e.target.value })}
                  />
                </td>
                <td>
                  <select
                    value={r.phase}
                    onChange={(e) =>
                      patch(i, { phase: e.target.value as RulePhase })
                    }
                  >
                    <option value="request">request</option>
                    <option value="response">response</option>
                  </select>
                </td>
                <td>
                  <select
                    value={r.part}
                    onChange={(e) =>
                      patch(i, { part: e.target.value as RulePart })
                    }
                  >
                    <option value="first_line">first line</option>
                    <option value="headers">headers</option>
                    <option value="body">body</option>
                  </select>
                </td>
                <td>
                  <input
                    className="mono"
                    style={{ width: "100%" }}
                    value={r.match}
                    onChange={(e) => patch(i, { match: e.target.value })}
                  />
                </td>
                <td>
                  <input
                    className="mono"
                    style={{ width: "100%" }}
                    value={r.replace}
                    onChange={(e) => patch(i, { replace: e.target.value })}
                  />
                </td>
                <td>
                  <input
                    style={{ width: "100%" }}
                    placeholder="any"
                    value={r.host ?? ""}
                    onChange={(e) => patch(i, { host: e.target.value })}
                  />
                </td>
                <td>
                  <button className="danger" onClick={() => remove(i)}>
                    ✕
                  </button>
                </td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={8} className="empty">
                  No rules. Add one to rewrite requests or responses as they
                  pass through the proxy.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
