import { DiffResult } from "../lib/api";

/** Shared line-diff renderer (Repeater "diff vs previous" and Comparer). */
export default function DiffLines({ diff, caption, onClose }: { diff: DiffResult; caption: string; onClose?: () => void }) {
  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Diff</b>
        <span className="pill" style={{ color: "var(--ok)" }}>+{diff.stats.added}</span>
        <span className="pill" style={{ color: "var(--err)" }}>−{diff.stats.removed}</span>
        <span className="dim">{caption}</span>
        {onClose && (
          <>
            <span className="grow" />
            <button onClick={onClose}>Close diff</button>
          </>
        )}
      </div>
      <div className="pane msg" style={{ overflow: "auto" }}>
        <pre style={{ margin: 0 }}>
          {diff.lines.map((l, i) => (
            <div
              key={i}
              className={l.op === "insert" ? "diff-add" : l.op === "delete" ? "diff-del" : undefined}
              style={{
                color: l.op === "equal" ? "var(--text-dim)" : "var(--text)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {l.op === "insert" ? "+ " : l.op === "delete" ? "- " : "  "}
              {l.text}
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}
