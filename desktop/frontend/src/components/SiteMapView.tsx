import { useEffect, useState } from "react";
import { api, on, SiteMapNode } from "../lib/api";

function statusClass(code?: number): string {
  if (!code) return "dim";
  if (code >= 500) return "status-5";
  if (code >= 400) return "status-4";
  if (code >= 300) return "status-3";
  if (code >= 200) return "status-2";
  return "";
}

function TreeNode({ node, depth }: { node: SiteMapNode; depth: number }) {
  const kids = node.children ?? [];
  const [open, setOpen] = useState(depth < 1);
  const hasKids = kids.length > 0;

  return (
    <div>
      <div
        className="row"
        style={{
          padding: "3px 8px",
          paddingLeft: 8 + depth * 16,
          cursor: hasKids ? "pointer" : "default",
          borderBottom: "1px solid var(--bg-elev)",
        }}
        onClick={() => hasKids && setOpen(!open)}
      >
        <span className="dim" style={{ width: 12, display: "inline-block" }}>
          {hasKids ? (open ? "▾" : "▸") : ""}
        </span>
        {node.method && (
          <span className="method" style={{ minWidth: 44 }}>
            {node.method}
          </span>
        )}
        <span className="mono grow" title={node.url || node.path}>
          {depth === 0 ? node.name : "/" + node.name}
        </span>
        {node.statusCode ? (
          <span className={"pill " + statusClass(node.statusCode)}>
            {node.statusCode}
          </span>
        ) : null}
        <span className="pill dim">{node.count}</span>
      </div>
      {open &&
        kids.map((c, i) => <TreeNode key={i} node={c} depth={depth + 1} />)}
    </div>
  );
}

export default function SiteMapView() {
  const [roots, setRoots] = useState<SiteMapNode[]>([]);

  const refresh = async () => setRoots(await api.getSiteMap());

  useEffect(() => {
    refresh();
    const offFlow = on("proxy:flow", () => refresh());
    const offProj = on("project:loaded", () => refresh());
    return () => {
      offFlow();
      offProj();
    };
  }, []);

  return (
    <div className="split-v">
      <div className="toolbar">
        <b>Site map</b>
        <span className="dim">endpoints observed through the proxy, by host</span>
        <span className="grow" />
        <button onClick={refresh}>Refresh</button>
      </div>
      <div className="pane">
        {roots.length === 0 ? (
          <div className="empty">
            No traffic yet. Browse a target through the proxy to build its map.
          </div>
        ) : (
          roots.map((r, i) => <TreeNode key={i} node={r} depth={0} />)
        )}
      </div>
    </div>
  );
}
