import { useEffect, useState } from "react";
import { api, on, HeldView } from "../lib/api";
import RawMessage from "./RawMessage";

interface Props {
  intercepting: boolean;
  setIntercepting: (v: boolean) => void;
  onQueueChange: (n: number) => void;
}

export default function InterceptView({
  intercepting,
  setIntercepting,
  onQueueChange,
}: Props) {
  const [queue, setQueue] = useState<HeldView[]>([]);
  const [interceptResponses, setInterceptResponses] = useState(false);
  const [draft, setDraft] = useState("");

  useEffect(() => {
    const off = on("intercept:hold", (h: HeldView) => {
      setQueue((q) => {
        const next = [...q, h];
        onQueueChange(next.length);
        return next;
      });
    });
    return off;
  }, [onQueueChange]);

  const current = queue[0];
  useEffect(() => {
    setDraft(current ? current.raw : "");
  }, [current?.id]);

  const pop = () => {
    setQueue((q) => {
      const next = q.slice(1);
      onQueueChange(next.length);
      return next;
    });
  };

  const forward = () => {
    if (!current) return;
    // Only send edited bytes when the user actually changed them.
    api.forwardHeld(current.id, draft !== current.raw ? draft : "");
    pop();
  };
  const drop = () => {
    if (!current) return;
    api.dropHeld(current.id);
    pop();
  };
  const forwardAll = () => {
    api.forwardAll();
    setQueue([]);
    onQueueChange(0);
  };

  const toggle = (v: boolean) => {
    setIntercepting(v);
    api.setIntercept(v);
  };

  return (
    <div className="split-v">
      <div className="toolbar">
        <button
          className={intercepting ? "primary" : ""}
          onClick={() => toggle(!intercepting)}
        >
          {intercepting ? "Intercept is ON" : "Intercept is OFF"}
        </button>
        <button onClick={forward} disabled={!current}>
          Forward
        </button>
        <button className="danger" onClick={drop} disabled={!current}>
          Drop
        </button>
        <button onClick={forwardAll} disabled={queue.length === 0}>
          Forward all ({queue.length})
        </button>
        <span className="spacer grow" />
        <label className="row">
          <input
            type="checkbox"
            checked={interceptResponses}
            onChange={(e) => {
              setInterceptResponses(e.target.checked);
              api.setInterceptResponses(e.target.checked);
            }}
          />
          <span className="dim">Intercept responses</span>
        </label>
      </div>
      {current ? (
        <RawMessage
          title={`${current.direction} — ${current.method} ${current.url}`}
          value={draft}
          editable
          onChange={setDraft}
        />
      ) : (
        <div className="empty">
          {intercepting
            ? "Waiting for traffic… requests will pause here for editing."
            : "Interception is off — traffic passes straight through to the history."}
        </div>
      )}
    </div>
  );
}
