import { useRef } from "react";

// useCoalescedRefresh wraps an async loader so at most one call runs at a time,
// and calls that arrive meanwhile collapse into a single follow-up. A busy page
// emits proxy:flow many times a second; without this every event would refetch
// the whole list, and a slow older response could overwrite a newer one.
export function useCoalescedRefresh(load: () => Promise<void>, gapMs = 150): () => void {
  const loadRef = useRef(load);
  loadRef.current = load;
  const state = useRef({ running: false, queued: false });
  const run = useRef<() => void>();
  if (!run.current) {
    run.current = () => {
      const s = state.current;
      if (s.running) {
        s.queued = true;
        return;
      }
      s.running = true;
      loadRef
        .current()
        .catch(() => {})
        .finally(() => {
          s.running = false;
          if (s.queued) {
            s.queued = false;
            setTimeout(run.current!, gapMs);
          }
        });
    };
  }
  return run.current;
}
