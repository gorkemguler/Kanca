// Typed wrappers over the Wails-injected backend bindings and event bus.
//
// Wails exposes bound Go methods at window.go.main.App.<Method> and an event
// API at window.runtime. We call those directly (rather than the generated
// bindings) so the frontend type-checks before the first `wails generate`.

export interface ProxyStatus {
  running: boolean;
  addr: string;
}

export interface Entry {
  id: number;
  method: string;
  scheme: string;
  host: string;
  path: string;
  statusCode: number;
  length: number;
  mime: string;
  durationMs: number;
  comment?: string;
  highlight?: string;
  error?: string;
}

export interface FlowView {
  id: number;
  scheme: string;
  method: string;
  host: string;
  path: string;
  url: string;
  statusCode: number;
  durationMs: number;
  error?: string;
  reqHeaders: Record<string, string>;
  respHeaders: Record<string, string>;
  requestRaw: string;
  responseRaw: string;
  respLength: number;
  mime: string;
  respEncoding?: string;
}

export interface HeldView {
  id: number;
  direction: "request" | "response";
  host: string;
  method: string;
  url: string;
  raw: string;
}

export interface RepeaterTab {
  id: number;
  name: string;
  scheme: string;
  host: string;
  raw: string;
  history: FlowView[] | null;
}

export type AttackType =
  | "sniper"
  | "battering_ram"
  | "pitchfork"
  | "cluster_bomb";

export interface IntruderConfig {
  type: AttackType;
  scheme: string;
  host: string;
  template: string;
  marker: string;
  payloads: string[][];
  grepMatch: string;
  threads: number;
}

export interface IntruderPreview {
  positions: number;
  requests: number;
}

export interface ScopeConfig {
  enabled: boolean;
  hosts: string[];
}

export interface IntruderResult {
  index: number;
  payloads: string[];
  statusCode: number;
  length: number;
  durationMs: number;
  matched: boolean;
  error?: string;
}

// The shape Wails injects on window. Only the members we use are declared.
interface WailsBackend {
  GetStatus(): Promise<ProxyStatus>;
  StartProxy(addr: string): Promise<ProxyStatus>;
  StopProxy(): Promise<void>;
  GetRootCAPEM(): Promise<string>;
  ExportRootCA(path: string): Promise<void>;
  GetScope(): Promise<ScopeConfig>;
  SetScope(cfg: ScopeConfig): Promise<void>;
  ListHistory(text: string, methods: string[]): Promise<Entry[]>;
  ClearHistory(): Promise<void>;
  GetFlow(id: number): Promise<FlowView>;
  SetIntercept(enabled: boolean): Promise<void>;
  SetInterceptResponses(enabled: boolean): Promise<void>;
  ForwardHeld(id: number, raw: string): Promise<void>;
  DropHeld(id: number): Promise<void>;
  ForwardAll(): Promise<void>;
  RepeaterFromFlow(id: number): Promise<RepeaterTab>;
  RepeaterNewTab(scheme: string, host: string, raw: string): Promise<RepeaterTab>;
  RepeaterUpdate(id: number, scheme: string, host: string, raw: string): Promise<boolean>;
  RepeaterSend(id: number): Promise<FlowView>;
  RepeaterClose(id: number): Promise<void>;
  PreviewIntruder(cfg: IntruderConfig): Promise<IntruderPreview>;
  StartIntruder(cfg: IntruderConfig): Promise<void>;
  StopIntruder(): Promise<void>;
}

interface WailsRuntime {
  EventsOn(event: string, cb: (...data: any[]) => void): () => void;
  EventsOff(event: string): void;
}

declare global {
  interface Window {
    go?: { main?: { App?: WailsBackend } };
    runtime?: WailsRuntime;
  }
}

function backend(): WailsBackend {
  const b = window.go?.main?.App;
  if (!b) {
    throw new Error(
      "Wails backend not available. Run this UI through `wails dev` or a `wails build` binary."
    );
  }
  return b;
}

export const api = {
  getStatus: () => backend().GetStatus(),
  startProxy: (addr: string) => backend().StartProxy(addr),
  stopProxy: () => backend().StopProxy(),
  getRootCA: () => backend().GetRootCAPEM(),
  exportRootCA: (path: string) => backend().ExportRootCA(path),
  getScope: () => backend().GetScope(),
  setScope: (cfg: ScopeConfig) => backend().SetScope(cfg),
  listHistory: (text: string, methods: string[]) =>
    backend().ListHistory(text, methods),
  clearHistory: () => backend().ClearHistory(),
  getFlow: (id: number) => backend().GetFlow(id),
  setIntercept: (on: boolean) => backend().SetIntercept(on),
  setInterceptResponses: (on: boolean) => backend().SetInterceptResponses(on),
  forwardHeld: (id: number, raw: string) => backend().ForwardHeld(id, raw),
  dropHeld: (id: number) => backend().DropHeld(id),
  forwardAll: () => backend().ForwardAll(),
  repeaterFromFlow: (id: number) => backend().RepeaterFromFlow(id),
  repeaterNewTab: (scheme: string, host: string, raw: string) =>
    backend().RepeaterNewTab(scheme, host, raw),
  repeaterUpdate: (id: number, scheme: string, host: string, raw: string) =>
    backend().RepeaterUpdate(id, scheme, host, raw),
  repeaterSend: (id: number) => backend().RepeaterSend(id),
  repeaterClose: (id: number) => backend().RepeaterClose(id),
  previewIntruder: (cfg: IntruderConfig) => backend().PreviewIntruder(cfg),
  startIntruder: (cfg: IntruderConfig) => backend().StartIntruder(cfg),
  stopIntruder: () => backend().StopIntruder(),
};

/** on subscribes to a Wails runtime event and returns an unsubscribe fn. */
export function on(event: string, cb: (...data: any[]) => void): () => void {
  if (!window.runtime) return () => {};
  return window.runtime.EventsOn(event, cb);
}
