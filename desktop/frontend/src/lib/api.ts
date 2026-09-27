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

export type Processor =
  | "url"
  | "base64"
  | "lower"
  | "upper"
  | "md5"
  | "sha1"
  | "sha256";

export interface NumberRange {
  from: number;
  to: number;
  step: number;
  pad: number;
}

export interface PayloadSpec {
  list: string[];
  numbers?: NumberRange | null;
  processors?: Processor[];
}

export interface IntruderConfig {
  type: AttackType;
  scheme: string;
  host: string;
  template: string;
  marker: string;
  payloads: string[][];
  specs?: PayloadSpec[];
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

export type RulePhase = "request" | "response";
export type RulePart = "first_line" | "headers" | "body";

export interface Rule {
  id: number;
  name: string;
  enabled: boolean;
  phase: RulePhase;
  part: RulePart;
  match: string;
  replace: string;
  host?: string;
}

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  id: number;
  severity: Severity;
  title: string;
  detail: string;
  host: string;
  url: string;
  flowId: number;
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

export interface WSFrameView {
  direction: "client->server" | "server->client";
  opcode: string;
  final: boolean;
  masked: boolean;
  length: number;
  text: string;
  isText: boolean;
  at: string;
}

export interface WSSession {
  id: number;
  host: string;
  url: string;
  open: boolean;
  openedAt: string;
  closedAt?: string;
  frames: WSFrameView[] | null;
}

export interface SiteMapNode {
  name: string;
  path: string;
  url?: string;
  method?: string;
  statusCode?: number;
  flowId?: number;
  count: number;
  children?: SiteMapNode[] | null;
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
  ListHistory(
    text: string,
    methods: string[],
    searchBodies: boolean
  ): Promise<Entry[]>;
  ClearHistory(): Promise<void>;
  GetFlow(id: number): Promise<FlowView>;
  GetRules(): Promise<Rule[]>;
  SetRules(rules: Rule[]): Promise<void>;
  GetFindings(): Promise<Finding[]>;
  ClearFindings(): Promise<void>;
  ExportHAR(): Promise<void>;
  SaveProject(): Promise<void>;
  LoadProject(): Promise<void>;
  GetWSSessions(): Promise<WSSession[]>;
  ClearWSSessions(): Promise<void>;
  ImportHAR(): Promise<void>;
  GetSiteMap(): Promise<SiteMapNode[]>;
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
  listHistory: (text: string, methods: string[], searchBodies: boolean) =>
    backend().ListHistory(text, methods, searchBodies),
  clearHistory: () => backend().ClearHistory(),
  getFlow: (id: number) => backend().GetFlow(id),
  getRules: () => backend().GetRules(),
  setRules: (rules: Rule[]) => backend().SetRules(rules),
  getFindings: () => backend().GetFindings(),
  clearFindings: () => backend().ClearFindings(),
  exportHAR: () => backend().ExportHAR(),
  saveProject: () => backend().SaveProject(),
  loadProject: () => backend().LoadProject(),
  getWSSessions: () => backend().GetWSSessions(),
  clearWSSessions: () => backend().ClearWSSessions(),
  importHAR: () => backend().ImportHAR(),
  getSiteMap: () => backend().GetSiteMap(),
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
