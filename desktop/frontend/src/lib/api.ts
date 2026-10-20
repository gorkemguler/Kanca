// Typed wrappers over the Wails-injected backend bindings and event bus.
//
// Wails exposes bound Go methods at window.go.main.App.<Method> and an event
// API at window.runtime. We call those directly (rather than the generated
// bindings) so the frontend type-checks before the first `wails generate`.

export interface ProxyStatus {
  running: boolean;
  addr: string;
}

export interface TrustStatus {
  supported: boolean;
  trusted: boolean;
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
  extractGrep: string;
  threads: number;
  delayMs: number;
}

export interface IntruderPreview {
  positions: number;
  requests: number;
  /** true when the combination space exceeded the server cap and was cut. */
  capped: boolean;
}

export interface JwtToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Decoded JSON exactly as it appeared in the token; use these for editing
   *  and re-signing so 64-bit numbers (sub, exp, nonces) stay exact in JS. */
  headerJson: string;
  payloadJson: string;
  alg: string;
  unsigned: boolean;
}

/** hosts are the targets (the only hosts Kanca scans); enabled also limits
 * recording to them. */
export interface ScopeConfig {
  enabled: boolean;
  hosts: string[];
}

export interface SiteScanPlan {
  host: string;
  safe: number;
  unsafe: number;
}

export interface SiteScanProgress {
  host: string;
  done: number;
  total: number;
  current: string;
  found: number;
}

export interface SiteScanDone {
  host: string;
  scanned: number;
  found: number;
  stopped: boolean;
  errors: number;
  errorSample?: string;
}

export interface SiteScanOptions {
  includeUnsafe: boolean;
  includeDelete: boolean;
  aggressive: boolean;
  skipQuery: boolean;
  skipBody: boolean;
  skipJson: boolean;
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

export type FindingStatus = "new" | "confirmed" | "resolved" | "false-positive";

export interface Finding {
  id: number;
  severity: Severity;
  title: string;
  detail: string;
  host: string;
  url: string;
  flowId: number;
  /** "ai" when an AI assistant reported it over MCP. */
  source?: string;
  /** triage state; absent means "new". */
  status?: FindingStatus;
}

export type MCPLevel = "read" | "readwrite";

export interface MCPActivity {
  at: string;
  tool: string;
  action: string;
  result: string;
  error?: boolean;
}

export interface MCPStatus {
  enabled: boolean;
  running: boolean;
  level: MCPLevel;
  mask: boolean;
  allowDelete: boolean;
  url: string;
  error?: string;
  sent: number;
  budget: number;
  claudeCode: string;
  claudeDesktop: string;
  claudeDesktopPath: string;
  opencodeRemote?: string;
  opencodeLocal?: string;
  opencodeExport?: string;
  opencodeExportWin?: string;
}

export interface IntruderResult {
  index: number;
  payloads: string[];
  statusCode: number;
  length: number;
  durationMs: number;
  matched: boolean;
  extracted?: string;
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

export interface DiffLine {
  op: "equal" | "insert" | "delete";
  text: string;
  aLine: number;
  bLine: number;
}

export interface DiffResult {
  lines: DiffLine[];
  stats: { added: number; removed: number };
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
  ExportRootCA(): Promise<string>;
  GetTrustStatus(): Promise<TrustStatus>;
  InstallCA(): Promise<TrustStatus>;
  RemoveCA(): Promise<TrustStatus>;
  OpenBrowser(): Promise<string>;
  ExportExtension(): Promise<string>;
  GetScope(): Promise<ScopeConfig>;
  SetScope(cfg: ScopeConfig): Promise<void>;
  AddTarget(host: string): Promise<ScopeConfig>;
  PlanSiteScan(host: string, opts: SiteScanOptions): Promise<SiteScanPlan>;
  ScanSite(host: string, opts: SiteScanOptions): Promise<void>;
  StopSiteScan(): Promise<void>;
  SiteScanStatus(): Promise<SiteScanProgress | null>;
  ListHistory(
    text: string,
    methods: string[],
    searchBodies: boolean,
    hideStatus: number[]
  ): Promise<Entry[]>;
  ClearHistory(): Promise<void>;
  AnnotateFlow(id: number, comment: string, highlight: string): Promise<void>;
  GetFlow(id: number): Promise<FlowView>;
  GetRules(): Promise<Rule[]>;
  SetRules(rules: Rule[]): Promise<void>;
  GetFindings(): Promise<Finding[]>;
  SetFindingStatus(id: number, status: FindingStatus): Promise<void>;
  ClearFindings(): Promise<void>;
  ActiveScan(flowId: number, aggressive: boolean): Promise<void>;
  StopActiveScan(flowId: number): Promise<void>;
  ExportHAR(): Promise<void>;
  SaveProject(): Promise<void>;
  LoadProject(): Promise<void>;
  GetWSSessions(): Promise<WSSession[]>;
  ClearWSSessions(): Promise<void>;
  ImportHAR(): Promise<void>;
  GetSiteMap(): Promise<SiteMapNode[]>;
  DiffText(before: string, after: string): Promise<DiffResult>;
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
  PauseIntruder(paused: boolean): Promise<void>;
  StopIntruder(): Promise<void>;
  DecodeJWT(token: string): Promise<JwtToken>;
  SignJWT(
    header: string,
    payload: string,
    alg: string,
    secret: string
  ): Promise<string>;
  VerifyJWT(token: string, secret: string): Promise<boolean>;
  GetMCPStatus(): Promise<MCPStatus>;
  SetMCPSettings(
    enabled: boolean,
    level: MCPLevel,
    mask: boolean,
    allowDelete: boolean
  ): Promise<MCPStatus>;
  RegenerateMCPToken(): Promise<MCPStatus>;
  GetMCPActivity(): Promise<MCPActivity[]>;
  AddToClaudeDesktop(): Promise<string>;
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
  exportRootCA: () => backend().ExportRootCA(),
  getTrustStatus: () => backend().GetTrustStatus(),
  installCA: () => backend().InstallCA(),
  removeCA: () => backend().RemoveCA(),
  openBrowser: () => backend().OpenBrowser(),
  exportExtension: () => backend().ExportExtension(),
  getScope: () => backend().GetScope(),
  setScope: (cfg: ScopeConfig) => backend().SetScope(cfg),
  addTarget: (host: string) => backend().AddTarget(host),
  planSiteScan: (host: string, opts: SiteScanOptions) =>
    backend().PlanSiteScan(host, opts),
  scanSite: (host: string, opts: SiteScanOptions) =>
    backend().ScanSite(host, opts),
  stopSiteScan: () => backend().StopSiteScan(),
  siteScanStatus: () => backend().SiteScanStatus(),
  listHistory: (text: string, methods: string[], searchBodies: boolean, hideStatus: number[]) =>
    backend().ListHistory(text, methods, searchBodies, hideStatus),
  clearHistory: () => backend().ClearHistory(),
  annotateFlow: (id: number, comment: string, highlight: string) =>
    backend().AnnotateFlow(id, comment, highlight),
  getFlow: (id: number) => backend().GetFlow(id),
  getRules: () => backend().GetRules(),
  setRules: (rules: Rule[]) => backend().SetRules(rules),
  getFindings: () => backend().GetFindings(),
  setFindingStatus: (id: number, status: FindingStatus) =>
    backend().SetFindingStatus(id, status),
  clearFindings: () => backend().ClearFindings(),
  activeScan: (flowId: number, aggressive: boolean) =>
    backend().ActiveScan(flowId, aggressive),
  stopActiveScan: (flowId: number) => backend().StopActiveScan(flowId),
  exportHAR: () => backend().ExportHAR(),
  saveProject: () => backend().SaveProject(),
  loadProject: () => backend().LoadProject(),
  getWSSessions: () => backend().GetWSSessions(),
  clearWSSessions: () => backend().ClearWSSessions(),
  importHAR: () => backend().ImportHAR(),
  getSiteMap: () => backend().GetSiteMap(),
  diffText: (before: string, after: string) => backend().DiffText(before, after),
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
  pauseIntruder: (paused: boolean) => backend().PauseIntruder(paused),
  stopIntruder: () => backend().StopIntruder(),
  decodeJWT: (token: string) => backend().DecodeJWT(token),
  signJWT: (header: string, payload: string, alg: string, secret: string) =>
    backend().SignJWT(header, payload, alg, secret),
  verifyJWT: (token: string, secret: string) => backend().VerifyJWT(token, secret),
  getMCPStatus: () => backend().GetMCPStatus(),
  setMCPSettings: (
    enabled: boolean,
    level: MCPLevel,
    mask: boolean,
    allowDelete: boolean
  ) => backend().SetMCPSettings(enabled, level, mask, allowDelete),
  regenerateMCPToken: () => backend().RegenerateMCPToken(),
  getMCPActivity: () => backend().GetMCPActivity(),
  addToClaudeDesktop: () => backend().AddToClaudeDesktop(),
};

/** on subscribes to a Wails runtime event and returns an unsubscribe fn. */
export function on(event: string, cb: (...data: any[]) => void): () => void {
  if (!window.runtime) return () => {};
  return window.runtime.EventsOn(event, cb);
}

/** isNotTarget reports whether an error says a host must be added as a target. */
export function isNotTarget(e: unknown): boolean {
  return String((e as any)?.message ?? e).includes("not one of your targets");
}

/** copyText copies to the clipboard, falling back to a hidden textarea when
 *  the async clipboard API is unavailable (e.g. insecure context). It
 *  returns false instead of throwing when everything fails. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}
export function hostOf(authority: string): string {
  const m = authority.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (m) return m[1];
  const i = authority.lastIndexOf(":");
  return i > 0 && authority.indexOf(":") === i ? authority.slice(0, i) : authority;
}

/** matchesTarget mirrors Kanca's target rules: exact host, parent domain
 * ("example.com" covers "api.example.com"), or "*.example.com" for subdomains. */
export function matchesTarget(host: string, targets: string[]): boolean {
  const h = host.toLowerCase();
  return targets.some((t) =>
    t.startsWith("*.") ? h.endsWith(t.slice(1)) : h === t || h.endsWith("." + t)
  );
}
