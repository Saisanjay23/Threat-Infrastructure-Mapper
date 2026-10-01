import type {
  Case,
  CaseListItem,
  ExportRequest,
  Report,
  ReportFormat,
  UploadMatch,
  Cluster,
  ClusterListItem,
  GraphPayload,
  ScoringConfig,
  AssetDetail,
  Artifact,
  Asset,
  AuditLog,
  CurrentUser,
  DashboardData,
  Health,
  Investigation,
  InvestigationListItem,
  InvestigationOptions,
  Page,
  Provider,
  ProviderRunInfo,
  ProviderTestResult,
  Role,
  TokenResponse,
  UsageDay,
  User,
} from "@/types/api";

export const API_BASE = "/api";
const TOKEN_KEY = "tim.token";

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

export const tokenStore = {
  get: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set: (token: string) => {
    try {
      localStorage.setItem(TOKEN_KEY, token);
    } catch {
      /* storage unavailable */
    }
  },
  clear: () => {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      /* storage unavailable */
    }
  },
};

export const AUTH_EXPIRED_EVENT = "tim:auth-expired";

type Query = Record<string, string | number | boolean | string[] | null | undefined>;

export function buildQuery(params?: Query): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => sp.append(key, v));
    else sp.append(key, String(value));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

function errorMessage(body: any, fallback: string): string {
  if (!body) return fallback;
  if (typeof body.detail === "string") return body.detail;
  if (Array.isArray(body.detail)) {
    return body.detail.map((d: any) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
  }
  return fallback;
}

export async function request<T>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = tokenStore.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: payload, ...init });
  if (res.status === 401 && token) {
    tokenStore.clear();
    window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
  }
  if (!res.ok) {
    let parsed: any = null;
    try {
      parsed = await res.json();
    } catch {
      /* not json */
    }
    throw new ApiError(res.status, errorMessage(parsed, `${res.status} ${res.statusText}`), parsed);
  }
  if (res.status === 204) return undefined as T;
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

export async function requestBlob(method: string, path: string, body?: unknown): Promise<{ blob: Blob; filename?: string }> {
  const headers: Record<string, string> = {};
  const token = tokenStore.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (!res.ok) {
    let parsed: any = null;
    try {
      parsed = await res.json();
    } catch {
      /* not json */
    }
    throw new ApiError(res.status, errorMessage(parsed, `${res.status} ${res.statusText}`), parsed);
  }
  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return { blob: await res.blob(), filename: match?.[1] };
}

export function fileUrl(fileId: string, download = false): string {
  const token = tokenStore.get();
  return `${API_BASE}/files/${fileId}${buildQuery({ access_token: token, download: download || undefined })}`;
}

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}${API_BASE}${path}${buildQuery({ token: tokenStore.get() })}`;
}

export const api = {
  login: (username: string, password: string) => request<TokenResponse>("POST", "/auth/login", { username, password }),
  me: () => request<CurrentUser>("GET", "/auth/me"),
  health: () => request<Health>("GET", "/health"),
  dashboard: () => request<DashboardData>("GET", "/dashboard"),

  investigate: (ioc: string, options: Partial<InvestigationOptions>, tags: string[] = [], case_id?: string) =>
    request<Investigation>("POST", "/investigate", { ioc, options, tags, case_id }),
  bulkInvestigate: (iocs: string[], options: Partial<InvestigationOptions>, tags: string[] = []) =>
    request<{ bulk_id: string; investigation_ids: string[]; rejected: { ioc: string; reason: string }[] }>(
      "POST",
      "/bulk-investigate",
      { iocs, options, tags },
    ),
  investigations: (params: Query) => request<Page<InvestigationListItem>>("GET", `/investigations${buildQuery(params)}`),
  investigation: (id: string) => request<Investigation>("GET", `/investigation/${id}`),
  investigationAssets: (id: string, params: Query = {}) =>
    request<Page<Asset>>("GET", `/investigation/${id}/assets${buildQuery({ page_size: 500, ...params })}`),
  investigationArtifacts: (id: string) => request<Artifact[]>("GET", `/investigation/${id}/artifacts`),
  providerRuns: (id: string) => request<ProviderRunInfo[]>("GET", `/investigation/${id}/provider-runs`),
  cancelInvestigation: (id: string) => request("POST", `/investigation/${id}/cancel`),
  rerunInvestigation: (id: string) => request<Investigation>("POST", `/investigation/${id}/rerun`),
  deleteInvestigation: (id: string) => request("DELETE", `/investigation/${id}`),
  addNote: (id: string, text: string) => request<Investigation>("POST", `/investigation/${id}/notes`, { text }),

  assets: (params: Query) => request<Page<Asset>>("GET", `/assets${buildQuery(params)}`),
  asset: (id: string) => request<AssetDetail>("GET", `/asset/${id}`),
  setAssetTags: (id: string, tags: string[]) => request<Asset>("PUT", `/asset/${id}/tags`, { tags }),

  providers: () => request<Provider[]>("GET", "/providers"),
  providerUsage: (days = 30) => request<UsageDay[]>("GET", `/providers/usage${buildQuery({ days })}`),
  updateProvider: (name: string, body: Partial<Pick<Provider, "enabled" | "priority" | "cache_ttl_hours" | "daily_limit">>) =>
    request<Provider>("PATCH", `/providers/${name}`, body),
  setProviderKey: (name: string, api_key: string, api_secret?: string) =>
    request<Provider>("PUT", `/providers/${name}/api-key`, { api_key, api_secret: api_secret || null }),
  deleteProviderKey: (name: string) => request<Provider>("DELETE", `/providers/${name}/api-key`),
  testProvider: (name: string) => request<ProviderTestResult>("POST", `/providers/${name}/test`),
  clearProviderCache: (name: string) => request<{ message: string }>("POST", `/providers/${name}/cache/clear`),

  auditLogs: (params: Query) => request<Page<AuditLog>>("GET", `/audit-logs${buildQuery(params)}`),

  graph: (id: string, params: Query = {}) => request<GraphPayload>("GET", `/graph/${encodeURIComponent(id)}${buildQuery(params)}`),
  clusters: (params: Query) => request<Page<ClusterListItem>>("GET", `/clusters${buildQuery(params)}`),
  cluster: (id: string) => request<Cluster>("GET", `/clusters/${encodeURIComponent(id)}`),
  updateCluster: (id: string, body: Partial<Pick<Cluster, "name" | "tags" | "severity">>) =>
    request<Cluster>("PATCH", `/clusters/${encodeURIComponent(id)}`, body),
  addClusterNote: (id: string, text: string) => request<Cluster>("POST", `/clusters/${encodeURIComponent(id)}/notes`, { text }),
  rebuildClusters: () => request<{ clusters: string[]; count: number }>("POST", "/clusters/rebuild"),
  scoring: () => request<ScoringConfig>("GET", "/settings/scoring"),
  saveScoring: (body: ScoringConfig) => request<ScoringConfig>("PUT", "/settings/scoring", body),
  resetScoring: () => request("DELETE", "/settings/scoring"),

  exportReport: (format: ReportFormat, body: ExportRequest) => requestBlob("POST", `/export/${format}`, body),
  reports: (params: Query = {}) => request<Page<Report>>("GET", `/reports${buildQuery(params)}`),
  deleteReport: (id: string) => request("DELETE", `/reports/${id}`),
  reportDownloadUrl: (id: string) => `${API_BASE}/reports/${id}/download${buildQuery({ access_token: tokenStore.get() })}`,

  cases: (params: Query = {}) => request<Page<CaseListItem>>("GET", `/cases${buildQuery(params)}`),
  case: (id: string) => request<Case>("GET", `/cases/${id}`),
  createCase: (body: Partial<Case> & { title: string }) => request<Case>("POST", "/cases", body),
  updateCase: (id: string, body: Partial<Pick<Case, "title" | "description" | "severity" | "status" | "tags" | "assignee">>) =>
    request<Case>("PATCH", `/cases/${id}`, body),
  linkCase: (id: string, body: { asset_ids?: string[]; investigation_ids?: string[]; cluster_ids?: string[] }) =>
    request<Case>("POST", `/cases/${id}/links`, { asset_ids: [], investigation_ids: [], cluster_ids: [], ...body }),
  unlinkCase: (id: string, body: { asset_ids?: string[]; investigation_ids?: string[]; cluster_ids?: string[] }) =>
    request<Case>("POST", `/cases/${id}/unlink`, { asset_ids: [], investigation_ids: [], cluster_ids: [], ...body }),
  addCaseNote: (id: string, text: string) => request<Case>("POST", `/cases/${id}/notes`, { text }),
  deleteCase: (id: string) => request("DELETE", `/cases/${id}`),

  upload: <T = { matches: UploadMatch[]; [k: string]: any }>(kind: "logo" | "html" | "screenshot" | "certificate", form: FormData) =>
    request<T>("POST", `/upload/${kind}`, form),

  users: () => request<User[]>("GET", "/users"),
  createUser: (body: { username: string; password: string; role: Role; email?: string; full_name?: string }) =>
    request<User>("POST", "/users", body),
  updateUser: (id: string, body: Partial<{ role: Role; disabled: boolean; password: string; full_name: string; email: string }>) =>
    request<User>("PATCH", `/users/${id}`, body),
  deleteUser: (id: string) => request("DELETE", `/users/${id}`),
};
