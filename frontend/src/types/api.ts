export type Role = "admin" | "analyst" | "viewer";
export type IOCType = "domain" | "url" | "ip" | "certificate";
export type AssetType =
  | "domain"
  | "url"
  | "ip"
  | "certificate"
  | "analytics"
  | "pixel"
  | "tracking"
  | "favicon"
  | "logo"
  | "asn"
  | "hosting"
  | "nameserver"
  | "cluster";
export type SiteStatus = "ACTIVE" | "INACTIVE" | "PARKED" | "TAKEDOWN" | "ERROR" | "UNKNOWN";
export type InvestigationStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type StageStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type StageName = "collection" | "enrichment" | "pivot" | "correlation";
export type CreditPolicy = "never" | "when_needed" | "always";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface User {
  id: string;
  username: string;
  email?: string | null;
  full_name?: string | null;
  role: Role;
  disabled: boolean;
  created_at: string;
  last_login?: string | null;
}

export interface CurrentUser {
  id: string;
  username: string;
  role: Role;
  permissions: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface InvestigationOptions {
  screenshots: boolean;
  credit_policy: CreditPolicy;
  providers?: string[] | null;
  expand_pivots: boolean;
  max_pivot_assets: number;
  brand?: string | null;
  brand_domains: string[];
  notes?: string | null;
}

export interface StageEvent {
  timestamp: string;
  level: "info" | "warning" | "error";
  message: string;
}

export interface StageState {
  status: StageStatus;
  progress: number;
  message?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  events: StageEvent[];
}

export interface InvestigationSummary {
  assets_discovered: number;
  domains: number;
  ips: number;
  certificates: number;
  tracking_ids: number;
  relationships: number;
  clusters: number;
  high_confidence: number;
  site_status?: SiteStatus | null;
  impersonation_score?: number | null;
  max_confidence: number;
}

export interface Note {
  id: string;
  text: string;
  author: string;
  created_at: string;
}

export interface Investigation {
  id: string;
  ioc: string;
  ioc_type: IOCType;
  normalized: string;
  status: InvestigationStatus;
  options: InvestigationOptions;
  stages: Record<StageName, StageState>;
  summary: InvestigationSummary;
  root_asset_id?: string | null;
  tags: string[];
  case_id?: string | null;
  bulk_id?: string | null;
  cluster_ids?: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  notes: Note[];
}

export type InvestigationListItem = Pick<
  Investigation,
  "id" | "ioc" | "ioc_type" | "status" | "summary" | "tags" | "created_by" | "created_at" | "finished_at"
>;

export interface ProviderRunInfo {
  provider: string;
  ok: boolean;
  cached: boolean;
  skipped: boolean;
  error?: string | null;
  latency_ms: number;
  summary: Record<string, unknown>;
  related_count: number;
  stage: string;
  target?: string | null;
  at: string;
}

export interface Asset {
  id: string;
  type: AssetType;
  value: string;
  status: SiteStatus;
  attributes: Record<string, any>;
  fingerprints: Record<string, any>;
  enrichment?: Record<string, any>;
  investigation_ids?: string[];
  cluster_ids: string[];
  sources: string[];
  tags: string[];
  confidence?: number | null;
  impersonation_score?: number | null;
  brand_similarity_score?: number | null;
  confidence_level?: string | null;
  correlation?: Record<string, { score: number; level: string; matches: { feature: string; label: string; weight: number; values: string[]; detail?: string }[]; computed_at: string }>;
  is_root?: boolean | null;
  first_seen: string;
  last_seen: string;
}

export interface Artifact {
  id: string;
  investigation_id?: string | null;
  asset_id?: string | null;
  kind: string;
  content_type?: string | null;
  size?: number | null;
  sha256?: string | null;
  file_id?: string | null;
  data?: any;
  created_at: string;
}

export interface AssetRelationship {
  id: string;
  type: string;
  direction: "in" | "out";
  other: { id: string; type: AssetType; value: string; status?: SiteStatus; confidence?: number | null };
  sources: string[];
  evidence: Record<string, any>[];
  first_seen: string;
  last_seen: string;
}

export interface AssetDetail {
  asset: Asset;
  relationships: AssetRelationship[];
  artifacts: Artifact[];
}

export interface ProviderHealth {
  state: "healthy" | "degraded" | "down" | "unknown" | "unconfigured";
  last_checked?: string | null;
  last_success?: string | null;
  last_error?: string | null;
  consecutive_failures: number;
}

export interface ProviderUsage {
  total_calls: number;
  cache_hits: number;
  errors: number;
  credits_used: number;
  avg_latency_ms: number;
  last_called?: string | null;
  today_calls: number;
}

export interface Provider {
  name: string;
  display_name: string;
  description: string;
  category: "free" | "credit";
  supported_types: string[];
  requires_api_key: boolean;
  has_api_key: boolean;
  api_key_masked?: string | null;
  enabled: boolean;
  priority: number;
  cache_ttl_hours: number;
  daily_limit?: number | null;
  health: ProviderHealth;
  usage: ProviderUsage;
  docs_url?: string | null;
}

export interface ProviderTestResult {
  name: string;
  ok: boolean;
  latency_ms: number;
  message: string;
  sample?: Record<string, unknown> | null;
}

export interface UsageDay {
  provider: string;
  day: string;
  calls?: number;
  cache_hits?: number;
  errors?: number;
  credits?: number;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  username?: string | null;
  role?: string | null;
  action: string;
  resource_type?: string | null;
  resource_id?: string | null;
  ip?: string | null;
  status: string;
  details?: Record<string, unknown> | null;
}

export interface DashboardData {
  stats: {
    investigations_today: number;
    investigations_running: number;
    investigations_total: number;
    assets_discovered: number;
    assets_today: number;
    threat_clusters: number;
    high_confidence_findings: number;
    relationships: number;
  };
  assets_by_type: Record<string, number>;
  assets_by_status: Record<string, number>;
  activity: { day: string; investigations: number; assets: number }[];
  recent_investigations: InvestigationListItem[];
  recent_clusters: {
    id: string;
    name: string;
    confidence: number;
    confidence_level?: string;
    counts?: Record<string, number>;
    updated_at: string;
    severity?: string;
  }[];
  recent_screenshots: {
    file_id: string;
    asset_id?: string;
    investigation_id?: string;
    url?: string;
    value?: string;
    status?: SiteStatus;
    created_at: string;
  }[];
}

export interface Health {
  status: string;
  version: string;
  environment: string;
  mongodb: { ok: boolean; database: string; error?: string | null };
  browser: { available: boolean | null; last_error?: string | null; enabled: boolean };
  pipeline?: { tracked: number } | null;
  websocket_subscribers: number;
}

export interface ProgressMessage {
  type: string;
  investigation_id?: string;
  stage?: StageName;
  progress?: number;
  message?: string | null;
  level?: StageEvent["level"];
  status?: InvestigationStatus;
  timestamp?: string;
  investigation?: Investigation;
  [key: string]: unknown;
}

export interface GraphNode {
  id: string;
  type: AssetType;
  label: string;
  value: string;
  position: { x: number; y: number };
  data: {
    status?: SiteStatus | null;
    confidence?: number | null;
    confidence_level?: string | null;
    impersonation_score?: number | null;
    cluster_ids: string[];
    is_root: boolean;
    title?: string | null;
    thumbnail?: string | null;
    family?: string | null;
    file_id?: string | null;
    degree: number;
    centrality: number;
    component: number;
    tags: string[];
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  weight: number;
  sources: string[];
  evidence: Record<string, any>[];
}

export interface GraphPayload {
  id: string;
  kind: "investigation" | "cluster" | "asset";
  focus?: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    nodes: number;
    edges: number;
    components: number;
    node_types: Record<string, number>;
    relationship_types: Record<string, number>;
    density: number;
    hubs: { id: string; label: string; type: string; degree: number }[];
  };
}

export interface ClusterListItem {
  id: string;
  name: string;
  confidence: number;
  confidence_level: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  counts: Record<string, number>;
  status_breakdown: Record<string, number>;
  brands: string[];
  domains: string[];
  tags: string[];
  investigation_ids: string[];
  evidence: { feature: string; members: number }[];
  screenshots: { asset_id: string; value: string; file_id: string }[];
  created_at: string;
  updated_at: string;
}

export interface Cluster extends ClusterListItem {
  asset_ids: string[];
  fingerprint_ids: string[];
  ips: string[];
  certificates: string[];
  favicons: string[];
  tracking_ids: string[];
  logos: string[];
  notes: Note[];
}

export interface ScoringConfig {
  weights: Record<string, number>;
  thresholds: { very_high: number; high: number; medium: number; low: number; cluster_min: number };
  similarity: { html: number; logo: number; screenshot: number; title: number };
  noisy_fingerprint_limit: number;
  labels?: Record<string, string>;
  defaults?: Record<string, number>;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type CaseStatus = "open" | "in_progress" | "closed";

export interface CaseListItem {
  id: string;
  title: string;
  severity: Severity;
  status: CaseStatus;
  tags: string[];
  assignee?: string | null;
  asset_count: number;
  investigation_count: number;
  cluster_count: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Case {
  id: string;
  title: string;
  description?: string | null;
  severity: Severity;
  status: CaseStatus;
  tags: string[];
  assignee?: string | null;
  asset_ids: string[];
  investigation_ids: string[];
  cluster_ids: string[];
  notes: Note[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

export type ReportFormat = "pdf" | "html" | "csv" | "json";
export type ReportSection =
  | "executive_summary"
  | "investigation_details"
  | "evidence"
  | "screenshots"
  | "threat_clusters"
  | "related_assets"
  | "confidence_scores"
  | "graph_snapshot"
  | "analyst_notes";

export interface ExportRequest {
  investigation_id?: string;
  cluster_id?: string;
  case_id?: string;
  asset_ids?: string[];
  title?: string;
  sections?: ReportSection[];
  min_confidence?: number;
  max_assets?: number;
  max_screenshots?: number;
  analyst_notes?: string;
  tlp?: "CLEAR" | "GREEN" | "AMBER" | "AMBER+STRICT" | "RED";
  save?: boolean;
}

export interface Report {
  id: string;
  title: string;
  format: ReportFormat;
  scope_type: string;
  scope_id?: string | null;
  size: number;
  file_id: string;
  filename: string;
  sections: string[];
  tlp: string;
  created_by: string;
  created_at: string;
}

export interface UploadMatch {
  id: string;
  type: AssetType;
  value: string;
  status?: SiteStatus;
  confidence?: number | null;
  similarity: number;
  via: string;
  shared?: string[];
}
