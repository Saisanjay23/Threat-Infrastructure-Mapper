import { useQuery } from "@tanstack/react-query";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  MarkerType,
  MiniMap,
  type Node,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ExternalLink, Filter, Loader2, Maximize2, Network, PanelRightClose, PanelRightOpen, Plus, Search, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader, StatusBadge, TypeBadge } from "@/components/common";
import { AssetNode, TYPE_COLORS, type AssetNodeData } from "@/components/graph/AssetNode";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, fileUrl } from "@/lib/api";
import { cn, timeAgo, truncate } from "@/lib/utils";
import type { GraphEdge, GraphNode, GraphPayload } from "@/types/api";

const nodeTypes = { asset: AssetNode };

const RELATION_COLORS: Record<string, string> = {
  SHARES_ANALYTICS: "#fbbf24",
  SHARES_PIXEL: "#fb923c",
  SHARES_TRACKING: "#facc15",
  SHARES_FAVICON: "#94a3b8",
  USES_CERTIFICATE: "#34d399",
  SHARES_CERTIFICATE: "#34d399",
  SHARES_LOGO: "#e2e8f0",
  SIMILAR_HTML: "#f472b6",
  SIMILAR_TITLE: "#f9a8d4",
  SIMILAR_SCREENSHOT: "#e879f9",
  RESOLVES_TO: "#c084fc",
  HISTORICAL_RESOLUTION: "#a78bfa",
  HOSTED_ON: "#78716c",
  BELONGS_TO_ASN: "#737373",
  USES_NAMESERVER: "#6b7280",
  REDIRECTS_TO: "#ef4444",
  HAS_URL: "#60a5fa",
  MEMBER_OF_CLUSTER: "#f87171",
  SUBDOMAIN_OF: "#22d3ee",
};

function toFlow(payload: GraphPayload): { nodes: Node[]; edges: Edge[] } {
  return {
    nodes: payload.nodes.map((n) => ({
      id: n.id,
      type: "asset",
      position: n.position,
      data: {
        label: truncate(n.label, 42),
        assetType: n.type,
        status: n.data.status,
        confidence: n.data.confidence,
        isRoot: n.data.is_root,
        degree: n.data.degree,
      } satisfies AssetNodeData,
    })),
    edges: payload.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: "straight",
      data: { relation: e.type },
      style: { stroke: RELATION_COLORS[e.type] ?? "#64748b", strokeWidth: e.type.startsWith("SIMILAR") ? 1.5 : 1.2, strokeDasharray: e.type.startsWith("SIMILAR") ? "4 3" : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12, color: RELATION_COLORS[e.type] ?? "#64748b" },
    })),
  };
}

function mergePayload(base: GraphPayload, extra: GraphPayload, anchor?: { x: number; y: number }): GraphPayload {
  const known = new Set(base.nodes.map((n) => n.id));
  const offset = anchor ? { x: anchor.x - (extra.nodes.find((n) => n.id === extra.focus)?.position.x ?? 0), y: anchor.y - (extra.nodes.find((n) => n.id === extra.focus)?.position.y ?? 0) } : { x: 0, y: 0 };
  const nodes = [...base.nodes, ...extra.nodes.filter((n) => !known.has(n.id)).map((n) => ({ ...n, position: { x: n.position.x * 0.5 + offset.x, y: n.position.y * 0.5 + offset.y } }))];
  const edgeIds = new Set(base.edges.map((e) => e.id));
  const edges = [...base.edges, ...extra.edges.filter((e) => !edgeIds.has(e.id))];
  return { ...base, nodes, edges, stats: { ...base.stats, nodes: nodes.length, edges: edges.length } };
}

function EvidenceSidebar({
  node,
  edge,
  payload,
  investigationId,
  onExpand,
  expanding,
  onClose,
}: {
  node: GraphNode | null;
  edge: GraphEdge | null;
  payload: GraphPayload;
  investigationId?: string | null;
  onExpand: (id: string) => void;
  expanding: boolean;
  onClose: () => void;
}) {
  const detail = useQuery({ queryKey: ["asset", node?.id], queryFn: () => api.asset(node!.id), enabled: !!node });
  const byId = useMemo(() => new Map(payload.nodes.map((n) => [n.id, n])), [payload.nodes]);

  if (edge) {
    const s = byId.get(edge.source);
    const t = byId.get(edge.target);
    return (
      <div className="space-y-3 p-4 text-sm">
        <div className="flex items-center justify-between">
          <Badge variant="secondary" className="font-mono">{edge.type}</Badge>
          <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label="Close"><X /></Button>
        </div>
        <div className="space-y-1">
          <div className="text-muted-foreground text-xs">From</div>
          <div className="flex items-center gap-2"><TypeBadge type={s?.type ?? "?"} /><Mono>{s?.value}</Mono></div>
          <div className="text-muted-foreground mt-2 text-xs">To</div>
          <div className="flex items-center gap-2"><TypeBadge type={t?.type ?? "?"} /><Mono>{t?.value}</Mono></div>
        </div>
        <div><span className="text-muted-foreground text-xs">Sources:</span> {edge.sources.join(", ") || "—"}</div>
        <div><span className="text-muted-foreground text-xs">Weight:</span> {edge.weight}</div>
        <div className="text-muted-foreground text-xs">Evidence</div>
        <pre className="bg-muted/40 max-h-80 overflow-auto rounded-md border p-2 font-mono text-[11px]">{JSON.stringify(edge.evidence, null, 2)}</pre>
      </div>
    );
  }
  if (!node) {
    return (
      <div className="space-y-4 p-4 text-sm">
        <div className="font-medium">Graph statistics</div>
        <div className="grid grid-cols-3 gap-2 text-center">
          <div className="rounded-md border p-2"><div className="text-lg font-semibold">{payload.stats.nodes}</div><div className="text-muted-foreground text-[11px]">nodes</div></div>
          <div className="rounded-md border p-2"><div className="text-lg font-semibold">{payload.stats.edges}</div><div className="text-muted-foreground text-[11px]">edges</div></div>
          <div className="rounded-md border p-2"><div className="text-lg font-semibold">{payload.stats.components}</div><div className="text-muted-foreground text-[11px]">components</div></div>
        </div>
        <div>
          <div className="text-muted-foreground mb-1 text-xs">Hubs (highest degree)</div>
          {payload.stats.hubs.map((h) => (
            <div key={h.id} className="flex items-center justify-between gap-2 py-0.5 text-xs">
              <span className="flex min-w-0 items-center gap-1.5"><span className="size-2 shrink-0 rounded-full" style={{ background: TYPE_COLORS[h.type] }} /><span className="truncate font-mono">{h.label}</span></span>
              <span className="tabular-nums">{h.degree}</span>
            </div>
          ))}
        </div>
        <div>
          <div className="text-muted-foreground mb-1 text-xs">Node types</div>
          <div className="flex flex-wrap gap-1">
            {Object.entries(payload.stats.node_types).map(([t, n]) => (
              <Badge key={t} variant="outline" className="gap-1"><span className="size-2 rounded-full" style={{ background: TYPE_COLORS[t] }} />{t} {n}</Badge>
            ))}
          </div>
        </div>
        <p className="text-muted-foreground text-xs">Click a node for evidence, double-click to expand its neighbourhood, click an edge for relationship provenance.</p>
      </div>
    );
  }
  const asset = detail.data?.asset;
  const correlation = asset?.correlation && investigationId ? asset.correlation[investigationId] : asset?.correlation ? Object.values(asset.correlation)[0] : null;
  return (
    <div className="space-y-3 p-4 text-sm">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <TypeBadge type={node.type} />
          <div className="mt-1 font-mono text-xs break-all">{node.value}</div>
        </div>
        <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label="Close"><X /></Button>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge status={node.data.status} />
        <ConfidenceBadge score={node.data.confidence} />
        {node.data.impersonation_score ? <Badge variant="destructive">impersonation {node.data.impersonation_score}</Badge> : null}
      </div>
      {node.data.thumbnail && <img src={fileUrl(node.data.thumbnail)} alt="" className="w-full rounded-md border" />}
      {node.data.title && <div className="text-muted-foreground text-xs">“{node.data.title}”</div>}
      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={() => onExpand(node.id)} disabled={expanding}>
          {expanding ? <Loader2 className="animate-spin" /> : <Plus />} Expand
        </Button>
        <Button size="sm" variant="outline" asChild>
          <Link to={`/assets/${node.id}`}><ExternalLink /> Open asset</Link>
        </Button>
      </div>
      {detail.isLoading && <LoadingBlock />}
      {correlation && (
        <div>
          <div className="text-muted-foreground mb-1 text-xs">Correlation evidence · score {correlation.score} ({correlation.level})</div>
          <div className="space-y-1">
            {(correlation.matches ?? []).map((m: { feature: string; label: string; weight: number; values: string[]; detail?: string }) => (
              <div key={m.feature} className="rounded-md border px-2 py-1">
                <div className="flex justify-between text-xs"><span>{m.label}</span><span className="font-semibold tabular-nums">+{m.weight}</span></div>
                {m.values?.length > 0 && <div className="text-muted-foreground truncate font-mono text-[11px]">{m.values.join(", ")}</div>}
                {m.detail && <div className="text-muted-foreground text-[11px]">{m.detail}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
      {detail.data && (
        <div>
          <div className="text-muted-foreground mb-1 text-xs">Relationships ({detail.data.relationships.length})</div>
          <div className="max-h-64 space-y-0.5 overflow-y-auto">
            {detail.data.relationships.slice(0, 60).map((r) => (
              <div key={r.id} className="flex items-center gap-1.5 text-[11px]">
                <span className="text-muted-foreground w-4">{r.direction === "out" ? "→" : "←"}</span>
                <span className="text-muted-foreground shrink-0 font-mono">{r.type}</span>
                <span className="truncate font-mono">{r.other.value}</span>
              </div>
            ))}
          </div>
          <div className="text-muted-foreground mt-2 text-[11px]">Sources: {asset?.sources.join(", ")} · last seen {timeAgo(asset?.last_seen)}</div>
        </div>
      )}
    </div>
  );
}

function GraphCanvas({ initial, investigationId, initialSelected }: { initial: GraphPayload; investigationId?: string | null; initialSelected?: string | null }) {
  const flow = useReactFlow();
  const [payload, setPayload] = useState<GraphPayload>(initial);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [search, setSearch] = useState("");
  const [hiddenRelations, setHiddenRelations] = useState<Set<string>>(new Set(["HAS_URL"]));
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [cluster, setCluster] = useState<string>("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [selectedNode, setSelectedNode] = useState<string | null>(initialSelected ?? null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [sidebar, setSidebar] = useState(true);
  const [expanding, setExpanding] = useState(false);

  useEffect(() => setPayload(initial), [initial]);

  const clusters = useMemo(() => Array.from(new Set(payload.nodes.flatMap((n) => n.data.cluster_ids))).sort(), [payload.nodes]);
  const relationTypes = useMemo(() => Array.from(new Set(payload.edges.map((e) => e.type))).sort(), [payload.edges]);
  const nodeTypesPresent = useMemo(() => Array.from(new Set(payload.nodes.map((n) => n.type))).sort(), [payload.nodes]);

  // Visible subgraph after filters.
  const visible = useMemo(() => {
    const keepNode = new Set(
      payload.nodes
        .filter((n) => !hiddenTypes.has(n.type))
        .filter((n) => cluster === "all" || n.data.cluster_ids.includes(cluster) || !["domain", "ip", "url"].includes(n.type))
        .filter((n) => !["domain", "ip"].includes(n.type) || (n.data.confidence ?? 0) >= minConfidence || n.data.is_root)
        .map((n) => n.id),
    );
    const keptEdges = payload.edges.filter((e) => !hiddenRelations.has(e.type) && keepNode.has(e.source) && keepNode.has(e.target));
    if (cluster !== "all" || minConfidence > 0) {
      // Drop fingerprint nodes that no longer connect to any visible host.
      const connected = new Set(keptEdges.flatMap((e) => [e.source, e.target]));
      for (const n of payload.nodes) if (keepNode.has(n.id) && !["domain", "ip", "url"].includes(n.type) && !connected.has(n.id)) keepNode.delete(n.id);
    }
    return { keepNode, keptEdges };
  }, [payload, hiddenTypes, hiddenRelations, cluster, minConfidence]);

  const matches = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return new Set<string>();
    return new Set(
      payload.nodes
        .filter((n) => visible.keepNode.has(n.id))
        .filter((n) => n.value.toLowerCase().includes(q) || (n.data.title ?? "").toLowerCase().includes(q))
        .map((n) => n.id),
    );
  }, [search, payload.nodes, visible.keepNode]);

  const neighborhood = useMemo(() => {
    if (!selectedNode) return null;
    const set = new Set([selectedNode]);
    for (const e of visible.keptEdges) {
      if (e.source === selectedNode) set.add(e.target);
      if (e.target === selectedNode) set.add(e.source);
    }
    return set;
  }, [selectedNode, visible.keptEdges]);

  useEffect(() => {
    const flowData = toFlow({ ...payload, nodes: payload.nodes.filter((n) => visible.keepNode.has(n.id)), edges: visible.keptEdges });
    setNodes((current) => {
      const pos = new Map(current.map((n) => [n.id, n.position]));
      return flowData.nodes.map((n) => ({
        ...n,
        position: pos.get(n.id) ?? n.position,
        data: {
          ...n.data,
          highlighted: matches.has(n.id),
          dimmed: (matches.size > 0 && !matches.has(n.id)) || (neighborhood !== null && !neighborhood.has(n.id)),
        },
      }));
    });
    setEdges(
      flowData.edges.map((e) => ({
        ...e,
        animated: neighborhood !== null && (e.source === selectedNode || e.target === selectedNode),
        style: { ...e.style, opacity: neighborhood !== null && e.source !== selectedNode && e.target !== selectedNode ? 0.12 : matches.size ? 0.3 : 0.8 },
        label: selectedEdge === e.id || (neighborhood !== null && (e.source === selectedNode || e.target === selectedNode)) ? (e.data as { relation: string }).relation : undefined,
        labelStyle: { fontSize: 9, fill: "var(--muted-foreground)" },
      })),
    );
  }, [payload, visible, matches, neighborhood, selectedNode, selectedEdge, setNodes, setEdges]);

  const focusMatches = useCallback(() => {
    const points = nodes.filter((n) => matches.has(n.id)).map((n) => n.position);
    if (!points.length) return;
    if (points.length === 1) {
      flow.setCenter(points[0].x + 60, points[0].y + 12, { zoom: 1.3, duration: 600 });
      return;
    }
    const xs = points.map((p) => p.x);
    const ys = points.map((p) => p.y);
    const minX = Math.min(...xs);
    const minY = Math.min(...ys);
    flow.fitBounds({ x: minX - 80, y: minY - 60, width: Math.max(...xs) - minX + 280, height: Math.max(...ys) - minY + 140 }, { duration: 600, padding: 0.2 });
  }, [flow, matches, nodes]);

  const expand = useCallback(
    async (id: string) => {
      setExpanding(true);
      try {
        const extra = await api.graph(id, { kind: "asset", depth: 1, max_nodes: 200 });
        const anchor = nodes.find((n) => n.id === id)?.position;
        const before = payload.nodes.length;
        const merged = mergePayload(payload, extra, anchor);
        setPayload(merged);
        toast.success(`Added ${merged.nodes.length - before} node(s)`);
      } catch (e) {
        toast.error((e as Error).message);
      } finally {
        setExpanding(false);
      }
    },
    [nodes, payload],
  );

  const toggle = (set: Set<string>, value: string, update: (s: Set<string>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  const node = selectedNode ? payload.nodes.find((n) => n.id === selectedNode) ?? null : null;
  const edge = selectedEdge ? payload.edges.find((e) => e.id === selectedEdge) ?? null : null;

  return (
    <div className="bg-card flex h-[calc(100vh-11rem)] min-h-[520px] overflow-hidden rounded-xl border">
      <div className="relative min-w-0 flex-1">
        <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2">
          <form className="relative" onSubmit={(e) => { e.preventDefault(); focusMatches(); }}>
            <Search className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search & highlight…" className="bg-card/90 h-8 w-56 pl-8 text-xs backdrop-blur" />
          </form>
          {matches.size > 0 && <Badge variant="default">{matches.size} match(es)</Badge>}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" className="bg-card/90"><Filter /> Relationships ({relationTypes.length - hiddenRelations.size})</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem onSelect={(e) => { e.preventDefault(); setHiddenRelations(new Set()); }}>Show all</DropdownMenuItem>
              <DropdownMenuItem onSelect={(e) => { e.preventDefault(); setHiddenRelations(new Set(relationTypes.filter((r) => !r.startsWith("SHARES") && !r.startsWith("SIMILAR") && r !== "USES_CERTIFICATE"))); }}>Fingerprint links only</DropdownMenuItem>
              <DropdownMenuSeparator />
              {relationTypes.map((r) => (
                <DropdownMenuCheckboxItem key={r} checked={!hiddenRelations.has(r)} onCheckedChange={() => toggle(hiddenRelations, r, setHiddenRelations)} onSelect={(e) => e.preventDefault()}>
                  <span className="mr-2 inline-block size-2 rounded-full" style={{ background: RELATION_COLORS[r] ?? "#64748b" }} />
                  <span className="font-mono text-xs">{r}</span>
                  <span className="text-muted-foreground ml-auto pl-3 text-xs">{payload.stats.relationship_types[r] ?? ""}</span>
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" className="bg-card/90"><Network /> Node types</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuLabel>Show node types</DropdownMenuLabel>
              {nodeTypesPresent.map((t) => (
                <DropdownMenuCheckboxItem key={t} checked={!hiddenTypes.has(t)} onCheckedChange={() => toggle(hiddenTypes, t, setHiddenTypes)} onSelect={(e) => e.preventDefault()}>
                  <span className="mr-2 inline-block size-2 rounded-full" style={{ background: TYPE_COLORS[t] }} />
                  {t}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          {clusters.length > 0 && (
            <Select value={cluster} onValueChange={setCluster}>
              <SelectTrigger className="bg-card/90 h-8 w-48 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All clusters</SelectItem>
                {clusters.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
              </SelectContent>
            </Select>
          )}
          <Select value={String(minConfidence)} onValueChange={(v) => setMinConfidence(Number(v))}>
            <SelectTrigger className="bg-card/90 h-8 w-40 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {[0, 30, 50, 70, 90].map((v) => <SelectItem key={v} value={String(v)}>{v ? `Confidence ≥ ${v}` : "Any confidence"}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" className="bg-card/90" onClick={() => flow.fitView({ duration: 500, padding: 0.15 })}><Maximize2 /> Fit</Button>
        </div>
        <Button size="icon-sm" variant="outline" className="bg-card/90 absolute top-3 right-3 z-10" onClick={() => setSidebar((s) => !s)} aria-label="Toggle sidebar">
          {sidebar ? <PanelRightClose /> : <PanelRightOpen />}
        </Button>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, n) => { setSelectedNode(n.id); setSelectedEdge(null); setSidebar(true); }}
          onNodeDoubleClick={(_, n) => expand(n.id)}
          onEdgeClick={(_, e) => { setSelectedEdge(e.id); setSelectedNode(null); setSidebar(true); }}
          onPaneClick={() => { setSelectedNode(null); setSelectedEdge(null); }}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.05}
          maxZoom={2.5}
          onlyRenderVisibleElements
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border)" />
          <Controls position="bottom-left" />
          <MiniMap pannable zoomable position="bottom-right" nodeColor={(n) => TYPE_COLORS[(n.data as AssetNodeData).assetType] ?? "#64748b"} maskColor="rgba(0,0,0,0.5)" />
        </ReactFlow>
      </div>
      {sidebar && (
        <aside className="bg-sidebar w-80 shrink-0 overflow-y-auto border-l">
          <EvidenceSidebar
            node={node}
            edge={edge}
            payload={payload}
            investigationId={investigationId}
            onExpand={expand}
            expanding={expanding}
            onClose={() => { setSelectedNode(null); setSelectedEdge(null); }}
          />
        </aside>
      )}
    </div>
  );
}

function GraphPicker() {
  const navigate = useNavigate();
  const invs = useQuery({ queryKey: ["investigations", "graph-picker"], queryFn: () => api.investigations({ page_size: 12, status: "completed" }) });
  const clusters = useQuery({ queryKey: ["clusters", "graph-picker"], queryFn: () => api.clusters({ page_size: 12 }) });
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>Investigations</CardTitle></CardHeader>
        <CardContent className="space-y-1">
          {invs.data?.items.length ? invs.data.items.map((i) => (
            <button key={i.id} type="button" onClick={() => navigate(`/graph?investigation=${i.id}`)} className="hover:bg-accent flex w-full cursor-pointer items-center justify-between rounded-md border px-3 py-2 text-left">
              <span className="flex items-center gap-2"><TypeBadge type={i.ioc_type} /><Mono>{i.ioc}</Mono></span>
              <span className="text-muted-foreground text-xs">{i.summary?.relationships ?? 0} edges · {timeAgo(i.created_at)}</span>
            </button>
          )) : <EmptyState title="No completed investigations" />}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Threat clusters</CardTitle></CardHeader>
        <CardContent className="space-y-1">
          {clusters.data?.items.length ? clusters.data.items.map((c) => (
            <button key={c.id} type="button" onClick={() => navigate(`/graph?cluster=${c.id}`)} className="hover:bg-accent flex w-full cursor-pointer items-center justify-between rounded-md border px-3 py-2 text-left">
              <span className="truncate">{c.name}</span>
              <ConfidenceBadge score={c.confidence} />
            </button>
          )) : <EmptyState title="No clusters yet" />}
        </CardContent>
      </Card>
    </div>
  );
}

export default function GraphExplorerPage() {
  const [params] = useSearchParams();
  const investigation = params.get("investigation");
  const cluster = params.get("cluster");
  const asset = params.get("asset");
  const id = asset && !investigation ? asset : (cluster ?? investigation ?? asset);
  const kind = asset && !investigation ? "asset" : cluster ? "cluster" : investigation ? "investigation" : null;
  const graph = useQuery({
    queryKey: ["graph", id, kind],
    queryFn: () => api.graph(id!, { kind: kind!, depth: 2 }),
    enabled: !!id && !!kind,
  });

  return (
    <>
      <PageHeader
        title="Graph Explorer"
        description={
          kind ? (
            <span className="flex items-center gap-2">
              <Badge variant="secondary">{kind}</Badge>
              <Mono>{id}</Mono>
              {graph.data && <span>· {graph.data.stats.nodes} nodes · {graph.data.stats.edges} relationships</span>}
            </span>
          ) : (
            "Choose an investigation or cluster to explore its infrastructure graph"
          )
        }
        actions={
          kind === "investigation" && id ? (
            <Button variant="outline" asChild><Link to={`/investigations/${id}`}>Back to investigation</Link></Button>
          ) : kind === "cluster" && id ? (
            <Button variant="outline" asChild><Link to={`/clusters/${id}`}>Open cluster</Link></Button>
          ) : null
        }
      />
      {!kind ? (
        <GraphPicker />
      ) : graph.isLoading ? (
        <LoadingBlock label="Building graph…" />
      ) : graph.error ? (
        <ErrorBlock error={graph.error} />
      ) : graph.data && graph.data.nodes.length ? (
        <ReactFlowProvider>
          <GraphCanvas initial={graph.data} investigationId={investigation} initialSelected={asset && investigation ? asset : null} />
        </ReactFlowProvider>
      ) : (
        <EmptyState title="Empty graph" description="No relationships recorded yet." />
      )}
      <div className={cn("text-muted-foreground mt-2 flex flex-wrap gap-3 text-[11px]", !graph.data && "hidden")}>
        {Object.entries(TYPE_COLORS).map(([t, c]) => (
          <span key={t} className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: c }} />{t}</span>
        ))}
      </div>
    </>
  );
}
