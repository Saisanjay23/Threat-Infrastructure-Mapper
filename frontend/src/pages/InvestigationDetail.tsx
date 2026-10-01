import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, CircleDashed, Loader2, Network, RotateCcw, Square, Trash2, XCircle } from "lucide-react";
import { useCallback, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { BrandPanel, ContentPanel, InfrastructurePanel, ScreenshotGallery, WebPanel, WebsitePanel } from "@/components/asset-panels";
import { ConfidenceBadge, CopyButton, EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader, StatusBadge, TypeBadge } from "@/components/common";
import { AddToCaseDialog } from "@/components/AddToCaseDialog";
import { ExportDialog } from "@/components/ExportDialog";
import { InvestigationAssets } from "@/components/InvestigationAssets";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/hooks/useWebSocket";
import { api, fileUrl } from "@/lib/api";
import { cn, formatDate, timeAgo } from "@/lib/utils";
import type { Investigation, ProgressMessage, StageEvent, StageName, StageState } from "@/types/api";

const STAGES: { key: StageName; label: string; description: string }[] = [
  { key: "collection", label: "Collection", description: "HTTP, redirects, TLS, favicon, screenshots, DNS, WHOIS, ASN" },
  { key: "enrichment", label: "Enrichment", description: "CT logs, history, reputation, credit sources" },
  { key: "pivot", label: "Pivot", description: "Expand via certificates, favicons, trackers, infrastructure" },
  { key: "correlation", label: "Correlation", description: "Score relationships and build threat clusters" },
];

const STAGE_ICON: Record<string, ReactNode> = {
  pending: <CircleDashed className="text-muted-foreground size-4" />,
  running: <Loader2 className="size-4 animate-spin text-sky-300" />,
  completed: <CheckCircle2 className="size-4 text-emerald-400" />,
  failed: <XCircle className="size-4 text-red-400" />,
  skipped: <CircleDashed className="text-muted-foreground size-4" />,
};

function StageCard({ label, description, state }: { label: string; description: string; state?: StageState }) {
  const status = state?.status ?? "pending";
  return (
    <div className={cn("rounded-lg border p-4 transition-colors", status === "running" && "border-sky-400/50 bg-sky-400/5")}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 font-medium">
          {STAGE_ICON[status]} {label}
        </div>
        <span className="text-muted-foreground text-xs tabular-nums">{state?.progress ?? 0}%</span>
      </div>
      <Progress
        value={status === "completed" ? 100 : (state?.progress ?? 0)}
        className="mt-3"
        indicatorClassName={status === "failed" ? "bg-destructive" : status === "completed" ? "bg-emerald-400" : undefined}
      />
      <div className="text-muted-foreground mt-2 line-clamp-2 min-h-8 text-xs">{state?.message ?? description}</div>
    </div>
  );
}

export default function InvestigationDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [live, setLive] = useState<Investigation | null>(null);
  const [note, setNote] = useState("");

  const query = useQuery({ queryKey: ["investigation", id], queryFn: () => api.investigation(id), enabled: !!id });
  const inv = live ?? query.data ?? null;
  const done = inv ? ["completed", "failed", "cancelled"].includes(inv.status) : false;

  const onMessage = useCallback(
    (msg: ProgressMessage) => {
      if (msg.type === "snapshot" && msg.investigation) {
        setLive(msg.investigation);
        return;
      }
      setLive((prev) => {
        const base = prev ?? query.data;
        if (!base) return prev;
        const next: Investigation = { ...base, stages: { ...base.stages } };
        const stage = msg.stage as StageName | undefined;
        if (stage && next.stages[stage]) {
          const st = { ...next.stages[stage] };
          if (msg.type === "stage_progress") {
            st.progress = msg.progress ?? st.progress;
            if (msg.message) st.message = msg.message;
          } else if (msg.type === "stage_event") {
            st.events = [...st.events, { timestamp: msg.timestamp ?? new Date().toISOString(), level: msg.level ?? "info", message: msg.message ?? "" }];
          } else if (msg.type === "stage_started") {
            st.status = "running";
          } else if (msg.type === "stage_completed") {
            st.status = "completed";
            st.progress = 100;
            st.message = msg.message ?? st.message;
          } else if (msg.type === "stage_failed") {
            st.status = "failed";
            st.message = String(msg.error ?? "failed");
          }
          next.stages[stage] = st;
        }
        if (msg.type === "investigation_status" && msg.status) {
          next.status = msg.status;
          if (["completed", "failed", "cancelled"].includes(msg.status)) {
            qc.invalidateQueries({ queryKey: ["investigation", id] });
            qc.invalidateQueries({ queryKey: ["investigation-assets", id] });
            qc.invalidateQueries({ queryKey: ["investigation-root", id] });
            setTimeout(() => setLive(null), 300);
          }
        }
        return next;
      });
    },
    [id, qc, query.data],
  );
  const wsState = useWebSocket(id ? `/ws/investigations/${id}` : null, onMessage, !!query.data && !done);

  const root = useQuery({
    queryKey: ["investigation-root", id, inv?.root_asset_id, done],
    queryFn: () => api.asset(inv!.root_asset_id!),
    enabled: !!inv?.root_asset_id,
  });
  const hostAsset = useQuery({
    queryKey: ["investigation-host", id, done],
    queryFn: async () => {
      const page = await api.investigationAssets(id, { type: inv?.ioc_type === "ip" ? "ip" : "domain", page_size: 50 });
      return page.items.find((a) => a.attributes?.web || a.attributes?.infrastructure) ?? null;
    },
    enabled: !!inv && inv.ioc_type === "url",
  });
  const runs = useQuery({ queryKey: ["provider-runs", id, done], queryFn: () => api.providerRuns(id), enabled: !!inv });
  const artifacts = useQuery({ queryKey: ["artifacts", id, done], queryFn: () => api.investigationArtifacts(id), enabled: !!inv });

  const cancel = useMutation({ mutationFn: () => api.cancelInvestigation(id), onSuccess: () => toast.info("Cancellation requested"), onError: (e: Error) => toast.error(e.message) });
  const rerun = useMutation({ mutationFn: () => api.rerunInvestigation(id), onSuccess: (n) => navigate(`/investigations/${n.id}`), onError: (e: Error) => toast.error(e.message) });
  const remove = useMutation({
    mutationFn: () => api.deleteInvestigation(id),
    onSuccess: () => {
      toast.success("Investigation deleted");
      navigate("/investigations");
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const addNote = useMutation({
    mutationFn: () => api.addNote(id, note),
    onSuccess: () => {
      setNote("");
      qc.invalidateQueries({ queryKey: ["investigation", id] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const events = useMemo(() => {
    if (!inv) return [] as (StageEvent & { stage: string })[];
    return STAGES.flatMap((s) => (inv.stages[s.key]?.events ?? []).map((e) => ({ ...e, stage: s.key }))).sort((a, b) =>
      a.timestamp < b.timestamp ? 1 : -1,
    );
  }, [inv]);

  if (query.isLoading) return <LoadingBlock />;
  if (query.error || !inv) return <ErrorBlock error={query.error ?? "Not found"} />;

  const overall = Math.round(STAGES.reduce((acc, s) => acc + (inv.stages[s.key]?.status === "skipped" ? 100 : inv.stages[s.key]?.progress ?? 0), 0) / STAGES.length);
  const profile = (inv.ioc_type === "url" ? hostAsset.data : null) ?? root.data?.asset;
  const screenshots = root.data?.asset.attributes.screenshots ?? profile?.attributes.screenshots;

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <TypeBadge type={inv.ioc_type} />
            <Mono className="text-xl">{inv.normalized}</Mono>
            <CopyButton value={inv.normalized} label="IOC" />
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadge status={inv.status} /> started by {inv.created_by} · {formatDate(inv.created_at)}
            {inv.finished_at && <> · finished {timeAgo(inv.finished_at)}</>}
            {!done && <Badge variant={wsState === "open" ? "success" : "secondary"}>live {wsState}</Badge>}
            {inv.tags.map((t) => (
              <Badge key={t} variant="outline">#{t}</Badge>
            ))}
          </span>
        }
        actions={
          <>
            <Button variant="outline" asChild>
              <Link to={`/graph?investigation=${inv.id}`}>
                <Network /> Open graph
              </Link>
            </Button>
            {can("report:export") && done && <ExportDialog scope={{ investigation_id: inv.id }} />}
            {can("case:write") && (
              <AddToCaseDialog links={{ investigation_ids: [inv.id] }} trigger={<Button variant="outline">Add to case</Button>} />
            )}
            {can("investigation:write") && !done && (
              <Button variant="outline" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
                <Square /> Cancel
              </Button>
            )}
            {can("investigation:write") && done && (
              <Button variant="outline" onClick={() => rerun.mutate()} disabled={rerun.isPending}>
                <RotateCcw /> Re-run
              </Button>
            )}
            {can("investigation:write") && (
              <Button
                variant="ghost"
                className="text-red-400"
                onClick={() => {
                  if (window.confirm("Delete this investigation and its raw artifacts? Discovered assets are kept.")) remove.mutate();
                }}
              >
                <Trash2 /> Delete
              </Button>
            )}
          </>
        }
      />

      <Card className="mb-4">
        <CardHeader>
          <div>
            <CardTitle>Pipeline</CardTitle>
            <CardDescription>{done ? `Finished with status ${inv.status}` : `Overall ${overall}%`}</CardDescription>
          </div>
          {inv.error && (
            <Badge variant="warning" className="max-w-md truncate">
              <AlertTriangle /> {inv.error}
            </Badge>
          )}
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {STAGES.map((s) => (
            <StageCard key={s.key} label={s.label} description={s.description} state={inv.stages[s.key]} />
          ))}
        </CardContent>
      </Card>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        {(
          [
            ["Assets", inv.summary?.assets_discovered],
            ["Domains", inv.summary?.domains],
            ["IPs", inv.summary?.ips],
            ["Certificates", inv.summary?.certificates],
            ["Tracking IDs", inv.summary?.tracking_ids],
            ["Relationships", inv.summary?.relationships],
            ["Clusters", inv.summary?.clusters],
            ["High confidence", inv.summary?.high_confidence],
          ] as [string, number | undefined][]
        ).map(([label, value]) => (
          <div key={label} className="bg-card rounded-lg border px-3 py-2">
            <div className="text-muted-foreground text-[11px] uppercase tracking-wide">{label}</div>
            <div className="text-xl font-semibold tabular-nums">{value ?? 0}</div>
          </div>
        ))}
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="assets">Results</TabsTrigger>
          <TabsTrigger value="log">Event log ({events.length})</TabsTrigger>
          <TabsTrigger value="providers">Provider runs ({runs.data?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="artifacts">Artifacts ({artifacts.data?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="notes">Notes ({inv.notes.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {profile ? (
            <>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <span className="text-muted-foreground">Site status</span> <StatusBadge status={profile.status} />
                <span className="text-muted-foreground ml-4">Impersonation</span> <ConfidenceBadge score={profile.impersonation_score} />
                <span className="text-muted-foreground ml-4">Max correlation</span> <ConfidenceBadge score={inv.summary?.max_confidence || null} />
                <Link to={`/assets/${profile.id}`} className="text-primary ml-auto text-sm hover:underline">
                  Open asset →
                </Link>
              </div>
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                <WebPanel asset={profile} />
                <InfrastructurePanel asset={profile} />
                <ContentPanel asset={profile} />
                <BrandPanel asset={profile} />
                <div className="xl:col-span-2">
                  <WebsitePanel asset={profile} />
                </div>
              </div>
            </>
          ) : root.isLoading ? (
            <LoadingBlock />
          ) : (
            <EmptyState title="Waiting for collection" description="The asset profile appears once the collection stage creates the root asset." />
          )}
          <Card>
            <CardHeader>
              <CardTitle>Screenshots</CardTitle>
            </CardHeader>
            <CardContent>
              <ScreenshotGallery screenshots={screenshots} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="assets">
          <InvestigationAssets investigationId={inv.id} refreshKey={done ? "done" : inv.status} />
        </TabsContent>

        <TabsContent value="log">
          <Card>
            <CardContent className="max-h-[560px] overflow-y-auto font-mono text-xs">
              {events.length ? (
                events.map((e, i) => (
                  <div key={i} className="flex gap-3 border-b border-dashed py-1.5 last:border-0">
                    <span className="text-muted-foreground shrink-0">{new Date(e.timestamp).toLocaleTimeString()}</span>
                    <span className="w-24 shrink-0 text-sky-300">{e.stage}</span>
                    <span className={cn("whitespace-pre-wrap break-all", e.level === "warning" && "text-amber-300", e.level === "error" && "text-red-400")}>
                      {e.message}
                    </span>
                  </div>
                ))
              ) : (
                <EmptyState title="No events yet" />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="providers">
          <Card>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Provider</TableHead>
                    <TableHead>Stage</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="text-right">Related</TableHead>
                    <TableHead className="text-right">Latency</TableHead>
                    <TableHead>Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(runs.data ?? []).map((r, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-medium">{r.provider}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{r.stage}</TableCell>
                      <TableCell><Mono>{r.target}</Mono></TableCell>
                      <TableCell>
                        {r.skipped ? <Badge variant="secondary">skipped</Badge> : r.ok ? <Badge variant="success">{r.cached ? "cached" : "ok"}</Badge> : <Badge variant="destructive">error</Badge>}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{r.related_count}</TableCell>
                      <TableCell className="text-right tabular-nums text-xs">{r.cached ? "—" : `${Math.round(r.latency_ms)} ms`}</TableCell>
                      <TableCell className="text-muted-foreground max-w-md truncate text-xs" title={r.error ?? ""}>{r.error ?? Object.keys(r.summary ?? {}).slice(0, 6).join(", ")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="artifacts">
          <Card>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Kind</TableHead>
                    <TableHead>Content type</TableHead>
                    <TableHead className="text-right">Size</TableHead>
                    <TableHead>SHA-256</TableHead>
                    <TableHead>Collected</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(artifacts.data ?? []).map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-medium">{a.kind}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{a.content_type}</TableCell>
                      <TableCell className="text-right tabular-nums text-xs">{a.size != null ? `${(a.size / 1024).toFixed(1)} KB` : "—"}</TableCell>
                      <TableCell><Mono className="text-muted-foreground">{a.sha256 ? `${a.sha256.slice(0, 16)}…` : "—"}</Mono></TableCell>
                      <TableCell className="text-muted-foreground text-xs">{formatDate(a.created_at)}</TableCell>
                      <TableCell className="text-right">
                        {a.file_id ? (
                          <a className="text-primary text-xs hover:underline" href={fileUrl(a.file_id, true)}>download</a>
                        ) : a.data ? (
                          <button
                            type="button"
                            className="text-primary cursor-pointer text-xs hover:underline"
                            onClick={() => {
                              const blob = new Blob([JSON.stringify(a.data, null, 2)], { type: "application/json" });
                              const url = URL.createObjectURL(blob);
                              window.open(url, "_blank", "noopener");
                              setTimeout(() => URL.revokeObjectURL(url), 60000);
                            }}
                          >
                            view JSON
                          </button>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notes">
          <Card>
            <CardContent className="space-y-4">
              {inv.notes.length ? (
                inv.notes.map((n) => (
                  <div key={n.id} className="rounded-lg border p-3">
                    <div className="text-muted-foreground mb-1 text-xs">
                      {n.author} · {formatDate(n.created_at)}
                    </div>
                    <div className="text-sm whitespace-pre-wrap">{n.text}</div>
                  </div>
                ))
              ) : (
                <div className="text-muted-foreground text-sm">No analyst notes yet.</div>
              )}
              {can("investigation:write") && (
                <form
                  className="space-y-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (note.trim()) addNote.mutate();
                  }}
                >
                  <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an analyst note…" rows={3} />
                  <Button type="submit" size="sm" disabled={!note.trim() || addNote.isPending}>
                    Add note
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  );
}
