import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Loader2, RefreshCw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, EmptyState, ErrorBlock, LoadingBlock, PageHeader } from "@/components/common";
import { Badge, type BadgeVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/hooks/useAuth";
import { api, fileUrl } from "@/lib/api";
import { timeAgo } from "@/lib/utils";

export const SEVERITY_VARIANT: Record<string, BadgeVariant> = {
  critical: "destructive",
  high: "warning",
  medium: "info",
  low: "secondary",
  info: "outline",
};

export default function ClustersPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [minConfidence, setMinConfidence] = useState("0");
  const [sort, setSort] = useState<"updated_at" | "confidence" | "created_at">("updated_at");
  const list = useQuery({
    queryKey: ["clusters", page, q, severity, minConfidence, sort],
    queryFn: () =>
      api.clusters({ page, page_size: 24, q: q || undefined, severity: severity === "all" ? undefined : severity, min_confidence: Number(minConfidence) || undefined, sort }),
    placeholderData: keepPreviousData,
  });
  const rebuild = useMutation({
    mutationFn: api.rebuildClusters,
    onSuccess: (r) => {
      toast.success(`Re-clustered inventory: ${r.count} cluster(s)`);
      qc.invalidateQueries({ queryKey: ["clusters"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const pages = list.data ? Math.max(1, Math.ceil(list.data.total / list.data.page_size)) : 1;

  return (
    <>
      <PageHeader
        title="Threat Clusters"
        description="Infrastructure automatically grouped into operations by shared, distinctive fingerprints"
        actions={
          can("settings:admin") && (
            <Button variant="outline" onClick={() => rebuild.mutate()} disabled={rebuild.isPending}>
              {rebuild.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Re-cluster inventory
            </Button>
          )
        }
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <Input placeholder="Search name, domain, IP, tracking ID, cluster ID…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="w-80" />
        <Select value={severity} onValueChange={(v) => { setSeverity(v); setPage(1); }}>
          <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={minConfidence} onValueChange={(v) => { setMinConfidence(v); setPage(1); }}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            {["0", "30", "50", "70", "90"].map((v) => <SelectItem key={v} value={v}>{v === "0" ? "Any confidence" : `Confidence ≥ ${v}`}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={sort} onValueChange={(v) => setSort(v as typeof sort)}>
          <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="updated_at">Recently updated</SelectItem>
            <SelectItem value="confidence">Highest confidence</SelectItem>
            <SelectItem value="created_at">Newest</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {list.isLoading ? (
        <LoadingBlock />
      ) : list.error ? (
        <ErrorBlock error={list.error} />
      ) : !list.data?.items.length ? (
        <EmptyState title="No clusters" description="Clusters form automatically when an investigation correlates two or more hosts above the cluster threshold." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {list.data.items.map((c) => (
            <Link key={c.id} to={`/clusters/${c.id}`} className="group">
              <Card className="group-hover:border-primary h-full transition-colors">
                <CardHeader>
                  <div className="min-w-0">
                    <CardTitle className="flex items-center gap-2 truncate">
                      <ShieldAlert className="size-4 shrink-0 text-red-400" />
                      <span className="truncate">{c.name}</span>
                    </CardTitle>
                    <div className="text-muted-foreground mt-1 font-mono text-[11px]">{c.id}</div>
                  </div>
                  <Badge variant={SEVERITY_VARIANT[c.severity] ?? "secondary"} className="uppercase">{c.severity}</Badge>
                </CardHeader>
                <CardContent className="space-y-3">
                  {c.screenshots.length > 0 && (
                    <div className="grid grid-cols-4 gap-1.5">
                      {c.screenshots.slice(0, 4).map((s) => (
                        <img key={s.file_id} src={fileUrl(s.file_id)} alt={s.value} loading="lazy" className="aspect-video w-full rounded border bg-black object-cover object-top" />
                      ))}
                    </div>
                  )}
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <ConfidenceBadge score={c.confidence} />
                    <Badge variant="outline">{c.counts.domain ?? 0} domains</Badge>
                    <Badge variant="outline">{c.counts.ip ?? 0} IPs</Badge>
                    {(c.counts.analytics ?? 0) + (c.counts.pixel ?? 0) + (c.counts.tracking ?? 0) > 0 && (
                      <Badge variant="warning">{(c.counts.analytics ?? 0) + (c.counts.pixel ?? 0) + (c.counts.tracking ?? 0)} trackers</Badge>
                    )}
                    {(c.counts.certificate ?? 0) > 0 && <Badge variant="success">{c.counts.certificate} certs</Badge>}
                    {c.brands.map((b) => <Badge key={b} variant="purple">{b}</Badge>)}
                  </div>
                  <div className="text-muted-foreground line-clamp-2 font-mono text-[11px]">{c.domains.slice(0, 6).join(" · ")}</div>
                  <div className="flex flex-wrap gap-1">
                    {c.evidence.slice(0, 5).map((e) => (
                      <Badge key={e.feature} variant="secondary" className="text-[10px]">{e.feature} ×{e.members}</Badge>
                    ))}
                  </div>
                  <div className="text-muted-foreground text-[11px]">
                    {c.status_breakdown.ACTIVE ?? 0} active · updated {timeAgo(c.updated_at)}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
      <div className="mt-4 flex items-center justify-end gap-2 text-xs">
        <span className="text-muted-foreground">{list.data?.total ?? 0} cluster(s) · page {page} of {pages}</span>
        <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="Previous page"><ChevronLeft /></Button>
        <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label="Next page"><ChevronRight /></Button>
      </div>
    </>
  );
}
