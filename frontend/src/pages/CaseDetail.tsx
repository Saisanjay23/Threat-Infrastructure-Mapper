import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2, X } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader, StatusBadge, TypeBadge } from "@/components/common";
import { ExportDialog } from "@/components/ExportDialog";
import { ResultsTable } from "@/components/ResultsTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/utils";
import { CASE_STATUS_VARIANT, SEVERITY_BADGE } from "@/pages/Cases";
import type { Case, CaseStatus, Severity } from "@/types/api";

export default function CaseDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const write = can("case:write");
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [note, setNote] = useState("");
  const [tag, setTag] = useState("");
  const [desc, setDesc] = useState<string | null>(null);
  const c = useQuery({ queryKey: ["case", id], queryFn: () => api.case(id) });
  const assets = useQuery({ queryKey: ["case-assets", id, c.data?.asset_ids.length], queryFn: () => api.assets({ case_id: id, page_size: 500, sort: "confidence" }), enabled: !!c.data });
  const invs = useQuery({
    queryKey: ["case-invs", id, c.data?.investigation_ids.join(",")],
    queryFn: async () => Promise.all((c.data?.investigation_ids ?? []).map((i) => api.investigation(i).catch(() => null))),
    enabled: !!c.data?.investigation_ids.length,
  });
  const clusters = useQuery({
    queryKey: ["case-clusters", id, c.data?.cluster_ids.join(",")],
    queryFn: async () => Promise.all((c.data?.cluster_ids ?? []).map((i) => api.cluster(i).catch(() => null))),
    enabled: !!c.data?.cluster_ids.length,
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["case", id] });
    qc.invalidateQueries({ queryKey: ["cases"] });
  };
  const update = useMutation({
    mutationFn: (body: Partial<Pick<Case, "title" | "description" | "severity" | "status" | "tags" | "assignee">>) => api.updateCase(id, body),
    onSuccess: refresh,
    onError: (e: Error) => toast.error(e.message),
  });
  const unlink = useMutation({ mutationFn: (body: Parameters<typeof api.unlinkCase>[1]) => api.unlinkCase(id, body), onSuccess: refresh });
  const addNote = useMutation({ mutationFn: () => api.addCaseNote(id, note), onSuccess: () => { setNote(""); refresh(); } });
  const remove = useMutation({ mutationFn: () => api.deleteCase(id), onSuccess: () => { toast.success("Case deleted"); navigate("/cases"); } });

  if (c.isLoading) return <LoadingBlock />;
  if (c.error || !c.data) return <ErrorBlock error={c.error ?? "Case not found"} />;
  const data = c.data;

  return (
    <>
      <PageHeader
        title={data.title}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Mono>{data.id}</Mono>
            <Badge variant={SEVERITY_BADGE[data.severity]} className="uppercase">{data.severity}</Badge>
            <Badge variant={CASE_STATUS_VARIANT[data.status]}>{data.status.replace("_", " ")}</Badge>
            <span>· opened by {data.created_by} {timeAgo(data.created_at)} · updated {timeAgo(data.updated_at)}</span>
          </span>
        }
        actions={
          <>
            {write && (
              <>
                <Select value={data.status} onValueChange={(v) => update.mutate({ status: v as CaseStatus })}>
                  <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
                  <SelectContent>{["open", "in_progress", "closed"].map((s) => <SelectItem key={s} value={s}>{s.replace("_", " ")}</SelectItem>)}</SelectContent>
                </Select>
                <Select value={data.severity} onValueChange={(v) => update.mutate({ severity: v as Severity })}>
                  <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                  <SelectContent>{["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
                </Select>
              </>
            )}
            {can("report:export") && <ExportDialog scope={{ case_id: data.id }} defaultTitle={`Case ${data.id}: ${data.title}`} />}
            {write && (
              <Button variant="ghost" className="text-red-400" onClick={() => window.confirm("Delete this case? Linked assets and investigations are kept.") && remove.mutate()}>
                <Trash2 /> Delete
              </Button>
            )}
          </>
        }
      />
      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle>Description</CardTitle></CardHeader>
          <CardContent>
            {desc !== null ? (
              <div className="space-y-2">
                <Textarea rows={5} value={desc} onChange={(e) => setDesc(e.target.value)} />
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => { update.mutate({ description: desc }); setDesc(null); }}>Save</Button>
                  <Button size="sm" variant="ghost" onClick={() => setDesc(null)}>Cancel</Button>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-sm whitespace-pre-wrap">{data.description || <span className="text-muted-foreground">No description.</span>}</p>
                {write && <Button size="sm" variant="outline" onClick={() => setDesc(data.description ?? "")}>Edit</Button>}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Tags & assignment</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-1">
              {data.tags.map((t) => (
                <Badge key={t} variant="outline" className="gap-1">
                  #{t}
                  {write && <button type="button" className="cursor-pointer" onClick={() => update.mutate({ tags: data.tags.filter((x) => x !== t) })} aria-label={`Remove ${t}`}><X className="size-3" /></button>}
                </Badge>
              ))}
            </div>
            {write && (
              <form onSubmit={(e) => { e.preventDefault(); if (tag.trim()) { update.mutate({ tags: [...data.tags, tag.trim()] }); setTag(""); } }}>
                <Input value={tag} onChange={(e) => setTag(e.target.value)} placeholder="Add tag and press Enter" className="h-8" />
              </form>
            )}
            {write && (
              <Input defaultValue={data.assignee ?? ""} placeholder="Assignee" className="h-8" onBlur={(e) => e.target.value !== (data.assignee ?? "") && update.mutate({ assignee: e.target.value || null })} />
            )}
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="assets">
        <TabsList>
          <TabsTrigger value="assets">Assets ({data.asset_ids.length})</TabsTrigger>
          <TabsTrigger value="investigations">Investigations ({data.investigation_ids.length})</TabsTrigger>
          <TabsTrigger value="clusters">Clusters ({data.cluster_ids.length})</TabsTrigger>
          <TabsTrigger value="notes">Notes ({data.notes.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="assets">
          {data.asset_ids.length ? (
            <ResultsTable data={assets.data?.items ?? []} loading={assets.isLoading} storageKey="case" exportName={`tim-${data.id}`} />
          ) : (
            <EmptyState title="No assets yet" description="Select rows in any results table and choose “Add to case”." />
          )}
        </TabsContent>
        <TabsContent value="investigations" className="space-y-2">
          {(invs.data ?? []).filter(Boolean).map((inv) => inv && (
            <div key={inv.id} className="bg-card flex items-center justify-between rounded-lg border px-4 py-2">
              <Link to={`/investigations/${inv.id}`} className="hover:text-primary flex items-center gap-2"><TypeBadge type={inv.ioc_type} /><Mono>{inv.normalized}</Mono></Link>
              <div className="flex items-center gap-3 text-xs">
                <StatusBadge status={inv.status} /> <span className="text-muted-foreground">{inv.summary?.assets_discovered ?? 0} assets · {formatDate(inv.created_at)}</span>
                {write && <Button variant="ghost" size="icon-sm" onClick={() => unlink.mutate({ investigation_ids: [inv.id] })} aria-label="Remove"><X /></Button>}
              </div>
            </div>
          ))}
          {!data.investigation_ids.length && <EmptyState title="No investigations linked" />}
        </TabsContent>
        <TabsContent value="clusters" className="space-y-2">
          {(clusters.data ?? []).filter(Boolean).map((cl) => cl && (
            <div key={cl.id} className="bg-card flex items-center justify-between rounded-lg border px-4 py-2">
              <Link to={`/clusters/${cl.id}`} className="hover:text-primary">{cl.name} <Mono className="text-muted-foreground">{cl.id}</Mono></Link>
              <div className="flex items-center gap-2">
                <ConfidenceBadge score={cl.confidence} />
                {write && <Button variant="ghost" size="icon-sm" onClick={() => unlink.mutate({ cluster_ids: [cl.id] })} aria-label="Remove"><X /></Button>}
              </div>
            </div>
          ))}
          {!data.cluster_ids.length && <EmptyState title="No clusters linked" />}
        </TabsContent>
        <TabsContent value="notes">
          <Card>
            <CardContent className="space-y-3">
              {data.notes.map((n) => (
                <div key={n.id} className="rounded-lg border p-3">
                  <div className="text-muted-foreground mb-1 text-xs">{n.author} · {formatDate(n.created_at)}</div>
                  <div className="text-sm whitespace-pre-wrap">{n.text}</div>
                </div>
              ))}
              {write && (
                <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (note.trim()) addNote.mutate(); }}>
                  <Textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Add a case note…" />
                  <Button type="submit" size="sm" disabled={!note.trim()}>Add note</Button>
                </form>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  );
}
