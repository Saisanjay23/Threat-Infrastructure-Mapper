import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Network, Pencil } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, CopyButton, ErrorBlock, KeyValue, LoadingBlock, Mono, PageHeader } from "@/components/common";
import { AddToCaseDialog } from "@/components/AddToCaseDialog";
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
import { api, fileUrl } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { SEVERITY_VARIANT } from "@/pages/Clusters";
import type { Cluster } from "@/types/api";

function ValueList({ values, label }: { values: string[]; label: string }) {
  if (!values.length) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {values.slice(0, 40).map((v) => (
        <Badge key={v} variant="secondary" className="font-mono">{v}</Badge>
      ))}
      {values.length > 40 && <span className="text-muted-foreground text-xs">+{values.length - 40}</span>}
      <CopyButton value={values.join("\n")} label={`${values.length} ${label}`} />
    </div>
  );
}

export default function ClusterDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const cluster = useQuery({ queryKey: ["cluster", id], queryFn: () => api.cluster(id) });
  const members = useQuery({ queryKey: ["cluster-members", id], queryFn: () => api.assets({ cluster_id: id, page_size: 500, sort: "confidence" }) });
  const update = useMutation({
    mutationFn: (body: Partial<Pick<Cluster, "name" | "tags" | "severity">>) => api.updateCluster(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cluster", id] });
      setEditing(false);
      toast.success("Cluster updated");
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const addNote = useMutation({
    mutationFn: () => api.addClusterNote(id, note),
    onSuccess: () => {
      setNote("");
      qc.invalidateQueries({ queryKey: ["cluster", id] });
    },
  });

  if (cluster.isLoading) return <LoadingBlock />;
  if (cluster.error || !cluster.data) return <ErrorBlock error={cluster.error ?? "Cluster not found"} />;
  const c = cluster.data;

  return (
    <>
      <PageHeader
        title={
          editing ? (
            <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); update.mutate({ name }); }}>
              <Input value={name} onChange={(e) => setName(e.target.value)} className="w-96" autoFocus />
              <Button type="submit" size="sm">Save</Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
            </form>
          ) : (
            <span className="flex items-center gap-2">
              {c.name}
              {can("case:write") && (
                <Button variant="ghost" size="icon-sm" onClick={() => { setName(c.name); setEditing(true); }} aria-label="Rename"><Pencil /></Button>
              )}
            </span>
          )
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Mono>{c.id}</Mono>
            <Badge variant={SEVERITY_VARIANT[c.severity]} className="uppercase">{c.severity}</Badge>
            <ConfidenceBadge score={c.confidence} />
            <span>· created {formatDate(c.created_at)} · updated {formatDate(c.updated_at)}</span>
          </span>
        }
        actions={
          <>
            {can("case:write") && (
              <Select value={c.severity} onValueChange={(v) => update.mutate({ severity: v as Cluster["severity"] })}>
                <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            )}
            {can("report:export") && <ExportDialog scope={{ cluster_id: c.id }} defaultTitle={`Threat cluster report: ${c.name}`} />}
            {can("case:write") && <AddToCaseDialog links={{ cluster_ids: [c.id] }} trigger={<Button variant="outline">Add to case</Button>} />}
            <Button asChild>
              <Link to={`/graph?cluster=${c.id}`}><Network /> Open graph</Link>
            </Button>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        {[
          ["Domains", c.domains.length],
          ["IPs", c.ips.length],
          ["Certificates", c.certificates.length],
          ["Favicons", c.favicons.length],
          ["Tracking IDs", c.tracking_ids.length],
          ["Active", c.status_breakdown.ACTIVE ?? 0],
          ["Parked", c.status_breakdown.PARKED ?? 0],
          ["Taken down", c.status_breakdown.TAKEDOWN ?? 0],
        ].map(([label, value]) => (
          <div key={label as string} className="bg-card rounded-lg border px-3 py-2">
            <div className="text-muted-foreground text-[11px] uppercase tracking-wide">{label}</div>
            <div className="text-xl font-semibold tabular-nums">{value}</div>
          </div>
        ))}
      </div>

      <Tabs defaultValue="members">
        <TabsList>
          <TabsTrigger value="members">Members ({c.asset_ids.length})</TabsTrigger>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
          <TabsTrigger value="screenshots">Screenshots ({c.screenshots.length})</TabsTrigger>
          <TabsTrigger value="notes">Notes ({c.notes.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="members">
          <ResultsTable data={members.data?.items ?? []} loading={members.isLoading} storageKey="cluster" exportName={`tim-${c.id}`} />
        </TabsContent>
        <TabsContent value="evidence" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Why these assets belong together</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {c.evidence.map((e) => (
                <div key={e.feature} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                  <span className="font-medium">{e.feature}</span>
                  <span className="text-muted-foreground">shared by {e.members} member(s)</span>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Shared artefacts</CardTitle></CardHeader>
            <CardContent>
              <KeyValue
                items={[
                  ["Domains", <ValueList key="d" values={c.domains} label="domains" />],
                  ["IP addresses", <ValueList key="i" values={c.ips} label="IPs" />],
                  ["Tracking IDs", <ValueList key="t" values={c.tracking_ids} label="tracking IDs" />],
                  ["Favicon hashes", <ValueList key="f" values={c.favicons} label="favicon hashes" />],
                  ["Certificates", <ValueList key="c" values={c.certificates} label="certificates" />],
                  ["Brands", c.brands.length ? c.brands.join(", ") : null],
                  ["Investigations", c.investigation_ids.length ? (
                    <div className="flex flex-wrap gap-1">
                      {c.investigation_ids.map((i) => <Link key={i} to={`/investigations/${i}`} className="text-primary font-mono text-xs hover:underline">{i}</Link>)}
                    </div>
                  ) : null],
                ]}
              />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="screenshots">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
            {c.screenshots.map((s) => (
              <Link key={s.file_id} to={`/assets/${s.asset_id}`} className="hover:border-primary overflow-hidden rounded-lg border">
                <img src={fileUrl(s.file_id)} alt={s.value} className="aspect-video w-full bg-black object-cover object-top" loading="lazy" />
                <div className="truncate px-2 py-1 font-mono text-[11px]">{s.value}</div>
              </Link>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="notes">
          <Card>
            <CardContent className="space-y-3">
              {c.notes.map((n) => (
                <div key={n.id} className="rounded-lg border p-3">
                  <div className="text-muted-foreground mb-1 text-xs">{n.author} · {formatDate(n.created_at)}</div>
                  <div className="text-sm whitespace-pre-wrap">{n.text}</div>
                </div>
              ))}
              {can("case:write") && (
                <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (note.trim()) addNote.mutate(); }}>
                  <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an analyst note…" rows={3} />
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
