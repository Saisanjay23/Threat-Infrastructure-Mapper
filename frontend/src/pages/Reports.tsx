import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Download, FileText, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader } from "@/components/common";
import { ExportDialog } from "@/components/ExportDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";

type ScopeKind = "investigation" | "cluster" | "case";

function Generator() {
  const [kind, setKind] = useState<ScopeKind>("investigation");
  const [id, setId] = useState("");
  const invs = useQuery({ queryKey: ["investigations", "report-picker"], queryFn: () => api.investigations({ page_size: 50 }), enabled: kind === "investigation" });
  const clusters = useQuery({ queryKey: ["clusters", "report-picker"], queryFn: () => api.clusters({ page_size: 50 }), enabled: kind === "cluster" });
  const cases = useQuery({ queryKey: ["cases", "report-picker"], queryFn: () => api.cases({ page_size: 50 }), enabled: kind === "case" });
  const options: { id: string; label: string }[] =
    kind === "investigation"
      ? (invs.data?.items ?? []).map((i) => ({ id: i.id, label: `${i.ioc} · ${i.status}` }))
      : kind === "cluster"
        ? (clusters.data?.items ?? []).map((c) => ({ id: c.id, label: `${c.name} · ${c.id}` }))
        : (cases.data?.items ?? []).map((c) => ({ id: c.id, label: `${c.id} · ${c.title}` }));
  const scope = kind === "investigation" ? { investigation_id: id } : kind === "cluster" ? { cluster_id: id } : { case_id: id };
  return (
    <Card className="mb-4">
      <CardHeader>
        <div>
          <CardTitle className="flex items-center gap-2"><FileText className="size-4" /> Generate a report</CardTitle>
          <CardDescription>Executive summary, investigation details, evidence, screenshots, clusters, related assets, confidence scores, graph snapshot and analyst notes.</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        <Select value={kind} onValueChange={(v) => { setKind(v as ScopeKind); setId(""); }}>
          <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="investigation">Investigation</SelectItem>
            <SelectItem value="cluster">Threat cluster</SelectItem>
            <SelectItem value="case">Case</SelectItem>
          </SelectContent>
        </Select>
        <Select value={id} onValueChange={setId}>
          <SelectTrigger className="w-[28rem] max-w-full"><SelectValue placeholder={`Choose ${kind}…`} /></SelectTrigger>
          <SelectContent>{options.map((o) => <SelectItem key={o.id} value={o.id}>{o.label}</SelectItem>)}</SelectContent>
        </Select>
        {id ? <ExportDialog scope={scope} trigger={<Button><Download /> Configure & generate</Button>} /> : <Button disabled><Download /> Configure & generate</Button>}
      </CardContent>
    </Card>
  );
}

export default function ReportsPage() {
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const list = useQuery({ queryKey: ["reports", page], queryFn: () => api.reports({ page, page_size: 25 }), placeholderData: keepPreviousData });
  const remove = useMutation({
    mutationFn: (rid: string) => api.deleteReport(rid),
    onSuccess: () => {
      toast.success("Report deleted");
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
  });
  const pages = list.data ? Math.max(1, Math.ceil(list.data.total / list.data.page_size)) : 1;
  const scopeLink = (t: string, sid?: string | null) =>
    !sid ? null : t === "investigation" ? `/investigations/${sid}` : t === "cluster" ? `/clusters/${sid}` : t === "case" ? `/cases/${sid}` : null;

  return (
    <>
      <PageHeader title="Reports" description="PDF, HTML, CSV and JSON exports with a searchable report library" />
      <Generator />
      <Card>
        <CardHeader><CardTitle>Report library</CardTitle></CardHeader>
        <CardContent className="px-0">
          {list.isLoading ? <LoadingBlock /> : list.error ? <div className="px-5"><ErrorBlock error={list.error} /></div> : !list.data?.items.length ? (
            <div className="px-5"><EmptyState title="No reports yet" /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>TLP</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Author</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.data.items.map((r) => {
                  const link = scopeLink(r.scope_type, r.scope_id);
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="max-w-md truncate font-medium">{r.title}</TableCell>
                      <TableCell><Badge variant="secondary" className="uppercase">{r.format}</Badge></TableCell>
                      <TableCell className="text-xs">{r.scope_type} {link ? <Link to={link} className="text-primary hover:underline"><Mono>{r.scope_id}</Mono></Link> : null}</TableCell>
                      <TableCell><Badge variant="outline">TLP:{r.tlp}</Badge></TableCell>
                      <TableCell className="text-right tabular-nums text-xs">{(r.size / 1024).toFixed(0)} KB</TableCell>
                      <TableCell className="text-xs">{r.created_by}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{formatDate(r.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon-sm" asChild><a href={api.reportDownloadUrl(r.id)} aria-label="Download"><Download /></a></Button>
                        <Button variant="ghost" size="icon-sm" className="text-red-400" onClick={() => window.confirm("Delete this report?") && remove.mutate(r.id)} aria-label="Delete"><Trash2 /></Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
          <div className="flex items-center justify-end gap-2 px-5 pt-4 text-xs">
            <span className="text-muted-foreground">{list.data?.total ?? 0} report(s) · page {page} of {pages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="Previous page"><ChevronLeft /></Button>
            <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label="Next page"><ChevronRight /></Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
