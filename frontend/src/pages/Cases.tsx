import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, FolderPlus, Loader2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader } from "@/components/common";
import { Badge, type BadgeVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import type { Severity } from "@/types/api";

export const CASE_STATUS_VARIANT: Record<string, BadgeVariant> = { open: "info", in_progress: "warning", closed: "secondary" };
export const SEVERITY_BADGE: Record<string, BadgeVariant> = { critical: "destructive", high: "warning", medium: "info", low: "secondary", info: "outline" };

function NewCaseDialog() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [tags, setTags] = useState("");
  const create = useMutation({
    mutationFn: () => api.createCase({ title, description: description || undefined, severity, tags: tags.split(/[,\s]+/).filter(Boolean) }),
    onSuccess: (c) => {
      qc.invalidateQueries({ queryKey: ["cases"] });
      setOpen(false);
      navigate(`/cases/${c.id}`);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button><FolderPlus /> New case</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Create case</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5"><Label htmlFor="nc-title">Title</Label><Input id="nc-title" value={title} onChange={(e) => setTitle(e.target.value)} /></div>
          <div className="space-y-1.5"><Label htmlFor="nc-desc">Description</Label><Textarea id="nc-desc" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5"><Label htmlFor="nc-tags">Tags</Label><Input id="nc-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="phishing, brand-x" /></div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={() => create.mutate()} disabled={!title.trim() || create.isPending}>{create.isPending && <Loader2 className="animate-spin" />} Create</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CasesPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const list = useQuery({
    queryKey: ["cases", page, q, status, severity],
    queryFn: () => api.cases({ page, page_size: 25, q: q || undefined, status: status === "all" ? undefined : status, severity: severity === "all" ? undefined : severity }),
    placeholderData: keepPreviousData,
  });
  const pages = list.data ? Math.max(1, Math.ceil(list.data.total / list.data.page_size)) : 1;
  return (
    <>
      <PageHeader title="Cases" description="Track operations end-to-end: assets, investigations, clusters, notes and exports" actions={can("case:write") && <NewCaseDialog />} />
      <div className="mb-4 flex flex-wrap gap-2">
        <Input placeholder="Search cases…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="w-72" />
        <Select value={status} onValueChange={(v) => { setStatus(v); setPage(1); }}>
          <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>{["all", "open", "in_progress", "closed"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All statuses" : s}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={severity} onValueChange={(v) => { setSeverity(v); setPage(1); }}>
          <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>{["all", "critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All severities" : s}</SelectItem>)}</SelectContent>
        </Select>
      </div>
      <Card>
        <CardContent className="px-0">
          {list.isLoading ? <LoadingBlock /> : list.error ? <div className="px-5"><ErrorBlock error={list.error} /></div> : !list.data?.items.length ? (
            <div className="px-5"><EmptyState title="No cases" description="Create a case, or add assets to one from any results table." /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Case</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Assets</TableHead>
                  <TableHead className="text-right">Investigations</TableHead>
                  <TableHead className="text-right">Clusters</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.data.items.map((c) => (
                  <TableRow key={c.id} className="cursor-pointer" onClick={() => navigate(`/cases/${c.id}`)}>
                    <TableCell><Mono>{c.id}</Mono></TableCell>
                    <TableCell className="font-medium">{c.title}</TableCell>
                    <TableCell><Badge variant={SEVERITY_BADGE[c.severity]} className="uppercase">{c.severity}</Badge></TableCell>
                    <TableCell><Badge variant={CASE_STATUS_VARIANT[c.status]}>{c.status.replace("_", " ")}</Badge></TableCell>
                    <TableCell className="text-right tabular-nums">{c.asset_count}</TableCell>
                    <TableCell className="text-right tabular-nums">{c.investigation_count}</TableCell>
                    <TableCell className="text-right tabular-nums">{c.cluster_count}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{c.tags.join(", ") || "—"}</TableCell>
                    <TableCell className="text-xs">{c.assignee ?? c.created_by}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{timeAgo(c.updated_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <div className="flex items-center justify-end gap-2 px-5 pt-4 text-xs">
            <span className="text-muted-foreground">{list.data?.total ?? 0} case(s) · page {page} of {pages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="Previous page"><ChevronLeft /></Button>
            <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label="Next page"><ChevronRight /></Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
