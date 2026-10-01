import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, FileUp, ListPlus, Loader2, Radar, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, EmptyState, ErrorBlock, LoadingBlock, PageHeader, StatusBadge, TypeBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { UploadPanel } from "@/components/UploadPanel";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/hooks/useWebSocket";
import { api } from "@/lib/api";
import { formatDate, timeAgo, truncate } from "@/lib/utils";
import type { CreditPolicy, InvestigationOptions, InvestigationStatus } from "@/types/api";

function OptionsForm({ value, onChange }: { value: Partial<InvestigationOptions>; onChange: (v: Partial<InvestigationOptions>) => void }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      <div className="space-y-2">
        <Label>Credit-based sources</Label>
        <Select value={value.credit_policy ?? "when_needed"} onValueChange={(v) => onChange({ ...value, credit_policy: v as CreditPolicy })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="when_needed">Only when needed</SelectItem>
            <SelectItem value="never">Never (free only)</SelectItem>
            <SelectItem value="always">Always</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label htmlFor="brand">Brand to protect (optional)</Label>
        <Input id="brand" placeholder="e.g. Contoso Bank" value={value.brand ?? ""} onChange={(e) => onChange({ ...value, brand: e.target.value || null })} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="brand_domains">Legitimate brand domains</Label>
        <Input
          id="brand_domains"
          placeholder="contoso.com, contoso.co.uk"
          value={(value.brand_domains ?? []).join(", ")}
          onChange={(e) => onChange({ ...value, brand_domains: e.target.value.split(/[,\s]+/).filter(Boolean) })}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="max_pivot">Max pivot expansions</Label>
        <Input
          id="max_pivot"
          type="number"
          min={0}
          max={200}
          value={value.max_pivot_assets ?? 15}
          onChange={(e) => onChange({ ...value, max_pivot_assets: Number(e.target.value) })}
        />
      </div>
      <label className="flex items-center gap-3 text-sm">
        <Switch checked={value.screenshots ?? true} onCheckedChange={(c) => onChange({ ...value, screenshots: c })} /> Capture screenshots
      </label>
      <label className="flex items-center gap-3 text-sm">
        <Switch checked={value.expand_pivots ?? true} onCheckedChange={(c) => onChange({ ...value, expand_pivots: c })} /> Expand pivots
      </label>
    </div>
  );
}

export default function InvestigationsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [ioc, setIoc] = useState("");
  const [bulk, setBulk] = useState("");
  const [tags, setTags] = useState("");
  const [options, setOptions] = useState<Partial<InvestigationOptions>>({ credit_policy: "when_needed", screenshots: true, expand_pivots: true, max_pivot_assets: 15 });
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<InvestigationStatus | "all">("all");

  const list = useQuery({
    queryKey: ["investigations", page, q, status],
    queryFn: () => api.investigations({ page, page_size: 25, q: q || undefined, status: status === "all" ? undefined : status }),
    refetchInterval: 15000,
  });

  useWebSocket("/ws/events", (msg) => {
    if (msg.type === "investigation_status" || msg.type === "investigation_queued") qc.invalidateQueries({ queryKey: ["investigations"] });
  });

  const tagList = tags.split(/[,\s]+/).filter(Boolean);
  const single = useMutation({
    mutationFn: () => api.investigate(ioc.trim(), options, tagList),
    onSuccess: (inv) => {
      toast.success(`Investigation started for ${inv.normalized}`);
      navigate(`/investigations/${inv.id}`);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const bulkRun = useMutation({
    mutationFn: () => api.bulkInvestigate(bulk.split(/\r?\n/).map((l) => l.trim()).filter(Boolean), options, tagList),
    onSuccess: (res) => {
      toast.success(`${res.investigation_ids.length} investigation(s) queued`);
      if (res.rejected.length) toast.warning(`${res.rejected.length} rejected: ${res.rejected.slice(0, 3).map((r) => `${r.ioc} (${r.reason})`).join(", ")}`);
      setBulk("");
      qc.invalidateQueries({ queryKey: ["investigations"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const totalPages = list.data ? Math.max(1, Math.ceil(list.data.total / list.data.page_size)) : 1;

  return (
    <>
      <PageHeader title="Investigations" description="Turn a single IOC into a full infrastructure investigation" />
      {can("investigation:write") && (
        <Card className="glow mb-6">
          <CardContent>
            <Tabs defaultValue="single">
              <TabsList>
                <TabsTrigger value="single">
                  <Radar /> Single IOC
                </TabsTrigger>
                <TabsTrigger value="bulk">
                  <ListPlus /> Bulk
                </TabsTrigger>
                {can("upload:write") && (
                  <TabsTrigger value="upload">
                    <FileUp /> Artefact upload
                  </TabsTrigger>
                )}
              </TabsList>
              <TabsContent value="single">
                <form
                  className="flex flex-col gap-3 md:flex-row"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (ioc.trim()) single.mutate();
                  }}
                >
                  <Input
                    value={ioc}
                    onChange={(e) => setIoc(e.target.value)}
                    placeholder="Domain, URL, IP address or certificate SHA-256 — defanged input (hxxp, [.]) accepted"
                    className="h-11 font-mono text-base"
                    aria-label="IOC"
                    autoFocus
                  />
                  <Button type="submit" size="lg" className="h-11" disabled={single.isPending || !ioc.trim()}>
                    {single.isPending ? <Loader2 className="animate-spin" /> : <Radar />} Investigate
                  </Button>
                </form>
              </TabsContent>
              <TabsContent value="bulk">
                <div className="space-y-3">
                  <Textarea
                    value={bulk}
                    onChange={(e) => setBulk(e.target.value)}
                    rows={6}
                    placeholder={"One IOC per line (max 500). Lines starting with # are ignored.\nexample.com\nhxxps://login-example[.]net/verify\n203.0.113.10"}
                    className="font-mono"
                  />
                  <Button onClick={() => bulkRun.mutate()} disabled={bulkRun.isPending || !bulk.trim()}>
                    {bulkRun.isPending ? <Loader2 className="animate-spin" /> : <ListPlus />} Queue {bulk.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#")).length} IOC(s)
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="upload">
                <UploadPanel />
              </TabsContent>
            </Tabs>
            <details className="mt-4">
              <summary className="text-muted-foreground cursor-pointer text-sm select-none">Investigation options</summary>
              <div className="mt-4 space-y-4">
                <OptionsForm value={options} onChange={setOptions} />
                <div className="max-w-md space-y-2">
                  <Label htmlFor="tags">Tags</Label>
                  <Input id="tags" placeholder="phishing, campaign-x" value={tags} onChange={(e) => setTags(e.target.value)} />
                </div>
              </div>
            </details>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex-col gap-3 md:flex-row md:items-center">
          <div>
            <CardTitle>History</CardTitle>
            <CardDescription>{list.data ? `${list.data.total} investigation(s)` : "…"}</CardDescription>
          </div>
          <div className="flex w-full flex-wrap gap-2 md:w-auto">
            <Input placeholder="Filter by IOC…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="md:w-64" />
            <Select value={status} onValueChange={(v) => { setStatus(v as InvestigationStatus | "all"); setPage(1); }}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["all", "queued", "running", "completed", "failed", "cancelled"].map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon" onClick={() => list.refetch()} aria-label="Refresh">
              <RefreshCw className={list.isFetching ? "animate-spin" : ""} />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="px-0">
          {list.isLoading ? (
            <LoadingBlock />
          ) : list.error ? (
            <div className="px-5"><ErrorBlock error={list.error} /></div>
          ) : !list.data?.items.length ? (
            <div className="px-5"><EmptyState title="No investigations match" /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IOC</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Assets</TableHead>
                  <TableHead className="text-right">Domains</TableHead>
                  <TableHead className="text-right">IPs</TableHead>
                  <TableHead className="text-right">Edges</TableHead>
                  <TableHead>Site</TableHead>
                  <TableHead>Top confidence</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Analyst</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.data.items.map((inv) => (
                  <TableRow key={inv.id} className="cursor-pointer" onClick={() => navigate(`/investigations/${inv.id}`)}>
                    <TableCell>
                      <Link to={`/investigations/${inv.id}`} className="hover:text-primary flex items-center gap-2 font-mono text-[0.8rem]" onClick={(e) => e.stopPropagation()}>
                        <TypeBadge type={inv.ioc_type} /> {truncate(inv.ioc, 56)}
                      </Link>
                    </TableCell>
                    <TableCell><StatusBadge status={inv.status} /></TableCell>
                    <TableCell className="text-right tabular-nums">{inv.summary?.assets_discovered ?? 0}</TableCell>
                    <TableCell className="text-right tabular-nums">{inv.summary?.domains ?? 0}</TableCell>
                    <TableCell className="text-right tabular-nums">{inv.summary?.ips ?? 0}</TableCell>
                    <TableCell className="text-right tabular-nums">{inv.summary?.relationships ?? 0}</TableCell>
                    <TableCell><StatusBadge status={inv.summary?.site_status} /></TableCell>
                    <TableCell><ConfidenceBadge score={inv.summary?.max_confidence || null} /></TableCell>
                    <TableCell className="text-muted-foreground text-xs">{inv.tags.join(", ") || "—"}</TableCell>
                    <TableCell className="text-xs">{inv.created_by}</TableCell>
                    <TableCell className="text-muted-foreground text-xs" title={formatDate(inv.created_at)}>{timeAgo(inv.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <div className="flex items-center justify-end gap-2 px-5 pt-4">
            <span className="text-muted-foreground text-xs">Page {page} of {totalPages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="Previous page"><ChevronLeft /></Button>
            <Button variant="outline" size="icon-sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} aria-label="Next page"><ChevronRight /></Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
