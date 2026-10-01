import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Database, ExternalLink, FlaskConical, KeyRound, Loader2, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";
import { ErrorBlock, LoadingBlock, PageHeader, StatusBadge } from "@/components/common";
import { ApiKeyDialog } from "@/components/ApiKeyDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/misc";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import type { Provider } from "@/types/api";

const tooltipStyle = { backgroundColor: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 };

function NumberCell({ value, onCommit, disabled, min = 0 }: { value: number | null | undefined; onCommit: (v: number | null) => void; disabled?: boolean; min?: number }) {
  const [draft, setDraft] = useState<string>(value == null ? "" : String(value));
  return (
    <Input
      value={draft}
      disabled={disabled}
      inputMode="numeric"
      className="h-8 w-20 text-xs tabular-nums"
      onChange={(e) => setDraft(e.target.value.replace(/[^0-9]/g, ""))}
      onBlur={() => {
        const next = draft === "" ? null : Math.max(min, Number(draft));
        if (next !== (value ?? null)) onCommit(next);
      }}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
    />
  );
}

export default function ProvidersPage() {
  const { can } = useAuth();
  const admin = can("provider:admin");
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: api.providers, refetchInterval: 20000 });
  const usage = useQuery({ queryKey: ["provider-usage"], queryFn: () => api.providerUsage(14) });
  const [keyFor, setKeyFor] = useState<Provider | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const update = useMutation({
    mutationFn: ({ name, body }: { name: string; body: Parameters<typeof api.updateProvider>[1] }) => api.updateProvider(name, body),
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: ["providers"] });
      toast.success(`${p.display_name} updated`);
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const clearCache = useMutation({
    mutationFn: (name: string) => api.clearProviderCache(name),
    onSuccess: (r) => toast.success(r.message),
    onError: (e: Error) => toast.error(e.message),
  });

  const runTest = async (p: Provider) => {
    setTesting(p.name);
    try {
      const r = await api.testProvider(p.name);
      if (r.ok) toast.success(`${p.display_name}: OK in ${Math.round(r.latency_ms)} ms`);
      else toast.error(`${p.display_name}: ${r.message}`);
      qc.invalidateQueries({ queryKey: ["providers"] });
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setTesting(null);
    }
  };

  const chart = useMemo(() => {
    const byDay: Record<string, { day: string; calls: number; cache_hits: number; errors: number }> = {};
    for (const u of usage.data ?? []) {
      const d = (byDay[u.day] ??= { day: u.day, calls: 0, cache_hits: 0, errors: 0 });
      d.calls += u.calls ?? 0;
      d.cache_hits += u.cache_hits ?? 0;
      d.errors += u.errors ?? 0;
    }
    return Object.values(byDay).sort((a, b) => a.day.localeCompare(b.day));
  }, [usage.data]);

  if (providers.isLoading) return <LoadingBlock />;
  if (providers.error) return <ErrorBlock error={providers.error} />;
  const list = providers.data ?? [];
  const totals = list.reduce(
    (acc, p) => ({ calls: acc.calls + p.usage.total_calls, hits: acc.hits + p.usage.cache_hits, errors: acc.errors + p.usage.errors }),
    { calls: 0, hits: 0, errors: 0 },
  );

  const section = (category: "free" | "credit") => (
    <Card key={category}>
      <CardHeader>
        <div>
          <CardTitle>{category === "free" ? "Free sources" : "Credit-based sources"}</CardTitle>
          <CardDescription>
            {category === "free"
              ? "Queried on every investigation when enabled."
              : "Only queried when an investigation's credit policy allows it — by default only when free sources return too little."}
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="px-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Enabled</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Supports</TableHead>
              <TableHead>Health</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Cache TTL (h)</TableHead>
              <TableHead>Daily limit</TableHead>
              <TableHead className="text-right">Today</TableHead>
              <TableHead className="text-right">Calls</TableHead>
              <TableHead className="text-right">Cache hits</TableHead>
              <TableHead className="text-right">Errors</TableHead>
              <TableHead className="text-right">Avg latency</TableHead>
              <TableHead>API key</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {list
              .filter((p) => p.category === category)
              .map((p) => (
                <TableRow key={p.name}>
                  <TableCell>
                    <Switch
                      checked={p.enabled}
                      disabled={!admin}
                      onCheckedChange={(enabled) => update.mutate({ name: p.name, body: { enabled } })}
                      aria-label={`Enable ${p.display_name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{p.display_name}</div>
                    <div className="text-muted-foreground max-w-xs text-xs">{p.description}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {p.supported_types.map((t) => (
                        <Badge key={t} variant="secondary">{t}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Tooltip content={p.health.last_error ?? (p.health.last_success ? `Last success ${timeAgo(p.health.last_success)}` : "Not used yet")}>
                      <span><StatusBadge status={p.health.state} /></span>
                    </Tooltip>
                  </TableCell>
                  <TableCell><NumberCell value={p.priority} min={1} disabled={!admin} onCommit={(v) => v && update.mutate({ name: p.name, body: { priority: v } })} /></TableCell>
                  <TableCell><NumberCell value={p.cache_ttl_hours} disabled={!admin} onCommit={(v) => update.mutate({ name: p.name, body: { cache_ttl_hours: v ?? 0 } })} /></TableCell>
                  <TableCell><NumberCell value={p.daily_limit} disabled={!admin} onCommit={(v) => update.mutate({ name: p.name, body: { daily_limit: v ?? 0 } })} /></TableCell>
                  <TableCell className="text-right tabular-nums">{p.usage.today_calls}</TableCell>
                  <TableCell className="text-right tabular-nums">{p.usage.total_calls}</TableCell>
                  <TableCell className="text-right tabular-nums">{p.usage.cache_hits}</TableCell>
                  <TableCell className="text-right tabular-nums">{p.usage.errors}</TableCell>
                  <TableCell className="text-right tabular-nums text-xs">{p.usage.avg_latency_ms ? `${Math.round(p.usage.avg_latency_ms)} ms` : "—"}</TableCell>
                  <TableCell>
                    {p.has_api_key ? (
                      <Badge variant="success" className="font-mono">{p.api_key_masked}</Badge>
                    ) : p.requires_api_key ? (
                      <Badge variant="warning">required</Badge>
                    ) : (
                      <span className="text-muted-foreground text-xs">optional</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      {admin && (
                        <>
                          <Tooltip content="Run live health check">
                            <Button variant="ghost" size="icon-sm" onClick={() => runTest(p)} disabled={testing === p.name}>
                              {testing === p.name ? <Loader2 className="animate-spin" /> : <FlaskConical />}
                            </Button>
                          </Tooltip>
                          <Tooltip content="Manage API key">
                            <Button variant="ghost" size="icon-sm" onClick={() => setKeyFor(p)}>
                              <KeyRound />
                            </Button>
                          </Tooltip>
                          <Tooltip content="Clear cached responses">
                            <Button variant="ghost" size="icon-sm" onClick={() => clearCache.mutate(p.name)}>
                              <Trash2 />
                            </Button>
                          </Tooltip>
                        </>
                      )}
                      {p.docs_url && (
                        <Tooltip content="Provider documentation">
                          <Button variant="ghost" size="icon-sm" asChild>
                            <a href={p.docs_url} target="_blank" rel="noreferrer noopener"><ExternalLink /></a>
                          </Button>
                        </Tooltip>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );

  return (
    <>
      <PageHeader title="Provider Management" description="Intelligence sources, priorities, API keys, health, usage and caching" />
      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Activity className="size-4" /> Totals</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-3 gap-3 text-center">
            <div><div className="text-2xl font-semibold tabular-nums">{totals.calls}</div><div className="text-muted-foreground text-xs">live calls</div></div>
            <div><div className="text-2xl font-semibold tabular-nums text-emerald-400">{totals.hits}</div><div className="text-muted-foreground text-xs">cache hits</div></div>
            <div><div className="text-2xl font-semibold tabular-nums text-red-400">{totals.errors}</div><div className="text-muted-foreground text-xs">errors</div></div>
            <div className="text-muted-foreground col-span-3 flex items-center justify-center gap-1 text-xs">
              <Database className="size-3" /> cache hit ratio {totals.calls + totals.hits ? Math.round((100 * totals.hits) / (totals.calls + totals.hits)) : 0}%
            </div>
          </CardContent>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle>Usage · last 14 days</CardTitle></CardHeader>
          <CardContent className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chart} margin={{ left: -20 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                <ChartTooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--accent)" }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="calls" stackId="a" fill="var(--chart-1)" name="Live calls" />
                <Bar dataKey="cache_hits" stackId="a" fill="var(--chart-2)" name="Cache hits" />
                <Bar dataKey="errors" fill="var(--chart-5)" name="Errors" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
      <div className="space-y-4">
        {section("free")}
        {section("credit")}
      </div>
      <ApiKeyDialog provider={keyFor} onClose={() => setKeyFor(null)} />
    </>
  );
}
