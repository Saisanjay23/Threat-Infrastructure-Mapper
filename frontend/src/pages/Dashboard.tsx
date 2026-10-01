import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Image as ImageIcon, Radar, ShieldAlert, Target } from "lucide-react";
import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from "recharts";
import { ConfidenceBadge, EmptyState, ErrorBlock, LoadingBlock, PageHeader, StatCard, StatusBadge, TypeBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useWebSocket } from "@/hooks/useWebSocket";
import { api, fileUrl } from "@/lib/api";
import { timeAgo, truncate } from "@/lib/utils";

const tooltipStyle = {
  backgroundColor: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--foreground)",
  fontSize: 12,
};

export default function DashboardPage() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard, refetchInterval: 30000 });

  useWebSocket("/ws/events", (msg) => {
    if (msg.type === "investigation_status" || msg.type === "investigation_queued") {
      qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });

  if (isLoading) return <LoadingBlock />;
  if (error || !data) return <ErrorBlock error={error ?? "No data"} />;
  const s = data.stats;
  const byType = Object.entries(data.assets_by_type)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Infrastructure intelligence at a glance"
        actions={
          <Button asChild>
            <Link to="/investigations">
              <Radar /> New investigation
            </Link>
          </Button>
        }
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Investigations today" value={s.investigations_today} icon={<Radar />} hint={`${s.investigations_running} running · ${s.investigations_total} total`} />
        <StatCard label="Assets discovered" value={s.assets_discovered} icon={<Boxes />} accent="text-fuchsia-300" hint={`+${s.assets_today} today · ${s.relationships} relationships`} />
        <StatCard label="Threat clusters" value={s.threat_clusters} icon={<ShieldAlert />} accent="text-amber-300" />
        <StatCard label="High confidence findings" value={s.high_confidence_findings} icon={<Target />} accent="text-red-400" hint="confidence ≥ 70" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Activity</CardTitle>
              <CardDescription>Investigations and newly discovered assets, last 14 days</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.activity} margin={{ left: -20, right: 8, top: 8 }}>
                <defs>
                  <linearGradient id="gInv" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--chart-1)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--chart-1)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gAsset" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--chart-4)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="var(--chart-4)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                <ChartTooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="assets" name="Assets" stroke="var(--chart-4)" fill="url(#gAsset)" strokeWidth={2} />
                <Area type="monotone" dataKey="investigations" name="Investigations" stroke="var(--chart-1)" fill="url(#gInv)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Assets by type</CardTitle>
              <CardDescription>Whole inventory</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="h-64">
            {byType.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={byType} layout="vertical" margin={{ left: 10, right: 12 }}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="type" stroke="var(--muted-foreground)" fontSize={11} width={80} />
                  <ChartTooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--accent)" }} />
                  <Bar dataKey="count" fill="var(--chart-1)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No assets yet" />
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Recent investigations</CardTitle>
            <Button variant="link" size="sm" asChild>
              <Link to="/investigations">View all</Link>
            </Button>
          </CardHeader>
          <CardContent className="px-0">
            {data.recent_investigations.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IOC</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Assets</TableHead>
                    <TableHead>Top confidence</TableHead>
                    <TableHead>Started</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.recent_investigations.map((inv) => (
                    <TableRow key={inv.id}>
                      <TableCell>
                        <Link to={`/investigations/${inv.id}`} className="hover:text-primary flex items-center gap-2 font-mono text-[0.8rem]">
                          <TypeBadge type={inv.ioc_type} /> {truncate(inv.ioc, 48)}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={inv.status} />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{inv.summary?.assets_discovered ?? 0}</TableCell>
                      <TableCell>
                        <ConfidenceBadge score={inv.summary?.max_confidence || null} />
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{timeAgo(inv.created_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="px-5">
                <EmptyState title="No investigations yet" description="Start by investigating a domain, URL or IP address." />
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent clusters</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {data.recent_clusters.length ? (
              data.recent_clusters.map((c) => (
                <Link key={c.id} to={`/clusters/${c.id}`} className="hover:bg-accent flex items-center justify-between gap-2 rounded-md border px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium">{c.name}</div>
                    <div className="text-muted-foreground text-xs">
                      {c.counts?.domain ?? 0} domains · {c.counts?.ip ?? 0} IPs · {timeAgo(c.updated_at)}
                    </div>
                  </div>
                  <ConfidenceBadge score={c.confidence} />
                </Link>
              ))
            ) : (
              <EmptyState title="No clusters yet" description="Clusters appear once correlated infrastructure is found." />
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <div>
            <CardTitle className="flex items-center gap-2">
              <ImageIcon className="size-4" /> Recent screenshots
            </CardTitle>
            <CardDescription>Latest rendered pages captured by the screenshot engine</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {data.recent_screenshots.length ? (
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
              {data.recent_screenshots.map((shot) => (
                <Link
                  key={shot.file_id}
                  to={shot.asset_id ? `/assets/${shot.asset_id}` : "#"}
                  className="group hover:border-primary overflow-hidden rounded-lg border transition-colors"
                >
                  <img src={fileUrl(shot.file_id)} alt={shot.value ?? "screenshot"} loading="lazy" className="aspect-video w-full bg-black object-cover object-top" />
                  <div className="flex items-center justify-between gap-1 px-2 py-1.5">
                    <span className="truncate font-mono text-[11px]">{shot.value ?? shot.url}</span>
                    <StatusBadge status={shot.status} className="text-[10px]" />
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState title="No screenshots captured yet" />
          )}
        </CardContent>
      </Card>
    </>
  );
}
