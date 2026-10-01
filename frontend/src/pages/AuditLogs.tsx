import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorBlock, LoadingBlock, Mono, PageHeader, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function AuditLogsPage() {
  const [page, setPage] = useState(1);
  const [username, setUsername] = useState("");
  const [action, setAction] = useState("");
  const [status, setStatus] = useState("all");
  const { data, isLoading, error } = useQuery({
    queryKey: ["audit", page, username, action, status],
    queryFn: () => api.auditLogs({ page, page_size: 50, username: username || undefined, action: action || undefined, status: status === "all" ? undefined : status }),
    placeholderData: keepPreviousData,
  });
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <>
      <PageHeader title="Audit Logs" description="Immutable record of authentication, investigation, provider and administrative actions" />
      <Card>
        <CardContent className="space-y-4 px-0">
          <div className="flex flex-wrap gap-2 px-5">
            <Input placeholder="Username" value={username} onChange={(e) => { setUsername(e.target.value); setPage(1); }} className="w-44" />
            <Input placeholder="Action prefix (e.g. provider.)" value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} className="w-56" />
            <Select value={status} onValueChange={(v) => { setStatus(v); setPage(1); }}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All results</SelectItem>
                <SelectItem value="success">success</SelectItem>
                <SelectItem value="failure">failure</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {isLoading ? (
            <LoadingBlock />
          ) : error ? (
            <div className="px-5"><ErrorBlock error={error} /></div>
          ) : !data?.items.length ? (
            <div className="px-5"><EmptyState title="No audit events match" /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">{formatDate(log.timestamp)}</TableCell>
                    <TableCell>
                      {log.username ?? "—"} {log.role && <Badge variant="secondary" className="ml-1">{log.role}</Badge>}
                    </TableCell>
                    <TableCell><Mono>{log.action}</Mono></TableCell>
                    <TableCell className="text-xs">
                      {log.resource_type ? `${log.resource_type}:` : ""}
                      <Mono className="text-muted-foreground">{log.resource_id ?? ""}</Mono>
                    </TableCell>
                    <TableCell><StatusBadge status={log.status} /></TableCell>
                    <TableCell><Mono className="text-muted-foreground">{log.ip ?? "—"}</Mono></TableCell>
                    <TableCell className="text-muted-foreground max-w-md truncate font-mono text-xs" title={JSON.stringify(log.details)}>
                      {log.details && Object.keys(log.details).length ? JSON.stringify(log.details) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <div className="flex items-center justify-end gap-2 px-5 text-xs">
            <span className="text-muted-foreground">{data?.total ?? 0} event(s) · page {page} of {pages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} aria-label="Previous page"><ChevronLeft /></Button>
            <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)} aria-label="Next page"><ChevronRight /></Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
