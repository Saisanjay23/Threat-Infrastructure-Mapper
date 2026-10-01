import {
  type ColumnDef,
  type RowSelectionState,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Columns3, Copy, Download, ExternalLink, Filter, Network } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { AddToCaseDialog } from "@/components/AddToCaseDialog";
import { ConfidenceBadge, CopyButton, EmptyState, LoadingBlock, Mono, StatusBadge, TypeBadge } from "@/components/common";
import { ExportDialog } from "@/components/ExportDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/hooks/useAuth";
import { cn, copyText, downloadBlob, formatDate, timeAgo, truncate } from "@/lib/utils";
import type { Asset } from "@/types/api";

export const ASSET_TYPES = ["domain", "url", "ip", "certificate", "analytics", "pixel", "tracking", "favicon", "logo", "asn", "hosting", "nameserver"];
export const SITE_STATUSES = ["ACTIVE", "INACTIVE", "PARKED", "TAKEDOWN", "ERROR", "UNKNOWN"];

export function assetTitle(a: Asset): string | undefined {
  return a.attributes?.web?.title ?? a.attributes?.title ?? undefined;
}
export function assetIp(a: Asset): string | undefined {
  if (a.type === "ip") return a.value;
  return a.attributes?.web?.ip ?? a.attributes?.infrastructure?.ips?.[0] ?? a.fingerprints?.ips?.[0];
}
export function assetAsn(a: Asset): string | undefined {
  return a.fingerprints?.asn ?? a.attributes?.infrastructure?.asns?.[0] ?? a.fingerprints?.asns?.[0] ?? (a.type === "asn" ? a.value : undefined);
}
export function assetHosting(a: Asset): string | undefined {
  return a.fingerprints?.hosting && typeof a.fingerprints.hosting === "string"
    ? a.fingerprints.hosting
    : (a.attributes?.infrastructure?.hosting_providers?.[0] ?? a.attributes?.network?.hosting_provider);
}
export function assetUrl(a: Asset): string | undefined {
  if (a.type === "url") return a.value;
  return a.attributes?.web?.final_url;
}
export function assetDomain(a: Asset): string | undefined {
  if (a.type === "domain") return a.value;
  if (a.type === "url") {
    try {
      return new URL(a.value).hostname;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

const CSV_FIELDS: [string, (a: Asset) => unknown][] = [
  ["type", (a) => a.type],
  ["value", (a) => a.value],
  ["status", (a) => a.status],
  ["confidence", (a) => a.confidence],
  ["impersonation_score", (a) => a.impersonation_score],
  ["title", assetTitle],
  ["ip", assetIp],
  ["asn", assetAsn],
  ["hosting", assetHosting],
  ["final_url", (a) => a.attributes?.web?.final_url],
  ["sources", (a) => a.sources.join(" ")],
  ["clusters", (a) => a.cluster_ids.join(" ")],
  ["tags", (a) => a.tags.join(" ")],
  ["first_seen", (a) => a.first_seen],
  ["last_seen", (a) => a.last_seen],
];

export function toCsv(rows: Asset[]): string {
  const esc = (v: unknown) => {
    const s = v == null ? "" : String(v);
    // Neutralise spreadsheet formula injection from attacker-controlled values.
    const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
    return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  return [CSV_FIELDS.map(([h]) => h).join(","), ...rows.map((r) => CSV_FIELDS.map(([, f]) => esc(f(r))).join(","))].join("\n");
}

export interface ManualTableState {
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  sorting: SortingState;
  onSortingChange: (s: SortingState) => void;
  search: string;
  onSearchChange: (s: string) => void;
  typeFilter: string;
  onTypeFilterChange: (t: string) => void;
  statusFilter: string;
  onStatusFilterChange: (s: string) => void;
}

interface Props {
  data: Asset[];
  loading?: boolean;
  manual?: ManualTableState;
  investigationId?: string;
  storageKey?: string;
  exportName?: string;
}

const DEFAULT_HIDDEN: VisibilityState = { first_seen: false, sources: false, hosting: false, impersonation: false };

function loadVisibility(key?: string): VisibilityState {
  if (!key) return DEFAULT_HIDDEN;
  try {
    const raw = localStorage.getItem(`tim.cols.${key}`);
    return raw ? (JSON.parse(raw) as VisibilityState) : DEFAULT_HIDDEN;
  } catch {
    return DEFAULT_HIDDEN;
  }
}

function SortIcon({ dir }: { dir: false | "asc" | "desc" }) {
  if (dir === "asc") return <ArrowUp className="size-3" />;
  if (dir === "desc") return <ArrowDown className="size-3" />;
  return <ArrowUpDown className="size-3 opacity-40" />;
}

export function ResultsTable({ data, loading, manual, investigationId, storageKey, exportName = "tim-assets" }: Props) {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [sorting, setSorting] = useState<SortingState>([{ id: "confidence", desc: true }]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(() => loadVisibility(storageKey));

  useEffect(() => {
    if (!storageKey) return;
    try {
      localStorage.setItem(`tim.cols.${storageKey}`, JSON.stringify(columnVisibility));
    } catch {
      /* ignore */
    }
  }, [columnVisibility, storageKey]);

  const filtered = useMemo(() => {
    if (manual) return data;
    return data.filter((a) => (typeFilter === "all" || a.type === typeFilter) && (statusFilter === "all" || a.status === statusFilter));
  }, [data, manual, typeFilter, statusFilter]);

  const columns = useMemo<ColumnDef<Asset>[]>(
    () => [
      {
        id: "select",
        enableSorting: false,
        enableHiding: false,
        header: ({ table }) => (
          <Checkbox
            aria-label="Select all"
            checked={table.getIsAllPageRowsSelected() ? true : table.getIsSomePageRowsSelected() ? "indeterminate" : false}
            onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
          />
        ),
        cell: ({ row }) => (
          <Checkbox aria-label="Select row" checked={row.getIsSelected()} onCheckedChange={(v) => row.toggleSelected(!!v)} onClick={(e) => e.stopPropagation()} />
        ),
      },
      { id: "type", accessorKey: "type", header: "Type", cell: ({ row }) => <TypeBadge type={row.original.type} /> },
      {
        id: "value",
        accessorKey: "value",
        header: "Value",
        cell: ({ row }) => (
          <div className="flex max-w-[420px] items-center gap-1">
            <Link to={`/assets/${row.original.id}`} className="hover:text-primary truncate font-mono text-[0.8rem]" onClick={(e) => e.stopPropagation()} title={row.original.value}>
              {truncate(row.original.value, 72)}
            </Link>
            <CopyButton value={row.original.value} label={row.original.type} />
          </div>
        ),
      },
      { id: "status", accessorKey: "status", header: "Status", cell: ({ row }) => <StatusBadge status={row.original.status} /> },
      {
        id: "confidence",
        accessorFn: (a) => a.confidence ?? -1,
        header: "Confidence",
        cell: ({ row }) => <ConfidenceBadge score={row.original.confidence} />,
      },
      {
        id: "impersonation",
        accessorFn: (a) => a.impersonation_score ?? -1,
        header: "Impersonation",
        cell: ({ row }) => <ConfidenceBadge score={row.original.impersonation_score} />,
      },
      { id: "title", accessorFn: (a) => assetTitle(a) ?? "", header: "Title", cell: ({ getValue }) => <span className="text-muted-foreground block max-w-[260px] truncate text-xs">{String(getValue() || "—")}</span> },
      {
        id: "ip",
        accessorFn: (a) => assetIp(a) ?? "",
        header: "IP",
        cell: ({ getValue }) => (getValue() ? <Mono>{String(getValue())}</Mono> : <span className="text-muted-foreground">—</span>),
      },
      { id: "asn", accessorFn: (a) => assetAsn(a) ?? "", header: "ASN", cell: ({ getValue }) => <span className="text-xs">{String(getValue() || "—")}</span> },
      { id: "hosting", accessorFn: (a) => assetHosting(a) ?? "", header: "Hosting", cell: ({ getValue }) => <span className="block max-w-[180px] truncate text-xs">{String(getValue() || "—")}</span> },
      {
        id: "clusters",
        accessorFn: (a) => a.cluster_ids.length,
        header: "Clusters",
        cell: ({ row }) =>
          row.original.cluster_ids.length ? (
            <Link to={`/clusters/${row.original.cluster_ids[0]}`} onClick={(e) => e.stopPropagation()}>
              <Badge variant="destructive">{row.original.cluster_ids.length}</Badge>
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      { id: "sources", accessorFn: (a) => a.sources.join(", "), header: "Sources", cell: ({ getValue }) => <span className="text-muted-foreground block max-w-[200px] truncate text-xs">{String(getValue())}</span> },
      { id: "first_seen", accessorKey: "first_seen", header: "First seen", cell: ({ getValue }) => <span className="text-muted-foreground text-xs">{formatDate(String(getValue()))}</span> },
      { id: "last_seen", accessorKey: "last_seen", header: "Last seen", cell: ({ getValue }) => <span className="text-muted-foreground text-xs" title={formatDate(String(getValue()))}>{timeAgo(String(getValue()))}</span> },
      {
        id: "actions",
        enableSorting: false,
        enableHiding: false,
        header: "",
        cell: ({ row }) => (
          <div className="flex justify-end gap-0.5" onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="icon-sm" asChild title="Open asset">
              <Link to={`/assets/${row.original.id}`}>
                <ExternalLink />
              </Link>
            </Button>
            <Button variant="ghost" size="icon-sm" asChild title="Open in graph">
              <Link to={`/graph?asset=${row.original.id}${investigationId ? `&investigation=${investigationId}` : ""}`}>
                <Network />
              </Link>
            </Button>
          </div>
        ),
      },
    ],
    [investigationId],
  );

  const table = useReactTable({
    data: filtered,
    columns,
    getRowId: (a) => a.id,
    state: {
      sorting: manual ? manual.sorting : sorting,
      globalFilter: manual ? undefined : globalFilter,
      rowSelection,
      columnVisibility,
      ...(manual ? { pagination: { pageIndex: manual.page - 1, pageSize: manual.pageSize } } : {}),
    },
    enableRowSelection: true,
    onRowSelectionChange: setRowSelection,
    onColumnVisibilityChange: setColumnVisibility,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(manual ? manual.sorting : sorting) : updater;
      if (manual) manual.onSortingChange(next);
      else setSorting(next);
    },
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: (row, _col, value: string) => {
      const v = value.toLowerCase();
      const a = row.original;
      return [a.value, assetTitle(a), assetIp(a), assetAsn(a), assetHosting(a), a.tags.join(" ")].some((x) => x && String(x).toLowerCase().includes(v));
    },
    manualPagination: !!manual,
    manualSorting: !!manual,
    manualFiltering: !!manual,
    pageCount: manual ? Math.max(1, Math.ceil(manual.total / manual.pageSize)) : undefined,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: manual ? undefined : getSortedRowModel(),
    getFilteredRowModel: manual ? undefined : getFilteredRowModel(),
    getPaginationRowModel: manual ? undefined : getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  });

  const selected = table.getSelectedRowModel().rows.map((r) => r.original);
  const allRows = manual ? data : table.getFilteredRowModel().rows.map((r) => r.original);

  const copyList = async (values: (string | undefined)[], label: string) => {
    const unique = Array.from(new Set(values.filter((v): v is string => !!v)));
    if (!unique.length) {
      toast.warning(`No ${label} to copy`);
      return;
    }
    if (await copyText(unique.join("\n"))) toast.success(`Copied ${unique.length} ${label}`);
  };

  const exportRows = (rows: Asset[], format: "csv" | "json") => {
    if (!rows.length) {
      toast.warning("Nothing to export");
      return;
    }
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    if (format === "csv") downloadBlob(new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" }), `${exportName}-${stamp}.csv`);
    else downloadBlob(new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }), `${exportName}-${stamp}.json`);
  };

  const search = manual ? manual.search : globalFilter;
  const setSearch = manual ? manual.onSearchChange : setGlobalFilter;
  const tf = manual ? manual.typeFilter : typeFilter;
  const setTf = manual ? manual.onTypeFilterChange : setTypeFilter;
  const sf = manual ? manual.statusFilter : statusFilter;
  const setSf = manual ? manual.onStatusFilterChange : setStatusFilter;
  const pageIndex = manual ? manual.page - 1 : table.getState().pagination.pageIndex;
  const pageSize = manual ? manual.pageSize : table.getState().pagination.pageSize;
  const totalRows = manual ? manual.total : table.getFilteredRowModel().rows.length;
  const pageCount = Math.max(1, Math.ceil(totalRows / pageSize));
  const goTo = (p: number) => (manual ? manual.onPageChange(p + 1) : table.setPageIndex(p));

  return (
    <div className="bg-card rounded-xl border">
      <div className="flex flex-wrap items-center gap-2 border-b p-3">
        <Input placeholder="Search value, title, IP, ASN, hosting, tag…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full md:w-72" aria-label="Search results" />
        <Select value={tf} onValueChange={setTf}>
          <SelectTrigger className="w-36" aria-label="Filter type">
            <Filter className="size-3.5" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {ASSET_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={sf} onValueChange={setSf}>
          <SelectTrigger className="w-36" aria-label="Filter status">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {SITE_STATUSES.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {selected.length > 0 && <Badge variant="default">{selected.length} selected</Badge>}
          {can("case:write") && <AddToCaseDialog links={{ asset_ids: selected.map((a) => a.id) }} disabled={!selected.length} />}
          {can("report:export") && selected.length > 0 && (
            <ExportDialog scope={{ asset_ids: selected.map((a) => a.id) }} defaultTitle={`Selected assets (${selected.length})`}
              trigger={<Button variant="outline" size="sm"><Download /> Report</Button>} />
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Copy /> Copy
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Selected ({selected.length})</DropdownMenuLabel>
              <DropdownMenuItem disabled={!selected.length} onClick={() => copyList(selected.map((a) => a.value), "selected values")}>Copy selected</DropdownMenuItem>
              <DropdownMenuItem disabled={!selected.length} onClick={() => copyList(selected.map(assetUrl), "URLs")}>Copy selected URLs</DropdownMenuItem>
              <DropdownMenuItem disabled={!selected.length} onClick={() => copyList(selected.map(assetDomain), "domains")}>Copy selected domains</DropdownMenuItem>
              <DropdownMenuItem disabled={!selected.length} onClick={() => copyList(selected.map(assetIp), "IPs")}>Copy selected IPs</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>All {manual ? "on page" : "filtered"} ({allRows.length})</DropdownMenuLabel>
              <DropdownMenuItem onClick={() => copyList(allRows.map(assetUrl), "URLs")}>Copy all URLs</DropdownMenuItem>
              <DropdownMenuItem onClick={() => copyList(allRows.map(assetDomain), "domains")}>Copy all domains</DropdownMenuItem>
              <DropdownMenuItem onClick={() => copyList(allRows.map(assetIp), "IPs")}>Copy all IPs</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Download /> Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem disabled={!selected.length} onClick={() => exportRows(selected, "csv")}>Export selected · CSV</DropdownMenuItem>
              <DropdownMenuItem disabled={!selected.length} onClick={() => exportRows(selected, "json")}>Export selected · JSON</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => exportRows(allRows, "csv")}>Export all · CSV</DropdownMenuItem>
              <DropdownMenuItem onClick={() => exportRows(allRows, "json")}>Export all · JSON</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3 /> Columns
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {table
                .getAllLeafColumns()
                .filter((c) => c.getCanHide())
                .map((c) => (
                  <DropdownMenuCheckboxItem key={c.id} checked={c.getIsVisible()} onCheckedChange={(v) => c.toggleVisibility(!!v)} onSelect={(e) => e.preventDefault()} className="capitalize">
                    {typeof c.columnDef.header === "string" ? c.columnDef.header : c.id}
                  </DropdownMenuCheckboxItem>
                ))}
            </DropdownMenuContent>
          </DropdownMenu>
          {investigationId && (
            <Button variant="outline" size="sm" asChild>
              <Link to={`/graph?investigation=${investigationId}`}>
                <Network /> Open graph
              </Link>
            </Button>
          )}
        </div>
      </div>

      {loading ? (
        <LoadingBlock />
      ) : !table.getRowModel().rows.length ? (
        <div className="p-4">
          <EmptyState title="No results" description="Adjust the search or filters." />
        </div>
      ) : (
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => (
                  <TableHead key={h.id} className={cn(h.column.id === "select" && "w-8")}>
                    {h.isPlaceholder ? null : h.column.getCanSort() ? (
                      <button type="button" className="hover:text-foreground inline-flex cursor-pointer items-center gap-1" onClick={h.column.getToggleSortingHandler()}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        <SortIcon dir={h.column.getIsSorted()} />
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.map((row) => (
              <TableRow key={row.id} data-state={row.getIsSelected() ? "selected" : undefined} className="cursor-pointer" onClick={() => navigate(`/assets/${row.original.id}`)}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t p-3 text-xs">
        <span className="text-muted-foreground">{totalRows} result(s)</span>
        <div className="flex items-center gap-2">
          <Select
            value={String(pageSize)}
            onValueChange={(v) => (manual ? manual.onPageSizeChange(Number(v)) : table.setPageSize(Number(v)))}
          >
            <SelectTrigger className="h-8 w-24" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[10, 25, 50, 100, 200].map((n) => (
                <SelectItem key={n} value={String(n)}>
                  {n} / page
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="text-muted-foreground">
            Page {pageIndex + 1} of {pageCount}
          </span>
          <Button variant="outline" size="icon-sm" onClick={() => goTo(0)} disabled={pageIndex === 0} aria-label="First page"><ChevronsLeft /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => goTo(pageIndex - 1)} disabled={pageIndex === 0} aria-label="Previous page"><ChevronLeft /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => goTo(pageIndex + 1)} disabled={pageIndex + 1 >= pageCount} aria-label="Next page"><ChevronRight /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => goTo(pageCount - 1)} disabled={pageIndex + 1 >= pageCount} aria-label="Last page"><ChevronsRight /></Button>
        </div>
      </div>
    </div>
  );
}
