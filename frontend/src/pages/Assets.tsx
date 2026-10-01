import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { SortingState } from "@tanstack/react-table";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ErrorBlock, PageHeader } from "@/components/common";
import { ResultsTable } from "@/components/ResultsTable";
import { api } from "@/lib/api";

const SORT_MAP: Record<string, string> = {
  confidence: "confidence",
  impersonation: "impersonation_score",
  value: "value",
  type: "type",
  status: "status",
  first_seen: "first_seen",
  last_seen: "last_seen",
};

function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export default function AssetsPage() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [typeFilter, setTypeFilter] = useState(params.get("type") ?? "all");
  const [statusFilter, setStatusFilter] = useState(params.get("status") ?? "all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sorting, setSorting] = useState<SortingState>([{ id: "last_seen", desc: true }]);
  const q = useDebounced(search);

  useEffect(() => {
    const fromUrl = params.get("q") ?? "";
    setSearch(fromUrl);
  }, [params]);

  const sort = sorting[0];
  const { data, isLoading, error } = useQuery({
    queryKey: ["assets", q, typeFilter, statusFilter, page, pageSize, sort?.id, sort?.desc],
    queryFn: () =>
      api.assets({
        q: q || undefined,
        type: typeFilter === "all" ? undefined : [typeFilter],
        status: statusFilter === "all" ? undefined : [statusFilter],
        page,
        page_size: pageSize,
        sort: SORT_MAP[sort?.id ?? "last_seen"] ?? "last_seen",
        order: sort?.desc === false ? "asc" : "desc",
      }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Assets" description="Every domain, URL, IP, certificate, tracker and favicon TIM has observed" />
      {error ? (
        <ErrorBlock error={error} />
      ) : (
        <ResultsTable
          data={data?.items ?? []}
          loading={isLoading}
          storageKey="assets"
          exportName="tim-assets"
          manual={{
            total: data?.total ?? 0,
            page,
            pageSize,
            onPageChange: setPage,
            onPageSizeChange: (s) => {
              setPageSize(s);
              setPage(1);
            },
            sorting,
            onSortingChange: (s) => {
              setSorting(s);
              setPage(1);
            },
            search,
            onSearchChange: (s) => {
              setSearch(s);
              setPage(1);
              if (params.get("q")) setParams({}, { replace: true });
            },
            typeFilter,
            onTypeFilterChange: (t) => {
              setTypeFilter(t);
              setPage(1);
            },
            statusFilter,
            onStatusFilterChange: (s) => {
              setStatusFilter(s);
              setPage(1);
            },
          }}
        />
      )}
    </>
  );
}
