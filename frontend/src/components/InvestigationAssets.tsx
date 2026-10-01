import { useQuery } from "@tanstack/react-query";
import { ErrorBlock } from "@/components/common";
import { ResultsTable } from "@/components/ResultsTable";
import { api } from "@/lib/api";

export function InvestigationAssets({ investigationId, refreshKey }: { investigationId: string; refreshKey: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["investigation-assets", investigationId, refreshKey],
    queryFn: () => api.investigationAssets(investigationId, { page_size: 500 }),
    refetchInterval: refreshKey === "done" ? false : 8000,
  });
  if (error) return <ErrorBlock error={error} />;
  return (
    <ResultsTable
      data={data?.items ?? []}
      loading={isLoading}
      investigationId={investigationId}
      storageKey="investigation"
      exportName={`tim-${investigationId}`}
    />
  );
}
