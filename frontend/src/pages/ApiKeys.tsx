import { useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { ApiKeyDialog } from "@/components/ApiKeyDialog";
import { ErrorBlock, LoadingBlock, PageHeader, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/utils";
import type { Provider } from "@/types/api";

export default function ApiKeysPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["providers"], queryFn: api.providers });
  const [keyFor, setKeyFor] = useState<Provider | null>(null);
  if (isLoading) return <LoadingBlock />;
  if (error) return <ErrorBlock error={error} />;
  const keyed = (data ?? []).filter((p) => p.requires_api_key || p.has_api_key || ["greynoise", "urlscan"].includes(p.name));

  return (
    <>
      <PageHeader
        title="API Keys"
        description={
          <span className="flex items-center gap-1.5">
            <ShieldCheck className="size-4 text-emerald-400" /> Encrypted at rest · only masked values are ever displayed · every change is audited
          </span>
        }
      />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {keyed.map((p) => (
          <Card key={p.name}>
            <CardHeader>
              <div>
                <CardTitle className="flex items-center gap-2">
                  {p.display_name}
                  <Badge variant={p.category === "free" ? "success" : "warning"}>{p.category}</Badge>
                </CardTitle>
                <CardDescription className="mt-1">{p.description}</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Key</span>
                {p.has_api_key ? (
                  <span className="font-mono text-xs">{p.api_key_masked}</span>
                ) : (
                  <Badge variant={p.requires_api_key ? "warning" : "secondary"}>{p.requires_api_key ? "required" : "optional"}</Badge>
                )}
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Health</span>
                <StatusBadge status={p.health.state} />
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Usage today</span>
                <span className="tabular-nums">
                  {p.usage.today_calls}
                  {p.daily_limit ? ` / ${p.daily_limit}` : ""}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Last call</span>
                <span>{timeAgo(p.usage.last_called)}</span>
              </div>
              <Button variant="outline" className="w-full" onClick={() => setKeyFor(p)}>
                <KeyRound /> {p.has_api_key ? "Rotate / remove key" : "Add key"}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
      <ApiKeyDialog provider={keyFor} onClose={() => setKeyFor(null)} />
    </>
  );
}
