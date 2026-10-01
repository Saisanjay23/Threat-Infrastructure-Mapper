import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, RotateCcw, Save, Scale } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ErrorBlock, LoadingBlock } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import type { ScoringConfig } from "@/types/api";

export function ScoringSettings() {
  const { can } = useAuth();
  const admin = can("settings:admin");
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["scoring"], queryFn: api.scoring });
  const [draft, setDraft] = useState<ScoringConfig | null>(null);
  useEffect(() => {
    if (query.data) setDraft(query.data);
  }, [query.data]);

  const save = useMutation({
    mutationFn: (body: ScoringConfig) => api.saveScoring(body),
    onSuccess: () => {
      toast.success("Scoring model saved — applies to new correlations");
      qc.invalidateQueries({ queryKey: ["scoring"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const reset = useMutation({
    mutationFn: api.resetScoring,
    onSuccess: () => {
      toast.success("Defaults restored");
      qc.invalidateQueries({ queryKey: ["scoring"] });
    },
  });

  if (query.isLoading || !draft) return <LoadingBlock />;
  if (query.error) return <ErrorBlock error={query.error} />;
  const labels = query.data?.labels ?? {};
  const defaults = query.data?.defaults ?? {};
  const setWeight = (k: string, v: number) => setDraft({ ...draft, weights: { ...draft.weights, [k]: Math.max(0, Math.min(100, v)) } });
  const setThreshold = (k: keyof ScoringConfig["thresholds"], v: number) => setDraft({ ...draft, thresholds: { ...draft.thresholds, [k]: v } });
  const setSimilarity = (k: keyof ScoringConfig["similarity"], v: number) => setDraft({ ...draft, similarity: { ...draft.similarity, [k]: v } });
  const { labels: _l, defaults: _d, ...payload } = draft;
  void _l;
  void _d;

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Card className="xl:col-span-2">
        <CardHeader>
          <div>
            <CardTitle className="flex items-center gap-2"><Scale className="size-4" /> Correlation weights</CardTitle>
            <CardDescription>Points awarded when a candidate shares a feature with the investigation seed. Scores are capped at 100.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-2">
          {Object.keys(defaults).map((k) => (
            <div key={k} className="flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-sm">{labels[k] ?? k}</div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={draft.weights[k] ?? 0}
                  disabled={!admin}
                  onChange={(e) => setWeight(k, Number(e.target.value))}
                  className="accent-primary w-full"
                  aria-label={`${k} weight`}
                />
              </div>
              <Input type="number" className="h-8 w-16 text-right tabular-nums" value={draft.weights[k] ?? 0} disabled={!admin} onChange={(e) => setWeight(k, Number(e.target.value))} />
              {draft.weights[k] !== defaults[k] && <Badge variant="outline" className="text-[10px]">def {defaults[k]}</Badge>}
            </div>
          ))}
        </CardContent>
      </Card>
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Confidence levels</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(
              [
                ["very_high", "Very High ≥"],
                ["high", "High ≥"],
                ["medium", "Medium ≥"],
                ["low", "Low ≥"],
                ["cluster_min", "Cluster membership ≥"],
              ] as [keyof ScoringConfig["thresholds"], string][]
            ).map(([k, label]) => (
              <div key={k} className="flex items-center justify-between gap-3">
                <Label>{label}</Label>
                <Input type="number" min={1} max={100} className="h-8 w-20 text-right" value={draft.thresholds[k]} disabled={!admin} onChange={(e) => setThreshold(k, Number(e.target.value))} />
              </div>
            ))}
            <p className="text-muted-foreground text-xs">Below the Low threshold findings are Informational.</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Similarity thresholds</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(Object.keys(draft.similarity) as (keyof ScoringConfig["similarity"])[]).map((k) => (
              <div key={k} className="flex items-center justify-between gap-3">
                <Label className="capitalize">{k}</Label>
                <Input type="number" step={0.01} min={0.5} max={1} className="h-8 w-20 text-right" value={draft.similarity[k]} disabled={!admin} onChange={(e) => setSimilarity(k, Number(e.target.value))} />
              </div>
            ))}
            <div className="flex items-center justify-between gap-3">
              <Label>Noisy fingerprint limit</Label>
              <Input type="number" min={5} className="h-8 w-20 text-right" value={draft.noisy_fingerprint_limit} disabled={!admin} onChange={(e) => setDraft({ ...draft, noisy_fingerprint_limit: Number(e.target.value) })} />
            </div>
            <p className="text-muted-foreground text-xs">Fingerprints shared by more assets than the limit (CDN IPs, stock favicons) count at 25% weight.</p>
          </CardContent>
        </Card>
        {admin && (
          <div className="flex gap-2">
            <Button onClick={() => save.mutate(payload as ScoringConfig)} disabled={save.isPending}>
              {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
            </Button>
            <Button variant="outline" onClick={() => reset.mutate()} disabled={reset.isPending}><RotateCcw /> Defaults</Button>
          </div>
        )}
      </div>
    </div>
  );
}
