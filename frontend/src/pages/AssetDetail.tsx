import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDownLeft, ArrowUpRight, Network, Tag } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { BrandPanel, ContentPanel, InfrastructurePanel, ScreenshotGallery, WebPanel, WebsitePanel } from "@/components/asset-panels";
import { ConfidenceBadge, CopyButton, ErrorBlock, KeyValue, LoadingBlock, Mono, PageHeader, StatusBadge, TypeBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/useAuth";
import { api, fileUrl } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/utils";

function JsonBlock({ value }: { value: unknown }) {
  return <pre className="bg-muted/40 max-h-[520px] overflow-auto rounded-lg border p-3 font-mono text-xs leading-relaxed">{JSON.stringify(value, null, 2)}</pre>;
}

export default function AssetDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({ queryKey: ["asset", id], queryFn: () => api.asset(id), enabled: !!id });
  const [tagInput, setTagInput] = useState("");
  const setTags = useMutation({
    mutationFn: (tags: string[]) => api.setAssetTags(id, tags),
    onSuccess: () => {
      setTagInput("");
      qc.invalidateQueries({ queryKey: ["asset", id] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (isLoading) return <LoadingBlock />;
  if (error || !data) return <ErrorBlock error={error ?? "Asset not found"} />;
  const { asset, relationships, artifacts } = data;
  const isHost = asset.type === "domain" || asset.type === "ip" || asset.type === "url";
  const cert = asset.type === "certificate" ? asset.attributes : null;
  const favicon = asset.type === "favicon" ? asset.attributes : null;

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <TypeBadge type={asset.type} />
            <Mono className="text-xl break-all">{asset.value}</Mono>
            <CopyButton value={asset.value} />
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadge status={asset.status} /> first seen {formatDate(asset.first_seen)} · last seen {timeAgo(asset.last_seen)} · sources: {asset.sources.join(", ") || "—"}
          </span>
        }
        actions={
          <Button variant="outline" asChild>
            <Link to={`/graph?asset=${asset.id}`}>
              <Network /> Open in graph
            </Link>
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-4 text-sm">
        <span className="text-muted-foreground">Correlation</span> <ConfidenceBadge score={asset.confidence} />
        <span className="text-muted-foreground">Impersonation</span> <ConfidenceBadge score={asset.impersonation_score} />
        <span className="text-muted-foreground">Brand similarity</span> <ConfidenceBadge score={asset.brand_similarity_score} />
        <span className="text-muted-foreground">Clusters</span>
        {asset.cluster_ids.length ? (
          asset.cluster_ids.map((c) => (
            <Link key={c} to={`/clusters/${c}`}>
              <Badge variant="destructive">{c}</Badge>
            </Link>
          ))
        ) : (
          <span className="text-muted-foreground">none</span>
        )}
        <span className="text-muted-foreground ml-auto flex items-center gap-1">
          <Tag className="size-3.5" /> Tags
        </span>
        {asset.tags.map((t) => (
          <Badge key={t} variant="outline" className="cursor-pointer" onClick={() => can("case:write") && setTags.mutate(asset.tags.filter((x) => x !== t))} title="Remove tag">
            #{t} ×
          </Badge>
        ))}
        {can("case:write") && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (tagInput.trim()) setTags.mutate([...asset.tags, tagInput.trim()]);
            }}
          >
            <Input value={tagInput} onChange={(e) => setTagInput(e.target.value)} placeholder="add tag" className="h-7 w-28 text-xs" />
          </form>
        )}
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="relationships">Relationships ({relationships.length})</TabsTrigger>
          <TabsTrigger value="fingerprints">Fingerprints</TabsTrigger>
          <TabsTrigger value="enrichment">Enrichment ({Object.keys(asset.enrichment ?? {}).length})</TabsTrigger>
          <TabsTrigger value="artifacts">Artifacts ({artifacts.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {isHost && (asset.attributes.web || asset.attributes.infrastructure || asset.attributes.network) && (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              {asset.attributes.web && <WebPanel asset={asset} />}
              {(asset.attributes.infrastructure || asset.attributes.network) && <InfrastructurePanel asset={asset} />}
              <ContentPanel asset={asset} />
              <BrandPanel asset={asset} />
              <div className="xl:col-span-2">
                <WebsitePanel asset={asset} />
              </div>
            </div>
          )}
          {cert && (
            <Card>
              <CardHeader>
                <CardTitle>Certificate</CardTitle>
                <Badge variant={cert.trusted ? "success" : "warning"}>{cert.trusted ? "trusted" : cert.validation_error ?? "untrusted"}</Badge>
              </CardHeader>
              <CardContent>
                <KeyValue
                  items={[
                    ["SHA-256", <Mono key="s">{asset.value}</Mono>],
                    ["SHA-1", cert.sha1 ? <Mono>{cert.sha1}</Mono> : null],
                    ["Subject", cert.subject],
                    ["Issuer", cert.issuer],
                    ["Valid", cert.not_before ? `${formatDate(cert.not_before, false)} → ${formatDate(cert.not_after, false)} (${cert.validity_days} days)` : null],
                    ["Key", cert.key_type ? `${cert.key_type} ${cert.key_size ?? ""}` : null],
                    ["Self-signed", cert.self_signed == null ? null : String(cert.self_signed)],
                    ["SAN", cert.san?.length ? <div className="flex flex-wrap gap-1">{cert.san.map((s: string) => <Badge key={s} variant="secondary" className="font-mono">{s}</Badge>)}</div> : null],
                  ]}
                />
              </CardContent>
            </Card>
          )}
          {favicon && (
            <Card>
              <CardHeader>
                <CardTitle>Favicon</CardTitle>
              </CardHeader>
              <CardContent className="flex items-start gap-6">
                {favicon.file_id && <img src={fileUrl(favicon.file_id)} alt="favicon" className="size-16 rounded-md border bg-white/5 object-contain p-2" />}
                <KeyValue
                  items={[
                    ["MurmurHash3", <Mono key="m">{asset.value}</Mono>],
                    ["MD5", favicon.md5 ? <Mono>{favicon.md5}</Mono> : null],
                    ["SHA-256", favicon.sha256 ? <Mono>{favicon.sha256}</Mono> : null],
                    ["Source URL", favicon.url ? <Mono>{favicon.url}</Mono> : null],
                    ["Dimensions", favicon.width ? `${favicon.width}×${favicon.height} ${favicon.format ?? ""}` : favicon.format],
                  ]}
                />
              </CardContent>
            </Card>
          )}
          {!isHost && !cert && !favicon && (
            <Card>
              <CardHeader>
                <CardTitle>Attributes</CardTitle>
              </CardHeader>
              <CardContent>
                <JsonBlock value={asset.attributes} />
              </CardContent>
            </Card>
          )}
          {asset.attributes.screenshots && (
            <Card>
              <CardHeader>
                <CardTitle>Screenshots</CardTitle>
              </CardHeader>
              <CardContent>
                <ScreenshotGallery screenshots={asset.attributes.screenshots} />
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="relationships">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Relationships</CardTitle>
                <CardDescription>Every graph edge touching this asset, with provenance</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Direction</TableHead>
                    <TableHead>Relationship</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Sources</TableHead>
                    <TableHead>Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {relationships.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>{r.direction === "out" ? <ArrowUpRight className="size-4 text-sky-300" /> : <ArrowDownLeft className="size-4 text-fuchsia-300" />}</TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="font-mono">{r.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Link to={`/assets/${r.other.id}`} className="hover:text-primary flex items-center gap-2">
                          <TypeBadge type={r.other.type} />
                          <Mono>{r.other.value}</Mono>
                        </Link>
                      </TableCell>
                      <TableCell><StatusBadge status={r.other.status} /></TableCell>
                      <TableCell className="text-muted-foreground text-xs">{r.sources.join(", ")}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{timeAgo(r.last_seen)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="fingerprints">
          <Card>
            <CardContent>
              <JsonBlock value={asset.fingerprints} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="enrichment" className="space-y-4">
          {Object.entries(asset.enrichment ?? {}).map(([provider, summary]) => (
            <Card key={provider}>
              <CardHeader>
                <CardTitle className="font-mono text-sm">{provider}</CardTitle>
                <span className="text-muted-foreground text-xs">{formatDate((summary as Record<string, string>)._fetched_at)}</span>
              </CardHeader>
              <CardContent>
                <JsonBlock value={summary} />
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="artifacts">
          <Card>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Kind</TableHead>
                    <TableHead>Investigation</TableHead>
                    <TableHead>Collected</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {artifacts.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell>{a.kind}</TableCell>
                      <TableCell>
                        {a.investigation_id ? (
                          <Link to={`/investigations/${a.investigation_id}`} className="text-primary font-mono text-xs hover:underline">{a.investigation_id}</Link>
                        ) : "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{formatDate(a.created_at)}</TableCell>
                      <TableCell className="text-right">
                        {a.file_id && <a href={fileUrl(a.file_id, true)} className="text-primary text-xs hover:underline">download</a>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  );
}
