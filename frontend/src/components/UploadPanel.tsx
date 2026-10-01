import { FileCode2, FileKey2, Image as ImageIcon, Loader2, ScanSearch, Upload } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { ConfidenceBadge, EmptyState, Mono, StatusBadge, TypeBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { UploadMatch } from "@/types/api";

type Kind = "logo" | "html" | "screenshot" | "certificate";

const KINDS: { key: Kind; label: string; icon: React.ReactNode; accept: string; hint: string }[] = [
  { key: "logo", label: "Logo", icon: <ImageIcon />, accept: "image/*", hint: "Register a brand reference logo and find look-alike logos / favicons" },
  { key: "screenshot", label: "Screenshot", icon: <ScanSearch />, accept: "image/*", hint: "Find visually similar pages (perceptual hash)" },
  { key: "html", label: "HTML", icon: <FileCode2 />, accept: ".html,.htm,text/html,text/plain", hint: "Extract trackers, forms and structure; pivot on them" },
  { key: "certificate", label: "Certificate", icon: <FileKey2 />, accept: ".pem,.crt,.cer,.der", hint: "Fingerprint a PEM/DER certificate; find hosts using it" },
];

interface UploadResult {
  matches: UploadMatch[];
  [k: string]: unknown;
}

export function UploadPanel() {
  const [kind, setKind] = useState<Kind>("logo");
  const [file, setFile] = useState<File | null>(null);
  const [brand, setBrand] = useState("");
  const [pageUrl, setPageUrl] = useState("");
  const [investigate, setInvestigate] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const meta = KINDS.find((k) => k.key === kind)!;

  const submit = async () => {
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    if (kind === "logo" && brand) form.append("brand", brand);
    if (kind === "html") {
      if (pageUrl) form.append("page_url", pageUrl);
      if (brand) form.append("brand", brand);
    }
    if (kind === "certificate") form.append("investigate", String(investigate));
    setBusy(true);
    try {
      const res = await api.upload<UploadResult>(kind, form);
      setResult(res);
      toast.success(`${meta.label} analysed: ${res.matches.length} match(es)`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const fp = (result?.fingerprints ?? {}) as Record<string, any>;
  const brandRes = result?.brand as Record<string, any> | undefined;
  const content = result?.content as Record<string, any> | undefined;
  const cert = result?.certificate as Record<string, any> | undefined;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        {KINDS.map((k) => (
          <button
            key={k.key}
            type="button"
            onClick={() => { setKind(k.key); setResult(null); setFile(null); }}
            className={cn("flex cursor-pointer flex-col items-start gap-1 rounded-lg border p-3 text-left [&_svg]:size-5", kind === k.key ? "border-primary bg-primary/10" : "hover:bg-accent")}
          >
            {k.icon}
            <span className="font-medium">{k.label}</span>
            <span className="text-muted-foreground text-[11px]">{k.hint}</span>
          </button>
        ))}
      </div>
      <div className="grid grid-cols-1 items-end gap-3 md:grid-cols-4">
        <div className="space-y-1.5 md:col-span-2">
          <Label htmlFor="upload-file">File</Label>
          <Input id="upload-file" type="file" accept={meta.accept} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </div>
        {(kind === "logo" || kind === "html") && (
          <div className="space-y-1.5">
            <Label htmlFor="upload-brand">Brand {kind === "logo" ? "(registers a reference)" : "(optional)"}</Label>
            <Input id="upload-brand" value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="Contoso Bank" />
          </div>
        )}
        {kind === "html" && (
          <div className="space-y-1.5">
            <Label htmlFor="upload-url">Original page URL</Label>
            <Input id="upload-url" value={pageUrl} onChange={(e) => setPageUrl(e.target.value)} placeholder="https://suspicious.example/login" />
          </div>
        )}
        {kind === "certificate" && (
          <label className="flex items-center gap-2 pb-2 text-sm">
            <Switch checked={investigate} onCheckedChange={setInvestigate} /> Start investigation
          </label>
        )}
        <Button onClick={submit} disabled={!file || busy}>
          {busy ? <Loader2 className="animate-spin" /> : <Upload />} Analyse
        </Button>
      </div>

      {result && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2 text-xs">
            {fp.phash && <Badge variant="secondary" className="font-mono">phash {fp.phash}</Badge>}
            {fp.dhash && <Badge variant="secondary" className="font-mono">dhash {fp.dhash}</Badge>}
            {fp.mmh3 && <Badge variant="secondary" className="font-mono">mmh3 {fp.mmh3}</Badge>}
            {fp.title && <Badge variant="outline">title: {fp.title}</Badge>}
            {(fp.tracking_ids ?? []).map((t: string) => <Badge key={t} variant="warning" className="font-mono">{t}</Badge>)}
            {fp.has_login_form && <Badge variant="destructive">login form</Badge>}
            {content && <StatusBadge status={content.status} />}
            {brandRes && <Badge variant="destructive">impersonation {brandRes.impersonation_score}</Badge>}
            {cert && <Badge variant="success" className="font-mono">sha256 {String(cert.sha256).slice(0, 24)}…</Badge>}
            {cert && cert.san?.length > 0 && <Badge variant="outline">SAN: {cert.san.slice(0, 5).join(", ")}</Badge>}
            {result.reference ? <Badge variant="success">registered as {String(result.brand)} reference</Badge> : null}
            {result.investigation_id ? (
              <Link to={`/investigations/${String(result.investigation_id)}`}><Badge variant="info">investigation started →</Badge></Link>
            ) : null}
          </div>
          {result.matches.length ? (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Matched via</TableHead>
                    <TableHead>Similarity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Confidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.matches.map((m) => (
                    <TableRow key={m.id}>
                      <TableCell><TypeBadge type={m.type} /></TableCell>
                      <TableCell><Link to={`/assets/${m.id}`} className="hover:text-primary"><Mono>{m.value}</Mono></Link></TableCell>
                      <TableCell className="text-xs">{m.via}{m.shared?.length ? `: ${m.shared.join(", ")}` : ""}</TableCell>
                      <TableCell className="tabular-nums">{Math.round(m.similarity * 100)}%</TableCell>
                      <TableCell><StatusBadge status={m.status} /></TableCell>
                      <TableCell><ConfidenceBadge score={m.confidence} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState title="No matching infrastructure in the inventory yet" description="Fingerprints were stored; future investigations will correlate against them." />
          )}
        </div>
      )}
    </div>
  );
}
