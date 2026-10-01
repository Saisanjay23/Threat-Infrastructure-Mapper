import { ExternalLink, FileSearch, Fingerprint, Image as ImageIcon, Lock, Server, ShieldAlert, Unlock } from "lucide-react";
import { useState } from "react";
import { CopyButton, KeyValue, Mono, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { fileUrl } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import type { Asset } from "@/types/api";

const SHOT_LABELS: Record<string, string> = { desktop: "Desktop", mobile: "Mobile", fullpage: "Full page", thumbnail: "Thumbnail" };

export function ScreenshotGallery({ screenshots }: { screenshots?: Record<string, string> }) {
  const [open, setOpen] = useState<string | null>(null);
  const entries = Object.entries(screenshots ?? {}).filter(([k]) => k !== "thumbnail");
  if (!entries.length) {
    return (
      <div className="text-muted-foreground flex items-center gap-2 rounded-lg border border-dashed p-6 text-sm">
        <ImageIcon className="size-4" /> No screenshots captured
      </div>
    );
  }
  return (
    <>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {entries.map(([kind, id]) => (
          <button
            key={kind}
            type="button"
            onClick={() => setOpen(id)}
            className="group hover:border-primary cursor-zoom-in overflow-hidden rounded-lg border text-left transition-colors"
          >
            <img
              src={fileUrl(id)}
              alt={`${kind} screenshot`}
              loading="lazy"
              className={`w-full bg-black object-cover object-top ${kind === "mobile" ? "aspect-[9/16] max-h-72" : "aspect-video"}`}
            />
            <div className="text-muted-foreground flex items-center justify-between px-2 py-1 text-xs">
              {SHOT_LABELS[kind] ?? kind}
              <a href={fileUrl(id, true)} onClick={(e) => e.stopPropagation()} className="hover:text-primary">
                download
              </a>
            </div>
          </button>
        ))}
      </div>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <DialogContent className="max-w-[min(1400px,95vw)] sm:max-w-[min(1400px,95vw)]">
          <DialogTitle>Screenshot</DialogTitle>
          {open && <img src={fileUrl(open)} alt="screenshot" className="w-full rounded-md border" />}
        </DialogContent>
      </Dialog>
    </>
  );
}

function list(values?: string[] | null) {
  if (!values?.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Badge key={v} variant="secondary" className="font-mono">
          {v}
        </Badge>
      ))}
    </div>
  );
}

export function WebPanel({ asset }: { asset: Asset }) {
  const web = asset.attributes.web ?? {};
  const tls = asset.attributes.tls ?? {};
  const fav = asset.attributes.favicon;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ExternalLink className="size-4" /> Web
        </CardTitle>
        <StatusBadge status={asset.status} />
      </CardHeader>
      <CardContent>
        <KeyValue
          items={[
            ["Final URL", web.final_url ? (<span className="flex items-center gap-1"><Mono>{web.final_url}</Mono><CopyButton value={web.final_url} label="URL" /></span>) : null],
            ["HTTP status", web.status_code],
            ["Title", web.title],
            ["Server", web.server],
            ["Content type", web.content_type],
            ["Redirects", web.redirect_count],
            ["Served from", web.ip ? <Mono>{web.ip}</Mono> : null],
            [
              "TLS",
              tls.sha256 ? (
                <span className="flex items-center gap-2">
                  {tls.trusted ? <Lock className="size-3.5 text-emerald-400" /> : <Unlock className="size-3.5 text-amber-300" />}
                  {tls.issuer_org ?? "unknown issuer"} · {tls.protocol} · expires {formatDate(tls.not_after, false)}
                </span>
              ) : null,
            ],
            ["Favicon", fav ? (<span className="flex items-center gap-2"><img src={fileUrl(fav.file_id)} alt="" className="size-5 rounded-sm bg-white/5" /><Mono>mmh3 {fav.mmh3}</Mono></span>) : null],
            ["Fetch error", web.fetch_error ? <span className="text-amber-300">{web.fetch_error}</span> : null],
          ]}
        />
      </CardContent>
    </Card>
  );
}

export function ContentPanel({ asset }: { asset: Asset }) {
  const c = asset.attributes.content;
  if (!c) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="size-4" /> Content validation
        </CardTitle>
        <span className="flex items-center gap-2">
          <StatusBadge status={c.status} />
          <span className="text-muted-foreground text-xs tabular-nums">{c.confidence}% confidence</span>
        </span>
      </CardHeader>
      <CardContent className="space-y-3">
        <ul className="list-inside list-disc space-y-1 text-sm">
          {(c.reasons ?? []).map((r: string) => (
            <li key={r} className="break-words">{r}</li>
          ))}
        </ul>
        {c.scores && (
          <div className="flex flex-wrap gap-2 text-xs">
            {Object.entries(c.scores as Record<string, number>).map(([k, v]) => (
              <Badge key={k} variant="secondary" className="tabular-nums">
                {k}: {v}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ScoreBar({ label, value }: { label: string; value?: number | null }) {
  const v = value ?? 0;
  const color = v >= 70 ? "bg-red-500" : v >= 50 ? "bg-amber-400" : v >= 30 ? "bg-sky-400" : "bg-emerald-500";
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-semibold tabular-nums">{value ?? "—"}</span>
      </div>
      <div className="bg-muted h-2 overflow-hidden rounded-full">
        <div className={`${color} h-full transition-all`} style={{ width: `${v}%` }} />
      </div>
    </div>
  );
}

export function BrandPanel({ asset }: { asset: Asset }) {
  const b = asset.attributes.brand;
  if (!b) return null;
  const s = b.signals ?? {};
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="size-4" /> Brand impersonation
        </CardTitle>
        {b.brand ? (
          <Badge variant={b.legitimate ? "success" : "outline"}>
            {b.brand}
            {b.brand_inferred ? " (inferred)" : ""}
            {b.legitimate ? " · legitimate" : ""}
          </Badge>
        ) : (
          <Badge variant="secondary">no brand context</Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <ScoreBar label="Brand similarity" value={b.brand_similarity_score} />
          <ScoreBar label="Impersonation confidence" value={b.impersonation_score} />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {s.login_form && <Badge variant="destructive">login form</Badge>}
          {s.password_fields > 0 && <Badge variant="destructive">{s.password_fields} password field(s)</Badge>}
          {s.credential_collection && <Badge variant="destructive">credential collection</Badge>}
          {s.telegram_exfil && <Badge variant="destructive">telegram exfil</Badge>}
          {s.brand_in_domain && <Badge variant="warning">brand in domain</Badge>}
          {s.homoglyph && <Badge variant="warning">homoglyph</Badge>}
          {s.typosquat && <Badge variant="warning">typosquat</Badge>}
          {s.brand_in_title && <Badge variant="warning">brand in title</Badge>}
          {s.logo_similarity > 0 && <Badge variant="info">logo similarity {Math.round(s.logo_similarity * 100)}%</Badge>}
          {(s.domain_keywords ?? []).map((k: string) => (
            <Badge key={`d-${k}`} variant="secondary">domain:{k}</Badge>
          ))}
          {(s.page_keywords ?? []).map((k: string) => (
            <Badge key={`p-${k}`} variant="secondary">page:{k}</Badge>
          ))}
        </div>
        {b.indicators?.length > 0 && (
          <ul className="list-inside list-disc space-y-1 text-sm">
            {b.indicators.map((i: string) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

export function WebsitePanel({ asset }: { asset: Asset }) {
  const w = asset.attributes.website;
  if (!w || !Object.keys(w).length) return null;
  const trackers = Object.entries((w.trackers ?? {}) as Record<string, { id: string; family: string }[]>);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Fingerprint className="size-4" /> Website fingerprints
        </CardTitle>
      </CardHeader>
      <CardContent>
        <KeyValue
          items={[
            [
              "Tracking IDs",
              trackers.length ? (
                <div className="flex flex-wrap gap-1">
                  {trackers.flatMap(([type, items]) =>
                    items.map((t) => (
                      <Badge key={t.id} variant="warning" className="font-mono" title={`${type} · ${t.family}`}>
                        {t.family}: {t.id}
                      </Badge>
                    )),
                  )}
                </div>
              ) : null,
            ],
            ["Forms", w.form_count ? `${w.form_count} form(s), ${w.password_fields ?? 0} password field(s)` : null],
            ["Form targets", list(w.external_form_actions)],
            ["Technologies", list(w.technologies)],
            ["Script hosts", list(w.script_hosts?.slice(0, 12))],
            ["Language", w.language],
            ["Generator", w.meta?.generator],
            ["Description", w.meta?.description],
            ["E-mails", list(w.emails)],
            ["Crypto wallets", list(w.crypto_wallets)],
            ["Words", w.word_count],
          ]}
        />
      </CardContent>
    </Card>
  );
}

export function InfrastructurePanel({ asset }: { asset: Asset }) {
  const infra = asset.attributes.infrastructure ?? {};
  const net = asset.attributes.network ?? {};
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="size-4" /> Infrastructure
        </CardTitle>
      </CardHeader>
      <CardContent>
        <KeyValue
          items={[
            ["IP addresses", list(infra.ips)],
            ["Nameservers", list(infra.nameservers)],
            ["MX", list(infra.mx)],
            ["ASN", list(infra.asns ?? (net.asn ? [net.asn] : null))],
            ["Hosting", list(infra.hosting_providers ?? (net.hosting_provider ? [net.hosting_provider] : null))],
            ["Country", infra.country ?? net.country],
            ["Registrar", infra.registrar],
            ["Created", infra.created ? formatDate(infra.created, false) : null],
            ["Expires", infra.expires ? formatDate(infra.expires, false) : null],
            ["Registrant", infra.registrant_org],
            ["Abuse contact", infra.abuse_email],
            ["Network", net.network_name],
            ["PTR", list(net.ptr)],
          ]}
        />
      </CardContent>
    </Card>
  );
}
