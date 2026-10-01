import { useQueryClient } from "@tanstack/react-query";
import { Download, FileJson, FileSpreadsheet, FileText, Globe, Loader2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { cn, downloadBlob } from "@/lib/utils";
import type { ExportRequest, ReportFormat, ReportSection } from "@/types/api";

export const SECTIONS: { key: ReportSection; label: string }[] = [
  { key: "executive_summary", label: "Executive summary" },
  { key: "investigation_details", label: "Investigation details" },
  { key: "evidence", label: "Evidence" },
  { key: "screenshots", label: "Screenshots" },
  { key: "threat_clusters", label: "Threat clusters" },
  { key: "related_assets", label: "Related assets" },
  { key: "confidence_scores", label: "Confidence scores" },
  { key: "graph_snapshot", label: "Graph snapshot" },
  { key: "analyst_notes", label: "Analyst notes" },
];

const FORMATS: { key: ReportFormat; label: string; icon: ReactNode; hint: string }[] = [
  { key: "pdf", label: "PDF", icon: <FileText />, hint: "Analyst report (ReportLab)" },
  { key: "html", label: "HTML", icon: <Globe />, hint: "Self-contained, print to PDF" },
  { key: "csv", label: "CSV", icon: <FileSpreadsheet />, hint: "Related assets table" },
  { key: "json", label: "JSON", icon: <FileJson />, hint: "Full data model" },
];

type Scope = Pick<ExportRequest, "investigation_id" | "cluster_id" | "case_id" | "asset_ids">;

export function ExportDialog({ scope, defaultTitle, trigger }: { scope: Scope; defaultTitle?: string; trigger?: ReactNode }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [format, setFormat] = useState<ReportFormat>("pdf");
  const [sections, setSections] = useState<Set<ReportSection>>(new Set(SECTIONS.map((s) => s.key)));
  const [title, setTitle] = useState(defaultTitle ?? "");
  const [tlp, setTlp] = useState<NonNullable<ExportRequest["tlp"]>>("AMBER");
  const [minConfidence, setMinConfidence] = useState(0);
  const [notes, setNotes] = useState("");
  const [save, setSave] = useState(true);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      const { blob, filename } = await api.exportReport(format, {
        ...scope,
        title: title || undefined,
        sections: Array.from(sections),
        tlp,
        min_confidence: minConfidence,
        analyst_notes: notes || undefined,
        save,
      });
      downloadBlob(blob, filename ?? `tim-report.${format}`);
      toast.success(`${format.toUpperCase()} report generated`);
      qc.invalidateQueries({ queryKey: ["reports"] });
      setOpen(false);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button variant="outline">
            <Download /> Export
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Generate report</DialogTitle>
          <DialogDescription>Choose a format and the sections to include. Reports are saved to the library unless disabled.</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {FORMATS.map((f) => (
            <button
              key={f.key}
              type="button"
              onClick={() => setFormat(f.key)}
              className={cn(
                "flex cursor-pointer flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors [&_svg]:size-5",
                format === f.key ? "border-primary bg-primary/10" : "hover:bg-accent",
              )}
            >
              {f.icon}
              <span className="font-medium">{f.label}</span>
              <span className="text-muted-foreground text-[11px]">{f.hint}</span>
            </button>
          ))}
        </div>
        {(format === "pdf" || format === "html") && (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {SECTIONS.map((s) => (
              <label key={s.key} className="flex cursor-pointer items-center gap-2 text-sm">
                <Checkbox
                  checked={sections.has(s.key)}
                  onCheckedChange={(v) => {
                    const next = new Set(sections);
                    if (v) next.add(s.key);
                    else next.delete(s.key);
                    setSections(next);
                  }}
                />
                {s.label}
              </label>
            ))}
          </div>
        )}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="space-y-1.5 sm:col-span-3">
            <Label htmlFor="rep-title">Title</Label>
            <Input id="rep-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Auto-generated from scope" />
          </div>
          <div className="space-y-1.5">
            <Label>TLP</Label>
            <Select value={tlp} onValueChange={(v) => setTlp(v as typeof tlp)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"].map((t) => <SelectItem key={t} value={t}>TLP:{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>Minimum confidence</Label>
            <Select value={String(minConfidence)} onValueChange={(v) => setMinConfidence(Number(v))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {[0, 30, 50, 70, 90].map((v) => <SelectItem key={v} value={String(v)}>{v ? `≥ ${v}` : "All assets"}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 self-end pb-2 text-sm">
            <Switch checked={save} onCheckedChange={setSave} /> Save to library
          </label>
          <div className="space-y-1.5 sm:col-span-3">
            <Label htmlFor="rep-notes">Analyst notes (added to the report)</Label>
            <Textarea id="rep-notes" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={run} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <Download />} Generate {format.toUpperCase()}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
