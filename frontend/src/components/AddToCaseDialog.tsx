import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderPlus, Loader2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Severity } from "@/types/api";

interface Links {
  asset_ids?: string[];
  investigation_ids?: string[];
  cluster_ids?: string[];
}

export function AddToCaseDialog({ links, trigger, disabled }: { links: Links; trigger?: ReactNode; disabled?: boolean }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [caseId, setCaseId] = useState("");
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [busy, setBusy] = useState(false);
  const cases = useQuery({ queryKey: ["cases", "picker"], queryFn: () => api.cases({ page_size: 100, status: undefined }), enabled: open });
  const count = (links.asset_ids?.length ?? 0) + (links.investigation_ids?.length ?? 0) + (links.cluster_ids?.length ?? 0);

  const addExisting = async () => {
    setBusy(true);
    try {
      await api.linkCase(caseId, links);
      toast.success(`Added ${count} item(s) to ${caseId}`, { action: { label: "Open", onClick: () => navigate(`/cases/${caseId}`) } });
      qc.invalidateQueries({ queryKey: ["cases"] });
      setOpen(false);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const createNew = async () => {
    setBusy(true);
    try {
      const c = await api.createCase({ title, severity, ...links });
      toast.success(`Created ${c.id}`, { action: { label: "Open", onClick: () => navigate(`/cases/${c.id}`) } });
      qc.invalidateQueries({ queryKey: ["cases"] });
      setOpen(false);
      setTitle("");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild disabled={disabled}>
        {trigger ?? (
          <Button variant="outline" size="sm" disabled={disabled}>
            <FolderPlus /> Add to case
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add to case</DialogTitle>
          <DialogDescription>{count} item(s) will be attached.</DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="existing">
          <TabsList>
            <TabsTrigger value="existing">Existing case</TabsTrigger>
            <TabsTrigger value="new">New case</TabsTrigger>
          </TabsList>
          <TabsContent value="existing" className="space-y-3">
            <Select value={caseId} onValueChange={setCaseId}>
              <SelectTrigger><SelectValue placeholder={cases.isLoading ? "Loading cases…" : "Choose a case"} /></SelectTrigger>
              <SelectContent>
                {(cases.data?.items ?? []).map((c) => (
                  <SelectItem key={c.id} value={c.id}>{c.id} · {c.title}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <DialogFooter>
              <Button onClick={addExisting} disabled={!caseId || busy}>{busy && <Loader2 className="animate-spin" />} Add</Button>
            </DialogFooter>
          </TabsContent>
          <TabsContent value="new" className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="case-title">Title</Label>
              <Input id="case-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Contoso phishing wave — October" />
            </div>
            <div className="space-y-1.5">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["critical", "high", "medium", "low", "info"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <DialogFooter>
              <Button onClick={createNew} disabled={!title.trim() || busy}>{busy && <Loader2 className="animate-spin" />} Create case</Button>
            </DialogFooter>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
