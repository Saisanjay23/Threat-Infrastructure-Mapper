import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { Provider } from "@/types/api";

const SECRET_HINT: Record<string, string> = {
  censys: "Leave empty when using a Censys Platform personal access token; set the API secret for legacy Search API ID/secret pairs.",
  fofa: "Optional account e-mail (older FOFA accounts).",
};

export function ApiKeyDialog({ provider, onClose }: { provider: Provider | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [key, setKey] = useState("");
  const [secret, setSecret] = useState("");

  useEffect(() => {
    setKey("");
    setSecret("");
  }, [provider]);

  const save = useMutation({
    mutationFn: () => api.setProviderKey(provider!.name, key.trim(), secret.trim() || undefined),
    onSuccess: async (p) => {
      toast.success(`API key saved for ${p.display_name}`);
      if (!p.enabled) await api.updateProvider(p.name, { enabled: true });
      qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: () => api.deleteProviderKey(provider!.name),
    onSuccess: (p) => {
      toast.success(`API key removed from ${p.display_name}`);
      qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Dialog open={!!provider} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{provider?.display_name} API key</DialogTitle>
          <DialogDescription className="flex items-start gap-2">
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-emerald-400" />
            Keys are encrypted at rest (Fernet, derived from the server secret) and never returned in full by the API.
          </DialogDescription>
        </DialogHeader>
        <form
          id="api-key-form"
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (key.trim()) save.mutate();
          }}
        >
          {provider?.has_api_key && (
            <div className="text-muted-foreground text-sm">
              Current key: <span className="font-mono">{provider.api_key_masked}</span>
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="api_key">{provider?.has_api_key ? "Replace key" : "API key"}</Label>
            <Input id="api_key" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder="Paste API key" />
          </div>
          {provider && (provider.name === "censys" || provider.name === "fofa") && (
            <div className="space-y-2">
              <Label htmlFor="api_secret">{provider.name === "fofa" ? "Account e-mail (optional)" : "API secret (optional)"}</Label>
              <Input id="api_secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
              <p className="text-muted-foreground text-xs">{SECRET_HINT[provider.name]}</p>
            </div>
          )}
        </form>
        <DialogFooter>
          {provider?.has_api_key && (
            <Button variant="ghost" className="mr-auto text-red-400" onClick={() => remove.mutate()} disabled={remove.isPending}>
              Remove key
            </Button>
          )}
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="api-key-form" disabled={!key.trim() || save.isPending}>
            {save.isPending && <Loader2 className="animate-spin" />} Save key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
