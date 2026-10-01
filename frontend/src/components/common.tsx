import { Check, Copy, Inbox, Loader2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { Badge, type BadgeVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tooltip } from "@/components/ui/misc";
import { cn, confidenceLevel, copyText } from "@/lib/utils";

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-muted-foreground mt-1 text-sm">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({
  label,
  value,
  icon,
  hint,
  accent = "text-primary",
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  hint?: ReactNode;
  accent?: string;
}) {
  return (
    <Card className="gap-2 py-4">
      <CardContent className="flex items-start justify-between gap-3">
        <div>
          <div className="text-muted-foreground text-xs font-medium uppercase tracking-wide">{label}</div>
          <div className="mt-1 text-3xl font-semibold tabular-nums">{value}</div>
          {hint && <div className="text-muted-foreground mt-1 text-xs">{hint}</div>}
        </div>
        {icon && <div className={cn("bg-muted/60 rounded-lg p-2", accent)}>{icon}</div>}
      </CardContent>
    </Card>
  );
}

const STATUS_VARIANT: Record<string, BadgeVariant> = {
  queued: "secondary",
  running: "info",
  completed: "success",
  failed: "destructive",
  cancelled: "warning",
  pending: "secondary",
  skipped: "secondary",
  ACTIVE: "destructive",
  INACTIVE: "secondary",
  PARKED: "warning",
  TAKEDOWN: "success",
  ERROR: "secondary",
  UNKNOWN: "outline",
  healthy: "success",
  degraded: "warning",
  down: "destructive",
  unknown: "secondary",
  unconfigured: "outline",
  success: "success",
  failure: "destructive",
};

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  if (!status) return <span className="text-muted-foreground">—</span>;
  return (
    <Badge variant={STATUS_VARIANT[status] ?? "secondary"} className={className}>
      {status === "running" && <Loader2 className="animate-spin" />}
      {status}
    </Badge>
  );
}

export function ConfidenceBadge({ score }: { score?: number | null }) {
  if (score == null) return <span className="text-muted-foreground">—</span>;
  const variant: BadgeVariant = score >= 90 ? "destructive" : score >= 70 ? "warning" : score >= 50 ? "info" : score >= 30 ? "secondary" : "outline";
  return (
    <Badge variant={variant} className="tabular-nums">
      {score} · {confidenceLevel(score)}
    </Badge>
  );
}

const TYPE_VARIANT: Record<string, BadgeVariant> = {
  domain: "default",
  url: "info",
  ip: "purple",
  certificate: "success",
  analytics: "warning",
  pixel: "warning",
  tracking: "warning",
  favicon: "secondary",
  logo: "secondary",
  asn: "outline",
  hosting: "outline",
  nameserver: "outline",
  cluster: "destructive",
};

export function TypeBadge({ type }: { type: string }) {
  return <Badge variant={TYPE_VARIANT[type] ?? "secondary"}>{type}</Badge>;
}

export function CopyButton({ value, label, className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Tooltip content={label ?? "Copy"}>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className={cn("text-muted-foreground", className)}
        onClick={async (e) => {
          e.stopPropagation();
          if (await copyText(value)) {
            setDone(true);
            toast.success(label ? `${label} copied` : "Copied to clipboard");
            setTimeout(() => setDone(false), 1200);
          }
        }}
      >
        {done ? <Check className="text-emerald-400" /> : <Copy />}
      </Button>
    </Tooltip>
  );
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-12 text-center">
      <Inbox className="text-muted-foreground size-8" />
      <div className="font-medium">{title}</div>
      {description && <div className="text-muted-foreground max-w-md text-sm">{description}</div>}
      {action}
    </div>
  );
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="text-muted-foreground flex items-center justify-center gap-2 py-12 text-sm">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{message}</div>;
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-2 text-sm">
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v ?? <span className="text-muted-foreground">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[0.8rem]", className)}>{children}</span>;
}
