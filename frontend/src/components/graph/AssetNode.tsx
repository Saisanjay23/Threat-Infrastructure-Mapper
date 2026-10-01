import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  Award,
  BarChart3,
  Building2,
  Fingerprint,
  Globe,
  Image as ImageIcon,
  Link2,
  Network,
  Radar,
  Server,
  ShieldAlert,
  Tag,
  Waypoints,
} from "lucide-react";
import { memo, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export const TYPE_COLORS: Record<string, string> = {
  domain: "#22d3ee",
  url: "#60a5fa",
  ip: "#c084fc",
  certificate: "#34d399",
  analytics: "#fbbf24",
  pixel: "#fb923c",
  tracking: "#facc15",
  favicon: "#94a3b8",
  logo: "#cbd5e1",
  asn: "#a3a3a3",
  hosting: "#a8a29e",
  nameserver: "#9ca3af",
  cluster: "#f87171",
};

const TYPE_ICON: Record<string, ReactNode> = {
  domain: <Globe />,
  url: <Link2 />,
  ip: <Server />,
  certificate: <Award />,
  analytics: <BarChart3 />,
  pixel: <Radar />,
  tracking: <Tag />,
  favicon: <Fingerprint />,
  logo: <ImageIcon />,
  asn: <Network />,
  hosting: <Building2 />,
  nameserver: <Waypoints />,
  cluster: <ShieldAlert />,
};

export interface AssetNodeData extends Record<string, unknown> {
  label: string;
  assetType: string;
  status?: string | null;
  confidence?: number | null;
  isRoot?: boolean;
  dimmed?: boolean;
  highlighted?: boolean;
  degree?: number;
}

const STATUS_DOT: Record<string, string> = {
  ACTIVE: "bg-red-500",
  PARKED: "bg-amber-400",
  TAKEDOWN: "bg-emerald-400",
  INACTIVE: "bg-slate-500",
  ERROR: "bg-slate-500",
};

function AssetNodeComponent({ data, selected }: NodeProps) {
  const d = data as AssetNodeData;
  const color = TYPE_COLORS[d.assetType] ?? "#94a3b8";
  const host = d.assetType === "domain" || d.assetType === "ip" || d.assetType === "url";
  return (
    <div
      className={cn(
        "bg-card flex max-w-[240px] items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] shadow-sm transition-all",
        d.dimmed && "opacity-20",
        (selected || d.highlighted) && "ring-2 ring-offset-1 ring-offset-transparent",
        d.isRoot && "px-3.5 py-2 text-xs font-semibold",
      )}
      style={{
        borderColor: color,
        boxShadow: d.isRoot ? `0 0 0 2px ${color}, 0 0 24px -2px ${color}` : undefined,
        ["--tw-ring-color" as string]: color,
      }}
      title={`${d.assetType}: ${d.label}`}
    >
      <Handle type="target" position={Position.Top} className="!size-1 !min-h-0 !min-w-0 !border-0 !bg-transparent" />
      <span className="shrink-0 [&_svg]:size-3.5" style={{ color }}>
        {TYPE_ICON[d.assetType] ?? <Globe />}
      </span>
      <span className={cn("truncate font-mono", !host && "text-muted-foreground")}>{d.label}</span>
      {d.status && STATUS_DOT[d.status] && <span className={cn("size-1.5 shrink-0 rounded-full", STATUS_DOT[d.status])} />}
      {d.confidence != null && host && d.confidence > 0 && (
        <span
          className={cn(
            "shrink-0 rounded px-1 text-[10px] tabular-nums",
            d.confidence >= 70 ? "bg-red-500/20 text-red-300" : d.confidence >= 50 ? "bg-amber-400/20 text-amber-200" : "bg-muted text-muted-foreground",
          )}
        >
          {d.confidence}
        </span>
      )}
      <Handle type="source" position={Position.Bottom} className="!size-1 !min-h-0 !min-w-0 !border-0 !bg-transparent" />
    </div>
  );
}

export const AssetNode = memo(AssetNodeComponent);
