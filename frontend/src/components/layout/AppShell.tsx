import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Boxes,
  FileText,
  FolderKanban,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  PlugZap,
  Radar,
  ScrollText,
  Search,
  Settings,
  ShieldAlert,
  User as UserIcon,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Input } from "@/components/ui/input";
import { Tooltip } from "@/components/ui/misc";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  permission?: string;
  section: "Intelligence" | "Operations" | "Administration";
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", icon: <LayoutDashboard />, section: "Intelligence" },
  { to: "/investigations", label: "Investigations", icon: <Radar />, section: "Intelligence" },
  { to: "/assets", label: "Assets", icon: <Boxes />, section: "Intelligence" },
  { to: "/clusters", label: "Threat Clusters", icon: <ShieldAlert />, section: "Intelligence" },
  { to: "/graph", label: "Graph Explorer", icon: <Network />, section: "Intelligence" },
  { to: "/cases", label: "Cases", icon: <FolderKanban />, permission: "case:read", section: "Operations" },
  { to: "/reports", label: "Reports", icon: <FileText />, permission: "report:export", section: "Operations" },
  { to: "/providers", label: "Providers", icon: <PlugZap />, permission: "provider:read", section: "Administration" },
  { to: "/api-keys", label: "API Keys", icon: <KeyRound />, permission: "provider:admin", section: "Administration" },
  { to: "/audit-logs", label: "Audit Logs", icon: <ScrollText />, permission: "audit:read", section: "Administration" },
  { to: "/settings", label: "Settings", icon: <Settings />, section: "Administration" },
];

/** Routes registered by the router; nav entries for routes not yet registered are hidden. */
export let REGISTERED_ROUTES: Set<string> = new Set();
export function registerRoutes(paths: string[]) {
  REGISTERED_ROUTES = new Set(paths);
}

function HealthDot() {
  const { data, isError } = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 30000 });
  const ok = data?.status === "ok" && !isError;
  const label = isError
    ? "Backend unreachable"
    : data
      ? `API ${data.version} · MongoDB ${data.mongodb.ok ? "ok" : "down"} · Browser ${data.browser.available === false ? "unavailable" : "ready"}`
      : "Checking…";
  return (
    <Tooltip content={label}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span className={cn("size-2 rounded-full", ok ? "bg-emerald-400 shadow-[0_0_8px] shadow-emerald-400/60" : "bg-red-500")} />
        <span className="hidden lg:inline">{ok ? "Operational" : "Degraded"}</span>
      </div>
    </Tooltip>
  );
}

function SideNav({ items, onNavigate }: { items: NavItem[]; onNavigate?: () => void }) {
  const sections = ["Intelligence", "Operations", "Administration"] as const;
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto p-3">
      {sections.map((section) => {
        const group = items.filter((n) => n.section === section);
        if (!group.length) return null;
        return (
          <div key={section}>
            <div className="text-muted-foreground mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-widest">{section}</div>
            <div className="space-y-0.5">
              {group.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors [&_svg]:size-4",
                      isActive ? "bg-primary/12 text-primary font-medium" : "text-muted-foreground hover:bg-accent hover:text-foreground",
                    )
                  }
                >
                  {item.icon}
                  {item.label}
                </NavLink>
              ))}
            </div>
          </div>
        );
      })}
    </nav>
  );
}

export function AppShell() {
  const { user, logout, can } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const visible = NAV_ITEMS.filter((n) => (!n.permission || can(n.permission)) && REGISTERED_ROUTES.has(n.to));

  return (
    <div className="flex h-full">
      <aside className="bg-sidebar hidden w-60 shrink-0 flex-col border-r md:flex">
        <div className="flex h-14 items-center gap-2 border-b px-4">
          <img src="/tim.svg" alt="" className="size-7" />
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-wide">TIM</div>
            <div className="text-muted-foreground text-[10px] uppercase tracking-widest">Infrastructure Mapper</div>
          </div>
        </div>
        <SideNav items={visible} />
        <div className="text-muted-foreground border-t p-3 text-[11px]">
          <div className="flex items-center gap-1.5">
            <Activity className="size-3" /> Local-first · no data leaves this host except provider queries
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="bg-background/80 sticky top-0 z-30 flex h-14 items-center gap-3 border-b px-4 backdrop-blur">
          <DialogPrimitive.Root open={mobileNav} onOpenChange={setMobileNav}>
            <DialogPrimitive.Trigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open navigation">
                <Menu />
              </Button>
            </DialogPrimitive.Trigger>
            <DialogPrimitive.Portal>
              <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60" />
              <DialogPrimitive.Content className="bg-sidebar data-[state=open]:animate-in data-[state=open]:slide-in-from-left fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r">
                <DialogPrimitive.Title className="flex h-14 items-center gap-2 border-b px-4 text-sm font-semibold">
                  <img src="/tim.svg" alt="" className="size-7" /> TIM
                </DialogPrimitive.Title>
                <SideNav items={visible} onNavigate={() => setMobileNav(false)} />
              </DialogPrimitive.Content>
            </DialogPrimitive.Portal>
          </DialogPrimitive.Root>
          <form
            className="relative max-w-md flex-1"
            onSubmit={(e) => {
              e.preventDefault();
              if (search.trim()) navigate(`/assets?q=${encodeURIComponent(search.trim())}`);
            }}
          >
            <Search className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets: domain, IP, hash, tracking ID…"
              className="pl-8"
              aria-label="Search assets"
            />
          </form>
          <div className="ml-auto flex items-center gap-3">
            <HealthDot />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                  <UserIcon /> {user?.username}
                  <Badge variant="secondary" className="ml-1 capitalize">
                    {user?.role}
                  </Badge>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>Signed in as {user?.username}</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => navigate("/settings")}>
                  <Settings /> Settings
                </DropdownMenuItem>
                <DropdownMenuItem onClick={logout}>
                  <LogOut /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        <main className="grid-bg min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1600px] p-4 md:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
