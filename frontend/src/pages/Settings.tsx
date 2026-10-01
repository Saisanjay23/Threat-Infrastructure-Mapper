import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { HeartPulse, Loader2, UserPlus, Users } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ErrorBlock, KeyValue, LoadingBlock, PageHeader, StatusBadge } from "@/components/common";
import { ScoringSettings } from "@/components/ScoringSettings";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/utils";
import type { Role, User } from "@/types/api";

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" as Role, email: "", full_name: "" });
  const create = useMutation({
    mutationFn: () => api.createUser({ ...form, email: form.email || undefined, full_name: form.full_name || undefined }),
    onSuccess: (u) => {
      toast.success(`User ${u.username} created`);
      qc.invalidateQueries({ queryKey: ["users"] });
      setForm({ username: "", password: "", role: "analyst", email: "", full_name: "" });
      onClose();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create user</DialogTitle>
        </DialogHeader>
        <form id="create-user" className="grid grid-cols-2 gap-3" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <div className="col-span-2 space-y-2 sm:col-span-1">
            <Label htmlFor="nu-username">Username</Label>
            <Input id="nu-username" required minLength={3} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </div>
          <div className="col-span-2 space-y-2 sm:col-span-1">
            <Label>Role</Label>
            <Select value={form.role} onValueChange={(v) => setForm({ ...form, role: v as Role })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">viewer — read only</SelectItem>
                <SelectItem value="analyst">analyst — investigate, cases, export</SelectItem>
                <SelectItem value="admin">admin — everything</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="col-span-2 space-y-2">
            <Label htmlFor="nu-password">Password (min 8 characters)</Label>
            <Input id="nu-password" type="password" required minLength={8} autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </div>
          <div className="col-span-2 space-y-2 sm:col-span-1">
            <Label htmlFor="nu-name">Full name</Label>
            <Input id="nu-name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          </div>
          <div className="col-span-2 space-y-2 sm:col-span-1">
            <Label htmlFor="nu-email">E-mail</Label>
            <Input id="nu-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button type="submit" form="create-user" disabled={create.isPending}>
            {create.isPending && <Loader2 className="animate-spin" />} Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function UsersTab() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const users = useQuery({ queryKey: ["users"], queryFn: api.users });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof api.updateUser>[1] }) => api.updateUser(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
    onError: (e: Error) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      toast.success("User deleted");
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const resetPassword = (u: User) => {
    const pw = window.prompt(`New password for ${u.username} (min 8 characters)`);
    if (pw && pw.length >= 8) update.mutate({ id: u.id, body: { password: pw } }, { onSuccess: () => toast.success("Password updated") });
    else if (pw) toast.error("Password must be at least 8 characters");
  };

  if (users.isLoading) return <LoadingBlock />;
  if (users.error) return <ErrorBlock error={users.error} />;
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle className="flex items-center gap-2"><Users className="size-4" /> Users & roles</CardTitle>
          <CardDescription>Role-based access control: viewer, analyst, admin</CardDescription>
        </div>
        <Button size="sm" onClick={() => setCreating(true)}><UserPlus /> New user</Button>
      </CardHeader>
      <CardContent className="px-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead>Last login</TableHead>
              <TableHead>Created</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {(users.data ?? []).map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.username} {u.id === me?.id && <Badge variant="secondary">you</Badge>}</TableCell>
                <TableCell className="text-muted-foreground text-sm">{u.full_name ?? "—"}<div className="text-xs">{u.email}</div></TableCell>
                <TableCell>
                  <Select value={u.role} disabled={u.id === me?.id} onValueChange={(v) => update.mutate({ id: u.id, body: { role: v as Role } })}>
                    <SelectTrigger className="h-8 w-28"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">viewer</SelectItem>
                      <SelectItem value="analyst">analyst</SelectItem>
                      <SelectItem value="admin">admin</SelectItem>
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <Switch checked={!u.disabled} disabled={u.id === me?.id} onCheckedChange={(c) => update.mutate({ id: u.id, body: { disabled: !c } })} />
                </TableCell>
                <TableCell className="text-muted-foreground text-xs">{timeAgo(u.last_login)}</TableCell>
                <TableCell className="text-muted-foreground text-xs">{formatDate(u.created_at, false)}</TableCell>
                <TableCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => resetPassword(u)}>Reset password</Button>
                  {u.id !== me?.id && (
                    <Button variant="ghost" size="sm" className="text-red-400" onClick={() => window.confirm(`Delete ${u.username}?`) && remove.mutate(u.id)}>
                      Delete
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
      <CreateUserDialog open={creating} onClose={() => setCreating(false)} />
    </Card>
  );
}

function SystemTab() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 10000 });
  if (health.isLoading) return <LoadingBlock />;
  if (health.error || !health.data) return <ErrorBlock error={health.error ?? "unavailable"} />;
  const h = health.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><HeartPulse className="size-4" /> System health</CardTitle>
        <StatusBadge status={h.status === "ok" ? "healthy" : "degraded"} />
      </CardHeader>
      <CardContent>
        <KeyValue
          items={[
            ["API version", h.version],
            ["Environment", h.environment],
            ["MongoDB", <span key="m">{h.mongodb.ok ? "connected" : "unavailable"} · database <span className="font-mono">{h.mongodb.database}</span>{h.mongodb.error ? ` · ${h.mongodb.error}` : ""}</span>],
            ["Screenshot engine", h.browser.enabled ? (h.browser.available === false ? `unavailable — ${h.browser.last_error}` : h.browser.available ? "ready" : "idle (starts on first capture)") : "disabled"],
            ["Tracked pipelines", h.pipeline?.tracked ?? 0],
            ["WebSocket subscribers", h.websocket_subscribers],
            ["API docs", <a key="d" className="text-primary hover:underline" href="/api/docs" target="_blank" rel="noreferrer">/api/docs (OpenAPI)</a>],
            ["Metrics", <a key="p" className="text-primary hover:underline" href="/api/metrics" target="_blank" rel="noreferrer">/api/metrics (Prometheus)</a>],
          ]}
        />
      </CardContent>
    </Card>
  );
}

function AccountTab() {
  const { user } = useAuth();
  return (
    <Card>
      <CardHeader><CardTitle>Your account</CardTitle></CardHeader>
      <CardContent>
        <KeyValue
          items={[
            ["Username", user?.username],
            ["Role", user?.role],
            ["Permissions", <div key="p" className="flex flex-wrap gap-1">{user?.permissions.map((p) => <Badge key={p} variant="secondary" className="font-mono">{p}</Badge>)}</div>],
          ]}
        />
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const { can } = useAuth();
  return (
    <>
      <PageHeader title="Settings" description="Users, roles, system health and platform configuration" />
      <Tabs defaultValue={can("user:admin") ? "users" : "account"}>
        <TabsList>
          {can("user:admin") && <TabsTrigger value="users">Users</TabsTrigger>}
          <TabsTrigger value="scoring">Scoring model</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
        </TabsList>
        {can("user:admin") && <TabsContent value="users"><UsersTab /></TabsContent>}
        <TabsContent value="scoring"><ScoringSettings /></TabsContent>
        <TabsContent value="system"><SystemTab /></TabsContent>
        <TabsContent value="account"><AccountTab /></TabsContent>
      </Tabs>
    </>
  );
}
