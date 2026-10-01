import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { LoadingBlock } from "@/components/common";
import { AppShell, registerRoutes } from "@/components/layout/AppShell";
import { useAuth } from "@/hooks/useAuth";
import LoginPage from "@/pages/Login";

const DashboardPage = lazy(() => import("@/pages/Dashboard"));
const InvestigationsPage = lazy(() => import("@/pages/Investigations"));
const InvestigationDetailPage = lazy(() => import("@/pages/InvestigationDetail"));
const AssetsPage = lazy(() => import("@/pages/Assets"));
const AssetDetailPage = lazy(() => import("@/pages/AssetDetail"));
const ProvidersPage = lazy(() => import("@/pages/Providers"));
const ApiKeysPage = lazy(() => import("@/pages/ApiKeys"));
const AuditLogsPage = lazy(() => import("@/pages/AuditLogs"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const ClustersPage = lazy(() => import("@/pages/Clusters"));
const ClusterDetailPage = lazy(() => import("@/pages/ClusterDetail"));
const GraphExplorerPage = lazy(() => import("@/pages/GraphExplorer"));
const CasesPage = lazy(() => import("@/pages/Cases"));
const CaseDetailPage = lazy(() => import("@/pages/CaseDetail"));
const ReportsPage = lazy(() => import("@/pages/Reports"));

interface AppRoute {
  path: string;
  element: ReactNode;
  permission?: string;
}

export const APP_ROUTES: AppRoute[] = [
  { path: "/", element: <DashboardPage /> },
  { path: "/investigations", element: <InvestigationsPage /> },
  { path: "/investigations/:id", element: <InvestigationDetailPage /> },
  { path: "/assets", element: <AssetsPage /> },
  { path: "/assets/:id", element: <AssetDetailPage /> },
  { path: "/clusters", element: <ClustersPage /> },
  { path: "/clusters/:id", element: <ClusterDetailPage /> },
  { path: "/graph", element: <GraphExplorerPage /> },
  { path: "/cases", element: <CasesPage />, permission: "case:read" },
  { path: "/cases/:id", element: <CaseDetailPage />, permission: "case:read" },
  { path: "/reports", element: <ReportsPage />, permission: "report:export" },
  { path: "/providers", element: <ProvidersPage />, permission: "provider:read" },
  { path: "/api-keys", element: <ApiKeysPage />, permission: "provider:admin" },
  { path: "/audit-logs", element: <AuditLogsPage />, permission: "audit:read" },
  { path: "/settings", element: <SettingsPage /> },
];
registerRoutes(APP_ROUTES.map((r) => r.path));

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <LoadingBlock label="Restoring session…" />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
}

function Guard({ permission, children }: { permission?: string; children: ReactNode }) {
  const { can } = useAuth();
  if (permission && !can(permission)) {
    return <div className="text-muted-foreground py-24 text-center">You do not have permission to view this page ({permission}).</div>;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        {APP_ROUTES.map((r) => (
          <Route
            key={r.path}
            path={r.path}
            element={
              <Suspense fallback={<LoadingBlock />}>
                <Guard permission={r.permission}>{r.element}</Guard>
              </Suspense>
            }
          />
        ))}
        <Route path="*" element={<div className="text-muted-foreground py-24 text-center">Page not found.</div>} />
      </Route>
    </Routes>
  );
}
