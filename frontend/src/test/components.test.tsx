import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConfidenceBadge, KeyValue, StatusBadge, TypeBadge } from "@/components/common";
import { ResultsTable } from "@/components/ResultsTable";
import { TooltipProvider } from "@/components/ui/misc";
import { AuthProvider } from "@/hooks/useAuth";
import LoginPage from "@/pages/Login";
import type { Asset } from "@/types/api";

function wrap(ui: ReactNode, route = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>
        <AuthProvider>
          <TooltipProvider>{ui}</TooltipProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const assets: Asset[] = [
  { id: "1", type: "domain", value: "contoso-login.test", status: "ACTIVE", confidence: 95, attributes: { web: { title: "Contoso" } }, fingerprints: {}, cluster_ids: ["TIM-CL-1"], sources: ["dns"], tags: [], first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-01T00:00:00Z" },
  { id: "2", type: "ip", value: "192.0.2.7", status: "UNKNOWN", confidence: 20, attributes: {}, fingerprints: {}, cluster_ids: [], sources: ["dns"], tags: [], first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-01T00:00:00Z" },
  { id: "3", type: "domain", value: "parked-contoso.test", status: "PARKED", confidence: 55, attributes: {}, fingerprints: {}, cluster_ids: [], sources: ["crtsh"], tags: ["watch"], first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-01T00:00:00Z" },
];

describe("badges", () => {
  it("renders status, confidence level and type", () => {
    wrap(
      <>
        <StatusBadge status="TAKEDOWN" />
        <ConfidenceBadge score={72} />
        <TypeBadge type="certificate" />
        <StatusBadge status={null} />
      </>,
    );
    expect(screen.getByText("TAKEDOWN")).toBeInTheDocument();
    expect(screen.getByText("72 · High")).toBeInTheDocument();
    expect(screen.getByText("certificate")).toBeInTheDocument();
  });

  it("renders key/value lists with placeholders", () => {
    wrap(<KeyValue items={[["Registrar", "Example"], ["Created", null]]} />);
    expect(screen.getByText("Registrar")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});

describe("ResultsTable", () => {
  beforeEach(() => localStorage.clear());

  it("sorts by confidence, searches and supports row selection", async () => {
    const user = userEvent.setup();
    wrap(<ResultsTable data={assets} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("contoso-login.test")).toBeInTheDocument(); // default sort: confidence desc
    expect(within(rows[2]).getAllByText("192.0.2.7").length).toBeGreaterThan(0); // value + IP column

    await user.type(screen.getByLabelText("Search results"), "parked");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByText("parked-contoso.test")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Search results"));

    await user.click(screen.getAllByLabelText("Select row")[0]);
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    await user.click(screen.getByLabelText("Select all"));
    expect(screen.getByText("3 selected")).toBeInTheDocument();
    expect(screen.getByText("3 result(s)")).toBeInTheDocument();
  });

  it("shows an empty state", () => {
    wrap(<ResultsTable data={[]} />);
    expect(screen.getByText("No results")).toBeInTheDocument();
  });
});

describe("LoginPage", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  it("shows the API error for bad credentials", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ detail: "Invalid username or password" }), { status: 401, headers: { "content-type": "application/json" } }));
    const user = userEvent.setup();
    wrap(<LoginPage />, "/login");
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({ method: "POST" }));
  });

  it("stores the token after a successful login", async () => {
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    fetchMock
      .mockResolvedValueOnce(json({ access_token: "tok123", token_type: "bearer", expires_in: 3600, user: {} }))
      .mockResolvedValueOnce(json({ id: "u1", username: "admin", role: "admin", permissions: [] }));
    const user = userEvent.setup();
    wrap(<LoginPage />, "/login");
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "secret");
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(localStorage.getItem("tim.token")).toBe("tok123"));
    expect(fetchMock.mock.calls[1][1].headers.Authorization).toBe("Bearer tok123");
  });
});
