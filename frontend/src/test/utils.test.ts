import { describe, expect, it } from "vitest";
import { buildQuery } from "@/lib/api";
import { confidenceLevel, formatDate, timeAgo, truncate } from "@/lib/utils";
import { assetAsn, assetDomain, assetIp, assetTitle, assetUrl, toCsv } from "@/components/ResultsTable";
import type { Asset } from "@/types/api";

function asset(partial: Partial<Asset>): Asset {
  return {
    id: "a1",
    type: "domain",
    value: "example.test",
    status: "ACTIVE",
    attributes: {},
    fingerprints: {},
    cluster_ids: [],
    sources: [],
    tags: [],
    first_seen: "2026-10-01T00:00:00Z",
    last_seen: "2026-10-01T00:00:00Z",
    ...partial,
  };
}

describe("utils", () => {
  it("maps scores to confidence levels using the spec thresholds", () => {
    expect([95, 90, 75, 70, 55, 50, 35, 30, 10].map(confidenceLevel)).toEqual([
      "Very High", "Very High", "High", "High", "Medium", "Medium", "Low", "Low", "Informational",
    ]);
    expect(confidenceLevel(null)).toBe("—");
  });

  it("truncates long values with an ellipsis", () => {
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("abc", 4)).toBe("abc");
  });

  it("formats dates and relative times defensively", () => {
    expect(formatDate(null)).toBe("—");
    expect(formatDate("not a date")).toBe("not a date");
    expect(timeAgo(new Date(Date.now() - 90_000).toISOString())).toBe("1m ago");
    expect(timeAgo(new Date(Date.now() - 3 * 86_400_000).toISOString())).toBe("3d ago");
  });

  it("builds query strings, skipping empty values and repeating arrays", () => {
    expect(buildQuery({ a: 1, b: "", c: undefined, d: null, type: ["domain", "ip"], ok: true })).toBe("?a=1&type=domain&type=ip&ok=true");
    expect(buildQuery({})).toBe("");
  });
});

describe("asset accessors", () => {
  it("derives display fields from attributes and fingerprints", () => {
    const a = asset({
      attributes: { web: { title: "Login", ip: "192.0.2.1", final_url: "https://example.test/x" }, infrastructure: { asns: ["AS64500"] } },
    });
    expect(assetTitle(a)).toBe("Login");
    expect(assetIp(a)).toBe("192.0.2.1");
    expect(assetAsn(a)).toBe("AS64500");
    expect(assetUrl(a)).toBe("https://example.test/x");
    expect(assetDomain(a)).toBe("example.test");
    expect(assetDomain(asset({ type: "url", value: "https://sub.example.test/p" }))).toBe("sub.example.test");
    expect(assetIp(asset({ type: "ip", value: "198.51.100.5" }))).toBe("198.51.100.5");
  });
});

describe("CSV export", () => {
  it("neutralises spreadsheet formula injection and quotes separators", () => {
    const csv = toCsv([
      asset({ value: "=HYPERLINK(\"http://evil\")", tags: ["a,b"] }),
      asset({ value: "+cmd", attributes: { web: { title: 'say "hi"' } } }),
    ]);
    const lines = csv.split("\n");
    expect(lines[0].startsWith("type,value,status")).toBe(true);
    expect(lines[1]).toContain(`"'=HYPERLINK(""http://evil"")"`);
    expect(lines[1]).toContain('"a,b"');
    expect(lines[2]).toContain("'+cmd");
    expect(lines[2]).toContain('"say ""hi"""');
  });
});
