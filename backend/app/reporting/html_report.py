"""Self-contained HTML report (print-to-PDF friendly)."""

from __future__ import annotations

import base64
from datetime import datetime
from html import escape
from typing import Any

from app.reporting.data import ReportData
from app.reporting.pdf import LEVEL_COLORS, TLP_COLORS, TYPE_COLORS

CSS = """
*{box-sizing:border-box}body{font-family:Segoe UI,Inter,system-ui,sans-serif;color:#0f172a;margin:0;background:#f8fafc}
header{background:#0f172a;color:#fff;padding:18px 32px;display:flex;justify-content:space-between;align-items:center}
header .tlp{background:#000;padding:4px 10px;border-radius:4px;font-weight:700}
main{max-width:1100px;margin:0 auto;padding:24px 32px}h1{font-size:24px;margin:0 0 4px}
h2{color:#0891b2;border-bottom:2px solid #e2e8f0;padding-bottom:4px;margin-top:32px}h3{margin:18px 0 6px}
.muted{color:#64748b;font-size:12px}table{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0}
th{background:#0f172a;color:#fff;text-align:left;padding:6px}td{border-bottom:1px solid #e2e8f0;padding:5px 6px;vertical-align:top}
tr:nth-child(even) td{background:#f1f5f9}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.kpi{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:10px}.kpi b{font-size:22px;display:block}
.mono{font-family:Consolas,monospace;font-size:11px;word-break:break-all}.shots{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.shots figure{margin:0;background:#fff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden}
.shots img{width:100%;display:block;max-height:340px;object-fit:cover;object-position:top}
.shots figcaption{padding:6px 8px;font-family:Consolas,monospace;font-size:11px}.pill{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;color:#fff}
.note{background:#fff;border-left:3px solid #0891b2;padding:8px 12px;margin:8px 0;white-space:pre-wrap}
@media print{header{-webkit-print-color-adjust:exact;print-color-adjust:exact}h2{break-before:auto}.shots figure{break-inside:avoid}}
"""


def _e(value: Any) -> str:
    if value is None or value == "" or value == []:
        return '<span class="muted">—</span>'
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    if isinstance(value, datetime):
        value = value.strftime("%Y-%m-%d %H:%M")
    return escape(str(value))


def _kv(items: list[tuple[str, Any]]) -> str:
    rows = "".join(f"<tr><td style='width:28%' class='muted'>{escape(k)}</td><td>{_e(v)}</td></tr>" for k, v in items)
    return f"<table>{rows}</table>"


def _graph_svg(graph: dict[str, Any], width: int = 1000, height: int = 620) -> str:
    nodes = graph.get("nodes", [])[:400]
    if not nodes:
        return "<p class='muted'>No graph data.</p>"
    ids = {n["id"] for n in nodes}
    xs = [n["position"]["x"] for n in nodes]
    ys = [n["position"]["y"] for n in nodes]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    sx = (width - 40) / ((maxx - minx) or 1)
    sy = (height - 40) / ((maxy - miny) or 1)
    pos = {n["id"]: (20 + (n["position"]["x"] - minx) * sx, 20 + (n["position"]["y"] - miny) * sy) for n in nodes}
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px">'
    ]
    for e in graph.get("edges", [])[:2000]:
        if e["source"] in ids and e["target"] in ids:
            (x1, y1), (x2, y2) = pos[e["source"]], pos[e["target"]]
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#cbd5e1" stroke-width="0.6"/>'
            )
    for n in nodes:
        x, y = pos[n["id"]]
        root = n["data"].get("is_root")
        r = 7 if root else (4.5 if n["type"] in ("domain", "ip") else 3)
        color = TYPE_COLORS.get(n["type"], "#94a3b8")
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}"'
            f"{' stroke="#0f172a" stroke-width="1.5"' if root else ''}><title>{escape(n['type'])}: {escape(str(n.get('value')))}</title></circle>"
        )
        if root or (n["type"] == "domain" and (n["data"].get("confidence") or 0) >= 70):
            parts.append(
                f'<text x="{x + r + 2:.1f}" y="{y + 3:.1f}" font-size="9" fill="#0f172a">{escape(str(n.get("label"))[:40])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_html(data: ReportData) -> bytes:
    s = data.stats
    sections = set(data.sections)
    bt = s.get("by_type", {})
    out: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">",
        f"<title>{escape(data.title)}</title><style>{CSS}</style></head><body>",
        f"<header><div><b>THREAT INFRASTRUCTURE MAPPER</b><div class='muted' style='color:#94a3b8'>{escape(data.title)}</div></div>"
        f"<span class='tlp' style='color:{TLP_COLORS.get(data.tlp, '#ffc000')}'>TLP:{escape(data.tlp)}</span></header><main>",
        f"<h1>{escape(data.title)}</h1><div class='muted'>Scope {escape(data.scope_type)} {escape(data.scope_id or '')} · "
        f"generated {data.generated_at:%Y-%m-%d %H:%M} UTC by {escape(data.generated_by)}</div>",
    ]
    if "executive_summary" in sections:
        out.append(
            "<h2>Executive summary</h2><ul>"
            + "".join(f"<li>{escape(x)}</li>" for x in data.executive_summary)
            + "</ul>"
        )
        kpis = [
            ("Assets", s.get("assets", 0)),
            ("Domains", bt.get("domain", 0)),
            ("IP addresses", bt.get("ip", 0)),
            ("Certificates", bt.get("certificate", 0)),
            ("Tracking IDs", sum(bt.get(k, 0) for k in ("analytics", "pixel", "tracking"))),
            ("High confidence", s.get("high_confidence", 0)),
            ("Clusters", s.get("clusters", 0)),
            ("Max impersonation", s.get("max_impersonation", 0)),
        ]
        out.append(
            "<div class='kpis'>"
            + "".join(f"<div class='kpi'><span class='muted'>{k}</span><b>{v}</b></div>" for k, v in kpis)
            + "</div>"
        )
    if "investigation_details" in sections:
        out.append("<h2>Investigation details</h2>")
        if data.case:
            c = data.case
            out.append(
                _kv(
                    [
                        ("Case", f"{c['id']} — {c['title']}"),
                        ("Severity", c.get("severity")),
                        ("Status", c.get("status")),
                        ("Assignee", c.get("assignee")),
                        ("Tags", c.get("tags")),
                        ("Description", c.get("description")),
                    ]
                )
            )
        for inv in data.investigations[:10]:
            out.append(
                _kv(
                    [
                        ("Investigation", inv["id"]),
                        ("IOC", f"{inv['normalized']} ({inv['ioc_type']})"),
                        ("Status", inv.get("status")),
                        ("Analyst", inv.get("created_by")),
                        ("Started", inv.get("started_at")),
                        ("Finished", inv.get("finished_at")),
                    ]
                )
            )
        if data.root:
            r = data.root
            out.append(
                "<h3>Primary asset</h3>"
                + _kv(
                    [
                        ("Asset", r["value"]),
                        ("Status", r.get("status")),
                        ("Final URL", r.get("final_url")),
                        ("Title", r.get("title")),
                        ("IP addresses", r.get("ips")),
                        ("ASN", r.get("asn")),
                        ("Hosting", r.get("hosting")),
                        ("Registrar", r.get("registrar")),
                        ("Nameservers", r.get("nameservers")),
                        ("Tracking IDs", r.get("tracking_ids")),
                        ("Favicon mmh3", r.get("favicon_mmh3")),
                        ("Certificate SHA-256", r.get("cert_sha256")),
                        ("Impersonation", r.get("impersonation_score")),
                        ("Brand indicators", r.get("brand_indicators")),
                        ("Content verdict", r.get("content_reasons")),
                    ]
                )
            )
    if "evidence" in sections:
        rows = "".join(
            f"<tr><td class='mono'>{escape(a['value'])}</td><td>{_e(a.get('correlation_score'))}</td><td>"
            + "<br>".join(
                escape(f"{m['label']}: +{m['weight']} {', '.join(map(str, m.get('values', [])[:2]))}")
                for m in a["correlation_matches"][:6]
            )
            + "</td></tr>"
            for a in data.assets
            if a.get("correlation_matches")
        )
        out.append("<h2>Evidence</h2><table><tr><th>Asset</th><th>Score</th><th>Evidence</th></tr>" + rows + "</table>")
    if "screenshots" in sections and data.screenshots:
        figs = "".join(
            f"<figure><img alt='' src='data:{escape(sh.content_type)};base64,{base64.b64encode(sh.content).decode()}'>"
            f"<figcaption>{escape(sh.value)}</figcaption></figure>"
            for sh in data.screenshots
        )
        out.append(f"<h2>Screenshots</h2><div class='shots'>{figs}</div>")
    if "threat_clusters" in sections and data.clusters:
        out.append("<h2>Threat clusters</h2>")
        for c in data.clusters[:20]:
            out.append(
                f"<h3>{escape(c['id'])} — {escape(c['name'])}</h3>"
                + _kv(
                    [
                        ("Confidence", f"{c.get('confidence')} ({c.get('confidence_level')})"),
                        ("Severity", str(c.get("severity")).upper()),
                        ("Evidence", ", ".join(f"{e['feature']}×{e['members']}" for e in c.get("evidence", []))),
                        ("Domains", c.get("domains", [])[:60]),
                        ("IPs", c.get("ips", [])[:40]),
                        ("Tracking IDs", c.get("tracking_ids", [])),
                        ("Favicons", c.get("favicons", [])),
                    ]
                )
            )
    if "related_assets" in sections or "confidence_scores" in sections:
        rows = "".join(
            f"<tr><td>{escape(a['type'])}</td><td class='mono'>{escape(a['value'])}</td><td>{_e(a.get('status'))}</td>"
            f"<td>{_e(a.get('confidence'))}</td><td><span class='pill' style='background:{LEVEL_COLORS.get(a.get('confidence_level') or '', '#94a3b8')}'>"
            f"{_e(a.get('confidence_level'))}</span></td><td>{_e(a.get('impersonation_score'))}</td>"
            f"<td class='mono'>{_e((a.get('ips') or [])[:2])}</td><td>{_e(a.get('asn'))}</td><td>{_e(a.get('title'))}</td></tr>"
            for a in data.assets
        )
        out.append(
            "<h2>Related assets & confidence scores</h2><table><tr><th>Type</th><th>Value</th><th>Status</th>"
            "<th>Conf.</th><th>Level</th><th>Imp.</th><th>IPs</th><th>ASN</th><th>Title</th></tr>" + rows + "</table>"
        )
    if "graph_snapshot" in sections and data.graph:
        legend = " ".join(f"<span style='color:{c}'>●</span> {t}" for t, c in TYPE_COLORS.items())
        out.append(f"<h2>Graph snapshot</h2>{_graph_svg(data.graph)}<div class='muted'>{legend}</div>")
    if "analyst_notes" in sections:
        notes = "".join(
            f"<div class='note'><div class='muted'>{_e(n.get('author'))} · {_e(n.get('created_at'))} · "
            f"{_e(n.get('source'))}</div>{escape(str(n.get('text', '')))}</div>"
            for n in data.notes
        )
        out.append("<h2>Analyst notes</h2>" + (notes or "<p class='muted'>No analyst notes.</p>"))
    out.append("</main></body></html>")
    return "".join(out).encode("utf-8")
