"""PDF analyst report (ReportLab)."""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.graphics.shapes import Circle, Drawing, Line, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reporting.data import ReportData

ACCENT = colors.HexColor("#0891b2")
DARK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
GRID = colors.HexColor("#cbd5e1")
TLP_COLORS = {"CLEAR": "#ffffff", "GREEN": "#33ff00", "AMBER": "#ffc000", "AMBER+STRICT": "#ffc000", "RED": "#ff2b2b"}
TYPE_COLORS = {
    "domain": "#0891b2",
    "url": "#2563eb",
    "ip": "#9333ea",
    "certificate": "#059669",
    "analytics": "#d97706",
    "pixel": "#ea580c",
    "tracking": "#ca8a04",
    "favicon": "#64748b",
    "logo": "#94a3b8",
    "asn": "#525252",
    "hosting": "#57534e",
    "nameserver": "#4b5563",
    "cluster": "#dc2626",
}
LEVEL_COLORS = {
    "Very High": "#dc2626",
    "High": "#ea580c",
    "Medium": "#2563eb",
    "Low": "#64748b",
    "Informational": "#94a3b8",
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, leading=24, textColor=DARK, alignment=TA_LEFT),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontSize=14, textColor=ACCENT, spaceBefore=10, spaceAfter=6
        ),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11, textColor=DARK, spaceBefore=6, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9, leading=12.5),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=7.5, leading=9.5, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base["BodyText"], fontName="Courier", fontSize=7.5, leading=9.5),
        "cell": ParagraphStyle("c", parent=base["BodyText"], fontSize=7.5, leading=9.2),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "—")), style)


def _table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), DARK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        style += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")])]
    t.setStyle(TableStyle(style))
    return t


def _kv(items: list[tuple[str, Any]], st: dict[str, ParagraphStyle], width: float) -> Table:
    rows = [[_p(k, st["small"]), _p(v, st["cell"])] for k, v in items if v not in (None, "", [])]
    if not rows:
        rows = [[_p("—", st["small"]), _p("no data", st["cell"])]]
    return _table(rows, [width * 0.28, width * 0.72], header=False)


def _graph_drawing(graph: dict[str, Any], width: float, height: float) -> Drawing:
    nodes = graph.get("nodes", [])[:400]
    ids = {n["id"] for n in nodes}
    edges = [e for e in graph.get("edges", []) if e["source"] in ids and e["target"] in ids][:1500]
    d = Drawing(width, height)
    if not nodes:
        d.add(String(10, height / 2, "No graph data", fontSize=9, fillColor=MUTED))
        return d
    xs = [n["position"]["x"] for n in nodes]
    ys = [n["position"]["y"] for n in nodes]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    sx = (width - 30) / ((maxx - minx) or 1)
    sy = (height - 30) / ((maxy - miny) or 1)
    pos = {n["id"]: (15 + (n["position"]["x"] - minx) * sx, 15 + (maxy - n["position"]["y"]) * sy) for n in nodes}
    for e in edges:
        x1, y1 = pos[e["source"]]
        x2, y2 = pos[e["target"]]
        d.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.3))
    for n in nodes:
        x, y = pos[n["id"]]
        root = n["data"].get("is_root")
        r = 5 if root else (3.2 if n["type"] in ("domain", "ip") else 2.2)
        d.add(
            Circle(
                x,
                y,
                r,
                fillColor=colors.HexColor(TYPE_COLORS.get(n["type"], "#94a3b8")),
                strokeColor=colors.HexColor("#0f172a") if root else None,
                strokeWidth=0.8,
            )
        )
        if root or (n["type"] == "domain" and (n["data"].get("confidence") or 0) >= 70):
            d.add(String(x + r + 1.5, y - 2, str(n.get("label", ""))[:38], fontSize=5.5, fillColor=DARK))
    return d


def _image(content: bytes, max_w: float, max_h: float) -> Image | None:
    try:
        with PILImage.open(io.BytesIO(content)) as src:
            w, h = src.size
            img = src.crop((0, 0, w, int(w * 0.75))) if h > w * 1.2 else src  # crop very tall captures
            w, h = img.size
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=78)
    except Exception:
        return None
    scale = min(max_w / w, max_h / h)
    buf.seek(0)
    return Image(buf, width=w * scale, height=h * scale)


def render_pdf(data: ReportData) -> bytes:
    st = _styles()
    out = io.BytesIO()
    page_w, page_h = A4
    margin = 16 * mm
    width = page_w - 2 * margin

    def decorate(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFillColor(DARK)
        canvas.rect(0, page_h - 12 * mm, page_w, 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(margin, page_h - 7.5 * mm, "THREAT INFRASTRUCTURE MAPPER")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(page_w - margin - 30 * mm, page_h - 7.5 * mm, data.title[:90])
        tlp = data.tlp
        canvas.setFillColor(colors.black)
        canvas.rect(page_w - margin - 26 * mm, page_h - 10 * mm, 26 * mm, 7 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor(TLP_COLORS.get(tlp, "#ffc000")))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(page_w - margin - 13 * mm, page_h - 7.8 * mm, f"TLP:{tlp}")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(margin, 9 * mm, f"Generated {data.generated_at:%Y-%m-%d %H:%M} UTC by {data.generated_by}")
        canvas.drawRightString(page_w - margin, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        out,
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=data.title,
        author="Threat Infrastructure Mapper",
    )
    story: list[Any] = [
        _p(data.title, st["title"]),
        _p(f"Scope: {data.scope_type} {data.scope_id or ''} · {data.generated_at:%d %B %Y}", st["small"]),
        Spacer(1, 6),
    ]
    sections = set(data.sections)
    s = data.stats

    if "executive_summary" in sections:
        story.append(_p("Executive summary", st["h1"]))
        for line in data.executive_summary:
            story.append(_p(f"• {line}", st["body"]))
        kpis = [
            ["Assets", "Domains", "IPs", "Certificates", "Trackers", "High conf.", "Clusters", "Max imp."],
            [
                s.get("assets", 0),
                s.get("by_type", {}).get("domain", 0),
                s.get("by_type", {}).get("ip", 0),
                s.get("by_type", {}).get("certificate", 0),
                sum(s.get("by_type", {}).get(k, 0) for k in ("analytics", "pixel", "tracking")),
                s.get("high_confidence", 0),
                s.get("clusters", 0),
                s.get("max_impersonation", 0),
            ],
        ]
        story += [Spacer(1, 6), _table(kpis, [width / 8] * 8)]

    if "investigation_details" in sections and (data.investigations or data.case):
        story.append(_p("Investigation details", st["h1"]))
        if data.case:
            c = data.case
            story.append(
                _kv(
                    [
                        ("Case", f"{c['id']} — {c['title']}"),
                        ("Severity", c.get("severity")),
                        ("Status", c.get("status")),
                        ("Assignee", c.get("assignee")),
                        ("Tags", ", ".join(c.get("tags", []))),
                        ("Description", c.get("description")),
                    ],
                    st,
                    width,
                )
            )
            story.append(Spacer(1, 4))
        for inv in data.investigations[:10]:
            stages = ", ".join(f"{k}: {v.get('status')}" for k, v in (inv.get("stages") or {}).items())
            story.append(
                _kv(
                    [
                        ("Investigation", inv["id"]),
                        ("IOC", f"{inv['normalized']} ({inv['ioc_type']})"),
                        ("Status", inv.get("status")),
                        ("Analyst", inv.get("created_by")),
                        ("Started", inv.get("started_at")),
                        ("Finished", inv.get("finished_at")),
                        ("Pipeline", stages),
                        ("Tags", ", ".join(inv.get("tags", []))),
                    ],
                    st,
                    width,
                )
            )
            story.append(Spacer(1, 4))
        if data.root:
            r = data.root
            story.append(_p("Primary asset profile", st["h2"]))
            story.append(
                _kv(
                    [
                        ("Asset", f"{r['value']} ({r['type']})"),
                        ("Status", r.get("status")),
                        ("Final URL", r.get("final_url")),
                        ("Title", r.get("title")),
                        ("IP addresses", ", ".join(r.get("ips") or [])),
                        ("ASN / hosting", f"{r.get('asn') or '—'} / {r.get('hosting') or '—'}"),
                        ("Registrar", r.get("registrar")),
                        ("Registered", r.get("created")),
                        ("Nameservers", ", ".join(r.get("nameservers") or [])),
                        ("Tracking IDs", ", ".join(r.get("tracking_ids") or [])),
                        ("Favicon mmh3", r.get("favicon_mmh3")),
                        ("Certificate SHA-256", r.get("cert_sha256")),
                        ("Impersonation", r.get("impersonation_score")),
                        ("Brand indicators", "; ".join(r.get("brand_indicators") or [])),
                        ("Content verdict", "; ".join(r.get("content_reasons") or [])),
                    ],
                    st,
                    width,
                )
            )

    if "evidence" in sections:
        story.append(_p("Evidence", st["h1"]))
        story.append(
            _p(
                "Why each high-scoring asset is attributed to the operation (feature, points, shared value).",
                st["small"],
            )
        )
        rows = [["Asset", "Score", "Evidence"]]
        for r in [a for a in data.assets if a.get("correlation_matches")][:60]:
            ev = "<br/>".join(
                escape(f"{m['label']}: +{m['weight']} {', '.join(map(str, m.get('values', [])[:2]))}")
                for m in r["correlation_matches"][:6]
            )
            rows.append(
                [_p(r["value"], st["mono"]), _p(r.get("correlation_score"), st["cell"]), Paragraph(ev, st["cell"])]
            )
        if len(rows) > 1:
            story.append(_table(rows, [width * 0.33, width * 0.08, width * 0.59]))
        else:
            story.append(_p("No correlation evidence recorded.", st["body"]))

    if "screenshots" in sections and data.screenshots:
        story.append(PageBreak())
        story.append(_p("Screenshots", st["h1"]))
        cells: list[Any] = []
        for shot in data.screenshots:
            img = _image(shot.content, width / 2 - 8, 70 * mm)
            if img:
                cells.append([img, _p(shot.value, st["mono"])])
        grid = [cells[i : i + 2] + [""] * (2 - len(cells[i : i + 2])) for i in range(0, len(cells), 2)]
        if grid:
            t = Table(grid, colWidths=[width / 2] * 2)
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
            story.append(t)

    if "threat_clusters" in sections and data.clusters:
        story.append(_p("Threat clusters", st["h1"]))
        for c in data.clusters[:20]:
            story.append(_p(f"{c['id']} — {c['name']}", st["h2"]))
            story.append(
                _kv(
                    [
                        ("Confidence", f"{c.get('confidence')} ({c.get('confidence_level')})"),
                        ("Severity", str(c.get("severity")).upper()),
                        ("Members", f"{len(c.get('domains', []))} domains, {len(c.get('ips', []))} IPs"),
                        (
                            "Shared evidence",
                            ", ".join(f"{e['feature']}×{e['members']}" for e in c.get("evidence", [])[:8]),
                        ),
                        ("Tracking IDs", ", ".join(c.get("tracking_ids", [])[:20])),
                        ("Favicons", ", ".join(c.get("favicons", [])[:10])),
                        ("Domains", ", ".join(c.get("domains", [])[:40])),
                    ],
                    st,
                    width,
                )
            )

    if "related_assets" in sections or "confidence_scores" in sections:
        story.append(PageBreak())
        story.append(_p("Related assets & confidence scores", st["h1"]))
        rows = [["Type", "Value", "Status", "Conf.", "Level", "Imp.", "IP / ASN", "Title"]]
        for r in data.assets[:400]:
            level = r.get("confidence_level") or ""
            rows.append(
                [
                    _p(r["type"], st["cell"]),
                    _p(r["value"], st["mono"]),
                    _p(r.get("status"), st["cell"]),
                    _p(r.get("confidence"), st["cell"]),
                    Paragraph(f'<font color="{LEVEL_COLORS.get(level, "#64748b")}">{escape(level)}</font>', st["cell"]),
                    _p(r.get("impersonation_score"), st["cell"]),
                    _p(f"{', '.join((r.get('ips') or [])[:2])} {r.get('asn') or ''}", st["cell"]),
                    _p((r.get("title") or "")[:60], st["cell"]),
                ]
            )
        story.append(_table(rows, [width * x for x in (0.07, 0.27, 0.09, 0.06, 0.1, 0.06, 0.17, 0.18)]))
        if data.fingerprints:
            story.append(_p("Shared fingerprints", st["h2"]))
            fp_rows = [["Type", "Value", "Family"]] + [
                [_p(f["type"], st["cell"]), _p(f["value"], st["mono"]), _p(f.get("family"), st["cell"])]
                for f in data.fingerprints[:200]
                if f["type"]
                in ("certificate", "favicon", "analytics", "pixel", "tracking", "logo", "asn", "nameserver", "hosting")
            ]
            story.append(_table(fp_rows, [width * 0.15, width * 0.65, width * 0.2]))

    if "graph_snapshot" in sections and data.graph:
        story.append(PageBreak())
        story.append(_p("Graph snapshot", st["h1"]))
        gs = data.graph.get("stats", {})
        story.append(
            _p(
                f"{gs.get('nodes')} nodes · {gs.get('edges')} relationships · {gs.get('components')} components. "
                "Large dots are hosts; labelled nodes are the seed and high-confidence domains.",
                st["small"],
            )
        )
        story.append(_graph_drawing(data.graph, width, 150 * mm))
        legend = " ".join(f'<font color="{c}">●</font> {t}' for t, c in TYPE_COLORS.items())
        story.append(Paragraph(legend, st["small"]))

    if "analyst_notes" in sections:
        story.append(_p("Analyst notes", st["h1"]))
        if data.notes:
            for n in data.notes:
                when = n.get("created_at")
                when_s = when.strftime("%Y-%m-%d %H:%M") if isinstance(when, datetime) else str(when or "")
                story.append(_p(f"{n.get('author', 'analyst')} · {when_s} · {n.get('source', '')}", st["small"]))
                story.append(_p(n.get("text", ""), st["body"]))
                story.append(Spacer(1, 4))
        else:
            story.append(_p("No analyst notes.", st["body"]))

    story.append(Spacer(1, 10))
    story.append(
        _p("Scoring model: " + ", ".join(f"{k}={v}" for k, v in data.scoring.get("weights", {}).items()), st["small"])
    )
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return out.getvalue()
