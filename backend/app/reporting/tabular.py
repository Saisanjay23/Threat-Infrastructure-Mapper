"""CSV and JSON renderers."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from app.reporting.data import ReportData

CSV_COLUMNS = [
    "type",
    "value",
    "status",
    "confidence",
    "confidence_level",
    "impersonation_score",
    "brand_similarity_score",
    "title",
    "final_url",
    "http_status",
    "ips",
    "asn",
    "hosting",
    "registrar",
    "created",
    "nameservers",
    "tracking_ids",
    "favicon_mmh3",
    "cert_sha256",
    "correlation_score",
    "correlation_evidence",
    "cluster_ids",
    "sources",
    "tags",
    "first_seen",
    "last_seen",
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    elif isinstance(value, datetime):
        value = value.isoformat()
    text = str(value)
    # Neutralise CSV/spreadsheet formula injection: collected values are attacker controlled.
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def render_csv(data: ReportData) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for row in data.assets:
        evidence = "; ".join(f"{m['feature']}+{m['weight']}" for m in row.get("correlation_matches", []))
        writer.writerow([_cell(row.get(c) if c != "correlation_evidence" else evidence) for c in CSV_COLUMNS])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so Excel detects UTF-8


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return None
    return str(value)


def render_json(data: ReportData) -> bytes:
    return json.dumps(data.to_json(), default=_default, indent=2, ensure_ascii=False).encode("utf-8")
