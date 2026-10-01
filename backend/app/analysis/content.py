"""Content Validation Engine.

HTTP status alone is unreliable (soft-404s, parked pages returning 200, takedown banners). The engine
scores textual, structural, DNS and registry signals and classifies a site as:
ACTIVE | INACTIVE | PARKED | TAKEDOWN | ERROR.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.models.common import SiteStatus

# (pattern, weight) - weights are summed per category; the strongest category wins.
TAKEDOWN_PATTERNS: list[tuple[str, int]] = [
    (r"this (?:domain|website|site) has been seized", 100),
    (r"domain (?:name )?(?:has been )?seized", 90),
    (r"seized by (?:the )?(?:federal bureau|fbi|europol|national crime agency|law enforcement)", 100),
    (r"this (?:account|website|site|page) (?:has been|is) (?:suspended|disabled|terminated|deactivated)", 80),
    (r"account (?:has been )?suspended", 60),
    (r"website (?:is )?(?:suspended|disabled|blocked)", 60),
    (r"(?:has been|was) (?:removed|taken down) (?:for|due to) (?:violat|abuse|phishing|fraud)", 90),
    (r"phishing (?:site|page|content) (?:has been )?(?:removed|blocked|disabled)", 90),
    (r"suspected phishing", 40),
    (r"violat(?:ed|ion of) (?:our|the) (?:terms|acceptable use|tos)", 50),
    (r"site (?:has been )?(?:removed|disabled) by (?:the )?(?:host|administrator|owner)", 60),
    (r"this site can.?t be reached due to (?:abuse|a policy)", 50),
    (r"the requested (?:site|page) has been (?:disabled|deleted)", 50),
    (r"\bclienthold\b|\bserverhold\b", 70),
]
PARKED_PATTERNS: list[tuple[str, int]] = [
    (r"(?:this|the) domain (?:name )?(?:is|may be) for sale", 90),
    (r"buy this domain", 80),
    (r"domain (?:is )?parked", 80),
    (r"parked (?:free|domain|by|courtesy)", 70),
    (r"this domain (?:name )?(?:has been )?registered (?:at|by|with)", 40),
    (r"related (?:searches|links)", 30),
    (r"make an offer on this domain", 80),
    (
        r"\b(?:sedo|sedoparking|bodis|parkingcrew|above\.com|afternic|dan\.com|hugedomains|undeveloped|parklogic|"
        r"domainmarket|namebright|uniregistry|godaddy\.com/domainsearch|smartname)\b",
        50,
    ),
    (r"coming soon", 20),
    (r"under construction", 25),
    (r"future home of", 50),
    (r"website is (?:currently )?under maintenance", 15),
]
INACTIVE_PATTERNS: list[tuple[str, int]] = [
    (r"\b404\b.{0,40}not found|not found.{0,40}\b404\b", 70),
    (r"page (?:not found|does not exist|cannot be found)", 60),
    (r"the requested url was not found", 70),
    (r"no such (?:site|app|bucket)", 70),
    (r"there is no (?:app|site) configured at that hostname", 80),
    (r"(?:repository|site) not found", 50),
    (r"\bdomain (?:has )?expired\b", 70),
    (r"this domain is not (?:configured|connected)", 70),
    (
        r"welcome to nginx!|it works!|apache2 (?:ubuntu|debian) default page|iis windows server|"
        r"test page for the (?:nginx|apache)",
        60,
    ),
    (r"default (?:web )?page", 30),
    (r"index of /", 20),
]
PARKING_NAMESERVERS = re.compile(
    r"(?:sedoparking|parkingcrew|bodis|above\.com|parklogic|dan\.com|afternic|hugedomains|cashparking|"
    r"domaincontrol\.com\.parked|parking|undeveloped|ztomy|park\.)",
    re.IGNORECASE,
)
MARKUP_TAKEDOWN = re.compile(r"cgi-sys/suspendedpage|/suspended\.page|account-suspended", re.IGNORECASE)
MARKUP_PARKING = re.compile(
    r"(?:sedoparking\.com|parkingcrew\.net|bodis\.com|park\.above\.com|afternic\.com|dan\.com/|hugedomains\.com|"
    r"parklogic\.com|img\.sedoparking|domainmarket\.com|cashparking)",
    re.IGNORECASE,
)
SUSPENSION_STATUSES = {"clienthold", "serverhold", "client hold", "server hold", "redemptionperiod", "pendingdelete"}


@dataclass
class ContentVerdict:
    status: SiteStatus
    confidence: int
    reasons: list[str] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "scores": self.scores,
        }


def _score(text: str, patterns: list[tuple[str, int]]) -> tuple[int, list[str]]:
    total = 0
    hits: list[str] = []
    for pattern, weight in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            total += weight
            hits.append(m.group(0)[:80])
    return total, hits


def classify_content(
    *,
    status_code: int | None,
    html: str | None,
    text: str | None = None,
    title: str | None = None,
    fetch_error: str | None = None,
    dns_resolves: bool | None = None,
    nameservers: list[str] | None = None,
    registry_status: list[str] | None = None,
    word_count: int | None = None,
    has_login_form: bool = False,
) -> ContentVerdict:
    reasons: list[str] = []
    registry = {s.lower().replace(" ", "") for s in registry_status or []}
    held = registry & {s.replace(" ", "") for s in SUSPENSION_STATUSES}
    if held:
        return ContentVerdict(SiteStatus.TAKEDOWN, 90, [f"registry status {', '.join(sorted(held))}"])

    if dns_resolves is False:
        return ContentVerdict(SiteStatus.INACTIVE, 85, ["domain does not resolve (NXDOMAIN / no A records)"])

    parking_ns = [ns for ns in nameservers or [] if PARKING_NAMESERVERS.search(ns)]

    if fetch_error and status_code is None:
        lowered = fetch_error.lower()
        if parking_ns:
            return ContentVerdict(SiteStatus.PARKED, 70, [f"parking nameserver {parking_ns[0]}", "no web response"])
        if any(
            k in lowered
            for k in (
                "refused",
                "timed out",
                "timeout",
                "could not resolve",
                "resolution failed",
                "no route",
                "unreachable",
            )
        ):
            return ContentVerdict(SiteStatus.INACTIVE, 70, [f"no web service: {fetch_error[:120]}"])
        return ContentVerdict(SiteStatus.ERROR, 60, [f"collection error: {fetch_error[:120]}"])

    # Visible text drives classification; raw markup is only checked for infrastructure tell-tales
    # (suspension pages, parking-provider scripts) so that strings inside JS bundles do not mislead.
    blob = " ".join(x for x in (title or "", text or "") if x)
    if not blob and html:
        blob = re.sub(r"<[^>]+>", " ", html[:200_000])
    takedown, t_hits = _score(blob, TAKEDOWN_PATTERNS)
    parked, p_hits = _score(blob, PARKED_PATTERNS)
    inactive, i_hits = _score(blob, INACTIVE_PATTERNS)
    markup = (html or "")[:100_000]
    m = MARKUP_TAKEDOWN.search(markup)
    if m:
        takedown += 90
        t_hits.append(m.group(0)[:80])
    m = MARKUP_PARKING.search(markup)
    if m:
        parked += 60
        p_hits.append(f"parking provider markup: {m.group(0)[:60]}")
    if parking_ns:
        parked += 60
        p_hits.append(f"parking nameserver {parking_ns[0]}")
    if status_code in (404, 410):
        inactive += 70
        i_hits.append(f"HTTP {status_code}")
    elif status_code in (451,):
        takedown += 80
        t_hits.append("HTTP 451 unavailable for legal reasons")
    elif status_code in (402, 403) and takedown:
        takedown += 20
    elif status_code is not None and status_code >= 500:
        inactive += 30
        i_hits.append(f"HTTP {status_code}")

    words = word_count if word_count is not None else len((text or "").split())
    if status_code and 200 <= status_code < 300 and words < 8 and not has_login_form and not html:
        inactive += 40
        i_hits.append("empty response body")

    # A live credential form is strong evidence the page is operational regardless of noise words.
    if has_login_form:
        parked = max(0, parked - 60)
        inactive = max(0, inactive - 50)

    scores = {"takedown": takedown, "parked": parked, "inactive": inactive}
    best = max(scores, key=lambda k: scores[k])
    if scores[best] >= 50:
        status = {"takedown": SiteStatus.TAKEDOWN, "parked": SiteStatus.PARKED, "inactive": SiteStatus.INACTIVE}[best]
        hits = {"takedown": t_hits, "parked": p_hits, "inactive": i_hits}[best]
        reasons.extend(hits[:6])
        return ContentVerdict(status, min(99, 40 + scores[best] // 2), reasons, scores)

    if status_code is not None and status_code >= 500:
        return ContentVerdict(SiteStatus.ERROR, 60, [f"HTTP {status_code}"], scores)
    if status_code is not None and 200 <= status_code < 400:
        reasons.append(f"HTTP {status_code} with {words} words of content")
        if has_login_form:
            reasons.append("live credential form")
        return ContentVerdict(SiteStatus.ACTIVE, 70 if words > 30 or has_login_form else 55, reasons, scores)
    if status_code in (401, 403):
        return ContentVerdict(SiteStatus.ACTIVE, 45, [f"HTTP {status_code} (access restricted, service up)"], scores)
    return ContentVerdict(SiteStatus.ERROR, 40, [f"unclassified response (HTTP {status_code})"], scores)
