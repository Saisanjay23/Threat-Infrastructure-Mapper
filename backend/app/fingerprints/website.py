"""Website fingerprint extraction: title, meta, forms, scripts, tracking IDs, images, structure hashes."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.fingerprints.similarity import normalize_title, shingles, simhash_hex, title_hash, tokens
from app.utils.ioc import registered_domain

MAX_HTML = 2_000_000


@dataclass(frozen=True)
class TrackerPattern:
    family: str  # google_analytics, ga4, gtm, meta_pixel, ...
    asset_type: str  # analytics | pixel | tracking
    regex: re.Pattern[str]
    requires: tuple[str, ...] = ()  # page must contain one of these strings (reduces false positives)
    prefix: str = ""


TRACKERS: list[TrackerPattern] = [
    TrackerPattern("google_analytics", "analytics", re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b")),
    TrackerPattern(
        "ga4",
        "analytics",
        re.compile(r"\b(G-[A-Z0-9]{8,12})\b"),
        requires=("gtag", "googletagmanager", "google-analytics", "ga4"),
    ),
    TrackerPattern("gtm", "tracking", re.compile(r"\b(GTM-[A-Z0-9]{4,9})\b")),
    TrackerPattern(
        "meta_pixel",
        "pixel",
        re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]|facebook\.com/tr\?id=(\d{10,20})"),
    ),
    TrackerPattern(
        "linkedin_insight",
        "pixel",
        re.compile(r"_linkedin_partner_id\s*=\s*['\"]?(\d{3,12})|px\.ads\.linkedin\.com/collect/?\?pid=(\d{3,12})"),
    ),
    TrackerPattern(
        "tiktok_pixel",
        "pixel",
        re.compile(
            r"ttq\.load\(\s*['\"]([A-Z0-9]{15,25})['\"]|analytics\.tiktok\.com/i18n/pixel/events\.js\?sdkid=([A-Z0-9]{15,25})"
        ),
    ),
    TrackerPattern("google_adsense", "tracking", re.compile(r"\b(ca-pub-\d{10,20})\b")),
    TrackerPattern(
        "yandex_metrika",
        "tracking",
        re.compile(r"ym\(\s*(\d{5,10})\s*,\s*['\"]init['\"]|mc\.yandex\.ru/watch/(\d{5,10})"),
    ),
    TrackerPattern("hotjar", "tracking", re.compile(r"hjid\s*:\s*(\d{5,10})")),
    TrackerPattern("ms_clarity", "tracking", re.compile(r"clarity\.ms/tag/([a-z0-9]{8,12})")),
]

CREDENTIAL_INPUT_NAMES = re.compile(r"pass|pwd|pin|otp|card|cvv|cvc|ssn|account|user|login|email|phone", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_TELEGRAM_RE = re.compile(r"api\.telegram\.org/bot[0-9]{6,12}:[A-Za-z0-9_-]{30,}", re.IGNORECASE)
_TELEGRAM_TOKEN_RE = re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b")
_CRYPTO_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})\b"
)
_GENERATOR_HINTS = {
    "wordpress": re.compile(r"wp-content|wp-includes", re.I),
    "jquery": re.compile(r"jquery(?:\.min)?\.js", re.I),
    "react": re.compile(r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js|__NEXT_DATA__|data-reactroot", re.I),
    "bootstrap": re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I),
    "cloudflare": re.compile(r"cdn-cgi/|cf-ray|__cf_bm", re.I),
    "php": re.compile(r"\.php\b", re.I),
}


def _text(tag: Any) -> str:
    return " ".join(tag.get_text(" ").split()) if tag else ""


def extract_trackers(html: str) -> dict[str, list[dict[str, str]]]:
    lowered = html.lower()
    found: dict[str, dict[str, dict[str, str]]] = {}
    for pattern in TRACKERS:
        if pattern.requires and not any(r in lowered for r in pattern.requires):
            continue
        for match in pattern.regex.finditer(html):
            value = next((g for g in match.groups() if g), None) if match.groups() else match.group(0)
            if not value:
                continue
            found.setdefault(pattern.asset_type, {})[value] = {"id": value, "family": pattern.family}
    return {k: sorted(v.values(), key=lambda x: x["id"]) for k, v in found.items()}


def _forms(soup: Any, page_url: str) -> list[dict[str, Any]]:
    page_host = urlsplit(page_url).hostname or ""
    out: list[dict[str, Any]] = []
    for form in soup.find_all("form")[:20]:
        action_raw = (form.get("action") or "").strip()
        action = urljoin(page_url, action_raw) if action_raw and not action_raw.startswith("javascript:") else page_url
        action_host = urlsplit(action).hostname or ""
        inputs = []
        for inp in form.find_all(["input", "select", "textarea"])[:50]:
            itype = (inp.get("type") or inp.name or "text").lower()
            if itype in ("hidden", "submit", "button", "image", "reset"):
                continue
            inputs.append(
                {
                    "type": itype,
                    "name": (inp.get("name") or inp.get("id") or "")[:64],
                    "placeholder": (inp.get("placeholder") or "")[:64],
                }
            )
        has_password = any(i["type"] == "password" for i in inputs)
        has_email = any(
            i["type"] == "email" or re.search(r"mail|user|login", i["name"] + i["placeholder"], re.I) for i in inputs
        )
        sensitive = [
            i for i in inputs if CREDENTIAL_INPUT_NAMES.search(i["name"] + " " + i["placeholder"] + " " + i["type"])
        ]
        out.append(
            {
                "action": action[:500],
                "method": (form.get("method") or "get").lower(),
                "action_host": action_host,
                "external_action": bool(action_host) and registered_domain(action_host) != registered_domain(page_host),
                "inputs": inputs,
                "has_password": has_password,
                "has_email": has_email,
                "sensitive_fields": len(sensitive),
                "submit_text": _text(form.find(["button"]))
                or (form.find("input", {"type": "submit"}) or {}).get("value", ""),
            }
        )
    return out


def _logo_candidates(soup: Any, page_url: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for img in soup.find_all("img", src=True)[:200]:
        src = str(img["src"]).strip()
        if src.startswith("data:") and len(src) > 200_000:
            continue
        blob = " ".join(
            str(x) for x in (src, img.get("alt", ""), " ".join(img.get("class", []) or []), img.get("id", ""))
        )
        if re.search(r"logo|brand|header-img|site-icon", blob, re.I):
            out.append(
                {
                    "src": urljoin(page_url, src) if not src.startswith("data:") else src[:200_000],
                    "alt": str(img.get("alt", ""))[:120],
                }
            )
    for link in soup.find_all("meta", attrs={"property": "og:image"}):
        if link.get("content"):
            out.append({"src": urljoin(page_url, str(link["content"])), "alt": "og:image"})
    unique: dict[str, dict[str, str]] = {}
    for c in out:
        unique.setdefault(c["src"], c)
    return list(unique.values())[:5]


def dom_structure_hash(soup: Any) -> str:
    """SimHash over tag-path shingles: robust to text changes, sensitive to page template/kit."""
    sequence = []
    for tag in soup.find_all(True)[:5000]:
        classes = ".".join(sorted(tag.get("class", []) or [])[:3])
        sequence.append(f"{tag.name}{'.' + classes if classes else ''}")
    return simhash_hex(shingles(sequence, 4))


def extract_website_fingerprints(html: str, page_url: str, *, extra_html: str | None = None) -> dict[str, Any]:
    """Return a JSON-safe fingerprint document. `extra_html` (rendered DOM) is scanned for trackers too."""
    html = (html or "")[:MAX_HTML]
    # bs4 attribute values are str | list; the parsed tree is handled dynamically.
    soup: Any = BeautifulSoup(html, "lxml")
    for tag in soup(["noscript"]):
        tag.unwrap()
    title = " ".join(soup.title.get_text(" ").split())[:500] if soup.title else None
    language = soup.html.get("lang") if soup.html else None

    meta: dict[str, str] = {}
    for m in soup.find_all("meta"):
        key = (m.get("name") or m.get("property") or m.get("http-equiv") or "").lower()
        if (
            key
            and m.get("content")
            and key
            in {
                "description",
                "keywords",
                "generator",
                "author",
                "robots",
                "application-name",
                "og:title",
                "og:site_name",
                "og:description",
                "og:url",
                "og:image",
                "twitter:title",
                "twitter:site",
                "theme-color",
                "refresh",
            }
        ):
            meta[key] = str(m["content"])[:500]

    page_host = urlsplit(page_url).hostname or ""
    base = registered_domain(page_host) if page_host else ""
    script_srcs = [urljoin(page_url, str(s["src"])) for s in soup.find_all("script", src=True)][:200]
    inline_count = len(soup.find_all("script", src=False))
    script_hosts = sorted({urlsplit(s).hostname or "" for s in script_srcs} - {""})
    resource_hosts: set[str] = set(script_hosts)
    for tag_name, attr in (("link", "href"), ("img", "src"), ("iframe", "src"), ("a", "href")):
        for el in soup.find_all(tag_name, attrs={attr: True})[:500]:
            host = urlsplit(urljoin(page_url, str(el[attr]))).hostname
            if host:
                resource_hosts.add(host.lower())
    external_hosts = sorted(h for h in resource_hosts if base and registered_domain(h) != base)[:200]

    # Structure-dependent fingerprints are computed before scripts/styles are stripped for text extraction.
    forms = _forms(soup, page_url)
    logos = _logo_candidates(soup, page_url)
    image_count = len(soup.find_all("img"))
    dom_hash = dom_structure_hash(soup) if html else None

    for tag in soup(["script", "style", "template"]):
        tag.decompose()
    text = _text(soup.body or soup)
    word_tokens = tokens(text)
    combined = f"{html}\n{extra_html or ''}"

    trackers = extract_trackers(combined)
    tracking_ids = sorted({t["id"] for group in trackers.values() for t in group})
    technologies = sorted(name for name, rx in _GENERATOR_HINTS.items() if rx.search(combined))
    if meta.get("generator"):
        technologies.append(meta["generator"][:60])

    normalized_text = " ".join(word_tokens)
    return {
        "title": title,
        "title_normalized": normalize_title(title),
        "title_hash": title_hash(title),
        "meta": meta,
        "language": str(language) if language else None,
        "forms": forms,
        "form_count": len(forms),
        "password_fields": sum(1 for f in forms for i in f["inputs"] if i["type"] == "password"),
        "has_login_form": any(f["has_password"] for f in forms),
        "external_form_actions": sorted({f["action_host"] for f in forms if f["external_action"]}),
        "scripts": {"external": script_srcs[:100], "inline_count": inline_count, "hosts": script_hosts},
        "external_hosts": external_hosts,
        "trackers": trackers,
        "tracking_ids": tracking_ids,
        "logo_candidates": logos,
        "image_count": image_count,
        "technologies": sorted(set(technologies)),
        "emails": sorted(set(_EMAIL_RE.findall(text)))[:20],
        "telegram_exfil": bool(_TELEGRAM_RE.search(combined) or _TELEGRAM_TOKEN_RE.search(combined)),
        "crypto_wallets": sorted(set(_CRYPTO_RE.findall(text)))[:10],
        "word_count": len(word_tokens),
        "text_excerpt": text[:4000],
        "html_sha256": hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest(),
        "text_sha256": hashlib.sha256(normalized_text.encode()).hexdigest() if normalized_text else None,
        "dom_simhash": dom_hash,
        "text_simhash": simhash_hex(shingles(word_tokens, 3)) if word_tokens else None,
    }
