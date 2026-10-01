"""Brand Impersonation Engine.

Produces two scores:
* brand_similarity_score (0-100): how strongly the asset resembles the brand (domain, content, logo).
* impersonation_score  (0-100): likelihood the asset impersonates the brand to harvest credentials.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import tldextract

from app.fingerprints.images import hash_similarity
from app.fingerprints.similarity import string_similarity

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

PRIMARY_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "authenticate",
    "support",
    "account",
    "secure",
    "portal",
    "update",
    "reset",
]
SECONDARY_KEYWORDS = [
    "sign-in",
    "log-in",
    "verification",
    "auth",
    "security",
    "password",
    "banking",
    "wallet",
    "confirm",
    "unlock",
    "recover",
    "billing",
    "invoice",
    "payment",
    "webmail",
    "sso",
    "2fa",
    "otp",
    "helpdesk",
    "service",
    "online",
    "customer",
    "access",
    "validate",
    "restore",
    "suspend",
]
CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ԁ": "d",
    "ɡ": "g",
    "ӏ": "l",
    "ѕ": "s",
    "ԛ": "q",
    "ԝ": "w",
    "ν": "v",
    "ο": "o",
    "α": "a",
    "ı": "i",
    "ł": "l",
    "ø": "o",
}
LEET = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("4", "a"),
    ("5", "s"),
    ("7", "t"),
    ("8", "b"),
    ("9", "g"),
    ("@", "a"),
    ("$", "s"),
]
_GENERIC_TOKENS = {
    "the",
    "and",
    "inc",
    "ltd",
    "llc",
    "corp",
    "group",
    "online",
    "official",
    "home",
    "welcome",
    "login",
    "sign",
    "secure",
    "page",
    "account",
    "services",
    "service",
    "www",
    "com",
    "net",
    "org",
}


def skeleton(label: str) -> str:
    """Reduce a domain label to a confusable-insensitive skeleton."""
    try:
        if label.startswith("xn--"):
            label = label.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    label = "".join(CONFUSABLES.get(ch, ch) for ch in label.lower())
    label = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode("ascii")
    for src, dst in LEET:
        label = label.replace(src, dst)
    return re.sub(r"[^a-z]", "", label)


def brand_tokens(brand: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", brand.lower()) if len(t) >= 3 and t not in _GENERIC_TOKENS]


def infer_brand(fp: dict[str, Any]) -> str | None:
    meta = fp.get("meta") or {}
    for key in ("og:site_name", "application-name", "twitter:site"):
        if meta.get(key):
            return str(meta[key]).lstrip("@").strip()[:64]
    title = fp.get("title") or ""
    for sep in (" | ", " - ", " – ", " — ", " :: ", ": "):
        if sep in title:
            parts = [p.strip() for p in title.split(sep) if p.strip()]
            candidates = [p for p in parts if not any(k in p.lower() for k in PRIMARY_KEYWORDS + SECONDARY_KEYWORDS)]
            if candidates:
                return min(candidates, key=len)[:64]
    return None


@dataclass
class BrandAssessment:
    brand: str | None
    brand_inferred: bool
    legitimate: bool
    brand_similarity_score: int
    impersonation_score: int
    signals: dict[str, Any] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "brand": self.brand,
            "brand_inferred": self.brand_inferred,
            "legitimate": self.legitimate,
            "brand_similarity_score": self.brand_similarity_score,
            "impersonation_score": self.impersonation_score,
            "signals": self.signals,
            "indicators": self.indicators,
        }


def assess_brand(
    host: str,
    fp: dict[str, Any] | None,
    *,
    brand: str | None = None,
    brand_domains: list[str] | None = None,
    brand_logo_hashes: list[str] | None = None,
    page_logo_hashes: list[str] | None = None,
    site_active: bool = True,
) -> BrandAssessment:
    fp = fp or {}
    indicators: list[str] = []
    signals: dict[str, Any] = {}
    inferred = False
    if not brand:
        brand = infer_brand(fp)
        inferred = brand is not None
    tokens = brand_tokens(brand) if brand else []
    primary = max(tokens, key=len) if tokens else None

    ext = _EXTRACT(host)
    registered = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else host.lower()
    labels = [lbl for lbl in (ext.subdomain.split(".") if ext.subdomain else []) + [ext.domain] if lbl]
    host_compact = "".join(labels).replace("-", "").lower()
    host_skeleton = "".join(skeleton(lbl) for lbl in labels)
    legit_registered = {(_EXTRACT(d).domain + "." + _EXTRACT(d).suffix).lower() for d in brand_domains or [] if d}
    legitimate = registered in legit_registered
    signals["legitimate_domain"] = legitimate

    # ------------------------------------------------------------------ domain component (0-40)
    domain_score = 0.0
    if primary:
        if primary in host_compact:
            domain_score = 40
            indicators.append(f"brand '{primary}' appears in domain")
            signals["brand_in_domain"] = True
        elif primary in host_skeleton:
            domain_score = 40
            indicators.append(f"homoglyph/leet spelling of '{primary}' in domain")
            signals["homoglyph"] = True
        else:
            best = max((string_similarity(skeleton(lbl), primary) for lbl in labels), default=0.0)
            for legit in legit_registered:
                best = max(best, string_similarity(skeleton(ext.domain), skeleton(_EXTRACT(legit).domain)))
            signals["domain_similarity"] = round(best, 3)
            if best >= 0.75:
                domain_score = 30 * best
                indicators.append(f"typosquat-like domain (similarity {best:.2f} to brand)")
                signals["typosquat"] = True

    domain_keywords = sorted({k for k in PRIMARY_KEYWORDS + SECONDARY_KEYWORDS if k in host.lower()})
    signals["domain_keywords"] = domain_keywords
    if domain_keywords:
        indicators.append(f"domain keywords: {', '.join(domain_keywords[:6])}")

    # ------------------------------------------------------------------ content component (0-35)
    title = (fp.get("title") or "").lower()
    text = (fp.get("text_excerpt") or "").lower()
    meta_blob = " ".join(str(v) for v in (fp.get("meta") or {}).values()).lower()
    content_score = 0.0
    if primary:
        in_title = primary in title
        mentions = text.count(primary) + meta_blob.count(primary)
        signals["brand_in_title"] = in_title
        signals["brand_mentions"] = mentions
        if in_title:
            content_score += 20
            indicators.append("brand name in page title")
        content_score += min(15, 3 * mentions)
    page_keywords = sorted({k for k in PRIMARY_KEYWORDS if k in title or k in text})
    signals["page_keywords"] = page_keywords

    # ------------------------------------------------------------------ logo component (0-25)
    logo_similarity = 0.0
    for a in brand_logo_hashes or []:
        for b in page_logo_hashes or []:
            logo_similarity = max(logo_similarity, hash_similarity(a, b))
    signals["logo_similarity"] = round(logo_similarity, 3)
    logo_score = max(0.0, (logo_similarity - 0.7) / 0.3) * 25 if logo_similarity > 0.7 else 0.0
    if logo_similarity >= 0.85:
        indicators.append(f"logo matches brand reference (similarity {logo_similarity:.2f})")

    brand_similarity = int(round(min(100.0, domain_score + content_score + logo_score)))

    # ------------------------------------------------------------------ credential harvesting signals
    forms = fp.get("forms") or []
    login_form = bool(fp.get("has_login_form"))
    password_fields = int(fp.get("password_fields") or 0)
    sensitive = sum(int(f.get("sensitive_fields") or 0) for f in forms)
    external_actions = fp.get("external_form_actions") or []
    signals.update(
        {
            "login_form": login_form,
            "password_fields": password_fields,
            "sensitive_fields": sensitive,
            "external_form_actions": external_actions,
            "telegram_exfil": bool(fp.get("telegram_exfil")),
            "credential_collection": login_form or sensitive >= 2,
        }
    )
    harvesting = 0.0
    if login_form:
        harvesting += 15
        indicators.append("login form with password field")
    if password_fields:
        harvesting += 10
    if sensitive >= 2:
        harvesting += 5
    if external_actions:
        harvesting += 10
        indicators.append(f"credentials posted to external host {external_actions[0]}")
    if fp.get("telegram_exfil"):
        harvesting += 15
        indicators.append("Telegram bot exfiltration endpoint in page")

    keyword_score = min(15, 5 * len(domain_keywords)) + min(10, 3 * len(page_keywords))
    mismatch = 0.0
    if primary and not legitimate and (signals.get("brand_in_title") or logo_similarity >= 0.85):
        if not signals.get("brand_in_domain") or legit_registered:
            mismatch = 10
            indicators.append("page presents brand on a non-brand domain")

    impersonation = brand_similarity * 0.5 + harvesting + keyword_score + mismatch
    if inferred and signals.get("brand_in_domain") and not legit_registered:
        # A site presenting its own (inferred) brand on a matching domain is most likely the brand itself:
        # only credential-harvesting and keyword evidence count, at half weight.
        impersonation = (harvesting + keyword_score) * 0.5
    if not tokens:
        impersonation = harvesting + keyword_score
    if not site_active:
        impersonation *= 0.6
    if legitimate:
        impersonation = 0
        indicators.insert(0, "domain belongs to the legitimate brand")
    return BrandAssessment(
        brand=brand,
        brand_inferred=inferred,
        legitimate=legitimate,
        brand_similarity_score=brand_similarity,
        impersonation_score=int(round(min(99.0, impersonation))),
        signals=signals,
        indicators=indicators,
    )
