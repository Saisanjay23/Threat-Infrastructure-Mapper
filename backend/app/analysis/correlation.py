"""Correlation Engine: configurable, evidence-backed scoring of how strongly an asset belongs to the
same operation as the investigation seed(s).

Evidence comes from two places:
1. the relationship graph (shared fingerprint nodes: certificate, favicon, trackers, logo, IP/ASN/...);
2. fingerprint similarity between profiled hosts (HTML structure, title, screenshot, logo hashes).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.fingerprints.images import hash_similarity
from app.fingerprints.similarity import simhash_similarity, string_similarity
from app.models.scoring import FEATURE_LABELS, ScoringConfig
from app.utils.ioc import registered_domain

CDN_ASNS = {
    "AS13335",
    "AS20940",
    "AS16625",
    "AS54113",
    "AS15169",
    "AS8075",
    "AS16509",
    "AS14618",
    "AS209242",
    "AS396982",
    "AS8068",
    "AS32934",
    "AS19551",
    "AS60068",
}
SHARED_NAMESERVER_SUFFIXES = (
    "cloudflare.com",
    "awsdns",
    "domaincontrol.com",
    "azure-dns",
    "googledomains.com",
    "registrar-servers.com",
    "nsone.net",
    "dnsmadeeasy.com",
    "ultradns",
    "akam.net",
    "dynect.net",
    "hostinger",
    "name-services.com",
    "dns.google",
)
GENERIC_TITLES = {
    "",
    "home",
    "index",
    "login",
    "log in",
    "sign in",
    "welcome",
    "untitled",
    "document",
    "loading",
    "404 not found",
    "not found",
    "403 forbidden",
    "just a moment",
    "attention required cloudflare",
    "access denied",
    "error",
    "page not found",
    "default page",
    "website",
    "coming soon",
    "under construction",
    "it works",
    "welcome to nginx",
    "iis windows server",
}
NOISE_FACTOR = 0.25

NODE_FEATURE_RELATIONS: dict[str, str] = {
    "SHARES_FAVICON": "favicon",
    "SHARES_ANALYTICS": "analytics",
    "SHARES_PIXEL": "pixel",
    "SHARES_TRACKING": "tracking",
    "SHARES_LOGO": "logo",
    "USES_CERTIFICATE": "certificate",
}


@dataclass
class HostProfile:
    node: str
    value: str
    type: str
    fingerprint_nodes: dict[str, set[str]] = field(default_factory=dict)  # feature -> fingerprint node ids
    ips: set[str] = field(default_factory=set)
    asns: set[str] = field(default_factory=set)
    hosting: set[str] = field(default_factory=set)
    nameservers: set[str] = field(default_factory=set)
    html_simhash: str | None = None
    title_hash: str | None = None
    title_normalized: str | None = None
    screenshot_phash: str | None = None
    logo_phashes: list[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    asset_id: str
    score: int
    matches: list[dict[str, Any]]


def _neighbors_by_relation(g: nx.MultiDiGraph, node: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for _, t, d in g.out_edges(node, data=True):
        out.setdefault(d.get("type"), set()).add(t)
    for s, _, d in g.in_edges(node, data=True):
        out.setdefault("in:" + str(d.get("type")), set()).add(s)
    return out


def host_profile(g: nx.MultiDiGraph, node: str, asset: dict[str, Any] | None) -> HostProfile:
    data = g.nodes[node] if node in g else {}
    asset = asset or {}
    fp = asset.get("fingerprints") or {}
    prof = HostProfile(
        node=node,
        value=str(data.get("value") or asset.get("value") or ""),
        type=str(data.get("type") or asset.get("type") or ""),
    )
    rel = _neighbors_by_relation(g, node) if node in g else {}
    for relation, feature in NODE_FEATURE_RELATIONS.items():
        targets = rel.get(relation, set())
        if feature == "tracking":
            gtm = {t for t in targets if str(g.nodes[t].get("value", "")).upper().startswith("GTM-")}
            if gtm:
                prof.fingerprint_nodes.setdefault("gtm", set()).update(gtm)
            targets = targets - gtm
        if targets:
            prof.fingerprint_nodes.setdefault(feature, set()).update(targets)
    if prof.type == "ip":
        prof.ips.add(node)
    for ip in rel.get("RESOLVES_TO", set()) | rel.get("HISTORICAL_RESOLUTION", set()):
        if g.nodes[ip].get("type") == "ip":
            prof.ips.add(ip)
    for ip in list(prof.ips):
        ip_rel = _neighbors_by_relation(g, ip)
        prof.asns |= ip_rel.get("BELONGS_TO_ASN", set())
        prof.hosting |= ip_rel.get("HOSTED_ON", set())
    prof.nameservers = set(rel.get("USES_NAMESERVER", set()))
    prof.html_simhash = fp.get("html_simhash")
    prof.title_hash = fp.get("title_hash")
    prof.title_normalized = fp.get("title_normalized")
    prof.screenshot_phash = fp.get("screenshot_phash")
    prof.logo_phashes = list(fp.get("logo_phashes") or [])
    return prof


def merge_profiles(profiles: list[HostProfile]) -> HostProfile:
    merged = HostProfile(node="__seed__", value="seed", type="seed")
    for p in profiles:
        for feature, nodes in p.fingerprint_nodes.items():
            merged.fingerprint_nodes.setdefault(feature, set()).update(nodes)
        merged.ips |= p.ips
        merged.asns |= p.asns
        merged.hosting |= p.hosting
        merged.nameservers |= p.nameservers
        merged.logo_phashes.extend(p.logo_phashes)
    return merged


def redirect_hosts(g: nx.MultiDiGraph, seeds: list[str]) -> set[str]:
    """Hosts owning any URL in the redirect chain(s) that start at the seed hosts."""
    seed_urls = {t for s in seeds if s in g for _, t, d in g.out_edges(s, data=True) if d.get("type") == "HAS_URL"}
    redirect_graph = nx.Graph()
    for s, t, d in g.edges(data=True):
        if d.get("type") == "REDIRECTS_TO":
            redirect_graph.add_edge(s, t)
    chain: set[str] = set()
    for u in seed_urls:
        if u in redirect_graph:
            chain |= nx.node_connected_component(redirect_graph, u)
    hosts = {s for u in chain for s, _, d in g.in_edges(u, data=True) if d.get("type") == "HAS_URL"}
    return hosts - set(seeds)


def _label(g: nx.MultiDiGraph, node: str) -> str:
    return str(g.nodes[node].get("value", node)) if node in g else node


def score_candidate(
    g: nx.MultiDiGraph,
    seed: HostProfile,
    seed_profiles: list[HostProfile],
    cand: HostProfile,
    config: ScoringConfig,
    *,
    noise: Callable[[str], bool],
    redirect_chain: set[str],
    seed_domains: set[str],
) -> tuple[int, list[dict[str, Any]]]:
    w = config.weights
    matches: list[dict[str, Any]] = []

    def add(feature: str, values: list[str], factor: float = 1.0, detail: str | None = None) -> None:
        weight = round(w.get(feature, 0) * factor, 1)
        if weight <= 0:
            return
        matches.append(
            {
                "feature": feature,
                "label": FEATURE_LABELS.get(feature, feature),
                "values": values[:5],
                "weight": weight,
                **({"detail": detail} if detail else {}),
            }
        )

    if cand.node in redirect_chain:
        add("redirect", [cand.value])

    if cand.type == "domain" and seed_domains:
        cand_reg = registered_domain(cand.value)
        parent = next(
            (s for s in seed_domains if cand.value != s and (cand_reg == s or cand.value.endswith("." + s))), None
        )
        if parent is None:
            for sp in seed_profiles:
                if any(d.get("type") == "SUBDOMAIN_OF" for d in (g.get_edge_data(cand.node, sp.node) or {}).values()):
                    parent = sp.value
                    break
        if parent:
            add("subdomain", [cand.value], detail=f"subdomain of {parent}")

    for feature in ("analytics", "gtm", "pixel", "tracking", "favicon", "certificate", "logo"):
        shared = seed.fingerprint_nodes.get(feature, set()) & cand.fingerprint_nodes.get(feature, set())
        if shared:
            noisy = all(noise(n) for n in shared)
            add(
                feature,
                [_label(g, n) for n in shared],
                NOISE_FACTOR if noisy else 1.0,
                "common fingerprint (reduced weight)" if noisy else None,
            )

    # crt.sh co-SAN evidence is a direct domain<->domain SHARES_CERTIFICATE edge.
    if not any(m["feature"] == "certificate" for m in matches):
        for sp in seed_profiles:
            if g.has_edge(sp.node, cand.node) or g.has_edge(cand.node, sp.node):
                types = {d.get("type") for d in (g.get_edge_data(sp.node, cand.node) or {}).values()} | {
                    d.get("type") for d in (g.get_edge_data(cand.node, sp.node) or {}).values()
                }
                if "SHARES_CERTIFICATE" in types:
                    add("certificate", [f"{sp.value} <-> {cand.value}"], detail="names share a CT-logged certificate")
                    break

    # Similarity features (profiled hosts).
    sim = config.similarity
    best_html = max((simhash_similarity(sp.html_simhash, cand.html_simhash) for sp in seed_profiles), default=0.0)
    if cand.html_simhash and best_html >= sim.html:
        add("html", [f"{best_html:.2f}"], detail="DOM structure SimHash similarity")
    if cand.title_normalized and cand.title_normalized not in GENERIC_TITLES:
        exact = any(sp.title_hash and sp.title_hash == cand.title_hash for sp in seed_profiles)
        best_title = (
            1.0
            if exact
            else max(
                (string_similarity(sp.title_normalized or "", cand.title_normalized) for sp in seed_profiles),
                default=0.0,
            )
        )
        if best_title >= sim.title:
            add("title", [cand.title_normalized], best_title)
    best_shot = max((hash_similarity(sp.screenshot_phash, cand.screenshot_phash) for sp in seed_profiles), default=0.0)
    if cand.screenshot_phash and best_shot >= sim.screenshot:
        add("screenshot", [f"{best_shot:.2f}"], detail="screenshot perceptual-hash similarity")
    if not any(m["feature"] == "logo" for m in matches) and cand.logo_phashes and seed.logo_phashes:
        best_logo = max(hash_similarity(a, b) for a in seed.logo_phashes for b in cand.logo_phashes)
        if best_logo >= sim.logo:
            add("logo", [f"{best_logo:.2f}"], detail="logo perceptual-hash similarity")

    # Infrastructure features (low weight; CDN / shared providers further reduced).
    cdn = any(_label(g, n).upper() in CDN_ASNS for n in seed.asns)
    shared_ips = seed.ips & cand.ips  # an IP candidate's own node is in cand.ips
    if shared_ips:
        noisy = cdn or all(noise(n) for n in shared_ips)
        add(
            "ip",
            [_label(g, n) for n in shared_ips],
            NOISE_FACTOR if noisy else 1.0,
            "shared CDN / high-traffic IP" if noisy else None,
        )
    shared_asn = seed.asns & cand.asns
    if shared_asn:
        is_cdn = any(_label(g, n).upper() in CDN_ASNS for n in shared_asn)
        add("asn", [_label(g, n) for n in shared_asn], NOISE_FACTOR if is_cdn else 1.0)
    shared_hosting = seed.hosting & cand.hosting
    if shared_hosting:
        add("hosting", [_label(g, n) for n in shared_hosting], NOISE_FACTOR if cdn else 1.0)
    shared_ns = seed.nameservers & cand.nameservers
    if shared_ns:
        common = all(any(sfx in _label(g, n) for sfx in SHARED_NAMESERVER_SUFFIXES) for n in shared_ns)
        add("nameserver", [_label(g, n) for n in shared_ns], NOISE_FACTOR if common else 1.0)

    score = int(round(min(100.0, sum(m["weight"] for m in matches))))
    return score, sorted(matches, key=lambda m: m["weight"], reverse=True)


def correlate(
    g: nx.MultiDiGraph,
    seeds: list[str],
    assets: dict[str, dict[str, Any]],
    config: ScoringConfig,
    *,
    noise: Callable[[str], bool] = lambda _n: False,
) -> list[CorrelationResult]:
    seed_profiles = [host_profile(g, s, assets.get(s)) for s in seeds if s in g]
    seed = merge_profiles(seed_profiles)
    chain = redirect_hosts(g, seeds)
    seed_domains = {registered_domain(p.value) for p in seed_profiles if p.type == "domain"} | {
        p.value for p in seed_profiles if p.type == "domain"
    }
    results = [
        CorrelationResult(s, 100, [{"feature": "seed", "label": "Investigation seed", "values": [], "weight": 100}])
        for s in seeds
        if s in g
    ]
    for node, data in g.nodes(data=True):
        if node in seeds or data.get("type") not in ("domain", "ip", "url"):
            continue
        if data.get("type") == "url":
            # URLs inherit their host's score: they are scored through the host owning them.
            continue
        cand = host_profile(g, node, assets.get(node))
        score, matches = score_candidate(
            g, seed, seed_profiles, cand, config, noise=noise, redirect_chain=chain, seed_domains=seed_domains
        )
        results.append(CorrelationResult(node, score, matches))
    return results
