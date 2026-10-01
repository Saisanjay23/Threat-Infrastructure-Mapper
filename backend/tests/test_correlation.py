"""Correlation engine scoring and graph model tests (pure, no database)."""

import pytest

from app.analysis.correlation import correlate, redirect_hosts
from app.graph.builder import build_graph, serialize_graph, shared_neighbors
from app.models.scoring import DEFAULT_WEIGHTS, ScoringConfig, Thresholds


def asset(aid, typ, value, **fp):
    return {"_id": aid, "type": typ, "value": value, "fingerprints": fp}


def edge(s, t, typ):
    return {"_id": f"{s}-{typ}-{t}", "source": s, "target": t, "type": typ}


@pytest.fixture
def graph():
    assets = [
        asset(
            "seed",
            "domain",
            "contoso-login.test",
            html_simhash="ffff0000ffff0000",
            title_hash="t1",
            title_normalized="contoso bank secure login",
        ),
        asset(
            "twin",
            "domain",
            "contoso-verify.test",
            html_simhash="ffff0000ffff0001",
            title_hash="t1",
            title_normalized="contoso bank secure login",
        ),
        asset("weak", "domain", "unrelated.test", title_normalized="cooking"),
        asset("sub", "domain", "mail.contoso-login.test"),
        asset("ga", "analytics", "G-ABC123XYZ9"),
        asset("gtm", "tracking", "GTM-ABCD12"),
        asset("fav", "favicon", "-12345"),
        asset("cert", "certificate", "a" * 64),
        asset("ip1", "ip", "198.51.100.7"),
        asset("ip2", "ip", "198.51.100.8"),
        asset("asn", "asn", "AS64500"),
        asset("cf", "asn", "AS13335"),
        asset("ns", "nameserver", "ns1.bulletproof.test"),
        asset("u1", "url", "https://contoso-login.test/"),
        asset("u2", "url", "https://hop.test/r"),
        asset("hop", "domain", "hop.test"),
    ]
    edges = [
        edge("seed", "ga", "SHARES_ANALYTICS"),
        edge("twin", "ga", "SHARES_ANALYTICS"),
        edge("seed", "gtm", "SHARES_TRACKING"),
        edge("twin", "gtm", "SHARES_TRACKING"),
        edge("seed", "fav", "SHARES_FAVICON"),
        edge("twin", "fav", "SHARES_FAVICON"),
        edge("seed", "cert", "USES_CERTIFICATE"),
        edge("twin", "cert", "USES_CERTIFICATE"),
        edge("seed", "ip1", "RESOLVES_TO"),
        edge("twin", "ip1", "RESOLVES_TO"),
        edge("weak", "ip2", "RESOLVES_TO"),
        edge("ip1", "asn", "BELONGS_TO_ASN"),
        edge("ip2", "asn", "BELONGS_TO_ASN"),
        edge("seed", "ns", "USES_NAMESERVER"),
        edge("weak", "ns", "USES_NAMESERVER"),
        edge("sub", "seed", "SUBDOMAIN_OF"),
        edge("seed", "u1", "HAS_URL"),
        edge("hop", "u2", "HAS_URL"),
        edge("u1", "u2", "REDIRECTS_TO"),
    ]
    return build_graph(assets, edges), {a["_id"]: a for a in assets}


def scores(results):
    return {r.asset_id: r for r in results}


def test_correlation_scores_and_evidence(graph):
    g, assets = graph
    out = scores(correlate(g, ["seed"], assets, ScoringConfig()))
    assert out["seed"].score == 100
    twin = out["twin"]
    feats = {m["feature"] for m in twin.matches}
    assert {"analytics", "gtm", "favicon", "certificate", "html", "title", "ip", "asn"} <= feats
    assert twin.score == 100  # capped
    weak = out["weak"]
    assert {m["feature"] for m in weak.matches} == {"asn", "nameserver"}
    assert weak.score == DEFAULT_WEIGHTS["asn"] + DEFAULT_WEIGHTS["nameserver"]
    assert out["sub"].matches[0]["feature"] == "subdomain"
    assert out["hop"].matches[0]["feature"] == "redirect"
    assert out["ip1"].score >= DEFAULT_WEIGHTS["ip"]
    assert "u1" not in out  # URLs are scored through their host


def test_custom_weights_and_noise(graph):
    g, assets = graph
    config = ScoringConfig(
        weights={"analytics": 0, "gtm": 0, "favicon": 10, "certificate": 0, "html": 0, "title": 0, "ip": 0, "asn": 0}
    )
    out = scores(correlate(g, ["seed"], assets, config, noise=lambda n: n == "fav"))
    twin = out["twin"]
    assert [m["feature"] for m in twin.matches] == ["favicon"]
    assert twin.matches[0]["weight"] == 2.5  # 25% for a noisy fingerprint
    assert twin.score == 2  # rounded


def test_cdn_asn_dampens_infrastructure(graph):
    g, assets = graph
    g.add_edge("ip1", "cf", key="cf", type="BELONGS_TO_ASN")
    out = scores(correlate(g, ["seed"], assets, ScoringConfig()))
    ip_match = next(m for m in out["twin"].matches if m["feature"] == "ip")
    assert ip_match["weight"] == DEFAULT_WEIGHTS["ip"] * 0.25


def test_thresholds_levels_and_validation():
    t = Thresholds()
    assert [t.level(s).value for s in (95, 75, 55, 35, 5, None)] == [
        "Very High",
        "High",
        "Medium",
        "Low",
        "Informational",
        "Informational",
    ]
    with pytest.raises(ValueError):
        Thresholds(very_high=50, high=70)
    with pytest.raises(ValueError):
        ScoringConfig(weights={"bogus": 10})
    with pytest.raises(ValueError):
        ScoringConfig(weights={"ip": 500})
    assert ScoringConfig(weights={"ip": 20}).weights["analytics"] == 40  # merged with defaults


def test_redirect_hosts(graph):
    g, _ = graph
    assert redirect_hosts(g, ["seed"]) == {"hop"}


def test_graph_serialization(graph):
    g, _ = graph
    payload = serialize_graph(g, focus="seed")
    assert payload["stats"]["nodes"] == g.number_of_nodes()
    assert payload["stats"]["edges"] == g.number_of_edges()
    node = next(n for n in payload["nodes"] if n["id"] == "seed")
    assert node["data"]["is_root"] is True and node["data"]["degree"] > 0
    assert {"x", "y"} <= set(node["position"])
    assert payload["stats"]["hubs"][0]["degree"] >= node["data"]["degree"] - 10
    shared = {n for n, *_ in shared_neighbors(g, "seed", "twin")}
    assert {"ga", "gtm", "fav", "cert", "ip1"} <= shared
