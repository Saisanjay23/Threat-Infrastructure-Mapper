"""Threat Cluster Engine: groups correlated infrastructure into operations with unique cluster IDs."""

from __future__ import annotations

import logging
import secrets
import statistics
from collections import Counter
from typing import Any

import networkx as nx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.analysis.correlation import CorrelationResult
from app.db.mongo import Collections
from app.graph.builder import NODE_PROJECTION, build_graph
from app.models.common import AssetType, Severity, utcnow
from app.models.graph import RelationType
from app.models.scoring import ScoringConfig
from app.repositories.assets import AssetRepository
from app.repositories.relationships import RelationshipRepository

log = logging.getLogger(__name__)

DISTINCTIVE_RELATIONS = {
    "SHARES_ANALYTICS",
    "SHARES_PIXEL",
    "SHARES_TRACKING",
    "SHARES_FAVICON",
    "USES_CERTIFICATE",
    "SHARES_LOGO",
    "SIMILAR_HTML",
    "SIMILAR_SCREENSHOT",
    "SHARES_CERTIFICATE",
    "REDIRECTS_TO",
}
RELATION_FEATURE = {
    "SHARES_ANALYTICS": "analytics",
    "SHARES_PIXEL": "pixel",
    "SHARES_TRACKING": "tracking",
    "SHARES_FAVICON": "favicon",
    "USES_CERTIFICATE": "certificate",
    "SHARES_CERTIFICATE": "certificate",
    "SHARES_LOGO": "logo",
    "SIMILAR_HTML": "html",
    "SIMILAR_SCREENSHOT": "screenshot",
    "REDIRECTS_TO": "redirect",
}
HOST_TYPES = {"domain", "ip"}


def new_cluster_id() -> str:
    return f"TIM-CL-{utcnow():%Y%m%d}-{secrets.token_hex(3).upper()}"


def severity_for(members: list[dict[str, Any]]) -> Severity:
    active = [m for m in members if m.get("status") == "ACTIVE"]
    top = max((m.get("impersonation_score") or 0 for m in members), default=0)
    top_active = max((m.get("impersonation_score") or 0 for m in active), default=0)
    if top_active >= 80:
        return Severity.CRITICAL
    if top_active >= 60 or top >= 80:
        return Severity.HIGH
    if top >= 30 or len(active) >= 3:
        return Severity.MEDIUM
    if members:
        return Severity.LOW
    return Severity.INFO


class ClusterEngine:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.assets = AssetRepository(db)
        self.relationships = RelationshipRepository(db)
        self.col = db[Collections.CLUSTERS]

    # ------------------------------------------------------------------ persistence helpers
    async def _summarize(self, member_ids: list[str], fingerprint_ids: list[str]) -> dict[str, Any]:
        members = (
            await self.db[Collections.ASSETS]
            .find(
                {"_id": {"$in": member_ids}},
                {
                    "type": 1,
                    "value": 1,
                    "status": 1,
                    "confidence": 1,
                    "impersonation_score": 1,
                    "attributes.screenshots": 1,
                    "attributes.title": 1,
                    "attributes.brand.brand": 1,
                },
            )
            .to_list(length=len(member_ids) or 1)
        )
        prints = (
            await self.db[Collections.ASSETS]
            .find({"_id": {"$in": fingerprint_ids}}, {"type": 1, "value": 1, "attributes.family": 1})
            .to_list(length=len(fingerprint_ids) or 1)
        )
        by_type: dict[str, list[str]] = {}
        for p in prints:
            by_type.setdefault(p["type"], []).append(p["value"])
        counts = Counter(m["type"] for m in members)
        counts.update(p["type"] for p in prints)
        counts["ip"] = len({m["value"] for m in members if m["type"] == "ip"} | set(by_type.get("ip", [])))
        screenshots = [
            {
                "asset_id": m["_id"],
                "value": m["value"],
                "file_id": (m.get("attributes") or {}).get("screenshots", {}).get("thumbnail"),
            }
            for m in members
            if (m.get("attributes") or {}).get("screenshots", {}).get("thumbnail")
        ][:24]
        brands = Counter(((m.get("attributes") or {}).get("brand") or {}).get("brand") for m in members)
        brands.pop(None, None)
        return {
            "members": members,
            "domains": sorted(m["value"] for m in members if m["type"] == "domain")[:1000],
            "ips": sorted({m["value"] for m in members if m["type"] == "ip"} | set(by_type.get("ip", [])))[:500],
            "certificates": sorted(by_type.get("certificate", []))[:200],
            "favicons": sorted(by_type.get("favicon", []))[:100],
            "tracking_ids": sorted(
                by_type.get("analytics", []) + by_type.get("pixel", []) + by_type.get("tracking", [])
            )[:200],
            "logos": by_type.get("logo", [])[:50],
            "screenshots": screenshots,
            "counts": dict(counts),
            "status_breakdown": dict(Counter(m.get("status") or "UNKNOWN" for m in members)),
            "brands": [b for b, _ in brands.most_common(3)],
        }

    async def _save(
        self,
        *,
        member_ids: list[str],
        fingerprint_ids: list[str],
        confidence: int,
        evidence: list[dict[str, Any]],
        config: ScoringConfig,
        investigation_id: str | None,
        name_hint: str,
    ) -> dict[str, Any]:
        existing = await self.col.find({"asset_ids": {"$in": member_ids}}).sort("created_at", 1).to_list(length=50)
        now = utcnow()
        if existing:
            target = existing[0]
            cluster_id = target["_id"]
            merged_assets = set(target.get("asset_ids", [])) | set(member_ids)
            merged_prints = set(target.get("fingerprint_ids", [])) | set(fingerprint_ids)
            merged_invs = set(target.get("investigation_ids", []))
            for other in existing[1:]:
                merged_assets |= set(other.get("asset_ids", []))
                merged_prints |= set(other.get("fingerprint_ids", []))
                merged_invs |= set(other.get("investigation_ids", []))
                await self.db[Collections.ASSETS].update_many(
                    {"cluster_ids": other["_id"]}, {"$pull": {"cluster_ids": other["_id"]}}
                )
                await self.col.delete_one({"_id": other["_id"]})
                await self.db[Collections.ASSETS].delete_one({"type": "cluster", "value": other["_id"]})
            member_ids = sorted(merged_assets)
            fingerprint_ids = sorted(merged_prints)
            investigation_ids = sorted(merged_invs | ({investigation_id} if investigation_id else set()))
            created_at = target.get("created_at", now)
            name = target.get("name") or name_hint
            notes = target.get("notes", [])
            tags = target.get("tags", [])
            evidence = _merge_evidence(target.get("evidence", []), evidence)
            confidence = max(confidence, int(target.get("confidence") or 0)) if len(existing) == 1 else confidence
        else:
            cluster_id = new_cluster_id()
            investigation_ids = [investigation_id] if investigation_id else []
            created_at = now
            name = name_hint
            notes, tags = [], []
        summary = await self._summarize(member_ids, fingerprint_ids)
        members = summary.pop("members")
        doc = {
            "_id": cluster_id,
            "name": name,
            "asset_ids": member_ids,
            "fingerprint_ids": fingerprint_ids,
            "investigation_ids": investigation_ids,
            "confidence": confidence,
            "confidence_level": config.thresholds.level(confidence).value,
            "severity": severity_for(members).value,
            "evidence": evidence[:30],
            "notes": notes,
            "tags": tags,
            "created_at": created_at,
            "updated_at": now,
            **summary,
        }
        await self.col.replace_one({"_id": cluster_id}, doc, upsert=True)
        await self.db[Collections.ASSETS].update_many(
            {"_id": {"$in": member_ids}}, {"$addToSet": {"cluster_ids": cluster_id}}
        )
        cluster_node = await self.assets.upsert(
            AssetType.CLUSTER,
            cluster_id,
            investigation_id=investigation_id,
            source="cluster-engine",
            attributes={"name": name, "confidence": confidence, "severity": doc["severity"]},
            extra={"confidence": confidence},
        )
        for mid in member_ids:
            await self.relationships.upsert(
                mid,
                cluster_node["_id"],
                RelationType.MEMBER_OF_CLUSTER.value,
                investigation_id=investigation_id,
                provider="cluster-engine",
            )
        return doc

    # ------------------------------------------------------------------ per investigation
    async def build_for_investigation(
        self,
        investigation_id: str,
        results: list[CorrelationResult],
        g: nx.MultiDiGraph,
        config: ScoringConfig,
        *,
        root_value: str,
        brand: str | None = None,
    ) -> dict[str, Any] | None:
        threshold = config.thresholds.cluster_min
        members = [r for r in results if r.score >= threshold and g.nodes.get(r.asset_id, {}).get("type") in HOST_TYPES]
        if len(members) < 2:
            return None
        member_ids = [m.asset_id for m in members]
        member_set = set(member_ids)
        fingerprint_ids: set[str] = set()
        undirected = nx.Graph(g)
        for node, data in g.nodes(data=True):
            if node in member_set or data.get("type") in ("url", "cluster", "domain"):
                continue
            linked = [n for n in undirected.neighbors(node) if n in member_set]
            # IPs the members resolve to are the operation's hosting infrastructure; other artefacts
            # (certificates, trackers, favicons, ASNs...) count when shared by at least two members.
            if (data.get("type") == "ip" and linked) or len(linked) >= 2:
                fingerprint_ids.add(node)
        non_seed = [m.score for m in members if not any(x["feature"] == "seed" for x in m.matches)]
        confidence = int(round(statistics.median(non_seed))) if non_seed else threshold
        features: Counter[str] = Counter()
        for m in members:
            for match in m.matches:
                if match["feature"] != "seed":
                    features[match["feature"]] += 1
        evidence = [{"feature": f, "members": n} for f, n in features.most_common()]
        name = f"{brand} impersonation cluster" if brand else f"Operation around {root_value}"
        return await self._save(
            member_ids=member_ids,
            fingerprint_ids=sorted(fingerprint_ids),
            confidence=confidence,
            evidence=evidence,
            config=config,
            investigation_id=investigation_id,
            name_hint=name,
        )

    # ------------------------------------------------------------------ global rebuild
    async def rebuild_all(self, config: ScoringConfig, *, min_members: int = 2, max_assets: int = 50000) -> list[str]:
        """Cluster the whole inventory: connected components over distinctive shared fingerprints."""
        edges = (
            await self.db[Collections.RELATIONSHIPS]
            .find({"type": {"$in": sorted(DISTINCTIVE_RELATIONS)}})
            .to_list(length=max_assets * 4)
        )
        node_ids = list({n for e in edges for n in (e["source"], e["target"])})
        assets = (
            await self.db[Collections.ASSETS]
            .find({"_id": {"$in": node_ids}}, NODE_PROJECTION)
            .to_list(length=len(node_ids) or 1)
        )
        g = build_graph(assets, edges)
        undirected = nx.Graph()
        limit = config.noisy_fingerprint_limit
        for s, t, d in g.edges(data=True):
            st, tt = g.nodes[s].get("type"), g.nodes[t].get("type")
            if st in HOST_TYPES or tt in HOST_TYPES:
                fp_node = t if st in HOST_TYPES else s
                if g.nodes[fp_node].get("type") not in HOST_TYPES and g.degree(fp_node) > limit:
                    continue
                undirected.add_edge(s, t, type=d.get("type"))
        cluster_ids: list[str] = []
        for component in nx.connected_components(undirected):
            hosts = [n for n in component if g.nodes[n].get("type") in HOST_TYPES]
            if len(hosts) < min_members:
                continue
            prints = [n for n in component if g.nodes[n].get("type") not in HOST_TYPES]
            features_per_host: dict[str, set[str]] = {h: set() for h in hosts}
            for h in hosts:
                for nbr in undirected.neighbors(h):
                    rel = undirected.edges[h, nbr].get("type")
                    feature = RELATION_FEATURE.get(rel or "")
                    if feature is None:
                        continue
                    if g.nodes[nbr].get("type") in HOST_TYPES:
                        features_per_host[h].add(feature)
                    elif sum(1 for x in undirected.neighbors(nbr) if x in features_per_host) >= 2:
                        if feature == "tracking" and str(g.nodes[nbr].get("value", "")).upper().startswith("GTM-"):
                            feature = "gtm"
                        features_per_host[h].add(feature)
            scores = [min(100, sum(config.weights.get(f, 0) for f in fs)) for fs in features_per_host.values()]
            confidence = int(round(statistics.mean(scores))) if scores else 0
            for h, s in zip(features_per_host, scores, strict=True):
                current = g.nodes[h].get("confidence") or 0
                if s > current:
                    await self.db[Collections.ASSETS].update_one(
                        {"_id": h}, {"$set": {"confidence": s, "confidence_level": config.thresholds.level(s).value}}
                    )
            feature_counts = Counter(f for fs in features_per_host.values() for f in fs)
            top = max(hosts, key=lambda n: g.degree(n))
            doc = await self._save(
                member_ids=sorted(hosts),
                fingerprint_ids=sorted(prints),
                confidence=confidence,
                evidence=[{"feature": f, "members": n} for f, n in feature_counts.most_common()],
                config=config,
                investigation_id=None,
                name_hint=f"Operation around {g.nodes[top].get('value')}",
            )
            cluster_ids.append(doc["_id"])
        return cluster_ids


def _merge_evidence(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for item in a + b:
        counts[item["feature"]] = max(counts[item["feature"]], int(item.get("members", 0)))
    return [{"feature": f, "members": n} for f, n in counts.most_common()]
