"""Cluster engine (MongoDB), graph API, cluster API and scoring settings API."""

from app.models.scoring import ScoringConfig
from app.repositories.assets import AssetRepository
from app.repositories.relationships import RelationshipRepository
from app.services.clusters import ClusterEngine


async def _seed_operation(db, inv_id="inv_test"):
    assets = AssetRepository(db)
    rels = RelationshipRepository(db)
    hosts = []
    for i, name in enumerate(["op-one.test", "op-two.test", "op-three.test"]):
        hosts.append(
            await assets.upsert(
                "domain",
                name,
                investigation_id=inv_id,
                source="test",
                extra={"status": "ACTIVE", "impersonation_score": 85 if i == 0 else 40},
            )
        )
    ga = await assets.upsert("analytics", "UA-999-1", investigation_id=inv_id, source="test")
    fav = await assets.upsert("favicon", "-424242", investigation_id=inv_id, source="test")
    lone = await assets.upsert("domain", "alone.test", investigation_id=inv_id, source="test")
    for h in hosts:
        await rels.upsert(h["_id"], ga["_id"], "SHARES_ANALYTICS", investigation_id=inv_id)
    for h in hosts[:2]:
        await rels.upsert(h["_id"], fav["_id"], "SHARES_FAVICON", investigation_id=inv_id)
    return hosts, ga, fav, lone


async def test_rebuild_all_creates_scored_cluster(db):
    hosts, ga, fav, lone = await _seed_operation(db)
    ids = await ClusterEngine(db).rebuild_all(ScoringConfig())
    assert len(ids) == 1
    cluster = await db["clusters"].find_one({"_id": ids[0]})
    assert cluster["_id"].startswith("TIM-CL-")
    assert set(cluster["domains"]) == {"op-one.test", "op-two.test", "op-three.test"}
    assert "alone.test" not in cluster["domains"]
    assert set(cluster["tracking_ids"]) == {"UA-999-1"} and cluster["favicons"] == ["-424242"]
    assert cluster["severity"] == "critical"
    assert cluster["confidence"] == round((70 + 70 + 40) / 3)
    member = await db["assets"].find_one({"_id": hosts[0]["_id"]})
    assert ids[0] in member["cluster_ids"] and member["confidence"] == 70
    assert await db["relationships"].count_documents({"type": "MEMBER_OF_CLUSTER"}) == 3
    # Re-running is idempotent: same cluster id, no duplicates.
    again = await ClusterEngine(db).rebuild_all(ScoringConfig())
    assert again == ids
    assert await db["clusters"].count_documents({}) == 1


async def test_clusters_merge_across_operations(db):
    await _seed_operation(db)
    first = await ClusterEngine(db).rebuild_all(ScoringConfig())
    assets = AssetRepository(db)
    rels = RelationshipRepository(db)
    newcomer = await assets.upsert("domain", "op-four.test", source="test")
    favicon = await db["assets"].find_one({"type": "favicon"})
    await rels.upsert(newcomer["_id"], favicon["_id"], "SHARES_FAVICON")
    second = await ClusterEngine(db).rebuild_all(ScoringConfig())
    assert second == first
    cluster = await db["clusters"].find_one({"_id": first[0]})
    assert "op-four.test" in cluster["domains"]


async def test_graph_and_cluster_api(client, admin_headers, db):
    hosts, *_ = await _seed_operation(db, inv_id="inv_graphtest")
    await db["investigations"].insert_one({"_id": "inv_graphtest", "root_asset_id": hosts[0]["_id"]})
    r = await client.get("/graph/inv_graphtest", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "investigation" and body["focus"] == hosts[0]["_id"]
    assert body["stats"]["nodes"] == 6 and body["stats"]["edges"] == 5
    assert {e["type"] for e in body["edges"]} == {"SHARES_ANALYTICS", "SHARES_FAVICON"}

    neighborhood = (await client.get(f"/graph/{hosts[0]['_id']}?depth=2", headers=admin_headers)).json()
    assert neighborhood["kind"] == "asset" and neighborhood["stats"]["nodes"] >= 4
    assert (await client.get("/graph/inv_missing", headers=admin_headers)).status_code == 404

    rebuilt = (await client.post("/clusters/rebuild", headers=admin_headers)).json()
    cid = rebuilt["clusters"][0]
    listing = (await client.get("/clusters?q=op-two", headers=admin_headers)).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == cid
    detail = (await client.get(f"/clusters/{cid}", headers=admin_headers)).json()
    assert len(detail["asset_ids"]) == 3
    upd = await client.patch(
        f"/clusters/{cid}", headers=admin_headers, json={"name": "Campaign X", "tags": ["APT", "x"]}
    )
    assert upd.json()["name"] == "Campaign X" and upd.json()["tags"] == ["apt", "x"]
    note = await client.post(f"/clusters/{cid}/notes", headers=admin_headers, json={"text": "same kit"})
    assert note.json()["notes"][0]["text"] == "same kit"
    cgraph = (await client.get(f"/graph/{cid}", headers=admin_headers)).json()
    assert cgraph["kind"] == "cluster" and cgraph["stats"]["nodes"] >= 5
    assert (await client.get("/clusters/TIM-CL-nope", headers=admin_headers)).status_code == 404


async def test_scoring_settings_api(client, admin_headers, make_user):
    current = (await client.get("/settings/scoring", headers=admin_headers)).json()
    assert current["weights"]["analytics"] == 40 and current["labels"]["gtm"]
    body = {
        "weights": {**current["weights"], "ip": 15},
        "thresholds": current["thresholds"],
        "similarity": current["similarity"],
        "noisy_fingerprint_limit": 100,
    }
    saved = await client.put("/settings/scoring", headers=admin_headers, json=body)
    assert saved.status_code == 200 and saved.json()["weights"]["ip"] == 15
    bad = await client.put(
        "/settings/scoring", headers=admin_headers, json={**body, "thresholds": {**current["thresholds"], "high": 95}}
    )
    assert bad.status_code == 422
    analyst = await make_user("scorer", "analyst")
    assert (await client.put("/settings/scoring", headers=analyst, json=body)).status_code == 403
    assert (await client.get("/settings/scoring", headers=analyst)).status_code == 200
    await client.delete("/settings/scoring", headers=admin_headers)
    assert (await client.get("/settings/scoring", headers=admin_headers)).json()["weights"]["ip"] == 10
