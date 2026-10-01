"""Reporting (PDF/HTML/CSV/JSON + library), case management and upload endpoints."""

import csv
import io
import json

from app.db.mongo import get_fs
from app.fingerprints.images import image_fingerprints
from app.models.common import utcnow
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.relationships import RelationshipRepository
from tests.helpers import PHISH_HTML, png_bytes, self_signed_der

INV = "inv_reporttest"


async def _seed(db):
    assets = AssetRepository(db)
    rels = RelationshipRepository(db)
    shot = await ArtifactRepository(db, get_fs()).store_file(
        "screenshot_desktop", png_bytes(size=64), filename="d.png", content_type="image/png", investigation_id=INV
    )
    root = await assets.upsert(
        "domain",
        "contoso-login.test",
        investigation_id=INV,
        source="test",
        attributes={
            "web": {"final_url": "https://contoso-login.test/", "status_code": 200, "title": "Contoso"},
            "screenshots": {"desktop": shot["file_id"]},
            "content": {"reasons": ["HTTP 200 with login form"]},
            "brand": {"indicators": ["login form with password field"]},
        },
        fingerprints={"tracking_ids": ['=HYPERLINK("x")'], "favicon_mmh3": "-1"},
        extra={
            "status": "ACTIVE",
            "confidence": 100,
            "confidence_level": "Very High",
            "impersonation_score": 88,
            "is_root": True,
        },
    )
    sister = await assets.upsert(
        "domain",
        "contoso-verify.test",
        investigation_id=INV,
        source="test",
        extra={
            "status": "ACTIVE",
            "confidence": 75,
            "confidence_level": "High",
            "correlation": {
                INV: {
                    "score": 75,
                    "matches": [
                        {"feature": "analytics", "label": "Analytics ID match", "weight": 40, "values": ["G-1"]},
                        {"feature": "favicon", "label": "Favicon hash match", "weight": 35, "values": ["-1"]},
                    ],
                }
            },
        },
    )
    ga = await assets.upsert("analytics", "G-1", investigation_id=INV, source="test")
    for h in (root, sister):
        await rels.upsert(h["_id"], ga["_id"], "SHARES_ANALYTICS", investigation_id=INV)
    await db["investigations"].insert_one(
        {
            "_id": INV,
            "ioc": "contoso-login.test",
            "ioc_type": "domain",
            "normalized": "contoso-login.test",
            "status": "completed",
            "options": {},
            "stages": {},
            "summary": {},
            "root_asset_id": root["_id"],
            "tags": [],
            "created_by": "admin",
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "notes": [{"id": "n1", "text": "kit reused", "author": "admin", "created_at": utcnow()}],
        }
    )
    return root, sister


async def test_exports_all_formats(client, admin_headers, db):
    await _seed(db)
    body = {"investigation_id": INV, "analyst_notes": "Escalated to takedown team", "tlp": "AMBER"}

    pdf = await client.post("/export/pdf", headers=admin_headers, json=body)
    assert pdf.status_code == 200, pdf.text
    assert pdf.content[:4] == b"%PDF" and len(pdf.content) > 5000
    assert "attachment" in pdf.headers["content-disposition"]
    report_id = pdf.headers["x-report-id"]

    html = await client.post("/export/html", headers=admin_headers, json=body)
    text = html.text
    assert html.status_code == 200 and "<svg" in text and "data:image/png;base64," in text
    assert "Executive summary" in text and "Escalated to takedown team" in text and "kit reused" in text
    assert "Content-Security-Policy" in text

    c = await client.post("/export/csv", headers=admin_headers, json={**body, "save": False})
    rows = list(csv.DictReader(io.StringIO(c.content.decode("utf-8-sig"))))
    assert {r["value"] for r in rows} == {"contoso-login.test", "contoso-verify.test"}
    root_row = next(r for r in rows if r["value"] == "contoso-login.test")
    assert root_row["tracking_ids"].startswith("'=")  # formula injection neutralised
    sister_row = next(r for r in rows if r["value"] == "contoso-verify.test")
    assert "analytics+40" in sister_row["correlation_evidence"]
    assert "x-report-id" not in c.headers

    j = await client.post("/export/json", headers=admin_headers, json=body)
    data = json.loads(j.content)
    assert data["scope"] == {"type": "investigation", "id": INV}
    assert data["statistics"]["high_confidence"] == 2
    assert any("contoso-login.test" in line for line in data["executive_summary"])
    assert data["root_asset"]["value"] == "contoso-login.test"

    library = (await client.get("/reports", headers=admin_headers)).json()
    assert library["total"] == 3
    dl = await client.get(f"/reports/{report_id}/download", headers=admin_headers)
    assert dl.content[:4] == b"%PDF"
    assert (await client.delete(f"/reports/{report_id}", headers=admin_headers)).status_code == 200
    assert (await client.get(f"/reports/{report_id}/download", headers=admin_headers)).status_code == 404


async def test_export_validation_and_rbac(client, admin_headers, make_user):
    assert (await client.post("/export/pdf", headers=admin_headers, json={})).status_code == 422
    both = {"investigation_id": "a", "cluster_id": "b"}
    assert (await client.post("/export/pdf", headers=admin_headers, json=both)).status_code == 422
    assert (
        await client.post("/export/json", headers=admin_headers, json={"investigation_id": "inv_nope"})
    ).status_code == 404
    viewer = await make_user("reportviewer", "viewer")
    assert (await client.post("/export/csv", headers=viewer, json={"asset_ids": ["x"]})).status_code == 403


async def test_case_lifecycle_and_case_export(client, admin_headers, db):
    root, sister = await _seed(db)
    created = await client.post(
        "/cases",
        headers=admin_headers,
        json={
            "title": "Contoso phishing wave",
            "severity": "high",
            "tags": ["Phishing", "contoso"],
            "asset_ids": [root["_id"]],
            "investigation_ids": [INV],
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["id"].startswith("CASE-") and case["status"] == "open" and case["tags"] == ["contoso", "phishing"]
    cid = case["id"]
    assert (await db["investigations"].find_one({"_id": INV}))["case_id"] == cid

    bad = await client.post(f"/cases/{cid}/links", headers=admin_headers, json={"asset_ids": ["missing"]})
    assert bad.status_code == 422
    linked = await client.post(f"/cases/{cid}/links", headers=admin_headers, json={"asset_ids": [sister["_id"]]})
    assert len(linked.json()["asset_ids"]) == 2
    upd = await client.patch(
        f"/cases/{cid}", headers=admin_headers, json={"status": "in_progress", "severity": "critical"}
    )
    assert upd.json()["status"] == "in_progress" and upd.json()["severity"] == "critical"
    note = await client.post(f"/cases/{cid}/notes", headers=admin_headers, json={"text": "Registrar notified"})
    assert note.json()["notes"][0]["text"] == "Registrar notified"
    listing = (await client.get("/cases?q=contoso", headers=admin_headers)).json()
    assert listing["total"] == 1 and listing["items"][0]["asset_count"] == 2
    by_asset = (await client.get(f"/cases?asset_id={sister['_id']}", headers=admin_headers)).json()
    assert by_asset["total"] == 1

    export = await client.post("/export/json", headers=admin_headers, json={"case_id": cid})
    data = json.loads(export.content)
    assert data["case"]["id"] == cid and any(n["text"] == "Registrar notified" for n in data["notes"])

    unlinked = await client.post(f"/cases/{cid}/unlink", headers=admin_headers, json={"asset_ids": [sister["_id"]]})
    assert len(unlinked.json()["asset_ids"]) == 1
    second = await client.post("/cases", headers=admin_headers, json={"title": "Second"})
    assert int(second.json()["id"].rsplit("-", 1)[1]) == int(cid.rsplit("-", 1)[1]) + 1
    assert (await client.delete(f"/cases/{cid}", headers=admin_headers)).status_code == 200
    assert (await client.get(f"/cases/{cid}", headers=admin_headers)).status_code == 404


async def test_logo_upload_registers_reference_and_matches(client, admin_headers, db):
    logo = png_bytes((10, 90, 200), size=96)
    fp = image_fingerprints(logo)
    await AssetRepository(db).upsert(
        "domain", "lookalike.test", source="test", fingerprints={"logo_phashes": [fp["phash"]]}
    )
    r = await client.post(
        "/upload/logo",
        headers=admin_headers,
        files={"file": ("logo.png", logo, "image/png")},
        data={"brand": "Contoso"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reference"] is True and body["fingerprints"]["phash"] == fp["phash"]
    assert [m["value"] for m in body["matches"]] == ["lookalike.test"]
    ref = await db["assets"].find_one({"_id": body["asset_id"]})
    assert ref["attributes"]["brand_lc"] == "contoso" and ref["attributes"]["reference"] is True
    bad = await client.post(
        "/upload/logo", headers=admin_headers, files={"file": ("x.png", b"not an image", "image/png")}
    )
    assert bad.status_code == 415


async def test_html_upload_pivots_on_trackers(client, admin_headers, db):
    await AssetRepository(db).upsert(
        "domain", "sister-kit.test", source="test", fingerprints={"tracking_ids": ["UA-1234567-1"]}
    )
    r = await client.post(
        "/upload/html",
        headers=admin_headers,
        files={"file": ("page.html", PHISH_HTML.encode(), "text/html")},
        data={"page_url": "https://contoso-secure.test/login", "brand": "Contoso"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fingerprints"]["has_login_form"] is True
    assert body["content"]["status"] == "ACTIVE"
    assert body["brand"]["impersonation_score"] >= 50
    match = next(m for m in body["matches"] if m["value"] == "sister-kit.test")
    assert match["via"] == "tracking_id" and match["shared"] == ["UA-1234567-1"]


async def test_screenshot_and_certificate_upload(client, admin_headers, db):
    shot = png_bytes((240, 240, 240), size=200)
    fp = image_fingerprints(shot)
    await AssetRepository(db).upsert(
        "domain",
        "same-look.test",
        source="test",
        fingerprints={"screenshot_phash": fp["phash"], "screenshot_dhash": fp["dhash"]},
    )
    r = await client.post("/upload/screenshot", headers=admin_headers, files={"file": ("s.png", shot, "image/png")})
    assert r.status_code == 200 and r.json()["matches"][0]["value"] == "same-look.test"

    der = self_signed_der("upload.test", ("upload.test",))
    c = await client.post(
        "/upload/certificate", headers=admin_headers, files={"file": ("cert.der", der, "application/pkix-cert")}
    )
    assert c.status_code == 200, c.text
    cert = c.json()["certificate"]
    assert cert["san"] == ["upload.test"] and len(cert["sha256"]) == 64
    assert (await db["assets"].find_one({"_id": c.json()["asset_id"]}))["type"] == "certificate"
    bad = await client.post(
        "/upload/certificate", headers=admin_headers, files={"file": ("c.pem", b"garbage", "text/plain")}
    )
    assert bad.status_code == 415


async def test_upload_requires_permission(client, make_user):
    viewer = await make_user("uploadviewer", "viewer")
    r = await client.post("/upload/logo", headers=viewer, files={"file": ("l.png", png_bytes(), "image/png")})
    assert r.status_code == 403
