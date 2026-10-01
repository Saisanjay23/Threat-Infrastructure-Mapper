"""HTTP API tests: authentication, RBAC, validation, providers, audit, health, metrics."""

import pytest


async def test_health_and_metrics_are_public(client):
    health = await client.get("/health")
    assert health.status_code == 200
    assert health.json()["mongodb"]["ok"] is True
    metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    assert "tim_uptime_seconds" in metrics.text
    assert "tim_http_requests_total" in metrics.text


async def test_openapi_documents_core_endpoints(client):
    spec = (await client.get("/openapi.json")).json()
    for path in (
        "/investigate",
        "/bulk-investigate",
        "/dashboard",
        "/investigation/{inv_id}",
        "/assets",
        "/asset/{asset_id}",
        "/health",
        "/metrics",
        "/providers",
    ):
        assert path in spec["paths"], path


async def test_login_success_and_me(client, admin_headers):
    me = await client.get("/auth/me", headers=admin_headers)
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert "user:admin" in me.json()["permissions"]


async def test_login_failure_and_throttle(client):
    for _ in range(10):
        r = await client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
    r = await client.post("/auth/login", json={"username": "admin", "password": "AdminPass!123"})
    assert r.status_code == 429


async def test_requests_without_token_are_rejected(client):
    assert (await client.get("/dashboard")).status_code == 401
    assert (await client.get("/assets", headers={"Authorization": "Bearer nope"})).status_code == 401


async def test_viewer_cannot_start_investigations_or_manage_providers(client, make_user):
    viewer = await make_user("viewer1", "viewer")
    assert (await client.get("/investigations", headers=viewer)).status_code == 200
    r = await client.post("/investigate", headers=viewer, json={"ioc": "example.com"})
    assert r.status_code == 403
    r = await client.patch("/providers/dns", headers=viewer, json={"enabled": False})
    assert r.status_code == 403
    assert (await client.get("/audit-logs", headers=viewer)).status_code == 403


async def test_analyst_permissions(client, make_user):
    analyst = await make_user("analyst1", "analyst")
    assert (await client.get("/providers", headers=analyst)).status_code == 200
    assert (
        await client.put("/providers/virustotal/api-key", headers=analyst, json={"api_key": "x"})
    ).status_code == 403
    assert (await client.get("/users", headers=analyst)).status_code == 403


async def test_investigate_rejects_invalid_ioc(client, admin_headers):
    r = await client.post("/investigate", headers=admin_headers, json={"ioc": "not a valid ioc!!"})
    assert r.status_code == 422


async def test_bulk_investigate_dedupes_and_rejects(client, admin_headers, app, monkeypatch):
    scheduled: list[str] = []
    monkeypatch.setattr(app.state.runner, "schedule", lambda inv_id: scheduled.append(inv_id))
    r = await client.post(
        "/bulk-investigate",
        headers=admin_headers,
        json={
            "iocs": ["example.com", "EXAMPLE.com", "bad ioc", "# comment", "8.8.8.8"],
            "options": {"screenshots": False},
        },
    )
    assert r.status_code == 202
    body = r.json()
    assert len(body["investigation_ids"]) == 2
    assert {x["reason"] for x in body["rejected"]} >= {"duplicate"}
    assert len(scheduled) == 2
    listing = await client.get(f"/investigations?bulk_id={body['bulk_id']}", headers=admin_headers)
    assert listing.json()["total"] == 2


async def test_investigation_lifecycle_endpoints(client, admin_headers, app, monkeypatch):
    monkeypatch.setattr(app.state.runner, "schedule", lambda inv_id: None)
    created = await client.post(
        "/investigate", headers=admin_headers, json={"ioc": "hxxps://login[.]example[.]com/a", "tags": ["Phish"]}
    )
    assert created.status_code == 202
    inv = created.json()
    assert inv["ioc_type"] == "url" and inv["normalized"] == "https://login.example.com/a"
    assert inv["tags"] == ["phish"]
    assert set(inv["stages"]) == {"collection", "enrichment", "pivot", "correlation"}
    inv_id = inv["id"]

    detail = await client.get(f"/investigation/{inv_id}", headers=admin_headers)
    assert detail.status_code == 200
    note = await client.post(f"/investigation/{inv_id}/notes", headers=admin_headers, json={"text": "suspicious"})
    assert note.json()["notes"][0]["text"] == "suspicious"
    assert (await client.get("/investigation/missing", headers=admin_headers)).status_code == 404
    assert (await client.get(f"/investigation/{inv_id}/assets", headers=admin_headers)).json()["total"] == 0
    assert (await client.get(f"/investigation/{inv_id}/artifacts", headers=admin_headers)).json() == []
    assert (await client.get(f"/investigation/{inv_id}/provider-runs", headers=admin_headers)).json() == []
    filtered = await client.get("/investigations?q=login.example", headers=admin_headers)
    assert filtered.json()["total"] == 1
    deleted = await client.delete(f"/investigation/{inv_id}", headers=admin_headers)
    assert deleted.status_code == 200
    assert (await client.get(f"/investigation/{inv_id}", headers=admin_headers)).status_code == 404


async def test_provider_admin_endpoints(client, admin_headers):
    listed = (await client.get("/providers", headers=admin_headers)).json()
    names = {p["name"] for p in listed}
    assert {
        "dns",
        "rdap",
        "whois",
        "crtsh",
        "wayback",
        "cymru",
        "abuseipdb",
        "greynoise",
        "virustotal",
        "censys",
        "urlscan",
        "fofa",
    } <= names
    vt = next(p for p in listed if p["name"] == "virustotal")
    assert vt["category"] == "credit" and vt["enabled"] is False and vt["requires_api_key"] is True

    upd = await client.patch("/providers/wayback", headers=admin_headers, json={"enabled": False, "priority": 7})
    assert upd.status_code == 200 and upd.json()["enabled"] is False and upd.json()["priority"] == 7
    key = await client.put("/providers/virustotal/api-key", headers=admin_headers, json={"api_key": "1234567890abcdef"})
    assert key.json()["has_api_key"] is True
    assert key.json()["api_key_masked"] == "1234********cdef"
    assert (await client.put("/providers/dns/api-key", headers=admin_headers, json={"api_key": "x"})).status_code == 400
    assert (await client.delete("/providers/virustotal/api-key", headers=admin_headers)).json()["has_api_key"] is False
    assert (await client.get("/providers/nope", headers=admin_headers)).status_code == 404
    cleared = await client.post("/providers/dns/cache/clear", headers=admin_headers)
    assert cleared.status_code == 200
    assert (await client.get("/providers/usage", headers=admin_headers)).status_code == 200

    audit = (await client.get("/audit-logs?action=provider.", headers=admin_headers)).json()
    actions = {i["action"] for i in audit["items"]}
    assert {"provider.update", "provider.api_key.set", "provider.api_key.delete"} <= actions


async def test_user_admin(client, admin_headers):
    created = await client.post(
        "/users", headers=admin_headers, json={"username": "bob", "password": "BobPass!123", "role": "viewer"}
    )
    assert created.status_code == 201
    dup = await client.post(
        "/users", headers=admin_headers, json={"username": "bob", "password": "BobPass!123", "role": "viewer"}
    )
    assert dup.status_code == 409
    uid = created.json()["id"]
    upd = await client.patch(f"/users/{uid}", headers=admin_headers, json={"role": "analyst", "disabled": True})
    assert upd.json()["role"] == "analyst" and upd.json()["disabled"] is True
    assert (await client.post("/auth/login", json={"username": "bob", "password": "BobPass!123"})).status_code == 401
    me = (await client.get("/auth/me", headers=admin_headers)).json()
    assert (await client.delete(f"/users/{me['id']}", headers=admin_headers)).status_code == 400
    assert (await client.patch(f"/users/{me['id']}", headers=admin_headers, json={"role": "viewer"})).status_code == 400
    assert (await client.delete(f"/users/{uid}", headers=admin_headers)).status_code == 200


async def test_dashboard_shape(client, admin_headers):
    data = (await client.get("/dashboard", headers=admin_headers)).json()
    assert set(data["stats"]) >= {
        "investigations_today",
        "assets_discovered",
        "threat_clusters",
        "high_confidence_findings",
    }
    assert len(data["activity"]) == 14
    for key in ("recent_investigations", "recent_clusters", "recent_screenshots"):
        assert isinstance(data[key], list)


@pytest.mark.parametrize("sort", ["bogus", "password_hash"])
async def test_asset_sort_is_whitelisted(client, admin_headers, sort):
    assert (await client.get(f"/assets?sort={sort}", headers=admin_headers)).status_code == 422


async def test_file_endpoint_requires_auth_and_handles_missing(client, admin_headers):
    assert (await client.get("/files/507f1f77bcf86cd799439011")).status_code == 401
    assert (await client.get("/files/507f1f77bcf86cd799439011", headers=admin_headers)).status_code == 404
    token = admin_headers["Authorization"].split()[1]
    assert (await client.get(f"/files/not-an-id?access_token={token}")).status_code == 404
