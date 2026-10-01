# API documentation

Base URL: `http://127.0.0.1:8000`. In the UI the same API is reachable at `/api` through the Vite proxy.

Interactive documentation is generated from the code:
- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc
- OpenAPI 3.1 schema: http://127.0.0.1:8000/openapi.json (a snapshot is committed as [`openapi.json`](openapi.json))

## Authentication

```bash
curl -s -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"ChangeMe!2026\"}"
```

The response contains `access_token` (JWT, HS256). Send it on every request as `Authorization: Bearer <token>`. File downloads, report downloads, and WebSockets also accept the token as a query parameter (`?access_token=` for files, `?token=` for WebSockets), because `<img>` tags and `WebSocket` cannot set headers.

| Role | Permissions |
|---|---|
| viewer | `investigation:read`, `asset:read`, `case:read`, `provider:read` |
| analyst | viewer + `investigation:write`, `case:write`, `report:export`, `upload:write` |
| admin | all, including `provider:admin`, `settings:admin`, `user:admin`, `audit:read` |

Errors use FastAPI's format: `{"detail": "..."}`, or a list of validation errors with HTTP 422. Status codes: 401 not authenticated · 403 missing permission · 404 not found · 409 conflict · 413 upload too large · 415 unsupported upload · 429 login throttled.

## Common workflows

**Start an investigation** (202 Accepted; it runs in the background):

```bash
curl -s -X POST http://127.0.0.1:8000/investigate -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"ioc\":\"hxxps://login-contoso[.]example/verify\",\"options\":{\"credit_policy\":\"when_needed\",\"brand\":\"Contoso\",\"brand_domains\":[\"contoso.com\"],\"max_pivot_assets\":15},\"tags\":[\"phishing\"]}"
```

**Poll or stream progress:** `GET /investigation/{id}`, or connect to `ws://127.0.0.1:8000/ws/investigations/{id}?token=$TOKEN`.

**Results:** `GET /investigation/{id}/assets?page_size=500`, `GET /graph/{id}`, `GET /clusters?investigation_id={id}`.

**Export:**

```bash
curl -s -X POST http://127.0.0.1:8000/export/pdf -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"investigation_id\":\"inv_...\",\"tlp\":\"AMBER\",\"analyst_notes\":\"Escalated\"}" -o report.pdf
```

`ExportRequest` takes exactly one scope (`investigation_id`, `cluster_id`, `case_id`, or `asset_ids`). Optional fields: `sections` (`executive_summary`, `investigation_details`, `evidence`, `screenshots`, `threat_clusters`, `related_assets`, `confidence_scores`, `graph_snapshot`, `analyst_notes`), `min_confidence`, `max_assets`, `max_screenshots`, `analyst_notes`, `tlp`, and `save` (store in the report library; the response header `X-Report-Id` returns the stored ID).

**Uploads** are `multipart/form-data`:
- `POST /upload/logo` with `file`, `brand`, `reference`, `threshold`
- `POST /upload/screenshot` with `file`, `threshold`
- `POST /upload/html` with `file`, `page_url`, `brand`
- `POST /upload/certificate` with `file`, `investigate`

## WebSocket protocol

| Endpoint | Purpose |
|---|---|
| `/ws/investigations/{id}?token=JWT` | First message `{"type":"snapshot","investigation":{...}}`, then live events for that investigation |
| `/ws/events?token=JWT` | Live events for all investigations (used by the dashboard and list) |

Event types:
- `investigation_queued`
- `investigation_status` (`status`, plus `summary`/`error` when finished)
- `stage_started`
- `stage_progress` (`stage`, `progress`, `message`)
- `stage_event` (`stage`, `level`, `message`)
- `stage_completed`
- `stage_failed`

A `{"type":"ping"}` keep-alive is sent every 25 seconds. Close codes: 4401 invalid or missing token · 4403 forbidden · 4404 unknown investigation.

## Endpoints

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login` | Obtain a JWT access token |
| `GET` | `/auth/me` | Current user and permissions |

### Users

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List users |
| `POST` | `/users` | Create a user |
| `PATCH` | `/users/{user_id}` | Update a user |
| `DELETE` | `/users/{user_id}` | Delete a user |

### Investigations

| Method | Path | Description |
|---|---|---|
| `POST` | `/investigate` | Start an investigation from a single IOC (domain, URL, IP or certificate hash) |
| `POST` | `/bulk-investigate` | Start investigations for up to 500 IOCs |
| `GET` | `/investigations` | List investigations |
| `GET` | `/investigation/{inv_id}` | Investigation detail and stage progress |
| `DELETE` | `/investigation/{inv_id}` | Delete an investigation and its artifacts |
| `GET` | `/investigation/{inv_id}/provider-runs` | Every provider call made by the investigation |
| `GET` | `/investigation/{inv_id}/assets` | Assets found by an investigation |
| `GET` | `/investigation/{inv_id}/artifacts` | Raw collected artifacts |
| `POST` | `/investigation/{inv_id}/cancel` | Cancel a queued/running investigation |
| `POST` | `/investigation/{inv_id}/rerun` | Re-run an investigation with the same IOC and options |
| `POST` | `/investigation/{inv_id}/notes` | Add an analyst note |

### Assets

| Method | Path | Description |
|---|---|---|
| `GET` | `/assets` | Search the asset inventory |
| `GET` | `/asset/{asset_id}` | Asset detail with relationships and artifacts |
| `PUT` | `/asset/{asset_id}/tags` | Replace an asset's tags |
| `GET` | `/files/{file_id}` | Download a stored GridFS file (screenshot, HTML, favicon, upload) |

### Graph & Clusters

| Method | Path | Description |
|---|---|---|
| `GET` | `/graph/{graph_id}` | Investigation / cluster / asset relationship graph (NetworkX, React Flow format) |
| `GET` | `/clusters` | Threat clusters |
| `GET` | `/clusters/{cluster_id}` | Cluster detail |
| `PATCH` | `/clusters/{cluster_id}` | Rename, tag or re-rate a cluster |
| `POST` | `/clusters/{cluster_id}/notes` | Add an analyst note to a cluster |
| `POST` | `/clusters/rebuild` | Re-cluster the entire inventory over distinctive shared fingerprints |
| `GET` | `/settings/scoring` | Correlation scoring weights and thresholds |
| `PUT` | `/settings/scoring` | Update scoring weights and thresholds |
| `DELETE` | `/settings/scoring` | Restore default scoring |

### Cases

| Method | Path | Description |
|---|---|---|
| `POST` | `/cases` | Create a case |
| `GET` | `/cases` | List cases |
| `GET` | `/cases/{case_id}` | Case detail |
| `PATCH` | `/cases/{case_id}` | Update title, description, severity, status, tags, assignee |
| `DELETE` | `/cases/{case_id}` | Delete a case (linked data is kept) |
| `POST` | `/cases/{case_id}/links` | Add assets, investigations or clusters to a case |
| `POST` | `/cases/{case_id}/unlink` | Remove assets, investigations or clusters from a case |
| `POST` | `/cases/{case_id}/notes` | Add a case note |

### Reporting

| Method | Path | Description |
|---|---|---|
| `POST` | `/export/pdf` | Generate a PDF analyst report |
| `POST` | `/export/html` | Generate a self-contained HTML report (print to PDF) |
| `POST` | `/export/csv` | Export related assets as CSV |
| `POST` | `/export/json` | Export the full investigation data model as JSON |
| `GET` | `/reports` | Report library |
| `GET` | `/reports/{report_id}/download` | Download a stored report |
| `DELETE` | `/reports/{report_id}` | Delete a stored report |

### Uploads

| Method | Path | Description |
|---|---|---|
| `POST` | `/upload/logo` | Upload a brand logo: register as brand reference and find visually similar assets |
| `POST` | `/upload/screenshot` | Upload a screenshot and find visually similar pages |
| `POST` | `/upload/html` | Upload page HTML: extract fingerprints and pivot on trackers, title and structure |
| `POST` | `/upload/certificate` | Upload a PEM/DER certificate: fingerprint, match inventory, optionally investigate |

### Providers

| Method | Path | Description |
|---|---|---|
| `GET` | `/providers` | All providers with health and usage |
| `GET` | `/providers/usage` | Daily usage history (calls, cache hits, errors, credits) |
| `GET` | `/providers/{name}` | One provider |
| `PATCH` | `/providers/{name}` | Enable/disable, set priority, cache TTL, daily limit |
| `PUT` | `/providers/{name}/api-key` | Store an API key (encrypted at rest) |
| `DELETE` | `/providers/{name}/api-key` | Remove a stored API key |
| `POST` | `/providers/{name}/test` | Live health check against a sample IOC |
| `POST` | `/providers/{name}/cache/clear` | Purge cached responses for one provider |

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/dashboard` | Dashboard statistics, recent investigations, clusters and screenshots |
| `GET` | `/audit-logs` | Audit trail |
| `GET` | `/health` | Liveness / readiness |
| `GET` | `/metrics` | Prometheus metrics |

WebSocket endpoints `/ws/investigations/{id}` and `/ws/events` are documented above (OpenAPI does not describe WebSockets).
