# Developer guide

## Layout

```
backend/
  app/
    main.py                FastAPI factory + lifespan (Mongo, providers, runner, browser)
    cli.py                 db-setup · create-user · reset-password · seed
    seed.py                demo dataset (uses the real correlation/cluster engines)
    core/                  config (pydantic-settings), security (JWT, bcrypt, RBAC, Fernet), logging
    db/                    Motor client, GridFS, index definitions
    models/                Pydantic v2 API/domain models
    repositories/          thin async data access (assets, artifacts, relationships, users, investigations)
    providers/             base contract, registry, manager, free/ and credit/ implementations
    collectors/            web (curl_cffi), tls, favicon, browser (Playwright)
    fingerprints/          website, images, similarity
    analysis/              content validation, brand impersonation, correlation
    pipeline/              runner, context, web_profile, stages/{collection,enrichment,pivot,correlation}
    graph/                 NetworkX builder + React Flow serialisation
    services/              audit, progress hub, metrics, dashboard, clusters, scoring config, bootstrap
    reporting/             data assembly, PDF, HTML, CSV/JSON
    api/                   deps (auth/RBAC), routes/*
  tests/                   pytest (asyncio) against a real local MongoDB database `tim_test`
frontend/
  src/
    components/ui/         shadcn-style primitives (Radix + Tailwind v4 tokens)
    components/            ResultsTable, panels, dialogs, graph node, layout
    pages/                 one file per route
    hooks/                 useAuth, useWebSocket
    lib/api.ts             typed API client (JWT, blobs, WS URLs)
    types/api.ts           API types mirroring backend models
  e2e/                     Playwright end-to-end tests
```

## Running in development

```bash
run_backend.bat --reload
```

```bash
run_frontend.bat
```

API docs: http://127.0.0.1:8000/docs (Swagger) and `/redoc`. The UI proxies `/api` and `/api/ws/*` to the backend, so no CORS setup is needed during development.

## Quality gates

| Check | Command |
|---|---|
| Backend tests + coverage (≥ 85 %) | `cd backend && .venv\Scripts\python.exe -m pytest --cov=app` |
| Lint / format | `.venv\Scripts\python.exe -m ruff check app tests` · `ruff format app tests` |
| Type checking | `.venv\Scripts\python.exe -m mypy app` |
| Frontend unit tests | `cd frontend && npm test` |
| Frontend types / lint | `npm run typecheck` · `npm run lint` |
| End-to-end (needs seed data) | `database_setup.bat --seed` then `cd frontend && npm run test:e2e` |
| Pre-commit (git checkout) | `backend\.venv\Scripts\pre-commit install` then `pre-commit run --all-files` |

Backend tests use the `tim_test` database and never touch `tim`. Network-dependent code is exercised offline:
- a fake aiohttp session for providers;
- a local aiohttp HTTP/TLS server for collectors;
- patched DNS and WHOIS;
- fake collectors for the full pipeline.

## Adding an intelligence provider

1. Create `app/providers/free/<name>.py` or `credit/<name>.py`:

```python
class MyProvider(BaseProvider):
    name = "myprov"
    display_name = "My Provider"
    description = "What it returns"
    category = "free"                       # or "credit"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.IP})
    supported_pivots = frozenset({"favicon_mmh3"})   # optional
    requires_api_key = False
    accepts_api_key = True
    default_priority = 40
    default_cache_ttl_hours = 24

    async def query(self, ioc, ctx):
        data = await self.get_json(ctx, "https://api.example/lookup", params={"q": ioc.value},
                                   headers={"Authorization": f"Bearer {ctx.api_key}"} if ctx.api_key else None)
        return ProviderResult(
            summary={"score": data["score"]},
            related=[RelatedEntity(type="ip", value=ip, relation=RelationType.RESOLVES_TO) for ip in data["ips"]],
            raw=data, credits_used=1,
        )
```

2. Register the class in `app/providers/registry.py`. A configuration document is created on the next start.
3. `ProviderManager` provides caching, accounting, health, daily limits, key decryption, and error isolation. Raise `ProviderNotConfiguredError` or `ProviderRateLimitedError` from the base helpers for correct health states.
4. Every `RelatedEntity` becomes an asset plus a graph edge automatically. Pick an existing `RelationType`, or add one in `app/models/graph.py`.
5. Add an offline test in `tests/test_providers_http.py` using `FakeSession`.

## Adding a pipeline stage

Implement `Stage` (`name: StageName`, `async def run(ctx) -> str | None`) and register it in `default_stages()`. Use these context helpers:
- `ctx.progress()` and `ctx.log()` for live UI updates;
- `ctx.add_asset()`, `ctx.link()`, and `ctx.apply_related()` to write the graph;
- `ctx.record_provider_run()` to log provider calls;
- `ctx.check_cancelled()` at await boundaries.

## Adding a correlation feature

1. Add a weight and label in `app/models/scoring.py` (`DEFAULT_WEIGHTS`, `FEATURE_LABELS`).
2. Emit the evidence in `score_candidate()` (`app/analysis/correlation.py`), either from shared fingerprint nodes (`NODE_FEATURE_RELATIONS`) or from fingerprint similarity.
3. It appears automatically in the scoring editor, the evidence sidebar, reports, and CSV exports.

## Conventions

- Asset and edge IDs are deterministic hashes, so writes are idempotent upserts.
- Never trust collected content:
  - keep the SSRF checks in `collectors/web.py`;
  - serve collected files as attachments;
  - escape everything in reports.
- API routes must declare a permission through `require(...)` and call `audit(...)` for state-changing actions.
- The browser engine runs Playwright on its own Proactor event-loop thread (Windows-safe with any uvicorn loop). Call it only via `BrowserEngine.instance().capture()`.
