# Installation guide (Windows 11, no Docker)

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| Python | 3.13 (64-bit) | Install from python.org and tick "Add python.exe to PATH". The `py` launcher is used to pick 3.13 if several versions exist. |
| Node.js | LTS (20/22) or newer | Provides `npm`. Node 25 also works. |
| MongoDB Community Edition | 7.x or 8.x | Install "as a Service" (default). TIM connects to `mongodb://127.0.0.1:27017`. |
| Disk | ~2 GB | venv, node_modules and the Playwright Chromium build |

Network access is needed during setup (pip, npm, Playwright) and for live investigations. Demo data works offline.

## One-click setup

From the project folder:

```bash
setup.bat
```

`setup.bat` performs every step and is safe to re-run:

1. `install_requirements.bat`: creates `backend\.venv` with Python 3.13, installs `requirements-dev.txt`, downloads Playwright Chromium, and runs `npm install` in `frontend`.
2. Creates `backend\.env` from `.env.example` with a freshly generated `TIM_SECRET_KEY`.
3. `database_setup.bat --seed`: starts the MongoDB service if it is stopped, creates indexes, bootstraps the admin account and provider configuration, and (if you agree) loads the demo dataset.
4. Offers to launch TIM via `start_tim.bat`.

## Starting and stopping

| Script | What it does |
|---|---|
| `start_tim.bat` | Opens backend and frontend in their own console windows, waits for `/health`, then opens http://127.0.0.1:5173 |
| `run_backend.bat` | FastAPI on http://127.0.0.1:8000 (`run_backend.bat --reload` for development) |
| `run_frontend.bat` | Vite dev server on http://127.0.0.1:5173 (proxies `/api` and WebSockets to the backend) |
| `database_setup.bat [--seed\|--reseed]` | Verify MongoDB, ensure indexes and admin, optionally (re)load demo data |

Close the console windows (or press Ctrl+C) to stop.

## First login

The credentials are `TIM_ADMIN_USERNAME` / `TIM_ADMIN_PASSWORD` from `backend\.env` (default `admin` / `ChangeMe!2026`). The admin account is created only when no admin exists. **Change the password** under Settings → Users → Reset password, or run:

```bash
backend\.venv\Scripts\python.exe -m app.cli reset-password admin "a-new-strong-password"
```

## Configuration (`backend\.env`)

| Variable | Default | Purpose |
|---|---|---|
| `TIM_MONGO_URI` / `TIM_MONGO_DB` | `mongodb://127.0.0.1:27017` / `tim` | Database |
| `TIM_SECRET_KEY` | generated | Signs JWTs **and** encrypts provider API keys. Changing it invalidates sessions and stored keys. |
| `TIM_ACCESS_TOKEN_MINUTES` | 480 | Session length |
| `TIM_HOST` / `TIM_PORT` | 127.0.0.1 / 8000 | Bind address. Keep loopback unless you add TLS and a reverse proxy. |
| `TIM_CORS_ORIGINS` | localhost:5173 | Comma separated |
| `TIM_SCREENSHOTS_ENABLED` | true | Disable to skip Playwright |
| `TIM_ALLOW_PRIVATE_TARGETS` | false | SSRF guard; enable only for lab targets on private networks |
| `TIM_MAX_CONCURRENT_INVESTIGATIONS` | 4 | Pipeline concurrency |

## Provider API keys (optional)

Free sources (DNS, RDAP, WHOIS, crt.sh, Wayback, Team Cymru, GreyNoise Community) work without keys. Add keys under **Administration → API Keys** for AbuseIPDB, VirusTotal, Censys (Platform token, or API ID + secret), urlscan, and FOFA. Keys are encrypted at rest. Saving a key also enables that provider.

## Production-style build of the UI (optional)

```bash
cd frontend && npm run build
```

The static `frontend\dist` can be served by any web server that proxies `/api` to `127.0.0.1:8000`.
