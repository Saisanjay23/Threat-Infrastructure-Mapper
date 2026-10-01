# Threat Infrastructure Mapper (TIM)

Local-first threat intelligence and infrastructure mapping for threat intelligence, digital risk protection, brand protection, and external attack surface teams.

> TIM does not ask *"Is this domain malicious?"* It asks *"What infrastructure belongs to the same operation?"*

Give TIM one IOC: a domain, URL, IP, or certificate hash, or an uploaded logo, screenshot, HTML file, or certificate. It returns:
- related domains, IPs, certificates, favicons, and analytics/tracking IDs;
- threat clusters with evidence-backed confidence scores;
- an interactive investigation graph;
- an analyst report.

Everything runs on one Windows 11 machine with Python, Node.js, and MongoDB. **No Docker.**

## Quick start

```bash
# Start the entire tool (Web UI + Backend API) with one command:
python run.py

# Custom port (e.g. 9000):
python run.py --port 9000

# Share via free public Cloudflare tunnel:
python run.py --share
```

Open **http://127.0.0.1:8000** and sign in with the admin credentials in `backend\.env` (default `admin` / `ChangeMe!2026`).

| Command | Purpose |
|---|---|
| `python run.py` | Starts the unified application on port 8000 and opens browser |
| `python run.py --port 9000` | Starts the application on a custom port |
| `python run.py --share` | Starts application with an encrypted public Cloudflare tunnel |
| `setup.bat` | One-time installer (dependencies + MongoDB + admin + demo data) |

## Capabilities

| Area | Highlights |
|---|---|
| Collection | Final URL, full redirect chain (HTTP and meta-refresh), headers, per-hop cookies, HTML, rendered DOM, TLS chain details, favicon, DNS (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/PTR), RDAP, WHOIS, ASN and hosting. Raw artefacts go to GridFS. |
| Screenshots | Playwright + stealth: desktop, mobile (iPhone 13), full page, thumbnail |
| Fingerprints | Certificate SHA-1/SHA-256/SPKI, issuer, subject, SAN. Title, meta, forms, scripts, external hosts. **GA (UA), GA4, GTM, Meta Pixel, LinkedIn Insight, TikTok Pixel**, AdSense, Hotjar, Clarity, Metrika. Favicon mmh3/MD5/SHA-256, pHash/aHash/dHash/wHash, DOM and text SimHash |
| Content validation | ACTIVE · INACTIVE · PARKED · TAKEDOWN · ERROR, from text, markup, DNS, and registry status, not just the HTTP code |
| Brand impersonation | Login and password forms, credential exfiltration targets, brand tokens with homoglyph/typosquat detection, logo similarity, keyword indicators. Produces a brand similarity score and an impersonation confidence score. |
| Providers | Free: crt.sh, RDAP, DNS, WHOIS, Wayback, Team Cymru, AbuseIPDB, GreyNoise. Credit: VirusTotal, Censys, urlscan, FOFA. Enable/disable, encrypted API keys, priorities, health, usage, cache, daily limits, credit policy. |
| Pivot engine | Certificate, favicon, analytics, pixel, tracking IDs, IP, ASN, hosting, nameservers, logo/HTML/title/screenshot similarity, historical screenshots and DNS. Every pivot becomes a graph relationship. |
| Correlation | Configurable weights (analytics, GTM, and pixel 40; favicon 30; certificate and logo 25; HTML 20; title 15; IP 10; ASN, nameserver, and hosting 5), with CDN and noise dampening. Levels: Very High, High, Medium, Low, Informational. |
| Clusters | Automatic grouping with unique IDs, merged across investigations: members, shared artefacts, screenshots, evidence, confidence, severity |
| Graph | NetworkX model (12 node types, 20+ relationship types). React Flow explorer with search and highlight, relationship and cluster filters, an evidence sidebar, and node expansion. |
| Workflow | Live WebSocket progress; a results table with search, filter, sort, pagination, column choice, copy actions, and export; cases; notes; tags |
| Reporting | PDF (ReportLab), HTML (print-to-PDF), CSV, and JSON, with TLP marking and a report library |
| Platform | JWT + RBAC (viewer, analyst, admin), audit log, SSRF guard, OpenAPI docs, Prometheus `/metrics`, health checks |

## Project structure

```
backend/        FastAPI app (app/), tests (tests/), requirements, pyproject (ruff, mypy, pytest)
frontend/       React + Vite + TypeScript + Tailwind + shadcn UI (src/), Playwright e2e (e2e/)
docs/           Architecture, installation, user, developer, troubleshooting, API (+ openapi.json)
*.bat           Windows setup / run scripts
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md): system diagram, data model, pipeline, scoring, security
- [Installation guide](docs/INSTALLATION.md)
- [User guide](docs/USER_GUIDE.md)
- [Developer guide](docs/DEVELOPER_GUIDE.md): extending providers, stages, and scoring; quality gates
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [API documentation](docs/API.md), plus live Swagger at http://127.0.0.1:8000/docs

## Quality

| Gate | Result |
|---|---|
| Backend tests (pytest, real MongoDB `tim_test`, network-free) | 148 passed |
| Backend coverage | 89 % (target 85 %) |
| Lint / format / types | ruff ✓ · ruff format ✓ · mypy ✓ |
| Frontend unit tests (Vitest + Testing Library) | 12 passed · `tsc` ✓ · ESLint 0 errors |
| End-to-end (Playwright, live stack + demo data) | 6 passed |

## Responsible use

TIM actively fetches and renders suspicious sites from your machine and queries third-party intelligence services. Use it only on infrastructure you are authorised to investigate, respect each provider's terms, and treat collected content as hostile. The demo dataset uses only reserved names (`.test`, `.example`), documentation IP ranges, and fictional brands.
