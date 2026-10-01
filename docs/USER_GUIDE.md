# User guide

TIM answers one question: **what infrastructure belongs to the same operation as this indicator?** It does not ask whether a domain is malicious.

## Roles

| Role | Can |
|---|---|
| viewer | Read dashboards, investigations, assets, clusters, graphs, cases and providers |
| analyst | Everything a viewer can, plus start investigations, upload artefacts, manage cases and tags, and export reports |
| admin | Everything, plus provider configuration and API keys, scoring model, user management, cluster rebuilds, and audit logs |

## 1. Start an investigation

**Investigations → Single IOC.** Paste a domain, URL, IP address, or certificate SHA-256/SHA-1. Defanged input such as `hxxps://login[.]example[.]com` is accepted. Expand **Investigation options** to set:

- **Credit-based sources.**
  - *Only when needed* (default): VirusTotal, Censys, urlscan, and FOFA are queried only if free sources found fewer than 5 infrastructure assets, or the site was unreachable.
  - *Never*: free sources only.
  - *Always*: every enabled credit source.
- **Brand to protect / legitimate brand domains.** Enables precise impersonation scoring, and stops your own domains from being flagged.
- **Max pivot expansions.** How many discovered candidates get a full web profile.
- **Capture screenshots / Expand pivots.**

**Bulk** accepts up to 500 IOCs (one per line, `#` comments ignored). **Artefact upload** accepts:
- a **logo**, registered as a brand reference, plus matching of look-alike logos and favicons;
- a **screenshot**, matched against visually similar pages;
- **HTML**, with trackers, forms, and structure extracted and pivoted;
- a **certificate** (PEM/DER), fingerprinted, with hosts using it listed, and optionally investigated.

## 2. Follow progress live

The investigation page streams progress over WebSocket. There are four stages: **Collection → Enrichment → Pivot → Correlation**. Each shows a progress bar, a status message, and an event log. Cancel a running investigation, or re-run a finished one, from the header.

Tabs:
- **Overview.** Web profile (final URL, status, server, TLS, favicon), infrastructure (IPs, nameservers, MX, ASN, hosting, registrar, dates), **Content validation**, **Brand impersonation**, **Website fingerprints**, and screenshots (desktop, mobile, full page). Click a screenshot to enlarge it.
- **Results.** Every related asset (see the results table below).
- **Event log, Provider runs** (every source call: cached, skipped, error, latency), **Artifacts** (raw evidence downloads), and **Notes**.

### Site status (Content Validation)

| Status | Meaning |
|---|---|
| ACTIVE | Serving real content or a live credential form |
| INACTIVE | NXDOMAIN, connection refused, 404/410, soft-404, or a default server page |
| PARKED | For-sale or parking pages, parking nameservers, or parking-provider markup |
| TAKEDOWN | Suspended, disabled, seized, or removed-for-abuse pages; `clientHold`/`serverHold` registry status; HTTP 451 |
| ERROR | Collection failed for other reasons (TLS errors, 5xx…) |

### Brand impersonation

**Brand similarity** combines brand tokens in the domain (including homoglyph, leet, and typosquat variants), brand mentions in the title and content, and logo perceptual-hash similarity. **Impersonation confidence** adds credential-harvesting evidence on top of that:
- login or password fields;
- forms posting to another host;
- Telegram bot exfiltration;
- login/verify/secure/… keywords in the domain or page.

Legitimate brand domains score 0.

## 3. Results table

On investigation, cluster, case, and asset lists you can:
- **search** across value, title, IP, ASN, hosting, and tags;
- **filter** by type and status;
- **sort** any column;
- **paginate**;
- **choose columns** (the choice is remembered);
- **select** rows.

**Copy:**
- copy one value per row;
- copy the selected values, URLs, domains, or IPs;
- copy all URLs, domains, or IPs.

**Export:** CSV or JSON for the selected rows or all rows. **Report** builds a server-side report for the selection.

**Open:** **Add to case**, plus per-row **Open asset** and **Open graph**.

## 4. Graph Explorer

Open it from an investigation, cluster, asset, or the sidebar.
- **Navigate:** zoom and pan, with the minimap and controls.
- **Find:** search and highlight (press Enter to zoom to matches).
- **Filter** by relationship, node type, cluster, and minimum confidence.
- **Evidence sidebar:** click a node to see its correlation evidence (feature, points, shared value) and relationships. Click an edge to see its provenance and evidence.
- **Expand:** double-click a node, or use **Expand**, to pull in its neighbourhood.

## 5. Threat clusters

Clusters form automatically when two or more hosts score at least the cluster threshold against the seed. They merge across investigations when they share members.

Each cluster has a unique ID (`TIM-CL-YYYYMMDD-XXXXXX`), plus:
- severity (from impersonation and live status);
- confidence;
- members, shared certificates, favicons, and tracking IDs;
- screenshots, evidence, and notes.

You can rename a cluster, re-rate its severity, add notes, open its graph, export it, or attach it to a case. Admins can **Re-cluster inventory** to rebuild clusters across everything collected.

## 6. Cases

Create a case (`CASE-YYYY-NNNN`) from **Cases**, or by selecting assets anywhere and clicking **Add to case**. A case has a title, description, severity, status (open, in progress, closed), tags, an assignee, linked assets, investigations, and clusters, and notes. **Export** generates a report for the whole case.

## 7. Reports

**Export** on an investigation, cluster, case, or selection, or the **Reports** page. Formats:

- **PDF.** Analyst report with TLP marking and these sections: Executive Summary, Investigation Details, Evidence, Screenshots, Threat Clusters, Related Assets, Confidence Scores, Graph Snapshot, Analyst Notes.
- **HTML.** The same content, self-contained. Print to PDF from any browser.
- **CSV.** Related assets with correlation evidence. Formula injection is neutralised.
- **JSON.** The full data model.

Reports are kept in the **Report library** unless *Save to library* is off.

## 8. Administration

- **Providers.** Enable or disable each source and set its priority (execution order), cache TTL, and daily limit. The page also shows live health, a test button, cache purge, usage counters, and a 14-day usage chart.
- **API Keys.** Add, rotate, or remove keys. Only masked values are ever displayed.
- **Settings.**
  - Users and roles.
  - **Scoring model:** feature weights, confidence thresholds, similarity thresholds, and the noisy-fingerprint limit.
  - System health and account.
- **Audit Logs.** Filter by user, action prefix (`provider.`, `export.`, `auth.`…), and result.

## Demo data

`database_setup.bat --seed` loads 10 fictional phishing operations:
- **Brands:** Contoso Bank, Fabrikam Pay, Northwind Logistics, Woodgrove Wallet, Tailspin Air, Litware Mail, Adventure Works Shop, Proseware Cloud, Wingtip Telecom, Fourth Coffee Rewards.
- **Infrastructure:** 100 domains, 30 IPs, and 15 certificates, using reserved `.test`/`.example` names and documentation IP ranges.

Clusters and scores are produced by the real engines. `--reseed` reloads it.
