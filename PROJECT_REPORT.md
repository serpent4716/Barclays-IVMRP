# Intelligent Vulnerability Management & Risk Prioritization Platform: Basic Working Prototype (v2)

All asset/company data is **synthetic**. Vulnerability IDs, titles, CVSS and CWE are real public CVEs (Log4Shell, Spring4Shell, Citrix Bleed, MOVEit, Zerologon, xz, etc.). KEV/EPSS values are **sample approximations** — refresh from CISA KEV / FIRST EPSS feeds and verify CVSS against NVD before real use.

## 1. Run it
```bash
pip install -r requirements.txt
cp .env.example .env        # then edit .env and paste your Gemini key (optional)
python app.py               # http://localhost:5000
python gen_pages.py         # only if you edit pages
```
Demo logins: one click on the login page (password = `<role>123`).

## 2. Gemini setup (.env)
| Variable | Meaning |
|---|---|
| GEMINI_API_KEY | Key from https://aistudio.google.com/apikey. Empty / placeholder = AI runs in **rules fallback mode** |
| GEMINI_MODEL | Default `gemini-2.5-flash` (change if your key uses another model) |
| GEMINI_TIMEOUT | Seconds before falling back to rules |
| PORT, DEMO_TODAY | Server port; "today" for SLA maths |
Safety design: the key stays on the server (never sent to the browser, never returned by any API); `.env` is git-ignored; Gemini only *explains* data passed to it (system prompt forbids recalculating scores); any error → automatic rule-based fallback with a note. Gemini powers 3 endpoints: `/api/ask`, `/api/findings/<id>/explain`, `/api/ai/executive-summary`.

## 3. Data and sources (8 sources, 24 raw records → 18 findings)
Network Scanner, Agent Scanner, Legacy Scanner, Cloud CSPM, Container Scanner, Penetration Test, Dependency Scan (SCA), Identity Assessment. Each source has a **field-mapping config** in `data/sources.json` (different field names per tool), so adding a source = adding JSON, not code. Duplicates are merged on (vulnerability, asset); unmapped records (e.g. `unknown-host-99`) go to an import-error list. 12 fake assets, 18 vulnerability definitions (13 real CVEs + 5 non-CVE findings), 10 asset relationships.

## 4. Who fixes it and how urgent
- **Routing** (`data/teams.json`): vulnerability category → team. java-library / web-app → backend-dev-team; frontend-lib → frontend-team; web-server / os / file-transfer → infra-ops-team; network → network-team; database → dba-team; container → platform-team; cloud → cloud-ops-team; identity → iam-ops-team; unknown → security-triage-team. The asset's business owner is kept separately (`business_owner`). Managers/analysts can **reassign** (audited).
- **Urgency**: EMERGENCY (risk ≥ 80, or known-exploited AND internet-facing → fix within 2 days), HIGH (≥ 60 → 7 days), MEDIUM (≥ 40 → 30 days), LOW (can wait → 90 days / backlog).
- **Risk score** (0–100, deterministic): CVSS×30 + KEV 20 + EPSS×15 + internet 10 + criticality ≤10 + sensitive data 5 + regulatory 3 + attack-path 7. Demo proof: xz backdoor (CVSS 10.0) on a dev laptop = 32, LOW "can wait"; Log4Shell on the payment API = 100, EMERGENCY.

## 5. Workflow
Login → pipeline (ingest → normalize → resolve asset → dedup → enrich KEV/EPSS → attack-path → score → urgency → route to team → create task with SLA due date) → fix team works its queue (`ASSIGNED → IN_PROGRESS → REMEDIATED → VERIFIED → CLOSED`) → overdue tasks escalate to the vulnerability manager → exceptions (request → manager approve/reject → expiry) → analytics + AI → everything audited.

## 6. Dashboards (6)
| Page | Role | Widgets |
|---|---|---|
| dashboard_executive | Executive / CISO | KPIs, findings by urgency, risk by BU, top risks (CVE + urgency + team), attack paths, AI summary |
| dashboard_analyst | Security Analyst | KPIs, urgency, run pipeline, all findings, sources, attack paths, AI, exceptions |
| dashboard_manager | Vuln / BU Manager | KPIs, team workload, overdue, task queue (+reassign), exceptions, tickets |
| dashboard_owner | Fix team / asset owner | Task queue with **team selector** (backend, frontend, infra...), status update, exceptions, AI |
| dashboard_auditor | Auditor | Exceptions, audit trail, routing rules, config |
| dashboard_admin | Platform Admin | KPIs, AI status, pipeline, sources, routing, assets, config, audit, tickets |

## 7. API pages (24, `static/api_*.html`, index: api_index.html)
login, pipeline_run, sources, teams, assets_list, assets_add, findings_list, finding_risk, attack_paths, tasks_list, task_update, task_reassign, sla_overdue, tickets, exceptions_list, exception_request, exception_decision, analytics, audit, config, ai_status, ask, finding_explain, ai_summary.

## 8. Testing done
Flask test client: pipeline counts, dedup, score spread, routing, attack paths, RBAC (401/403), reassign, task filters, exceptions, rules fallback, **Gemini request/response with a mocked HTTP call**, failure fallback, placeholder-key detection. **Not tested: a live call to Google's API** (no network in my sandbox), so check it once with your own key via `api_ai_status.html` then `api_ask.html`.

## 9. Token usage (estimates; I have no exact counter)
Roughly 4 characters per token.
| Round | Approx. output tokens |
|---|---|
| Round 1 (v1 platform + report + reply) | ~19,000 |
| Round 2 (data, backend rewrite, UI, tests, this report; ~44681 chars of code/data in the final project) | ~21,000 |
| Round 3 (benchmarks, new-CVE simulation, 2 documents) | ~7,000 |
| Round 4 (UI redesign, detail endpoint, docs) | ~9,000 |
| **Cumulative** | **~56,000 output tokens** (input extra: PDFs + context re-read each turn) |
Round 2 had no failed retries.

## 10. Pending
- Live-key verification of Gemini; streaming answers; conversation memory.
- Persistence (SQLite/Postgres); real auth (JWT, hashed passwords, MFA, HTTPS); server-side team scoping per user.
- Real NVD / CISA KEV / EPSS feed import; upload UI for scanner files; CWE table.
- Neo4j graph; charts/heatmaps/trends over time; search & filter UI; pagination.
- Exception-expiry job and notification delivery; editable scoring weights/routing via API.
- Unit tests (≥70% coverage), OpenAPI spec, HLD/LLD, threat model, CI/CD, Docker, dependency scan.

## 11. What could be added later, and what to use
| Area | Add later | Suggested technology |
|---|---|---|
| Storage | Persistent data, history, trend charts, backups | PostgreSQL (SQLAlchemy + Alembic migrations); SQLite is enough for a quick first step |
| Real feeds | Automatic daily import of CVE, KEV, EPSS, CWE data | NVD API 2.0, CISA KEV JSON feed, FIRST EPSS CSV; run with APScheduler or Celery beat |
| Ingestion | Upload scanner files (JSON/CSV) and API connectors | Flask upload endpoint + pandas; connectors for Nessus/Qualys/Trivy exports; a message queue (RabbitMQ/Kafka) for large volume |
| Attack paths | Real graph model, richer path scoring | Neo4j + Cypher (or NetworkX as a lighter step); cap path length to keep BFS cheap |
| Authentication | Real login, MFA, per-user data scoping | JWT/OAuth2 (Authlib), bcrypt/argon2 password hashing, SSO via OIDC (Azure AD/Okta), HTTPS (nginx) |
| AI | Live Gemini verification, streaming answers, chat memory, executive-summary export, predictive SLA-breach model | Gemini API (already wired), scikit-learn/XGBoost for forecasting, response caching to cut cost |
| Frontend | Charts, heatmaps, filters, pagination, accessibility | React or Vue + Chart.js/Recharts/D3; keep the REST API unchanged |
| Notifications | Escalation and exception-expiry alerts | Email (SMTP), Slack/Teams webhooks; a scheduled job to check due dates |
| Ticketing | Real JIRA/ServiceNow sync | Their REST APIs (simulated `/api/tickets` is the contract to replace) |
| Governance | Editable scoring weights and routing rules with audit | Admin UI + versioned config table |
| Quality | Unit/integration/E2E tests (70%+ coverage), OpenAPI spec, linting | pytest + coverage, Flask-Smorest/flasgger, Playwright, ruff, Bandit, pip-audit |
| DevOps | Containers, CI/CD, secrets management, monitoring | Docker/docker-compose, GitHub Actions, Gunicorn, a secrets manager, Prometheus/Grafana |

Suggested order: (1) database, (2) real auth, (3) real feeds, (4) tests, (5) charts UI, (6) notifications, (7) graph DB and ML.

## 12. UI notes (round 4)
Roles live in the top-right navigation menu; dashboards have welcome banner, glossary and a clickable risk detail panel (`/api/findings/<id>/detail`). Not yet done: visual testing in real browsers on several screen sizes, saved filters, charts beyond the urgency bar, dark mode.
