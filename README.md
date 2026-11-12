# Barclays Intelligent Vulnerability Management & Risk Prioritization Platform (IVMRP)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20(WAL)-blue.svg)](https://www.sqlite.org/)
[![AI](https://img.shields.io/badge/AI-Google%20Gemini%20Flash-orange.svg)](https://aistudio.google.com/)
[![Local AI](https://img.shields.io/badge/Local%20AI-Ollama-black.svg)](https://ollama.com/)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(100%25)-brightgreen.svg)](#testing)

An enterprise vulnerability management and automated risk prioritization platform that aggregates disparate scanner feeds, calculates business-contextual risk scores (0–100), maps attack paths from internet-exposed perimeters to crown jewels, routes remediation tasks with SLA deadlines to appropriate teams, and provides natural-language AI insights.

---

## Key Features

- **Multi-Source Scanner Ingestion & Deduplication**: Normalizes records from network scanners, agent scanners, cloud CSPM, container registries, SCA, identity assessments, and manual pentests. Merges duplicates on `(vulnerability, asset)`.
- **Dynamic Scan Uploads**: Upload scanner exports via API (`POST /api/sources/upload`) or dashboard UI (JSON or CSV).
- **Explainable 0–100 Risk Engine**:
  - Technical Severity: CVSS (max 30 pts)
  - Real-World Exploitability: CISA KEV (20 pts) + FIRST EPSS (max 15 pts)
  - Business Impact: Internet exposure (10 pts), Asset criticality (up to 10 pts), Sensitive data (5 pts), Regulatory relevance (3 pts)
  - Threat Graph: Attack path influence to crown-jewel assets (7 pts)
- **Automated Routing & SLA Urgency**:
  - `EMERGENCY` (Score ≥ 80 or KEV + Internet-facing) → Fix within **2 days**
  - `HIGH` (Score ≥ 60) → Fix within **7 days**
  - `MEDIUM` (Score ≥ 40) → Fix within **30 days**
  - `LOW` (Backlog) → Fix within **90 days**
- **Non-Destructive Persistence (SQLite)**: Tasks, remediation statuses (`ASSIGNED → IN_PROGRESS → REMEDIATED → VERIFIED → CLOSED`), reassignments, exceptions, and audit logs are permanently persisted across restarts and pipeline re-runs.
- **6 Role-Tailored Dashboards**:
  - **Executive / CISO**: High-level risk posture, interactive Chart.js urgency doughnut chart, BU risk breakdown, top risks, attack path topology, and AI board summary.
  - **Security Analyst**: Full findings catalog with real-time search and multi-filter bar, scanner sources, SVG attack path topology, and AI queries.
  - **Vulnerability Manager**: Team workload visual chart, overdue escalations, alert banner, automated housekeeping scan, reassignment, and exception approval.
  - **Asset Owner / Fix Team**: Filtered remediation queues by team, real-time search, remediation advice, and exception requests.
  - **Auditor**: Full immutable audit trail, exception registry, and scoring configurations.
  - **Platform Admin**: System configuration with dynamic scoring/SLA tuning, asset inventory, pipeline controls, and AI health checks.
- **Interactive Visual Analytics & Network Topology**:
  - **Chart.js Visualizations**: Interactive doughnut chart of urgency distribution, BU comparative bar charts, and team workload/overdue distribution.
  - **Attack Path Topology Canvas**: SVG-rendered network diagram mapping attacker hops from perimeter ingress to crown jewels with clickable node inspection and active attack traversal highlighting.
  - **Client-Side Real-Time Search & Multi-Filter**: Search across findings and tasks by CVE, host, title, or owner with instantaneous urgency dropdown filtering.
  - **Automated SLA & Expiry Housekeeping**: On-demand and background engine (`POST /api/jobs/check-sla-and-expiry`) that automatically marks expired risk exceptions and restores findings to assigned queues.
  - **Dynamic Governance Tuning**: Administrators can dynamically modify intel scoring weights and SLA urgency days via `PUT /api/config` and immediate re-scoring.
- **Multi-Tier AI Layer (Gemini Cloud → Ollama Local → Rules Fallback)**: Translates technical CVE data into plain-English root causes and step-by-step remediation guidance. Checks for Google Gemini API first; if unavailable, automatically checks for local Ollama models (e.g. `deepseek-coder`); if neither is available, defaults seamlessly to deterministic rule-based explanations.

---

## Architecture

```
  [ Scanner Feeds & Dynamic Uploads (JSON/CSV) ]       [ Intel: NVD CVSS/CWE, CISA KEV, EPSS ]
                        |                                                 |
                        v                                                 |
         1. NORMALIZE (Config-driven schema mapper)                       |
                        v                                                 |
         2. RESOLVE ASSET (IP / Hostname / Alias mapping) <---------------+ [ Asset Inventory & Topology ]
                        v
         3. DEDUPLICATE (Merge sources, preserve earliest detection)
                        v
         4. ATTACK PATH BFS (Internet perimeter -> Crown jewels)
                        v
         5. DETERMINISTIC SCORING (8 weighted business & threat factors)
                        v
         6. ROUTING & SLA DUE DATES (Category -> Team & Urgency)
                        v
         7. NON-DESTRUCTIVE PERSISTENCE (data/ivmrp.db - SQLite WAL)
            * Preserves in-progress tasks, reassignments, & approved exceptions
                        v
    [ REST API & RBAC ] <---> [ 6 Role Dashboards & Interactive API Pages ]
            ^
            +---------------> [ Tiered AI: Gemini Cloud -> Ollama Local -> Rules Fallback ]
```

---

## Quickstart

### Option A: Run with Docker Compose (Recommended for Teams)
Run the entire platform in a container with persistent shared volume mounts and automatic host Ollama bridging:
```bash
git clone https://github.com/pradness/Barclays-IVMRP.git
cd Barclays-IVMRP

# Build and start in detached mode
docker compose up --build -d

# Check container status
docker compose ps
```
The application will be live at: **`http://localhost:5000`** with all changes permanently stored in `./data/ivmrp.db`.

To stop the container:
```bash
docker compose down
```

### Option B: Local Python Setup
#### 1. Prerequisites
- Python 3.10+
- `pip`
- (Optional) [Ollama](https://ollama.com/) running locally for offline on-prem AI inference

#### 2. Installation
```bash
# Optional: Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

#### 3. Configuration (Optional: Gemini AI or Ollama)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` to configure your preferred AI backend:
```ini
# Option A: Cloud AI via Google Gemini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# Option B: Local AI via Ollama (Zero Cloud Dependencies)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=deepseek-coder:latest
```

#### 4. Run Locally
```bash
python3 app.py
```
Open your browser to: **`http://localhost:5000`**

---

## Demo Role Logins

Clicking any role card on the homepage logs you in automatically. Credentials for manual login:

| Role | Username | Password | Permissions |
|---|---|---|---|
| **Platform Admin** | `admin` | `admin123` | Full system access, asset management, scan uploads, pipeline execution |
| **Security Analyst** | `analyst` | `analyst123` | View all findings, run pipeline, scan uploads, request exceptions |
| **Vulnerability Manager** | `manager` | `manager123` | Reassign tasks, approve/reject exceptions, view overdue SLA queues |
| **Fix Team / Asset Owner** | `owner` | `owner123` | Update task statuses, view team queues, request exceptions |
| **Executive / CISO** | `executive` | `executive123` | Read-only KPIs, BU breakdown, executive summaries |
| **Auditor** | `auditor` | `auditor123` | Read-only audit logs, approved exceptions, scoring configurations |

---

## Testing

Run the automated test suite covering RBAC, deduplication, scoring maths, BFS attack paths, task persistence across pipeline re-runs, dynamic scanner uploads, and fallback mode:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## API Reference

The platform includes 28 RESTful endpoints. An interactive catalog is accessible via the web interface at **`http://localhost:5000/api_index.html`**.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/login` | Authenticate with username & password; issues signed session token |
| `GET` | `/api/me` | Current authenticated user profile & team scoping |
| `GET` | `/api/users` | List registered platform users (admin, auditor) |
| `POST` | `/api/users` | Register a new team member with assigned team (admin) |
| `POST` | `/api/pipeline/run` | Trigger full ingestion, deduplication, and scoring |
| `POST` | `/api/sources/upload` | Ingest scan records dynamically (JSON or CSV) |
| `POST` | `/api/feeds/sync` | Sync live CISA Known Exploited Vulnerabilities catalog (admin, analyst) |
| `GET` | `/api/findings` | Ranked findings list (filters: `urgency`, `fix_team`, `business_unit`) |
| `GET` | `/api/findings/<id>/detail` | Plain-English risk explanation, factors, asset context, and fix steps |
| `GET` | `/api/findings/<id>/risk` | Full 8-factor score breakdown |
| `GET` | `/api/tasks` | Remediation queue (server-side scoped to user's team for fix owners) |
| `PATCH`| `/api/tasks/<id>` | Update remediation status (`IN_PROGRESS`, `REMEDIATED`, etc.) |
| `PATCH`| `/api/tasks/<id>/reassign` | Reassign task to another team |
| `GET` | `/api/attack-paths` | BFS attack paths from internet assets to crown jewels |
| `GET` | `/api/attack-paths/graph` | Network topology graph nodes, edges, and attack traversals |
| `GET` | `/api/sla/overdue` | Overdue task list with automatic escalation |
| `POST` | `/api/jobs/check-sla-and-expiry` | Automated scan for expired risk exceptions & SLA escalations |
| `POST` | `/api/exceptions` | Request temporary risk exception |
| `POST` | `/api/exceptions/<id>/decision` | Approve or reject risk exception |
| `GET` | `/api/config` | Scoring weights and SLA urgency turnaround days |
| `PUT` | `/api/config` | Dynamically update scoring weights and SLA urgency days (admin) |
| `POST` | `/api/ask` | Natural language question answering via Gemini / Ollama / rules |
| `POST` | `/api/ai/executive-summary` | 5-sentence executive summary |
| `GET` | `/api/audit` | Comprehensive audit trail |
| `GET` | `/api/analytics` | High-level KPIs, MTTR, SLA compliance, and workload stats |

---

## Repository Structure

```
Barclays-IVMRP/
├── Dockerfile               # Multi-stage lightweight Docker image (Gunicorn WSGI)
├── docker-compose.yml       # Docker orchestration with persistent volume and host networking
├── app.py                   # Flask server, REST APIs, enterprise auth, pipeline orchestration
├── db.py                    # SQLite persistence layer, user management, non-destructive upserts
├── gen_pages.py             # Static page generator for dashboards and API testing pages
├── requirements.txt         # Project dependencies (Flask 3.x, Gunicorn 21+)
├── .env.example             # Template for environment configuration
├── tests/
│   └── test_platform.py     # 17 automated unittest test suites
├── data/
│   ├── assets.json          # Synthetic asset inventory (12 assets with metadata)
│   ├── intel.json           # Real CVE definitions, CVSS, CISA KEV flags, EPSS scores, topologies
│   ├── sources.json         # 8 heterogeneous scanner configs & sample records
│   ├── teams.json           # Routing rules, team descriptions, SLA configurations
│   └── ivmrp.db             # Persistent SQLite database (created automatically; git-ignored)
├── static/
│   ├── index.html           # Authentication portal (sign in / registration)
│   ├── app.js               # Frontend single-page application router & modal system
│   ├── style.css            # Responsive layout styling and badge indicators
│   ├── favicon.svg          # Vector brand favicon
│   ├── dashboard_*.html     # 6 role-based dashboard views
│   └── api_*.html           # 34 interactive API testing pages (index: api_index.html)
├── PROJECT_REPORT.md        # Prototype development report, benchmarks, and roadmap
└── SYSTEM_GUIDE.md          # In-depth system architecture guide and delivery logs
```

---

## Further Documentation

- **[System Architecture Guide (`SYSTEM_GUIDE.md`)](SYSTEM_GUIDE.md)**: Deep dive into the data flow, risk formula breakdown, attack graph modeling, and delivery changelog.
- **[Project Report (`PROJECT_REPORT.md`)](PROJECT_REPORT.md)**: Original technical specifications, benchmark measurements, and future roadmap.

---

## License
This project is licensed under the MIT License - see the repository LICENSE file for details.
