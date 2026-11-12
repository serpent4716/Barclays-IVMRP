"""Generates all HTML pages: login, one dashboard per role, one page per API call."""
import json
H=lambda t,b,a='':f'<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>{t}</title><link rel="icon" type="image/svg+xml" href="favicon.svg"><link rel=stylesheet href=style.css><script>document.documentElement.setAttribute("data-theme",localStorage.theme||"light");</script><script src="https://cdn.jsdelivr.net/npm/chart.js"></script></head><body {a}><header id=top></header><main>{b}</main><script src=app.js></script></body></html>'
DASH={'executive':('Executive / CISO','kpis,urgency,bu,top,paths,aistatus,ask'),
'analyst':('Security Analyst','kpis,urgency,pipe,allf,sources,paths,aistatus,ask,exc'),
'manager':('Vulnerability Manager / BU Manager','kpis,teams,overdue,tasks,exc,tickets'),
'owner':('Fix Team / Asset Owner','tasks,exc,ask'),
'auditor':('Auditor','exc,audit,routing,config'),
'admin':('Platform Administrator','kpis,aistatus,pipe,sources,routing,assets,config,audit,tickets')}
APIS=[('login','POST','/api/login','Any','{"username":"analyst","password":"analyst123"}','Authenticate, returns cryptographically signed token'),
('signup','POST','/api/signup','Any','{"username":"newanalyst","password":"secretpassword123","full_name":"New Security Analyst","role":"analyst"}','Public user sign up, creates account and returns signed token'),
('me','GET','/api/me','any logged-in','','Current authenticated user profile and team scoping'),
('users_list','GET','/api/users','admin, auditor','','List registered platform users'),
('users_add','POST','/api/users','admin','{"username":"dev1","password":"devpassword123","role":"owner","team":"backend-dev-team","full_name":"Lead Dev"}','Register a new team member'),
('pipeline_run','POST','/api/pipeline/run','admin, analyst','','Ingest 8 sources, normalize, dedup, score, route, create tasks'),
('sources_upload','POST','/api/sources/upload','admin, analyst','[{"host":"10.10.1.15","cve_id":"CVE-2021-44228","first_seen":"2026-11-11"}]','Dynamic scan ingestion (JSON or CSV) without data loss'),
('feeds_sync','POST','/api/feeds/sync','admin, analyst','','Sync live CISA Known Exploited Vulnerabilities catalog'),
('sources','GET','/api/sources','any logged-in','','Finding sources and record counts'),
('teams','GET','/api/teams','any','','Routing rules + team workload'),
('assets_list','GET','/api/assets','any','','Asset inventory'),
('assets_add','POST','/api/assets','admin','{"asset_id":"AST-0013","name":"new-app","business_unit":"Retail","owner":"retail-web-team","criticality":"medium","internet_exposed":false,"crown_jewel":false,"sensitive_data":false,"regulatory_relevance":false,"ip":"10.10.7.7"}','Register asset'),
('findings_list','GET','/api/findings?limit=20','any','','Findings ranked by risk (filters: urgency, fix_team, risk_level, business_unit, status)'),
('finding_risk','GET','/api/findings/FND-000001/risk','any','','Explainable score breakdown'),
('finding_detail','GET','/api/findings/FND-000001/detail','any','','Plain-English explanation of a risk: what it is, why it is here, score factors, owner, fix'),
('attack_paths','GET','/api/attack-paths','any','','Internet to crown-jewel paths'),
('attack_paths_graph','GET','/api/attack-paths/graph','any','','Network attack path topology graph nodes and edges'),
('tasks_list','GET','/api/tasks?team=frontend-team','any','','Remediation queue (filters: team, urgency, status)'),
('task_update','PATCH','/api/tasks/TASK-0001','admin, analyst, manager, owner','{"status":"IN_PROGRESS"}','Update remediation status'),
('task_reassign','PATCH','/api/tasks/TASK-0001/reassign','admin, analyst, manager','{"team":"platform-team"}','Change the fixing team'),
('sla_overdue','GET','/api/sla/overdue','any','','Overdue tasks + escalation'),
('jobs_expiry','POST','/api/jobs/check-sla-and-expiry','admin, manager, analyst','','Automated exception expiry and SLA escalation scan'),
('tickets','GET','/api/tickets','any','','Simulated JIRA tickets'),
('exceptions_list','GET','/api/exceptions','any','','Exceptions'),
('exception_request','POST','/api/exceptions','admin, analyst, owner','{"finding_id":"FND-000003","reason":"Needs maintenance window","days":30}','Request exception'),
('exception_decision','POST','/api/exceptions/EXC-001/decision','admin, manager','{"decision":"APPROVED"}','Approve / reject'),
('analytics','GET','/api/analytics','any','','KPIs, urgency, SLA, MTTR, BU and team workload'),
('audit','GET','/api/audit','admin, auditor','','Audit trail'),
('config','GET','/api/config','admin, auditor','','Scoring weights and SLA days'),
('config_update','PUT','/api/config','admin','{"weights":{"cvss":0.35,"epss":0.25},"sla_days":{"EMERGENCY":2,"HIGH":7}}','Update scoring weights and SLA urgency days'),
('ai_status','GET','/api/ai/status','any','','Is Gemini configured? (never returns the key)'),
('ask','POST','/api/ask','any','{"question":"what must the frontend team fix?"}','Gemini (or rules fallback) natural-language Q&A'),
('finding_explain','POST','/api/findings/FND-000001/explain','any','','Gemini explanation + remediation steps'),
('ai_summary','POST','/api/ai/executive-summary','any','','Gemini executive summary')]
rows=''
for s,m,p,r,b,d in APIS:
    box=f'<p>Body:<textarea id=body>{b}</textarea></p>' if m in('POST','PATCH','PUT') else ''
    open(f'static/api_{s}.html','w').write(H(f'API: {m} {p}',f'<div class=card><h2>{m} <input id=path value="{p}" size=45></h2><p>{d}<br>Allowed roles: <b>{r}</b></p>{box}<button onclick=runApi()>Call API</button> <b id=status></b><div id=tbl></div><pre id=out></pre></div>',f'data-method={m}'))
    rows+=f'<tr><td><a href=api_{s}.html>api_{s}.html</a></td><td>{m}</td><td>{p}</td><td>{r}</td><td>{d}</td></tr>'
open('static/api_index.html','w').write(H('API pages',f'<div class=card><h2>One page per API call</h2><table><tr><th>Page<th>Method<th>Endpoint<th>Roles<th>Purpose</tr>{rows}</table></div>'))
for k,(n,w) in DASH.items(): open(f'static/dashboard_{k}.html','w').write(H(n,'<div id=welcome></div><div id=alerts></div><div id=w class=grid></div>',f'data-widgets="{w}"'))
open('static/index.html','w').write(H('Sign In or Register · VulnIQ',''))
