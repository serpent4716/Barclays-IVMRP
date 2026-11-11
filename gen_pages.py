"""Generates all HTML pages: login, one dashboard per role, one page per API call."""
import json
H=lambda t,b,a='':f'<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>{t}</title><link rel=stylesheet href=style.css></head><body {a}><header id=top></header><main>{b}</main><script src=app.js></script></body></html>'
DASH={'executive':('Executive / CISO','kpis,urgency,bu,top,paths,aistatus,ask'),
'analyst':('Security Analyst','kpis,urgency,pipe,allf,sources,paths,aistatus,ask,exc'),
'manager':('Vulnerability Manager / BU Manager','kpis,teams,overdue,tasks,exc,tickets'),
'owner':('Fix Team / Asset Owner','tasks,exc,ask'),
'auditor':('Auditor','exc,audit,routing,config'),
'admin':('Platform Administrator','kpis,aistatus,pipe,sources,routing,assets,config,audit,tickets')}
APIS=[('login','POST','/api/login','Any','{"username":"analyst","password":"analyst123"}','Authenticate, returns token'),
('pipeline_run','POST','/api/pipeline/run','admin, analyst','','Ingest 8 sources, normalize, dedup, score, route, create tasks'),
('sources','GET','/api/sources','any logged-in','','Finding sources and record counts'),
('teams','GET','/api/teams','any','','Routing rules + team workload'),
('assets_list','GET','/api/assets','any','','Asset inventory'),
('assets_add','POST','/api/assets','admin','{"asset_id":"AST-0013","name":"new-app","business_unit":"Retail","owner":"retail-web-team","criticality":"medium","internet_exposed":false,"crown_jewel":false,"sensitive_data":false,"regulatory_relevance":false,"ip":"10.10.7.7"}','Register asset'),
('findings_list','GET','/api/findings?limit=20','any','','Findings ranked by risk (filters: urgency, fix_team, risk_level, business_unit, status)'),
('finding_risk','GET','/api/findings/FND-000001/risk','any','','Explainable score breakdown'),
('finding_detail','GET','/api/findings/FND-000001/detail','any','','Plain-English explanation of a risk: what it is, why it is here, score factors, owner, fix'),
('attack_paths','GET','/api/attack-paths','any','','Internet to crown-jewel paths'),
('tasks_list','GET','/api/tasks?team=frontend-team','any','','Remediation queue (filters: team, urgency, status)'),
('task_update','PATCH','/api/tasks/TASK-0001','admin, analyst, manager, owner','{"status":"IN_PROGRESS"}','Update remediation status'),
('task_reassign','PATCH','/api/tasks/TASK-0001/reassign','admin, analyst, manager','{"team":"platform-team"}','Change the fixing team'),
('sla_overdue','GET','/api/sla/overdue','any','','Overdue tasks + escalation'),
('tickets','GET','/api/tickets','any','','Simulated JIRA tickets'),
('exceptions_list','GET','/api/exceptions','any','','Exceptions'),
('exception_request','POST','/api/exceptions','admin, analyst, owner','{"finding_id":"FND-000003","reason":"Needs maintenance window","days":30}','Request exception'),
('exception_decision','POST','/api/exceptions/EXC-001/decision','admin, manager','{"decision":"APPROVED"}','Approve / reject'),
('analytics','GET','/api/analytics','any','','KPIs, urgency, SLA, MTTR, BU and team workload'),
('audit','GET','/api/audit','admin, auditor','','Audit trail'),
('config','GET','/api/config','admin, auditor','','Scoring weights and SLA days'),
('ai_status','GET','/api/ai/status','any','','Is Gemini configured? (never returns the key)'),
('ask','POST','/api/ask','any','{"question":"what must the frontend team fix?"}','Gemini (or rules fallback) natural-language Q&A'),
('finding_explain','POST','/api/findings/FND-000001/explain','any','','Gemini explanation + remediation steps'),
('ai_summary','POST','/api/ai/executive-summary','any','','Gemini executive summary')]
rows=''
for s,m,p,r,b,d in APIS:
    box=f'<p>Body:<textarea id=body>{b}</textarea></p>' if m in('POST','PATCH') else ''
    open(f'static/api_{s}.html','w').write(H(f'API: {m} {p}',f'<div class=card><h2>{m} <input id=path value="{p}" size=45></h2><p>{d}<br>Allowed roles: <b>{r}</b></p>{box}<button onclick=runApi()>Call API</button> <b id=status></b><div id=tbl></div><pre id=out></pre></div>',f'data-method={m}'))
    rows+=f'<tr><td><a href=api_{s}.html>api_{s}.html</a></td><td>{m}</td><td>{p}</td><td>{r}</td><td>{d}</td></tr>'
open('static/api_index.html','w').write(H('API pages',f'<div class=card><h2>One page per API call</h2><table><tr><th>Page<th>Method<th>Endpoint<th>Roles<th>Purpose</tr>{rows}</table></div>'))
for k,(n,w) in DASH.items(): open(f'static/dashboard_{k}.html','w').write(H(n,'<div id=welcome></div><div id=w class=grid></div>',f'data-widgets="{w}"'))
open('static/index.html','w').write(H('Welcome','<section class=hero><h1>Vulnerability management in one place</h1><p>This tool collects security weaknesses from many scanners, scores how dangerous each one is for <i>our</i> business, tells you <b>who must fix it</b> and <b>how fast</b>, and tracks it until it is closed.</p><div class=steps><span>1 Collect</span><span>2 Score</span><span>3 Assign</span><span>4 Track</span></div><p><b>New here?</b> Pick the role that matches your job below. You can switch role any time from the ☰ menu at the top right.</p></section><div id=roles class=rolegrid></div>'))
