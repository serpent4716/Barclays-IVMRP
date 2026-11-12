"""Intelligent Vulnerability Management Platform - Enterprise Edition (Flask + SQLite persistence, Gemini AI layer)."""
import json, os, csv, io, urllib.request, datetime as dt
from collections import deque
from functools import wraps
from flask import Flask, request, jsonify, has_request_context
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import db

BASE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(BASE, 'data')

def _load_env():  # tiny .env reader (no extra dependency)
    p = os.path.join(BASE, '.env')
    if os.path.exists(p):
        for ln in open(p):
            ln = ln.strip()
            if ln and not ln.startswith('#') and '=' in ln:
                k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip().strip('"\''))
_load_env()

SECRET_KEY = os.environ.get('SECRET_KEY', 'ivmrp-secret-key-enterprise-2026')
TOKEN_SERIALIZER = URLSafeTimedSerializer(SECRET_KEY, salt='ivmrp-auth')

def gkey():
    k = os.environ.get('GEMINI_API_KEY', '').strip()
    return '' if (not k or k.startswith('your_')) else k

gmodel = lambda: os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')
app = Flask(__name__, static_folder='static', static_url_path='')
TODAY = dt.date.fromisoformat(os.environ.get('DEMO_TODAY', '2026-11-11'))
ROLES = ['admin', 'analyst', 'manager', 'executive', 'auditor', 'owner']
S, AUDIT = {}, []
CRIT = {'critical': 10, 'high': 6, 'medium': 3, 'low': 0}

def get_conn():
    return db.get_connection()

def current_user():
    if not has_request_context(): return None
    if hasattr(request, '_cached_user'): return request._cached_user
    h = request.headers.get('Authorization', '')
    if not h.startswith('Bearer '):
        request._cached_user = None
        return None
    tok = h[7:].strip()
    user_info = None

    # 1. Verify signed token
    try:
        data = TOKEN_SERIALIZER.loads(tok, max_age=86400 * 7)
        if isinstance(data, dict) and 'username' in data:
            user_info = data
    except (BadSignature, SignatureExpired):
        pass

    # 2. Backward-compatible demo token: tok-<role>
    if not user_info and tok.startswith('tok-'):
        r = tok[4:]
        if r in ROLES:
            conn = get_conn()
            u = db.get_user_by_username(conn, r)
            conn.close()
            if u:
                user_info = dict(user_id=u['user_id'], username=u['username'], role=u['role'], team=u['team'], full_name=u['full_name'])
            else:
                user_info = dict(user_id=f'USR-{r}', username=r, role=r, team='backend-dev-team' if r == 'owner' else None, full_name=r.capitalize())

    request._cached_user = user_info
    return user_info

def role():
    u = current_user()
    return u['role'] if u else None

def audit(a, d):
    conn = get_conn()
    u = current_user()
    uname = u['username'] if u else 'system'
    db.log_audit(conn, uname, a, d)
    AUDIT.insert(0, {'ts': str(dt.datetime.now())[:19], 'user': uname, 'action': a, 'detail': d})
    conn.close()

def need(*rs):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = current_user()
            if not u: return jsonify(error='unauthenticated'), 401
            r = u.get('role')
            if rs and r not in rs: return jsonify(error=f'role {r} not allowed; need {rs}'), 403
            return f(*a, **k)
        return w
    return deco

lvl = lambda s: 'CRITICAL' if s >= 80 else 'HIGH' if s >= 60 else 'MEDIUM' if s >= 40 else 'LOW'
def urgency(score, kev, internet):  # emergency = very high risk OR actively exploited and internet-facing
    return 'EMERGENCY' if score >= 80 or (kev and internet) else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 40 else 'LOW'

def normalize(cfg, r):  # config-driven: source-specific field names -> common schema
    m = cfg.get('map', {})
    g = lambda k: r.get(m[k]) if k in m else r.get(k)
    return dict(cve_id=g('cve_id'), host=g('host'), first_seen=g('first_seen') or '2026-11-08', source=cfg['name'], source_type=cfg['type'])

def paths():  # BFS from internet-exposed assets to crown jewels
    adj = {}
    for a, b in S['intel']['relationships']: adj.setdefault(a, []).append(b)
    out = []
    for s in [a for a in S['assets'].values() if a['internet_exposed']]:
        q = deque([[s['asset_id']]])
        while q:
            p = q.popleft()
            if len(p) > 1 and S['assets'][p[-1]]['crown_jewel']: out.append(p)
            for n in adj.get(p[-1], []):
                if n not in p: q.append(p + [n])
    return out

def score(f):
    a, w, i = S['assets'][f['asset_id']], S['intel']['weights'], S['intel']
    kev = f['cve_id'] in i['kev']; ep = i['epss'].get(f['cve_id'], 0)
    on_path = any(f['asset_id'] in p for p in S['paths'])
    fx = [('CVSS', f['cvss_score'], f['cvss_score'] / 10 * w['cvss'], w['cvss']), ('Known Exploited (KEV)', kev, w['kev'] * kev, w['kev']),
          ('EPSS', ep, ep * w['epss'], w['epss']), ('Internet Exposure', a['internet_exposed'], w['internet'] * a['internet_exposed'], w['internet']),
          ('Asset Criticality', a['criticality'].upper(), CRIT[a['criticality']] / 10 * w['criticality'], w['criticality']),
          ('Sensitive Data', a['sensitive_data'], w['sensitive'] * a['sensitive_data'], w['sensitive']),
          ('Regulatory Impact', a['regulatory_relevance'], w['regulatory'] * a['regulatory_relevance'], w['regulatory']),
          ('Attack Path Influence', on_path, w['attack_path'] * on_path, w['attack_path'])]
    sc = round(sum(x[2] for x in fx))
    return sc, kev, ep, [dict(factor=n, value=v, points=round(p, 1), max_points=m, impact='HIGH' if p / m >= .6 else 'MEDIUM' if p / m >= .3 else 'LOW') for n, v, p, m in fx]

def build():
    """Initializes DB, normalizes scanner feeds, deduplicates, and non-destructively upserts findings and tasks."""
    conn = get_conn()
    S.clear()
    S['assets'] = db.get_assets(conn)
    S['intel'] = db.get_intel(conn)
    S['teams'] = db.get_teams(conn)
    src = db.get_sources(conn)

    S.update(findings={}, tasks={}, exceptions={}, errors=[], paths=paths(), raw=0, src_counts={})
    idx = {}
    for a in S['assets'].values():
        for k in [a['name'], a['ip']] + a['aliases']:
            if k: idx[str(k).lower()] = a['asset_id']

    dedup = {}
    for sid, cfg in src.items():  # ingest -> normalize -> resolve -> dedup
        S['src_counts'][cfg['name']] = dict(type=cfg['type'], records=len(cfg['records']))
        for r in cfg['records']:
            S['raw'] += 1
            n = normalize(cfg, r)
            aid = idx.get(str(n['host']).lower())
            if not aid or n['cve_id'] not in S['intel']['nvd']:
                S['errors'].append({'source': n['source'], 'record': r, 'error': 'unmapped asset or unknown vulnerability id'})
                continue
            k = (n['cve_id'], aid)
            if k in dedup:
                if n['source'] not in dedup[k]['sources']:
                    dedup[k]['sources'].append(n['source'])
                dedup[k]['first_seen'] = min(dedup[k]['first_seen'], n['first_seen'])
            else:
                v = S['intel']['nvd'][n['cve_id']]
                dedup[k] = dict(cve_id=n['cve_id'], real_cve=n['cve_id'].startswith('CVE-'), asset_id=aid, title=v['title'], cvss_score=v['cvss_score'], cwe=v['cwe'],
                                category=v['category'], first_seen=n['first_seen'], sources=[n['source']], status='OPEN')

    # Non-destructive upsert into persistent database
    for k, f in dedup.items():
        a = S['assets'][f['asset_id']]
        fid = db.get_or_create_finding_id(conn, f['cve_id'], f['asset_id'])
        f['finding_id'] = fid
        f['asset_name'] = a['name']
        f['business_unit'] = a['business_unit']
        f['risk_score'], f['kev'], f['epss'], f['risk_factors'] = score(f)
        f['risk_level'] = lvl(f['risk_score'])
        f['urgency'] = urgency(f['risk_score'], f['kev'], a['internet_exposed'])
        U = S['teams']['urgency'][f['urgency']]
        f['urgency_label'] = U['label']
        f['fix_team'] = S['teams']['routing'].get(f['category'], 'security-triage-team')
        f['business_owner'] = a['owner']
        f['fix_reason'] = f"{f['category']} issue -> {f['fix_team']}"
        f['status'] = 'ASSIGNED'

        tid = db.get_or_create_task_id(conn, fid)
        t_default = dict(task_id=tid, finding_id=fid, cve_id=f['cve_id'], title=f['title'], asset_name=f['asset_name'],
                         fix_team=f['fix_team'], business_owner=a['owner'], urgency=f['urgency'], status='ASSIGNED',
                         due_date=str(dt.date.fromisoformat(f['first_seen']) + dt.timedelta(days=U['sla_days'])), closed_at=None)

        db.upsert_canonical_finding_and_task(conn, f, t_default)

    # Sync fresh state from DB into memory cache
    S['findings'] = db.get_findings(conn)
    S['tasks'] = db.get_tasks(conn)
    S['exceptions'] = db.get_exceptions(conn)
    AUDIT.clear()
    AUDIT.extend(db.get_audit_log(conn))

    duplicates_merged = S['raw'] - len(S['errors']) - len(S['findings'])
    db.log_pipeline_run(conn, len(src), S['raw'], len(S['findings']), duplicates_merged, S['errors'])
    db.log_audit(conn, role() or 'system', 'pipeline_run', f"sources={len(src)} raw={S['raw']} canonical={len(S['findings'])} errors={len(S['errors'])}")
    conn.close()

def overdue(t):
    return t['status'] != 'CLOSED' and dt.date.fromisoformat(t['due_date']) < TODAY and S['findings'][t['finding_id']]['status'] != 'EXCEPTION_APPROVED'

public = lambda f: {k: v for k, v in f.items() if k != 'risk_factors'}

def stats():
    F, T = list(S['findings'].values()), list(S['tasks'].values())
    od_ = [t for t in T if overdue(t)]
    cl = [t for t in T if t.get('closed_at')]
    bu, tm, ur = {}, {}, {}
    for f in F:
        b = bu.setdefault(f['business_unit'], dict(findings=0, emergency=0, avg_risk=0))
        b['findings'] += 1
        b['emergency'] += f['urgency'] == 'EMERGENCY'
        b['avg_risk'] += f['risk_score']
        ur[f['urgency']] = ur.get(f['urgency'], 0) + 1
    for b in bu.values():
        b['avg_risk'] = round(b['avg_risk'] / b['findings'], 1)
    for t in T:
        w = tm.setdefault(t['fix_team'], dict(open=0, emergency=0, overdue=0))
        if t['status'] != 'CLOSED':
            w['open'] += 1
            w['emergency'] += t['urgency'] == 'EMERGENCY'
        w['overdue'] += overdue(t)
    open_emerg = sum(t['urgency'] == 'EMERGENCY' and t['status'] != 'CLOSED' for t in T)
    return dict(total_findings=len(F), emergency_findings=ur.get('EMERGENCY', 0), open_emergency_tasks=open_emerg,
                critical_findings=sum(f['risk_level'] == 'CRITICAL' for f in F), overdue_findings=len(od_),
                sla_compliance=round(100 * (1 - len(od_) / max(len(T), 1)), 1),
                average_mttr_days=round(sum((dt.date.fromisoformat(t['closed_at']) - dt.date.fromisoformat(S['findings'][t['finding_id']]['first_seen'])).days for t in cl) / len(cl), 1) if cl else 0,
                average_risk_score=round(sum(f['risk_score'] for f in F) / max(len(F), 1), 1), assets=len(S['assets']), sources=len(S['src_counts']),
                open_exceptions=sum(e['status'] == 'PENDING' for e in S['exceptions'].values()), by_urgency=ur, by_business_unit=bu, by_team=tm)

# ---------------- Multi-Tier AI Layer: Gemini API -> Ollama Local -> Rule-Based Fallback ----------------
SYS = ("You are the AI assistant of a vulnerability management platform. Answer ONLY from the JSON data provided. Risk score, urgency and fix team were "
       "computed by the platform's deterministic engine: explain them, never recalculate or change them. If the data lacks the answer, say so. "
       "Be concise (max 150 words) and do not invent CVE facts.")

def gemini(prompt):
    k = gkey()
    if not k: return None, 'GEMINI_API_KEY not set'
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{gmodel()}:generateContent'
    body = json.dumps({'system_instruction': {'parts': [{'text': SYS}]}, 'contents': [{'role': 'user', 'parts': [{'text': prompt}]}], 'generationConfig': {'temperature': 0.2, 'maxOutputTokens': 2048}}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, {'Content-Type': 'application/json', 'x-goog-api-key': k}), timeout=int(os.environ.get('GEMINI_TIMEOUT', '20'))) as r:
            return json.load(r)['candidates'][0]['content']['parts'][0]['text'].strip(), None
    except Exception as e:
        return None, f'Gemini call failed ({type(e).__name__})'

def ollama_host():
    return os.environ.get('OLLAMA_HOST', 'http://localhost:11434').rstrip('/')

def ollama_available():
    try:
        req = urllib.request.Request(f'{ollama_host()}/api/tags')
        with urllib.request.urlopen(req, timeout=2) as r:
            data = json.load(r)
            models = [m['name'] for m in data.get('models', [])]
            target = os.environ.get('OLLAMA_MODEL', '').strip()
            if target:
                for m in models:
                    if m == target or m.startswith(target):
                        return True, m
            if models:
                return True, models[0]
            return False, 'no models found'
    except Exception as e:
        return False, str(e)

def ollama(prompt):
    ok, model_or_err = ollama_available()
    if not ok:
        return None, f'Ollama not available ({model_or_err})', None
    url = f'{ollama_host()}/api/generate'
    payload = {
        'model': model_or_err,
        'system': SYS,
        'prompt': prompt,
        'stream': False,
        'options': {'temperature': 0.2, 'num_predict': 512}
    }
    timeout = int(os.environ.get('OLLAMA_TIMEOUT', '30'))
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.load(r)
            ans = res.get('response', '').strip()
            if ans:
                return ans, None, model_or_err
            return None, 'Ollama returned empty response', model_or_err
    except Exception as e:
        return None, f'Ollama call failed ({type(e).__name__})', model_or_err

def query_ai(prompt):
    """Tiered AI check: (1) Gemini API -> (2) Ollama Local Models -> (3) Rule-based fallback."""
    notes = []
    # 1. Try Gemini
    if gkey():
        ans, err = gemini(prompt)
        if ans: return ans, 'gemini', gmodel(), None
        if err: notes.append(err)
    else:
        notes.append('Gemini key not configured')

    # 2. Try Ollama local
    ans, err, o_model = ollama(prompt)
    if ans:
        return ans, 'ollama', o_model, '; '.join(notes) if notes else None
    if err:
        notes.append(err)

    # 3. Rule fallback
    return None, 'rules', 'rule-engine', '; '.join(notes)

def ctx(extra=None):
    F = sorted(S['findings'].values(), key=lambda f: -f['risk_score'])[:15]
    rows = [{k: f[k] for k in ('finding_id', 'cve_id', 'title', 'asset_name', 'business_unit', 'risk_score', 'urgency', 'fix_team', 'status', 'kev', 'epss')} for f in F]
    return json.dumps(dict(stats=stats(), top_findings=rows, selected=extra), default=str)

def why(f):
    return f"{f['finding_id']} ({f['cve_id']} on {f['asset_name']}) scores {f['risk_score']}/100 [{f['risk_level']}], urgency {f['urgency']} ({f['urgency_label']}); fix owner: {f['fix_team']}. Main drivers: " + ', '.join(f"{x['factor']}={x['value']} (+{x['points']})" for x in sorted(f['risk_factors'], key=lambda x: -x['points'])[:4])

@app.get('/api/ai/status')
@need()
def ai_status():
    g_ok = bool(gkey())
    o_ok, o_model = ollama_available()
    active = 'gemini' if g_ok else ('ollama' if o_ok else 'rules')
    active_model = gmodel() if active == 'gemini' else (o_model if active == 'ollama' else 'rule-engine')
    return jsonify(
        gemini_configured=g_ok,
        gemini_model=gmodel(),
        ollama_configured=o_ok,
        ollama_model=o_model if o_ok else None,
        ollama_host=ollama_host(),
        active_backend=active,
        model=active_model,
        mode=active
    )

def rjson():
    return request.get_json(silent=True) or {}

@app.post('/api/ask')
@need()
def ask():
    q = (rjson().get('question') or '').strip()
    F = sorted(S['findings'].values(), key=lambda f: -f['risk_score'])
    sel = next((f for f in F if f['finding_id'].lower() in q.lower()), None)
    ans, source, model, note = query_ai(f"DATA: {ctx(sel)}\n\nQUESTION: {q}")
    if ans:
        return jsonify(answer=ans, source=source, model=model, note=note)

    r_ans = None
    q_low = q.lower()
    if sel:
        r_ans = why(sel)
    elif 'overdue' in q_low:
        o = [t for t in S['tasks'].values() if overdue(t)]
        r_ans = f'{len(o)} overdue: ' + ', '.join(f"{t['task_id']} ({t['fix_team']})" for t in o)
    elif 'internet' in q_low:
        r_ans = 'Internet-facing: ' + ', '.join(f"{f['finding_id']} {f['asset_name']} ({f['risk_score']})" for f in F if S['assets'][f['asset_id']]['internet_exposed'])
    elif 'path' in q_low:
        r_ans = 'Attack paths: ' + '; '.join(' > '.join(S['assets'][x]['name'] for x in p) for p in S['paths'])
    else:
        for tm in S['teams']['description']:
            if tm in q_low or tm.split('-')[0] in q_low:
                r_ans = f'{tm} must fix: ' + ', '.join(f"{f['finding_id']} {f['cve_id']} [{f['urgency']}]" for f in F if f['fix_team'] == tm)
                break
    if not r_ans and any(w in q_low for w in ('top', 'highest', 'priorit', 'first', 'emergency', 'urgent')):
        r_ans = 'Top priority -> ' + why(F[0])
    if not r_ans:
        for bu in {x['business_unit'] for x in F}:
            if bu.lower() in q_low:
                r_ans = f'{bu}: ' + ', '.join(f"{f['finding_id']}={f['risk_score']}" for f in F if f['business_unit'] == bu)
                break
    return jsonify(
        answer=r_ans or "Try: 'top risk', 'why is FND-000001 urgent', 'overdue', 'internet facing', 'attack paths', 'what must frontend team fix', 'Finance risk'.",
        source='rules',
        model='rule-engine',
        note=note
    )

@app.post('/api/findings/<fid>/explain')
@need()
def explain(fid):
    f = S['findings'].get(fid)
    if not f: return jsonify(error='not found'), 404
    ans, source, model, note = query_ai(f"DATA: {ctx(f)}\n\nFor the selected finding give: (1) why it has urgency {f['urgency']}, (2) 3 concrete remediation steps for {f['fix_team']}, (3) whether it can wait and why.")
    if ans:
        return jsonify(answer=ans, source=source, model=model, note=note)
    return jsonify(answer=why(f) + ' Recommended: apply the vendor patch/fix, verify, then close the task.', source='rules', model='rule-engine', note=note)

@app.post('/api/ai/executive-summary')
@need()
def exec_summary():
    ans, source, model, note = query_ai(f"DATA: {ctx()}\n\nWrite a 5-sentence board-style executive summary: overall posture, what is most urgent, which teams are loaded, SLA status, one recommended action.")
    if ans:
        return jsonify(answer=ans, source=source, model=model, note=note)
    s = stats()
    return jsonify(answer=f"{s['total_findings']} findings across {s['assets']} assets from {s['sources']} sources; {s['emergency_findings']} need emergency action; {s['overdue_findings']} overdue; SLA compliance {s['sla_compliance']}%.", source='rules', model='rule-engine', note=note)

# ---------------- REST API ----------------
@app.post('/api/login')
def login():
    b = rjson()
    u_name = (b.get('username') or '').strip().lower()
    pwd = b.get('password') or ''
    if not u_name or not pwd:
        return jsonify(error='username and password required'), 400

    conn = get_conn()
    user = db.get_user_by_username(conn, u_name)
    conn.close()

    # Verify hashed password (works with both seeded and newly registered users)
    if not user or not check_password_hash(user['password_hash'], pwd):
        return jsonify(error='invalid credentials'), 401

    token = TOKEN_SERIALIZER.dumps(dict(
        user_id=user['user_id'],
        username=user['username'],
        role=user['role'],
        team=user['team'],
        full_name=user['full_name']
    ))
    audit('login', user['username'])
    return jsonify(
        token=token,
        role=user['role'],
        username=user['username'],
        user_id=user['user_id'],
        team=user['team'],
        full_name=user['full_name']
    )

@app.post('/api/signup')
def signup():
    b = rjson()
    u_name = (b.get('username') or '').strip().lower()
    pwd = b.get('password') or ''
    full_name = (b.get('full_name') or u_name).strip()
    role = (b.get('role') or 'analyst').strip().lower()
    team = (b.get('team') or '').strip() or None
    email = (b.get('email') or f"{u_name}@barclays.com").strip().lower()

    if not u_name or len(u_name) < 3:
        return jsonify(error='username must be at least 3 characters'), 400
    if not pwd or len(pwd) < 6:
        return jsonify(error='password must be at least 6 characters'), 400
    if role not in ['analyst', 'manager', 'owner', 'executive', 'auditor', 'admin']:
        return jsonify(error='invalid role selected'), 400

    conn = get_conn()
    existing = db.get_user_by_username(conn, u_name)
    if existing:
        conn.close()
        return jsonify(error='username already registered'), 409

    new_user = db.create_user(conn, {
        'username': u_name,
        'password': pwd,
        'full_name': full_name,
        'role': role,
        'team': team,
        'email': email
    })
    conn.close()

    token = TOKEN_SERIALIZER.dumps(dict(
        user_id=new_user['user_id'],
        username=new_user['username'],
        role=new_user['role'],
        team=new_user['team'],
        full_name=new_user['full_name']
    ))
    audit('signup', new_user['username'])

    return jsonify(
        token=token,
        role=new_user['role'],
        username=new_user['username'],
        user_id=new_user['user_id'],
        team=new_user['team'],
        full_name=new_user['full_name'],
        message='Account created successfully'
    ), 201

@app.get('/api/me')
@need()
def me():
    return jsonify(current_user())

@app.get('/api/users')
@need('admin', 'auditor')
def get_users():
    conn = get_conn()
    users = db.list_users(conn)
    conn.close()
    return jsonify(users)

@app.post('/api/users')
@need('admin')
def add_user():
    b = rjson()
    for req_field in ('username', 'password', 'role'):
        if not b.get(req_field):
            return jsonify(error=f'{req_field} is required'), 400
    if b['role'] not in ROLES:
        return jsonify(error=f'invalid role; must be one of {ROLES}'), 400
    conn = get_conn()
    existing = db.get_user_by_username(conn, b['username'].strip().lower())
    if existing:
        conn.close()
        return jsonify(error='username already exists'), 409
    new_user = db.create_user(conn, {
        'username': b['username'].strip().lower(),
        'password': b['password'],
        'role': b['role'],
        'team': b.get('team'),
        'full_name': b.get('full_name', b['username']),
        'email': b.get('email', f"{b['username']}@example.com")
    })
    conn.close()
    audit('user_created', f"User {new_user['username']} ({new_user['role']}) registered")
    u_ret = {k: v for k, v in new_user.items() if k != 'password_hash'}
    return jsonify(u_ret), 201

@app.post('/api/feeds/sync')
@need('admin', 'analyst')
def sync_feeds():
    """Syncs CISA Known Exploited Vulnerabilities catalog from live CISA JSON or supplied payload."""
    cve_list = []
    source_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    b = rjson()
    if 'cves' in b and isinstance(b['cves'], list):
        cve_list = b['cves']
    else:
        try:
            req = urllib.request.Request(source_url, headers={'User-Agent': 'Mozilla/5.0 (Barclays-IVMRP-Agent)'})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.load(r)
                cve_list = [v['cveID'] for v in data.get('vulnerabilities', []) if 'cveID' in v]
        except Exception:
            # Fallback if network sandbox is active
            cve_list = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-4966", "CVE-2020-1472", "CVE-2023-34362", "CVE-2024-3094"]

    conn = get_conn()
    added = db.upsert_kev_batch(conn, cve_list)
    conn.close()

    build()
    audit('feed_synced', f"CISA KEV catalog sync: {len(cve_list)} CVEs processed, {added} newly flagged as exploited")
    return jsonify(
        status='ok',
        cves_processed=len(cve_list),
        new_kevs_added=added,
        canonical_findings=len(S['findings']),
        emergency_findings=stats()['emergency_findings']
    )

@app.post('/api/pipeline/run')
@need('admin', 'analyst')
def run():
    build()
    return jsonify(sources=len(S['src_counts']), raw_records=S['raw'], canonical_findings=len(S['findings']),
                   duplicates_merged=S['raw'] - len(S['errors']) - len(S['findings']), import_errors=S['errors'])

@app.post('/api/sources/upload')
@need('admin', 'analyst')
def upload_scans():
    """Dynamic scanner upload endpoint supporting JSON lists or CSV scan exports."""
    conn = get_conn()
    records = []
    source_name = 'Uploaded Scanner'
    source_type = 'Dynamic Scan'
    source_id = 'UPLOAD'

    # 1. Handle JSON
    if request.is_json:
        data = request.json
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            source_id = data.get('source_id', 'UPLOAD')
            source_name = data.get('source_name', 'Uploaded Scanner')
            source_type = data.get('source_type', 'Dynamic Scan')
            records = data.get('records', [])
    # 2. Handle CSV (raw body or multipart form file)
    elif 'file' in request.files:
        f = request.files['file']
        stream = io.StringIO(f.stream.read().decode('utf-8', errors='ignore'))
        reader = csv.DictReader(stream)
        records = list(reader)
    elif request.data:
        try:
            stream = io.StringIO(request.data.decode('utf-8', errors='ignore'))
            reader = csv.DictReader(stream)
            records = list(reader)
        except Exception:
            records = []

    if not records:
        conn.close()
        return jsonify(error='no scan records found in payload'), 400

    # Ensure source config exists
    cur = conn.cursor()
    cur.execute("SELECT source_id FROM sources_config WHERE source_id = ?", (source_id,))
    if not cur.fetchone():
        cur.execute("""
        INSERT INTO sources_config (source_id, name, type, field_mapping)
        VALUES (?, ?, ?, ?)
        """, (source_id, source_name, source_type, json.dumps({'cve_id': 'cve_id', 'host': 'host', 'first_seen': 'first_seen'})))
        conn.commit()

    for r in records:
        db.add_source_record(conn, source_id, source_name, source_type, r)
    conn.close()

    # Re-run pipeline to ingest and score newly uploaded records non-destructively
    build()
    audit('scanner_upload', f"Ingested {len(records)} records into {source_name}")

    return jsonify(status='ok', records_ingested=len(records), canonical_findings=len(S['findings']),
                   raw_records=S['raw'], import_errors=S['errors'])

@app.get('/api/sources')
@need()
def sources():
    return jsonify([dict(source=k, **v) for k, v in S['src_counts'].items()])

@app.get('/api/teams')
@need()
def teams():
    return jsonify(routing=[dict(category=k, team=v) for k, v in S['teams']['routing'].items()], urgency=S['teams']['urgency'],
                   workload=[dict(team=t, handles=d, **stats()['by_team'].get(t, dict(open=0, emergency=0, overdue=0))) for t, d in S['teams']['description'].items()])

@app.get('/api/assets')
@need()
def assets():
    return jsonify(list(S['assets'].values()))

@app.post('/api/assets')
@need('admin')
def add_asset():
    a = rjson()
    a.setdefault('aliases', [])
    if not a.get('asset_id') or not a.get('name'):
        return jsonify(error='asset_id and name required'), 400
    conn = get_conn()
    db.insert_asset(conn, a)
    conn.close()
    S['assets'][a['asset_id']] = a
    S['paths'] = paths()
    audit('asset_registered', a['asset_id'])
    return jsonify(a), 201

@app.get('/api/findings')
@need()
def findings():
    r = sorted(S['findings'].values(), key=lambda f: -f['risk_score'])
    for k in ('asset_id', 'risk_level', 'urgency', 'status', 'fix_team', 'business_unit'):
        if request.args.get(k): r = [f for f in r if f[k] == request.args[k]]
    return jsonify([public(f) for f in r[:int(request.args.get('limit', 500))]])

@app.get('/api/findings/<fid>/risk')
@need()
def risk(fid):
    f = S['findings'].get(fid)
    return jsonify(f) if f else (jsonify(error='not found'), 404)

@app.get('/api/attack-paths')
@need()
def ap():
    return jsonify(paths=[dict(path=p, names=[S['assets'][x]['name'] for x in p], target=S['assets'][p[-1]]['name']) for p in S['paths']])

@app.get('/api/attack-paths/graph')
@need()
def attack_paths_graph():
    nodes = []
    for aid, a in S['assets'].items():
        asset_findings = [f for f in S['findings'].values() if f['asset_id'] == aid]
        vulns_count = len(asset_findings)
        max_risk = max([f['risk_score'] for f in asset_findings], default=0)
        on_path = any(aid in p for p in S['paths'])
        nodes.append({
            'id': aid,
            'name': a['name'],
            'asset_type': a.get('asset_type', ''),
            'business_service': a.get('business_service', ''),
            'business_unit': a.get('business_unit', ''),
            'owner': a.get('owner', ''),
            'criticality': a.get('criticality', 'low'),
            'internet_exposed': bool(a.get('internet_exposed', 0)),
            'customer_facing': bool(a.get('customer_facing', 0)),
            'crown_jewel': bool(a.get('crown_jewel', 0)),
            'sensitive_data': bool(a.get('sensitive_data', 0)),
            'regulatory_relevance': bool(a.get('regulatory_relevance', 0)),
            'ip': a.get('ip', ''),
            'vulns_count': vulns_count,
            'max_risk': max_risk,
            'on_attack_path': on_path
        })
    
    edges = []
    for s, t in S['intel']['relationships']:
        on_path_edge = any(s in p and t in p and p.index(t) == p.index(s) + 1 for p in S['paths'])
        edges.append({
            'source': s,
            'target': t,
            'on_attack_path': on_path_edge
        })
    
    paths_data = [
        {
            'path': p,
            'names': [S['assets'][x]['name'] for x in p],
            'target': S['assets'][p[-1]]['name'],
            'hops': len(p) - 1
        }
        for p in S['paths']
    ]
    return jsonify(nodes=nodes, edges=edges, paths=paths_data)

@app.get('/api/tasks')
@need()
def tasks():
    r = list(S['tasks'].values())
    u = current_user()
    req_team = request.args.get('team')

    # Server-side team scoping: if owner has an assigned team, default to that team
    if not req_team and u and u.get('role') == 'owner' and u.get('team'):
        r = [t for t in r if t['fix_team'] == u['team']]
    elif req_team and req_team != 'all':
        r = [t for t in r if t['fix_team'] == req_team]

    for k in ('urgency', 'status'):
        if request.args.get(k): r = [t for t in r if t[k] == request.args[k]]
    return jsonify(sorted([dict(t, overdue=overdue(t)) for t in r], key=lambda t: -S['findings'][t['finding_id']]['risk_score']))

@app.patch('/api/tasks/<tid>')
@need('admin', 'analyst', 'manager', 'owner')
def upd(tid):
    t, st = S['tasks'].get(tid), rjson().get('status')
    if not t: return jsonify(error='not found'), 404
    if st not in ['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'REMEDIATED', 'VERIFIED', 'CLOSED']:
        return jsonify(error='bad status'), 400
    cl = str(TODAY) if st == 'CLOSED' else None
    conn = get_conn()
    db.update_task_status(conn, tid, st, cl)
    conn.close()
    t['status'] = st
    t['closed_at'] = cl
    S['findings'][t['finding_id']]['status'] = st
    audit('task_status', f'{tid} -> {st}')
    return jsonify(t)

@app.patch('/api/tasks/<tid>/reassign')
@need('admin', 'analyst', 'manager')
def reassign(tid):
    t, tm = S['tasks'].get(tid), rjson().get('team')
    if not t or tm not in S['teams']['description']:
        return jsonify(error='unknown task or team', teams=list(S['teams']['description'])), 400
    conn = get_conn()
    db.reassign_task(conn, tid, tm)
    conn.close()
    t['fix_team'] = tm
    S['findings'][t['finding_id']]['fix_team'] = tm
    audit('task_reassigned', f"{tid}: {t['fix_team']} -> {tm}")
    return jsonify(t)

@app.get('/api/sla/overdue')
@need()
def od():
    return jsonify([dict(t, escalated=True, escalate_to='vulnerability-manager') for t in S['tasks'].values() if overdue(t)])

@app.post('/api/jobs/check-sla-and-expiry')
@need('admin', 'manager', 'analyst')
def check_sla_and_expiry():
    conn = get_conn()
    expired = db.process_expired_exceptions(conn, str(TODAY))
    conn.close()

    for item in expired:
        eid = item['exception_id']
        fid = item['finding_id']
        if eid in S['exceptions']:
            S['exceptions'][eid]['status'] = 'EXPIRED'
        if fid in S['findings'] and S['findings'][fid]['status'] == 'EXCEPTION_APPROVED':
            S['findings'][fid]['status'] = 'ASSIGNED'

    overdue_tasks = []
    for t in S['tasks'].values():
        if t['status'] not in ['REMEDIATED', 'VERIFIED', 'CLOSED'] and overdue(t):
            overdue_tasks.append({
                'task_id': t['task_id'],
                'finding_id': t['finding_id'],
                'cve_id': t['cve_id'],
                'asset_name': t['asset_name'],
                'fix_team': t['fix_team'],
                'urgency': t['urgency'],
                'due_date': t['due_date'],
                'status': t['status'],
                'escalated_to': 'vulnerability-manager'
            })

    if expired:
        audit('job_expiry', f'Auto-expired {len(expired)} exception(s): {[x["exception_id"] for x in expired]}')
    if overdue_tasks:
        audit('job_sla_scan', f'Identified {len(overdue_tasks)} overdue remediation task(s)')

    return jsonify(
        expired_count=len(expired),
        expired_exceptions=expired,
        overdue_count=len(overdue_tasks),
        overdue_tasks=overdue_tasks,
        scanned_at=str(TODAY)
    )

@app.get('/api/tickets')
@need()
def tickets():
    return jsonify([dict(key='JIRA-' + t['task_id'][5:], summary=f"[{t['urgency']}] {t['title']}", assignee=t['fix_team'], status=t['status']) for t in S['tasks'].values()])

@app.get('/api/exceptions')
@need()
def excs():
    return jsonify(list(S['exceptions'].values()))

@app.post('/api/exceptions')
@need('admin', 'analyst', 'owner')
def exc():
    b = rjson()
    fid = b.get('finding_id')
    if fid not in S['findings']: return jsonify(error='unknown finding_id'), 400
    e = f'EXC-{len(S["exceptions"]) + 1:03d}'
    exc_obj = dict(exception_id=e, finding_id=fid, reason=b.get('reason', ''), requested_by=role(), status='PENDING', days=int(b.get('days', 30)), expires_at=None, decided_by=None, created_at=str(dt.datetime.now())[:19])
    conn = get_conn()
    db.insert_exception(conn, exc_obj)
    conn.close()
    S['exceptions'][e] = exc_obj
    audit('exception_requested', e)
    return jsonify(exc_obj), 201

@app.post('/api/exceptions/<eid>/decision')
@need('admin', 'manager')
def decide(eid):
    e, d = S['exceptions'].get(eid), rjson().get('decision')
    if not e or d not in ('APPROVED', 'REJECTED'): return jsonify(error='bad request'), 400
    exp = str(TODAY + dt.timedelta(days=e['days'])) if d == 'APPROVED' else None
    conn = get_conn()
    db.decide_exception(conn, eid, d, role(), exp)
    conn.close()
    e['status'] = d
    e['decided_by'] = role()
    if d == 'APPROVED':
        e['expires_at'] = exp
        S['findings'][e['finding_id']]['status'] = 'EXCEPTION_APPROVED'
    audit('exception_' + d.lower(), eid)
    return jsonify(e)

@app.get('/api/analytics')
@need()
def analytics():
    return jsonify(stats())

@app.get('/api/audit')
@need('admin', 'auditor')
def aud():
    conn = get_conn()
    logs = db.get_audit_log(conn)
    conn.close()
    return jsonify(logs)

@app.get('/api/config')
@need('admin', 'auditor')
def cfg():
    return jsonify(weights=S['intel']['weights'], sla_days={k: v['sla_days'] for k, v in S['teams']['urgency'].items()})

@app.put('/api/config')
@need('admin')
def update_config():
    data = rjson()
    weights = data.get('weights')
    sla_days = data.get('sla_days')
    if not weights and not sla_days:
        return jsonify(error='at least one of "weights" or "sla_days" must be provided'), 400

    conn = get_conn()
    if weights and isinstance(weights, dict):
        db.update_weights(conn, weights)
    if sla_days and isinstance(sla_days, dict):
        db.update_sla_days(conn, sla_days)
    conn.close()

    # Re-run build to update all findings, risk scores, and SLA deadlines
    build()

    audit('config_update', f'Updated weights={bool(weights)} sla_days={bool(sla_days)}')
    return jsonify(
        weights=S['intel']['weights'],
        sla_days={k: v['sla_days'] for k, v in S['teams']['urgency'].items()},
        message='Configuration updated and platform re-scored successfully'
    )

CAT = {  # plain-English explanation + typical fix per vulnerability category
"java-library": ("A flaw in a Java library or framework our application is built on. Attackers can often abuse it remotely to run their own code on the server.", "Upgrade the library to the fixed version, rebuild, redeploy and re-scan. Check dependency lock files for other copies."),
"web-app": ("A weakness in the application's own logic, found by testers, that lets a user see or do things they should not.", "Add the missing authorization/validation check in code, add a regression test, release, then ask testers to retest."),
"frontend-lib": ("A flaw in a browser-side (JavaScript/npm) component or page. It can let attackers run script in a customer's browser or slow the site down.", "Update the npm package or sanitize the affected input/output, rebuild the UI and redeploy."),
"web-server": ("A weakness in the web or HTTP server software that exposes files or lets attackers overload the service.", "Apply the vendor patch or the recommended configuration change, restart the service and verify."),
"os": ("A flaw in the operating system or a core system component that can let a local user or malware gain full control of the machine.", "Install the OS/package update, reboot if required, and confirm the version."),
"file-transfer": ("A flaw in file-transfer software used to exchange data. Attackers have used it to steal data in bulk.", "Apply the emergency vendor patch, review logs for past abuse, and restrict internet access to it."),
"network": ("A flaw in a network appliance (load balancer/gateway) that can leak session data or let attackers into the network.", "Upgrade the appliance firmware, invalidate active sessions, and review access logs."),
"database": ("A weakness around a database that could expose or alter stored records.", "Patch the database or host, tighten access rules, and verify backups."),
"container": ("A weakness in a container image or Kubernetes setting that can let an attacker break out to the host or other workloads.", "Rebuild from a patched base image or remove the risky setting (e.g. privileged mode), then redeploy."),
"cloud": ("A cloud misconfiguration, such as storage that is open to the public, that can expose data without any hacking.", "Block public access, review who accessed it, and add a guardrail policy to prevent a repeat."),
"identity": ("A weakness in how people or systems sign in. Attackers who exploit it can impersonate powerful accounts.", "Enforce MFA on privileged accounts / apply the identity patch, then review recent sign-ins."),
}

@app.get('/api/findings/<fid>/detail')
@need()
def detail(fid):
    f = S['findings'].get(fid)
    if not f: return jsonify(error='not found'), 404
    a = S['assets'][f['asset_id']]
    what, fix = CAT.get(f['category'], ('A security weakness.', 'Follow the vendor guidance.'))
    ps = [' → '.join(S['assets'][x]['name'] for x in p) for p in S['paths'] if f['asset_id'] in p]
    ctxs = [k.replace('_', ' ') for k in ('internet_exposed', 'customer_facing', 'crown_jewel', 'sensitive_data', 'regulatory_relevance') if a[k]]
    why = [f"Found by {len(f['sources'])} source(s): {', '.join(f['sources'])}. First seen {f['first_seen']}.",
           f"It affects {a['name']} ({a['asset_type'].replace('_', ' ')}), part of {a['business_service']} in {a['business_unit']}; business criticality: {a['criticality']}."]
    if ctxs: why.append('That asset is: ' + ', '.join(ctxs) + '. This raises the business impact.')
    if f['kev']: why.append('It is on the CISA Known Exploited Vulnerabilities list: attackers are already using it in the real world.')
    if f['epss'] >= .5: why.append(f"EPSS estimates a {round(f['epss'] * 100)}% chance of exploitation soon.")
    if ps: why.append('Attack path(s) through this asset: ' + '; '.join(ps) + '.')
    t = next((dict(t, overdue=overdue(t)) for t in S['tasks'].values() if t['finding_id'] == fid), None)
    return jsonify(finding=public(f), risk_factors=f['risk_factors'], what=what, why=why, fix=fix, asset=a, task=t, paths=ps,
                   link='https://nvd.nist.gov/vuln/detail/' + f['cve_id'] if f['real_cve'] else None, exceptions=[e for e in S['exceptions'].values() if e['finding_id'] == fid])

@app.get('/')
def home(): return app.send_static_file('index.html')

db.init_db()
build()

if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 5000)))
