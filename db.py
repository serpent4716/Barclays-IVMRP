"""SQLite persistence layer for Intelligent Vulnerability Management Platform.
Provides schema creation, initial JSON seeding, non-destructive pipeline upserts,
and CRUD methods for assets, findings, tasks, exceptions, and audit logs.
"""
import json, os, sqlite3, datetime as dt

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, 'data')
DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'ivmrp.db')

def get_connection(db_path=None):
    path = db_path or os.environ.get('IVMRP_DB_PATH', DEFAULT_DB_PATH)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db(db_path=None, seed_if_empty=True):
    """Initializes tables and seeds from JSON files if database is empty."""
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        asset_type TEXT,
        business_service TEXT,
        business_unit TEXT,
        owner TEXT,
        criticality TEXT,
        internet_exposed INTEGER DEFAULT 0,
        customer_facing INTEGER DEFAULT 0,
        crown_jewel INTEGER DEFAULT 0,
        sensitive_data INTEGER DEFAULT 0,
        regulatory_relevance INTEGER DEFAULT 0,
        ip TEXT,
        aliases TEXT
    );

    CREATE TABLE IF NOT EXISTS asset_relationships (
        source_asset_id TEXT,
        target_asset_id TEXT,
        PRIMARY KEY (source_asset_id, target_asset_id)
    );

    CREATE TABLE IF NOT EXISTS intel_nvd (
        cve_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        cwe TEXT,
        category TEXT,
        real_cve INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS intel_kev (
        cve_id TEXT PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS intel_epss (
        cve_id TEXT PRIMARY KEY,
        score REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS intel_weights (
        name TEXT PRIMARY KEY,
        weight REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS teams_routing (
        category TEXT PRIMARY KEY,
        team TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS teams_description (
        team TEXT PRIMARY KEY,
        description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS teams_urgency (
        urgency TEXT PRIMARY KEY,
        sla_days INTEGER NOT NULL,
        label TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sources_config (
        source_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        field_mapping TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS source_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        cve_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        asset_name TEXT NOT NULL,
        business_unit TEXT NOT NULL,
        title TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        cwe TEXT,
        category TEXT,
        real_cve INTEGER DEFAULT 1,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        urgency TEXT NOT NULL,
        urgency_label TEXT NOT NULL,
        fix_team TEXT NOT NULL,
        business_owner TEXT NOT NULL,
        fix_reason TEXT,
        first_seen TEXT NOT NULL,
        status TEXT NOT NULL,
        kev INTEGER DEFAULT 0,
        epss REAL DEFAULT 0,
        sources_json TEXT NOT NULL,
        risk_factors_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
    );

    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        title TEXT NOT NULL,
        asset_name TEXT NOT NULL,
        fix_team TEXT NOT NULL,
        business_owner TEXT NOT NULL,
        urgency TEXT NOT NULL,
        status TEXT NOT NULL,
        due_date TEXT NOT NULL,
        closed_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
    );

    CREATE TABLE IF NOT EXISTS exceptions (
        exception_id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        reason TEXT,
        requested_by TEXT,
        status TEXT NOT NULL,
        days INTEGER NOT NULL,
        expires_at TEXT,
        decided_by TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        user TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pipeline_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        sources_count INTEGER NOT NULL,
        raw_records INTEGER NOT NULL,
        canonical_findings INTEGER NOT NULL,
        duplicates_merged INTEGER NOT NULL,
        errors_json TEXT NOT NULL
    );
    """)
    conn.commit()

    if seed_if_empty:
        cur.execute("SELECT COUNT(*) FROM assets")
        if cur.fetchone()[0] == 0:
            seed_from_json(conn)

    conn.close()

def _read_json(name):
    with open(os.path.join(DATA_DIR, name + '.json'), 'r', encoding='utf-8') as f:
        return json.load(f)

def seed_from_json(conn):
    """Loads default JSON files from data directory into SQLite."""
    cur = conn.cursor()
    L = _read_json

    # 1. Assets & Relationships
    if os.path.exists(os.path.join(DATA_DIR, 'assets.json')):
        assets_data = L('assets')
        for a in assets_data:
            cur.execute("""
            INSERT OR REPLACE INTO assets 
            (asset_id, name, asset_type, business_service, business_unit, owner, criticality,
             internet_exposed, customer_facing, crown_jewel, sensitive_data, regulatory_relevance, ip, aliases)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a['asset_id'], a['name'], a.get('asset_type'), a.get('business_service'),
                a.get('business_unit'), a.get('owner'), a.get('criticality', 'medium'),
                int(bool(a.get('internet_exposed'))), int(bool(a.get('customer_facing'))),
                int(bool(a.get('crown_jewel'))), int(bool(a.get('sensitive_data'))),
                int(bool(a.get('regulatory_relevance'))), a.get('ip'),
                json.dumps(a.get('aliases', []))
            ))

    # 2. Intel
    if os.path.exists(os.path.join(DATA_DIR, 'intel.json')):
        intel_data = L('intel')
        for cve_id, v in intel_data.get('nvd', {}).items():
            cur.execute("""
            INSERT OR REPLACE INTO intel_nvd (cve_id, title, cvss_score, cwe, category, real_cve)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (cve_id, v['title'], float(v['cvss_score']), v.get('cwe'), v.get('category'), int(v.get('real', True))))

        for cve_id in intel_data.get('kev', []):
            cur.execute("INSERT OR REPLACE INTO intel_kev (cve_id) VALUES (?)", (cve_id,))

        for cve_id, ep in intel_data.get('epss', {}).items():
            cur.execute("INSERT OR REPLACE INTO intel_epss (cve_id, score) VALUES (?, ?)", (cve_id, float(ep)))

        for rel in intel_data.get('relationships', []):
            if len(rel) == 2:
                cur.execute("INSERT OR REPLACE INTO asset_relationships (source_asset_id, target_asset_id) VALUES (?, ?)", (rel[0], rel[1]))

        for w_name, w_val in intel_data.get('weights', {}).items():
            cur.execute("INSERT OR REPLACE INTO intel_weights (name, weight) VALUES (?, ?)", (w_name, float(w_val)))

    # 3. Teams & Urgency
    if os.path.exists(os.path.join(DATA_DIR, 'teams.json')):
        teams_data = L('teams')
        for cat, tm in teams_data.get('routing', {}).items():
            cur.execute("INSERT OR REPLACE INTO teams_routing (category, team) VALUES (?, ?)", (cat, tm))
        for tm, desc in teams_data.get('description', {}).items():
            cur.execute("INSERT OR REPLACE INTO teams_description (team, description) VALUES (?, ?)", (tm, desc))
        for urg, u_info in teams_data.get('urgency', {}).items():
            cur.execute("INSERT OR REPLACE INTO teams_urgency (urgency, sla_days, label) VALUES (?, ?, ?)",
                        (urg, int(u_info['sla_days']), u_info['label']))

    # 4. Sources & Records
    if os.path.exists(os.path.join(DATA_DIR, 'sources.json')):
        sources_data = L('sources')
        now_str = str(dt.datetime.now())[:19]
        for sid, scfg in sources_data.items():
            cur.execute("INSERT OR REPLACE INTO sources_config (source_id, name, type, field_mapping) VALUES (?, ?, ?, ?)",
                        (sid, scfg['name'], scfg['type'], json.dumps(scfg.get('map', {}))))
            for r in scfg.get('records', []):
                cur.execute("""
                INSERT INTO source_records (source_id, source_name, source_type, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """, (sid, scfg['name'], scfg['type'], json.dumps(r), now_str))

    conn.commit()


def dict_from_row(row):
    return dict(row) if row else None

def get_assets(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM assets")
    res = {}
    for r in cur.fetchall():
        d = dict(r)
        d['aliases'] = json.loads(d['aliases']) if d['aliases'] else []
        d['internet_exposed'] = bool(d['internet_exposed'])
        d['customer_facing'] = bool(d['customer_facing'])
        d['crown_jewel'] = bool(d['crown_jewel'])
        d['sensitive_data'] = bool(d['sensitive_data'])
        d['regulatory_relevance'] = bool(d['regulatory_relevance'])
        res[d['asset_id']] = d
    return res

def insert_asset(conn, a):
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO assets 
    (asset_id, name, asset_type, business_service, business_unit, owner, criticality,
     internet_exposed, customer_facing, crown_jewel, sensitive_data, regulatory_relevance, ip, aliases)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        a['asset_id'], a['name'], a.get('asset_type'), a.get('business_service'),
        a.get('business_unit'), a.get('owner'), a.get('criticality', 'medium'),
        int(bool(a.get('internet_exposed'))), int(bool(a.get('customer_facing'))),
        int(bool(a.get('crown_jewel'))), int(bool(a.get('sensitive_data'))),
        int(bool(a.get('regulatory_relevance'))), a.get('ip'),
        json.dumps(a.get('aliases', []))
    ))
    conn.commit()

def get_intel(conn):
    cur = conn.cursor()
    nvd = {}
    cur.execute("SELECT * FROM intel_nvd")
    for r in cur.fetchall():
        nvd[r['cve_id']] = dict(title=r['title'], cvss_score=r['cvss_score'], cwe=r['cwe'], category=r['category'], real=bool(r['real_cve']))
    
    cur.execute("SELECT cve_id FROM intel_kev")
    kev = [r['cve_id'] for r in cur.fetchall()]

    cur.execute("SELECT cve_id, score FROM intel_epss")
    epss = {r['cve_id']: r['score'] for r in cur.fetchall()}

    cur.execute("SELECT name, weight FROM intel_weights")
    weights = {r['name']: r['weight'] for r in cur.fetchall()}

    cur.execute("SELECT source_asset_id, target_asset_id FROM asset_relationships")
    rel = [[r['source_asset_id'], r['target_asset_id']] for r in cur.fetchall()]

    return dict(nvd=nvd, kev=kev, epss=epss, weights=weights, relationships=rel)

def get_teams(conn):
    cur = conn.cursor()
    cur.execute("SELECT category, team FROM teams_routing")
    routing = {r['category']: r['team'] for r in cur.fetchall()}

    cur.execute("SELECT team, description FROM teams_description")
    description = {r['team']: r['description'] for r in cur.fetchall()}

    cur.execute("SELECT urgency, sla_days, label FROM teams_urgency")
    urgency = {r['urgency']: dict(sla_days=r['sla_days'], label=r['label']) for r in cur.fetchall()}

    return dict(routing=routing, description=description, urgency=urgency)

def get_sources(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM sources_config")
    sources = {}
    for r in cur.fetchall():
        sources[r['source_id']] = dict(
            name=r['name'],
            type=r['type'],
            map=json.loads(r['field_mapping']),
            records=[]
        )
    cur.execute("SELECT source_id, payload FROM source_records ORDER BY id ASC")
    for r in cur.fetchall():
        if r['source_id'] in sources:
            sources[r['source_id']]['records'].append(json.loads(r['payload']))
    return sources

def add_source_record(conn, source_id, source_name, source_type, payload):
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]
    cur.execute("""
    INSERT INTO source_records (source_id, source_name, source_type, payload, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (source_id, source_name, source_type, json.dumps(payload), now_str))
    conn.commit()

def get_findings(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings")
    res = {}
    for r in cur.fetchall():
        d = dict(r)
        d['real_cve'] = bool(d['real_cve'])
        d['kev'] = bool(d['kev'])
        d['sources'] = json.loads(d['sources_json'])
        d['risk_factors'] = json.loads(d['risk_factors_json'])
        res[d['finding_id']] = d
    return res

def get_tasks(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM tasks")
    return {r['task_id']: dict(r) for r in cur.fetchall()}

def get_exceptions(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM exceptions")
    return {r['exception_id']: dict(r) for r in cur.fetchall()}

def get_audit_log(conn):
    cur = conn.cursor()
    cur.execute("SELECT ts, user, action, detail FROM audit_log ORDER BY id DESC")
    return [dict(r) for r in cur.fetchall()]

def log_audit(conn, user, action, detail):
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]
    cur.execute("INSERT INTO audit_log (ts, user, action, detail) VALUES (?, ?, ?, ?)",
                (now_str, user or 'system', action, detail))
    conn.commit()

def log_pipeline_run(conn, sources_count, raw_records, canonical_findings, duplicates_merged, errors_json):
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]
    cur.execute("""
    INSERT INTO pipeline_runs (ts, sources_count, raw_records, canonical_findings, duplicates_merged, errors_json)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (now_str, sources_count, raw_records, canonical_findings, duplicates_merged, json.dumps(errors_json)))
    conn.commit()

def upsert_canonical_finding_and_task(conn, f, t_default):
    """
    Non-destructive upsert:
    - Inserts or updates the finding.
    - If a task already exists for this finding:
      PRESERVES user-managed state (status, re-assigned team, closed_at).
    - If task is brand new, creates it with initial default state.
    """
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]

    # Check if finding already exists
    cur.execute("SELECT finding_id, status FROM findings WHERE finding_id = ?", (f['finding_id'],))
    existing_finding = cur.fetchone()

    # If existing finding was approved for exception, keep that status
    finding_status = f['status']
    if existing_finding and existing_finding['status'] == 'EXCEPTION_APPROVED':
        finding_status = 'EXCEPTION_APPROVED'

    cur.execute("""
    INSERT INTO findings 
    (finding_id, cve_id, asset_id, asset_name, business_unit, title, cvss_score, cwe,
     category, real_cve, risk_score, risk_level, urgency, urgency_label, fix_team,
     business_owner, fix_reason, first_seen, status, kev, epss, sources_json, risk_factors_json,
     created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(finding_id) DO UPDATE SET
        title = excluded.title,
        cvss_score = excluded.cvss_score,
        risk_score = excluded.risk_score,
        risk_level = excluded.risk_level,
        urgency = excluded.urgency,
        urgency_label = excluded.urgency_label,
        kev = excluded.kev,
        epss = excluded.epss,
        sources_json = excluded.sources_json,
        risk_factors_json = excluded.risk_factors_json,
        updated_at = excluded.updated_at
    """, (
        f['finding_id'], f['cve_id'], f['asset_id'], f['asset_name'], f['business_unit'],
        f['title'], f['cvss_score'], f['cwe'], f['category'], int(f['real_cve']),
        f['risk_score'], f['risk_level'], f['urgency'], f['urgency_label'], f['fix_team'],
        f['business_owner'], f['fix_reason'], f['first_seen'], finding_status,
        int(f['kev']), float(f['epss']), json.dumps(f['sources']),
        json.dumps(f['risk_factors']), now_str, now_str
    ))

    # Check if task already exists for this finding
    cur.execute("SELECT * FROM tasks WHERE finding_id = ?", (f['finding_id'],))
    existing_task = cur.fetchone()

    if existing_task:
        # Non-destructive update: preserve status, fix_team (if reassigned), closed_at
        cur.execute("""
        UPDATE tasks SET
            title = ?,
            urgency = ?,
            updated_at = ?
        WHERE finding_id = ?
        """, (f['title'], f['urgency'], now_str, f['finding_id']))
    else:
        # Insert new task
        cur.execute("""
        INSERT INTO tasks 
        (task_id, finding_id, cve_id, title, asset_name, fix_team, business_owner,
         urgency, status, due_date, closed_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            t_default['task_id'], t_default['finding_id'], t_default['cve_id'],
            t_default['title'], t_default['asset_name'], t_default['fix_team'],
            t_default['business_owner'], t_default['urgency'], t_default['status'],
            t_default['due_date'], t_default['closed_at'], now_str, now_str
        ))

    conn.commit()

def update_task_status(conn, task_id, status, closed_at):
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]
    cur.execute("UPDATE tasks SET status = ?, closed_at = ?, updated_at = ? WHERE task_id = ?",
                (status, closed_at, now_str, task_id))
    cur.execute("SELECT finding_id FROM tasks WHERE task_id = ?", (task_id,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                    (status, now_str, row['finding_id']))
    conn.commit()

def reassign_task(conn, task_id, new_team):
    cur = conn.cursor()
    now_str = str(dt.datetime.now())[:19]
    cur.execute("UPDATE tasks SET fix_team = ?, updated_at = ? WHERE task_id = ?",
                (new_team, now_str, task_id))
    cur.execute("SELECT finding_id FROM tasks WHERE task_id = ?", (task_id,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE findings SET fix_team = ?, updated_at = ? WHERE finding_id = ?",
                    (new_team, now_str, row['finding_id']))
    conn.commit()

def insert_exception(conn, e):
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO exceptions (exception_id, finding_id, reason, requested_by, status, days, expires_at, decided_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        e['exception_id'], e['finding_id'], e['reason'], e['requested_by'],
        e['status'], e['days'], e['expires_at'], e['decided_by'], e['created_at']
    ))
    conn.commit()

def decide_exception(conn, exception_id, decision, decided_by, expires_at=None):
    cur = conn.cursor()
    cur.execute("UPDATE exceptions SET status = ?, decided_by = ?, expires_at = ? WHERE exception_id = ?",
                (decision, decided_by, expires_at, exception_id))
    cur.execute("SELECT finding_id FROM exceptions WHERE exception_id = ?", (exception_id,))
    row = cur.fetchone()
    if row and decision == 'APPROVED':
        cur.execute("UPDATE findings SET status = 'EXCEPTION_APPROVED' WHERE finding_id = ?", (row['finding_id'],))
    conn.commit()


def get_or_create_finding_id(conn, cve_id, asset_id):
    cur = conn.cursor()
    cur.execute("SELECT finding_id FROM findings WHERE cve_id = ? AND asset_id = ?", (cve_id, asset_id))
    row = cur.fetchone()
    if row:
        return row['finding_id']
    cur.execute("SELECT MAX(CAST(SUBSTR(finding_id, 5) AS INTEGER)) FROM findings")
    val = cur.fetchone()[0]
    m = val if val is not None else 0
    return f"FND-{m + 1:06d}"

def get_or_create_task_id(conn, finding_id):
    cur = conn.cursor()
    cur.execute("SELECT task_id FROM tasks WHERE finding_id = ?", (finding_id,))
    row = cur.fetchone()
    if row:
        return row['task_id']
    cur.execute("SELECT MAX(CAST(SUBSTR(task_id, 6) AS INTEGER)) FROM tasks")
    val = cur.fetchone()[0]
    m = val if val is not None else 0
    return f"TASK-{m + 1:04d}"
