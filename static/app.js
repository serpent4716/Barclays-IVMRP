const $=s=>document.querySelector(s),esc=x=>String(x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

// SVG Icon Engine (replaces all emojis with crisp vector UI icons)
const ICONS = {
  shield: '<svg class="ui-icon brand-icon" viewBox="0 0 24 24"><path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z"/></svg>',
  chart: '<svg class="ui-icon" viewBox="0 0 24 24"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
  search: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  compass: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></svg>',
  tool: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
  clipboard: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>',
  settings: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  user: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  users: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  sun: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
  moon: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
  alert: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  check: '<svg class="ui-icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',
  close: '<svg class="ui-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  logout: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
  home: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
  help: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  api: '<svg class="ui-icon" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
  bot: '<svg class="ui-icon" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8.01" y2="16"/><line x1="16" y1="16" x2="16.01" y2="16"/></svg>',
  crown: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M2 4l3 12h14l3-12-6 7-4-7-4 7-6-7zm3 16h14v2H5v-2z"/></svg>',
  globe: '<svg class="ui-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  play: '<svg class="ui-icon" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
  upload: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
  save: '<svg class="ui-icon" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
  bolt: '<svg class="ui-icon" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  menu: '<svg class="ui-icon lg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>'
};
function icon(name){return ICONS[name]||'';}

// Theme handling (Light / Dark Mode)
function getTheme(){return localStorage.theme||'light';}
function setTheme(t){
  localStorage.theme=t;
  document.documentElement.setAttribute('data-theme',t);
  const btn=$('#theme-toggle-btn');
  if(btn)btn.innerHTML=icon(t==='dark'?'sun':'moon');
  // Re-render charts with contrast colors if active
  if(window._lastCache)initCharts(window._lastCache);
}
function toggleTheme(){
  const cur=getTheme();
  setTheme(cur==='dark'?'light':'dark');
  toast(getTheme()==='dark'?'Dark mode active':'Light mode active');
  if($('#menu')&&!$('#menu').hidden){
    renderMenu();
  }
}

const ROLES={
  executive:['Executive / CISO','See overall risk and the most urgent issues. Read-only.','chart'],
  analyst:['Security Analyst','Run imports, review every finding, ask the AI, raise exceptions.','search'],
  manager:['Vulnerability Manager','Watch team workload and overdue fixes, reassign work, approve exceptions.','compass'],
  owner:['Fix Team / Asset Owner','See the issues assigned to your team, update progress, request exceptions.','tool'],
  auditor:['Auditor','Review the audit trail, exceptions and scoring rules. Read-only.','clipboard'],
  admin:['Platform Admin','Manage assets, imports, AI status and configuration. Full access.','settings']
};
const TIPS={
  executive:'Start with the KPI cards, then the top risks. Click any risk to see what it is and why it matters.',
  analyst:'Click "Run pipeline" to re-import all sources, then open the highest-scoring findings and click them for the full story.',
  manager:'Check "Who must fix what" for overloaded teams, then the overdue list. Reassign work with the form under the task queue.',
  owner:'Choose your team in the queue filter, click a task to read how to fix it, and update its status as you work.',
  auditor:'The audit trail lists every action. Exceptions show who accepted which risk and until when.',
  admin:'Check AI status and sources first. Assets and routing rules show how the data is organised.'
};
const GLOSS=[
  ['Risk score (0–100)','How dangerous a finding is for OUR business. Combines technical severity (CVSS), whether attackers already use it (KEV), how likely exploitation is (EPSS), and affected system criticality.'],
  ['Urgency','EMERGENCY = fix within 2 days · HIGH = within a week · MEDIUM = within a month · LOW = can wait.'],
  ['CVE','A public ID for a known security flaw, e.g. CVE-2021-44228 (Log4Shell). Items like PENTEST-0001 are internal findings with no CVE.'],
  ['CVSS','The industry severity rating of a flaw, 0–10, regardless of where it exists.'],
  ['KEV','CISA list of flaws attackers are known to be actively exploiting.'],
  ['EPSS','Estimated probability that a flaw will be exploited in the wild.'],
  ['Fix team','The team that should apply the fix, routed automatically based on category.'],
  ['SLA / overdue','Deadline for remediation. Missed deadline triggers escalation to managers.'],
  ['Attack path','A chain of connected systems an attacker could traverse from the perimeter to crown jewels.'],
  ['Exception','An approved, time-limited decision to delay a fix, with formal justification.'],
  ['Crown jewel','A critical system whose compromise would severely disrupt operations or violate regulation.']
];
const HINT={
  kpis:'Headline security metrics for today.',
  urgency:'Findings distribution by SLA urgency tier.',
  bu:'Risk burden across business units.',
  teams:'Remediation workload and SLA health per engineering team.',
  routing:'Category-to-team assignment rules.',
  sources:'Connected ingestion tools and deduplicated counts.',
  top:'Highest risk findings ranked by business impact. Click any row for details.',
  allf:'Complete findings inventory. Filter in real time using the search bar.',
  paths:'Interactive topology mapping attacker hops from internet ingress to crown jewels.',
  overdue:'Remediation tasks that have exceeded their SLA deadline.',
  tasks:'Work items for fixing teams, prioritized by risk. Filter by team or urgency.',
  tickets:'External ticketing simulation (JIRA sync).',
  exc:'Formal risk exceptions submitted for manager review.',
  audit:'Immutable log of all administrative and pipeline events.',
  assets:'Enterprise asset directory with criticality and exposure flags.',
  config:'Scoring weights and SLA turnaround days. Tunable by platform admins.',
  aistatus:'Connected AI inference backends (Gemini, Ollama, or rules engine).',
  pipe:'Pipeline controls for manual ingestion, deduplication, scoring, and CISA sync.',
  ask:'Natural language query assistant for explaining risk factors and remediation guidance.'
};

async function api(p,m='GET',b){
  const r=await fetch(p,{method:m,headers:{'Content-Type':'application/json',Authorization:'Bearer '+(localStorage.tok||'')},body:b?JSON.stringify(b):undefined});
  let d;try{d=await r.json()}catch(e){d={}}
  return{status:r.status,data:d};
}
const BADGE={EMERGENCY:'b-red',CRITICAL:'b-red',HIGH:'b-orange',MEDIUM:'b-yellow',LOW:'b-green'},UL={EMERGENCY:'fix within 2 days',HIGH:'within a week',MEDIUM:'within a month',LOW:'can wait'};

function cell(c,v){
  if(v==null)return'';
  if(['urgency','risk_level'].includes(c)&&BADGE[v])return`<span class="badge ${BADGE[v]}">${v}</span>`;
  if(c==='overdue')return v?'<span class="badge b-red">OVERDUE</span>':'<span class="badge b-green">on track</span>';
  if(c==='risk_score')return`<b class="score ${v>=80?'s-red':v>=60?'s-orange':v>=40?'s-yellow':'s-green'}">${v}</b>`;
  if(c==='status')return`<span class="badge b-gray">${esc(v)}</span>`;
  if(typeof v==='boolean')return v?'Yes':'No';
  if(typeof v==='object')return esc(Array.isArray(v)?v.join(', '):JSON.stringify(v));
  return esc(v);
}

function tbl(rows,cols){
  if(!Array.isArray(rows)||!rows.length)return'<p class=hint>Nothing to show yet.</p>';
  cols=cols||Object.keys(rows[0]);
  return'<table><thead><tr>'+cols.map(c=>'<th>'+c.replace(/_/g,' ')+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>`<tr${r.finding_id?` class=click onclick="openRisk('${r.finding_id}')"`:''}>`+cols.map(c=>'<td>'+cell(c,r[c])+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
}

function filterTable(input){
  const card=input.closest('.card');
  const q=(card.querySelector('.filter-input')?.value||'').toLowerCase();
  const urgSel=card.querySelector('.filter-urgency')?.value||'';
  const rows=card.querySelectorAll('tbody tr');
  let visible=0;
  rows.forEach(r=>{
    const textMatch=!q||r.innerText.toLowerCase().includes(q);
    const badges=Array.from(r.querySelectorAll('.badge')).map(b=>b.innerText.trim());
    const urgMatch=!urgSel||badges.includes(urgSel);
    if(textMatch&&urgMatch){r.style.display='';visible++;}else{r.style.display='none';}
  });
  const cnt=card.querySelector('.filter-count');
  if(cnt)cnt.innerText=visible+' items';
}
function filterUrgency(sel){filterTable(sel);}

function searchableTbl(rows,cols){
  if(!Array.isArray(rows)||!rows.length)return'<p class=hint>Nothing to show yet.</p>';
  return `<div class="filter-bar">
    <input class="filter-input" placeholder="Real-time filter (CVE, title, host, owner, team)..." oninput="filterTable(this)">
    <select class="filter-urgency" onchange="filterUrgency(this)">
      <option value="">All Urgencies</option>
      <option value="EMERGENCY">EMERGENCY</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <span class="filter-count">${rows.length} items</span>
  </div><div class="tbl-wrap">${tbl(rows,cols)}</div>`;
}

const FC=['finding_id','cve_id','title','asset_name','risk_score','urgency','fix_team','status'],TC=['task_id','cve_id','title','asset_name','urgency','fix_team','status','due_date','overdue'];
const TEAMS=['backend-dev-team','frontend-team','infra-ops-team','network-team','dba-team','platform-team','cloud-ops-team','iam-ops-team','security-triage-team'],opts=l=>l.map(x=>'<option>'+x).join('');
const kv=o=>tbl(Object.entries(o).map(([k,v])=>({name:k,...(typeof v==='object'?v:{count:v})})));
const KP=[['total_findings','Total findings'],['emergency_findings','Emergency','red'],['overdue_findings','Overdue','red'],['sla_compliance','On-time %'],['average_risk_score','Avg risk score'],['average_mttr_days','Avg days to fix'],['assets','Assets'],['sources','Sources'],['open_exceptions','Pending exceptions']];
const HALF=['urgency','bu','sources','routing','config','aistatus'];
window._charts={};
window._topoNodes={};
window._lastCache=null;

function renderTopo(d){
  const nodes=d.nodes||[],edges=d.edges||[],paths=d.paths||[];
  nodes.forEach(n=>window._topoNodes[n.id]=n);
  const ingress=nodes.filter(n=>n.internet_exposed&&!n.crown_jewel);
  const crown=nodes.filter(n=>n.crown_jewel);
  const internal=nodes.filter(n=>!n.internet_exposed&&!n.crown_jewel);
  const pos={};
  const W=720,H=300;
  const place=(arr,x)=>{
    const n=arr.length;
    arr.forEach((it,i)=>{
      const y=n===1?H/2:40+i*((H-80)/Math.max(1,n-1));
      pos[it.id]={x,y,node:it};
    });
  };
  place(ingress,90);
  place(internal,360);
  place(crown,630);
  let svgEdges='';
  edges.forEach(e=>{
    const p1=pos[e.source],p2=pos[e.target];
    if(p1&&p2){
      const stroke=e.on_attack_path?'#dc2626':'#334155';
      const w=e.on_attack_path?'2.5':'1.2';
      const dash=e.on_attack_path?'4,4':'none';
      svgEdges+=`<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="${stroke}" stroke-width="${w}" stroke-dasharray="${dash}" marker-end="url(#${e.on_attack_path?'arrow-red':'arrow-dim'})"/>`;
    }
  });
  let svgNodes='';
  Object.values(pos).forEach(p=>{
    const n=p.node;
    const col=n.crown_jewel?'#dc2626':n.internet_exposed?'#2563eb':'#f59e0b';
    const r=n.crown_jewel?16:13;
    svgNodes+=`<g class="topo-node" style="cursor:pointer" onclick="showNode('${n.id}')">
      <circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${col}" stroke="#ffffff" stroke-width="2"/>
      <text x="${p.x}" y="${p.y+22}" fill="#cbd5e1" font-size="11" font-weight="600" text-anchor="middle" font-family="system-ui">${esc(n.name)}</text>
    </g>`;
  });
  return `<div class="topo-container">
    <svg class="topo-svg" viewBox="0 0 ${W} ${H}">
      <defs>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="21" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626"/></marker>
        <marker id="arrow-dim" viewBox="0 0 10 10" refX="21" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#475569"/></marker>
      </defs>
      ${svgEdges}
      ${svgNodes}
    </svg>
    <div id="topo-details" class="topo-details"></div>
    <div class="topo-legend">
      <span><i class="topo-dot" style="background:#2563eb"></i> Internet Ingress (Perimeter)</span>
      <span><i class="topo-dot" style="background:#f59e0b"></i> Application / Intermediate Pivot</span>
      <span><i class="topo-dot" style="background:#dc2626"></i> Crown Jewel Target</span>
      <span style="color:#ef4444;font-weight:600">--- Active Attack Traversal Path (BFS)</span>
    </div>
  </div>
  <p class=hint style="margin-top:12px"><b>Traversable paths detected from perimeter:</b></p>
  ${tbl(paths.map(p=>({path:p.names.join(' -> '),hops:p.hops,target:p.target})))}`;
}

function showNode(id){
  const n=window._topoNodes[id];
  const box=$('#topo-details');
  if(!n||!box)return;
  box.style.display='block';
  box.innerHTML=`<b>Asset: ${esc(n.name)}</b> (${esc(n.ip||'No IP')}) · Type: <i>${esc(n.asset_type)}</i> · BU: <b>${esc(n.business_unit)}</b> · Owner: ${esc(n.owner)} · Criticality: <span class="badge ${n.criticality==='high'?'b-red':'b-yellow'}">${esc(n.criticality.toUpperCase())}</span> · Open Vulns: <b>${n.vulns_count}</b> · Max Risk Score: <b>${n.max_risk}</b>/100 ${n.crown_jewel?'· <span class="badge b-red">CROWN JEWEL</span>':''}`;
}

const WID={
  kpis:{t:'Key numbers',u:'/api/analytics',r:d=>'<div class=k>'+KP.map(([k,l,c])=>`<div class="${c||''}"><b>${d[k]}</b>${l}</div>`).join('')+'</div>'},
  urgency:{t:'How urgent is our work?',u:'/api/analytics',r:d=>{const o=d.by_urgency,O=['EMERGENCY','HIGH','MEDIUM','LOW'];return'<div class="chart-box"><canvas id="chart_urgency"></canvas></div><div class=legend>'+O.map(k=>`<span><i class="${BADGE[k]}"></i><b>${k}</b> ${o[k]||0} · ${UL[k]}</span>`).join('')+'</div>'}},
  bu:{t:'Risk by business unit',u:'/api/analytics',r:d=>'<div class="chart-box"><canvas id="chart_bu"></canvas></div>'+kv(d.by_business_unit)},
  teams:{t:'Who must fix what',u:'/api/teams',r:d=>'<div class="chart-box"><canvas id="chart_teams"></canvas></div>'+tbl(d.workload,['team','handles','open','emergency','overdue'])},
  routing:{t:'Routing rules',u:'/api/teams',r:d=>tbl(d.routing)},
  sources:{t:'Finding sources',u:'/api/sources',r:d=>tbl(d)},
  top:{t:'Top risks right now',u:'/api/findings?limit=8',r:d=>searchableTbl(d,FC)},
  allf:{t:'All findings',u:'/api/findings',r:d=>searchableTbl(d,FC)},
  paths:{t:'Attack paths to crown jewels',u:'/api/attack-paths/graph',r:d=>renderTopo(d)},
  overdue:{t:'Overdue and escalated',u:'/api/sla/overdue',r:d=>tbl(d,TC)},
  tasks:{t:'Remediation queue',u:()=>'/api/tasks'+(window.TEAM?'?team='+TEAM:''),r:d=>searchableTbl(d,TC),a:`<p>Show team: <select onchange="TEAM=this.value;load()"><option value="">All teams${opts(TEAMS)}</select></p><p>Update status: <input id=tid placeholder=TASK-0001 size=10> <select id=tst><option>IN_PROGRESS<option>REMEDIATED<option>VERIFIED<option>CLOSED</select> <button onclick="act('/api/tasks/'+$('#tid').value,'PATCH',{status:$('#tst').value})">${icon('tool')} Update</button></p><p>Reassign: <input id=rt placeholder=TASK-0001 size=10> to <select id=rteam>${opts(TEAMS)}</select> <button onclick="act('/api/tasks/'+$('#rt').value+'/reassign','PATCH',{team:$('#rteam').value})">${icon('compass')} Reassign</button></p>`},
  tickets:{t:'Ticketing view (simulated JIRA)',u:'/api/tickets',r:d=>tbl(d)},
  exc:{t:'Risk exceptions',u:'/api/exceptions',r:d=>tbl(d),a:`<p>Request: <input id=ef placeholder=FND-000003 size=11> <input id=er placeholder=reason> <button onclick="act('/api/exceptions','POST',{finding_id:$('#ef').value,reason:$('#er').value,days:30})">Request</button></p><p>Decide: <input id=ei placeholder=EXC-001 size=9> <button onclick="act('/api/exceptions/'+$('#ei').value+'/decision','POST',{decision:'APPROVED'})">${icon('check')} Approve</button> <button onclick="act('/api/exceptions/'+$('#ei').value+'/decision','POST',{decision:'REJECTED'})">${icon('close')} Reject</button></p>`},
  audit:{t:'Audit trail',u:'/api/audit',r:d=>tbl(d)},
  assets:{t:'Asset inventory (synthetic)',u:'/api/assets',r:d=>tbl(d,['asset_id','name','asset_type','business_unit','owner','criticality','internet_exposed','crown_jewel'])},
  config:{t:'Scoring weights and SLA turnaround days',u:'/api/config',r:d=>{
    const isAdmin=localStorage.role==='admin';
    const wInputs=Object.entries(d.weights).map(([k,v])=>`<div class="config-card"><label>${esc(k.replace(/_/g,' ').toUpperCase())}</label><input class="cfg-w" data-k="${esc(k)}" type="number" step="0.05" value="${v}" ${isAdmin?'':'disabled'}></div>`).join('');
    const sInputs=Object.entries(d.sla_days).map(([k,v])=>`<div class="config-card"><label>${esc(k)} (DAYS)</label><input class="cfg-s" data-k="${esc(k)}" type="number" step="1" value="${v}" ${isAdmin?'':'disabled'}></div>`).join('');
    return `<p class=hint>Scoring intel weights:</p><div class="config-grid">${wInputs}</div><p class=hint>SLA deadlines (turnaround days per urgency):</p><div class="config-grid">${sInputs}</div>${isAdmin?'<button onclick="saveConfig()">'+icon('save')+' Save and Re-score</button>':''}`;
  }},
  aistatus:{t:'AI status',u:'/api/ai/status',r:d=>{
    if(d.active_backend==='gemini')return`<p>${icon('check')} <b>Google Gemini</b> cloud AI active (<code>${esc(d.model)}</code>)</p>`;
    if(d.active_backend==='ollama')return`<p>${icon('bot')} <b>Ollama</b> local model active (<code>${esc(d.model)}</code> on <code>${esc(d.ollama_host)}</code>)</p>`;
    return`<p>${icon('alert')} Cloud and local AI not connected. Built-in rules engine active.</p>`;
  }},
  pipe:{t:'Import and scoring pipeline',r:()=>'',a:`<button onclick="act('/api/pipeline/run','POST')">${icon('play')} Run pipeline</button> <button onclick="syncFeeds()">${icon('globe')} Sync CISA KEV</button><hr style="margin:10px 0;border:none;border-top:1px solid var(--line)"><p class=hint><b>Quick scan upload</b> (JSON record):</p><input id=up_cve placeholder="CVE-2021-44228" size=14> <input id=up_host placeholder="payment-api-prod" size=16> <button onclick="uploadScan()">${icon('upload')} Upload Scan</button>`},
  ask:{t:'Ask the AI',r:()=>'',a:`<p><input id=q size=46 placeholder="What must the frontend team fix?"> <button onclick="ask()">${icon('search')} Ask</button></p><p><button onclick="act('/api/ai/executive-summary','POST')">${icon('clipboard')} Executive summary</button></p>`}
};

async function saveConfig(){
  const weights={},sla_days={};
  document.querySelectorAll('.cfg-w').forEach(inp=>weights[inp.dataset.k]=parseFloat(inp.value));
  document.querySelectorAll('.cfg-s').forEach(inp=>sla_days[inp.dataset.k]=parseInt(inp.value));
  toast('Updating configuration and re-scoring platform...');
  const r=await api('/api/config','PUT',{weights,sla_days});
  if(r.status===200){toast('Config updated and all findings re-scored');load();}else{toast('Error: '+(r.data.error||r.status));}
}

async function runSlaScan(){
  toast('Scanning SLA deadlines and exception expiries...');
  const r=await api('/api/jobs/check-sla-and-expiry','POST');
  if(r.status===200){
    show('SLA and Expiry Scan Results',`<p>Scan complete as of <b>${esc(r.data.scanned_at)}</b>:</p>
      <ul>
        <li><b>${r.data.expired_count}</b> exception(s) expired and restored to ASSIGNED status.</li>
        <li><b>${r.data.overdue_count}</b> task(s) currently past SLA deadline and escalated.</li>
      </ul>`+(r.data.overdue_tasks.length?tbl(r.data.overdue_tasks,['task_id','cve_id','asset_name','fix_team','urgency','due_date']):''));
    load();
  }else{toast('Error: '+(r.data.error||r.status));}
}

async function syncFeeds(){
  toast('Syncing threat feeds...');
  const r=await api('/api/feeds/sync','POST');
  toast(r.status<300?`Synced: ${r.data.cves_processed} CVEs, ${r.data.new_kevs_added} new KEVs`:'Error: '+(r.data.error||r.status));
  if(r.status<300)load();
}

async function uploadScan(){
  const cve=$('#up_cve')?.value,host=$('#up_host')?.value;
  if(!cve||!host)return toast('CVE and host required');
  const r=await api('/api/sources/upload','POST',[{cve_id:cve,host:host,first_seen:new Date().toISOString().slice(0,10)}]);
  toast(r.status<300?'Scan uploaded and pipeline updated':'Error: '+(r.data.error||r.status));
  if(r.status<300)load();
}

function show(t,h){
  $('#modal')?.remove();$('#veil')?.remove();
  document.body.insertAdjacentHTML('beforeend',`<div id=veil onclick=hide()></div><div id=modal><button class=x onclick=hide() style="float:right">${icon('close')}</button><h2>${t}</h2>${h}</div>`);
}
const hide=()=>{$('#modal')?.remove();$('#veil')?.remove();};

function toast(m){
  $('#toast')?.remove();
  document.body.insertAdjacentHTML('beforeend',`<div id=toast>${icon('check')} <span>${esc(m)}</span></div>`);
  setTimeout(()=>$('#toast')?.remove(),2800);
}

const ans=r=>'<p>'+esc(r.data.answer).replace(/\n/g,'<br>')+'</p><p class=hint>Backend: <b>'+esc(r.data.source||'rules')+'</b>'+(r.data.model?` (${esc(r.data.model)})`:'')+(r.data.note?` · Note: ${esc(r.data.note)}`:'')+'</p>';

async function act(p,m,b){
  const r=await api(p,m,b);
  if(r.data.answer)show('AI answer · '+r.data.source,ans(r));
  else if(p.includes('pipeline')&&r.status<300)show('Pipeline finished',`<p>${r.data.raw_records} raw records from ${r.data.sources} sources became <b>${r.data.canonical_findings}</b> findings. ${r.data.duplicates_merged} duplicates merged, ${r.data.import_errors.length} could not be matched to an asset.</p>`+tbl(r.data.import_errors,['source','error']));
  else toast(r.status<300?'Action completed successfully':'Error: '+(r.data.error||r.status));
  if(r.status<300)load();
}

async function ask(){
  const r=await api('/api/ask','POST',{question:$('#q').value});
  show('AI answer · '+(r.data.source||''),r.data.answer?ans(r):'<p>'+esc(r.data.error||'No answer')+'</p>');
}

async function openRisk(id){
  const r=await api('/api/findings/'+id+'/detail');
  if(r.status!=200)return toast('Could not load '+id);
  const d=r.data,f=d.finding,t=d.task;
  $('#drawer')?.remove();$('#veil')?.remove();
  document.body.insertAdjacentHTML('beforeend',`<div id=veil onclick=closeRisk()></div><aside id=drawer><button class=x onclick=closeRisk()>${icon('close')}</button><p class=hint>${f.finding_id}</p><h2>${esc(f.title)}</h2><p>${f.real_cve?`<a target=_blank href="${d.link}">${f.cve_id} -></a>`:`<b>${f.cve_id}</b> (internal finding, no CVE)`} · ${cell('urgency',f.urgency)} · score ${cell('risk_score',f.risk_score)}/100 · CVSS ${f.cvss_score} · ${f.cwe}</p>
  <h3>What is this risk?</h3><p>${esc(d.what)}</p><h3>Why is it in our system?</h3><ul>${d.why.map(x=>'<li>'+esc(x)+'</li>').join('')}</ul>
  <h3>Why this score and urgency</h3><p class=hint>${esc(f.urgency_label)}. The score adds up these factors (max 100):</p>${d.risk_factors.map(x=>`<div class=fr><span>${x.factor}: <b>${esc(String(x.value))}</b></span><em>+${x.points} / ${x.max_points}</em></div><div class=fbar><i style="width:${x.points/x.max_points*100}%"></i></div>`).join('')}
  <h3>Who fixes it, and by when</h3><p><b>${f.fix_team}</b> (${esc(f.fix_reason)}). Business owner: ${f.business_owner}.${t?`<br>${t.task_id} · ${cell('status',t.status)} · due <b>${t.due_date}</b> ${cell('overdue',t.overdue)}`:''}</p>
  <h3>How to fix it</h3><p>${esc(d.fix)}</p><h3>Ask the AI</h3><button onclick="aiExplain('${id}')">${icon('bot')} Explain and recommend</button><div id=aiexp class=hint></div>
  ${['admin','analyst','owner'].includes(localStorage.role)?`<h3>Cannot fix it now?</h3><input id=xr placeholder="Reason, e.g. needs maintenance window" size=32> <button onclick="reqExc('${id}')">Request exception</button>`:''}</aside>`);
  setTimeout(()=>$('#drawer').classList.add('open'),10);
}
const closeRisk=()=>{$('#drawer')?.classList.remove('open');setTimeout(()=>{$('#drawer')?.remove();$('#veil')?.remove();},250);};

async function aiExplain(id){$('#aiexp').textContent='Thinking...';const r=await api('/api/findings/'+id+'/explain','POST');$('#aiexp').innerHTML=r.data.answer?ans(r):'Error';}
async function reqExc(id){const r=await api('/api/exceptions','POST',{finding_id:id,reason:$('#xr').value,days:30});toast(r.status<300?'Exception requested: '+r.data.exception_id:'Error: '+(r.data.error||r.status));}

function help(){
  $('#menu').hidden=true;
  show('How to use this platform',`<p>Every row that shows a finding is <b>clickable</b>: click it to read what the risk is, why it is in our system, who fixes it and how.</p><dl>${GLOSS.map(([a,b])=>`<dt><b>${a}</b></dt><dd style="margin:0 0 8px">${b}</dd>`).join('')}</dl>`);
}

function shell(){
  const r=localStorage.role,I=ROLES[r],tm=localStorage.team;
  $('#top').innerHTML=`
    <a class=brand href="${r?'dashboard_'+r+'.html':'index.html'}">${icon('shield')} VulnIQ <small>Barclays IVMRP</small></a>
    <span class=pt>${document.title}</span>
    <span class=sp></span>
    ${I?`<span class=chip>${icon(I[2])} ${I[0]}${tm?` · ${icon('users')} ${tm}`:''}</span>`:''}
    <div class="header-actions">
      <button id="ham-btn" class="icon-btn ham-btn" onclick="menu(event)" aria-label="Main Menu" title="Main Menu">${icon('menu')}</button>
    </div>
    <div id=menu hidden></div>
  `;
  document.addEventListener('click',e=>{if(!e.target.closest('#menu,#ham-btn'))$('#menu').hidden=true;});
}

function renderMenu(){
  const m=$('#menu');
  if(!m)return;
  const curTheme=getTheme();
  const u=localStorage.user||'Not logged in',r=localStorage.role||'None',tm=localStorage.team;
  m.innerHTML=`
    <div class="menu-user-header">
      <div class="menu-user-name">${icon('user')} ${esc(u)}</div>
      <div class="menu-user-meta">${esc(r.toUpperCase())}${tm?` · ${esc(tm)}`:''}</div>
    </div>
    <hr>
    <a onclick="toggleTheme()" class="menu-action-item">
      ${icon(curTheme==='dark'?'sun':'moon')}
      <span>Switch to ${curTheme==='dark'?'Light':'Dark'} Mode</span>
    </a>
    <hr>
    <h4>Switch role</h4>
    ${Object.entries(ROLES).map(([k,v])=>`<a onclick="loginAs('${k}')" class="${k===localStorage.role?'on':''}">${icon(v[2])} ${v[0]}</a>`).join('')}
    <hr>
    <a onclick="help()">${icon('help')} Guide and Glossary</a>
    <a href="api_index.html">${icon('api')} API Catalog</a>
    ${localStorage.tok?`<hr><a onclick="logout()" class="menu-logout-item">${icon('logout')} Sign Out</a>`:''}
  `;
}

function menu(e){
  e.stopPropagation();
  const m=$('#menu');
  if(!m)return;
  const willShow=m.hidden;
  if(willShow){
    renderMenu();
    m.hidden=false;
  }else{
    m.hidden=true;
  }
}

const logout=()=>{localStorage.clear();location='index.html';};

async function loginAs(u){
  const r=await api('/api/login','POST',{username:u,password:u+'123'});
  if(r.status==200){
    localStorage.tok=r.data.token;
    localStorage.role=r.data.role;
    localStorage.user=r.data.username;
    localStorage.team=r.data.team||'';
    location='dashboard_'+r.data.role+'.html';
  }
}

function initCharts(cache){
  if(typeof Chart==='undefined')return;
  window._lastCache=cache;
  const isDark=getTheme()==='dark';
  const gridCol=isDark?'#334155':'#e2e8f0';
  const textCol=isDark?'#94a3b8':'#64748b';

  if($('#chart_urgency')&&cache.analytics?.by_urgency){
    if(window._charts.urgency)window._charts.urgency.destroy();
    const u=cache.analytics.by_urgency;
    window._charts.urgency=new Chart($('#chart_urgency'),{
      type:'doughnut',
      data:{
        labels:['EMERGENCY','HIGH','MEDIUM','LOW'],
        datasets:[{data:[u.EMERGENCY||0,u.HIGH||0,u.MEDIUM||0,u.LOW||0],backgroundColor:['#dc2626','#f97316','#eab308','#22c55e'],borderWidth:1,borderColor:isDark?'#111827':'#ffffff'}]
      },
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:textCol}}}}
    });
  }
  if($('#chart_bu')&&cache.analytics?.by_business_unit){
    if(window._charts.bu)window._charts.bu.destroy();
    const bu=cache.analytics.by_business_unit;
    window._charts.bu=new Chart($('#chart_bu'),{
      type:'bar',
      data:{
        labels:Object.keys(bu),
        datasets:[{label:'Findings Count',data:Object.values(bu).map(v=>typeof v==='object'?v.count:v),backgroundColor:'#0284c7'}]
      },
      options:{
        responsive:true,
        maintainAspectRatio:false,
        plugins:{legend:{display:false}},
        scales:{x:{grid:{color:gridCol},ticks:{color:textCol}},y:{beginAtZero:true,grid:{color:gridCol},ticks:{color:textCol}}}
      }
    });
  }
  if($('#chart_teams')&&cache.teams?.workload){
    if(window._charts.teams)window._charts.teams.destroy();
    const wl=cache.teams.workload;
    window._charts.teams=new Chart($('#chart_teams'),{
      type:'bar',
      data:{
        labels:wl.map(w=>w.team.replace('-team','')),
        datasets:[
          {label:'Open',data:wl.map(w=>w.open),backgroundColor:'#38bdf8'},
          {label:'Emergency',data:wl.map(w=>w.emergency),backgroundColor:'#dc2626'},
          {label:'Overdue',data:wl.map(w=>w.overdue),backgroundColor:'#ef4444'}
        ]
      },
      options:{
        responsive:true,
        maintainAspectRatio:false,
        plugins:{legend:{labels:{color:textCol}}},
        scales:{x:{grid:{color:gridCol},ticks:{color:textCol}},y:{beginAtZero:true,grid:{color:gridCol},ticks:{color:textCol}}}
      }
    });
  }
}

async function load(){
  const el=$('#w');if(!el)return;
  const cache={};
  let h='';
  for(const k of document.body.dataset.widgets.split(',')){
    const w=WID[k];let b='';
    if(w.u){
      const url=typeof w.u==='function'?w.u():w.u;
      const r=await api(url);
      if(r.status==401){location='index.html';return;}
      if(url.includes('analytics'))cache.analytics=r.data;
      if(url.includes('teams'))cache.teams=r.data;
      b=r.status==200?w.r(r.data):'<p class=hint>Error '+r.status+': '+esc(JSON.stringify(r.data))+'</p>';
    }
    h+=`<div class="card ${HALF.includes(k)?'':'full'}"><h2>${w.t}</h2><p class=hint>${HINT[k]||''}</p>${b}${w.a||''}</div>`;
  }
  el.innerHTML=h;
  initCharts(cache);
  checkAlerts();
}

async function checkAlerts(){
  const box=$('#alerts');
  if(!box)return;
  if(['admin','manager','analyst'].includes(localStorage.role)){
    const r=await api('/api/sla/overdue');
    const odCount=(r.status===200&&Array.isArray(r.data))?r.data.length:0;
    box.innerHTML=`<div class="alert-banner">
      <div>
        <b>${icon('alert')} Vulnerability Management & SLA Alert Center</b>
        <p>${odCount} task(s) currently overdue. Run automated scan to re-verify SLAs and expire outdated risk exceptions.</p>
      </div>
      <button onclick="runSlaScan()">${icon('bolt')} Run SLA & Expiry Scan</button>
    </div>`;
  }else{box.innerHTML='';}
}

function welcome(){
  const r=localStorage.role,I=ROLES[r];
  if(!I||localStorage['seen_'+r]){$('#welcome').innerHTML='';return;}
  $('#welcome').innerHTML=`<div class=welcome><h2>Welcome, ${I[0]}</h2><p>${I[1]}</p><ul><li>${TIPS[r]}</li><li>Urgency tells you how fast to act: EMERGENCY means within 2 days.</li><li>Use the user menu (top right) to switch role, change theme, or open the glossary.</li></ul><button onclick="localStorage['seen_${r}']=1;welcome()">Got it</button><button onclick="help()">Open glossary</button></div>`;
}

// Authentication Portal Handlers (Login & Sign Up)
function switchAuthTab(tab){
  const isLogin=tab==='login';
  $('#tab-login').classList.toggle('active',isLogin);
  $('#tab-signup').classList.toggle('active',!isLogin);
  $('#form-login').style.display=isLogin?'block':'none';
  $('#form-signup').style.display=isLogin?'none':'block';
  $('#login-alert').style.display='none';
  $('#signup-alert').style.display='none';
}

function toggleSignupTeam(role){
  const teamGrp=$('#signup-team-group');
  if(teamGrp)teamGrp.style.display=role==='owner'?'block':'none';
}

async function handleLogin(e){
  if(e)e.preventDefault();
  const u=$('#login-user').value.trim(),p=$('#login-pwd').value;
  const alertBox=$('#login-alert');
  alertBox.style.display='none';
  if(!u||!p){alertBox.innerText='Username and password are required.';alertBox.style.display='block';return;}
  const r=await api('/api/login','POST',{username:u,password:p});
  if(r.status===200){
    localStorage.tok=r.data.token;
    localStorage.role=r.data.role;
    localStorage.user=r.data.username;
    localStorage.team=r.data.team||'';
    toast('Authentication successful. Redirecting...');
    setTimeout(()=>{location='dashboard_'+r.data.role+'.html';},400);
  }else{
    alertBox.innerText=r.data.error||'Invalid username or password.';
    alertBox.style.display='block';
  }
}

async function handleSignup(e){
  if(e)e.preventDefault();
  const name=$('#signup-name').value.trim(),u=$('#signup-user').value.trim(),email=$('#signup-email').value.trim(),role=$('#signup-role').value,team=role==='owner'?$('#signup-team').value:'',pwd=$('#signup-pwd').value;
  const alertBox=$('#signup-alert');
  alertBox.style.display='none';
  if(!name||!u||!pwd){alertBox.innerText='Please fill in all required fields.';alertBox.style.display='block';return;}
  const r=await api('/api/signup','POST',{username:u,password:pwd,full_name:name,email:email,role:role,team:team});
  if(r.status===201){
    localStorage.tok=r.data.token;
    localStorage.role=r.data.role;
    localStorage.user=r.data.username;
    localStorage.team=r.data.team||'';
    toast('Account created successfully! Welcome to VulnIQ.');
    setTimeout(()=>{location='dashboard_'+r.data.role+'.html';},500);
  }else{
    alertBox.innerText=r.data.error||'Could not create account.';
    alertBox.style.display='block';
  }
}

function quickFill(user,pwd){
  $('#login-user').value=user;
  $('#login-pwd').value=pwd;
  handleLogin();
}

function renderAuthPortal(){
  const main=$('main');
  if(!main)return;
  main.innerHTML=`
    <div class="auth-wrap">
      <div class="auth-hero">
        <div class="auth-brand">
          ${icon('shield')}
          <h1>VulnIQ Platform</h1>
        </div>
        <p class="auth-tagline">Intelligent Vulnerability Management & Risk Prioritization</p>
        <div class="auth-points">
          <div class="point-item">
            <span class="point-icon">${icon('chart')}</span>
            <div><b>Unified Multi-Scanner Aggregation</b><p>Normalizes & deduplicates findings from network, agent, CSPM, and container scanners.</p></div>
          </div>
          <div class="point-item">
            <span class="point-icon">${icon('search')}</span>
            <div><b>Explainable 0–100 Risk Prioritization</b><p>Combines CVSS, live CISA KEV, EPSS exploitability, asset context, and attack paths.</p></div>
          </div>
          <div class="point-item">
            <span class="point-icon">${icon('compass')}</span>
            <div><b>Automated SLA Tracking & Governance</b><p>Strict SLAs, auto-escalations, non-destructive persistence, and time-limited risk exceptions.</p></div>
          </div>
        </div>
      </div>

      <div class="auth-card-container">
        <div class="card auth-card">
          <div class="auth-tabs">
            <button id="tab-login" class="tab-btn active" onclick="switchAuthTab('login')">Sign In</button>
            <button id="tab-signup" class="tab-btn" onclick="switchAuthTab('signup')">Create Account</button>
          </div>

          <!-- Sign In Form -->
          <form id="form-login" onsubmit="handleLogin(event)">
            <div id="login-alert" class="auth-alert" style="display:none"></div>
            <div class="form-group">
              <label>Username</label>
              <input id="login-user" required placeholder="Enter username (e.g. analyst)" autocomplete="username">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input id="login-pwd" type="password" required placeholder="Enter password (e.g. analyst123)" autocomplete="current-password">
            </div>
            <button type="submit" class="btn-primary w-full">Sign In</button>

            <div class="demo-pills-box">
              <p class="demo-title">Quick Demo Profiles (Click to sign in instantly):</p>
              <div class="demo-pills">
                <button type="button" class="demo-pill" onclick="quickFill('analyst','analyst123')">Security Analyst</button>
                <button type="button" class="demo-pill" onclick="quickFill('manager','manager123')">Vulnerability Manager</button>
                <button type="button" class="demo-pill" onclick="quickFill('owner','owner123')">Backend Fix Team</button>
                <button type="button" class="demo-pill" onclick="quickFill('executive','executive123')">Executive / CISO</button>
                <button type="button" class="demo-pill" onclick="quickFill('auditor','auditor123')">Auditor</button>
                <button type="button" class="demo-pill" onclick="quickFill('admin','admin123')">Platform Admin</button>
              </div>
            </div>
          </form>

          <!-- Sign Up Form -->
          <form id="form-signup" onsubmit="handleSignup(event)" style="display:none">
            <div id="signup-alert" class="auth-alert" style="display:none"></div>
            <div class="form-group">
              <label>Full Name</label>
              <input id="signup-name" required placeholder="Jane Doe">
            </div>
            <div class="form-group">
              <label>Username</label>
              <input id="signup-user" required placeholder="janedoe" autocomplete="username">
            </div>
            <div class="form-group">
              <label>Work Email</label>
              <input id="signup-email" type="email" placeholder="jane.doe@barclays.com">
            </div>
            <div class="form-group">
              <label>Platform Role</label>
              <select id="signup-role" onchange="toggleSignupTeam(this.value)">
                <option value="analyst">Security Analyst (Triage & Scan Ingestion)</option>
                <option value="manager">Vulnerability / BU Manager (SLA Oversight)</option>
                <option value="owner">Fix Team / Asset Owner (Remediation)</option>
                <option value="executive">Executive / CISO (High-Level Posture)</option>
                <option value="auditor">Compliance Auditor (Audit Trail & Scoring)</option>
              </select>
            </div>
            <div id="signup-team-group" class="form-group" style="display:none">
              <label>Assigned Remediation Team</label>
              <select id="signup-team">
                <option value="backend-dev-team">backend-dev-team (Application & API Logic)</option>
                <option value="frontend-team">frontend-team (Web UI & JavaScript/npm)</option>
                <option value="infra-ops-team">infra-ops-team (OS, Web Servers, Linux)</option>
                <option value="network-team">network-team (Load Balancers & Gateways)</option>
                <option value="dba-team">dba-team (Databases & Storage)</option>
                <option value="platform-team">platform-team (Containers & Kubernetes)</option>
                <option value="cloud-ops-team">cloud-ops-team (CSPM & Cloud Infrastructure)</option>
                <option value="iam-ops-team">iam-ops-team (Identity & Access Management)</option>
              </select>
            </div>
            <div class="form-group">
              <label>Password (min 6 characters)</label>
              <input id="signup-pwd" type="password" minlength="6" required placeholder="Create secure password" autocomplete="new-password">
            </div>
            <button type="submit" class="btn-primary w-full">Create Account & Enter</button>
          </form>
        </div>
      </div>
    </div>
  `;
}

async function runApi(){
  let p=$('#path').value,m=document.body.dataset.method,b=$('#body')?JSON.parse($('#body').value||'{}'):undefined;
  const r=await api(p,m,b);
  $('#status').textContent='HTTP '+r.status;
  $('#out').textContent=JSON.stringify(r.data,null,2);
  const rows=Array.isArray(r.data)?r.data:(r.data.paths||r.data.nodes||null);
  $('#tbl').innerHTML=rows?tbl(rows):'';
}

window.onload=()=>{
  setTheme(getTheme());
  shell();
  const isIndex=location.pathname.endsWith('index.html')||location.pathname==='/'||location.pathname==='';
  if(isIndex){
    if(localStorage.tok&&localStorage.role){
      location='dashboard_'+localStorage.role+'.html';
      return;
    }
    renderAuthPortal();
    return;
  }
  // Enforce auth on dashboard pages
  if(document.body.dataset.widgets){
    if(!localStorage.tok){
      location='index.html';
      return;
    }
    welcome();
    load();
  }
};
