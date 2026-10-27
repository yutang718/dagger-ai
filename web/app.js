/* Dagger-AI console controller (vanilla JS, no build step). */
const S = { token: localStorage.getItem("dagger_token") || "", meta: null, view: "dashboard",
            pollTimer: null };
const $ = s => document.querySelector(s);
const main = () => $("#main");
const esc = s => (s ?? "").toString().replace(/[&<>"]/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

async function api(path, opts = {}) {
  const r = await fetch("/api" + path, {
    ...opts,
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + S.token,
               ...(opts.headers || {}) },
  });
  if (r.status === 401) { logout(); throw new Error("unauthorized"); }
  if (!r.ok) { const e = await r.json().catch(()=>({detail:r.statusText})); throw new Error(e.detail || "error"); }
  return r.status === 204 ? null : r.json();
}
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.add("hidden"), 2600); }

/* ---------- auth ---------- */
$("#login-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const d = await (await fetch("/api/login", { method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ user: $("#l-user").value, password: $("#l-pass").value }) })).json();
    if (!d.token) throw new Error();
    S.token = d.token; localStorage.setItem("dagger_token", d.token); boot();
  } catch { $("#login-err").textContent = "Invalid credentials"; }
});
function logout() { S.token = ""; localStorage.removeItem("dagger_token");
  $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
$("#logout").addEventListener("click", logout);

async function boot() {
  try { S.meta = await api("/meta"); } catch { return logout(); }
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#ver").textContent = S.meta.attacker_online !== undefined ? "" : "";
  $("#ver").textContent = (S.meta.version || "1.0.0");
  $("#attacker-mode").textContent = S.meta.attacker_online ? "⚡ LLM attacker online" : "◇ Offline engine";
  show(S.view);
}
document.querySelectorAll("nav a").forEach(a =>
  a.addEventListener("click", () => { document.querySelectorAll("nav a").forEach(x=>x.classList.remove("active"));
    a.classList.add("active"); show(a.dataset.view); }));

function show(view) {
  S.view = view; clearInterval(S.pollTimer); closeDrawer();
  ({ dashboard: viewDashboard, targets: viewTargets, campaigns: viewCampaigns,
     runs: viewRuns }[view] || viewDashboard)();
}

/* ---------- dashboard ---------- */
async function viewDashboard() {
  const d = await api("/dashboard");
  const sev = d.severity_totals;
  main().innerHTML = `
    <h1>Dashboard</h1><p class="lead">Posture across all red-team runs, mapped to OWASP LLM Top 10 (2025).</p>
    <div class="cards">
      ${kpi(d.targets,"Targets")}${kpi(d.campaigns,"Campaigns")}
      ${kpi(d.runs,"Runs")}${kpi(d.findings,"Findings")}
    </div>
    <div class="grid2">
      <div class="panel"><h3>Findings by severity</h3>${donut(sev)}</div>
      <div class="panel"><h3>OWASP LLM Top 10 coverage</h3>${owaspBars(d)}</div>
    </div>
    <div class="panel"><h3>Recent runs</h3>${runsTable(d.recent_runs)}</div>`;
  bindRunRows();
}
const kpi = (n,l) => `<div class="card kpi"><div class="n">${n}</div><div class="l">${l}</div></div>`;

function donut(sev) {
  const order=["critical","high","medium","low","info"];
  const col={critical:"#e5484d",high:"#f76808",medium:"#f5a623",low:"#3b82f6",info:"#8b8d98"};
  const total = order.reduce((s,k)=>s+(sev[k]||0),0);
  let off=0, segs="";
  const C=2*Math.PI*52;
  order.forEach(k=>{ const v=sev[k]||0; if(!v)return; const frac=v/total;
    segs+=`<circle r="52" cx="70" cy="70" fill="none" stroke="${col[k]}" stroke-width="18"
      stroke-dasharray="${frac*C} ${C}" stroke-dashoffset="${-off*C}" transform="rotate(-90 70 70)"/>`;
    off+=frac; });
  const legend = order.map(k=>`<div class="spread" style="margin:4px 0">
    <span><span class="badge sev-${k}">${k}</span></span><b>${sev[k]||0}</b></div>`).join("");
  return `<div class="row" style="align-items:center;gap:26px">
    <svg width="140" height="140" viewBox="0 0 140 140">${segs||
      `<circle r="52" cx="70" cy="70" fill="none" stroke="#1a2130" stroke-width="18"/>`}
      <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800" fill="#e6edf6">${total}</text>
      <text x="70" y="86" text-anchor="middle" font-size="11" fill="#8b97ab">findings</text></svg>
    <div style="flex:1;min-width:160px">${legend}</div></div>`;
}

function owaspBars(d) {
  const max = Math.max(1, ...Object.values(d.owasp_hits));
  return Object.entries(d.owasp_labels).map(([k,label])=>{
    const n=d.owasp_hits[k]||0;
    return `<div style="margin:9px 0"><div class="spread"><span class="mono" style="font-size:12px">
      <span class="tag">${k}</span> ${esc(label)}</span><b>${n}</b></div>
      <div class="bar"><i style="width:${n/max*100}%"></i></div></div>`;
  }).join("");
}

/* ---------- targets ---------- */
async function viewTargets() {
  const ts = await api("/targets");
  main().innerHTML = `
    <div class="spread"><div><h1>Targets</h1><p class="lead">AI systems under test.</p></div>
      <div class="row"><button class="ghost" id="add-demo">+ Add bundled demo agent</button>
      <button id="add-target">+ New target</button></div></div>
    <div class="warn">⚖ Only run campaigns against systems you own or are explicitly authorized to test.
      ${S.meta.require_authorization ? "Each target must carry an authorization note before it can be attacked." : ""}</div>
    <div class="panel">${ts.length? `<table><thead><tr><th>Name</th><th>Kind</th><th>Endpoint</th>
      <th>Authorized</th><th></th></tr></thead><tbody>
      ${ts.map(t=>`<tr><td><b>${esc(t.name)}</b></td><td><span class="tag">${t.kind}</span></td>
        <td class="mono" style="font-size:12px">${esc(t.endpoint||"—")}</td>
        <td>${t.authorized?`<span class="ok">✔ yes</span>`:`<span class="no">✗ no</span>`}</td>
        <td style="text-align:right">
          ${t.authorized?"":`<button class="sm ghost" data-auth="${t.id}">Authorize</button>`}
          <button class="sm danger" data-del="${t.id}">Delete</button></td></tr>`).join("")}
      </tbody></table>`: `<div class="empty">No targets yet. Add the bundled demo agent to try a full exploit chain safely.</div>`}
    </div>`;
  $("#add-demo").onclick = async () => { await api("/targets/demo",{method:"POST"});
    toast("Demo agent registered (isolated lab target)"); viewTargets(); };
  $("#add-target").onclick = targetForm;
  main().querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    await api("/targets/"+b.dataset.del,{method:"DELETE"}); viewTargets(); });
  main().querySelectorAll("[data-auth]").forEach(b=>b.onclick=()=>authorizeForm(b.dataset.auth));
}

function targetForm() {
  openDrawer(`<h2>New target</h2>
    <label>Name</label><input id="t-name" placeholder="My chatbot (staging)">
    <label>Endpoint URL</label><input id="t-ep" placeholder="https://host/v1/chat/completions">
    <label>HTTP method</label><input id="t-method" value="POST">
    <label>Request body template <span class="no">(use {{PROMPT}})</span></label>
    <textarea id="t-body" rows="4">{"model":"your-model","messages":[{"role":"user","content":"{{PROMPT}}"}]}</textarea>
    <label>Response text path <span class="no">(dotted)</span></label>
    <input id="t-path" value="choices.0.message.content">
    <div class="row" style="margin-top:18px"><button id="t-save">Create</button>
      <button class="ghost" onclick="closeDrawer()">Cancel</button></div>`);
  $("#t-save").onclick = async () => {
    try{ await api("/targets",{method:"POST",body:JSON.stringify({
      name:$("#t-name").value, endpoint:$("#t-ep").value, http_method:$("#t-method").value,
      body_template:$("#t-body").value, response_path:$("#t-path").value })});
      closeDrawer(); viewTargets(); toast("Target created"); }
    catch(e){ toast(e.message); }
  };
}
function authorizeForm(id){
  openDrawer(`<h2>Authorize target</h2>
    <div class="warn">Confirm you have written permission to test this system. This note is recorded with every run.</div>
    <label>Authorization note</label>
    <textarea id="a-note" rows="4" placeholder="e.g. Pentest engagement #1234, scope approved by owner on 2026-10-27"></textarea>
    <div class="row" style="margin-top:16px"><button id="a-save">Confirm authorization</button>
      <button class="ghost" onclick="closeDrawer()">Cancel</button></div>`);
  $("#a-save").onclick = async () => {
    try{ await api(`/targets/${id}/authorize`,{method:"POST",body:JSON.stringify({note:$("#a-note").value})});
      closeDrawer(); viewTargets(); toast("Target authorized"); }
    catch(e){ toast(e.message); }
  };
}

/* ---------- campaigns ---------- */
async function viewCampaigns() {
  const [cs, ts] = await Promise.all([api("/campaigns"), api("/targets")]);
  const tmap = Object.fromEntries(ts.map(t=>[t.id,t]));
  main().innerHTML = `
    <div class="spread"><div><h1>Campaigns</h1><p class="lead">A campaign bundles probes + an orchestration strategy against one target.</p></div>
      <button id="new-camp">+ New campaign</button></div>
    <div class="panel">${cs.length? `<table><thead><tr><th>Name</th><th>Target</th><th>Probes</th>
      <th>Strategy</th><th></th></tr></thead><tbody>
      ${cs.map(c=>`<tr><td><b>${esc(c.name)}</b></td>
        <td>${esc(tmap[c.target_id]?.name||"—")}</td>
        <td>${(c.probes||[]).map(p=>`<span class="tag">${p}</span>`).join(" ")}</td>
        <td>${esc((S.meta.strategies[c.orchestrator]||c.orchestrator))}</td>
        <td style="text-align:right"><button class="sm" data-run="${c.id}">▶ Run</button>
          <button class="sm danger" data-del="${c.id}">Delete</button></td></tr>`).join("")}
      </tbody></table>`:`<div class="empty">No campaigns yet.</div>`}</div>`;
  $("#new-camp").onclick = () => campaignForm(ts);
  main().querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    await api("/campaigns/"+b.dataset.del,{method:"DELETE"}); viewCampaigns(); });
  main().querySelectorAll("[data-run]").forEach(b=>b.onclick=async()=>{
    try{ const r=await api(`/campaigns/${b.dataset.run}/run`,{method:"POST"});
      toast("Run started"); openRun(r.run_id); }
    catch(e){ toast("⚠ "+e.message); }});
}

function campaignForm(ts){
  if(!ts.length){ toast("Add a target first"); return; }
  const probes = S.meta.probes.map(p=>`
    <label class="probe" data-p="${p.id}">
      <input type="checkbox" value="${p.id}" ${p.id!=="agent_tool_abuse"?"checked":""}>
      <div><div class="pn">${esc(p.name)} <span class="badge sev-${p.severity}">${p.severity}</span>
        <span class="tag">${p.owasp}</span></div>
      <div class="pd">${esc(p.description)}${p.requires_tools?" · needs a tool-enabled target":""}</div></div>
    </label>`).join("");
  const strat = Object.entries(S.meta.strategies).map(([k,v])=>`<option value="${k}">${esc(v)}</option>`).join("");
  const topts = ts.map(t=>`<option value="${t.id}">${esc(t.name)}${t.authorized?"":" (not authorized)"}</option>`).join("");
  openDrawer(`<h2>New campaign</h2>
    <label>Name</label><input id="c-name" placeholder="Baseline LLM assessment">
    <label>Target</label><select id="c-target">${topts}</select>
    <label>Orchestration strategy</label><select id="c-strat">${strat}</select>
    <label>Max turns (multi-turn strategies)</label><input id="c-turns" type="number" value="4" min="1" max="8">
    <label>Probes</label><div style="display:grid;gap:8px">${probes}</div>
    <div class="row" style="margin-top:18px"><button id="c-save">Create campaign</button>
      <button class="ghost" onclick="closeDrawer()">Cancel</button></div>`);
  main().querySelectorAll(".probe").forEach(p=>{ const cb=p.querySelector("input");
    const sync=()=>p.classList.toggle("on",cb.checked); cb.onchange=sync; sync(); });
  $("#c-save").onclick = async () => {
    const chosen=[...main().querySelectorAll(".probe input:checked")].map(i=>i.value);
    if(!chosen.length){ toast("Pick at least one probe"); return; }
    try{ await api("/campaigns",{method:"POST",body:JSON.stringify({
      name:$("#c-name").value||"Untitled", target_id:+$("#c-target").value, probes:chosen,
      orchestrator:$("#c-strat").value, max_turns:+$("#c-turns").value })});
      closeDrawer(); viewCampaigns(); toast("Campaign created"); }
    catch(e){ toast(e.message); }
  };
}

/* ---------- runs ---------- */
async function viewRuns(){
  const rs = await api("/runs");
  main().innerHTML = `<h1>Runs</h1><p class="lead">Every executed assessment.</p>
    <div class="panel">${runsTable(rs)}</div>`;
  bindRunRows();
}
function runsTable(rs){
  if(!rs||!rs.length) return `<div class="empty">No runs yet.</div>`;
  return `<table><thead><tr><th>Run</th><th>Status</th><th>Attempts</th><th>Successes</th>
    <th>Worst</th><th>Started</th></tr></thead><tbody>
    ${rs.map(r=>{const s=r.summary||{};return `<tr data-run="${r.id}" style="cursor:pointer">
      <td><b>#${r.id}</b></td>
      <td><span class="status ${r.status}">${r.status==="running"?'<span class="spin"></span> ':''}${r.status}</span></td>
      <td>${s.attempts??"—"}</td><td>${s.successes??"—"}</td>
      <td>${s.worst?`<span class="badge sev-${s.worst}">${s.worst}</span>`:"—"}</td>
      <td class="no">${r.started_at?new Date(r.started_at+"Z").toLocaleString():""}</td></tr>`;}).join("")}
    </tbody></table>`;
}
function bindRunRows(){ main().querySelectorAll("[data-run]").forEach(tr=>
  tr.onclick=()=>openRun(tr.dataset.run)); }

/* ---------- run detail (live) ---------- */
async function openRun(id){
  clearInterval(S.pollTimer);
  const paint = async () => {
    let d; try{ d = await api("/runs/"+id); }catch{ return; }
    renderRun(d);
    if(["running","queued"].includes(d.run.status)) {} else clearInterval(S.pollTimer);
  };
  await paint();
  S.pollTimer = setInterval(paint, 1500);
}
function renderRun(d){
  const r=d.run, s=r.summary||{};
  const live = ["running","queued"].includes(r.status);
  main().innerHTML = `
    <div class="spread"><div><h1>Run #${r.id} <span class="status ${r.status}">
      ${live?'<span class="spin"></span> ':''}${r.status}</span></h1>
      <p class="lead">${s.attempts||0} attempts · ${s.successes||0} successful ·
      strategy visualised below</p></div>
      <div class="row">${live?`<button class="danger" id="stop">Stop</button>`:""}
      <button class="ghost" onclick="show('runs')">← All runs</button></div></div>
    ${r.error?`<div class="warn">Error: ${esc(r.error)}</div>`:""}
    <div class="panel"><h3>Attack-chain graph</h3>
      <div id="graph"></div>
      <p class="no" style="font-size:12px;margin-top:8px">Red paths = successful exploits.
      Click any node to inspect its step-by-step attack trail.</p></div>
    <div class="panel"><h3>Findings (${d.findings.length})</h3>${findingsList(d.findings)}</div>
    <div class="panel"><h3>All attempts</h3>${attemptsTable(d.attempts)}</div>`;
  if(live) $("#stop").onclick=async()=>{ await api(`/runs/${r.id}/stop`,{method:"POST"}); toast("Stopping…"); };
  AttackGraph.render($("#graph"), {attempts:d.attempts, targetName:"AI system"}, openAttempt);
  main().querySelectorAll("[data-att]").forEach(tr=>tr.onclick=()=>{
    openAttempt(d.attempts.find(a=>a.id==tr.dataset.att)); });
  main().querySelectorAll("[data-find]").forEach(c=>c.onclick=()=>{
    const f=d.findings.find(x=>x.id==c.dataset.find); openFinding(f); });
}
function findingsList(fs){
  if(!fs.length) return `<div class="empty">No successful exploits — the target resisted every probe. ✔</div>`;
  return fs.sort((a,b)=>sevScore(b.severity)-sevScore(a.severity)).map(f=>`
    <div class="step" data-find="${f.id}" style="cursor:pointer">
      <div class="sh"><span><span class="badge sev-${f.severity}">${f.severity}</span>
        <b style="margin-left:8px">${esc(f.title)}</b></span>
        <span class="tag">${f.owasp}</span></div></div>`).join("");
}
function attemptsTable(as){
  if(!as.length) return `<div class="empty">No attempts recorded yet…</div>`;
  return `<table><thead><tr><th>Probe</th><th>Technique</th><th>OWASP</th><th>Result</th>
    <th>Score</th><th>Steps</th></tr></thead><tbody>
    ${as.map(a=>`<tr data-att="${a.id}" style="cursor:pointer">
      <td>${esc(a.probe)}</td><td class="mono" style="font-size:12px">${esc(a.technique)}</td>
      <td><span class="tag">${a.owasp}</span></td>
      <td>${a.success?`<span class="badge sev-${a.severity}">exploited</span>`:`<span class="no">resisted</span>`}</td>
      <td>${(a.score*10).toFixed(1)}</td><td>${a.steps.length}</td></tr>`).join("")}
    </tbody></table>`;
}

/* ---------- drawers ---------- */
function openAttempt(a){
  if(!a) return;
  const steps = a.steps.map(s=>`
    <div class="step"><div class="sh"><span>Step ${s.idx+1} · ${esc(s.role)}</span>
      <span>${s.latency_ms} ms</span></div>
      <div class="io"><div class="lab">▸ ${esc(s.note||"attack prompt")}</div>
        <pre>${esc(s.prompt)}</pre>
        <div class="lab">target response</div>
        <pre class="resp">${esc(s.response)}</pre></div></div>`).join("");
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${a.success?"✔ ":""}${esc(a.probe)} · ${esc(a.technique)}</h2>
    <div class="row" style="gap:8px;margin-bottom:10px">
      <span class="badge sev-${a.severity}">${a.severity}</span>
      <span class="tag">${a.owasp}</span><span class="tag">${a.atlas}</span>
      <span class="tag">score ${(a.score*10).toFixed(1)}</span></div>
    <p class="no" style="font-size:13px"><b>Objective:</b> ${esc(a.objective)}</p>
    <p class="no" style="font-size:13px"><b>Judge:</b> ${esc(a.rationale)}</p>
    ${a.evidence?`<div class="lab">evidence</div><div class="evidence">${esc(a.evidence)}</div>`:""}
    <h3 style="margin-top:18px">Attack trail (${a.steps.length} steps)</h3>${steps}`);
}
function openFinding(f){
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${esc(f.title)}</h2>
    <div class="row" style="gap:8px;margin-bottom:12px">
      <span class="badge sev-${f.severity}">${f.severity}</span>
      <span class="tag">${f.owasp}</span><span class="tag">${f.atlas}</span></div>
    <div class="lab">description</div><p style="font-size:13px;white-space:pre-wrap">${esc(f.description)}</p>
    <div class="lab">evidence</div><div class="evidence">${esc(f.evidence)}</div>
    <div class="lab" style="margin-top:14px">remediation</div>
    <p style="font-size:13px;white-space:pre-wrap">${esc(f.remediation)}</p>`);
}
function openDrawer(html){ $("#drawer-body").innerHTML=html; $("#drawer").classList.remove("hidden"); }
function closeDrawer(){ $("#drawer").classList.add("hidden"); }
$("#drawer").addEventListener("click",e=>{ if(e.target.id==="drawer") closeDrawer(); });

const sevScore = s => ({critical:5,high:4,medium:3,low:2,info:1}[s]||0);

/* ---------- start ---------- */
if (S.token) boot();
