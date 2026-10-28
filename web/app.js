/* Dagger-AI console controller (vanilla JS, no build step).
   Bilingual (I18N), themeable (Theme), AI pentest + LLM/web red-team, with a
   live engagement monitor and runtime LLM configuration. */
const S = { token: localStorage.getItem("dagger_token") || "", meta: null,
            view: "dashboard", pollTimer: null };
const $ = s => document.querySelector(s);
const main = () => $("#main");
const t = (k, v) => I18N.t(k, v);
const esc = s => (s ?? "").toString().replace(/[&<>"]/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const zh = () => I18N.getLang() === "zh";

/* ---------- localized lookups over meta ---------- */
const probeName = p => (zh() && p.name_zh) ? p.name_zh : p.name;
const probeDesc = p => (zh() && p.description_zh) ? p.description_zh : p.description;
const moduleName = m => (zh() && m.name_zh) ? m.name_zh : m.name;
const strategyLabel = k => (zh() ? (S.meta.strategies_zh||{})[k] : (S.meta.strategies||{})[k]) || k;
const phaseLabel = p => (zh() ? (S.meta.phases_zh||{})[p] : p) || p;
function owaspLabel(code) {
  const m = zh() ? {...S.meta.owasp_llm_zh, ...S.meta.owasp_web_zh}
                 : {...S.meta.owasp_llm, ...S.meta.owasp_web};
  return m[code] || code;
}
const sevLabel = s => (zh() ? (S.meta.severity_zh||{})[s] : s) || s;
const statusLabel = s => t("status." + s);
const fmtDate = ts => ts ? new Date(ts + "Z").toLocaleString(zh() ? "zh-CN" : undefined) : "";

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
function toast(msg) { const el = $("#toast"); el.textContent = msg; el.classList.remove("hidden");
  clearTimeout(el._t); el._t = setTimeout(() => el.classList.add("hidden"), 2600); }

/* ---------- i18n + controls ---------- */
function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach(e => e.textContent = t(e.dataset.i18n));
  $("#l-subtitle").textContent = t("login.subtitle");
  $("#l-legal").textContent = t("login.legal");
  $("#l-signin").textContent = t("login.signin");
  $("#l-user").placeholder = t("login.user");
  $("#l-pass").placeholder = t("login.pass");
  buildLoginLang();
}
function seg(id, items, onPick) {
  const box = $(id); if (!box) return;
  box.innerHTML = items.map(it =>
    `<a data-k="${it.key}" class="${it.active ? "on" : ""}">${esc(it.label)}</a>`).join("");
  box.querySelectorAll("a").forEach(a => a.onclick = () => onPick(a.dataset.k));
}
function buildLoginLang() {
  const box = $("#l-lang"); if (!box) return;
  box.innerHTML = [["en","EN"],["zh","中文"]].map(([k,l]) =>
    `<a data-k="${k}" class="${I18N.getLang()===k?"on":""}">${l}</a>`).join("");
  box.querySelectorAll("a").forEach(a => a.onclick = () => { I18N.setLang(a.dataset.k); applyI18n(); });
}
function buildControls() {
  seg("#seg-lang", [{key:"en",label:"EN",active:I18N.getLang()==="en"},
                    {key:"zh",label:"中",active:I18N.getLang()==="zh"}],
      k => { I18N.setLang(k); applyI18n(); buildControls(); refreshAttackerPill(); show(S.view); });
  const selT=$("#sel-theme");
  selT.innerHTML=Theme.THEMES.map(x=>`<option value="${x}" ${Theme.getTheme()===x?"selected":""}>${t("theme."+x)}</option>`).join("");
  selT.onchange=()=>{ Theme.setTheme(selT.value); show(S.view); };
  const selF=$("#sel-font");
  selF.innerHTML=Theme.FONTS.map(x=>`<option value="${x}" ${Theme.getFont()===x?"selected":""}>${t("font."+x)}</option>`).join("");
  selF.onchange=()=>{ Theme.setFont(selF.value); };
}
function refreshAttackerPill() {
  const on = S.meta && ((S.meta.llm && S.meta.llm.online) || S.meta.attacker_online);
  const el = $("#attacker-mode");
  el.textContent = on ? "⚡ " + t("side.attackerOnline") : "◇ " + t("side.offline");
  el.classList.toggle("on", !!on);
}

/* ---------- auth ---------- */
$("#login-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const d = await (await fetch("/api/login", { method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ user: $("#l-user").value, password: $("#l-pass").value }) })).json();
    if (!d.token) throw new Error();
    S.token = d.token; localStorage.setItem("dagger_token", d.token); boot();
  } catch { $("#login-err").textContent = t("login.err"); }
});
function logout() { S.token = ""; localStorage.removeItem("dagger_token");
  clearInterval(S.pollTimer); $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
$("#logout").addEventListener("click", logout);

async function boot() {
  try { S.meta = await api("/meta"); } catch { return logout(); }
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#ver").textContent = S.meta.version || "1.0.0";
  applyI18n(); buildControls(); refreshAttackerPill();
  show(S.view);
}
document.querySelectorAll("nav a").forEach(a =>
  a.addEventListener("click", () => show(a.dataset.view)));

function show(view) {
  S.view = view; clearInterval(S.pollTimer); closeDrawer();
  document.querySelectorAll("nav a").forEach(x => x.classList.toggle("active", x.dataset.view === view));
  ({ dashboard: viewDashboard, targets: viewTargets, campaigns: viewCampaigns,
     runs: viewRuns, monitor: viewMonitor, settings: viewSettings }[view] || viewDashboard)();
}

/* ---------- dashboard ---------- */
async function viewDashboard() {
  const d = await api("/dashboard");
  let tools = null; try { tools = await api("/tools/status"); } catch {}
  const sev = d.severity_totals;
  main().innerHTML = `
    <h1>${t("dashboard.title")}</h1><p class="lead">${t("dashboard.lead")}</p>
    <div class="cards">
      ${kpi(d.targets,t("kpi.targets"))}${kpi(d.campaigns,t("kpi.campaigns"))}
      ${kpi(d.runs,t("kpi.runs"))}${kpi(d.findings,t("kpi.findings"))}
    </div>
    <div class="grid2">
      <div class="panel"><h3>${t("dash.sevTitle")}</h3>${donut(sev)}</div>
      <div class="panel"><h3>${t("dash.domainTitle")}</h3>${domainSplit(d)}</div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>${t("dash.llmTitle")}</h3>${owaspBars(d.owasp_llm_hits)}</div>
      <div class="panel"><h3>${t("dash.webTitle")}</h3>${owaspBars(d.owasp_web_hits)}</div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>${t("dash.toolRunner")}</h3>${toolStatus(tools)}</div>
      <div class="panel"><h3>${t("usage.title")}</h3>${usagePanel(d.llm_usage)}</div>
    </div>
    <div class="panel"><h3>${t("dash.recent")}</h3>${runsTable(d.recent_runs)}</div>`;
  bindRunRows();
}
function toolStatus(tl){
  if(!tl || !tl.tools || !Object.keys(tl.tools).length)
    return `<div class="no" style="font-size:13px">${t("dash.toolDown")}</div>`;
  return `<div class="row" style="gap:8px;flex-wrap:wrap">`+Object.entries(tl.tools).map(([k,v])=>
    `<span class="tag" style="border-color:${v?'var(--ok)':'var(--line)'};color:${v?'var(--ok)':'var(--muted)'}">`
    + (v?'✔':'✗') + ` ${k}</span>`).join("")+`</div>
    <p class="no" style="font-size:12px;margin-top:8px">${t("dash.toolNote")}</p>`;
}
function domainSplit(d){
  const llm=Object.values(d.owasp_llm_hits).reduce((a,b)=>a+b,0);
  const web=Object.values(d.owasp_web_hits).reduce((a,b)=>a+b,0);
  const tot=Math.max(1,llm+web);
  return `<div style="padding:8px 0">
    <div class="spread"><span>🤖 ${t("dash.llmSystems")}</span><b>${llm}</b></div>
    <div class="bar"><i style="width:${llm/tot*100}%"></i></div>
    <div class="spread" style="margin-top:14px"><span>🌐 ${t("dash.webApps")}</span><b>${web}</b></div>
    <div class="bar"><i style="width:${web/tot*100}%;background:linear-gradient(90deg,var(--high),var(--med))"></i></div>
    <p class="no" style="font-size:12px;margin-top:14px">${t("dash.domainNote")}</p></div>`;
}
const kpi = (n,l) => `<div class="card kpi"><div class="n">${n}</div><div class="l">${l}</div></div>`;

function usagePanel(u){
  u=u||{};
  if(!u.total_tokens) return `<div class="no" style="font-size:13px;padding:6px 0">${t("usage.none")}</div>`;
  return `<div class="usage" style="padding:6px 0">
    <span><b>${(u.total_tokens||0).toLocaleString()}</b> ${t("usage.tokens")}</span>
    <span class="ucost">~$${(u.cost_usd||0).toFixed(4)}</span>
    <span><b>${u.calls||0}</b> ${t("usage.calls")}</span></div>
    <p class="no" style="font-size:11px;margin-top:8px">${t("usage.est")}</p>`;
}
function usageInline(u){
  u=u||{}; if(!u.total_tokens) return "";
  return ` · <span class="usage" style="display:inline-flex"><b>${(u.total_tokens||0).toLocaleString()}</b> ${t("usage.tokens")}
    <span class="ucost">~$${(u.cost_usd||0).toFixed(4)}</span></span>`;
}

function donut(sev) {
  const order=["critical","high","medium","low","info"];
  const col={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)",info:"var(--info)"};
  const total = order.reduce((s,k)=>s+(sev[k]||0),0);
  let off=0, segs="";
  const C=2*Math.PI*52;
  order.forEach(k=>{ const v=sev[k]||0; if(!v)return; const frac=v/total;
    segs+=`<circle r="52" cx="70" cy="70" fill="none" stroke="${col[k]}" stroke-width="18"
      stroke-dasharray="${frac*C} ${C}" stroke-dashoffset="${-off*C}" transform="rotate(-90 70 70)"/>`;
    off+=frac; });
  const legend = order.map(k=>`<div class="spread" style="margin:4px 0">
    <span><span class="badge sev-${k}">${sevLabel(k)}</span></span><b>${sev[k]||0}</b></div>`).join("");
  return `<div class="row donut" style="align-items:center;gap:26px">
    <svg width="140" height="140" viewBox="0 0 140 140">${segs||
      `<circle r="52" cx="70" cy="70" fill="none" stroke="var(--line)" stroke-width="18"/>`}
      <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800">${total}</text>
      <text x="70" y="86" text-anchor="middle" font-size="11" class="sub">${t("donut.findings")}</text></svg>
    <div style="flex:1;min-width:160px">${legend}</div></div>`;
}
function owaspBars(hits) {
  const max = Math.max(1, ...Object.values(hits));
  return Object.entries(hits).map(([k,n])=>`<div style="margin:9px 0"><div class="spread">
      <span style="font-size:12px"><span class="tag">${k}</span> ${esc(owaspLabel(k))}</span><b>${n}</b></div>
      <div class="bar"><i style="width:${n/max*100}%"></i></div></div>`).join("");
}

/* ---------- targets ---------- */
async function viewTargets() {
  const ts = await api("/targets");
  main().innerHTML = `
    <div class="spread"><div><h1>${t("targets.title")}</h1><p class="lead">${t("targets.lead")}</p></div>
      <div class="row"><button class="ghost" id="add-demo-host">${t("targets.addDemoHost")}</button>
      <button class="ghost" id="add-demo-web">${t("targets.addDemoWeb")}</button>
      <button class="ghost" id="add-demo">${t("targets.addDemo")}</button>
      <button id="add-target">${t("targets.new")}</button></div></div>
    <div class="warn">${t("targets.warn")}
      ${S.meta.require_authorization ? t("targets.authEach") : ""}</div>
    <div class="panel">${ts.length? `<table><thead><tr><th>${t("col.name")}</th><th>${t("col.kind")}</th>
      <th>${t("col.endpoint")}</th><th>${t("col.authorized")}</th><th></th></tr></thead><tbody>
      ${ts.map(x=>`<tr><td><b>${esc(x.name)}</b></td><td><span class="tag">${x.kind}</span></td>
        <td class="mono" style="font-size:12px">${esc(x.endpoint||"—")}</td>
        <td>${x.authorized?`<span class="ok">✔ ${t("common.yes")}</span>`:`<span class="no">✗ ${t("common.no")}</span>`}</td>
        <td style="text-align:right">
          ${x.authorized?"":`<button class="sm ghost" data-auth="${x.id}">${t("common.authorize")}</button>`}
          <button class="sm danger" data-del="${x.id}">${t("common.delete")}</button></td></tr>`).join("")}
      </tbody></table>`: `<div class="empty">${t("targets.empty")}</div>`}
    </div>`;
  $("#add-demo").onclick = async () => { await api("/targets/demo",{method:"POST"});
    toast(t("targets.demoRegistered")); viewTargets(); };
  $("#add-demo-web").onclick = async () => { await api("/targets/demo_web",{method:"POST"});
    toast(t("targets.demoWebRegistered")); viewTargets(); };
  $("#add-demo-host").onclick = async () => { await api("/targets/demo_host",{method:"POST"});
    toast(t("targets.demoHostRegistered")); viewTargets(); };
  $("#add-target").onclick = targetForm;
  main().querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    await api("/targets/"+b.dataset.del,{method:"DELETE"}); viewTargets(); });
  main().querySelectorAll("[data-auth]").forEach(b=>b.onclick=()=>authorizeForm(b.dataset.auth));
}

function targetForm() {
  openDrawer(`<h2>${t("targetForm.title")}</h2>
    <label>${t("form.type")}</label>
    <select id="t-kind">
      <option value="host">${t("form.kindHost")}</option>
      <option value="web_app">${t("form.kindWebBuiltin")}</option>
      <option value="http_chat">${t("form.kindChat")}</option>
    </select>
    <label>${t("form.name")}</label><input id="t-name" placeholder="My app (staging)">
    <label id="ep-lab">${t("form.targetHostUrl")}</label>
    <input id="t-ep" placeholder="${t("form.hostPh")}">
    <div id="chat-fields">
      <label>${t("form.method")}</label><input id="t-method" value="POST">
      <label>${t("form.bodyTpl")} <span class="no">${t("form.bodyHint")}</span></label>
      <textarea id="t-body" rows="4">{"model":"your-model","messages":[{"role":"user","content":"{{PROMPT}}"}]}</textarea>
      <label>${t("form.respPath")} <span class="no">${t("form.respHint")}</span></label>
      <input id="t-path" value="choices.0.message.content">
    </div>
    <div class="row" style="margin-top:18px"><button id="t-save">${t("common.create")}</button>
      <button class="ghost" onclick="closeDrawer()">${t("common.cancel")}</button></div>`);
  const sync=()=>{ const k=$("#t-kind").value; const chat=k==="http_chat";
    $("#chat-fields").style.display=chat?"block":"none";
    $("#ep-lab").textContent = k==="host" ? t("form.targetHostUrl")
      : k==="web_app" ? t("form.baseUrl") : t("form.endpoint");
    $("#t-ep").placeholder = k==="host" ? t("form.hostPh")
      : k==="web_app" ? "https://app.example.com" : "https://host/v1/chat/completions"; };
  $("#t-kind").onchange=sync; sync();
  $("#t-save").onclick = async () => {
    const chat=$("#t-kind").value==="http_chat";
    try{ await api("/targets",{method:"POST",body:JSON.stringify({
      name:$("#t-name").value, kind:$("#t-kind").value, endpoint:$("#t-ep").value,
      http_method: chat?$("#t-method").value:"GET",
      body_template: chat?$("#t-body").value:"",
      response_path: chat?$("#t-path").value:"" })});
      closeDrawer(); viewTargets(); toast(t("toast.targetCreated")); }
    catch(e){ toast(e.message); }
  };
}
function authorizeForm(id){
  openDrawer(`<h2>${t("authForm.title")}</h2>
    <div class="warn">${t("authForm.warn")}</div>
    <label>${t("authForm.note")}</label>
    <textarea id="a-note" rows="4" placeholder="${t("authForm.notePh")}"></textarea>
    <div class="row" style="margin-top:16px"><button id="a-save">${t("authForm.confirm")}</button>
      <button class="ghost" onclick="closeDrawer()">${t("common.cancel")}</button></div>`);
  $("#a-save").onclick = async () => {
    try{ await api(`/targets/${id}/authorize`,{method:"POST",body:JSON.stringify({note:$("#a-note").value})});
      closeDrawer(); viewTargets(); toast(t("toast.targetAuthorized")); }
    catch(e){ toast(e.message); }
  };
}

/* ---------- campaigns ---------- */
async function viewCampaigns() {
  const [cs, ts] = await Promise.all([api("/campaigns"), api("/targets")]);
  const tmap = Object.fromEntries(ts.map(x=>[x.id,x]));
  main().innerHTML = `
    <div class="spread"><div><h1>${t("campaigns.title")}</h1><p class="lead">${t("campaigns.lead")}</p></div>
      <button id="new-camp">${t("campaigns.new")}</button></div>
    <div class="panel">${cs.length? `<table><thead><tr><th>${t("col.name")}</th><th>${t("col.target")}</th>
      <th>${t("col.probes")}</th><th>${t("col.strategy")}</th><th></th></tr></thead><tbody>
      ${cs.map(c=>`<tr><td><b>${esc(c.name)}</b></td>
        <td>${esc(tmap[c.target_id]?.name||"—")}</td>
        <td>${(c.probes||[]).map(p=>`<span class="tag">${p}</span>`).join(" ")}</td>
        <td>${esc(strategyLabel(c.orchestrator))}</td>
        <td style="text-align:right"><button class="sm" data-run="${c.id}">▶ ${t("common.run")}</button>
          <button class="sm danger" data-del="${c.id}">${t("common.delete")}</button></td></tr>`).join("")}
      </tbody></table>`:`<div class="empty">${t("campaigns.empty")}</div>`}</div>`;
  $("#new-camp").onclick = () => campaignForm(ts);
  main().querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    await api("/campaigns/"+b.dataset.del,{method:"DELETE"}); viewCampaigns(); });
  main().querySelectorAll("[data-run]").forEach(b=>b.onclick=async()=>{
    try{ const r=await api(`/campaigns/${b.dataset.run}/run`,{method:"POST"});
      toast(t("toast.runStarted")); openRun(r.run_id); }
    catch(e){ toast("⚠ "+e.message); }});
}

function campaignForm(ts){
  if(!ts.length){ toast(t("toast.addTarget")); return; }
  const strat = Object.keys(S.meta.strategies).map(k=>`<option value="${k}">${esc(strategyLabel(k))}</option>`).join("");
  const topts = ts.map(x=>`<option value="${x.id}" data-kind="${x.kind}">${esc(x.name)}${x.authorized?"":t("notAuthorized")}</option>`).join("");
  openDrawer(`<h2>${t("campaignForm.title")}</h2>
    <label>${t("campaignForm.name")}</label><input id="c-name" placeholder="${t("campaignForm.namePh")}">
    <label>${t("campaignForm.target")}</label><select id="c-target">${topts}</select>
    <div id="strat-wrap"><label>${t("campaignForm.strategy")}</label><select id="c-strat">${strat}</select>
    <label>${t("campaignForm.maxTurns")}</label><input id="c-turns" type="number" value="4" min="1" max="8"></div>
    <label>${t("campaignForm.probes")} <span id="probe-domain" class="no"></span></label>
    <div id="probe-list" style="display:grid;gap:8px"></div>
    <div class="row" style="margin-top:18px"><button id="c-save">${t("campaignForm.create")}</button>
      <button class="ghost" onclick="closeDrawer()">${t("common.cancel")}</button></div>`);
  const renderProbes=()=>{
    const opt=$("#c-target").selectedOptions[0];
    const kind=opt?opt.dataset.kind:"http_chat";
    let html="";
    if(kind==="host"){
      $("#probe-domain").textContent=t("domain.host");
      $("#strat-wrap").style.display="none";
      html=(S.meta.pentest_modules||[]).map(m=>`
        <label class="probe" data-p="${m.id}">
          <input type="checkbox" value="${m.id}" checked>
          <div><div class="pn">${esc(moduleName(m))}
            <span class="tag">${esc(phaseLabel(m.phase))}</span> <span class="tag">${m.tool}</span></div></div>
        </label>`).join("");
    } else {
      const cat = kind==="web_app" ? "web" : "llm";
      $("#probe-domain").textContent = cat==="web" ? t("domain.web") : t("domain.llm");
      $("#strat-wrap").style.display = cat==="web" ? "none" : "block";
      html=S.meta.probes.filter(p=>p.category===cat).map(p=>`
        <label class="probe" data-p="${p.id}">
          <input type="checkbox" value="${p.id}" checked>
          <div><div class="pn">${esc(probeName(p))} <span class="badge sev-${p.severity}">${sevLabel(p.severity)}</span>
            <span class="tag">${p.owasp}</span> <span class="tag">${p.mitre}</span></div>
          <div class="pd">${esc(probeDesc(p))}${p.requires_tools?t("probe.needsTools"):""}</div></div>
        </label>`).join("");
    }
    $("#probe-list").innerHTML=html;
    $("#probe-list").querySelectorAll(".probe").forEach(p=>{ const cb=p.querySelector("input");
      const s=()=>p.classList.toggle("on",cb.checked); cb.onchange=s; s(); });
  };
  $("#c-target").onchange=renderProbes; renderProbes();
  $("#c-save").onclick = async () => {
    const chosen=[...$("#probe-list").querySelectorAll("input:checked")].map(i=>i.value);
    if(!chosen.length){ toast(t("toast.pickModule")); return; }
    const kind=($("#c-target").selectedOptions[0]||{}).dataset?.kind;
    try{ await api("/campaigns",{method:"POST",body:JSON.stringify({
      name:$("#c-name").value||"Untitled", target_id:+$("#c-target").value, probes:chosen,
      orchestrator:$("#c-strat").value,
      max_turns: kind==="host" ? 12 : +($("#c-turns").value||4) })});
      closeDrawer(); viewCampaigns(); toast(t("toast.campaignCreated")); }
    catch(e){ toast(e.message); }
  };
}

/* ---------- runs ---------- */
async function viewRuns(){
  const rs = await api("/runs");
  main().innerHTML = `<h1>${t("runs.title")}</h1><p class="lead">${t("runs.lead")}</p>
    <div class="panel">${runsTable(rs)}</div>`;
  bindRunRows();
}
function runsTable(rs){
  if(!rs||!rs.length) return `<div class="empty">${t("runs.empty")}</div>`;
  return `<table><thead><tr><th>${t("col.run")}</th><th>${t("col.status")}</th><th>${t("col.attempts")}</th>
    <th>${t("col.successes")}</th><th>${t("col.worst")}</th><th>${t("col.started")}</th></tr></thead><tbody>
    ${rs.map(r=>{const s=r.summary||{};return `<tr data-run="${r.id}" style="cursor:pointer">
      <td><b>#${r.id}</b></td>
      <td><span class="status ${r.status}">${r.status==="running"?'<span class="spin"></span> ':''}${statusLabel(r.status)}</span></td>
      <td>${s.attempts??"—"}</td><td>${s.successes??"—"}</td>
      <td>${s.worst?`<span class="badge sev-${s.worst}">${sevLabel(s.worst)}</span>`:"—"}</td>
      <td class="no">${fmtDate(r.started_at)}</td></tr>`;}).join("")}
    </tbody></table>`;
}
function bindRunRows(){ main().querySelectorAll("[data-run]").forEach(tr=>
  tr.onclick=()=>openRun(tr.dataset.run)); }

/* ---------- run detail (live) ---------- */
async function openRun(id){
  clearInterval(S.pollTimer); S.view = "runs";
  const paint = async () => {
    let d; try{ d = await api("/runs/"+id); }catch{ return; }
    renderRun(d);
    if(!["running","queued"].includes(d.run.status)) clearInterval(S.pollTimer);
  };
  await paint();
  S.pollTimer = setInterval(paint, 1500);
}
function renderRun(d){
  const r=d.run, s=r.summary||{};
  const live = ["running","queued"].includes(r.status);
  const plan=d.attempts.find(a=>a.phase==="plan");
  const report=d.attempts.find(a=>a.phase==="report");
  const validation=d.attempts.find(a=>a.phase==="validate");
  const steps=d.attempts.filter(a=>!["plan","report","validate"].includes(a.phase));
  main().innerHTML = `
    <div class="spread"><div><h1>${t("run.title")} #${r.id} <span class="status ${r.status}">
      ${live?'<span class="spin"></span> ':''}${statusLabel(r.status)}</span></h1>
      <p class="lead">${t("run.summary",{a:s.attempts||0,s:s.successes||0})}${usageInline(s.usage)}</p></div>
      <div class="row">${live?`<button class="danger" id="stop">${t("common.stop")}</button>`:""}
      <button class="ghost" id="back-runs">${t("common.back")}</button></div></div>
    ${r.error?`<div class="warn">${t("run.error")}: ${esc(r.error)}</div>`:""}
    ${plan?playbookPanel(t("run.playbook"),plan):""}
    <div class="panel"><h3>${t("run.graphTitle")}</h3>
      <div id="graph"></div>
      <p class="no" style="font-size:12px;margin-top:8px">${t("run.graphNote")}</p></div>
    <div class="panel"><h3>${t("run.findingsTitle",{n:d.findings.length})}</h3>
      <div class="scrollbox">${findingsList(d.findings)}</div></div>
    <div class="panel"><h3>${t("run.phasesTitle")}</h3>${phaseGroups(steps)}</div>
    ${validation?playbookPanel(t("run.validation"),validation):""}
    ${report?playbookPanel(t("run.execSummary"),report):""}`;
  $("#back-runs").onclick=()=>show("runs");
  if(live) $("#stop").onclick=async()=>{ await api(`/runs/${r.id}/stop`,{method:"POST"}); toast(t("common.stop")+"…"); };
  AttackGraph.render($("#graph"), {attempts:steps, targetLabel:"Target", targetName:"",
    resistedLabel:t("result.clean")}, openAttempt);
  main().querySelectorAll("[data-att]").forEach(tr=>tr.onclick=()=>{
    openAttempt(d.attempts.find(a=>a.id==tr.dataset.att)); });
  main().querySelectorAll("[data-find]").forEach(c=>c.onclick=()=>{
    openFinding(d.findings.find(x=>x.id==c.dataset.find)); });
}
function playbookPanel(title, a){
  const s=(a.steps&&a.steps[0])||{};
  return `<div class="panel"><h3>${esc(title)}</h3>
    ${s.note?`<div class="pb-note">${esc(s.note)}</div>`:""}
    <div class="playbook">${esc(s.response||"")}</div></div>`;
}
const PHASE_ORDER=["recon","fingerprint","discovery","vuln","exploit"];
function phaseGroups(as){
  if(!as.length) return `<div class="empty">${t("run.noAttempts")}</div>`;
  const groups={};
  as.forEach(a=>{ (groups[a.phase||"_"]=groups[a.phase||"_"]||[]).push(a); });
  const order=[...PHASE_ORDER,"_"].filter(p=>groups[p]);
  Object.keys(groups).forEach(p=>{ if(!order.includes(p)) order.push(p); });
  return order.map(p=>{
    const items=groups[p]; if(!items) return "";
    const label = p==="_" ? t("run.attemptsTitle") : phaseLabel(p);
    const hits=items.filter(a=>a.success).length;
    return `<div class="phase">
      <div class="phase-head"><span class="dot"></span>${esc(label)}
        <span class="ln"></span><span>${items.length}${hits?` · ${hits}✓`:""}</span></div>
      ${items.map(atkRow).join("")}</div>`;
  }).join("");
}
function atkRow(a){
  const s0=(a.steps&&a.steps[0])||{};
  const sub=(s0.prompt||a.rationale||"").slice(0,120);
  return `<div class="atk ${a.success?"ok":""}" data-att="${a.id}">
    <span class="ti"><div class="tn">${esc(a.technique)}
      ${a.success?`<span class="badge sev-${a.severity}">${t("result.finding")}</span>`
                 :`<span class="no" style="font-size:11px">${t("result.clean")}</span>`}
      ${a.owasp?`<span class="tag">${a.owasp}</span>`:""}${a.atlas?`<span class="tag">${a.atlas}</span>`:""}</div>
      ${sub?`<div class="tc">${esc(sub)}</div>`:""}</span>
    <span class="chev">›</span></div>`;
}
function findingsList(fs){
  if(!fs.length) return `<div class="empty">${t("run.noFindings")}</div>`;
  return fs.slice().sort((a,b)=>sevScore(b.severity)-sevScore(a.severity)).map(f=>`
    <div class="step" data-find="${f.id}" style="cursor:pointer">
      <div class="sh"><span><span class="badge sev-${f.severity}">${sevLabel(f.severity)}</span>
        <b style="margin-left:8px">${esc(f.title)}</b></span>
        <span class="tag">${f.owasp}</span></div></div>`).join("");
}
function attemptsTable(as){
  if(!as.length) return `<div class="empty">${t("run.noAttempts")}</div>`;
  const hasPhase = as.some(a=>a.phase);
  return `<table><thead><tr>${hasPhase?`<th>${t("col.phase")}</th>`:''}<th>${t("col.technique")}</th>
    <th>${t("col.owasp")}</th><th>${t("col.mitre")}</th><th>${t("col.result")}</th><th>${t("col.steps")}</th></tr></thead><tbody>
    ${as.map(a=>`<tr data-att="${a.id}" style="cursor:pointer">
      ${hasPhase?`<td><span class="tag">${esc(phaseLabel(a.phase)||'–')}</span></td>`:''}
      <td class="mono" style="font-size:12px">${esc(a.technique)}</td>
      <td>${a.owasp?`<span class="tag">${a.owasp}</span>`:'–'}</td>
      <td>${a.atlas?`<span class="tag">${a.atlas}</span>`:'–'}</td>
      <td>${a.success?`<span class="badge sev-${a.severity}">${t("result.finding")}</span>`:`<span class="no">${t("result.clean")}</span>`}</td>
      <td>${a.steps.length}</td></tr>`).join("")}
    </tbody></table>`;
}

/* ---------- live monitor ---------- */
async function viewMonitor(){
  clearInterval(S.pollTimer);
  const [rs, cs, ts] = await Promise.all([api("/runs"), api("/campaigns"), api("/targets")]);
  if(!rs.length){ main().innerHTML =
    `<h1>${t("monitor.title")}</h1><p class="lead">${t("monitor.lead")}</p>
     <div class="panel"><div class="empty">${t("monitor.noRun")}</div></div>`; return; }
  const cmap=Object.fromEntries(cs.map(c=>[c.id,c])), tmap=Object.fromEntries(ts.map(x=>[x.id,x]));
  const active = rs.find(r=>["running","queued"].includes(r.status)) || rs[0];
  const paint = async () => {
    let d; try{ d = await api("/runs/"+active.id); }catch{ return; }
    renderMonitor(d, cmap, tmap);
    if(!["running","queued"].includes(d.run.status)) clearInterval(S.pollTimer);
  };
  await paint();
  S.pollTimer = setInterval(paint, 1000);
}
function renderMonitor(d, cmap, tmap){
  const r=d.run, live=["running","queued"].includes(r.status);
  const camp=cmap[r.campaign_id]||{}, tgt=tmap[camp.target_id]||{};
  const attempts=d.attempts||[];
  const events=[]; const lat=[];
  attempts.forEach(a=>a.steps.forEach(st=>{ lat.push(st.latency_ms||0); events.push({a, st}); }));
  const done=attempts.length, succ=attempts.filter(a=>a.success).length;
  const rate=done?Math.round(succ/done*100):0;
  const avg=lat.length?Math.round(lat.reduce((x,y)=>x+y,0)/lat.length):0;
  const last=attempts[attempts.length-1];
  const cur = live && last ? (phaseLabel(last.phase)||last.technique||last.probe) : "—";
  main().innerHTML = `
    <div class="mon-head">
      <h1 style="margin:0">${t("monitor.title")}</h1>
      ${live?`<span class="live-dot"></span><span class="live-tag">${t("monitor.live")}</span>`
            :`<span class="status ${r.status}">${statusLabel(r.status)}</span>`}
      <span class="tag">#${r.id}</span>
      <span class="no" style="font-size:12px">${t("monitor.target")}: <b>${esc(tgt.name||"—")}</b> ·
        ${t("monitor.strategy")}: <b>${esc(strategyLabel(camp.orchestrator||"single_turn"))}</b>${usageInline((r.summary||{}).usage)}</span>
      <a class="no" id="mon-open" style="margin-left:auto;font-size:12px">${t("monitor.viewFull")}</a>
    </div>
    <p class="lead">${live?t("monitor.lead"):t("monitor.idle")}</p>
    <div class="mon-tiles">
      <div class="mtile"><div class="mv">${done}<span class="no" style="font-size:14px"> / ${succ}✓</span></div>
        <div class="ml">${t("monitor.throughput")}</div></div>
      <div class="mtile"><div class="mv" style="color:${rate?'var(--crit)':'var(--ink)'}">${rate}%</div>
        <div class="ml">${t("monitor.successRate")}</div></div>
      <div class="mtile"><div class="mv">${avg}<span class="no" style="font-size:14px"> ms</span></div>
        <div class="ml">${t("monitor.avgLatency")}</div></div>
      <div class="mtile"><div class="mv sm">${esc(cur)}</div><div class="ml">${t("monitor.currentProbe")}</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>${t("run.graphTitle")}</h3><div id="mon-graph"></div></div>
      <div class="panel"><h3>${t("monitor.latencyTrend")}</h3>${sparkline(lat)}
        <h3 style="margin-top:16px">${t("monitor.liveFeed")}</h3>
        <div class="feed">${feedHtml(events)}</div></div>
    </div>`;
  $("#mon-open").onclick=()=>openRun(r.id);
  AttackGraph.render($("#mon-graph"), {attempts, targetLabel:"Target", targetName:tgt.name||"",
    resistedLabel:t("result.clean")}, openAttempt);
}
function sparkline(vals){
  if(!vals.length) return `<div class="no" style="font-size:12px;padding:16px 0">${t("monitor.waiting")}</div>`;
  const W=100, H=70, max=Math.max(...vals,1), n=vals.length;
  const pts=vals.map((v,i)=>`${n<2?0:(i/(n-1)*W).toFixed(1)},${(H-v/max*(H-8)-4).toFixed(1)}`).join(" ");
  const last=vals[vals.length-1];
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.6" vector-effect="non-scaling-stroke"/>
    <circle cx="${n<2?0:W}" cy="${(H-last/max*(H-8)-4).toFixed(1)}" r="2.4" fill="var(--accent)"/>
  </svg><div class="no" style="font-size:11px">max ${max} ms · last ${last} ms · ${n} steps</div>`;
}
function feedHtml(events){
  if(!events.length) return `<div class="no" style="font-size:12px;padding:10px 0">${t("monitor.waiting")}</div>`;
  return events.slice().reverse().slice(0,40).map(({a,st})=>`
    <div class="fev ${a.success?"ok":""}">
      <div class="fh"><span>${esc(a.phase?phaseLabel(a.phase)+" · ":"")}<span class="mono">${esc(a.technique)}</span></span>
        <span>${st.latency_ms||0} ms ${a.success?`· <b style="color:var(--crit)">${t("monitor.exploited")}</b>`:""}</span></div>
      <div class="fp">${esc((st.response||st.prompt||"").slice(0,180))}</div></div>`).join("");
}

/* ---------- settings (LLM config) ---------- */
async function viewSettings(){
  const cfg = await api("/settings/llm");
  const prov = p => `<option value="${p}" ${cfg.provider===p?"selected":""}>${t("settings.provider"+p[0].toUpperCase()+p.slice(1))}</option>`;
  main().innerHTML = `
    <h1>${t("settings.title")}</h1><p class="lead">${t("settings.lead")}</p>
    <div class="grid2">
      <div class="panel"><h3>${t("settings.llmTitle")}</h3>
        <label>${t("settings.provider")}</label>
        <select id="s-prov">${prov("offline")}${prov("openai")}${prov("azure")}${prov("anthropic")}</select>
        <div id="s-azure-note" class="note" style="margin:10px 0 0;display:none">${t("settings.azureHint")}</div>
        <div id="s-online">
          <label>${t("settings.baseUrl")}</label>
          <input id="s-base" value="${esc(cfg.base_url||"")}" placeholder="https://api.openai.com/v1">
          <div class="no" style="font-size:11px;margin-top:3px">${t("settings.baseUrlHint")}</div>
          <label>${t("settings.model")}</label>
          <input id="s-model" value="${esc(cfg.model||"")}" placeholder="gpt-4o-mini">
          <div class="no" style="font-size:11px;margin-top:3px">${t("settings.modelHint")}</div>
          <div id="s-apiver-wrap" style="display:none">
            <label>${t("settings.apiVersion")}</label>
            <input id="s-apiver" value="${esc(cfg.api_version||"")}" placeholder="2024-10-21">
            <div class="no" style="font-size:11px;margin-top:3px">${t("settings.apiVersionHint")}</div>
          </div>
          <label>${t("settings.apiKey")} <span class="no">· ${cfg.has_api_key?t("settings.apiKeySet"):t("settings.apiKeyNone")}</span></label>
          <input id="s-key" type="password" placeholder="${cfg.has_api_key?"••••••••••":"sk-…"}">
          <div class="no" style="font-size:11px;margin-top:3px">${t("settings.apiKeyHint")}</div>
        </div>
        <div class="row" style="margin-top:18px">
          <button id="s-save">${t("settings.save")}</button>
          <button class="ghost" id="s-test">${t("settings.test")}</button></div>
        <div id="s-status" class="note" style="margin-top:14px"></div>
      </div>
      <div class="panel"><h3>${t("settings.roleTitle")}</h3>
        <p class="no" style="font-size:13px;line-height:1.7">${t("settings.roleNote")}</p>
        <div class="note">${t("settings.source")}: <b>${cfg.source==="console"?t("settings.srcConsole"):t("settings.srcEnv")}</b></div>
      </div>
    </div>`;
  const statusEl=$("#s-status");
  const paintStatus = online => { statusEl.innerHTML =
    (online?`<span class="ok">● </span>${t("settings.online")}`:`<span class="no">○ </span>${t("settings.offlineMode")}`); };
  const syncProv=()=>{ const v=$("#s-prov").value, off=v==="offline";
    $("#s-online").style.display=off?"none":"block";
    $("#s-azure-note").style.display=v==="azure"?"block":"none";
    $("#s-apiver-wrap").style.display=v==="azure"?"block":"none";
    paintStatus(!off && (cfg.has_api_key||$("#s-base").value)); };
  $("#s-prov").onchange=syncProv; syncProv();
  $("#s-save").onclick=async()=>{
    const body={provider:$("#s-prov").value, base_url:$("#s-base")?$("#s-base").value:"",
      model:$("#s-model")?$("#s-model").value:"",
      api_version:$("#s-apiver")?$("#s-apiver").value:""};
    const k=$("#s-key")?$("#s-key").value:""; if(k) body.api_key=k;
    try{ const res=await api("/settings/llm",{method:"PUT",body:JSON.stringify(body)});
      S.meta.llm=res; refreshAttackerPill(); paintStatus(res.online);
      toast(t("settings.saved")); viewSettings(); }
    catch(e){ toast(e.message); }
  };
  $("#s-test").onclick=async()=>{
    const btn=$("#s-test"); btn.disabled=true; btn.textContent=t("settings.testing");
    statusEl.textContent="…";
    try{ const res=await api("/settings/llm/test",{method:"POST"});
      if(res.ok&&res.online) statusEl.innerHTML=`<span class="ok">✔ </span>${t("settings.testOk",{ms:res.latency_ms,model:esc(res.model)})}`;
      else if(!res.online) paintStatus(false);
      else statusEl.innerHTML=`<span style="color:var(--crit)">✘ </span>${t("settings.testFail")}: ${esc(res.detail||"")}`;
    }catch(e){ statusEl.textContent=e.message; }
    finally{ btn.disabled=false; btn.textContent=t("settings.test"); }
  };
}

/* ---------- drawers ---------- */
function openAttempt(a){
  if(!a) return;
  const steps = a.steps.map(s=>`
    <div class="step"><div class="sh"><span>${t("attempt.step")} ${s.idx+1} · ${esc(s.role)}</span>
      <span>${s.latency_ms} ms</span></div>
      <div class="io"><div class="lab">▸ ${esc(s.note||t("attempt.attackPrompt"))}</div>
        <pre>${esc(s.prompt)}</pre>
        <div class="lab">${t("attempt.targetResponse")}</div>
        <pre class="resp">${esc(s.response)}</pre></div></div>`).join("");
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${a.success?"✔ ":""}${esc(a.probe||a.technique)}</h2>
    <div class="row" style="gap:8px;margin-bottom:10px">
      <span class="badge sev-${a.severity}">${sevLabel(a.severity)}</span>
      ${a.phase?`<span class="tag">${esc(phaseLabel(a.phase))}</span>`:""}
      ${a.owasp?`<span class="tag">${a.owasp}</span>`:""}${a.atlas?`<span class="tag">${a.atlas}</span>`:""}
      <span class="tag">score ${(a.score*10).toFixed(1)}</span></div>
    <p class="no" style="font-size:13px"><b>${t("attempt.objective")}:</b> ${esc(a.objective)}</p>
    <p class="no" style="font-size:13px"><b>${t("attempt.judge")}:</b> ${esc(a.rationale)}</p>
    ${a.evidence?`<div class="lab">${t("attempt.evidence")}</div><div class="evidence">${esc(a.evidence)}</div>`:""}
    <h3 style="margin-top:18px">${t("attempt.trail",{n:a.steps.length})}</h3>${steps}`);
}
function openFinding(f){
  if(!f) return;
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${esc(f.title)}</h2>
    <div class="row" style="gap:8px;margin-bottom:12px">
      <span class="badge sev-${f.severity}">${sevLabel(f.severity)}</span>
      ${f.owasp?`<span class="tag">${f.owasp}</span>`:""}${f.atlas?`<span class="tag">${f.atlas}</span>`:""}</div>
    <div class="lab">${t("finding.description")}</div><p style="font-size:13px;white-space:pre-wrap">${esc(f.description)}</p>
    <div class="lab">${t("finding.evidence")}</div><div class="evidence">${esc(f.evidence)}</div>
    <div class="lab" style="margin-top:14px">${t("finding.remediation")}</div>
    <p style="font-size:13px;white-space:pre-wrap">${esc(f.remediation)}</p>`);
}
function openDrawer(html){ $("#drawer-body").innerHTML=html; $("#drawer").classList.remove("hidden"); }
function closeDrawer(){ $("#drawer").classList.add("hidden"); }
$("#drawer").addEventListener("click",e=>{ if(e.target.id==="drawer") closeDrawer(); });

const sevScore = s => ({critical:5,high:4,medium:3,low:2,info:1}[s]||0);

/* ---------- start ---------- */
applyI18n();
if (S.token) boot();
