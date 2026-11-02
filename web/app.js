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
          <button class="sm ghost" data-report="${x.id}">${t("targets.report")}</button>
          <button class="sm ghost" data-prof="${x.id}">${t("targets.bom")}</button>
          <button class="sm ghost" data-edit="${x.id}">${t("common.edit")}</button>
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
  main().querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>targetForm(ts.find(x=>x.id==b.dataset.edit)));
  main().querySelectorAll("[data-prof]").forEach(b=>b.onclick=()=>openProfile(b.dataset.prof));
  main().querySelectorAll("[data-report]").forEach(b=>b.onclick=()=>openReport(b.dataset.report));
}

/* ---------- per-target pentest report (printable / save-as-PDF) ---------- */
async function openReport(id){
  let p, cs, rs;
  try{ [p,cs,rs]=await Promise.all([api(`/targets/${id}/profile`),api("/campaigns"),api("/runs")]); }
  catch(e){ toast(e.message); return; }
  const campIds=new Set(cs.filter(c=>String(c.target_id)===String(id)).map(c=>c.id));
  const runs=rs.filter(r=>campIds.has(r.campaign_id))
               .sort((a,b)=>(b.started_at||"").localeCompare(a.started_at||""));
  const blob=new Blob([reportHtml(p, runs)],{type:"text/html;charset=utf-8"});
  const url=URL.createObjectURL(blob);
  const w=window.open(url,"_blank");
  if(!w){   // popups blocked → download the report instead
    const a=document.createElement("a");
    a.href=url; a.download=("dagger-report-"+(p.target.name||"target")+".html").replace(/[^\w.\-]+/g,"_");
    document.body.appendChild(a); a.click(); a.remove();
    toast(t("report.downloaded"));
  }
  setTimeout(()=>URL.revokeObjectURL(url), 60000);
}
function reportHtml(p, runs){
  const E=esc, sv=p.findings_by_sev||{}, order=["critical","high","medium","low","info"];
  const SEVC={critical:"#c62828",high:"#e65100",medium:"#f9a825",low:"#1565c0",info:"#616161"};
  const sevChip=s=>`<span style="display:inline-block;padding:1px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff;background:${SEVC[s]||'#616161'}">${E(sevLabel(s))}</span>`;
  const total=Object.values(sv).reduce((a,b)=>a+b,0);
  const sevSummary=order.filter(s=>sv[s]).map(s=>`${sevChip(s)} ${sv[s]}`).join("  ")||t("run.noFindings");
  const vulns=(p.vulnerabilities||[]).map((v,i)=>`
    <div class="v">
      <div class="vh">${i+1}. ${sevChip(v.severity)} <b>${E(v.title)}</b>
        ${v.count>1?`<span class="x">×${v.count}</span>`:""} ${v.owasp?`<span class="tg">${E(v.owasp)}</span>`:""}
        ${v.atlas?`<span class="tg">${E(v.atlas)}</span>`:""}</div>
      ${v.description?`<div class="vd">${E(v.description)}</div>`:""}
      ${v.evidence?`<div class="vl">${t("finding.evidence")}</div><pre>${E(v.evidence)}</pre>`:""}
      ${v.remediation?`<div class="vl">${t("finding.remediation")}</div><div class="vr">${E(v.remediation)}</div>`:""}
    </div>`).join("")||`<p>${t("run.noFindings")}</p>`;
  const row=(k,val)=>val&&val.length?`<tr><th>${E(k)}</th><td>${Array.isArray(val)?val.map(E).join("、"):E(val)}</td></tr>`:"";
  const comps=(p.components||[]).map(c=>`${c.name}${c.version?" "+c.version:""}`);
  const ports=(p.ports||[]).map(x=>`${x.port}/${x.proto} ${x.service}${x.product?" ("+x.product+")":""}`);
  const timeline=runs.length?`<table class="tl"><thead><tr><th>${t("col.run")}</th><th>${t("col.status")}</th>
      <th>${t("col.attempts")}</th><th>${t("col.successes")}</th><th>${t("col.worst")}</th><th>${t("col.started")}</th></tr></thead><tbody>
      ${runs.map(r=>{const s=r.summary||{};return `<tr><td>#${r.id}</td><td>${E(statusLabel(r.status))}</td>
        <td>${s.attempts??"—"}</td><td>${s.successes??"—"}</td><td>${s.worst?E(sevLabel(s.worst)):"—"}</td>
        <td>${E(fmtDate(r.started_at))}</td></tr>`;}).join("")}</tbody></table>`:`<p>—</p>`;
  return `<!doctype html><html lang="${I18N.getLang()}"><head><meta charset="utf-8">
    <title>${t("report.title")} — ${E(p.target.name)}</title><style>
    *{box-sizing:border-box}body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
      color:#1a1a1a;max-width:860px;margin:0 auto;padding:40px 32px;line-height:1.55;font-size:14px}
    h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;border-bottom:2px solid #eee;padding-bottom:6px}
    .meta{color:#666;font-size:13px;margin-bottom:6px}.sum{background:#f6f8fa;border:1px solid #e3e8ee;border-radius:8px;padding:14px 16px;margin:10px 0}
    table{width:100%;border-collapse:collapse;margin:6px 0}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top}
    th{color:#555;width:150px;font-weight:600}.tl th{width:auto}
    .v{border:1px solid #e3e8ee;border-radius:8px;padding:12px 14px;margin:10px 0}.vh{font-size:14px}.vh b{margin:0 4px}
    .vd{color:#444;font-size:13px;margin:7px 0}.vl{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#888;margin:8px 0 3px}
    .vr{font-size:13px}.x,.tg{display:inline-block;background:#eef1f5;border-radius:5px;padding:1px 6px;font-size:11px;color:#555;font-family:monospace}
    pre{background:#f6f8fa;border:1px solid #e3e8ee;border-radius:6px;padding:9px;font-size:12px;white-space:pre-wrap;word-break:break-word;margin:0}
    .noprint{margin:18px 0}button{padding:8px 16px;border:none;border-radius:7px;background:#3b63e0;color:#fff;font-weight:600;cursor:pointer}
    @media print{.noprint{display:none}body{padding:0}}
    </style></head><body>
    <div class="noprint"><button onclick="window.print()">${t("report.print")}</button></div>
    <h1>${t("report.title")}</h1>
    <div class="meta"><b>${E(p.target.name)}</b> · ${E(p.endpoint||"—")}</div>
    <div class="meta">${t("report.generated")}: ${E(new Date().toLocaleString(zh()?"zh-CN":undefined))} ·
      ${p.runs} ${t("bom.engagements")}${p.last_seen?" · "+t("report.lastScan")+": "+E(fmtDate(p.last_seen)):""}</div>
    <h2>${t("report.summary")}</h2>
    <div class="sum">${t("report.summaryText",{n:total,t:E(p.target.name)})}<div style="margin-top:8px">${sevSummary}</div></div>
    <h2>${t("profile.vulns")} (${(p.vulnerabilities||[]).length})</h2>${vulns}
    <h2>${t("profile.assets")}</h2>
    <table>${row(t("bom.webServer"),p.web_servers&&p.web_servers.length?p.web_servers:p.powered_by)}
      ${row(t("bom.os"),p.os)}${row(t("bom.ports"),ports)}${row(t("bom.components"),comps)}
      ${row(t("bom.paths")+" ("+(p.paths||[]).length+")",(p.paths||[]).slice(0,40))}${row(t("bom.endpoints"),p.endpoints)}</table>
    <h2>${t("report.timeline")}</h2>${timeline}
    <div class="meta" style="margin-top:30px;border-top:1px solid #eee;padding-top:12px">Dagger-AI · ${t("login.legal")}</div>
    </body></html>`;
}

async function openProfile(id){
  let p; try{ p=await api(`/targets/${id}/profile`); }catch(e){ toast(e.message); return; }
  const chips=a=>a.length?a.map(s=>`<span class="tag">${esc(s)}</span>`).join(" "):`<span class="no">—</span>`;
  const sec=(title,body)=>`<div class="lab" style="margin-top:14px">${title}</div>${body}`;
  const ports=p.ports.length?`<table><thead><tr><th>${t("bom.port")}</th><th>${t("bom.service")}</th>
      <th>${t("bom.product")}</th></tr></thead><tbody>${p.ports.map(x=>`<tr>
      <td class="mono">${x.port}/${x.proto}</td><td>${esc(x.service)}</td>
      <td class="mono" style="font-size:12px">${esc(x.product||"—")}</td></tr>`).join("")}</tbody></table>`
    :`<span class="no">—</span>`;
  const comps=p.components.length?`<div class="row" style="gap:6px;flex-wrap:wrap">${p.components.map(c=>
      `<span class="tag">${esc(c.name)}${c.version?" "+esc(c.version):""}</span>`).join("")}</div>`:`<span class="no">—</span>`;
  const paths=p.paths.length?`<div class="scrollbox" style="max-height:160px">${p.paths.map(x=>
      `<div class="mono" style="font-size:12px;padding:2px 0">${esc(x)}</div>`).join("")}</div>`:`<span class="no">—</span>`;
  const web=p.web_servers.length?chips(p.web_servers):chips(p.powered_by);
  const sevline=Object.entries(p.findings_by_sev||{}).sort((a,b)=>sevScore(b[0])-sevScore(a[0]))
      .map(([s,n])=>`<span class="badge sev-${s}">${sevLabel(s)} ${n}</span>`).join(" ")||`<span class="no">—</span>`;
  const vulns=(p.vulnerabilities||[]).map(v=>`
      <div class="vuln">
        <div class="vuln-h"><span class="badge sev-${v.severity}">${sevLabel(v.severity)}</span>
          <b>${esc(v.title)}</b>${v.count>1?`<span class="tag">×${v.count}</span>`:""}
          ${v.owasp?`<span class="tag">${v.owasp}</span>`:""}${v.atlas?`<span class="tag">${v.atlas}</span>`:""}</div>
        ${v.remediation?`<div class="vuln-fix"><b>${t("profile.remediation")}:</b> ${esc(v.remediation)}</div>`:""}
      </div>`).join("")||`<div class="ok" style="font-size:13px">${t("run.noFindings")}</div>`;
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${esc(p.target.name)} <span class="tag">${p.target.kind}</span></h2>
    <div class="pb-note">${esc(p.endpoint||"—")} · ${p.runs} ${t("bom.engagements")} ·
      ${sevline}${p.last_seen?" · "+fmtDate(p.last_seen):""}</div>
    <div class="lab" style="margin-top:6px">${t("profile.vulns")} (${(p.vulnerabilities||[]).length})</div>${vulns}
    <div class="lab" style="margin-top:18px;border-top:1px solid var(--line);padding-top:14px">${t("profile.assets")}</div>
    ${sec(t("bom.ports"),ports)}
    ${sec(t("bom.os"),chips(p.os))}
    ${sec(t("bom.webServer"),web)}
    ${sec(t("bom.components")+` (${p.components.length})`,comps)}
    ${sec(t("bom.paths")+` (${p.paths.length})`,paths)}
    ${sec(t("bom.endpoints"),chips(p.endpoints))}`);
}

function targetForm(existing) {
  const ed = existing && existing.id;
  openDrawer(`<h2>${ed?t("targetForm.editTitle"):t("targetForm.title")}</h2>
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
    <div class="row" style="margin-top:18px"><button id="t-save">${ed?t("common.save"):t("common.create")}</button>
      <button class="ghost" onclick="closeDrawer()">${t("common.cancel")}</button></div>`);
  const sync=()=>{ const k=$("#t-kind").value; const chat=k==="http_chat";
    $("#chat-fields").style.display=chat?"block":"none";
    $("#ep-lab").textContent = k==="host" ? t("form.targetHostUrl")
      : k==="web_app" ? t("form.baseUrl") : t("form.endpoint");
    $("#t-ep").placeholder = k==="host" ? t("form.hostPh")
      : k==="web_app" ? "https://app.example.com" : "https://host/v1/chat/completions"; };
  if(ed){   // prefill from the existing target
    $("#t-kind").value = existing.kind; $("#t-name").value = existing.name||"";
    $("#t-ep").value = existing.endpoint||"";
    if($("#t-method")) $("#t-method").value = existing.http_method||"POST";
    if($("#t-body")) $("#t-body").value = existing.body_template||"";
    if($("#t-path")) $("#t-path").value = existing.response_path||"";
  }
  $("#t-kind").onchange=sync; sync();
  $("#t-save").onclick = async () => {
    const chat=$("#t-kind").value==="http_chat";
    const body = {
      name:$("#t-name").value, kind:$("#t-kind").value, endpoint:$("#t-ep").value,
      http_method: chat?$("#t-method").value:"GET",
      body_template: chat?$("#t-body").value:"",
      response_path: chat?$("#t-path").value:"" };
    try{
      await api(ed?`/targets/${existing.id}`:"/targets",
                {method: ed?"PATCH":"POST", body:JSON.stringify(body)});
      closeDrawer(); viewTargets(); toast(ed?t("toast.targetUpdated"):t("toast.targetCreated")); }
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
          <button class="sm ghost" data-edit="${c.id}">${t("common.edit")}</button>
          <button class="sm danger" data-del="${c.id}">${t("common.delete")}</button></td></tr>`).join("")}
      </tbody></table>`:`<div class="empty">${t("campaigns.empty")}</div>`}</div>`;
  $("#new-camp").onclick = () => campaignForm(ts);
  main().querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>campaignForm(ts, cs.find(c=>c.id==b.dataset.edit)));
  main().querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    await api("/campaigns/"+b.dataset.del,{method:"DELETE"}); viewCampaigns(); });
  main().querySelectorAll("[data-run]").forEach(b=>b.onclick=async()=>{
    try{ const r=await api(`/campaigns/${b.dataset.run}/run?lang=${I18N.getLang()}`,{method:"POST"});
      toast(t("toast.runStarted")); openRun(r.run_id); }
    catch(e){ toast("⚠ "+e.message); }});
}

function campaignForm(ts, existing){
  if(!ts.length){ toast(t("toast.addTarget")); return; }
  const ed = existing && existing.id;
  const strat = Object.keys(S.meta.strategies).map(k=>`<option value="${k}">${esc(strategyLabel(k))}</option>`).join("");
  const topts = ts.map(x=>`<option value="${x.id}" data-kind="${x.kind}">${esc(x.name)}${x.authorized?"":t("notAuthorized")}</option>`).join("");
  openDrawer(`<h2>${ed?t("campaignForm.editTitle"):t("campaignForm.title")}</h2>
    <label>${t("campaignForm.name")}</label><input id="c-name" placeholder="${t("campaignForm.namePh")}">
    <label>${t("campaignForm.target")}</label><select id="c-target" ${ed?"disabled":""}>${topts}</select>
    <div id="strat-wrap"><label>${t("campaignForm.strategy")}</label><select id="c-strat">${strat}</select>
    <label>${t("campaignForm.maxTurns")}</label><input id="c-turns" type="number" value="4" min="1" max="8"></div>
    <label>${t("campaignForm.cookies")} <span class="no" style="font-weight:400">${t("campaignForm.cookiesHint")}</span></label>
    <textarea id="c-cookies" rows="3" placeholder="${t("campaignForm.cookiesPh")}" style="font-family:var(--mono);font-size:12px"></textarea>
    <label>${t("campaignForm.probes")} <span id="probe-domain" class="no"></span></label>
    <div id="probe-list" style="display:grid;gap:8px"></div>
    <div class="row" style="margin-top:18px"><button id="c-save">${ed?t("common.save"):t("campaignForm.create")}</button>
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
  if(ed){   // prefill from the existing campaign (target is fixed on edit)
    $("#c-name").value = existing.name||"";
    $("#c-target").value = existing.target_id;
    if(existing.orchestrator) $("#c-strat").value = existing.orchestrator;
    if(existing.max_turns) $("#c-turns").value = existing.max_turns;
    $("#c-cookies").value = existing.session_cookies||"";
  }
  const applyChecks=()=>{ if(!ed) return;
    $("#probe-list").querySelectorAll(".probe input").forEach(cb=>{
      cb.checked=(existing.probes||[]).includes(cb.value); cb.dispatchEvent(new Event("change")); }); };
  const render=()=>{ renderProbes(); applyChecks(); };
  $("#c-target").onchange=render; render();
  $("#c-save").onclick = async () => {
    const chosen=[...$("#probe-list").querySelectorAll("input:checked")].map(i=>i.value);
    if(!chosen.length){ toast(t("toast.pickModule")); return; }
    const kind=($("#c-target").selectedOptions[0]||{}).dataset?.kind;
    const body={ name:$("#c-name").value||"Untitled", probes:chosen,
      orchestrator:$("#c-strat").value, session_cookies:$("#c-cookies").value||"",
      max_turns: kind==="host" ? 12 : +($("#c-turns").value||4) };
    if(!ed) body.target_id=+$("#c-target").value;
    try{
      await api(ed?`/campaigns/${existing.id}`:"/campaigns",
                {method: ed?"PATCH":"POST", body:JSON.stringify(body)});
      closeDrawer(); viewCampaigns(); toast(ed?t("toast.campaignUpdated"):t("toast.campaignCreated")); }
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
    <th>${t("col.successes")}</th><th>${t("col.worst")}</th><th>${t("col.tokens")}</th><th>${t("col.cost")}</th>
    <th>${t("col.started")}</th></tr></thead><tbody>
    ${rs.map(r=>{const s=r.summary||{};const u=s.usage||{};return `<tr data-run="${r.id}" style="cursor:pointer">
      <td><b>#${r.id}</b></td>
      <td><span class="status ${r.status}">${r.status==="running"?'<span class="spin"></span> ':''}${statusLabel(r.status)}</span></td>
      <td>${s.attempts??"—"}</td><td>${s.successes??"—"}</td>
      <td>${s.worst?`<span class="badge sev-${s.worst}">${sevLabel(s.worst)}</span>`:"—"}</td>
      <td class="mono" style="font-size:12px">${u.total_tokens?u.total_tokens.toLocaleString():"—"}</td>
      <td>${u.cost_usd?`<span class="ucost">~$${u.cost_usd.toFixed(4)}</span>`:"—"}</td>
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
    <div class="panel"><h3>${t("run.findingsTitle",{n:dedupFindings(d.findings).length})}</h3>
      <div class="scrollbox">${findingsList(d.findings)}</div></div>
    <div class="panel"><h3>${t("run.phasesTitle")}</h3>${phaseGroups(steps)}</div>
    ${validation?playbookPanel(t("run.validation"),validation):""}
    ${report?playbookPanel(t("run.execSummary"),report):""}`;
  $("#back-runs").onclick=()=>show("runs");
  if(live) $("#stop").onclick=async()=>{ await api(`/runs/${r.id}/stop`,{method:"POST"}); toast(t("common.stop")+"…"); };
  AttackGraph.render($("#graph"), {attempts:steps, targetName:t("monitor.target"),
    phaseLabel:(k)=>phaseLabel(k), techLabel:(x)=>techLabel(x),
    findingLabel:t("result.finding"), cleanLabel:t("result.clean"), emptyLabel:t("run.noAttempts")},
    (grp)=>openAttempt(grp.find(a=>a.success)||grp[0]));
  main().querySelectorAll("[data-att]").forEach(tr=>tr.onclick=()=>{
    openAttempt(d.attempts.find(a=>a.id==tr.dataset.att)); });
  main().querySelectorAll("[data-find]").forEach(c=>c.onclick=()=>{
    openFinding(d.findings.find(x=>x.id==c.dataset.find)); });
}
function playbookPanel(title, a){
  const s=(a.steps&&a.steps[0])||{};
  return `<div class="panel"><h3>${esc(title)} ${aiBadge()}</h3>
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
  const sub=(a.rationale||s0.prompt||"").slice(0,150);
  return `<div class="atk ${a.success?"ok":""}" data-att="${a.id}">
    <span class="ti"><div class="tn">${kindBadge(a)} ${esc(techLabel(a.technique))}
      ${a.success?`<span class="badge sev-${a.severity}">${t("result.finding")}</span>`
                 :`<span class="no" style="font-size:11px">${t("result.clean")}</span>`}
      ${a.owasp?`<span class="tag">${a.owasp}</span>`:""}${a.atlas?`<span class="tag">${a.atlas}</span>`:""}</div>
      ${sub?`<div class="tc">${esc(sub)}</div>`:""}</span>
    <span class="chev">›</span></div>`;
}
/* Group findings by issue class (title prefix before ":"/"—" + owasp + severity)
   so many near-identical findings (e.g. dozens of "Sensitive path exposed: /X")
   collapse to one row with an ×N count, instead of flooding the list. */
const _findClass = f => (f.title||"").split(/[:：—]/)[0].trim();
function dedupFindings(fs){
  const seen={}, out=[];
  (fs||[]).forEach(f=>{
    const k=_findClass(f).toLowerCase()+"|"+(f.owasp||"")+"|"+(f.severity||"");
    if(seen[k]) seen[k].n++; else { seen[k]={f,n:1}; out.push(seen[k]); }
  });
  return out;
}
function findingsList(fs){
  if(!fs.length) return `<div class="empty">${t("run.noFindings")}</div>`;
  const uniq=dedupFindings(fs).sort((a,b)=>sevScore(b.f.severity)-sevScore(a.f.severity));
  return uniq.map(({f,n})=>{
    const title=n>1?_findClass(f):f.title;
    return `<div class="step" data-find="${f.id}" style="cursor:pointer">
      <div class="sh"><span><span class="badge sev-${f.severity}">${sevLabel(f.severity)}</span>
        <b style="margin-left:8px">${esc(title)}</b>${n>1?`<span class="tag" style="margin-left:6px">×${n}</span>`:""}</span>
        <span class="tag">${f.owasp}</span></div></div>`;
  }).join("");
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
  let lastSig = "";
  const paint = async () => {
    let d; try{ d = await api("/runs/"+active.id); }catch{ return; }
    // Only re-render when something actually changed, so the feed/graph don't
    // flicker and re-scroll every second while nothing new is happening.
    const sig = d.run.status + ":" + d.attempts.length + ":" +
                d.attempts.reduce((n,a)=>n+a.steps.length,0) + ":" + I18N.getLang() + ":" + Theme.getTheme();
    if (sig !== lastSig) { lastSig = sig; renderMonitor(d, cmap, tmap); }
    if(!["running","queued"].includes(d.run.status)) clearInterval(S.pollTimer);
  };
  await paint();
  S.pollTimer = setInterval(paint, 1500);
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
  AttackGraph.render($("#mon-graph"), {attempts, targetName:tgt.name||t("monitor.target"),
    endpoint:tgt.endpoint||"", phaseLabel:(k)=>phaseLabel(k), techLabel:(x)=>techLabel(x),
    findingLabel:t("result.finding"), cleanLabel:t("result.clean"), emptyLabel:t("run.noAttempts")},
    (grp)=>openAttempt(grp.find(a=>a.success)||grp[0]));
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
      <div class="fh"><span>${kindBadge(a)} ${phaseChip(a)} <span class="mono">${esc(techLabel(a.technique))}</span></span>
        <span>${st.latency_ms||0} ms ${a.success?`· <b style="color:var(--crit)">${t("monitor.exploited")}</b>`:""}</span></div>
      <div class="fp">${esc((a.rationale||st.response||st.prompt||"").slice(0,180))}</div>
      ${a.success&&isExploit(a)&&impactOf(a)?`<div class="fimp">▶ ${esc(impactOf(a))}</div>`:""}</div>`).join("");
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
    <div class="step"><div class="sh"><span>${stepKindBadge(s.role)} ${t("attempt.step")} ${s.idx+1} · ${esc(s.role)}</span>
      <span>${s.latency_ms} ms</span></div>
      <div class="io"><div class="lab">▸ ${esc(s.note||t("attempt.attackPrompt"))}</div>
        <pre>${esc(s.prompt)}</pre>
        <div class="lab">${t("attempt.targetResponse")}</div>
        <pre class="resp">${esc(s.response)}</pre></div></div>`).join("");
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${a.success?"✔ ":""}${esc(techLabel(a.probe||a.technique))}</h2>
    <div class="row" style="gap:8px;margin-bottom:10px">
      ${kindBadge(a)}
      <span class="badge sev-${a.severity}">${sevLabel(a.severity)}</span>
      ${a.phase?`<span class="tag">${esc(phaseLabel(a.phase))}</span>`:""}
      ${a.owasp?`<span class="tag">${a.owasp}</span>`:""}${a.atlas?`<span class="tag">${a.atlas}</span>`:""}
      <span class="tag">score ${(a.score*10).toFixed(1)}</span></div>
    ${isExploit(a)?exploitCard(a):""}
    <p class="no" style="font-size:13px"><b>${t("attempt.objective")}:</b> ${esc(a.objective)}</p>
    ${a.rationale?`<div class="lab" style="margin-top:12px">${t("attempt.conclusion")}</div>
      <div class="conclusion">${esc(a.rationale)}</div>`:""}
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

/* ---------- AI-decision vs tool-run marker ---------- */
const ICON_AI = `<svg class="kic" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M8 1l1.5 3.8L13.5 6l-3.8 1.5L8 11 6.5 7.5 2.5 6l3.9-1.5z" fill="currentColor"/></svg>`;
const ICON_TOOL = `<svg class="kic" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M2.8 4.2l3 3-3 3M8 12h5.2" stroke="currentColor" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
function kindOf(a){
  if(["plan","report","validate"].includes(a.phase)) return "ai";
  const role=((a.steps&&a.steps[0])||{}).role;
  return (role==="tool"||role==="request") ? "tool" : "ai";
}
const kindBadge = a => (kindOf(a)==="ai")
  ? `<span class="kind ai">${ICON_AI} ${t("kind.ai")}</span>`
  : `<span class="kind tool">${ICON_TOOL} ${t("kind.tool")}</span>`;
const aiBadge = () => `<span class="kind ai">${ICON_AI} ${t("kind.ai")}</span>`;
const stepKindBadge = role => ((role==="tool"||role==="request"))
  ? `<span class="kind tool">${ICON_TOOL} ${t("kind.tool")}</span>`
  : `<span class="kind ai">${ICON_AI} ${t("kind.ai")}</span>`;
/* localize a stored (English) module/probe technique name via meta */
function techLabel(tech){
  if(!S.meta || !zh()) return tech;
  const all=[...(S.meta.pentest_modules||[]),...(S.meta.probes||[])];
  const m=all.find(x=>x.name===tech);
  return (m && m.name_zh) ? m.name_zh : tech;
}
/* phase chip whose dot matches the kill-chain graph node colour */
const _SEVVAR={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)",info:"var(--info)"};
function phaseChip(a){
  if(!a.phase) return "";
  const col=a.success?(_SEVVAR[a.severity]||"var(--info)"):"var(--muted)";
  return `<span class="pchip"><span class="pdot" style="background:${col}"></span>${esc(phaseLabel(a.phase))}</span>`;
}

/* ---------- exploit verification: readable "what / payload / result / effect" ----------
   Turns a raw attempt into a human-readable card answering: what vuln, what
   payload was sent, what came back, and what an attacker could actually do. */
const IMPACT = {   // generic "what it enables" by OWASP class (en/zh)
  A01:{en:"Access or act on other users' data and functions without authorization.",zh:"越权访问或操作其他用户的数据与功能。"},
  A02:{en:"Read or tamper with data that should be protected by cryptography.",zh:"读取或篡改本应被加密保护的数据。"},
  A03:{en:"Inject code or commands the server runs — often full remote code execution.",zh:"注入由服务器执行的代码或命令——通常可达远程代码执行。"},
  A04:{en:"Abuse an insecure design to reach unintended, high-impact states.",zh:"利用不安全设计到达非预期的高危状态。"},
  A05:{en:"Leverage a misconfiguration to widen access or leak internals.",zh:"借助配置错误扩大访问面或泄露内部信息。"},
  A06:{en:"Exploit a known-vulnerable component via its public CVE.",zh:"针对已知漏洞组件,利用其公开 CVE。"},
  A07:{en:"Authenticate as another user or bypass the login controls.",zh:"冒充他人身份或绕过登录控制。"},
  A08:{en:"Tamper with data or updates whose integrity is never verified.",zh:"篡改未经完整性校验的数据或更新。"},
  A09:{en:"Act without being logged, hindering detection and response.",zh:"行动不被记录,妨碍检测与响应。"},
  A10:{en:"Make the server reach internal-only systems on your behalf (SSRF).",zh:"迫使服务器代为访问仅限内部的系统(SSRF)。"},
};
const IMPACT_CVE = {   // concrete effect for specific CVEs
  "CVE-2024-4577":{en:"Run arbitrary system commands on the server (PHP-CGI RCE) — full server takeover.",zh:"在服务器上执行任意系统命令(PHP-CGI RCE)——可完全接管服务器。"},
  "CVE-2021-41773":{en:"Read any file the web server can reach — /etc/passwd, source code, secrets.",zh:"读取 Web 服务可访问的任意文件——/etc/passwd、源码、密钥等。"},
  "CVE-2021-42013":{en:"Read any server-side file, and on some builds execute commands.",zh:"读取服务端任意文件,部分版本下还可执行命令。"},
};
function cveOf(a){
  const m=((a.technique||"")+" "+(a.objective||"")+" "+(a.evidence||"")+" "+(a.rationale||""))
          .match(/CVE-\d{4}-\d{3,7}/i);
  return m?m[0].toUpperCase():"";
}
function impactOf(a){
  const L=zh()?"zh":"en", cve=cveOf(a);
  if(cve && IMPACT_CVE[cve]) return IMPACT_CVE[cve][L];
  const tq=(a.technique||"").toLowerCase();
  if(tq.includes("sql"))                      return zh()?"读取或篡改数据库中的任意数据(数据泄露)。":"Read or modify arbitrary database data (data breach).";
  if(tq.includes("shell")||tq.includes("cmd")||tq.includes("command")) return zh()?"在服务器上执行任意系统命令。":"Execute arbitrary OS commands on the server.";
  if(tq.includes("template"))                 return zh()?"通过模板引擎执行代码(常可达 RCE)。":"Execute code through the template engine (often RCE).";
  if(tq.includes("xss")||tq.includes("marker"))return zh()?"在受害者浏览器中执行脚本,劫持其会话。":"Run script in a victim's browser and hijack their session.";
  if(tq.includes("idor")||tq.includes("enum"))return zh()?"枚举并读取其他用户的私密数据。":"Enumerate and read other users' private data.";
  if(tq.includes("ssrf")||tq.includes("metadata"))return zh()?"迫使服务器访问内部服务或云元数据。":"Force the server to reach internal services or cloud metadata.";
  return (IMPACT[a.owasp]||{})[L] || "";
}
function payloadOf(a){
  const req=(a.steps||[]).find(s=>s.role==="request"||s.role==="attack")||null;
  return req ? (req.prompt||"") : "";
}
function resultOf(a){
  if(a.evidence) return a.evidence;
  const req=(a.steps||[]).find(s=>s.role==="request")||((a.steps||[])[0]||{});
  return (req.response||"").slice(0,220);
}
function isExploit(a){
  if(["plan","report","validate"].includes(a.phase)) return false;
  if((a.technique||"").startsWith("verify:")) return true;
  if(a.phase==="exploit") return true;
  return (a.steps||[]).some(s=>s.role==="request");
}
function exploitCard(a){
  const cve=cveOf(a), imp=impactOf(a), pay=payloadOf(a), res=resultOf(a), ok=a.success;
  return `<div class="vcard ${ok?'ok':'no'}">
    <div class="vrow"><div class="vk">${t("vc.vuln")}</div><div class="vv">
       <b>${esc(techLabel(a.probe||a.technique))}</b>
       <span class="badge sev-${a.severity}">${sevLabel(a.severity)}</span>
       ${cve?`<span class="tag">${cve}</span>`:""}${a.owasp?`<span class="tag">${a.owasp}</span>`:""}</div></div>
    ${pay?`<div class="vrow"><div class="vk">${t("vc.payload")}</div><div class="vv"><pre class="pay">${esc(pay)}</pre></div></div>`:""}
    <div class="vrow"><div class="vk">${t("vc.result")}</div><div class="vv">
       <span class="rslt ${ok?'ok':'no'}">${ok?("✔ "+t("vc.confirmed")):("✘ "+t("vc.notconf"))}</span>
       ${res?`<pre class="pay">${esc(res)}</pre>`:""}</div></div>
    ${imp?`<div class="vrow"><div class="vk">${t("vc.impact")}</div><div class="vv imp">${esc(imp)}</div></div>`:""}
  </div>`;
}

/* ---------- start ---------- */
applyI18n();
if (S.token) boot();
