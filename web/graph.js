/* Attack kill-chain pipeline (self-contained SVG, offline, theme-aware).

   Renders the engagement as a clean horizontal timeline:
     Target ─● recon ─● fingerprint ─● discovery ─● vuln ─● exploit ─● validate
   Each phase is a ringed node showing its finding count, coloured by worst
   severity; the connecting track lights up through phases that produced
   findings. Compact and complete regardless of how many attempts a run has.
   Click a node to drill into that phase. Colours follow the active theme. */
(function (global) {
  const SVGNS = "http://www.w3.org/2000/svg";
  const pal = () => (global.Theme ? global.Theme.palette() : {});
  const SEVof = p => (p.sev || {critical:"#e5484d",high:"#f76808",medium:"#f5a623",
                                 low:"#3b82f6",info:"#8b8d98"});
  const sevScore = s => ({critical:5,high:4,medium:3,low:2,info:1}[s]||0);
  const ORDER = ["recon","fingerprint","discovery","vuln","exploit","validate"];

  function el(tag, attrs, parent) {
    const n = document.createElementNS(SVGNS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function text(parent, x, y, s, attrs) {
    const t = el("text", Object.assign({x, y, "text-anchor":"middle"}, attrs||{}), parent);
    t.textContent = s; return t;
  }
  const clip = (s, n) => (s && s.length > n) ? s.slice(0, n-1) + "…" : (s || "");

  function render(container, data, onNode) {
    container.innerHTML = "";
    const P = pal(), SEV = SEVof(P);
    const attempts = data.attempts || [];
    const groups = {};
    attempts.forEach(a => { const k = a.phase || a.probe || "steps"; (groups[k]=groups[k]||[]).push(a); });
    const keys = Object.keys(groups).sort((a,b)=>{
      const ia=ORDER.indexOf(a), ib=ORDER.indexOf(b);
      return (ia<0?99:ia)-(ib<0?99:ib) || a.localeCompare(b);
    });
    const total = keys.length + 1;                       // + target node
    const W = Math.max(container.clientWidth || 900, total*124, 540);
    const H = 150;
    const svg = el("svg", {width:"100%", height:H, viewBox:`0 0 ${W} ${H}`}, container);

    const ty = 56, r = 24;
    const x0 = 58, x1 = W - 58;
    const step = total > 1 ? (x1-x0)/(total-1) : 0;
    const xs = i => total > 1 ? x0 + i*step : (x0+x1)/2;

    // base track
    el("line", {x1:xs(0), y1:ty, x2:xs(total-1), y2:ty, stroke:P.line||"#2a3550",
                "stroke-width":2.5, "stroke-linecap":"round"}, svg);

    // precompute per-phase stats
    const stats = keys.map(k => {
      const items = groups[k];
      const hits = items.filter(a=>a.success).length;
      const worst = items.reduce((w,a)=>(a.success && sevScore(a.severity)>sevScore(w))?a.severity:w, "info");
      return {k, items, hits, worst, col: hits ? (SEV[worst]||SEV.info) : (P.muted||"#8b97ab")};
    });
    // lit track segments (target→phase1, phase→phase) where downstream has findings
    stats.forEach((st, i) => {
      if (st.hits) el("line", {x1:xs(i), y1:ty, x2:xs(i+1), y2:ty, stroke:st.col,
                               "stroke-width":3.5, "stroke-linecap":"round"}, svg);
    });

    // target node
    const tg = el("g", {class:"gnode"}, svg);
    el("circle", {cx:xs(0), cy:ty, r:r+2, fill:P.nodeTarget||"#1a2740",
                  stroke:P.accent||"#5b8cff", "stroke-width":2.5}, tg);
    el("circle", {cx:xs(0), cy:ty, r:9, fill:"none", stroke:P.accent||"#5b8cff", "stroke-width":2}, tg);
    el("circle", {cx:xs(0), cy:ty, r:2.5, fill:P.accent||"#5b8cff"}, tg);
    text(tg, xs(0), ty+r+22, clip(data.targetName || data.targetLabel || "Target", 16),
         {class:"glabel", "font-weight":"700"});
    if (data.endpoint) text(tg, xs(0), ty+r+37, clip(data.endpoint, 22), {class:"gsub","font-size":"10"});

    // phase nodes
    stats.forEach((st, i) => {
      const x = xs(i+1);
      const g = el("g", {class:"gnode"}, svg);
      if (onNode) g.addEventListener("click", () => onNode(st.items, st.k));
      el("circle", {cx:x, cy:ty, r:r+2, fill:P.nodeProbe||"#131824", stroke:st.col,
                    "stroke-width": st.hits?3:2}, g);
      if (st.hits) {
        text(g, x, ty+5, String(st.hits), {"font-weight":"800","font-size":"18",fill:st.col});
      } else {
        el("circle", {cx:x, cy:ty, r:4, fill:P.muted||"#8b97ab", opacity:"0.6"}, g);
      }
      const label = data.phaseLabel ? data.phaseLabel(st.k) : st.k;
      text(g, x, ty+r+22, clip(label, 14), {class:"glabel","font-weight":"700"});
      text(g, x, ty+r+37, `${st.items.length} ${data.stepsLabel||"steps"}`, {class:"gsub","font-size":"10"});
    });
  }

  global.AttackGraph = { render };
})(window);
