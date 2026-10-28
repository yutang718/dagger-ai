/* Attack-chain graph (self-contained SVG, offline, theme-aware).

   Renders the engagement as a kill-chain: Target → phase nodes
   (recon → fingerprint → discovery → vuln → exploit → …), each node summarising
   its steps + findings and coloured by worst severity. This stays complete and
   readable no matter how many attempts a run has (unlike one node per attempt).
   Clicking a node drills into that group. Colours follow the active theme. */
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
  function curve(x1, y1, x2, y2) {
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  }
  function node(svg, x, y, w, h, fill, stroke, label, sub, onclick) {
    const g = el("g", {class:"gnode"}, svg);
    el("rect", {x:x-w/2, y:y-h/2, width:w, height:h, rx:11, fill, stroke, "stroke-width":1.6}, g);
    const t = el("text", {x, y:y-3, "text-anchor":"middle", "font-weight":"700"}, g);
    t.textContent = label.length > 16 ? label.slice(0,15)+"…" : label;
    if (sub) {
      const s = el("text", {x, y:y+13, "text-anchor":"middle", class:"sub", "font-size":"10"}, g);
      s.textContent = sub;
    }
    if (onclick) g.addEventListener("click", onclick);
    return g;
  }
  function shade(c){ return (typeof c === "string" && c[0] === "#" && c.length <= 7)
    ? c + "22" : `color-mix(in srgb, ${c} 16%, transparent)`; }

  function render(container, data, onNode) {
    container.innerHTML = "";
    const P = pal(), SEV = SEVof(P);
    const attempts = data.attempts || [];
    const W = Math.max(container.clientWidth || 900, 560);
    // group by phase, else by probe, else "steps"
    const groups = {};
    attempts.forEach(a => { const k = a.phase || a.probe || "steps"; (groups[k]=groups[k]||[]).push(a); });
    let keys = Object.keys(groups).sort((a,b)=>{
      const ia=ORDER.indexOf(a), ib=ORDER.indexOf(b);
      return (ia<0?99:ia)-(ib<0?99:ib) || a.localeCompare(b);
    });
    const perRow = Math.min(keys.length, 4) || 1;
    const rows = Math.ceil(keys.length / perRow) || 1;
    const H = Math.max(170, 70 + rows * 84);
    const svg = el("svg", {width:"100%", height:H, viewBox:`0 0 ${W} ${H}`}, container);

    const tx = 78, ty = H/2;
    node(svg, tx, ty, 132, 48, P.nodeTarget||"#1a2740", P.accent||"#5b8cff",
      (data.targetName || data.targetLabel || "Target"), (data.endpoint||""), null);

    if (!keys.length) return;
    const x0 = 210, x1 = W - 96;
    const colW = perRow>1 ? (x1-x0)/(perRow-1) : 0;
    const nw = Math.max(96, Math.min(156, (perRow>1?colW:(x1-x0)) - 22));
    const rowGap = (H-40)/(rows+1);

    keys.forEach((k, i) => {
      const items = groups[k];
      const row = Math.floor(i/perRow), col = i%perRow;
      const inRow = Math.min(perRow, keys.length - row*perRow);
      const rx0 = x0, rxStep = inRow>1 ? (x1-x0)/(inRow-1) : 0;
      const x = inRow>1 ? rx0 + col*rxStep : (x0+x1)/2;
      const y = rowGap*(row+1) + 8;
      const hits = items.filter(a=>a.success).length;
      const worst = items.reduce((w,a)=>(a.success && sevScore(a.severity)>sevScore(w))?a.severity:w, "info");
      const col2 = hits ? (SEV[worst]||SEV.info) : (P.nodeIdle||"#1a2130");
      const stroke = hits ? (SEV[worst]||SEV.info) : (P.line||"#2a3550");
      // edge: from target (first in row 0) or straight in
      const sx = (col===0) ? tx+66 : x - rxStep + nw/2;
      const sy = (col===0) ? ty : y;
      el("path", {class:"gedge"+(hits?" ok":""), d:curve(sx, sy, x-nw/2, y)}, svg);
      const label = data.phaseLabel ? data.phaseLabel(k) : k;
      const sub = `${items.length} ${data.stepsLabel||"steps"}${hits?" · "+hits+"⚑":""}`;
      const g = node(svg, x, y, nw, 54, hits?shade(col2):(P.nodeProbe||"#131824"), stroke,
        label, sub, ()=>onNode && onNode(items, k));
      if (hits) el("circle", {cx:x+nw/2-11, cy:y-19, r:7, fill:col2}, g);
    });
  }

  global.AttackGraph = { render };
})(window);
