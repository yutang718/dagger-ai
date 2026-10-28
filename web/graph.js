/* Self-contained SVG attack-chain graph (no external library, works offline).
   Columns: Target -> Probes/Modules -> Attempts. Successful attempts glow in
   their severity colour; click an attempt to open its step-by-step trail.
   Colours are pulled from the active theme (Theme.palette()) so the graph
   follows Midnight / Aurora / Daylight. */
(function (global) {
  const SVGNS = "http://www.w3.org/2000/svg";
  const pal = () => (global.Theme ? global.Theme.palette() : {});
  const SEVof = p => (p.sev || {critical:"#e5484d",high:"#f76808",medium:"#f5a623",
                                 low:"#3b82f6",info:"#8b8d98"});

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
    const g = el("g", {class: "gnode"}, svg);
    el("rect", {x:x-w/2, y:y-h/2, width:w, height:h, rx:10, fill, stroke, "stroke-width":1.5}, g);
    const t = el("text", {x, y:y-2, "text-anchor":"middle", "font-weight":"700"}, g);
    t.textContent = label;
    if (sub) {
      const s = el("text", {x, y:y+13, "text-anchor":"middle", class:"sub", "font-size":"10"}, g);
      s.textContent = sub;
    }
    if (onclick) g.addEventListener("click", onclick);
    return g;
  }

  function render(container, data, onAttempt) {
    container.innerHTML = "";
    const P = pal(), SEV = SEVof(P);
    const attempts = data.attempts || [];
    const W = container.clientWidth || 900;
    const probes = {};
    attempts.forEach(a => { (probes[a.probe] ||= []).push(a); });
    const probeIds = Object.keys(probes);
    const rowH = 64;
    const H = Math.max(300, attempts.length * rowH + 60);
    const svg = el("svg", {width:"100%", height:H, viewBox:`0 0 ${W} ${H}`}, container);
    const xT = 95, xP = W * 0.42, xA = W - 150;
    const yMid = H / 2;

    node(svg, xT, yMid, 150, 46, P.nodeTarget||"#1a2740", P.accent||"#5b8cff",
      "🎯 " + (data.targetLabel || "Target"), data.targetName || "AI system", null);

    let i = 0;
    const attemptY = {};
    attempts.forEach(a => { attemptY[a.id] = 40 + (i + 0.5) * ((H - 60) / attempts.length); i++; });

    probeIds.forEach(pid => {
      const ys = probes[pid].map(a => attemptY[a.id]);
      const py = ys.reduce((s,v)=>s+v,0)/ys.length;
      el("path", {class:"gedge", d:curve(xT+75, yMid, xP-70, py)}, svg);
      node(svg, xP, py, 150, 40, P.nodeProbe||"#131824", P.line||"#2a3550",
        probes[pid][0].owasp || probes[pid][0].phase || "module", pid.replace(/_/g," ").slice(0,18), null);
      probes[pid].forEach(a => {
        const ay = attemptY[a.id];
        const ok = a.success;
        el("path", {class:"gedge"+(ok?" ok":""), d:curve(xP+70, py, xA-85, ay)}, svg);
        const col = ok ? SEV[a.severity]||SEV.info : (P.nodeIdle||"#1a2130");
        const stroke = ok ? SEV[a.severity]||SEV.info : (P.line||"#2a3550");
        const g = node(svg, xA, ay, 170, 44, ok? shade(col):(P.nodeProbe||"#131824"), stroke,
          (ok?"✔ ":"· ")+(a.technique||"").slice(0,16),
          ok?("CVSS "+(a.score*10).toFixed(1)):(data.resistedLabel||"resisted"),
          () => onAttempt && onAttempt(a));
        if (ok) el("circle", {cx:xA+78, cy:ay-14, r:5, fill:col}, g);
      });
    });
  }

  function shade(c){ return (typeof c === "string" && c[0] === "#" && c.length <= 7)
    ? c + "22" : `color-mix(in srgb, ${c} 16%, transparent)`; }

  global.AttackGraph = { render };
})(window);
