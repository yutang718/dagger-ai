/* Attack kill-chain flow (self-contained, offline, theme-aware).

   Renders the engagement as a left-to-right flow of PHASE columns, each holding
   the ACTION cards run in that phase, each card coloured by its STATUS
   (a finding in its severity colour, or clean/neutral). So at a glance you see:
   which phase → what actions it ran → the outcome of each. Click a card to open
   its step-by-step trail. Built as HTML (not SVG) so it reflows, themes via CSS
   variables, and stays legible with any number of actions. */
(function (global) {
  const PHASE_SEQ = ["plan", "recon", "fingerprint", "discovery", "vuln", "exploit", "validate", "report"];
  const SEV = {critical:"var(--crit)", high:"var(--high)", medium:"var(--med)",
               low:"var(--low)", info:"var(--info)"};
  const esc = s => (s ?? "").toString().replace(/[&<>"]/g, c =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

  function render(container, data, onNode) {
    const attempts = data.attempts || [];
    const tl = data.techLabel || (x => x);
    const pl = data.phaseLabel || (x => x);

    const groups = {};
    attempts.forEach(a => { const k = a.phase || a.probe || "steps"; (groups[k] = groups[k] || []).push(a); });
    const keys = Object.keys(groups).sort((a, b) => {
      const ia = PHASE_SEQ.indexOf(a), ib = PHASE_SEQ.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
    });

    if (!keys.length) { container.innerHTML = `<div class="chain-empty">${esc(data.emptyLabel || "—")}</div>`; return; }

    let html = `<div class="chain">`;
    // target node
    html += `<div class="chain-col chain-target"><div class="ct-card">
        <div class="ct-ic">◎</div><div class="ct-name">${esc(data.targetName || "Target")}</div>
        ${data.endpoint ? `<div class="ct-ep mono">${esc(data.endpoint)}</div>` : ""}</div></div>`;

    keys.forEach(k => {
      const items = groups[k];
      const hits = items.filter(a => a.success).length;
      html += `<div class="chain-sep">›</div>`;
      html += `<div class="chain-col">
          <div class="chain-head"><span>${esc(pl(k))}</span>
            <span class="ch-count">${hits
              ? `<b style="color:var(--crit)">${hits}⚑</b>`
              : `<span class="no">${items.length}</span>`}</span></div>
          <div class="chain-acts">`;
      items.forEach(a => {
        const col = a.success ? (SEV[a.severity] || SEV.info) : "var(--line)";
        const dot = a.success ? (SEV[a.severity] || SEV.info) : "var(--muted)";
        const st = a.success ? (data.findingLabel || "finding") : (data.cleanLabel || "clean");
        html += `<div class="chain-act${a.success ? " ok" : ""}" data-att="${a.id}"
            style="border-color:${col}" title="${esc(tl(a.technique))}">
            <span class="cdot" style="background:${dot}"></span>
            <span class="cact-body"><span class="cact-name">${esc(tl(a.technique))}</span>
              <span class="cact-st" style="color:${a.success ? col : "var(--muted)"}">${esc(st)}</span></span>
          </div>`;
      });
      html += `</div></div>`;
    });
    html += `</div>`;
    container.innerHTML = html;
    container.querySelectorAll(".chain-act[data-att]").forEach(el => el.onclick = () => {
      const a = attempts.find(x => String(x.id) === el.dataset.att);
      if (a && onNode) onNode([a], a.phase);
    });
  }

  global.AttackGraph = { render };
})(window);
