/* Attack kill-chain (self-contained, offline, theme-aware).

   A VERTICAL timeline: Target at the top, then each phase as a full-width row —
   a dot on a connecting rail, the phase name + finding count, and the ACTION
   cards for that phase wrapping across the available width (each coloured by its
   STATUS). Flows top→bottom so nothing runs off the right edge; it uses the full
   width and grows downward. Click a card to open its step trail. */
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

    const row = (dotColor, headHtml, actsHtml) => `
      <div class="vrow">
        <div class="vrail"><span class="vdot" style="background:${dotColor}"></span></div>
        <div class="vbody">${headHtml}${actsHtml || ""}</div>
      </div>`;

    let html = `<div class="vchain">`;
    // target
    html += row("var(--accent)",
      `<div class="vhead vtarget">◎ <b>${esc(data.targetName || "Target")}</b>
        ${data.endpoint ? `<span class="vep mono">${esc(data.endpoint)}</span>` : ""}</div>`, "");

    keys.forEach(k => {
      const items = groups[k];
      const hits = items.filter(a => a.success).length;
      const worst = items.reduce((w, a) => (a.success && _sev(a.severity) > _sev(w)) ? a.severity : w, "info");
      const dot = hits ? (SEV[worst] || SEV.info) : "var(--line)";
      const head = `<div class="vhead"><span>${esc(pl(k))}</span>
        <span class="vcount">${hits ? `<b style="color:var(--crit)">${hits}⚑</b>`
                                    : `<span class="no">${items.length}</span>`}</span></div>`;
      const acts = `<div class="vacts">` + items.map(a => {
        const col = a.success ? (SEV[a.severity] || SEV.info) : "var(--line)";
        const cdot = a.success ? (SEV[a.severity] || SEV.info) : "var(--muted)";
        const st = a.success ? (data.findingLabel || "finding") : (data.cleanLabel || "clean");
        return `<div class="chain-act${a.success ? " ok" : ""}" data-att="${a.id}"
            style="border-color:${col}" title="${esc(tl(a.technique))}">
            <span class="cdot" style="background:${cdot}"></span>
            <span class="cact-body"><span class="cact-name">${esc(tl(a.technique))}</span>
              <span class="cact-st" style="color:${a.success ? col : "var(--muted)"}">${esc(st)}</span></span>
          </div>`;
      }).join("") + `</div>`;
      html += row(dot, head, acts);
    });
    html += `</div>`;
    container.innerHTML = html;
    container.querySelectorAll(".chain-act[data-att]").forEach(el => el.onclick = () => {
      const a = attempts.find(x => String(x.id) === el.dataset.att);
      if (a && onNode) onNode([a], a.phase);
    });
  }
  const _sev = s => ({critical:5, high:4, medium:3, low:2, info:1}[s] || 0);

  global.AttackGraph = { render };
})(window);
