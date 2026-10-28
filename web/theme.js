/* Theme + font manager. Applies data-theme / data-font on <html>, persists the
   choice, and exposes the current graph palette (read from CSS variables so the
   SVG attack graph stays in sync with the active theme). */
(function (global) {
  const THEMES = ["midnight", "aurora", "daylight"];
  const FONTS = ["system", "mono", "humanist", "serif", "grotesk", "kai"];

  const get = (k, def, list) => {
    const v = localStorage.getItem(k);
    return list.includes(v) ? v : def;
  };
  let theme = get("dagger_theme", "midnight", THEMES);
  let font = get("dagger_font", "system", FONTS);

  function apply() {
    const r = document.documentElement;
    r.setAttribute("data-theme", theme);
    r.setAttribute("data-font", font);
  }
  function setTheme(t) { if (THEMES.includes(t)) { theme = t; localStorage.setItem("dagger_theme", t); apply(); } }
  function setFont(f) { if (FONTS.includes(f)) { font = f; localStorage.setItem("dagger_font", f); apply(); } }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function palette() {
    return {
      graphBg: cssVar("--graph-bg"), nodeTarget: cssVar("--node-target"),
      nodeProbe: cssVar("--node-probe"), nodeIdle: cssVar("--node-idle"),
      line: cssVar("--line"), edge: cssVar("--edge"), ink: cssVar("--ink"),
      muted: cssVar("--muted"), accent: cssVar("--accent"),
      sev: { critical: cssVar("--crit"), high: cssVar("--high"), medium: cssVar("--med"),
             low: cssVar("--low"), info: cssVar("--info") },
    };
  }

  apply();
  global.Theme = { THEMES, FONTS, setTheme, setFont, getTheme: () => theme, getFont: () => font, palette };
})(window);
