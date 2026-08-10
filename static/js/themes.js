/**
 * ServerShield — Theme Manager
 * Gestión de temas visuales con CSS variables
 */

const THEMES = {
  matrix: {
    name: "Matrix",
    emoji: "🟢",
    description: "Verde fosforescente clásico",
    vars: {
      "--green":        "#00ff41",
      "--green-dim":    "#00cc33",
      "--green-dark":   "#003d10",
      "--green-glow":   "rgba(0,255,65,0.15)",
      "--amber":        "#ffb300",
      "--red":          "#ff3333",
      "--bg":           "#030d05",
      "--panel":        "#050f07",
      "--panel2":       "#060e08",
      "--border":       "rgba(0,255,65,0.2)",
      "--border-bright":"rgba(0,255,65,0.4)",
      "--text-main":    "#00ff41",
      "--text-dim":     "rgba(0,255,65,0.5)",
      "--text-faint":   "rgba(0,255,65,0.25)",
      "--header-bg":    "#052e16",
      "--scanline":     "rgba(0,0,0,0.06)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  },

  cyber_blue: {
    name: "Cyber Blue",
    emoji: "🔵",
    description: "Azul eléctrico / negro profundo",
    vars: {
      "--green":        "#00d4ff",
      "--green-dim":    "#0099cc",
      "--green-dark":   "#001a33",
      "--green-glow":   "rgba(0,212,255,0.15)",
      "--amber":        "#ff9900",
      "--red":          "#ff4466",
      "--bg":           "#020810",
      "--panel":        "#040c18",
      "--panel2":       "#050e1c",
      "--border":       "rgba(0,212,255,0.2)",
      "--border-bright":"rgba(0,212,255,0.5)",
      "--text-main":    "#00d4ff",
      "--text-dim":     "rgba(0,212,255,0.5)",
      "--text-faint":   "rgba(0,212,255,0.25)",
      "--header-bg":    "#001833",
      "--scanline":     "rgba(0,0,0,0.07)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  },

  purple_haze: {
    name: "Purple Haze",
    emoji: "🟣",
    description: "Violeta neón / negro",
    vars: {
      "--green":        "#bf5fff",
      "--green-dim":    "#9933cc",
      "--green-dark":   "#1a0033",
      "--green-glow":   "rgba(191,95,255,0.15)",
      "--amber":        "#ffaa00",
      "--red":          "#ff4488",
      "--bg":           "#08020f",
      "--panel":        "#0d0518",
      "--panel2":       "#10061c",
      "--border":       "rgba(191,95,255,0.2)",
      "--border-bright":"rgba(191,95,255,0.5)",
      "--text-main":    "#bf5fff",
      "--text-dim":     "rgba(191,95,255,0.55)",
      "--text-faint":   "rgba(191,95,255,0.25)",
      "--header-bg":    "#1a0033",
      "--scanline":     "rgba(0,0,0,0.07)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  },

  red_alert: {
    name: "Red Alert",
    emoji: "🔴",
    description: "Rojo crítico / negro",
    vars: {
      "--green":        "#ff3333",
      "--green-dim":    "#cc1111",
      "--green-dark":   "#330000",
      "--green-glow":   "rgba(255,51,51,0.15)",
      "--amber":        "#ff8800",
      "--red":          "#ff6666",
      "--bg":           "#0d0202",
      "--panel":        "#140303",
      "--panel2":       "#180404",
      "--border":       "rgba(255,51,51,0.2)",
      "--border-bright":"rgba(255,51,51,0.5)",
      "--text-main":    "#ff3333",
      "--text-dim":     "rgba(255,51,51,0.55)",
      "--text-faint":   "rgba(255,51,51,0.25)",
      "--header-bg":    "#330000",
      "--scanline":     "rgba(0,0,0,0.07)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  },

  ghost: {
    name: "Ghost",
    emoji: "⚪",
    description: "Minimalista / profesional",
    vars: {
      "--green":        "#e0e0e0",
      "--green-dim":    "#aaaaaa",
      "--green-dark":   "#1a1a1a",
      "--green-glow":   "rgba(224,224,224,0.1)",
      "--amber":        "#f0a500",
      "--red":          "#e05555",
      "--bg":           "#0a0a0a",
      "--panel":        "#111111",
      "--panel2":       "#141414",
      "--border":       "rgba(200,200,200,0.15)",
      "--border-bright":"rgba(200,200,200,0.35)",
      "--text-main":    "#d0d0d0",
      "--text-dim":     "rgba(200,200,200,0.5)",
      "--text-faint":   "rgba(200,200,200,0.2)",
      "--header-bg":    "#111111",
      "--scanline":     "rgba(0,0,0,0.04)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  },

  amber_terminal: {
    name: "Amber Terminal",
    emoji: "🟡",
    description: "Ámbar retro / negro",
    vars: {
      "--green":        "#ffb300",
      "--green-dim":    "#cc8800",
      "--green-dark":   "#2a1a00",
      "--green-glow":   "rgba(255,179,0,0.15)",
      "--amber":        "#ff6600",
      "--red":          "#ff3333",
      "--bg":           "#0d0800",
      "--panel":        "#150e00",
      "--panel2":       "#191100",
      "--border":       "rgba(255,179,0,0.2)",
      "--border-bright":"rgba(255,179,0,0.45)",
      "--text-main":    "#ffb300",
      "--text-dim":     "rgba(255,179,0,0.55)",
      "--text-faint":   "rgba(255,179,0,0.25)",
      "--header-bg":    "#2a1500",
      "--scanline":     "rgba(0,0,0,0.06)",
      "--font-mono":    "'Share Tech Mono', monospace",
      "--font-display": "'Orbitron', monospace",
    }
  }
};

const DEFAULT_THEME = 'matrix';

function applyTheme(themeId) {
  const theme = THEMES[themeId] || THEMES[DEFAULT_THEME];
  const root = document.documentElement;
  Object.entries(theme.vars).forEach(([key, value]) => {
    root.style.setProperty(key, value);
  });
  localStorage.setItem('ss_theme', themeId);
  document.body.setAttribute('data-theme', themeId);
}

function getCurrentTheme() {
  return localStorage.getItem('ss_theme') || DEFAULT_THEME;
}

// Aplicar tema al cargar la página (antes del render para evitar flash)
(function() {
  const saved = localStorage.getItem('ss_theme') || DEFAULT_THEME;
  if (saved && THEMES[saved]) {
    const root = document.documentElement;
    Object.entries(THEMES[saved].vars).forEach(([key, value]) => {
      root.style.setProperty(key, value);
    });
    document.documentElement.setAttribute('data-theme', saved);
  }
})();
