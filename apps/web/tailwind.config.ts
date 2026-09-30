import type { Config } from "tailwindcss";

// Falcon design system. Neutral graphite surfaces, a cyan→indigo brand accent used sparingly,
// and the severity scale as the only other strong color (so findings always read loud).
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: "#22d3ee",
          strong: "#38bdf8",
          2: "#6366f1",
        },
        ink: {
          DEFAULT: "#e9eef5",
          muted: "#96a3b5",
          faint: "#5d6a7a",
        },
        surface: {
          DEFAULT: "#0a0c10",
          raised: "#10141b",
          sunken: "#070809",
        },
        line: "rgba(255,255,255,0.08)",
        "line-strong": "rgba(255,255,255,0.14)",
        sev: {
          info: "#64748b",
          low: "#0ea5e9",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#f43f5e",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      borderRadius: {
        xl2: "1.125rem",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,0.14), 0 8px 30px -8px rgba(34,211,238,0.30)",
        panel: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 16px 40px -24px rgba(0,0,0,0.8)",
        lift: "0 10px 40px -16px rgba(0,0,0,0.7)",
      },
      backgroundImage: {
        "brand-gradient": "linear-gradient(135deg, #22d3ee 0%, #6366f1 100%)",
        "grid-faint":
          "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-glow": {
          "0%,100%": { opacity: "0.55" },
          "50%": { opacity: "1" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.4s cubic-bezier(0.22,1,0.36,1) both",
        "pulse-glow": "pulse-glow 2.4s ease-in-out infinite",
        shimmer: "shimmer 2.5s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
