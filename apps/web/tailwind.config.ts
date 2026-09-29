import type { Config } from "tailwindcss";

// Only strong color is the severity scale; everything else stays neutral (Cobalt-style).
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        sev: {
          info: "#64748b",
          low: "#0ea5e9",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#dc2626",
        },
      },
    },
  },
  plugins: [],
};
export default config;
