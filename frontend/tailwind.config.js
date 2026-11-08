/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#06060e",
          900: "#0a0a16",
          850: "#0d0d1c",
          800: "#101021",
          700: "#161629",
          600: "#1e1e36",
          500: "#2a2a4a",
        },
        line: {
          DEFAULT: "rgba(148, 150, 200, 0.14)",
          strong: "rgba(148, 150, 200, 0.26)",
        },
        violet: {
          300: "#b9a5ff",
          400: "#9f7bff",
          500: "#7c5dfa",
          600: "#6947e8",
        },
        mint: {
          300: "#5eead4",
          400: "#2dd4bf",
        },
        blush: {
          400: "#f472b6",
        },
        tx: {
          1: "#f2f2f8",
          2: "#a5a6c0",
          3: "#6e7090",
        },
      },
      fontFamily: {
        sans: ["'Inter Variable'", "Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 30px -12px rgba(0,0,0,0.6)",
        glow: "0 0 60px -12px rgba(124, 93, 250, 0.45)",
      },
      borderRadius: {
        xl2: "1rem",
      },
    },
  },
  plugins: [],
};
