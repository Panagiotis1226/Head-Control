/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Neutral surface scale used across the app; dark mode flips via class.
        surface: {
          DEFAULT: "#ffffff",
          muted: "#f8fafc",
          dark: "#0b1120",
          "dark-muted": "#111a2e",
        },
      },
    },
  },
  plugins: [],
};
