import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base './' emits relative asset URLs so the backend can serve the bundle
// under any BASE_PATH at runtime (it rewrites <base href> in index.html).
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    proxy: {
      // Local dev against a locally running head-control backend.
      "/api": "http://localhost:8000",
    },
  },
});
