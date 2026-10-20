import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Wails serves the built assets from dist/ and injects its runtime bindings
// at window.go / window.runtime, so no proxy config is needed here.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
