import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build is embedded into smcpd (console/embed.go) and served under a
// CSP without 'unsafe-inline' and without data: sources, so nothing may be
// inlined: no data-URI assets and no inline module-preload polyfill.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: "es2022",
    cssCodeSplit: false,
  },
  server: {
    // `npm run dev` proxies the control API to a running smcpd.
    proxy: {
      "/api": { target: "https://127.0.0.1:8444", secure: false, changeOrigin: true },
      "/admin": { target: "https://127.0.0.1:8444", secure: false, changeOrigin: true },
    },
  },
});
