import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// See docs/architecture.md §31.1 for the frontend stack rationale, and
// §30 for why the IPC surface is deliberately narrow — nothing here should
// grow a generic fetch/proxy layer to the Rust core.
export default defineConfig({
  plugins: [svelte()],
  // Build order phase 10: matches `src-tauri/tauri.conf.json`'s
  // `build.devUrl` — Tauri's dev shell loads this exact port, so it must
  // be fixed and must fail loudly (`strictPort`) rather than silently
  // drifting to the next free port if something else is already using
  // 1420.
  server: {
    port: 1420,
    strictPort: true,
  },
  clearScreen: false,
});
