import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

// The Tauri CLI expects a fixed port and does not tolerate the dev server moving to
// another one, so this is deliberately not configurable.
const DEV_PORT = 1420;

export default defineConfig({
  plugins: [react(), tailwindcss()],

  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      '@sentinel/types': fileURLToPath(new URL('../../../packages/types/src/index.ts', import.meta.url)),
    },
  },

  // Tauri serves the built assets from a custom protocol, so asset URLs must be relative.
  base: './',

  server: {
    port: DEV_PORT,
    strictPort: true,
    watch: {
      // Watching the Rust sources through Vite triggers a rebuild loop; the Rust build is
      // driven by `cargo` and `tauri dev`, not by the frontend bundler.
      ignored: ['**/src-tauri/**', '**/target/**'],
    },
  },

  build: {
    // Matches the Tauri webview baseline: modern Chromium and WebKit, nothing older.
    target: ['es2022', 'chrome110', 'safari16'],
    sourcemap: false,
    // A security tool ships a readable bundle, not an obfuscated one; side effects are
    // preserved because Tauri and the vendor chunk rely on them.
    chunkSizeWarningLimit: 900,
  },
});
