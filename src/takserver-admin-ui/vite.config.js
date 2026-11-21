import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served by TAK Server at /Marti/ui/ (admin only, via the /Marti/** rule).
// `npm run dev` proxies API calls to a local server: set TAK_URL to override.
export default defineConfig({
  base: '/Marti/ui/',
  plugins: [react()],
  build: {
    outDir: 'build',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    proxy: {
      '/Marti/api': { target: process.env.TAK_URL || 'https://localhost:8443', secure: false, changeOrigin: true },
      '/user-management/api': { target: process.env.TAK_URL || 'https://localhost:8443', secure: false, changeOrigin: true },
    },
  },
});
