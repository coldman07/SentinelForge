import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const dashboardDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  plugins: [react()],
  base: '/',
  server: {
    proxy: {
      '/v1': 'http://127.0.0.1:8080',
    },
  },
  build: {
    outDir: resolve(dashboardDir, '../gateway/internal/dashboard/dist'),
    emptyOutDir: true,
  },
});
