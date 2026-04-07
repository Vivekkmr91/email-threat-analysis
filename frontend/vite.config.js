import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'build',      // match CRA output dir — Nginx COPY stays unchanged
    sourcemap: false,
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
      },
    },
  },
  // Expose REACT_APP_* env vars so existing utils/api.js works without changes
  define: {
    'process.env.REACT_APP_API_URL': JSON.stringify(
      process.env.REACT_APP_API_URL || '/api/v1'
    ),
    'process.env.REACT_APP_API_KEY': JSON.stringify(
      process.env.REACT_APP_API_KEY || 'demo-api-key-change-in-production'
    ),
  },
});
