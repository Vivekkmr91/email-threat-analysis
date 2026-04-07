import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Vite serves from /src/index.jsx - we keep src/index.js as the entry
  build: {
    outDir: 'build',          // keep same output dir as CRA for Nginx COPY
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
  // Expose env vars prefixed with REACT_APP_ so existing api.js still works
  define: {
    'process.env.REACT_APP_API_URL': JSON.stringify(
      process.env.REACT_APP_API_URL || '/api/v1'
    ),
    'process.env.REACT_APP_API_KEY': JSON.stringify(
      process.env.REACT_APP_API_KEY || 'demo-api-key-change-in-production'
    ),
  },
});
