# ── Build stage ──────────────────────────────────────────────────────────────
# Vite replaces react-scripts (CRA) — no CI env issues, no ESM/CJS conflicts,
# builds ~10x faster and uses far less memory.
FROM node:18-alpine AS builder

WORKDIR /app

# Build-time arguments — override in docker-compose with `args:`
# REACT_APP_API_KEY must match ALLOWED_API_KEYS in the backend .env
ARG REACT_APP_API_KEY=demo-api-key-change-in-production
ARG REACT_APP_API_URL=/api/v1

# Copy package manifests
COPY package.json package-lock.json* ./

# Clean install — Vite + @vitejs/plugin-react have no peer-dep conflicts
RUN npm install --legacy-peer-deps

# Copy all source files (node_modules excluded via .dockerignore)
COPY . .

# Build to /app/build  (outDir set in vite.config.js)
# Vite bakes REACT_APP_* into the JS bundle at build time via process.env shim
RUN REACT_APP_API_URL=${REACT_APP_API_URL} \
    REACT_APP_API_KEY=${REACT_APP_API_KEY} \
    npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM nginx:alpine

# SPA routing + /api/ reverse proxy to backend:8000
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy Vite output (same directory name as CRA: "build")
COPY --from=builder /app/build /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:80 || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
