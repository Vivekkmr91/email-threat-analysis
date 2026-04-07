# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package manifests (lock file included for reproducible installs)
COPY package.json package-lock.json* ./

# CI=false → ESLint warnings stay as warnings, never abort the build
# --legacy-peer-deps → handles transitive peer-dep conflicts cleanly
RUN CI=false npm install --legacy-peer-deps

# Copy all source files
COPY . .

# CI=false          : keep ESLint warnings non-fatal (CRA sets CI=true in Docker env)
# GENERATE_SOURCEMAP=false : skip source-map generation → faster build, less RAM
# REACT_APP_API_URL : baked-in at build time; Nginx proxies /api/ → backend:8000
RUN CI=false \
    GENERATE_SOURCEMAP=false \
    REACT_APP_API_URL=/api/v1 \
    npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM nginx:alpine

# Custom Nginx config (SPA fallback + /api/ reverse proxy to backend)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Serve compiled static assets
COPY --from=builder /app/build /usr/share/nginx/html

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:80 || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
