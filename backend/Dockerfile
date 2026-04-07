# ─── Backend Dockerfile ──────────────────────────────────────────────────────
# Multi-stage build for the FastAPI backend + ML models
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

# Install system-level dependencies required by pyzbar, python-magic, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libzbar0 \
        libzbar-dev \
        libmagic1 \
        libmagic-dev \
        gcc \
        g++ \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─── Dependencies layer (cached unless requirements.txt changes) ──────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ─── Application layer ───────────────────────────────────────────────────────
COPY . .

# Create directories needed at runtime
RUN mkdir -p /app/ml_models /app/logs

# Non-root user for security
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check uses the correct API path
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

EXPOSE 8000

# Default: run the FastAPI server
# Override the command in docker-compose for celery_worker / celery_beat
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
