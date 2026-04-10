"""
Main FastAPI application entry point.
Multi-Agent Email Threat Analysis System - Backend API
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
import structlog

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.database import init_db, init_neo4j_schema, close_neo4j_driver
from app.api.routes import router
from app.api.ml_routes import router as ml_router
from app.api.middleware import RequestLoggingMiddleware, RateLimitMiddleware, APIKeyMiddleware

# Setup logging
setup_logging()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("Starting Email Threat Analysis System", version=settings.APP_VERSION)

    try:
        await init_db()
        logger.info("PostgreSQL initialized")
    except Exception as e:
        logger.warning("PostgreSQL initialization warning", error=str(e))

    try:
        await init_neo4j_schema()
        logger.info("Neo4j schema initialized")
    except Exception as e:
        logger.warning("Neo4j initialization warning (non-fatal)", error=str(e))

    if settings.SEED_DEMO_DATA:
        try:
            from app.core.demo_seed import seed_postgres_demo
            inserted = await seed_postgres_demo(
                settings.SEED_DEMO_TRUNCATE,
                settings.SEED_DEMO_REPEAT,
                settings.SEED_DEMO_HOURS_STEP,
            )
            logger.info("Seeded demo PostgreSQL data", rows=inserted)
        except Exception as e:
            logger.warning("Demo PostgreSQL seeding failed", error=str(e))

        try:
            from app.core.demo_seed import seed_neo4j_demo
            nodes = await seed_neo4j_demo(settings.SEED_DEMO_TRUNCATE)
            logger.info("Seeded demo Neo4j data", nodes=nodes)
        except Exception as e:
            logger.warning("Demo Neo4j seeding failed", error=str(e))

    # Warm up ML model registry (loads checkpoints if they exist)
    try:
        from app.ml.phishing_classifier import get_registry
        registry = get_registry()
        logger.info("ML model registry initialized", status=registry.status())
    except Exception as e:
        logger.warning("ML model registry initialization warning", error=str(e))

    # Warm up RLHF pipeline
    try:
        from app.ml.rlhf import get_rlhf_pipeline
        pipeline = get_rlhf_pipeline()
        logger.info("RLHF pipeline initialized", stats=pipeline.store.stats())
    except Exception as e:
        logger.warning("RLHF pipeline initialization warning", error=str(e))

    logger.info("Application startup complete")
    yield

    # Shutdown
    logger.info("Shutting down application")
    await close_neo4j_driver()
    logger.info("Application shutdown complete")


# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## Multi-Agent Email Threat Analysis System

A production-grade email security platform using:
- **LangGraph** multi-agent orchestration
- **5 specialized AI agents** (Text, Metadata, Enrichment, Graph, Decision)
- **Custom ML Models** – 60-feature phishing classifier + LLM-generation detector
- **RLHF Pipeline** – Reinforcement Learning from Human Feedback for continuous improvement
- **Neo4j graph intelligence** for campaign correlation
- **VirusTotal & PhishTank** integration
- **Full explainability** with reasoning traces & feature attribution

### ML & RLHF
- `POST /api/v1/ml/predict` – Fast ML-only prediction with feature attribution
- `POST /api/v1/ml/feedback` – Submit analyst feedback for RLHF training
- `POST /api/v1/ml/train` – Trigger a training cycle
- `GET  /api/v1/ml/rlhf/status` – RLHF pipeline status

### Threat Categories Detected
- Business Email Compromise (BEC)
- Phishing & Spear Phishing
- LLM-Generated Phishing (custom model)
- QR Code Phishing (Quishing)
- Adversary-in-the-Middle (AiTM)
- Living-off-the-Land (LotL)
- Malware Attachments
- Executive Impersonation

### Quick Start
Submit an email via `POST /api/v1/analyze` to get a complete threat analysis.
    """,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc",
)

# ─── Middleware ───────────────────────────────────────────────────────────────

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.add_middleware(
    RateLimitMiddleware,
    limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
)

# Request logging
app.add_middleware(RequestLoggingMiddleware)

# API Key or session auth
app.add_middleware(APIKeyMiddleware)

# ─── Routes ──────────────────────────────────────────────────────────────────

app.include_router(router,    prefix="/api/v1")
app.include_router(ml_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/redoc",
        "api": "/api/v1",
    }


@app.get("/docs", include_in_schema=False)
async def custom_swagger():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{settings.APP_NAME} - API Docs",
    )
