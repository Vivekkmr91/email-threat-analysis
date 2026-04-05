"""
Database connection management - PostgreSQL (SQLAlchemy) and Neo4j.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from neo4j import AsyncGraphDatabase, AsyncDriver
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


# ─── PostgreSQL Setup ───────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency: get async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("PostgreSQL tables initialized")


# ─── Neo4j Setup ────────────────────────────────────────────────────────────


_neo4j_driver: AsyncDriver | None = None


async def get_neo4j_driver() -> AsyncDriver:
    """Get or create Neo4j async driver."""
    global _neo4j_driver
    if _neo4j_driver is None:
        _neo4j_driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
            max_connection_lifetime=3600,
            max_connection_pool_size=50,
        )
        logger.info("Neo4j driver initialized", uri=settings.NEO4J_URI)
    return _neo4j_driver


async def close_neo4j_driver() -> None:
    """Close Neo4j driver on shutdown."""
    global _neo4j_driver
    if _neo4j_driver:
        await _neo4j_driver.close()
        _neo4j_driver = None
        logger.info("Neo4j driver closed")


@asynccontextmanager
async def neo4j_session():
    """Context manager for Neo4j sessions."""
    driver = await get_neo4j_driver()
    async with driver.session(database=settings.NEO4J_DATABASE) as session:
        yield session


async def init_neo4j_schema() -> None:
    """Initialize Neo4j constraints and indexes."""
    constraints = [
        "CREATE CONSTRAINT email_addr_unique IF NOT EXISTS FOR (e:EmailAddress) REQUIRE e.address IS UNIQUE",
        "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
        "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE",
        "CREATE CONSTRAINT url_unique IF NOT EXISTS FOR (u:URL) REQUIRE u.url IS UNIQUE",
        "CREATE CONSTRAINT campaign_unique IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
        "CREATE INDEX email_threat_score IF NOT EXISTS FOR (e:EmailAddress) ON (e.threat_score)",
        "CREATE INDEX domain_registered IF NOT EXISTS FOR (d:Domain) ON (d.registered_date)",
        "CREATE INDEX url_vt_score IF NOT EXISTS FOR (u:URL) ON (u.virustotal_score)",
    ]

    async with neo4j_session() as session:
        for constraint in constraints:
            try:
                await session.run(constraint)
            except Exception as e:
                logger.warning("Neo4j constraint/index already exists or error", error=str(e))

    logger.info("Neo4j schema initialized")
