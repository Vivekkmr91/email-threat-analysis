"""
FastAPI route definitions for the Email Threat Analysis API.
"""
import uuid
import time
import asyncio
from typing import Optional, List
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, status, Response, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
import structlog

from app.core.database import get_db
from app.models.email import EmailAnalysis, URLAnalysis, AttachmentAnalysis, ThreatVerdict
from app.models.schemas import (
    EmailSubmitRequest, EmailAnalysisResponse, AnalysisListResponse,
    AnalysisListItem, FeedbackRequest, DashboardStats, AgentFinding,
    URLResult, AttachmentResult, ThreatVerdictEnum, ThreatCategoryEnum,
    HealthResponse, LoginRequest, SessionResponse,
)
from app.agents.orchestrator import analyze_email
from app.core.config import settings
from app.core.database import get_neo4j_driver
from app.api.middleware import create_session_token, verify_session_token

logger = structlog.get_logger(__name__)

router = APIRouter()


# ─── Authentication ──────────────────────────────────────────────────────────

@router.post("/auth/login", response_model=SessionResponse, tags=["Auth"])
async def login(request: LoginRequest, response: Response):
    """Create a dashboard session and set an HTTP-only cookie."""
    if request.username != settings.DASHBOARD_USERNAME or request.password != settings.DASHBOARD_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    expires_at = datetime.utcnow() + timedelta(minutes=settings.DASHBOARD_SESSION_TTL_MINUTES)
    token = create_session_token(request.username, settings.DASHBOARD_SESSION_TTL_MINUTES * 60)
    response.set_cookie(
        settings.SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.DASHBOARD_SESSION_TTL_MINUTES * 60,
        path="/",
    )
    return SessionResponse(username=request.username, expires_at=expires_at)


@router.post("/auth/logout", tags=["Auth"])
async def logout(response: Response):
    """Clear the dashboard session cookie."""
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/auth/me", response_model=SessionResponse, tags=["Auth"])
async def session_me(request: Request):
    """Validate the current dashboard session."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    payload = verify_session_token(token) if token else None
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    expires_at = datetime.utcfromtimestamp(payload["exp"])
    return SessionResponse(username=payload.get("sub", "unknown"), expires_at=expires_at)


# ─── Health Check ────────────────────────────────────────────────────────────

async def _check_neo4j(timeout: float = 3.0) -> str:
    """Check Neo4j connectivity with a strict timeout so it never hangs."""
    async def _probe():
        driver = await get_neo4j_driver()
        async with driver.session() as session:
            result = await session.run("RETURN 1")
            await result.consume()

    try:
        await asyncio.wait_for(_probe(), timeout=timeout)
        return "healthy"
    except Exception:
        return "unhealthy"


async def _check_redis(timeout: float = 3.0) -> str:
    """Check Redis connectivity with a strict timeout."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=timeout)
        await asyncio.wait_for(r.ping(), timeout=timeout)
        await r.aclose()
        return "healthy"
    except Exception:
        return "unhealthy"


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """
    System health check endpoint.

    Returns HTTP 200 in all cases so Docker's healthcheck never blocks startup.
    Status field is 'healthy' when all core services are reachable, or 'degraded'
    when optional services (e.g. Neo4j on first boot) are still initialising.
    """
    from app.core.llm import llm_provider_info

    # Run Neo4j and Redis checks in parallel, each with a 3-second hard cap.
    neo4j_status, redis_status = await asyncio.gather(
        _check_neo4j(timeout=3.0),
        _check_redis(timeout=3.0),
    )

    llm_info = llm_provider_info()
    services = {
        "api":   "healthy",
        "redis": redis_status,
        "neo4j": neo4j_status,   # Neo4j is optional; may be "unhealthy" early on
        "llm":   llm_info["provider"],   # openrouter | openai | none
    }

    # The container is considered healthy as long as Redis + API are up.
    # Neo4j being slow to start should NOT mark the backend as unhealthy.
    core_healthy = services["api"] == "healthy" and services["redis"] == "healthy"
    overall_status = "healthy" if core_healthy else "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.APP_VERSION,
        services=services,
        timestamp=datetime.now(timezone.utc),
    )


# ─── Email Analysis ──────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
    summary="Submit an email for threat analysis",
)
async def submit_email_for_analysis(
    request: EmailSubmitRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Submit an email for multi-agent threat analysis.
    
    Supports:
    - Raw RFC 2822 email (EML format)
    - Structured JSON email data
    - Attachments (base64 encoded)
    
    Returns a complete analysis with:
    - Threat verdict (clean/spam/suspicious/malicious)
    - Threat score (0.0 - 1.0)
    - Detailed reasoning trace from all agents
    - URL and attachment analysis results
    - Recommended actions
    """
    start_time = time.time()
    analysis_id = str(uuid.uuid4())
    log = logger.bind(analysis_id=analysis_id)
    log.info("Email analysis request received", source=request.source)

    try:
        # Prepare email dict from request
        email_dict = None
        if not request.raw_email:
            email_dict = {
                "subject": request.subject,
                "sender": request.sender,
                "recipients": request.recipients,
                "body_text": request.body_text,
                "body_html": request.body_html,
                "headers": request.headers,
                "attachments_base64": request.attachments_base64,
            }

        # Run multi-agent analysis
        result = await analyze_email(
            raw_email=request.raw_email,
            email_dict=email_dict,
            source=request.source or "api",
            analysis_id=analysis_id,
        )

        # Save to database in background
        background_tasks.add_task(
            _save_analysis_to_db, db, analysis_id, request, result
        )

        # Build response
        return _build_analysis_response(analysis_id, result)

    except Exception as e:
        log.error("Analysis failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get(
    "/analyses/{analysis_id}",
    response_model=EmailAnalysisResponse,
    tags=["Analysis"],
    summary="Get analysis by ID",
)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a previously performed email analysis by ID."""
    result = await db.get(EmailAnalysis, analysis_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found"
        )
    return _db_record_to_response(result)


@router.get(
    "/analyses",
    response_model=AnalysisListResponse,
    tags=["Analysis"],
    summary="List all analyses",
)
async def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
    search: Optional[str] = Query(None, description="Search by sender/subject"),
    days: int = Query(30, description="Show analyses from last N days"),
    db: AsyncSession = Depends(get_db),
):
    """List all email analyses with pagination and filtering."""
    filters = []
    since = datetime.now(timezone.utc) - timedelta(days=days)
    filters.append(EmailAnalysis.created_at >= since)

    if verdict:
        try:
            filters.append(EmailAnalysis.verdict == ThreatVerdict(verdict))
        except ValueError:
            pass

    if search:
        filters.append(
            (EmailAnalysis.sender_email.ilike(f"%{search}%")) |
            (EmailAnalysis.subject.ilike(f"%{search}%"))
        )

    # Count total
    count_stmt = select(func.count()).select_from(EmailAnalysis).where(and_(*filters))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    # Fetch page
    offset = (page - 1) * page_size
    stmt = (
        select(EmailAnalysis)
        .where(and_(*filters))
        .order_by(desc(EmailAnalysis.created_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    analyses = result.scalars().all()

    items = [
        AnalysisListItem(
            analysis_id=str(a.id),
            created_at=a.created_at,
            subject=a.subject,
            sender_email=a.sender_email,
            verdict=ThreatVerdictEnum(a.verdict.value),
            threat_score=a.threat_score,
            threat_categories=a.threat_categories or [],
            has_feedback=bool(a.analyst_feedback),
        )
        for a in analyses
    ]

    return AnalysisListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


# ─── Feedback ────────────────────────────────────────────────────────────────

@router.post(
    "/analyses/{analysis_id}/feedback",
    tags=["Feedback"],
    summary="Submit analyst feedback on verdict",
)
async def submit_feedback(
    analysis_id: str,
    feedback: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Submit analyst feedback on a verdict (Human-in-the-Loop).
    
    Feedback types:
    - correct: Verdict was correct
    - false_positive: Email was flagged but is legitimate
    - false_negative: Email was clean but is malicious
    """
    record = await db.get(EmailAnalysis, analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found"
        )

    record.analyst_feedback = feedback.feedback_type.value
    record.analyst_notes = feedback.notes
    record.feedback_at = datetime.now(timezone.utc)
    record.feedback_by = feedback.analyst_id or "anonymous"

    await db.commit()

    logger.info(
        "Analyst feedback submitted",
        analysis_id=analysis_id,
        feedback=feedback.feedback_type.value
    )

    return {"status": "feedback_recorded", "analysis_id": analysis_id}


# ─── Dashboard Stats ─────────────────────────────────────────────────────────

@router.get(
    "/dashboard/stats",
    response_model=DashboardStats,
    tags=["Dashboard"],
    summary="Get SOC dashboard statistics",
)
async def get_dashboard_stats(
    days: int = Query(30, description="Statistics for last N days"),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated statistics for the SOC dashboard."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Total counts
    total_stmt = select(func.count()).select_from(EmailAnalysis).where(
        EmailAnalysis.created_at >= since
    )
    total = (await db.execute(total_stmt)).scalar() or 0

    # By verdict
    verdicts_stmt = select(
        EmailAnalysis.verdict, func.count().label("count")
    ).where(EmailAnalysis.created_at >= since).group_by(EmailAnalysis.verdict)
    verdict_result = await db.execute(verdicts_stmt)
    verdict_counts = {r.verdict.value: r.count for r in verdict_result}

    malicious = verdict_counts.get("malicious", 0)
    suspicious = verdict_counts.get("suspicious", 0)
    spam = verdict_counts.get("spam", 0)
    clean = verdict_counts.get("clean", 0)

    # Detection rate
    threats = malicious + suspicious
    detection_rate = threats / max(total, 1)

    # False positive rate (from feedback)
    fp_stmt = select(func.count()).select_from(EmailAnalysis).where(
        and_(
            EmailAnalysis.created_at >= since,
            EmailAnalysis.analyst_feedback == "false_positive"
        )
    )
    fp_count = (await db.execute(fp_stmt)).scalar() or 0
    fp_rate = fp_count / max(total, 1)

    # Average analysis time
    avg_time_stmt = select(func.avg(EmailAnalysis.analysis_duration_ms)).where(
        EmailAnalysis.created_at >= since
    )
    avg_time = (await db.execute(avg_time_stmt)).scalar() or 0

    # Threats over time (last 7 days)
    threats_over_time = await _get_threats_over_time(db, since)

    # Top sender domains
    top_domains = await _get_top_sender_domains(db, since, malicious=True)

    return DashboardStats(
        total_analyzed=total,
        malicious_count=malicious,
        suspicious_count=suspicious,
        spam_count=spam,
        clean_count=clean,
        detection_rate=detection_rate,
        false_positive_rate=fp_rate,
        avg_analysis_time_ms=float(avg_time),
        top_threat_categories=[],
        threats_over_time=threats_over_time,
        top_sender_domains=top_domains,
    )


# ─── Helper Functions ────────────────────────────────────────────────────────

def _build_analysis_response(analysis_id: str, result: dict) -> EmailAnalysisResponse:
    """Build API response from analysis result state."""
    agent_findings = []
    for finding in result.get("agent_findings", []):
        agent_findings.append(AgentFinding(
            agent_name=finding.get("agent_name", "unknown"),
            score=float(finding.get("score", 0)),
            confidence=float(finding.get("confidence", 0)),
            findings=finding.get("findings", []),
            indicators=finding.get("indicators", {}),
            threat_categories=[
                ThreatCategoryEnum(c) if c in [e.value for e in ThreatCategoryEnum] else ThreatCategoryEnum.CLEAN
                for c in finding.get("threat_categories", [])
            ],
            processing_time_ms=finding.get("processing_time_ms"),
        ))

    url_results = []
    for url_data in result.get("url_analyses", []):
        url_results.append(URLResult(
            url=url_data.get("url", ""),
            domain=url_data.get("domain"),
            is_malicious=url_data.get("threat_score", 0) > 0.5,
            virustotal_score=url_data.get("virustotal_score"),
            phishtank_detected=url_data.get("phishtank_detected"),
            is_qr_code_url=url_data.get("is_qr_code_url", False),
            is_look_alike=url_data.get("is_look_alike", False),
            look_alike_target=url_data.get("look_alike_target"),
            domain_age_days=url_data.get("domain_age_days"),
            ssl_valid=url_data.get("ssl_valid"),
            threat_details=url_data.get("indicators", {}),
        ))

    attachment_results = []
    for att_data in result.get("attachment_analyses", []):
        attachment_results.append(AttachmentResult(
            filename=att_data.get("filename", "unknown"),
            file_type=att_data.get("file_type"),
            file_size_bytes=att_data.get("file_size_bytes"),
            sha256_hash=att_data.get("sha256_hash"),
            is_malicious=att_data.get("threat_score", 0) > 0.5,
            virustotal_score=att_data.get("virustotal_score"),
            contains_qr_code=att_data.get("contains_qr_code", False),
            qr_code_urls=att_data.get("qr_code_urls", []),
            sandbox_verdict=att_data.get("sandbox_verdict"),
            threat_details=att_data.get("indicators", {}),
        ))

    verdict = result.get("verdict", "unknown")
    try:
        verdict_enum = ThreatVerdictEnum(verdict)
    except ValueError:
        verdict_enum = ThreatVerdictEnum.UNKNOWN

    categories = []
    for cat in result.get("threat_categories", []):
        try:
            categories.append(ThreatCategoryEnum(cat))
        except ValueError:
            pass

    return EmailAnalysisResponse(
        analysis_id=analysis_id,
        created_at=datetime.now(timezone.utc),
        verdict=verdict_enum,
        threat_score=float(result.get("threat_score", 0)),
        threat_categories=categories,
        agent_findings=agent_findings,
        url_results=url_results,
        attachment_results=attachment_results,
        reasoning_trace=result.get("reasoning_trace", "Analysis complete."),
        reasoning_steps=result.get("reasoning_steps", []),
        recommended_actions=result.get("recommended_actions", []),
        analysis_duration_ms=result.get("analysis_duration_ms", 0),
        agents_triggered=[f.get("agent_name", "") for f in result.get("agent_findings", [])],
    )


async def _save_analysis_to_db(
    db: AsyncSession, analysis_id: str,
    request: EmailSubmitRequest, result: dict
) -> None:
    """Persist analysis result to PostgreSQL."""
    try:
        async with db.begin_nested():
            parsed = result.get("parsed_email") or {}

            record = EmailAnalysis(
                id=analysis_id,
                message_id=parsed.get("message_id"),
                subject=parsed.get("subject") or request.subject,
                sender_email=parsed.get("sender_email") or request.sender,
                sender_display_name=parsed.get("sender_display_name"),
                recipient_emails=parsed.get("recipient_emails", []),
                reply_to=parsed.get("reply_to"),
                body_text=parsed.get("body_text"),
                verdict=ThreatVerdict(result.get("verdict", "unknown")),
                threat_score=result.get("threat_score", 0.0),
                threat_categories=result.get("threat_categories", []),
                text_agent_score=_get_agent_score(result, "text_analysis_agent"),
                metadata_agent_score=_get_agent_score(result, "metadata_agent"),
                enrichment_agent_score=_get_agent_score(result, "enrichment_agent"),
                graph_agent_score=_get_agent_score(result, "graph_correlation_agent"),
                reasoning_trace=result.get("reasoning_steps", []),
                analysis_duration_ms=result.get("analysis_duration_ms"),
                agents_triggered=[f.get("agent_name") for f in result.get("agent_findings", [])],
                email_source=request.source,
                external_email_id=request.external_email_id,
            )
            db.add(record)

            # Save URL analyses
            for url_data in result.get("url_analyses", []):
                if url_data.get("url"):
                    url_record = URLAnalysis(
                        email_analysis_id=analysis_id,
                        url=url_data["url"][:2000],
                        domain=url_data.get("domain"),
                        is_malicious=url_data.get("threat_score", 0) > 0.5,
                        virustotal_score=url_data.get("virustotal_score"),
                        is_qr_code_url=url_data.get("is_qr_code_url", False),
                        is_look_alike=url_data.get("is_look_alike", False),
                        look_alike_target=url_data.get("look_alike_target"),
                        threat_details=url_data.get("indicators", {}),
                    )
                    db.add(url_record)

            # Save attachment analyses
            for att_data in result.get("attachment_analyses", []):
                att_record = AttachmentAnalysis(
                    email_analysis_id=analysis_id,
                    filename=att_data.get("filename", "unknown")[:512],
                    file_type=att_data.get("file_type"),
                    file_size_bytes=att_data.get("file_size_bytes"),
                    sha256_hash=att_data.get("sha256_hash"),
                    md5_hash=att_data.get("md5_hash"),
                    is_malicious=att_data.get("threat_score", 0) > 0.5,
                    virustotal_score=att_data.get("virustotal_score"),
                    contains_qr_code=att_data.get("contains_qr_code", False),
                    qr_code_urls=att_data.get("qr_code_urls", []),
                    threat_details=att_data.get("indicators", {}),
                )
                db.add(att_record)

        await db.commit()
        logger.debug("Analysis saved to database", analysis_id=analysis_id)
    except Exception as e:
        logger.error("Failed to save analysis to database", error=str(e), analysis_id=analysis_id)


def _get_agent_score(result: dict, agent_name: str) -> Optional[float]:
    """Extract specific agent score from findings."""
    for finding in result.get("agent_findings", []):
        if finding.get("agent_name") == agent_name:
            return finding.get("score")
    return None


def _db_record_to_response(record: EmailAnalysis) -> EmailAnalysisResponse:
    """Convert DB record to API response."""
    return EmailAnalysisResponse(
        analysis_id=str(record.id),
        created_at=record.created_at,
        verdict=ThreatVerdictEnum(record.verdict.value),
        threat_score=record.threat_score,
        threat_categories=[
            ThreatCategoryEnum(c) for c in (record.threat_categories or [])
            if c in [e.value for e in ThreatCategoryEnum]
        ],
        agent_findings=[],
        url_results=[
            URLResult(
                url=u.url,
                domain=u.domain,
                is_malicious=u.is_malicious,
                virustotal_score=u.virustotal_score,
                is_qr_code_url=u.is_qr_code_url,
                is_look_alike=u.is_look_alike,
                look_alike_target=u.look_alike_target,
                threat_details=u.threat_details or {},
            ) for u in (record.urls or [])
        ],
        attachment_results=[
            AttachmentResult(
                filename=a.filename,
                file_type=a.file_type,
                file_size_bytes=a.file_size_bytes,
                sha256_hash=a.sha256_hash,
                is_malicious=a.is_malicious,
                contains_qr_code=a.contains_qr_code,
                qr_code_urls=a.qr_code_urls or [],
                threat_details=a.threat_details or {},
            ) for a in (record.attachments or [])
        ],
        reasoning_trace="See reasoning_steps for details",
        reasoning_steps=record.reasoning_trace or [],
        recommended_actions=[],
        analysis_duration_ms=record.analysis_duration_ms or 0,
        agents_triggered=record.agents_triggered or [],
    )


async def _get_threats_over_time(db: AsyncSession, since: datetime) -> list:
    """Get daily threat counts for chart."""
    try:
        stmt = select(
            func.date_trunc("day", EmailAnalysis.created_at).label("date"),
            EmailAnalysis.verdict,
            func.count().label("count")
        ).where(
            EmailAnalysis.created_at >= since
        ).group_by(
            func.date_trunc("day", EmailAnalysis.created_at),
            EmailAnalysis.verdict
        ).order_by("date")

        result = await db.execute(stmt)
        rows = result.all()

        # Group by date
        by_date = {}
        for row in rows:
            date_str = row.date.strftime("%Y-%m-%d") if row.date else "unknown"
            if date_str not in by_date:
                by_date[date_str] = {"date": date_str, "malicious": 0, "suspicious": 0, "spam": 0, "clean": 0}
            by_date[date_str][row.verdict.value] = row.count

        return sorted(by_date.values(), key=lambda x: x["date"])
    except Exception:
        return []


async def _get_top_sender_domains(db: AsyncSession, since: datetime, malicious: bool = False) -> list:
    """Get top sender domains by threat count."""
    try:
        filters = [EmailAnalysis.created_at >= since, EmailAnalysis.sender_email.isnot(None)]
        if malicious:
            filters.append(EmailAnalysis.verdict.in_([ThreatVerdict.MALICIOUS, ThreatVerdict.SUSPICIOUS]))

        stmt = select(
            func.split_part(EmailAnalysis.sender_email, "@", 2).label("domain"),
            func.count().label("count")
        ).where(and_(*filters)).group_by("domain").order_by(desc("count")).limit(10)

        result = await db.execute(stmt)
        return [{"domain": r.domain, "count": r.count} for r in result]
    except Exception:
        return []
