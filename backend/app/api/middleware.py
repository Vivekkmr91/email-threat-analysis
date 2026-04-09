"""
FastAPI middleware for authentication, rate limiting, and request logging.
"""
import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Callable, Optional

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
import structlog
import redis.asyncio as aioredis

from app.core.config import settings

logger = structlog.get_logger(__name__)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """API key or session-based authentication middleware."""

    # Paths that bypass auth.
    # Include both bare paths AND the /api/v1-prefixed versions so the
    # Docker healthcheck (curl /api/v1/health) is never blocked.
    EXCLUDED_PATHS = {
        "/",
        "/health",
        "/api/v1/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/auth/login",
        "/api/v1/integrations/gmail/webhook",
        "/api/v1/integrations/microsoft/webhook",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Skip auth for excluded paths (exact match or health-check prefix)
        if path in self.EXCLUDED_PATHS or path.endswith("/health"):
            return await call_next(request)

        api_key = request.headers.get(settings.API_KEY_HEADER)
        if api_key and api_key in settings.ALLOWED_API_KEYS:
            return await call_next(request)

        session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if session_token and verify_session_token(session_token):
            return await call_next(request)

        return Response(
            content='{"detail": "Invalid or missing credentials"}',
            status_code=status.HTTP_401_UNAUTHORIZED,
            media_type="application/json",
        )


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests with timing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        structlog.contextvars.bind_contextvars(request_id=request_id)

        logger.info(
            "Request received",
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )

        response = await call_next(request)

        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms}ms"

        structlog.contextvars.unbind_contextvars("request_id")
        return response


def _pad_b64(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return value + padding


def create_session_token(username: str, expires_in_seconds: int) -> str:
    payload = {"sub": username, "exp": int(time.time()) + expires_in_seconds}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(settings.SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def verify_session_token(token: str) -> Optional[dict]:
    try:
        body, signature = token.rsplit(".", 1)
        expected = hmac.new(settings.SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64(body)))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Redis-backed rate limiting middleware with per-minute windows."""

    def __init__(self, app, limit_per_minute: int = 60):
        super().__init__(app)
        self.limit = limit_per_minute
        self._redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = int(time.time())
        window = now // 60
        key = f"rate_limit:{client_ip}:{window}"

        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, 60)
            if count > self.limit:
                return Response(
                    content='{"detail": "Rate limit exceeded. Try again in a minute."}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="application/json",
                )
        except Exception as exc:
            logger.warning("Rate limiter unavailable", error=str(exc))

        return await call_next(request)
