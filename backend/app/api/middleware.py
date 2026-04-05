"""
FastAPI middleware for authentication, rate limiting, and request logging.
"""
import time
import uuid
from typing import Callable

from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Simple API key authentication middleware."""

    EXCLUDED_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip auth for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        # Skip in debug mode
        if settings.DEBUG:
            return await call_next(request)

        api_key = request.headers.get(settings.API_KEY_HEADER)
        if not api_key or api_key not in settings.ALLOWED_API_KEYS:
            return Response(
                content='{"detail": "Invalid or missing API key"}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
            )

        return await call_next(request)


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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""

    def __init__(self, app, limit_per_minute: int = 60):
        super().__init__(app)
        self.limit = limit_per_minute
        self._requests: dict = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60

        # Clean old entries
        if client_ip in self._requests:
            self._requests[client_ip] = [t for t in self._requests[client_ip] if t > window_start]
        else:
            self._requests[client_ip] = []

        if len(self._requests[client_ip]) >= self.limit:
            return Response(
                content='{"detail": "Rate limit exceeded. Try again in a minute."}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json",
            )

        self._requests[client_ip].append(now)
        return await call_next(request)
