"""
Enterprise middleware for the AI Vulnerability Remediator.

Provides:
- API Key authentication (X-API-Key header)
- Request ID tracking for distributed tracing
- Rate limiting per IP
- Request/response logging with timing
- Error handling with structured responses
"""

import os
import time
import uuid
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Paths that don't require API key authentication
PUBLIC_PATHS = {
    "/", "/health", "/docs", "/redoc", "/openapi.json",
    "/docs/oauth2-redirect",
}


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    API Key authentication middleware.

    Requires X-API-Key header on all requests (except public paths).
    The key is configured via API_SECRET_KEY environment variable.

    If API_SECRET_KEY is not set, authentication is disabled (dev mode).
    """

    async def dispatch(self, request: Request, call_next):
        api_key = os.getenv("API_SECRET_KEY", "")

        # If no key configured, skip auth (dev mode)
        if not api_key:
            return await call_next(request)

        # Skip auth for public paths
        path = request.url.path
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth for WebSocket (authenticated via message)
        if path.startswith("/ws/"):
            return await call_next(request)

        # Skip auth for Swagger/OpenAPI static assets
        if path.startswith("/docs") or path.startswith("/redoc"):
            return await call_next(request)

        # Check X-API-Key header
        request_key = request.headers.get("X-API-Key", "")

        if not request_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Missing X-API-Key header. Provide your API key to access this endpoint.",
                },
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Constant-time comparison to prevent timing attacks
        if not _secure_compare(request_key, api_key):
            logger.warning(f"Invalid API key attempt from {request.client.host if request.client else 'unknown'}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "forbidden",
                    "message": "Invalid API key.",
                },
            )

        return await call_next(request)


def _secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        # Hash both to make timing constant even for different lengths
        return hashlib.sha256(a.encode()).digest() == hashlib.sha256(b.encode()).digest()
    return hashlib.sha256(a.encode()).digest() == hashlib.sha256(b.encode()).digest()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Adds a unique request ID to every request for tracing."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter.
    Limits requests per IP per time window.
    """

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and WebSocket
        if request.url.path in ("/health", "/", "/docs", "/openapi.json"):
            return await call_next(request)
        if request.url.path.startswith("/ws/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)

        # Clean old entries
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > window_start
        ]

        if len(self.requests[client_ip]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Limit: {self.max_requests} per {self.window_seconds}s",
                    "retry_after": self.window_seconds,
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        self.requests[client_ip].append(now)
        return await call_next(request)


class TimingMiddleware(BaseHTTPMiddleware):
    """Logs request duration and adds timing header."""

    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        response.headers["X-Response-Time"] = f"{duration:.3f}s"

        # Log slow requests
        if duration > 5.0:
            logger.warning(
                f"Slow request: {request.method} {request.url.path} "
                f"took {duration:.2f}s"
            )

        return response
