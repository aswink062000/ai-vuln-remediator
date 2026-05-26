"""
AI Vulnerability Remediator — Enterprise Backend

FastAPI application with:
- API Key authentication (X-API-Key header)
- REST API for scan/remediation operations
- WebSocket for real-time progress streaming
- Rate limiting, request tracing, and structured logging
- Multi-provider LLM routing with automatic fallback
- Cross-platform scanner support (Windows, macOS, Linux)
"""

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from dotenv import load_dotenv

from app.api.routes import router
from app.api.websocket import router as ws_router
from app.api.webhook import router as webhook_router
from app.middleware import (
    APIKeyMiddleware,
    RequestIDMiddleware,
    RateLimitMiddleware,
    TimingMiddleware,
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Load .env
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("=" * 60)
    logger.info("AI Vulnerability Remediator — Starting")
    logger.info(f"Python: {sys.version}")
    logger.info(f"Platform: {sys.platform}")

    api_key = os.getenv("API_SECRET_KEY", "")
    if api_key:
        logger.info("API Key authentication: ENABLED")
    else:
        logger.warning("API Key authentication: DISABLED (set API_SECRET_KEY to enable)")

    logger.info("=" * 60)

    # Load encrypted credentials from SQLite store
    try:
        from app.store import load_credentials_to_env
        load_credentials_to_env()
    except Exception as e:
        logger.warning(f"Could not load credential store: {e}")

    # Validate critical configuration
    if not os.getenv("GITHUB_TOKEN"):
        logger.warning("GITHUB_TOKEN not set — Scan & Fix mode will not work")

    # Check LLM provider availability
    try:
        from app.llm.llm_router import router as llm_router
        status = llm_router.get_status()
        available = [k for k, v in status.items() if v.get("configured")]
        if available:
            logger.info(f"LLM providers available: {', '.join(available)}")
        else:
            logger.warning("No LLM providers configured — AI fix generation disabled")
    except Exception as e:
        logger.warning(f"LLM router init check failed: {e}")

    yield

    logger.info("AI Vulnerability Remediator — Shutting down")


# Create FastAPI app with comprehensive OpenAPI docs
app = FastAPI(
    title="AI Vulnerability Remediator",
    description="""
## Enterprise AI Security Platform

Scan GitHub repositories for vulnerabilities and generate AI-powered fixes automatically.

### Authentication

All API endpoints (except `/health`, `/docs`) require the `X-API-Key` header:

```
X-API-Key: your-secret-key-here
```

Set `API_SECRET_KEY` in your `.env` file. If not set, auth is disabled (dev mode).

### Features

- **SAST Scanning** — Semgrep-powered static analysis
- **Dependency Scanning** — CVE detection via pip-audit, npm audit, OSV.dev
- **Secret Detection** — Finds hardcoded API keys, tokens, passwords
- **Code Quality** — Complexity, duplication, tech debt (SonarQube alternative)
- **AI Remediation** — Multi-LLM fix generation with confidence scoring
- **Custom Rules** — User-defined Semgrep rules
- **Export** — SARIF, CSV, PDF report formats
- **Real-time Progress** — WebSocket streaming with terminal UI

### Scan Pipeline

1. Clone → 2. SAST → 3. Dependencies → 4. Secrets → 5. Custom Rules → 6. ML Severity → 7. Code Quality → 8. Quality Gate
    """,
    version="2.2.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "AI Vulnerability Remediator",
    },
    license_info={
        "name": "Proprietary",
    },
)


# --- Middleware (order matters: last added = first executed) ---

# CORS
origins = os.getenv("CORS_ORIGINS", "http://localhost:3000")
allowed_origins = [origin.strip() for origin in origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time"],
)

# API Key authentication
app.add_middleware(APIKeyMiddleware)

# Rate limiting (configurable via env)
rate_limit = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
rate_window = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(RateLimitMiddleware, max_requests=rate_limit, window_seconds=rate_window)

# Request ID for tracing
app.add_middleware(RequestIDMiddleware)

# Response timing
app.add_middleware(TimingMiddleware)


# --- Global exception handler ---
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Check server logs for details.",
        },
    )


# --- Public Routes (no auth needed) ---

@app.get("/", tags=["System"])
def home():
    """Service info and links."""
    return {
        "service": "AI Vulnerability Remediator",
        "version": "2.2.0",
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "auth_required": bool(os.getenv("API_SECRET_KEY")),
    }


@app.get("/health", tags=["System"])
def health():
    """Health check with system info for monitoring."""
    import subprocess
    import platform

    semgrep_version = "not installed"
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            semgrep_version = result.stdout.strip()
    except Exception:
        pass

    return {
        "status": "healthy",
        "version": "2.2.0",
        "platform": platform.system(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "semgrep": semgrep_version,
        "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
        "auth_enabled": bool(os.getenv("API_SECRET_KEY")),
    }


# --- Include API routes with tags for Swagger grouping ---
app.include_router(router, prefix="/api/v1", tags=["API v1"])
app.include_router(router, tags=["API (legacy)"])
app.include_router(ws_router, tags=["WebSocket"])
app.include_router(webhook_router, tags=["Webhook"])


# --- Custom OpenAPI schema with security ---
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add API Key security scheme
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for authentication. Set API_SECRET_KEY in .env to enable.",
        }
    }

    # Apply security globally
    openapi_schema["security"] = [{"ApiKeyAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
