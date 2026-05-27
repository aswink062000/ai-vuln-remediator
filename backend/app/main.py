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

# App version — single source of truth
APP_VERSION = "2.2.0"

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

    # Check and auto-install prerequisites (Git, OpenGrep/Semgrep, pip-audit)
    try:
        from app.prerequisites import check_all_prerequisites
        prereq_status = check_all_prerequisites()
        if prereq_status["failed"]:
            logger.warning(f"Some prerequisites could not be installed: {prereq_status['failed']}")
    except Exception as e:
        logger.warning(f"Prerequisite check failed: {e}")

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
    version=APP_VERSION,
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

    error_msg = str(exc)
    status_code = 500
    error_type = "internal_server_error"
    user_message = "An unexpected error occurred. Check server logs for details."

    # Detect common error types and provide helpful messages
    if "GITHUB_TOKEN" in error_msg or "Bad credentials" in error_msg or "401" in error_msg:
        status_code = 401
        error_type = "github_auth_error"
        user_message = (
            "GitHub authentication failed. Please check your GITHUB_TOKEN in Settings. "
            "Ensure the token has 'repo' scope and hasn't expired."
        )
    elif "Not Found" in error_msg and "404" in error_msg:
        status_code = 404
        error_type = "repo_not_found"
        user_message = (
            "Repository not found. Check the URL is correct and the repo is accessible "
            "with your GitHub token (private repos need token with 'repo' scope)."
        )
    elif "Could not resolve host" in error_msg or "Name or service not known" in error_msg:
        status_code = 502
        error_type = "network_error"
        user_message = "Network error: cannot reach GitHub. Check your internet connection."
    elif "rate limit" in error_msg.lower() or "403" in error_msg:
        status_code = 429
        error_type = "rate_limited"
        user_message = (
            "GitHub API rate limit exceeded. Wait a few minutes and try again, "
            "or configure a GitHub token in Settings for higher limits."
        )
    elif "git" in error_msg.lower() and ("not found" in error_msg.lower() or "not installed" in error_msg.lower()):
        status_code = 503
        error_type = "git_not_installed"
        user_message = "Git is not installed on the server. Install Git and ensure it's in the system PATH."
    elif "clone" in error_msg.lower() and "failed" in error_msg.lower():
        status_code = 400
        error_type = "clone_failed"
        user_message = (
            "Failed to clone the repository. Possible causes: "
            "invalid URL, private repo without token, or branch doesn't exist."
        )
    elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
        status_code = 504
        error_type = "timeout"
        user_message = "The operation timed out. The repository might be too large or the network is slow."

    return JSONResponse(
        status_code=status_code,
        content={
            "error": error_type,
            "message": user_message,
            "detail": error_msg[:500] if status_code == 500 else None,
        },
    )


# --- Public Routes (no auth needed) ---

@app.get("/", tags=["System"])
def home():
    """Service info and links."""
    import platform

    return {
        "service": "AI Vulnerability Remediator",
        "version": APP_VERSION,
        "status": "running",
        "platform": platform.system(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "docs": "/docs",
        "redoc": "/redoc",
        "auth_required": bool(os.getenv("API_SECRET_KEY")),
        "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
    }


@app.get("/health", tags=["System"])
def health():
    """Health check with full dynamic system info for monitoring."""
    import subprocess
    import platform
    import shutil

    # Detect semgrep
    semgrep_version = "not installed"
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        try:
            result = subprocess.run(
                [semgrep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                semgrep_version = result.stdout.strip()
        except Exception:
            semgrep_version = "installed (version unknown)"

    # Detect git
    git_version = "not installed"
    git_path = shutil.which("git")
    if git_path:
        try:
            result = subprocess.run([git_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                git_version = result.stdout.strip().replace("git version ", "")
        except Exception:
            git_version = "installed (version unknown)"

    # Detect node
    node_version = "not installed"
    node_path = shutil.which("node")
    if node_path:
        try:
            result = subprocess.run([node_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                node_version = result.stdout.strip()
        except Exception:
            pass

    # LLM providers status
    llm_configured = []
    for key_name, provider_name in [
        ("GEMINI_API_KEY", "gemini"),
        ("GROQ_API_KEY", "groq"),
        ("NVIDIA_API_KEY", "nvidia"),
        ("OPENROUTER_API_KEY", "openrouter"),
        ("HUGGINGFACE_API_KEY", "huggingface"),
    ]:
        if os.getenv(key_name):
            llm_configured.append(provider_name)

    return {
        "status": "healthy",
        "version": APP_VERSION,
        "system": {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "python_path": sys.executable,
        },
        "tools": {
            "semgrep": semgrep_version,
            "semgrep_path": semgrep_path,
            "git": git_version,
            "node": node_version,
        },
        "config": {
            "github_token_configured": bool(os.getenv("GITHUB_TOKEN")),
            "auth_enabled": bool(os.getenv("API_SECRET_KEY")),
            "llm_providers_configured": llm_configured,
            "default_llm_provider": os.getenv("DEFAULT_LLM_PROVIDER", "auto"),
        },
    }


@app.get("/health/prerequisites", tags=["System"])
def prerequisites_status():
    """Check status of all required tools (Git, OpenGrep/Semgrep, pip-audit, npm)."""
    from app.prerequisites import get_prerequisite_status
    return get_prerequisite_status()


# --- Include API routes with tags for Swagger grouping ---
app.include_router(router, prefix="/api/v1", tags=["API v1"])
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
