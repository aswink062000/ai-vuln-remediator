import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from app.api.routes import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load .env
load_dotenv()

app = FastAPI(title="AI Vulnerability Remediator")

# Read CORS origins from .env
origins = os.getenv("CORS_ORIGINS", "")

allowed_origins = [
    origin.strip()
    for origin in origins.split(",")
    if origin.strip()
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Test route
@app.get("/")
def home():
    return {"message": "FastAPI CORS working"}


# Health check with semgrep version info
@app.get("/health")
def health():
    import subprocess

    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        semgrep_version = result.stdout.strip() if result.returncode == 0 else "not found"
    except Exception:
        semgrep_version = "not installed"

    return {
        "status": "healthy",
        "semgrep_version": semgrep_version
    }


# Include API routes
app.include_router(router)
