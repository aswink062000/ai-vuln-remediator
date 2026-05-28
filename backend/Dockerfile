# ============================================================================
# AI Vulnerability Remediator — Backend
# Compact Docker image for Railway deployment
# ============================================================================

FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Install system dependencies (git is required for cloning repos)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS (required for npm dependency scanning & jscodeshift/ts-morph migrations)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    node --version && npm --version

# Install Java 17 (required for OpenRewrite, Maven-based projects)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    maven \
    && rm -rf /var/lib/apt/lists/* && \
    java -version && mvn --version

# Install OpenGrep (SAST scanner)
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash || \
    pip install semgrep

# Install Trivy (dependency + container scanning)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || true

# Install Gitleaks (secret detection)
RUN curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh | sh -s -- -b /usr/local/bin || true

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data /app/skills

# Expose port (Railway uses PORT env var)
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run with uvicorn (Railway compatible)
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
