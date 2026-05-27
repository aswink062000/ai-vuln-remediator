# AI Vulnerability Remediator - System Knowledge Base

This document provides a comprehensive overview of the AI Vulnerability Remediator project to enable AI agents to understand the architecture, workflows, and technical implementation details.

## 🚀 Project Overview
The AI Vulnerability Remediator is an enterprise-grade security platform that automates the discovery and remediation of vulnerabilities in GitHub repositories. It combines Static Analysis Security Testing (SAST) via Semgrep with Large Language Models (LLMs) to generate and apply security patches.

## 🏗️ Architecture

### 1. Backend (FastAPI)
The backend is a Python-based FastAPI application structured as follows:
- **`app/api/`**: REST endpoints for triggering scans, managing credentials, and handling webhooks.
- **`app/scanners/`**: 
    - `semgrep_scan.py`: Cross-platform wrapper for Semgrep. Handles binary discovery and execution.
    - `multi_scanner.py`: Orchestrates multiple scanning tools.
- **`app/llm/`**: 
    - `llm_router.py`: A sophisticated routing system with automatic fallback across multiple providers (Gemini, Groq, NVIDIA, OpenRouter, HuggingFace). Implements exponential backoff for rate limits.
- **`app/gitops/`**: Manages the lifecycle of repository clones, branch creation, committing fixes, and pushing to GitHub.
- **`app/store.py`**: Secure SQLite-based credential store using Fernet (AES-128) encryption.
- **`app/workflow/`**: Orchestrates the end-to-end process: `Clone` $\rightarrow$ `Scan` $\rightarrow$ `Analyze` $\rightarrow$ `Fix` $\rightarrow$ `Validate` $\rightarrow$ `Push`.

### 2. Frontend (Next.js)
A modern React-based dashboard providing:
- Real-time scan progress via WebSockets.
- Vulnerability visualization and fix review.
- Credential management and system settings.

### 3. Infrastructure
- **Docker**: Containerized deployment using `docker-compose`.
- **Railway**: Optimized for cloud deployment with environment-aware binary discovery.

## 🛠️ Key Workflows

### Vulnerability Remediation Pipeline
1. **Ingestion**: User provides a GitHub URL.
2. **Cloning**: `gitops/clone.py` creates a temporary local copy of the repo.
3. **Scanning**: `scanners/semgrep_scan.py` runs SAST analysis and generates findings.
4. **Analysis**: `llm/analyzer.py` extracts context and identifies the root cause.
5. **Fix Generation**: `llm_router.py` selects the best available LLM to generate a security patch.
6. **Application**: `patchers/file_patcher.py` applies the fix to the source code.
7. **Validation**: `validators/validate.py` ensures the fix doesn't break the code.
8. **Delivery**: `gitops/push.py` creates a new branch and pushes the fix to the remote repository.

## 🔐 Security Implementation
- **Encryption at Rest**: All API keys and tokens are encrypted using a machine-specific or environment-provided `ENCRYPTION_SECRET`.
- **Token Safety**: GitHub tokens are injected into remote URLs only during the push operation and are immediately reverted to prevent leakage.
- **Input Sanitization**: Uses `GitPython` instead of raw shell commands to prevent command injection.

## ⚙️ Configuration
Critical environment variables:
- `API_SECRET_KEY`: Secures the backend API.
- `GITHUB_TOKEN`: Required for repository operations.
- `ENCRYPTION_SECRET`: Required for consistent credential decryption across deployments.
- `DEFAULT_LLM_PROVIDER`: Sets the preferred AI model.
- `GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, etc.: Provider-specific keys.

## ⚠️ Common Troubleshooting for Agents
- **Semgrep Binary**: If `semgrep` is not found, the system attempts auto-installation via pip. In cloud environments, ensure the binary is in the system `PATH`.
- **LLM Failures**: The router will automatically try the next provider if one fails or hits a rate limit.
- **Disk Space**: The system automatically cleans up cloned repositories older than 1 hour to prevent disk exhaustion.
