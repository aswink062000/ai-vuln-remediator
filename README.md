# AI Vulnerability Remediator

Enterprise-grade AI security platform that scans GitHub repositories for vulnerabilities and generates automated fixes with Pull Requests.

## Features

- **Multi-Scanner Architecture**: Semgrep (SAST) + Dependency scanning (pip-audit, npm audit, OSV.dev)
- **AI-Powered Remediation**: Multi-provider LLM routing (Gemini → Groq → NVIDIA → OpenRouter → HuggingFace)
- **Real-Time Progress**: WebSocket streaming with terminal-like UI
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Auto-Install**: Automatically installs missing scan tools
- **GitOps Pipeline**: Fork → Branch → Fix → Validate → Push → PR
- **PDF Reports**: Professional vulnerability reports
- **Enterprise Ready**: Rate limiting, request tracing, Docker support, API versioning

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- Git

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # Edit with your API keys
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Docker

```bash
docker-compose up --build
```

## Configuration

Copy `backend/.env.example` to `backend/.env` and configure:

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | For Scan & Fix | GitHub PAT with `repo` scope |
| `GEMINI_API_KEY` | Recommended | Google Gemini API key |
| `CORS_ORIGINS` | Yes | Allowed frontend origins |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/scan-only` | Scan without fixing |
| POST | `/scan` | Scan + fix + create PR |
| POST | `/report/pdf` | Generate PDF report |
| GET | `/environment` | Check system SDKs |
| WS | `/ws/scan` | Real-time scan progress |

All endpoints are also available under `/api/v1/` prefix.

## Architecture

```
┌─────────────┐     WebSocket/HTTP     ┌──────────────────┐
│   Frontend  │ ◄──────────────────── │     Backend      │
│  (Next.js)  │                        │    (FastAPI)     │
└─────────────┘                        └────────┬─────────┘
                                                │
                    ┌───────────────────────────┼───────────────┐
                    │                           │               │
              ┌─────▼─────┐            ┌───────▼──────┐  ┌────▼────┐
              │  Scanners  │            │  LLM Router  │  │ GitOps  │
              │ Semgrep    │            │ Gemini/Groq  │  │ Clone   │
              │ pip-audit  │            │ NVIDIA/OR    │  │ Branch  │
              │ npm audit  │            │ HuggingFace  │  │ Push/PR │
              │ OSV.dev    │            └──────────────┘  └─────────┘
              └────────────┘
```

## License

Proprietary — EY Internal Use
