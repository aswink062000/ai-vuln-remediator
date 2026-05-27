# AI Vulnerability Remediator

**Enterprise AI Security Platform** — Scan GitHub repositories for vulnerabilities and generate AI-powered fixes automatically.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()

---

## What It Does

A complete security scanning and auto-remediation platform that:

1. **Scans** your code for vulnerabilities (SAST, dependencies, secrets, code quality)
2. **Fixes** them automatically using AI (multi-LLM with fallback)
3. **Creates a Pull Request** with all fixes applied and inline review comments
4. **Reports** compliance status (OWASP, CWE, PCI-DSS) in PDF/SARIF/CSV

Think of it as **SonarQube + Snyk + GitHub Advanced Security + AI auto-fix** — combined into one tool.

---

## How We Compare to Traditional Scanners

### The Problem with Existing Tools

Traditional scanners **find** vulnerabilities but leave the hard part — **fixing them** — entirely to developers. Our platform closes that gap.

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                    TRADITIONAL TOOLS vs AI VULNERABILITY REMEDIATOR                  ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║  TRADITIONAL WORKFLOW                    OUR WORKFLOW                                 ║
║  ────────────────────                    ────────────                                 ║
║                                                                                      ║
║  Scanner finds 200 vulns                 Scanner finds 200 vulns                     ║
║       │                                       │                                      ║
║       ▼                                       ▼                                      ║
║  Developer reads report                  AI generates fixes automatically            ║
║       │                                       │                                      ║
║       ▼                                       ▼                                      ║
║  Developer researches each fix           Confidence scoring validates fixes           ║
║       │                                       │                                      ║
║       ▼                                       ▼                                      ║
║  Developer writes code (days/weeks)      PR created with all fixes (minutes)         ║
║       │                                       │                                      ║
║       ▼                                       ▼                                      ║
║  Code review + testing                   Inline review comments explain each fix      ║
║       │                                       │                                      ║
║       ▼                                       ▼                                      ║
║  Deploy (2-4 weeks later)                Developer reviews + merges (same day)        ║
║                                                                                      ║
║  ⏱️ Time: 2-4 weeks per scan             ⏱️ Time: 5-15 minutes per scan              ║
║  💰 Cost: Developer hours × findings     💰 Cost: Near zero (automated)              ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

### Feature-by-Feature Comparison

| Capability | Burp Suite | SonarQube | Snyk | Checkmarx | GitHub Advanced Security | **AI Vuln Remediator** |
|-----------|:----------:|:---------:|:----:|:---------:|:------------------------:|:---------------------:|
| **SAST (Source Code)** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DAST (Runtime)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Dependency CVEs** | ❌ | ✅ (paid) | ✅ | ✅ | ✅ | ✅ |
| **Secret Detection** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Code Quality/Debt** | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| **AI Auto-Fix** | ❌ | ❌ | ❌ | ❌ | ✅ (limited) | ✅ (multi-LLM) |
| **Auto PR Creation** | ❌ | ❌ | ✅ (deps only) | ❌ | ✅ (deps only) | ✅ (all fix types) |
| **Fix Confidence Score** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Compliance Mapping** | ❌ | ✅ (paid) | ❌ | ✅ (paid) | ❌ | ✅ |
| **Multi-Repo Dashboard** | ❌ | ✅ (paid) | ✅ (paid) | ✅ (paid) | ❌ | ✅ |
| **Baseline/Suppress** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Custom Rules** | ❌ | ✅ (paid) | ❌ | ✅ (paid) | ❌ | ✅ |
| **PDF Reports** | ✅ | ✅ (paid) | ❌ | ✅ | ❌ | ✅ |
| **SARIF Export** | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Real-time Progress** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (WebSocket) |
| **Breaking Change Migration** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Self-hosted** | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| **No license fees** | ❌ ($449/yr) | ❌ ($150k+/yr) | ❌ ($98+/mo) | ❌ ($$$) | ❌ ($21/user/mo) | ✅ |

### What Each Traditional Tool Does vs What We Do

#### Burp Suite (PortSwigger)
- **What it does**: Dynamic Application Security Testing (DAST) — tests running web apps by sending malicious requests
- **Limitation**: Only finds runtime vulnerabilities in web apps. Cannot scan source code. Cannot fix anything.
- **We differ**: We scan source code statically (SAST) — finds vulnerabilities before deployment. We also **fix** them.

#### SonarQube (Sonar)
- **What it does**: Code quality + some security rules. Measures complexity, duplication, tech debt.
- **Limitation**: Reports issues but doesn't fix them. Security rules are basic. Enterprise features cost $150k+/year.
- **We differ**: We include equivalent code quality metrics **plus** AI auto-fix, dependency scanning, secret detection, and compliance mapping — all free.

#### Snyk
- **What it does**: Dependency vulnerability scanning. Can auto-create PRs for version bumps.
- **Limitation**: Only fixes dependency issues (version bumps). Cannot fix code-level vulnerabilities (SQL injection, XSS, etc.). Paid plans required for teams.
- **We differ**: We fix **both** dependency vulnerabilities AND code-level vulnerabilities. Our AI rewrites the actual vulnerable code, not just version numbers.

#### Checkmarx
- **What it does**: Enterprise SAST with deep code analysis. Very thorough scanning.
- **Limitation**: Extremely expensive ($100k+/year). Reports only — no auto-fix. Slow scans (hours). Complex setup.
- **We differ**: Comparable scanning depth via Semgrep + ML severity prediction, but with AI auto-fix and results in minutes, not hours.

#### GitHub Advanced Security (CodeQL + Dependabot)
- **What it does**: CodeQL for SAST, Dependabot for dependency updates, secret scanning.
- **Limitation**: Copilot Autofix is limited to simple patterns. Dependabot only bumps versions. No code quality. No compliance. $21/user/month.
- **We differ**: Multi-LLM fix generation handles complex vulnerabilities. Includes code quality, compliance mapping, multi-repo dashboard, custom rules, and PDF reports.

### Our Unique Differentiators

| Feature | Why It Matters |
|---------|---------------|
| **Multi-LLM Fallback** | If Gemini hits rate limits, automatically tries Groq → NVIDIA → OpenRouter → HuggingFace. Fixes always get generated. |
| **Fix Confidence Scoring** | Re-scans the fixed code to verify the vulnerability is actually gone. Shows 0-100% confidence per file. |
| **Context-Aware Extraction** | Sends only the relevant function to the LLM (not the whole file). Saves 60-80% tokens, improves fix accuracy. |
| **Breaking Change Migration** | When upgrading Spring Boot 2→3 or JUnit 4→5, automatically migrates javax→jakarta, updates deprecated APIs. |
| **Inline PR Review Comments** | Each fix in the PR has a comment explaining what was found, why it's dangerous, and what the fix does. |
| **Per-Scan AI Instructions** | Users can provide project-specific instructions (coding standards, framework versions) directly in the scan form. |
| **Secret Safety Check** | Before pushing fixes, scans the AI-generated code to ensure it didn't accidentally introduce new secrets. |
| **Quality Gate** | Pass/fail decision based on configurable thresholds (like SonarQube) — blocks low-quality code. |

### Summary: Why Choose Us

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   Other tools:  Find vulnerabilities → Generate report → DONE       │
│                 (Developer spends days/weeks fixing manually)        │
│                                                                     │
│   Our tool:     Find vulnerabilities → AI fixes them → Create PR    │
│                 → Validate fixes → Explain changes → DONE            │
│                 (Developer just reviews and merges)                  │
│                                                                     │
│   Result: 95% reduction in remediation time                         │
│           Zero additional developer hours per vulnerability          │
│           Same-day security compliance instead of quarterly          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (Next.js 16)                              │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Scanner  │  │Dashboard │  │ Settings │  │  About   │  │Remediate │    │
│  │   Page    │  │  (Multi) │  │  (Token) │  │  (Docs)  │  │  (Fix)   │    │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └──────────┘  └──────────┘    │
│        │              │              │                                       │
│        ▼              ▼              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              WebSocket (real-time)  /  REST API (HTTP)               │   │
│  └─────────────────────────────────────┬───────────────────────────────┘   │
└────────────────────────────────────────┼────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BACKEND (FastAPI + Python)                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        API Layer (/api/v1/)                          │   │
│  │  • REST endpoints (scan, fix, export, settings, rules, schedules)   │   │
│  │  • WebSocket endpoint (real-time scan progress streaming)           │   │
│  │  • Webhook endpoint (GitHub push event auto-scan)                   │   │
│  │  • Middleware: API Key Auth, Rate Limiting, Request ID, Timing      │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                      SCAN PIPELINE                                   │   │
│  │                                                                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │   │
│  │  │  Clone  │→ │  SAST   │→ │  Deps   │→ │ Secrets │→ │ Custom  │ │   │
│  │  │  Repo   │  │(Semgrep)│  │(OSV/pip)│  │(Regex+  │  │  Rules  │ │   │
│  │  │         │  │         │  │         │  │Entropy) │  │         │ │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘ │   │
│  │       │                                                      │      │   │
│  │       ▼                                                      ▼      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐  │   │
│  │  │  Best   │→ │   ML    │→ │  Code   │→ │   Quality Gate      │  │   │
│  │  │Practice │  │Severity │  │ Quality │  │   (Pass/Fail)       │  │   │
│  │  │  Scan   │  │Predictor│  │ Scanner │  │                     │  │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────────────┘  │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                    REMEDIATION ENGINE                                │   │
│  │                                                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │  LLM Router │  │  Context    │  │  Confidence │  │  Secret   │ │   │
│  │  │  (Multi-    │  │  Extractor  │  │  Validator  │  │  Scanner  │ │   │
│  │  │  Provider)  │  │  (Token     │  │  (Re-scan   │  │  (Safety  │ │   │
│  │  │             │  │   Savings)  │  │   fixed)    │  │   Check)  │ │   │
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘  └───────────┘ │   │
│  │         │                                                           │   │
│  │         ▼                                                           │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  LLM Providers (Fallback Chain)                              │   │   │
│  │  │  1. Gemini 2.0 Flash  →  2. Gemini 1.5  →  3. Groq         │   │   │
│  │  │  4. NVIDIA NIM  →  5. OpenRouter  →  6. HuggingFace        │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼──────────────────────────────────────┐   │
│  │                      GIT OPERATIONS                                  │   │
│  │                                                                      │   │
│  │  Clone → Branch → Commit → Push → Pull Request (with inline review) │   │
│  │  Fork (if no push access) → Migration (breaking changes)            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      DATA & STORAGE                                  │   │
│  │                                                                      │   │
│  │  SQLite (encrypted credentials, scan history, baselines, rules)      │   │
│  │  Fernet AES-128 encryption at rest for all secrets                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL SERVICES                                     │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  GitHub  │  │  OSV.dev │  │  PyPI    │  │  npm     │  │  Maven   │    │
│  │  API     │  │  (CVE DB)│  │  Registry│  │  Registry│  │  Central │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Leadership Presentation Diagram

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              AI VULNERABILITY REMEDIATOR — HOW IT WORKS                       ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   DEVELOPER                    PLATFORM                      OUTCOME         ║
║   ─────────                    ────────                      ───────         ║
║                                                                              ║
║   ┌─────────┐     ┌──────────────────────────────┐     ┌──────────────┐    ║
║   │  Paste  │────▶│  1. SCAN                      │────▶│  Findings    │    ║
║   │  GitHub │     │     • Code vulnerabilities    │     │  Report      │    ║
║   │  URL    │     │     • Dependency CVEs         │     │  (PDF/SARIF) │    ║
║   └─────────┘     │     • Leaked secrets          │     └──────────────┘    ║
║                    │     • Code quality issues     │                          ║
║                    └──────────────┬───────────────┘                          ║
║                                   │                                          ║
║                                   ▼                                          ║
║                    ┌──────────────────────────────┐     ┌──────────────┐    ║
║                    │  2. FIX (AI-Powered)          │────▶│  Pull        │    ║
║                    │     • Multi-LLM generation    │     │  Request     │    ║
║                    │     • Confidence scoring      │     │  with fixes  │    ║
║                    │     • Syntax validation       │     │  + review    │    ║
║                    │     • Secret safety check     │     │  comments    │    ║
║                    └──────────────┬───────────────┘     └──────────────┘    ║
║                                   │                                          ║
║                                   ▼                                          ║
║                    ┌──────────────────────────────┐     ┌──────────────┐    ║
║                    │  3. COMPLY                    │────▶│  Compliance  │    ║
║                    │     • OWASP Top 10 mapping    │     │  Dashboard   │    ║
║                    │     • CWE classification      │     │  (Audit-     │    ║
║                    │     • PCI-DSS requirements    │     │   ready)     │    ║
║                    └──────────────────────────────┘     └──────────────┘    ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   KEY CAPABILITIES                                                           ║
║   ────────────────                                                           ║
║                                                                              ║
║   ✅ SAST Scanning (1000+ rules, 12+ languages)                             ║
║   ✅ Dependency CVE Detection (Python, Java, Node, .NET, Go, Rust, Ruby)    ║
║   ✅ Secret & Credential Detection (API keys, tokens, passwords)            ║
║   ✅ Code Quality & Technical Debt (SonarQube alternative)                  ║
║   ✅ AI Auto-Fix with Multi-LLM Fallback (Gemini, Groq, NVIDIA, etc.)      ║
║   ✅ Fix Confidence Scoring (re-scans to verify fix works)                  ║
║   ✅ Compliance Mapping (OWASP, CWE, PCI-DSS)                              ║
║   ✅ Multi-Repo Dashboard (Org Health Score)                                ║
║   ✅ Baseline & Suppress (reduce noise, track new-only)                     ║
║   ✅ CI/CD Webhook Integration (auto-scan on push)                          ║
║   ✅ Custom Scan Rules (user-defined patterns)                              ║
║   ✅ Export: PDF Report, SARIF (GitHub/Azure), CSV (JIRA)                   ║
║   ✅ Real-time Progress (WebSocket terminal UI)                             ║
║   ✅ Scheduled Recurring Scans (daily/weekly/monthly)                       ║
║   ✅ Breaking Change Migration (Spring Boot 2→3, JUnit 4→5, etc.)          ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   BUSINESS VALUE                                                             ║
║   ──────────────                                                             ║
║                                                                              ║
║   • Reduces vulnerability remediation time from days → minutes               ║
║   • Replaces 3-4 commercial tools (SonarQube, Snyk, Checkmarx, GitLeaks)   ║
║   • Audit-ready compliance reports generated automatically                   ║
║   • Zero manual fix writing — AI generates production-ready patches          ║
║   • Org-wide visibility with multi-repo health scoring                       ║
║   • Shift-left security: catches issues at push time, not quarterly audits   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Scan Pipeline Flow

```
┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
│ Clone  │───▶│  SAST  │───▶│  Deps  │───▶│Secrets │───▶│Custom  │
│  Repo  │    │Semgrep │    │OSV/pip │    │Detect  │    │ Rules  │
└────────┘    └────────┘    └────────┘    └────────┘    └────────┘
                                                              │
     ┌────────────────────────────────────────────────────────┘
     ▼
┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
│  Best  │───▶│   ML   │───▶│  Code  │───▶│Quality │───▶│Complian│
│Practice│    │Severity│    │Quality │    │  Gate  │    │ce Map  │
└────────┘    └────────┘    └────────┘    └────────┘    └────────┘
                                                              │
     ┌────────────────────────────────────────────────────────┘
     ▼
┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
│  AI    │───▶│Validate│───▶│ Branch │───▶│  Push  │───▶│Create  │
│  Fix   │    │& Check │    │& Commit│    │        │    │   PR   │
└────────┘    └────────┘    └────────┘    └────────┘    └────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- Git
- A GitHub Personal Access Token (with `repo` scope)

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env: set GITHUB_TOKEN, API_SECRET_KEY, and at least one LLM key

# Run
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install

# Configure environment
cp .env.local.example .env.local
# Edit .env.local if backend is not on localhost:8000

# Run
npm run dev
```

### Docker (Both)

```bash
docker-compose up --build
```

Open http://localhost:3000 — the app is ready.

---

## API Reference

Interactive docs available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scan` | POST | Scan + AI fix + create PR |
| `/api/v1/scan-only` | POST | Scan without fixing |
| `/api/v1/scan-multi` | POST | Scan multiple repos |
| `/api/v1/scan-secrets` | POST | Secret detection only |
| `/api/v1/branches` | POST | List repo branches |
| `/api/v1/merge` | POST | Merge a fix PR |
| `/api/v1/compliance` | POST | Compliance mapping |
| `/api/v1/report/pdf` | POST | Generate PDF report |
| `/api/v1/export/sarif` | POST | Export SARIF |
| `/api/v1/export/csv` | POST | Export CSV |
| `/api/v1/rules` | GET/POST | Custom scan rules |
| `/api/v1/schedules` | GET/POST | Scheduled scans |
| `/api/v1/baseline/suppress` | POST | Suppress findings |
| `/api/v1/history` | GET | Scan history |
| `/api/v1/settings/skill` | GET/POST | AI skill prompt |
| `/webhook/github` | POST | GitHub webhook |
| `/ws/scan` | WebSocket | Real-time progress |

---

## Supported Languages

| Language | SAST | Dependencies | Secrets | AI Fix |
|----------|:----:|:------------:|:-------:|:------:|
| Python | ✅ | ✅ (pip-audit, OSV) | ✅ | ✅ |
| Java (Maven) | ✅ | ✅ (OSV) | ✅ | ✅ |
| Java (Gradle) | ✅ | ✅ (OSV) | ✅ | ✅ |
| JavaScript | ✅ | ✅ (npm audit, OSV) | ✅ | ✅ |
| TypeScript | ✅ | ✅ (npm audit, OSV) | ✅ | ✅ |
| C# / .NET | ✅ | ✅ (NuGet, OSV) | ✅ | ✅ |
| Go | ✅ | ✅ (OSV) | ✅ | ✅ |
| Rust | ✅ | ✅ (crates.io, OSV) | ✅ | ✅ |
| Ruby | ✅ | ✅ (RubyGems, OSV) | ✅ | ✅ |
| PHP | ✅ | ✅ (Packagist, OSV) | ✅ | ✅ |
| Kotlin | ✅ | ✅ (via Maven/Gradle) | ✅ | ✅ |
| C/C++ | ✅ | — | ✅ | ✅ |

---

## LLM Providers (Fallback Chain)

The AI fix engine tries providers in order. If one fails (rate limit, timeout), it automatically falls through to the next:

| Priority | Provider | Free Tier | Speed |
|:--------:|----------|-----------|-------|
| 1 | Google Gemini 2.0 Flash | 15 RPM | Fast |
| 2 | Google Gemini 1.5 Flash | 15 RPM | Fast |
| 3 | Groq (Llama 3.1) | 30 RPM, 14400/day | Very Fast |
| 4 | NVIDIA NIM | Free tier | Fast |
| 5 | OpenRouter | Free models | Medium |
| 6 | HuggingFace (Qwen 2.5) | Free inference | Slow |

Configure via Settings page or `.env` file. At least one key is needed for AI fixes.

---

## Project Structure

```
ai-vuln-remediator/
├── backend/
│   ├── app/
│   │   ├── api/           # REST + WebSocket + Webhook endpoints
│   │   ├── gitops/        # Clone, branch, commit, push, PR, fork, merge
│   │   ├── llm/           # LLM router, analyzer, context extractor, skills
│   │   ├── ml/            # Secret detector, severity predictor, compliance, diff
│   │   ├── parsers/       # Semgrep output parser, file reader
│   │   ├── patchers/      # File patcher (applies fixes)
│   │   ├── reports/       # PDF, SARIF, CSV generators
│   │   ├── scanners/      # Semgrep, dependency, code quality, best practices, custom rules
│   │   ├── validators/    # Fix confidence, project validation
│   │   ├── workflow/      # Remediation orchestrator, migration handler
│   │   ├── main.py        # FastAPI app entry point
│   │   ├── middleware.py  # Auth, rate limit, request ID, timing
│   │   ├── store.py       # SQLite + encrypted credential store
│   │   ├── baseline.py    # Suppress/baseline management
│   │   └── scheduler.py   # Recurring scan scheduler
│   ├── skills/            # LLM skill prompts (editable from UI)
│   ├── data/              # SQLite DB, custom rules
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── app/               # Next.js pages (scanner, dashboard, settings, about)
│   ├── components/        # UI components (shadcn/ui + custom)
│   ├── lib/               # Utilities
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Security Features

- **API Key Authentication** — All endpoints protected via `X-API-Key` header
- **Rate Limiting** — Configurable per-IP rate limits
- **Encrypted Credential Store** — AES-128 Fernet encryption at rest
- **Secret Safety Check** — AI-generated fixes are scanned for accidentally introduced secrets
- **Constant-time Auth Comparison** — Prevents timing attacks
- **Request ID Tracing** — Every request gets a unique ID for debugging
- **Guaranteed Repo Cleanup** — Cloned repos are always deleted (atexit + periodic sweep)
- **No Secrets in Responses** — Credentials are masked in all API responses

---

## Environment Variables

| Variable | Required | Description |
|----------|:--------:|-------------|
| `GITHUB_TOKEN` | Yes (for fix) | GitHub PAT with `repo` scope |
| `API_SECRET_KEY` | No | API key for authentication (empty = auth disabled) |
| `GEMINI_API_KEY` | Recommended | Google Gemini API key |
| `GROQ_API_KEY` | Optional | Groq API key |
| `NVIDIA_API_KEY` | Optional | NVIDIA NIM API key |
| `OPENROUTER_API_KEY` | Optional | OpenRouter API key |
| `HUGGINGFACE_API_KEY` | Optional | HuggingFace API key |
| `DEFAULT_LLM_PROVIDER` | Optional | Preferred LLM (gemini, groq, nvidia, etc.) |
| `WEBHOOK_SECRET` | Optional | GitHub webhook signature secret |
| `ENCRYPTION_SECRET` | Optional | Custom encryption key (default: machine-derived) |
| `CORS_ORIGINS` | Optional | Allowed CORS origins (default: localhost:3000) |
| `RATE_LIMIT_MAX_REQUESTS` | Optional | Max requests per window (default: 30) |

---

## Version

**v2.2.0** — Enterprise AI Security Platform

---

## License

Proprietary — All rights reserved.
