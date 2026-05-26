import os
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from app.reports.pdf_report import generate_pdf_report
from app.validators.validate import (
    detect_environment,
    detect_project_language,
    check_sdk_availability,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanRequest(BaseModel):
    github_url: str


class TokenRequest(BaseModel):
    token: str


class TokenTestRequest(BaseModel):
    token: str
    github_url: str = ""


@router.post("/scan", tags=["Scanning"])
async def scan_repo(req: ScanRequest):
    """Run full remediation pipeline: multi-scan, fix, and create PR."""
    from app.workflow.remediation import run_remediation

    logger.info(f"Received scan request for: {req.github_url}")

    if not req.github_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only GitHub HTTPS URLs are supported"
        )

    result = run_remediation(req.github_url)
    return result


@router.post("/scan-only", tags=["Scanning"])
async def scan_only(req: ScanRequest):
    """
    Scan a repository for vulnerabilities without applying fixes.
    Runs both SAST (Semgrep) and Dependency scanning.
    Also detects project language and checks SDK availability.
    """
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.scanners.multi_scanner import run_all_scanners

    logger.info(f"Received scan-only request for: {req.github_url}")

    repo_path = None
    try:
        repo_path = clone_repo(req.github_url)

        # Detect project info
        project_info = detect_project_language(repo_path)
        sdk_check = check_sdk_availability(project_info)

        # Run scanners
        scan_result = run_all_scanners(repo_path)

        response = {
            "status": "success",
            "repo": req.github_url,
            "total_findings": scan_result["summary"]["total"],
            "scan_summary": scan_result["summary"],
            "findings": scan_result["findings"],
            "errors": scan_result["errors"],
            "project_info": project_info,
            "sdk_status": sdk_check,
            "code_quality": scan_result.get("code_quality", {}),
        }

        # Add compliance mapping
        try:
            from app.ml.compliance import map_compliance
            response["compliance"] = map_compliance(scan_result["findings"])
        except Exception:
            pass

        # Filter suppressed findings
        try:
            from app.baseline import filter_suppressed, get_new_findings
            filtered = filter_suppressed(scan_result["findings"])
            response["suppressed_count"] = filtered["suppressed_count"]
            response["active_findings_count"] = filtered["active_count"]

            # Compare to baseline
            baseline = get_new_findings(req.github_url, filtered["active_findings"])
            if baseline.get("has_baseline"):
                response["new_since_baseline"] = baseline["new_count"]
                response["baseline_count"] = baseline["baseline_count"]
        except Exception:
            pass

        # Save to history
        try:
            from app.store import save_scan_history
            save_scan_history(req.github_url, "scan-only", response)
        except Exception:
            pass  # Don't fail the scan if history save fails

        return response

    except Exception as e:
        logger.error(f"Scan-only failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if repo_path:
            cleanup_repo(repo_path)


class ReportRequest(BaseModel):
    scan_data: dict


@router.post("/report/pdf", tags=["Reports & Export"])
async def generate_pdf(req: ReportRequest):
    """
    Generate a PDF report from scan results.
    Accepts the scan result JSON and returns a downloadable PDF.
    """
    try:
        pdf_bytes = generate_pdf_report(req.scan_data)
        return Response(
            content=bytes(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=vulnerability_report.pdf"
            },
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


@router.get("/environment", tags=["System"])
async def get_environment():
    """
    Check which SDKs and tools are available on the system.
    Useful for debugging scan/fix issues.
    """
    from app.llm.llm_router import router as llm_router

    env = detect_environment()
    return {
        "status": "ok",
        "environment": env,
        "llm_providers": llm_router.get_status(),
        "summary": {
            "python": bool(env.get("python")),
            "java_jdk": bool(env.get("java") and env.get("javac")),
            "maven": bool(env.get("maven")),
            "gradle": bool(env.get("gradle")),
            "node": bool(env.get("node")),
            "npm": bool(env.get("npm")),
        }
    }


@router.post("/settings/token/test")
async def test_token(req: TokenTestRequest):
    """
    Test a GitHub token for required permissions.
    Checks: authentication, repo scope, and optionally push access to a specific repo.
    """
    from github import Github

    token = req.token.strip()

    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    try:
        g = Github(token)
        user = g.get_user()
        username = user.login
        scopes = g.oauth_scopes or []

        result = {
            "valid": True,
            "username": username,
            "scopes": scopes,
            "has_repo_scope": "repo" in scopes,
            "has_workflow_scope": "workflow" in scopes,
            "permissions_ok": "repo" in scopes,
            "repo_access": None,
        }

        # Check if 'repo' scope is present (needed for push + PR)
        if "repo" not in scopes:
            result["permissions_ok"] = False
            result["error"] = (
                "Token is missing the 'repo' scope. "
                "This is required to push branches and create Pull Requests. "
                "Generate a new token with the 'repo' scope at: "
                "https://github.com/settings/tokens"
            )

        # If a repo URL is provided, check push access
        if req.github_url and result["permissions_ok"]:
            repo_name = req.github_url.replace(
                "https://github.com/", ""
            ).replace(".git", "")

            try:
                repo = g.get_repo(repo_name)
                can_push = repo.permissions.push if repo.permissions else False
                result["repo_access"] = {
                    "repo": repo_name,
                    "can_push": can_push,
                    "default_branch": repo.default_branch,
                    "is_fork": repo.fork,
                    "owner": repo.owner.login,
                    "note": (
                        "You have push access."
                        if can_push
                        else f"No push access. The app will fork to {username}/{repo.name} and create a cross-repo PR."
                    ),
                }
            except Exception as e:
                result["repo_access"] = {
                    "repo": repo_name,
                    "error": str(e),
                }

        return result

    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "Bad credentials" in error_msg:
            return {
                "valid": False,
                "error": "Invalid token. Authentication failed (401). Please check your token.",
            }
        return {
            "valid": False,
            "error": f"Token validation failed: {error_msg}",
        }


@router.post("/settings/token/save")
async def save_token(req: TokenRequest):
    """Save the GitHub token securely (encrypted in SQLite)."""
    from app.store import save_credential

    token = req.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    success = save_credential("GITHUB_TOKEN", token)
    if success:
        logger.info("GitHub token saved to secure store")
        return {"status": "saved", "message": "Token saved securely (encrypted)"}
    else:
        raise HTTPException(status_code=500, detail="Failed to save token")


@router.get("/settings/token/status")
async def token_status():
    """
    Check if a GitHub token is currently configured.
    Does NOT return the token value.
    """
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("GITHUB_TOKEN", "")

    if not token:
        return {"configured": False, "message": "No GitHub token configured"}

    # Mask the token
    masked = f"{token[:4]}{'*' * (len(token) - 8)}{token[-4:]}" if len(token) > 8 else "****"

    return {
        "configured": True,
        "masked_token": masked,
        "token_type": (
            "Fine-grained"
            if token.startswith("github_pat_")
            else "Classic"
            if token.startswith("ghp_")
            else "Unknown"
        ),
    }


class LLMKeysRequest(BaseModel):
    keys: dict


@router.get("/settings/llm/status", tags=["Settings"])
async def get_llm_status():
    """Get LLM provider status and current default model."""
    from app.llm.llm_router import router as llm_router

    default_provider = os.getenv("DEFAULT_LLM_PROVIDER", "")
    status = llm_router.get_status()

    return {
        "default_provider": default_provider or "auto",
        "providers": status,
        "provider_order": [p.name for p in llm_router.providers],
    }


@router.post("/settings/llm/save", tags=["Settings"])
async def save_llm_keys(req: LLMKeysRequest):
    """Save LLM provider API keys securely (encrypted in SQLite)."""
    from app.store import save_credential

    allowed_keys = {"GEMINI_API_KEY", "NVIDIA_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "HUGGINGFACE_API_KEY", "DEFAULT_LLM_PROVIDER"}
    keys_to_save = {k: v for k, v in req.keys.items() if k in allowed_keys and v}

    if not keys_to_save:
        raise HTTPException(status_code=400, detail="No valid keys provided")

    saved = []
    for key_name, value in keys_to_save.items():
        if save_credential(key_name, value.strip()):
            saved.append(key_name)

    if not saved:
        raise HTTPException(status_code=500, detail="Failed to save keys")

    logger.info(f"Saved LLM keys: {saved}")
    return {
        "status": "saved",
        "keys_saved": saved,
        "message": f"Saved {len(saved)} key(s) securely. Active immediately.",
    }


# =============================================================================
# SCAN HISTORY ENDPOINTS
# =============================================================================

@router.get("/history")
async def get_history():
    """Get scan history (persisted in SQLite)."""
    from app.store import get_scan_history
    history = get_scan_history(limit=50)
    return {"history": history, "total": len(history)}


@router.get("/history/{history_id}")
async def get_history_detail(history_id: int):
    """Get full scan result from history."""
    from app.store import get_scan_history_detail
    detail = get_scan_history_detail(history_id)
    if not detail:
        raise HTTPException(status_code=404, detail="History entry not found")
    return detail


@router.delete("/history")
async def clear_history():
    """Clear all scan history."""
    from app.store import clear_scan_history
    count = clear_scan_history()
    return {"status": "cleared", "deleted": count}


@router.delete("/history/{history_id}")
async def delete_history_entry(history_id: int):
    """Delete a single history entry."""
    from app.store import _get_db
    try:
        conn = _get_db()
        cursor = conn.execute("DELETE FROM scan_history WHERE id = ?", (history_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Entry not found")
        return {"status": "deleted", "id": history_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# EXPORT ENDPOINTS (SARIF, CSV)
# =============================================================================

class ExportRequest(BaseModel):
    scan_data: dict


@router.post("/export/sarif", tags=["Reports & Export"])
async def export_sarif(req: ExportRequest):
    """Export scan results in SARIF 2.1.0 format (GitHub/Azure DevOps compatible)."""
    from app.reports.sarif_export import generate_sarif

    try:
        sarif_json = generate_sarif(req.scan_data)
        return Response(
            content=sarif_json,
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=scan-results.sarif"
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SARIF export failed: {e}")


@router.post("/export/csv", tags=["Reports & Export"])
async def export_csv(req: ExportRequest):
    """Export scan results as CSV (Excel/JIRA compatible)."""
    from app.reports.csv_export import generate_csv

    try:
        csv_content = generate_csv(req.scan_data)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=vulnerability-report.csv"
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV export failed: {e}")


# =============================================================================
# CUSTOM RULES ENDPOINTS
# =============================================================================

class CustomRuleRequest(BaseModel):
    name: str
    description: str = ""
    language: str = "python"
    severity: str = "WARNING"
    pattern: str
    message: str


@router.get("/rules", tags=["Custom Rules"])
async def list_rules():
    """List all custom scan rules."""
    from app.scanners.custom_rules import get_custom_rules
    rules = get_custom_rules()
    return {"rules": rules, "total": len(rules)}


@router.post("/rules", tags=["Custom Rules"])
async def create_rule(req: CustomRuleRequest):
    """Create a new custom scan rule."""
    from app.scanners.custom_rules import save_custom_rule

    if not req.pattern.strip():
        raise HTTPException(status_code=400, detail="Pattern is required")

    rule_id = save_custom_rule(req.model_dump())
    if rule_id < 0:
        raise HTTPException(status_code=500, detail="Failed to save rule")

    return {"status": "created", "id": rule_id}


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int):
    """Delete a custom rule."""
    from app.scanners.custom_rules import delete_custom_rule

    if delete_custom_rule(rule_id):
        return {"status": "deleted", "id": rule_id}
    raise HTTPException(status_code=404, detail="Rule not found")


class ToggleRequest(BaseModel):
    enabled: bool


@router.patch("/rules/{rule_id}")
async def toggle_rule(rule_id: int, req: ToggleRequest):
    """Enable or disable a custom rule."""
    from app.scanners.custom_rules import toggle_custom_rule

    if toggle_custom_rule(rule_id, req.enabled):
        return {"status": "updated", "id": rule_id, "enabled": req.enabled}
    raise HTTPException(status_code=404, detail="Rule not found")


# =============================================================================
# SCHEDULED SCANS ENDPOINTS
# =============================================================================

class ScheduleRequest(BaseModel):
    url: str
    frequency: str = "weekly"
    mode: str = "scan-only"


@router.get("/schedules")
async def list_schedules():
    """List all scan schedules."""
    from app.scheduler import get_schedules
    schedules = get_schedules()
    return {"schedules": schedules, "total": len(schedules)}


@router.post("/schedules")
async def create_schedule(req: ScheduleRequest):
    """Create a new recurring scan schedule."""
    from app.scheduler import add_schedule

    if not req.url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="Only GitHub URLs supported")

    try:
        schedule_id = add_schedule(req.url, req.frequency, req.mode)
        if schedule_id < 0:
            raise HTTPException(status_code=500, detail="Failed to create schedule")
        return {"status": "created", "id": schedule_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/schedules/{schedule_id}")
async def delete_schedule_endpoint(schedule_id: int):
    """Delete a scan schedule."""
    from app.scheduler import delete_schedule

    if delete_schedule(schedule_id):
        return {"status": "deleted", "id": schedule_id}
    raise HTTPException(status_code=404, detail="Schedule not found")


@router.post("/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int):
    """Manually trigger a scheduled scan."""
    from app.scheduler import run_scheduled_scan
    result = run_scheduled_scan(schedule_id)
    return result


@router.get("/trends/{repo_url:path}")
async def get_trends(repo_url: str):
    """Get scan trend data for a repository (findings over time)."""
    from app.scheduler import get_scan_trends

    full_url = f"https://github.com/{repo_url}" if not repo_url.startswith("http") else repo_url
    trends = get_scan_trends(full_url)
    return {"url": full_url, "trends": trends, "data_points": len(trends)}


# =============================================================================
# FIX CONFIDENCE ENDPOINT
# =============================================================================

class ConfidenceRequest(BaseModel):
    original_code: str
    fixed_code: str
    file_path: str
    findings: list


@router.post("/confidence")
async def check_fix_confidence(req: ConfidenceRequest):
    """
    Check confidence that an AI fix resolves the vulnerabilities.
    Re-scans the fixed code and compares findings.
    """
    from app.validators.confidence import calculate_fix_confidence

    result = calculate_fix_confidence(
        original_code=req.original_code,
        fixed_code=req.fixed_code,
        original_findings=req.findings,
        file_path=req.file_path,
    )
    return result


# =============================================================================
# DIFF VIEW ENDPOINT
# =============================================================================

class DiffRequest(BaseModel):
    original_code: str
    fixed_code: str
    file_path: str = "file"


@router.post("/diff")
async def generate_code_diff(req: DiffRequest):
    """Generate a unified diff between original and fixed code."""
    from app.ml.diff_generator import generate_diff

    result = generate_diff(req.original_code, req.fixed_code, req.file_path)
    return result


# =============================================================================
# SECRET SCAN ENDPOINT (standalone)
# =============================================================================

@router.post("/scan-secrets", tags=["Scanning"])
async def scan_secrets(req: ScanRequest):
    """Run secret detection on a repository (standalone)."""
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.ml.secret_detector import run_secret_scan

    repo_path = None
    try:
        repo_path = clone_repo(req.github_url)
        findings = run_secret_scan(repo_path)
        return {
            "status": "success",
            "repo": req.github_url,
            "total_secrets": len(findings),
            "findings": findings,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if repo_path:
            cleanup_repo(repo_path)


# =============================================================================
# REPO MANAGEMENT ENDPOINT
# =============================================================================

@router.get("/system/repos", tags=["System"])
async def get_repo_status():
    """Get status of cloned repositories (disk usage, active count)."""
    from app.gitops.clone import get_disk_usage_mb, _get_active_repos, cleanup_stale_repos

    active = _get_active_repos()
    disk_mb = get_disk_usage_mb()

    return {
        "active_repos": len(active),
        "disk_usage_mb": round(disk_mb, 1),
        "max_disk_mb": 2000,
        "usage_percentage": round((disk_mb / 2000) * 100, 1),
    }


@router.post("/system/cleanup", tags=["System"])
async def force_cleanup():
    """Force cleanup of stale repositories."""
    from app.gitops.clone import cleanup_stale_repos, get_disk_usage_mb

    before = get_disk_usage_mb()
    cleanup_stale_repos()
    after = get_disk_usage_mb()

    return {
        "status": "cleaned",
        "freed_mb": round(before - after, 1),
        "current_usage_mb": round(after, 1),
    }


# =============================================================================
# COMPLIANCE MAPPING
# =============================================================================

@router.post("/compliance", tags=["Compliance"])
async def get_compliance_report(req: ExportRequest):
    """Map scan findings to compliance frameworks (OWASP, CWE, PCI-DSS)."""
    from app.ml.compliance import map_compliance

    findings = req.scan_data.get("findings", [])
    compliance = map_compliance(findings)
    return compliance


# =============================================================================
# BASELINE / SUPPRESS FINDINGS
# =============================================================================

class SuppressRequest(BaseModel):
    rule_id: str
    path: str = ""
    reason: str = "accepted_risk"


@router.post("/baseline/suppress", tags=["Baseline"])
async def suppress(req: SuppressRequest):
    """Suppress a finding (mark as accepted risk or false positive)."""
    from app.baseline import suppress_finding

    success = suppress_finding(req.rule_id, req.path or None, req.reason)
    if success:
        return {"status": "suppressed", "rule_id": req.rule_id, "path": req.path or "*"}
    raise HTTPException(status_code=500, detail="Failed to suppress finding")


@router.delete("/baseline/suppress/{rule_id}", tags=["Baseline"])
async def unsuppress(rule_id: str):
    """Remove a suppression."""
    from app.baseline import unsuppress_finding

    unsuppress_finding(rule_id)
    return {"status": "unsuppressed", "rule_id": rule_id}


@router.get("/baseline/suppressions", tags=["Baseline"])
async def list_suppressions():
    """List all suppressed findings."""
    from app.baseline import get_suppressions
    return {"suppressions": get_suppressions()}


class BaselineRequest(BaseModel):
    repo_url: str
    findings: list


@router.post("/baseline/set", tags=["Baseline"])
async def set_scan_baseline(req: BaselineRequest):
    """Set a baseline for a repository. Future scans show only NEW findings."""
    from app.baseline import set_baseline

    count = set_baseline(req.repo_url, req.findings)
    if count >= 0:
        return {"status": "baseline_set", "findings_in_baseline": count}
    raise HTTPException(status_code=500, detail="Failed to set baseline")


@router.post("/baseline/compare", tags=["Baseline"])
async def compare_to_baseline(req: BaselineRequest):
    """Compare findings against the baseline. Returns only new findings."""
    from app.baseline import get_new_findings

    result = get_new_findings(req.repo_url, req.findings)
    return result


# =============================================================================
# MULTI-REPO SCAN
# =============================================================================

class MultiRepoRequest(BaseModel):
    repos: list  # List of GitHub URLs


@router.post("/scan-multi", tags=["Scanning"])
async def scan_multiple_repos(req: MultiRepoRequest):
    """
    Scan multiple repositories and return a portfolio dashboard.
    Shows org-level health score and per-repo breakdown.
    """
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.scanners.multi_scanner import run_all_scanners
    from app.validators.validate import detect_project_language
    from app.ml.compliance import map_compliance
    from app.store import save_scan_history

    if not req.repos or len(req.repos) > 10:
        raise HTTPException(status_code=400, detail="Provide 1-10 repository URLs")

    results = []
    total_findings = 0
    total_critical = 0

    for repo_url in req.repos:
        if not repo_url.startswith("https://github.com/"):
            results.append({"repo": repo_url, "status": "error", "message": "Invalid URL"})
            continue

        repo_path = None
        try:
            repo_path = clone_repo(repo_url)
            project_info = detect_project_language(repo_path)
            scan_result = run_all_scanners(repo_path)

            findings = scan_result["findings"]
            summary = scan_result["summary"]
            critical_high = (
                summary.get("by_severity", {}).get("CRITICAL", 0) +
                summary.get("by_severity", {}).get("HIGH", 0)
            )

            repo_result = {
                "repo": repo_url,
                "status": "success",
                "total_findings": summary["total"],
                "critical_high": critical_high,
                "by_severity": summary.get("by_severity", {}),
                "languages": project_info.get("languages", []),
                "quality_gate": scan_result.get("code_quality", {}).get("quality_gate_details", {}).get("passed"),
            }

            results.append(repo_result)
            total_findings += summary["total"]
            total_critical += critical_high

            # Save each to history
            save_scan_history(repo_url, "multi-scan", repo_result)

        except Exception as e:
            results.append({"repo": repo_url, "status": "error", "message": str(e)[:200]})
        finally:
            if repo_path:
                cleanup_repo(repo_path)

    # Calculate org health score (0-100)
    scanned = [r for r in results if r["status"] == "success"]
    if scanned:
        avg_findings = total_findings / len(scanned)
        health_score = max(0, min(100, round(100 - (total_critical * 10) - (avg_findings * 2))))
    else:
        health_score = 0

    return {
        "status": "success",
        "repos_scanned": len(scanned),
        "repos_failed": len(results) - len(scanned),
        "total_findings": total_findings,
        "total_critical_high": total_critical,
        "org_health_score": health_score,
        "health_rating": "A" if health_score >= 80 else "B" if health_score >= 60 else "C" if health_score >= 40 else "D" if health_score >= 20 else "F",
        "results": results,
    }
