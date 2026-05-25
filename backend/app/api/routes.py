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


@router.post("/scan")
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


@router.post("/scan-only")
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

        return {
            "status": "success",
            "repo": req.github_url,
            "total_findings": scan_result["summary"]["total"],
            "scan_summary": scan_result["summary"],
            "findings": scan_result["findings"],
            "errors": scan_result["errors"],
            "project_info": project_info,
            "sdk_status": sdk_check,
        }

    except Exception as e:
        logger.error(f"Scan-only failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if repo_path:
            cleanup_repo(repo_path)


class ReportRequest(BaseModel):
    scan_data: dict


@router.post("/report/pdf")
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


@router.get("/environment")
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
    """
    Save the GitHub token to the .env file.
    """
    from pathlib import Path

    token = req.token.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    env_path = Path(__file__).parent.parent.parent / ".env"

    try:
        # Read existing .env
        if env_path.exists():
            content = env_path.read_text()
        else:
            content = ""

        # Update or add GITHUB_TOKEN
        lines = content.splitlines()
        updated = False
        new_lines = []

        for line in lines:
            if line.startswith("GITHUB_TOKEN="):
                new_lines.append(f"GITHUB_TOKEN={token}")
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            new_lines.append(f"GITHUB_TOKEN={token}")

        env_path.write_text("\n".join(new_lines) + "\n")

        # Also update the runtime environment
        os.environ["GITHUB_TOKEN"] = token

        logger.info("GitHub token saved to .env")
        return {"status": "saved", "message": "Token saved successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save token: {e}")


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


@router.post("/settings/llm/save")
async def save_llm_keys(req: LLMKeysRequest):
    """
    Save LLM provider API keys to the .env file.
    Accepts: GEMINI_API_KEY, NVIDIA_API_KEY, OPENROUTER_API_KEY
    """
    from pathlib import Path

    allowed_keys = {"GEMINI_API_KEY", "NVIDIA_API_KEY", "OPENROUTER_API_KEY"}
    keys_to_save = {k: v for k, v in req.keys.items() if k in allowed_keys and v}

    if not keys_to_save:
        raise HTTPException(status_code=400, detail="No valid keys provided")

    env_path = Path(__file__).parent.parent.parent / ".env"

    try:
        if env_path.exists():
            content = env_path.read_text()
        else:
            content = ""

        lines = content.splitlines()
        updated_keys = set()
        new_lines = []

        for line in lines:
            key_name = line.split("=")[0].strip() if "=" in line else ""
            if key_name in keys_to_save:
                new_lines.append(f"{key_name}={keys_to_save[key_name]}")
                updated_keys.add(key_name)
            else:
                new_lines.append(line)

        # Add any keys that weren't already in the file
        for key_name, value in keys_to_save.items():
            if key_name not in updated_keys:
                new_lines.append(f"{key_name}={value}")

        env_path.write_text("\n".join(new_lines) + "\n")

        # Update runtime environment
        for key_name, value in keys_to_save.items():
            os.environ[key_name] = value

        logger.info(f"Saved LLM keys: {list(keys_to_save.keys())}")
        return {
            "status": "saved",
            "keys_saved": list(keys_to_save.keys()),
            "message": "Keys saved. Restart backend for full effect.",
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save keys: {e}")
