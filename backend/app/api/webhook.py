"""
GitHub Webhook Integration.

Receives push events from GitHub and triggers automatic scans.
Posts scan results back as commit status checks.

Setup:
1. In your GitHub repo → Settings → Webhooks → Add webhook
2. Payload URL: https://your-server.com/webhook/github
3. Content type: application/json
4. Secret: (set WEBHOOK_SECRET in .env)
5. Events: Push events
"""

import hmac
import hashlib
import os
import logging
import threading
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter()


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature (HMAC-SHA256)."""
    if not secret:
        return True  # No secret configured, skip verification

    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def _run_webhook_scan(repo_url: str, commit_sha: str, repo_full_name: str):
    """Run scan in background thread and post status to GitHub."""
    try:
        from app.gitops.clone import clone_repo, cleanup_repo
        from app.scanners.multi_scanner import run_all_scanners
        from app.validators.validate import detect_project_language, check_sdk_availability
        from app.ml.compliance import map_compliance
        from app.baseline import filter_suppressed, get_new_findings
        from app.store import save_scan_history

        # Post pending status
        _post_commit_status(repo_full_name, commit_sha, "pending", "Scan in progress...")

        repo_path = clone_repo(repo_url)
        try:
            project_info = detect_project_language(repo_path)
            scan_result = run_all_scanners(repo_path)

            findings = scan_result["findings"]
            total = scan_result["summary"]["total"]

            # Filter suppressed
            filtered = filter_suppressed(findings)
            active_count = filtered["active_count"]

            # Check against baseline
            baseline_info = get_new_findings(repo_url, filtered["active_findings"])
            new_count = baseline_info.get("new_count", active_count)

            # Determine status
            critical_high = sum(
                1 for f in filtered["active_findings"]
                if f.get("severity", "").upper() in ("CRITICAL", "HIGH")
            )

            if critical_high > 0:
                state = "failure"
                description = f"{critical_high} critical/high vulnerabilities found"
            elif new_count > 0:
                state = "failure"
                description = f"{new_count} new vulnerabilities since baseline"
            else:
                state = "success"
                description = f"No new vulnerabilities ({total} total, {filtered['suppressed_count']} suppressed)"

            # Post result status
            _post_commit_status(repo_full_name, commit_sha, state, description)

            # Save to history
            result = {
                "status": "success",
                "repo": repo_url,
                "total_findings": total,
                "active_findings": active_count,
                "new_findings": new_count,
                "scan_summary": scan_result["summary"],
                "triggered_by": "webhook",
                "commit": commit_sha,
            }
            save_scan_history(repo_url, "webhook", result)

            logger.info(f"Webhook scan complete for {repo_full_name}@{commit_sha[:7]}: {state}")

        finally:
            cleanup_repo(repo_path)

    except Exception as e:
        logger.error(f"Webhook scan failed: {e}")
        _post_commit_status(repo_full_name, commit_sha, "error", f"Scan failed: {str(e)[:100]}")


def _post_commit_status(repo_name: str, sha: str, state: str, description: str):
    """Post a commit status check to GitHub."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("No GITHUB_TOKEN — cannot post commit status")
        return

    try:
        from github import Github
        g = Github(token)
        repo = g.get_repo(repo_name)
        repo.get_commit(sha).create_status(
            state=state,
            description=description[:140],
            context="AI Vulnerability Remediator",
        )
        logger.info(f"Posted status '{state}' to {repo_name}@{sha[:7]}")
    except Exception as e:
        logger.error(f"Failed to post commit status: {e}")


@router.post("/webhook/github", tags=["Webhook"])
async def github_webhook(request: Request):
    """
    GitHub webhook endpoint.
    Receives push events and triggers automatic scans.
    Posts results as commit status checks.
    """
    # Verify signature
    secret = os.getenv("WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()

    if secret and not _verify_signature(body, signature, secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse event
    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return {"status": "pong"}

    if event != "push":
        return {"status": "ignored", "event": event}

    import json
    payload = json.loads(body)

    repo_full_name = payload.get("repository", {}).get("full_name", "")
    repo_url = payload.get("repository", {}).get("clone_url", "")
    commit_sha = payload.get("after", "")
    ref = payload.get("ref", "")

    if not repo_url or not commit_sha:
        return {"status": "ignored", "reason": "missing repo or commit info"}

    # Only scan main/master branch pushes
    if ref not in ("refs/heads/main", "refs/heads/master"):
        return {"status": "ignored", "reason": f"non-default branch: {ref}"}

    logger.info(f"Webhook received: push to {repo_full_name}@{commit_sha[:7]}")

    # Run scan in background
    thread = threading.Thread(
        target=_run_webhook_scan,
        args=(repo_url, commit_sha, repo_full_name),
        daemon=True,
    )
    thread.start()

    return {
        "status": "accepted",
        "repo": repo_full_name,
        "commit": commit_sha[:7],
        "message": "Scan triggered in background",
    }
