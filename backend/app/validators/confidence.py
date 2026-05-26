"""
Fix Confidence Score — Verifies AI-generated fixes actually resolve vulnerabilities.

After the AI generates a fix:
1. Writes the fixed code to a temp file
2. Re-runs the scanner on just that file
3. Checks if the original findings are gone
4. Returns a confidence percentage

This builds trust in the AI fixes before creating a PR.
"""

import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def calculate_fix_confidence(
    original_code: str,
    fixed_code: str,
    original_findings: List[Dict[str, Any]],
    file_path: str,
) -> Dict[str, Any]:
    """
    Calculate confidence that the AI fix resolves the vulnerabilities.

    Returns:
        {
            "confidence_percentage": 85.0,
            "findings_before": 10,
            "findings_after": 2,
            "resolved": [...],
            "remaining": [...],
            "rating": "HIGH"
        }
    """
    if not fixed_code or not fixed_code.strip():
        return {
            "confidence_percentage": 0,
            "findings_before": len(original_findings),
            "findings_after": len(original_findings),
            "resolved": [],
            "remaining": original_findings,
            "rating": "NONE",
            "error": "Empty fix generated",
        }

    # Create a temp directory with the fixed file
    temp_dir = tempfile.mkdtemp(prefix="confidence_check_")

    try:
        # Write fixed code to temp location
        fixed_file = Path(temp_dir) / file_path
        fixed_file.parent.mkdir(parents=True, exist_ok=True)
        fixed_file.write_text(fixed_code, encoding="utf-8")

        # Re-scan the fixed file
        after_findings = _scan_single_file(temp_dir, file_path)

        # Compare: which original findings are now gone?
        original_rule_ids = set(f.get("rule_id", "") for f in original_findings)
        after_rule_ids = set(f.get("rule_id", "") for f in after_findings)

        resolved_ids = original_rule_ids - after_rule_ids
        remaining_ids = original_rule_ids & after_rule_ids

        resolved = [f for f in original_findings if f.get("rule_id") in resolved_ids]
        remaining = [f for f in original_findings if f.get("rule_id") in remaining_ids]

        # Calculate confidence
        total = len(original_findings)
        fixed_count = len(resolved)
        confidence = (fixed_count / total * 100) if total > 0 else 100

        return {
            "confidence_percentage": round(confidence, 1),
            "findings_before": total,
            "findings_after": len(after_findings),
            "findings_resolved": fixed_count,
            "resolved": [{"rule_id": f.get("rule_id"), "message": f.get("message", "")[:100]} for f in resolved],
            "remaining": [{"rule_id": f.get("rule_id"), "message": f.get("message", "")[:100]} for f in remaining],
            "rating": _confidence_rating(confidence),
        }

    except Exception as e:
        logger.error(f"Confidence check failed: {e}")
        return {
            "confidence_percentage": -1,
            "error": str(e),
            "rating": "UNKNOWN",
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _scan_single_file(repo_path: str, file_path: str) -> List[Dict[str, Any]]:
    """Run semgrep on a single file and return findings."""
    from app.scanners.semgrep_scan import (
        _find_semgrep_binary,
        _get_subprocess_env,
        _run_semgrep_cmd,
    )

    semgrep_bin = _find_semgrep_binary()
    if not semgrep_bin:
        return []

    env = _get_subprocess_env()
    target = str(Path(repo_path) / file_path)

    # Use language-specific config for speed
    ext = Path(file_path).suffix.lower()
    config = "p/python" if ext == ".py" else "p/javascript" if ext in (".js", ".ts") else "p/java" if ext == ".java" else "auto"

    cmd = [
        semgrep_bin, "scan",
        "--config", config,
        "--json",
        "--no-git-ignore",
        target,
    ]

    output = _run_semgrep_cmd(cmd, env, "confidence re-scan")
    if not output:
        return []

    findings = []
    for item in output.get("results", []):
        findings.append({
            "rule_id": item.get("check_id", "unknown"),
            "message": item.get("extra", {}).get("message", ""),
            "severity": item.get("extra", {}).get("severity", "WARNING"),
            "line": item.get("start", {}).get("line"),
        })

    return findings


def _confidence_rating(percentage: float) -> str:
    """Rate the fix confidence."""
    if percentage >= 90:
        return "HIGH"
    elif percentage >= 70:
        return "MEDIUM"
    elif percentage >= 50:
        return "LOW"
    return "VERY_LOW"
