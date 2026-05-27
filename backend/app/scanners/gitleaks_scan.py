"""
Gitleaks Integration — Secret Detection Scanner.

Gitleaks is purpose-built for finding secrets in code:
- 150+ regex patterns for API keys, tokens, passwords
- Low false-positive rate (better than custom regex)
- Supports .gitleaksignore for suppression
- Scans git history (optional)

Install: brew install gitleaks  OR  https://github.com/gitleaks/gitleaks/releases

Falls back to built-in regex scanner if Gitleaks is not installed.
"""

import json
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def is_gitleaks_available() -> bool:
    """Check if Gitleaks is installed."""
    return shutil.which("gitleaks") is not None


def run_gitleaks_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run Gitleaks on the repository.
    Returns findings in the standard format.
    Falls back gracefully if Gitleaks is not installed.
    """
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        logger.debug("Gitleaks not installed — using built-in secret detector")
        return []

    logger.info(f"Running Gitleaks scan on: {repo_path}")
    findings = []

    try:
        # Use detect mode (scans files, not git history)
        report_path = Path(repo_path) / ".gitleaks-report.json"

        cmd = [
            gitleaks_bin, "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-git",  # Scan files directly, not git history
            "--exit-code", "0",  # Don't fail on findings
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if not report_path.exists():
            return []

        report_content = report_path.read_text(encoding="utf-8")
        report_path.unlink(missing_ok=True)  # Cleanup

        if not report_content.strip() or report_content.strip() == "null":
            return []

        leaks = json.loads(report_content)
        if not isinstance(leaks, list):
            return []

        for leak in leaks:
            file_path = leak.get("File", "")
            # Make path relative to repo
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            rule_id = leak.get("RuleID", "unknown")
            description = leak.get("Description", "Secret detected")
            secret = leak.get("Secret", "")
            line_num = leak.get("StartLine", 1)

            # Mask the secret
            masked = _mask_secret(secret)

            findings.append({
                "path": file_path,
                "line": line_num,
                "end_line": leak.get("EndLine", line_num),
                "rule_id": f"gitleaks-{rule_id}",
                "message": f"{description}. Value: {masked}",
                "severity": "HIGH" if "private" in rule_id.lower() or "key" in rule_id.lower() else "HIGH",
                "metadata": {
                    "scanner": "gitleaks",
                    "category": "secret",
                    "secret_type": description,
                    "rule_id": rule_id,
                    "entropy": leak.get("Entropy", 0),
                },
            })

        logger.info(f"Gitleaks found {len(findings)} secrets")
        return findings

    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks scan timed out")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gitleaks output: {e}")
        return []
    except Exception as e:
        logger.error(f"Gitleaks scan failed: {e}")
        return []


def _mask_secret(value: str) -> str:
    """Mask a secret value for safe display."""
    if not value or len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * min(len(value) - 8, 20)}{value[-4:]}"
