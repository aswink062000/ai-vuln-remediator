"""
Trivy Integration — Container & Dependency Vulnerability Scanner.

Trivy is a comprehensive security scanner that detects:
- Vulnerabilities in OS packages and language-specific dependencies
- Misconfigurations in IaC (Terraform, Kubernetes, Docker)
- Secrets (as backup to Gitleaks)
- License compliance issues

Install: brew install trivy  OR  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

Falls back to OSV.dev API if Trivy is not installed.
"""

import json
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def is_trivy_available() -> bool:
    """Check if Trivy is installed."""
    return shutil.which("trivy") is not None


def run_trivy_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run Trivy filesystem scan on the repository.
    Returns findings in the standard format.
    Falls back gracefully if Trivy is not installed.
    """
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        logger.debug("Trivy not installed — skipping (using OSV.dev fallback)")
        return []

    logger.info(f"Running Trivy scan on: {repo_path}")
    findings = []

    try:
        cmd = [
            trivy_bin, "fs",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--quiet",
            repo_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode not in (0, 1):  # 1 = vulns found (normal)
            logger.warning(f"Trivy exited with code {result.returncode}: {result.stderr[:200]}")
            return []

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        results = data.get("Results", [])

        for target in results:
            target_name = target.get("Target", "")
            vulns = target.get("Vulnerabilities") or []

            for vuln in vulns:
                severity = vuln.get("Severity", "MEDIUM").upper()
                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                vuln_id = vuln.get("VulnerabilityID", "")
                title = vuln.get("Title", "")
                description = vuln.get("Description", "")

                findings.append({
                    "path": target_name,
                    "line": None,
                    "end_line": None,
                    "rule_id": vuln_id,
                    "message": (
                        f"Vulnerable: {pkg_name}@{installed_ver} — "
                        f"{vuln_id}: {title or description[:200]}"
                    ),
                    "severity": severity,
                    "metadata": {
                        "scanner": "trivy",
                        "category": "dependency",
                        "package": pkg_name,
                        "installed_version": installed_ver,
                        "fix_versions": [fixed_ver] if fixed_ver else [],
                        "cve_id": vuln_id,
                        "title": title,
                    },
                })

        logger.info(f"Trivy found {len(findings)} vulnerabilities")
        return findings

    except subprocess.TimeoutExpired:
        logger.warning("Trivy scan timed out")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Trivy output: {e}")
        return []
    except Exception as e:
        logger.error(f"Trivy scan failed: {e}")
        return []


def run_trivy_config_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run Trivy misconfiguration scan (Dockerfile, Terraform, K8s).
    """
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        return []

    findings = []

    try:
        cmd = [
            trivy_bin, "fs",
            "--format", "json",
            "--scanners", "misconfig",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--quiet",
            repo_path,
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        results = data.get("Results", [])

        for target in results:
            misconfigs = target.get("Misconfigurations") or []
            target_name = target.get("Target", "")

            for mc in misconfigs:
                findings.append({
                    "path": target_name,
                    "line": mc.get("CauseMetadata", {}).get("StartLine"),
                    "end_line": mc.get("CauseMetadata", {}).get("EndLine"),
                    "rule_id": mc.get("ID", ""),
                    "message": mc.get("Message", mc.get("Title", "")),
                    "severity": mc.get("Severity", "MEDIUM").upper(),
                    "metadata": {
                        "scanner": "trivy",
                        "category": "misconfig",
                        "resolution": mc.get("Resolution", ""),
                    },
                })

        logger.info(f"Trivy misconfig: {len(findings)} findings")
        return findings

    except Exception as e:
        logger.debug(f"Trivy misconfig scan skipped: {e}")
        return []
