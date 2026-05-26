"""
Unified multi-scanner orchestrator.

Combines results from:
1. Semgrep (SAST - source code vulnerabilities)
2. Dependency Scanner (CVEs in packages/libraries)
3. Code Quality Scanner (complexity, duplication, smells, tech debt)

Returns a unified findings list with scanner metadata.
"""

import logging
from typing import List, Dict, Any

from app.scanners.semgrep_scan import run_semgrep
from app.scanners.dependency_scan import run_dependency_scan
from app.scanners.code_quality import run_code_quality_scan
from app.parsers.findings import extract_findings, normalize_paths

logger = logging.getLogger(__name__)


def run_all_scanners(repo_path: str) -> Dict[str, Any]:
    """
    Run all applicable scanners and return unified results.
    
    Returns:
        {
            "findings": [...],          # All findings combined
            "summary": {
                "total": int,
                "by_scanner": {...},
                "by_severity": {...},
                "by_category": {...},
            },
            "errors": [...]
        }
    """
    all_findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    # 1. SAST Scan (Semgrep)
    logger.info("=== Running SAST scan (Semgrep) ===")
    try:
        semgrep_result = run_semgrep(repo_path)
        sast_findings = extract_findings(semgrep_result)
        sast_findings = normalize_paths(sast_findings, repo_path)

        # Tag findings with scanner info
        for f in sast_findings:
            f.setdefault("metadata", {})
            f["metadata"]["scanner"] = "semgrep"
            f["metadata"]["category"] = "sast"

        all_findings.extend(sast_findings)
        logger.info(f"SAST scan: {len(sast_findings)} findings")

        # Collect semgrep errors
        semgrep_errors = semgrep_result.get("errors", [])
        if semgrep_errors:
            errors.extend([f"semgrep: {e}" for e in semgrep_errors[:3]])

    except Exception as e:
        logger.error(f"SAST scan failed: {e}")
        errors.append(f"SAST scan error: {str(e)}")

    # 2. Dependency Scan
    logger.info("=== Running Dependency scan ===")
    try:
        dep_findings = run_dependency_scan(repo_path)
        all_findings.extend(dep_findings)
        logger.info(f"Dependency scan: {len(dep_findings)} findings")
    except Exception as e:
        logger.error(f"Dependency scan failed: {e}")
        errors.append(f"Dependency scan error: {str(e)}")

    # 3. Secret Detection
    logger.info("=== Running Secret Detection ===")
    try:
        from app.ml.secret_detector import run_secret_scan
        secret_findings = run_secret_scan(repo_path)
        all_findings.extend(secret_findings)
        logger.info(f"Secret detection: {len(secret_findings)} findings")
    except Exception as e:
        logger.error(f"Secret detection failed: {e}")
        errors.append(f"Secret detection error: {str(e)}")

    # 4. Custom Rules (if any configured)
    try:
        from app.scanners.custom_rules import run_custom_rules
        custom_findings = run_custom_rules(repo_path)
        if custom_findings:
            for f in custom_findings:
                f.setdefault("metadata", {})
                f["metadata"]["scanner"] = "custom-rules"
                f["metadata"]["category"] = "custom"
            all_findings.extend(custom_findings)
            logger.info(f"Custom rules: {len(custom_findings)} findings")
    except Exception as e:
        logger.debug(f"Custom rules skipped: {e}")

    # 5. Best Practices & Deprecated Dependencies
    logger.info("=== Running Best Practices scan ===")
    try:
        from app.scanners.best_practices import run_best_practices_scan
        bp_findings = run_best_practices_scan(repo_path)
        all_findings.extend(bp_findings)
        logger.info(f"Best practices: {len(bp_findings)} findings")
    except Exception as e:
        logger.error(f"Best practices scan failed: {e}")
        errors.append(f"Best practices scan error: {str(e)}")

    # 6. Deduplicate findings
    all_findings = _deduplicate(all_findings)

    # 6. ML Severity Prediction (adjust priorities based on context)
    logger.info("=== Running ML Severity Analysis ===")
    try:
        from app.ml.severity_predictor import predict_severity
        all_findings = predict_severity(all_findings, repo_path)
        logger.info("Severity prediction applied")
    except Exception as e:
        logger.debug(f"Severity prediction skipped: {e}")

    # 7. Code Quality Scan
    logger.info("=== Running Code Quality scan ===")
    code_quality = {}
    try:
        code_quality = run_code_quality_scan(repo_path)
        logger.info(
            f"Code quality: gate={'PASSED' if code_quality.get('quality_gate_details', {}).get('passed') else 'FAILED'}"
        )
    except Exception as e:
        logger.error(f"Code quality scan failed: {e}")
        errors.append(f"Code quality scan error: {str(e)}")

    # 5. Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "MEDIUM").upper(), 3))

    # 5. Build summary
    summary = _build_summary(all_findings)

    logger.info(
        f"=== Scan complete: {summary['total']} total findings "
        f"({summary['by_category']}) ==="
    )

    return {
        "findings": all_findings,
        "summary": summary,
        "errors": errors,
        "code_quality": code_quality,
    }


def _deduplicate(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings (same CVE/rule in same file)."""
    seen = set()
    unique = []

    for f in findings:
        key = (
            f.get("rule_id", ""),
            f.get("path", ""),
            f.get("line"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if len(findings) != len(unique):
        logger.info(f"Deduplicated: {len(findings)} -> {len(unique)} findings")

    return unique


def _build_summary(findings: List[Dict]) -> Dict:
    """Build a summary of scan results."""
    by_scanner = {}
    by_severity = {}
    by_category = {}

    for f in findings:
        scanner = f.get("metadata", {}).get("scanner", "unknown")
        severity = f.get("severity", "MEDIUM").upper()
        category = f.get("metadata", {}).get("category", "unknown")

        by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1

    return {
        "total": len(findings),
        "by_scanner": by_scanner,
        "by_severity": by_severity,
        "by_category": by_category,
    }
