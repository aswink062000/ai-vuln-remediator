"""
Unified Multi-Scanner Orchestrator — Production-grade.

Runs all security scanners in parallel with:
- Per-scanner timeout protection (no single scanner can hang the pipeline)
- Graceful degradation (one scanner failing doesn't kill others)
- Input validation
- Structured error collection
- Deduplication and severity sorting

Scanners:
1. SAST (OpenGrep/Semgrep) — source code vulnerabilities
2. Dependency Scanner — CVEs in packages (Python, Java, Node, Go, Rust, Ruby, PHP)
3. Secret Detector — hardcoded credentials, API keys, tokens
4. Custom Rules — user-defined Semgrep patterns
5. Best Practices — deprecated deps, outdated versions, missing configs
6. Code Quality — complexity, duplication, tech debt, quality gate
7. ML Severity Predictor — adjusts priority based on code context
"""

import logging
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Timeout per scanner (seconds) — prevents any single scanner from blocking
SCANNER_TIMEOUT = 300  # 5 minutes max per scanner
CODE_QUALITY_TIMEOUT = 120  # 2 minutes for code quality


def run_all_scanners(repo_path: str) -> Dict[str, Any]:
    """
    Run all security scanners on a repository.

    This is the main entry point. Safe to call from:
    - FastAPI async endpoints
    - Background threads
    - WebSocket handlers
    - Synchronous scripts

    Returns:
        {
            "findings": [...],
            "summary": {"total": N, "by_severity": {...}, "by_scanner": {...}, "by_category": {...}},
            "errors": [...],
            "code_quality": {...},
            "scan_duration_seconds": N.N,
        }
    """
    start_time = time.time()

    # Validate input
    if not repo_path or not Path(repo_path).is_dir():
        return {
            "findings": [],
            "summary": {"total": 0, "by_severity": {}, "by_scanner": {}, "by_category": {}},
            "errors": [f"Invalid repository path: {repo_path}"],
            "code_quality": {},
            "scan_duration_seconds": 0,
        }

    logger.info(f"=== Starting Scan Pipeline: {repo_path} ===")

    all_findings: List[Dict] = []
    errors: List[str] = []

    # --- Phase 1: Run primary scanners in parallel (with timeouts) ---
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="scanner") as pool:
        # Submit all scanners
        sast_future = pool.submit(_run_sast_scan, repo_path)
        dep_future = pool.submit(_run_dependency_scan, repo_path)
        secret_future = pool.submit(_run_secret_scan, repo_path)
        custom_future = pool.submit(_run_custom_rules, repo_path)
        trivy_future = pool.submit(_run_trivy_scan, repo_path)
        gitleaks_future = pool.submit(_run_gitleaks_scan, repo_path)

        # Collect results with timeouts
        sast_findings, sast_errors = _collect_result(sast_future, "SAST", SCANNER_TIMEOUT)
        dep_findings, dep_errors = _collect_result(dep_future, "Dependency", SCANNER_TIMEOUT)
        secret_findings, secret_errors = _collect_result(secret_future, "Secret", SCANNER_TIMEOUT)
        custom_findings, custom_errors = _collect_result(custom_future, "Custom Rules", 60)
        trivy_findings, trivy_errors = _collect_result(trivy_future, "Trivy", SCANNER_TIMEOUT)
        gitleaks_findings, gitleaks_errors = _collect_result(gitleaks_future, "Gitleaks", 60)

        all_findings.extend(sast_findings)
        all_findings.extend(dep_findings)
        # Use Gitleaks if available, otherwise use built-in secret detector
        if gitleaks_findings:
            all_findings.extend(gitleaks_findings)
            logger.info("Using Gitleaks for secret detection")
        else:
            all_findings.extend(secret_findings)
        # Use Trivy if available (supplements OSV.dev dependency scan)
        if trivy_findings:
            all_findings.extend(trivy_findings)
        all_findings.extend(custom_findings)
        errors.extend(sast_errors)
        errors.extend(dep_errors)
        errors.extend(secret_errors)
        errors.extend(trivy_errors)
        errors.extend(gitleaks_errors)
        errors.extend(custom_errors)

    # --- Phase 2: Best practices scan (sequential, fast) ---
    bp_findings, bp_errors = _run_best_practices(repo_path)
    all_findings.extend(bp_findings)
    errors.extend(bp_errors)

    # --- Phase 3: Post-processing ---
    # Deduplicate
    all_findings = _deduplicate(all_findings)

    # ML Severity Prediction (adjusts priority based on code context)
    all_findings = _apply_severity_prediction(all_findings, repo_path)

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "MEDIUM").upper(), 3))

    # --- Phase 4: Code Quality (separate, non-blocking) ---
    code_quality = _run_code_quality(repo_path)

    # --- Build summary ---
    summary = _build_summary(all_findings)
    duration = round(time.time() - start_time, 1)

    logger.info(
        f"=== Scan complete in {duration}s: {summary['total']} findings "
        f"({summary.get('by_category', {})}) ==="
    )

    return {
        "findings": all_findings,
        "summary": summary,
        "errors": errors,
        "code_quality": code_quality,
        "scan_duration_seconds": duration,
    }


# =============================================================================
# INDIVIDUAL SCANNER WRAPPERS (each handles its own errors)
# =============================================================================

def _run_sast_scan(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run SAST scan (OpenGrep/Semgrep). Returns (findings, errors)."""
    try:
        from app.scanners.semgrep_scan import run_semgrep
        from app.parsers.findings import extract_findings, normalize_paths

        semgrep_result = run_semgrep(repo_path)

        findings = extract_findings(semgrep_result)
        findings = normalize_paths(findings, repo_path)

        for f in findings:
            f.setdefault("metadata", {})
            f["metadata"]["scanner"] = "semgrep"
            f["metadata"]["category"] = "sast"

        # Filter non-critical warnings from errors
        raw_errors = semgrep_result.get("errors", [])
        critical_errors = [
            e for e in raw_errors
            if isinstance(e, dict) and e.get("level") not in ("warn", "info")
        ]
        error_messages = []
        for e in critical_errors[:3]:
            msg = e.get("message", str(e))[:200] if isinstance(e, dict) else str(e)[:200]
            error_messages.append(f"SAST: {msg}")

        logger.info(f"SAST scan: {len(findings)} findings")
        return findings, error_messages

    except FileNotFoundError as e:
        logger.warning(f"SAST scanner not installed: {e}")
        return [], [f"SAST scanner not installed: {str(e)[:150]}"]
    except Exception as e:
        logger.error(f"SAST scan failed: {e}", exc_info=True)
        return [], [f"SAST scan error: {str(e)[:200]}"]


def _run_dependency_scan(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run dependency vulnerability scan. Returns (findings, errors)."""
    try:
        from app.scanners.dependency_scan import run_dependency_scan

        findings = run_dependency_scan(repo_path)
        logger.info(f"Dependency scan: {len(findings)} findings")
        return findings, []

    except Exception as e:
        logger.error(f"Dependency scan failed: {e}", exc_info=True)
        return [], [f"Dependency scan error: {str(e)[:200]}"]


def _run_secret_scan(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run secret/credential detection. Returns (findings, errors)."""
    try:
        from app.ml.secret_detector import run_secret_scan

        findings = run_secret_scan(repo_path)
        logger.info(f"Secret scan: {len(findings)} findings")
        return findings, []

    except Exception as e:
        logger.error(f"Secret detection failed: {e}", exc_info=True)
        return [], [f"Secret detection error: {str(e)[:200]}"]


def _run_custom_rules(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run user-defined custom rules. Returns (findings, errors)."""
    try:
        from app.scanners.custom_rules import run_custom_rules

        findings = run_custom_rules(repo_path)
        if findings:
            for f in findings:
                f.setdefault("metadata", {})
                f["metadata"]["scanner"] = "custom-rules"
                f["metadata"]["category"] = "custom"
            logger.info(f"Custom rules: {len(findings)} findings")
        return findings or [], []

    except Exception as e:
        logger.debug(f"Custom rules skipped: {e}")
        return [], []


def _run_trivy_scan(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run Trivy vulnerability + misconfig scan. Returns (findings, errors)."""
    try:
        from app.scanners.trivy_scan import run_trivy_scan, run_trivy_config_scan, is_trivy_available

        if not is_trivy_available():
            return [], []

        findings = run_trivy_scan(repo_path)
        # Also run misconfig scan (Dockerfile, Terraform, K8s)
        misconfig = run_trivy_config_scan(repo_path)
        findings.extend(misconfig)

        logger.info(f"Trivy scan: {len(findings)} findings")
        return findings, []

    except Exception as e:
        logger.debug(f"Trivy scan skipped: {e}")
        return [], []


def _run_gitleaks_scan(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run Gitleaks secret detection. Returns (findings, errors)."""
    try:
        from app.scanners.gitleaks_scan import run_gitleaks_scan, is_gitleaks_available

        if not is_gitleaks_available():
            return [], []

        findings = run_gitleaks_scan(repo_path)
        logger.info(f"Gitleaks scan: {len(findings)} findings")
        return findings, []

    except Exception as e:
        logger.debug(f"Gitleaks scan skipped: {e}")
        return [], []


def _run_best_practices(repo_path: str) -> Tuple[List[Dict], List[str]]:
    """Run best practices scan. Returns (findings, errors)."""
    try:
        from app.scanners.best_practices import run_best_practices_scan

        findings = run_best_practices_scan(repo_path)
        if findings:
            logger.info(f"Best practices: {len(findings)} findings")
        return findings or [], []

    except Exception as e:
        logger.error(f"Best practices scan failed: {e}")
        return [], [f"Best practices error: {str(e)[:200]}"]


def _run_code_quality(repo_path: str) -> Dict[str, Any]:
    """Run code quality analysis. Returns quality metrics or empty dict on failure."""
    try:
        from app.scanners.code_quality import run_code_quality_scan

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(run_code_quality_scan, repo_path)
            try:
                result = future.result(timeout=CODE_QUALITY_TIMEOUT)
                gate = result.get("quality_gate_details", {})
                logger.info(f"Code quality: gate={'PASSED' if gate.get('passed') else 'FAILED'}")
                return result
            except FuturesTimeoutError:
                logger.warning("Code quality scan timed out")
                return {}

    except Exception as e:
        logger.error(f"Code quality scan failed: {e}")
        return {}


def _apply_severity_prediction(findings: List[Dict], repo_path: str) -> List[Dict]:
    """Apply ML severity prediction. Returns findings unchanged if prediction fails."""
    try:
        from app.ml.severity_predictor import predict_severity

        enhanced = predict_severity(findings, repo_path)
        logger.info("ML severity prediction applied")
        return enhanced
    except Exception as e:
        logger.debug(f"Severity prediction skipped: {e}")
        return findings


# =============================================================================
# UTILITIES
# =============================================================================

def _collect_result(
    future, scanner_name: str, timeout: int
) -> Tuple[List[Dict], List[str]]:
    """
    Safely collect result from a future with timeout.
    Returns (findings, errors) — never raises.
    """
    try:
        findings, errors = future.result(timeout=timeout)
        return findings, errors
    except FuturesTimeoutError:
        logger.error(f"{scanner_name} scanner timed out after {timeout}s")
        return [], [f"{scanner_name} scanner timed out after {timeout}s"]
    except Exception as e:
        logger.error(f"{scanner_name} scanner crashed: {e}", exc_info=True)
        return [], [f"{scanner_name} scanner error: {str(e)[:200]}"]


def _deduplicate(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings (same rule + file + line)."""
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
        logger.info(f"Deduplicated: {len(findings)} → {len(unique)} findings")

    return unique


def _build_summary(findings: List[Dict]) -> Dict:
    """Build a structured summary of scan results."""
    by_scanner: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}

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
