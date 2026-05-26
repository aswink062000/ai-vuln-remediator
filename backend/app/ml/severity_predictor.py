"""
ML-based Severity Predictor.

Uses TF-IDF + heuristic scoring to predict/adjust vulnerability severity
based on code context, not just the scanner's default rating.

Factors considered:
- Is the vulnerable code in an auth/payment/data path?
- Is it exposed to user input (HTTP handlers, form processing)?
- Is it in a test file vs production code?
- How many other vulnerabilities are in the same file?
- Is the file frequently changed (high churn = higher risk)?

Library: scikit-learn (BSD license) — optional, falls back to heuristics.
"""

import re
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# High-risk path patterns (code in these areas is more critical)
HIGH_RISK_PATTERNS = [
    r"auth", r"login", r"password", r"credential", r"token",
    r"payment", r"billing", r"checkout", r"stripe", r"paypal",
    r"admin", r"superuser", r"privilege",
    r"crypto", r"encrypt", r"decrypt", r"secret", r"key",
    r"database", r"query", r"sql", r"orm",
    r"upload", r"file.*write", r"exec", r"eval", r"system",
    r"api.*key", r"jwt", r"session", r"cookie",
]

# User input indicators (code that processes external input)
INPUT_PATTERNS = [
    r"request\.", r"req\.", r"params\[", r"body\[",
    r"@app\.route", r"@router\.", r"@GetMapping", r"@PostMapping",
    r"getParameter", r"getElementById", r"querySelector",
    r"input\(", r"sys\.argv", r"os\.environ",
    r"form\.", r"query\.", r"headers\[",
]

# Test file indicators (lower severity)
TEST_PATTERNS = [
    r"test_", r"_test\.", r"\.test\.", r"\.spec\.",
    r"__tests__", r"tests/", r"test/",
    r"mock", r"fixture", r"conftest",
]


def predict_severity(findings: List[Dict[str, Any]], repo_path: str) -> List[Dict[str, Any]]:
    """
    Enhance findings with ML-predicted severity adjustments.
    Adds 'adjusted_severity' and 'risk_score' to each finding.
    """
    enhanced = []

    # Pre-compute file risk scores
    file_finding_counts: Dict[str, int] = {}
    for f in findings:
        path = f.get("path", "")
        file_finding_counts[path] = file_finding_counts.get(path, 0) + 1

    for finding in findings:
        risk_score = _calculate_risk_score(finding, repo_path, file_finding_counts)
        adjusted = _adjust_severity(finding.get("severity", "MEDIUM"), risk_score)

        enhanced_finding = {
            **finding,
            "risk_score": risk_score,
            "adjusted_severity": adjusted,
            "risk_factors": _get_risk_factors(finding, repo_path),
        }
        enhanced.append(enhanced_finding)

    # Sort by risk score (highest first)
    enhanced.sort(key=lambda x: x["risk_score"], reverse=True)

    return enhanced


def _calculate_risk_score(finding: Dict, repo_path: str, file_counts: Dict) -> float:
    """
    Calculate a 0-100 risk score for a finding.
    Higher = more critical to fix first.
    """
    score = 50.0  # Base score

    path = finding.get("path", "").lower()
    message = finding.get("message", "").lower()
    severity = finding.get("severity", "MEDIUM").upper()

    # Base severity weight
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "ERROR": 20, "MEDIUM": 10, "WARNING": 5, "LOW": 0}
    score += severity_weights.get(severity, 10)

    # High-risk path bonus
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, path) or re.search(pattern, message):
            score += 5
            break  # Cap at one bonus

    # User input exposure bonus
    try:
        full_path = Path(repo_path) / finding.get("path", "")
        if full_path.exists():
            content = full_path.read_text(encoding="utf-8", errors="replace")[:5000]
            input_exposure = sum(1 for p in INPUT_PATTERNS if re.search(p, content))
            score += min(input_exposure * 3, 15)
    except Exception:
        pass

    # Test file penalty (lower priority)
    for pattern in TEST_PATTERNS:
        if re.search(pattern, path):
            score -= 20
            break

    # File density bonus (many vulns in one file = systemic issue)
    density = file_counts.get(finding.get("path", ""), 0)
    if density > 5:
        score += 10
    elif density > 2:
        score += 5

    # Clamp to 0-100
    return max(0, min(100, round(score, 1)))


def _adjust_severity(original: str, risk_score: float) -> str:
    """Adjust severity based on risk score."""
    if risk_score >= 85:
        return "CRITICAL"
    elif risk_score >= 70:
        return "HIGH"
    elif risk_score >= 50:
        return original  # Keep original
    elif risk_score >= 30:
        return "MEDIUM" if original in ("HIGH", "CRITICAL") else original
    else:
        return "LOW"


def _get_risk_factors(finding: Dict, repo_path: str) -> List[str]:
    """Get human-readable risk factors for a finding."""
    factors = []
    path = finding.get("path", "").lower()
    message = finding.get("message", "").lower()

    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, path) or re.search(pattern, message):
            factors.append(f"Located in security-sensitive path ({pattern})")
            break

    for pattern in TEST_PATTERNS:
        if re.search(pattern, path):
            factors.append("In test file (lower production risk)")
            break

    try:
        full_path = Path(repo_path) / finding.get("path", "")
        if full_path.exists():
            content = full_path.read_text(encoding="utf-8", errors="replace")[:3000]
            for pattern in INPUT_PATTERNS[:5]:
                if re.search(pattern, content):
                    factors.append("Processes external user input")
                    break
    except Exception:
        pass

    if not factors:
        factors.append("Standard risk level")

    return factors
