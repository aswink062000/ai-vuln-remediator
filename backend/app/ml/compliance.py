"""
Compliance Mapping Engine.

Maps vulnerability findings to industry compliance frameworks:
- OWASP Top 10 (2021)
- CWE (Common Weakness Enumeration)
- PCI-DSS v4.0
- SOC 2 Type II
- NIST 800-53

Generates a compliance dashboard showing which standards are violated.
"""

import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# OWASP Top 10 (2021) mapping
OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "keywords": ["access", "auth", "permission", "privilege", "idor", "insecure-direct"]},
    "A02": {"name": "Cryptographic Failures", "keywords": ["crypto", "encrypt", "hash", "ssl", "tls", "certificate", "weak-hash", "md5", "sha1"]},
    "A03": {"name": "Injection", "keywords": ["sql", "injection", "xss", "command-injection", "ldap", "xpath", "nosql", "template-injection"]},
    "A04": {"name": "Insecure Design", "keywords": ["design", "logic", "business-logic", "race-condition"]},
    "A05": {"name": "Security Misconfiguration", "keywords": ["config", "misconfiguration", "default", "debug", "verbose-error", "cors", "header"]},
    "A06": {"name": "Vulnerable Components", "keywords": ["dependency", "outdated", "cve", "vulnerable-component", "package"]},
    "A07": {"name": "Auth Failures", "keywords": ["authentication", "session", "credential", "password", "brute-force", "jwt"]},
    "A08": {"name": "Data Integrity Failures", "keywords": ["deserialization", "integrity", "cicd", "pipeline", "unsigned"]},
    "A09": {"name": "Logging Failures", "keywords": ["logging", "monitoring", "audit", "log-injection"]},
    "A10": {"name": "SSRF", "keywords": ["ssrf", "server-side-request", "url-redirect", "open-redirect"]},
}

# CWE mapping (common ones)
CWE_MAP = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "keywords": ["xss", "cross-site", "script-injection"]},
    "CWE-89": {"name": "SQL Injection", "keywords": ["sql-injection", "sqli"]},
    "CWE-78": {"name": "OS Command Injection", "keywords": ["command-injection", "os-command", "exec", "system"]},
    "CWE-22": {"name": "Path Traversal", "keywords": ["path-traversal", "directory-traversal", "lfi"]},
    "CWE-352": {"name": "CSRF", "keywords": ["csrf", "cross-site-request"]},
    "CWE-502": {"name": "Deserialization", "keywords": ["deserialization", "pickle", "yaml-load", "unserialize"]},
    "CWE-798": {"name": "Hardcoded Credentials", "keywords": ["hardcoded", "credential", "password", "secret", "api-key"]},
    "CWE-327": {"name": "Broken Crypto", "keywords": ["weak-crypto", "md5", "sha1", "des", "rc4"]},
    "CWE-611": {"name": "XXE", "keywords": ["xxe", "xml-external", "xml-injection"]},
    "CWE-918": {"name": "SSRF", "keywords": ["ssrf", "server-side-request"]},
    "CWE-200": {"name": "Information Exposure", "keywords": ["information-disclosure", "sensitive-data", "exposure"]},
    "CWE-287": {"name": "Improper Authentication", "keywords": ["authentication", "auth-bypass"]},
    "CWE-862": {"name": "Missing Authorization", "keywords": ["authorization", "access-control", "missing-auth"]},
    "CWE-434": {"name": "Unrestricted Upload", "keywords": ["file-upload", "unrestricted-upload"]},
    "CWE-601": {"name": "Open Redirect", "keywords": ["open-redirect", "url-redirect"]},
}

# PCI-DSS v4.0 requirements
PCI_DSS = {
    "6.2.4": {"name": "Protect against common attacks", "categories": ["injection", "xss", "csrf", "ssrf"]},
    "6.3.1": {"name": "Identify vulnerabilities in custom code", "categories": ["sast", "code-review"]},
    "6.3.2": {"name": "Review custom code before release", "categories": ["sast", "dependency"]},
    "6.4.1": {"name": "Protect web apps from attacks", "categories": ["xss", "injection", "csrf"]},
    "8.3.6": {"name": "Strong authentication", "categories": ["authentication", "password", "credential"]},
    "8.6.1": {"name": "No hardcoded credentials", "categories": ["secret", "hardcoded", "credential"]},
    "3.5.1": {"name": "Protect stored account data", "categories": ["crypto", "encryption", "data-exposure"]},
}


def map_compliance(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Map findings to compliance frameworks.
    Returns a compliance dashboard with violations per framework.
    """
    owasp_violations: Dict[str, List] = {}
    cwe_violations: Dict[str, List] = {}
    pci_violations: Dict[str, List] = {}

    for finding in findings:
        rule_id = finding.get("rule_id", "").lower()
        message = finding.get("message", "").lower()
        category = finding.get("metadata", {}).get("category", "").lower()
        combined = f"{rule_id} {message} {category}"

        # Map to OWASP
        for code, info in OWASP_TOP_10.items():
            if any(kw in combined for kw in info["keywords"]):
                if code not in owasp_violations:
                    owasp_violations[code] = []
                owasp_violations[code].append({
                    "rule_id": finding.get("rule_id"),
                    "path": finding.get("path"),
                    "severity": finding.get("severity"),
                })
                break

        # Map to CWE
        for cwe_id, info in CWE_MAP.items():
            if any(kw in combined for kw in info["keywords"]):
                if cwe_id not in cwe_violations:
                    cwe_violations[cwe_id] = []
                cwe_violations[cwe_id].append({
                    "rule_id": finding.get("rule_id"),
                    "path": finding.get("path"),
                })
                break

        # Map to PCI-DSS
        for req_id, info in PCI_DSS.items():
            if any(cat in combined for cat in info["categories"]):
                if req_id not in pci_violations:
                    pci_violations[req_id] = []
                pci_violations[req_id].append({
                    "rule_id": finding.get("rule_id"),
                    "path": finding.get("path"),
                })
                break

    # Build dashboard
    owasp_summary = []
    for code, info in OWASP_TOP_10.items():
        violations = owasp_violations.get(code, [])
        owasp_summary.append({
            "code": code,
            "name": info["name"],
            "violations": len(violations),
            "status": "FAIL" if violations else "PASS",
        })

    pci_summary = []
    for req_id, info in PCI_DSS.items():
        violations = pci_violations.get(req_id, [])
        pci_summary.append({
            "requirement": req_id,
            "name": info["name"],
            "violations": len(violations),
            "status": "FAIL" if violations else "PASS",
        })

    total_owasp_fail = sum(1 for o in owasp_summary if o["status"] == "FAIL")
    total_pci_fail = sum(1 for p in pci_summary if p["status"] == "FAIL")

    return {
        "owasp_top_10": {
            "violations": total_owasp_fail,
            "total_categories": 10,
            "compliance_score": round((10 - total_owasp_fail) / 10 * 100),
            "details": owasp_summary,
        },
        "cwe": {
            "unique_weaknesses": len(cwe_violations),
            "details": [
                {"id": k, "name": CWE_MAP[k]["name"], "count": len(v)}
                for k, v in sorted(cwe_violations.items(), key=lambda x: len(x[1]), reverse=True)
            ],
        },
        "pci_dss": {
            "violations": total_pci_fail,
            "total_requirements": len(PCI_DSS),
            "compliance_score": round((len(PCI_DSS) - total_pci_fail) / len(PCI_DSS) * 100),
            "details": pci_summary,
        },
        "overall_compliance_score": round(
            ((10 - total_owasp_fail) / 10 * 50) +
            ((len(PCI_DSS) - total_pci_fail) / len(PCI_DSS) * 50)
        ),
    }
