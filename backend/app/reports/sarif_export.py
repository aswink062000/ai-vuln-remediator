"""
SARIF (Static Analysis Results Interchange Format) export.

SARIF is the standard format consumed by:
- GitHub Code Scanning
- Azure DevOps
- VS Code SARIF Viewer
- Many CI/CD tools

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
License: This is your own code — no license issues.
"""

import json
from typing import Dict, Any, List
from datetime import datetime


def generate_sarif(scan_data: Dict[str, Any]) -> str:
    """Generate SARIF 2.1.0 JSON from scan results."""
    findings = scan_data.get("findings", [])
    repo = scan_data.get("repo", "unknown")

    # Build rules from unique rule_ids
    rules = {}
    for f in findings:
        rule_id = f.get("rule_id", "unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", " ").replace("_", " ").title(),
                "shortDescription": {"text": f.get("message", "")[:200]},
                "defaultConfiguration": {
                    "level": _sarif_level(f.get("severity", "MEDIUM"))
                },
                "properties": {
                    "tags": [
                        f.get("metadata", {}).get("category", "security"),
                    ]
                },
            }

    # Build results
    results = []
    for f in findings:
        result = {
            "ruleId": f.get("rule_id", "unknown"),
            "level": _sarif_level(f.get("severity", "MEDIUM")),
            "message": {"text": f.get("message", "No description")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("path", "unknown"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.get("line", 1),
                            "endLine": f.get("end_line") or f.get("line", 1),
                        },
                    }
                }
            ],
        }

        # Add fix info if available
        metadata = f.get("metadata", {})
        if metadata.get("fix_versions"):
            result["fixes"] = [
                {
                    "description": {
                        "text": f"Upgrade to version {', '.join(metadata['fix_versions'])}"
                    }
                }
            ]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Vulnerability Remediator",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/ai-vuln-remediator",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                    }
                ],
                "properties": {
                    "repo": repo,
                    "totalFindings": len(findings),
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    s = severity.upper()
    if s in ("CRITICAL", "HIGH", "ERROR"):
        return "error"
    if s in ("MEDIUM", "WARNING", "MODERATE"):
        return "warning"
    return "note"
