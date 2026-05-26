"""
CSV export for vulnerability scan results.

Generates a spreadsheet-friendly CSV with all findings.
Compatible with Excel, Google Sheets, and JIRA CSV import.
"""

import csv
import io
from typing import Dict, Any


def generate_csv(scan_data: Dict[str, Any]) -> str:
    """Generate CSV string from scan results."""
    findings = scan_data.get("findings", [])
    repo = scan_data.get("repo", "unknown")

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "ID",
        "Severity",
        "Rule ID",
        "Category",
        "Scanner",
        "File",
        "Line",
        "Message",
        "Package",
        "Version",
        "Fix Versions",
        "CVE ID",
        "Repository",
    ])

    # Data rows
    for i, f in enumerate(findings, 1):
        metadata = f.get("metadata", {})
        writer.writerow([
            i,
            f.get("severity", "MEDIUM"),
            f.get("rule_id", "unknown"),
            metadata.get("category", ""),
            metadata.get("scanner", ""),
            f.get("path", ""),
            f.get("line", ""),
            f.get("message", "")[:500],
            metadata.get("package", ""),
            metadata.get("installed_version", ""),
            ", ".join(metadata.get("fix_versions", [])),
            metadata.get("cve_id", ""),
            repo,
        ])

    return output.getvalue()
