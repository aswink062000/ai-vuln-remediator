import os
import logging

logger = logging.getLogger(__name__)


def extract_findings(scan_result):
    """
    Extract vulnerability findings from semgrep scan results.
    Handles both absolute and relative file paths from semgrep output.
    """
    findings = []

    if not scan_result or not isinstance(scan_result, dict):
        logger.warning("Scan result is empty or not a dict")
        return findings

    results = scan_result.get("results", [])
    errors = scan_result.get("errors", [])

    if errors:
        # Only log actual errors, not parse warnings (PartialParsing is normal for template files)
        real_errors = [e for e in errors if not (isinstance(e, dict) and e.get("level") in ("warn", "info"))]
        if real_errors:
            logger.warning(f"Semgrep reported {len(real_errors)} errors during scan")
            for err in real_errors[:5]:
                msg = err.get("message", str(err))[:200] if isinstance(err, dict) else str(err)[:200]
                logger.warning(f"  Scan error: {msg}")
        else:
            logger.debug(f"Semgrep reported {len(errors)} non-critical warnings (PartialParsing, etc.)")

    logger.info(f"Processing {len(results)} raw findings from semgrep")

    for item in results:
        try:
            file_path = item.get("path", "")

            # Semgrep may return absolute paths - we need relative paths
            # for later use with repo_path
            if os.path.isabs(file_path):
                # Will be normalized later when we know repo_path
                pass

            finding = {
                "path": file_path,
                "line": item.get("start", {}).get("line"),
                "end_line": item.get("end", {}).get("line"),
                "rule_id": item.get("check_id", "unknown"),
                "message": item.get("extra", {}).get("message", "No message"),
                "severity": item.get("extra", {}).get("severity", "WARNING"),
                "metadata": item.get("extra", {}).get("metadata", {}),
            }

            findings.append(finding)
        except Exception as e:
            logger.error(f"Error parsing finding: {e}")
            continue

    logger.info(f"Extracted {len(findings)} findings")
    return findings


def normalize_paths(findings, repo_path):
    """
    Normalize file paths in findings to be relative to repo_path.
    Semgrep can return absolute paths depending on how it's invoked.
    """
    normalized = []

    for finding in findings:
        file_path = finding["path"]

        # If path is absolute and starts with repo_path, make it relative
        if os.path.isabs(file_path) and file_path.startswith(repo_path):
            file_path = os.path.relpath(file_path, repo_path)
            finding = {**finding, "path": file_path}

        normalized.append(finding)

    return normalized
