"""
Multi-scanner architecture for comprehensive vulnerability detection.

Scanners:
- semgrep_scan: SAST (source code analysis) for all languages
- dependency_scan: Dependency CVE scanning (pip-audit, npm audit, OSV.dev API)
- code_quality: Code quality metrics (complexity, duplication, smells, tech debt)
"""
