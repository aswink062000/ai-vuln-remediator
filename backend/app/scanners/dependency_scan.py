"""
Multi-stack dependency vulnerability scanner.

Detects CVEs in:
- Python: requirements.txt, Pipfile.lock, poetry.lock
- Java/Spring: pom.xml (Maven), build.gradle (Gradle)
- Node.js: package.json, package-lock.json

Uses pure Python approaches (no external binary dependencies like Trivy/brew)
so it works cross-platform (Windows, macOS, Linux).
"""

import subprocess
import json
import sys
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def run_dependency_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run all applicable dependency scanners based on project files found.
    Returns a unified list of vulnerability findings.
    """
    findings = []
    repo = Path(repo_path)

    # Detect project types
    has_python = _has_python_deps(repo)
    has_java_maven = (repo / "pom.xml").exists()
    has_java_gradle = (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists()
    has_node = (repo / "package.json").exists()
    has_dotnet = any(repo.rglob("*.csproj")) or any(repo.rglob("*.fsproj"))
    has_go = (repo / "go.mod").exists()
    has_rust = (repo / "Cargo.toml").exists()
    has_ruby = (repo / "Gemfile.lock").exists()
    has_php = (repo / "composer.lock").exists()

    logger.info(
        f"Project detection - Python: {has_python}, "
        f"Maven: {has_java_maven}, Gradle: {has_java_gradle}, "
        f"Node: {has_node}, .NET: {has_dotnet}, Go: {has_go}, "
        f"Rust: {has_rust}, Ruby: {has_ruby}, PHP: {has_php}"
    )

    # Run applicable scanners
    if has_python:
        findings.extend(scan_python_dependencies(repo_path))

    if has_java_maven:
        findings.extend(scan_maven_dependencies(repo_path))

    if has_java_gradle:
        findings.extend(scan_gradle_dependencies(repo_path))

    if has_node:
        findings.extend(scan_node_dependencies(repo_path))

    if has_dotnet:
        findings.extend(scan_dotnet_dependencies(repo_path))

    if has_go:
        findings.extend(scan_go_dependencies(repo_path))

    if has_rust:
        findings.extend(scan_rust_dependencies(repo_path))

    if has_ruby:
        findings.extend(scan_ruby_dependencies(repo_path))

    if has_php:
        findings.extend(scan_php_dependencies(repo_path))

    logger.info(f"Total dependency vulnerabilities found: {len(findings)}")
    return findings


def _has_python_deps(repo: Path) -> bool:
    """Check if repo has Python dependency files."""
    return any([
        (repo / "requirements.txt").exists(),
        (repo / "Pipfile").exists(),
        (repo / "Pipfile.lock").exists(),
        (repo / "poetry.lock").exists(),
        (repo / "pyproject.toml").exists(),
        (repo / "setup.py").exists(),
        (repo / "setup.cfg").exists(),
    ])


# =============================================================================
# PYTHON DEPENDENCY SCANNING (pip-audit)
# =============================================================================

def scan_python_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Python dependencies using pip-audit.
    pip-audit is a pure Python tool (pip install pip-audit) — works on all platforms.
    """
    findings = []
    repo = Path(repo_path)

    # Find requirements files
    req_files = []
    for pattern in ["requirements*.txt", "requirements/*.txt"]:
        req_files.extend(repo.glob(pattern))

    if not req_files:
        # Try Pipfile or pyproject.toml
        if (repo / "Pipfile.lock").exists():
            req_files = [repo / "Pipfile.lock"]
        elif (repo / "pyproject.toml").exists():
            req_files = [repo / "pyproject.toml"]

    if not req_files:
        logger.info("No Python dependency files found")
        return findings

    # Get pip-audit path
    pip_audit_bin = _get_pip_audit_path()
    if not pip_audit_bin:
        # Auto-install pip-audit
        logger.info("pip-audit not found, attempting auto-install...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "pip-audit"],
                capture_output=True,
                timeout=120
            )
            pip_audit_bin = _get_pip_audit_path()
        except Exception as e:
            logger.warning(f"Failed to auto-install pip-audit: {e}")

    if not pip_audit_bin:
        logger.warning(
            "pip-audit not found and auto-install failed. "
            "Install with: pip install pip-audit"
        )
        # Fallback to safety-db check
        return _scan_python_fallback(repo_path, req_files)

    for req_file in req_files:
        logger.info(f"Scanning Python deps: {req_file.name}")

        cmd = [
            pip_audit_bin,
            "-r", str(req_file),
            "--format", "json",
            "--progress-spinner", "off",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=False,
                timeout=300,
                cwd=repo_path
            )

            stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
            stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""

            if stdout:
                try:
                    audit_results = json.loads(stdout)
                    # pip-audit returns a list of vulnerability objects
                    if isinstance(audit_results, list):
                        vulns = audit_results
                    else:
                        vulns = audit_results.get("dependencies", [])

                    for dep in vulns:
                        dep_vulns = dep.get("vulns", [])
                        for vuln in dep_vulns:
                            findings.append({
                                "path": str(req_file.relative_to(repo)),
                                "line": _find_dep_line(req_file, dep.get("name", "")),
                                "end_line": None,
                                "rule_id": vuln.get("id", "unknown-cve"),
                                "message": (
                                    f"Vulnerable dependency: {dep.get('name')}=={dep.get('version')} — "
                                    f"{vuln.get('id')}: {vuln.get('description', 'No description')}"
                                ),
                                "severity": _map_pip_audit_severity(vuln),
                                "metadata": {
                                    "scanner": "pip-audit",
                                    "category": "dependency",
                                    "package": dep.get("name"),
                                    "installed_version": dep.get("version"),
                                    "fix_versions": vuln.get("fix_versions", []),
                                    "cve_id": vuln.get("id"),
                                    "aliases": vuln.get("aliases", []),
                                },
                            })

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse pip-audit output: {e}")

            if stderr:
                logger.debug(f"pip-audit stderr: {stderr[:500]}")

        except subprocess.TimeoutExpired:
            logger.warning(f"pip-audit timed out for {req_file.name}")
        except Exception as e:
            logger.error(f"pip-audit failed for {req_file.name}: {e}")

    logger.info(f"Python dependency scan found {len(findings)} vulnerabilities")
    return findings


def _get_pip_audit_path():
    """Find pip-audit binary."""
    venv_bin = Path(sys.executable).parent
    # Check for pip-audit in venv (works on Windows too: pip-audit.exe)
    for name in ["pip-audit", "pip-audit.exe"]:
        path = venv_bin / name
        if path.exists():
            return str(path)

    # System PATH
    return shutil.which("pip-audit")


def _scan_python_fallback(repo_path: str, req_files: List[Path]) -> List[Dict[str, Any]]:
    """
    Fallback Python dependency scanning using the OSV.dev API.
    No external binary needed — pure HTTP requests.
    """
    import requests

    findings = []
    repo = Path(repo_path)

    for req_file in req_files:
        if req_file.suffix != ".txt":
            continue

        try:
            content = req_file.read_text(encoding="utf-8", errors="replace")
            packages = _parse_requirements_txt(content)

            for pkg_name, pkg_version in packages:
                if not pkg_version:
                    continue

                # Query OSV.dev API (free, no auth needed)
                vulns = _query_osv(pkg_name, pkg_version, "PyPI")
                for vuln in vulns:
                    findings.append({
                        "path": str(req_file.relative_to(repo)),
                        "line": _find_dep_line(req_file, pkg_name),
                        "end_line": None,
                        "rule_id": vuln.get("id", "unknown"),
                        "message": (
                            f"Vulnerable dependency: {pkg_name}=={pkg_version} — "
                            f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                        ),
                        "severity": _osv_severity(vuln),
                        "metadata": {
                            "scanner": "osv-api",
                            "category": "dependency",
                            "package": pkg_name,
                            "installed_version": pkg_version,
                            "cve_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                            "references": [r.get("url") for r in vuln.get("references", [])[:3]],
                        },
                    })

        except Exception as e:
            logger.error(f"Fallback Python scan failed for {req_file}: {e}")

    return findings


# =============================================================================
# JAVA/MAVEN DEPENDENCY SCANNING
# =============================================================================

def scan_maven_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Maven (pom.xml) dependencies for known CVEs.
    
    Strategy:
    1. Try OWASP Dependency-Check if available (best for Java)
    2. Fallback: Parse pom.xml and query OSV.dev API (no binary needed)
    """
    # Try OWASP dependency-check first
    dc_path = shutil.which("dependency-check") or shutil.which("dependency-check.bat")
    if dc_path:
        return _run_owasp_dependency_check(repo_path, dc_path)

    # Fallback: parse pom.xml and check OSV
    logger.info("OWASP Dependency-Check not found, using OSV.dev API fallback")
    return _scan_maven_osv(repo_path)


def _run_owasp_dependency_check(repo_path: str, dc_path: str) -> List[Dict[str, Any]]:
    """Run OWASP Dependency-Check scanner."""
    findings = []
    output_file = Path(repo_path) / ".dependency-check-report.json"

    cmd = [
        dc_path,
        "--project", "scan",
        "--scan", repo_path,
        "--format", "JSON",
        "--out", str(output_file),
        "--noupdate",  # Skip DB update for speed (use cached)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=600,
            cwd=repo_path
        )

        if output_file.exists():
            report = json.loads(output_file.read_text(encoding="utf-8"))
            deps = report.get("dependencies", [])

            for dep in deps:
                vulns = dep.get("vulnerabilities", [])
                for vuln in vulns:
                    findings.append({
                        "path": "pom.xml",
                        "line": None,
                        "end_line": None,
                        "rule_id": vuln.get("name", "unknown-cve"),
                        "message": (
                            f"Vulnerable dependency: {dep.get('fileName', 'unknown')} — "
                            f"{vuln.get('name')}: {vuln.get('description', '')[:200]}"
                        ),
                        "severity": vuln.get("severity", "MEDIUM").upper(),
                        "metadata": {
                            "scanner": "owasp-dependency-check",
                            "category": "dependency",
                            "package": dep.get("fileName"),
                            "cve_id": vuln.get("name"),
                            "cvss_score": vuln.get("cvssv3", {}).get("baseScore"),
                        },
                    })

            # Cleanup report
            output_file.unlink(missing_ok=True)

    except subprocess.TimeoutExpired:
        logger.warning("OWASP Dependency-Check timed out")
    except Exception as e:
        logger.error(f"OWASP Dependency-Check failed: {e}")

    return findings


def _scan_maven_osv(repo_path: str) -> List[Dict[str, Any]]:
    """
    Parse pom.xml and check dependencies against OSV.dev.
    Pure Python — no external binary needed. Works on Windows.
    """
    import xml.etree.ElementTree as ET

    findings = []
    pom_path = Path(repo_path) / "pom.xml"

    if not pom_path.exists():
        return findings

    try:
        tree = ET.parse(str(pom_path))
        root = tree.getroot()

        # Handle Maven namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Extract dependencies
        deps_section = root.find(f".//{ns}dependencies")
        if deps_section is None:
            logger.info("No dependencies section found in pom.xml")
            dependencies = []
        else:
            dependencies = deps_section.findall(f"{ns}dependency")

        logger.info(f"Found {len(dependencies)} Maven dependencies to check")

        # Also check dependencyManagement
        dep_mgmt = root.find(f".//{ns}dependencyManagement/{ns}dependencies")
        if dep_mgmt is not None:
            dependencies.extend(dep_mgmt.findall(f"{ns}dependency"))

        # Also check <parent> section (Spring Boot, etc.)
        parent = root.find(f"{ns}parent")
        if parent is not None:
            parent_group = parent.findtext(f"{ns}groupId", "")
            parent_artifact = parent.findtext(f"{ns}artifactId", "")
            parent_version = parent.findtext(f"{ns}version", "")
            if parent_group and parent_artifact and parent_version:
                # Clean version (remove .RELEASE, .Final, etc.)
                clean_version = _clean_maven_version(parent_version)
                logger.info(f"Found parent: {parent_group}:{parent_artifact}@{parent_version}")

                maven_pkg = f"{parent_group}:{parent_artifact}"
                vulns = _query_osv(maven_pkg, clean_version, "Maven")
                for vuln in vulns:
                    findings.append({
                        "path": "pom.xml",
                        "line": _find_dep_line_xml(pom_path, parent_artifact),
                        "end_line": None,
                        "rule_id": vuln.get("id", "unknown"),
                        "message": (
                            f"Vulnerable parent: {maven_pkg}:{parent_version} — "
                            f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                        ),
                        "severity": _osv_severity(vuln),
                        "metadata": {
                            "scanner": "osv-api",
                            "category": "dependency",
                            "package": maven_pkg,
                            "installed_version": parent_version,
                            "cve_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                        },
                    })

        # Resolve properties for version placeholders
        properties = {}
        props_section = root.find(f".//{ns}properties")
        if props_section is not None:
            for prop in props_section:
                tag = prop.tag.replace(ns, "")
                properties[tag] = prop.text or ""

        for dep in dependencies:
            group_id = dep.findtext(f"{ns}groupId", "")
            artifact_id = dep.findtext(f"{ns}artifactId", "")
            version = dep.findtext(f"{ns}version", "")

            # Resolve property placeholders like ${spring.version}
            if version and version.startswith("${") and version.endswith("}"):
                prop_name = version[2:-1]
                version = properties.get(prop_name, version)

            if not version or version.startswith("${"):
                continue  # Can't check without a resolved version

            # Clean version (remove .RELEASE, .Final, -SNAPSHOT, etc.)
            clean_version = _clean_maven_version(version)

            # Query OSV for Maven package
            maven_pkg = f"{group_id}:{artifact_id}"
            vulns = _query_osv(maven_pkg, clean_version, "Maven")

            for vuln in vulns:
                line = _find_dep_line_xml(pom_path, artifact_id)
                findings.append({
                    "path": "pom.xml",
                    "line": line,
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable dependency: {group_id}:{artifact_id}:{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": maven_pkg,
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                        "aliases": vuln.get("aliases", []),
                        "references": [
                            r.get("url") for r in vuln.get("references", [])[:3]
                        ],
                    },
                })

    except ET.ParseError as e:
        logger.error(f"Failed to parse pom.xml: {e}")
    except Exception as e:
        logger.error(f"Maven dependency scan failed: {e}")

    logger.info(f"Maven dependency scan found {len(findings)} vulnerabilities")
    return findings


# =============================================================================
# JAVA/GRADLE DEPENDENCY SCANNING
# =============================================================================

def scan_gradle_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Gradle dependencies for known CVEs.
    Parses build.gradle and checks against OSV.dev API.
    """
    findings = []
    repo = Path(repo_path)

    gradle_files = list(repo.glob("**/build.gradle")) + list(repo.glob("**/build.gradle.kts"))

    for gradle_file in gradle_files:
        try:
            content = gradle_file.read_text(encoding="utf-8", errors="replace")
            deps = _parse_gradle_dependencies(content)

            logger.info(
                f"Found {len(deps)} Gradle dependencies in {gradle_file.name}"
            )

            for group_id, artifact_id, version in deps:
                if not version:
                    continue

                maven_pkg = f"{group_id}:{artifact_id}"
                vulns = _query_osv(maven_pkg, version, "Maven")

                for vuln in vulns:
                    rel_path = str(gradle_file.relative_to(repo))
                    findings.append({
                        "path": rel_path,
                        "line": _find_dep_line(gradle_file, artifact_id),
                        "end_line": None,
                        "rule_id": vuln.get("id", "unknown"),
                        "message": (
                            f"Vulnerable dependency: {group_id}:{artifact_id}:{version} — "
                            f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                        ),
                        "severity": _osv_severity(vuln),
                        "metadata": {
                            "scanner": "osv-api",
                            "category": "dependency",
                            "package": maven_pkg,
                            "installed_version": version,
                            "cve_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                        },
                    })

        except Exception as e:
            logger.error(f"Gradle scan failed for {gradle_file}: {e}")

    logger.info(f"Gradle dependency scan found {len(findings)} vulnerabilities")
    return findings


def _parse_gradle_dependencies(content: str) -> List[tuple]:
    """
    Parse Gradle build file to extract dependencies.
    Handles formats:
    - implementation 'group:artifact:version'
    - implementation "group:artifact:version"
    - implementation group: 'x', name: 'y', version: 'z'
    """
    import re

    deps = []

    # Pattern: implementation 'group:artifact:version'
    pattern1 = re.compile(
        r"(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation)"
        r"\s+['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]"
    )

    for match in pattern1.finditer(content):
        deps.append((match.group(1), match.group(2), match.group(3)))

    # Pattern: implementation group: 'x', name: 'y', version: 'z'
    pattern2 = re.compile(
        r"(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation)"
        r"\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]"
    )

    for match in pattern2.finditer(content):
        deps.append((match.group(1), match.group(2), match.group(3)))

    return deps


# =============================================================================
# NODE.JS DEPENDENCY SCANNING
# =============================================================================

def scan_node_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Node.js dependencies using npm audit.
    npm is available on all platforms where Node.js is installed.
    Falls back to OSV.dev API if npm is not available.
    """
    findings = []
    repo = Path(repo_path)

    npm_path = shutil.which("npm")
    if npm_path and (repo / "package-lock.json").exists():
        return _run_npm_audit(repo_path, npm_path)

    # Fallback: parse package.json and check OSV
    return _scan_node_osv(repo_path)


def _run_npm_audit(repo_path: str, npm_path: str) -> List[Dict[str, Any]]:
    """Run npm audit for Node.js dependency scanning."""
    findings = []

    cmd = [npm_path, "audit", "--json"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=120,
            cwd=repo_path
        )

        stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""

        if stdout:
            try:
                audit_data = json.loads(stdout)
                vulnerabilities = audit_data.get("vulnerabilities", {})

                for pkg_name, vuln_info in vulnerabilities.items():
                    severity = vuln_info.get("severity", "moderate").upper()
                    via = vuln_info.get("via", [])

                    for v in via:
                        if isinstance(v, dict):
                            findings.append({
                                "path": "package.json",
                                "line": None,
                                "end_line": None,
                                "rule_id": v.get("url", "npm-audit"),
                                "message": (
                                    f"Vulnerable dependency: {pkg_name}@{vuln_info.get('range', '?')} — "
                                    f"{v.get('title', 'Vulnerability detected')}"
                                ),
                                "severity": severity,
                                "metadata": {
                                    "scanner": "npm-audit",
                                    "category": "dependency",
                                    "package": pkg_name,
                                    "installed_version": vuln_info.get("range"),
                                    "fix_available": vuln_info.get("fixAvailable", False),
                                },
                            })

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse npm audit output: {e}")

    except subprocess.TimeoutExpired:
        logger.warning("npm audit timed out")
    except Exception as e:
        logger.error(f"npm audit failed: {e}")

    logger.info(f"Node.js dependency scan found {len(findings)} vulnerabilities")
    return findings


def _scan_node_osv(repo_path: str) -> List[Dict[str, Any]]:
    """Fallback: parse package.json and check OSV.dev."""
    findings = []
    pkg_json = Path(repo_path) / "package.json"

    if not pkg_json.exists():
        return findings

    try:
        data = json.loads(pkg_json.read_text())
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        for pkg_name, version_spec in all_deps.items():
            # Clean version spec (remove ^, ~, >=, etc.)
            version = version_spec.lstrip("^~>=<")
            if not version or version == "*":
                continue

            vulns = _query_osv(pkg_name, version, "npm")
            for vuln in vulns:
                findings.append({
                    "path": "package.json",
                    "line": _find_dep_line(pkg_json, pkg_name),
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable dependency: {pkg_name}@{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": pkg_name,
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                    },
                })

    except Exception as e:
        logger.error(f"Node.js OSV scan failed: {e}")

    return findings


# =============================================================================
# OSV.dev API (Free, no auth, cross-platform)
# =============================================================================

def _query_osv(package_name: str, version: str, ecosystem: str) -> List[Dict]:
    """
    Query OSV.dev API for known vulnerabilities.
    Free API, no authentication required, works everywhere.
    https://osv.dev/docs/
    """
    import requests

    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            if vulns:
                logger.debug(
                    f"OSV found {len(vulns)} vulns for {package_name}@{version} ({ecosystem})"
                )
            return vulns
        else:
            logger.debug(
                f"OSV API returned {response.status_code} for {package_name}"
            )
    except Exception as e:
        logger.debug(f"OSV API query failed for {package_name}: {e}")

    return []


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def _find_dep_line(file_path: Path, dep_name: str) -> int:
    """Find the line number where a dependency is declared."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            if dep_name.lower() in line.lower():
                return i
    except Exception:
        pass
    return 1


def _clean_maven_version(version: str) -> str:
    """
    Clean Maven version strings for OSV.dev lookup.
    Removes suffixes like .RELEASE, .Final, -SNAPSHOT that OSV doesn't understand.
    Examples:
        2.2.1.RELEASE → 2.2.1
        5.6.15.Final → 5.6.15
        3.0.0-SNAPSHOT → 3.0.0
        2.7.18 → 2.7.18 (unchanged)
    """
    import re
    # Remove common suffixes
    cleaned = re.sub(r'[.\-](RELEASE|Final|FINAL|GA|SNAPSHOT|SP\d+|M\d+|RC\d+|CR\d+|Beta\d*|Alpha\d*)$', '', version, flags=re.IGNORECASE)
    # Remove trailing dots
    cleaned = cleaned.rstrip(".")
    return cleaned if cleaned else version


def _find_dep_line_xml(file_path: Path, artifact_id: str) -> int:
    """Find the line number of an artifactId in pom.xml."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            if artifact_id in line:
                return i
    except Exception:
        pass
    return 1


def _parse_requirements_txt(content: str) -> List[tuple]:
    """Parse requirements.txt into (package_name, version) tuples."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Handle ==, >=, <=, ~=
        for sep in ["==", ">=", "<=", "~=", "!="]:
            if sep in line:
                parts = line.split(sep, 1)
                name = parts[0].strip()
                version = parts[1].strip().split(",")[0].strip()
                # Remove extras like [security]
                if "[" in name:
                    name = name.split("[")[0]
                packages.append((name, version))
                break
        else:
            # No version specified
            name = line.split("[")[0].strip()
            if name:
                packages.append((name, ""))

    return packages


def _map_pip_audit_severity(vuln: dict) -> str:
    """Map pip-audit vulnerability to severity level."""
    vuln_id = vuln.get("id", "")
    # pip-audit doesn't always provide severity, default to HIGH for CVEs
    if vuln_id.startswith("CVE") or vuln_id.startswith("GHSA"):
        return "HIGH"
    return "MEDIUM"


def _osv_severity(vuln: dict) -> str:
    """Extract severity from OSV vulnerability data."""
    severity_list = vuln.get("severity", [])
    if severity_list:
        for s in severity_list:
            score = s.get("score", "")
            # CVSS v3 score string like "CVSS:3.1/AV:N/AC:L/..."
            if "CVSS" in score:
                # Extract base score if available
                try:
                    # Parse CVSS score
                    if s.get("type") == "CVSS_V3":
                        # Try to get numeric score from database_specific
                        pass
                except Exception:
                    pass

    # Check database_specific for severity
    db_specific = vuln.get("database_specific", {})
    severity = db_specific.get("severity", "")
    if severity:
        return severity.upper()

    # Default based on whether it has aliases (CVEs are usually HIGH+)
    aliases = vuln.get("aliases", [])
    if any(a.startswith("CVE-") for a in aliases):
        return "HIGH"

    return "MEDIUM"


# =============================================================================
# .NET / NUGET DEPENDENCY SCANNING
# =============================================================================

def scan_dotnet_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan .NET (C#/F#) dependencies for known CVEs.
    Parses .csproj files and checks against OSV.dev API.
    """
    import xml.etree.ElementTree as ET

    findings = []
    repo = Path(repo_path)

    csproj_files = list(repo.rglob("*.csproj")) + list(repo.rglob("*.fsproj"))
    logger.info(f"Found {len(csproj_files)} .NET project files")

    for csproj in csproj_files:
        try:
            tree = ET.parse(str(csproj))
            root = tree.getroot()

            # .csproj files may or may not have a namespace
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            # Find PackageReference elements
            packages = root.findall(f".//{ns}PackageReference")
            if not packages:
                packages = root.findall(".//PackageReference")

            rel_path = str(csproj.relative_to(repo))
            logger.info(f"Checking {len(packages)} NuGet packages in {rel_path}")

            for pkg in packages:
                name = pkg.get("Include", "") or pkg.get("include", "")
                version = pkg.get("Version", "") or pkg.get("version", "")

                if not name or not version:
                    continue

                # Query OSV for NuGet package
                vulns = _query_osv(name, version, "NuGet")
                for vuln in vulns:
                    line = _find_dep_line(csproj, name)
                    findings.append({
                        "path": rel_path,
                        "line": line,
                        "end_line": None,
                        "rule_id": vuln.get("id", "unknown"),
                        "message": (
                            f"Vulnerable NuGet package: {name}@{version} — "
                            f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                        ),
                        "severity": _osv_severity(vuln),
                        "metadata": {
                            "scanner": "osv-api",
                            "category": "dependency",
                            "package": name,
                            "ecosystem": "NuGet",
                            "installed_version": version,
                            "cve_id": vuln.get("id"),
                            "aliases": vuln.get("aliases", []),
                        },
                    })

        except ET.ParseError as e:
            logger.error(f"Failed to parse {csproj}: {e}")
        except Exception as e:
            logger.error(f".NET scan failed for {csproj}: {e}")

    logger.info(f".NET dependency scan found {len(findings)} vulnerabilities")
    return findings


# =============================================================================
# GO MODULE DEPENDENCY SCANNING
# =============================================================================

def scan_go_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Go module dependencies for known CVEs.
    Parses go.mod/go.sum and checks against OSV.dev API.
    """
    findings = []
    repo = Path(repo_path)
    go_mod = repo / "go.mod"

    if not go_mod.exists():
        return findings

    try:
        content = go_mod.read_text(encoding="utf-8", errors="replace")
        deps = _parse_go_mod(content)
        logger.info(f"Found {len(deps)} Go dependencies")

        for module, version in deps:
            # Go versions start with 'v', OSV expects without
            clean_version = version.lstrip("v")
            vulns = _query_osv(module, clean_version, "Go")

            for vuln in vulns:
                line = _find_dep_line(go_mod, module)
                findings.append({
                    "path": "go.mod",
                    "line": line,
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable Go module: {module}@{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": module,
                        "ecosystem": "Go",
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                        "aliases": vuln.get("aliases", []),
                    },
                })

    except Exception as e:
        logger.error(f"Go dependency scan failed: {e}")

    logger.info(f"Go dependency scan found {len(findings)} vulnerabilities")
    return findings


def _parse_go_mod(content: str) -> List[tuple]:
    """Parse go.mod require block."""
    import re
    deps = []
    in_require = False

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")" and in_require:
            in_require = False
            continue
        if in_require:
            match = re.match(r'(\S+)\s+(v[\d.]+\S*)', line)
            if match:
                deps.append((match.group(1), match.group(2)))
        elif line.startswith("require "):
            match = re.match(r'require\s+(\S+)\s+(v[\d.]+\S*)', line)
            if match:
                deps.append((match.group(1), match.group(2)))

    return deps


# =============================================================================
# RUST / CARGO DEPENDENCY SCANNING
# =============================================================================

def scan_rust_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Rust/Cargo dependencies for known CVEs.
    Parses Cargo.toml and checks against OSV.dev API.
    """
    findings = []
    repo = Path(repo_path)
    cargo_toml = repo / "Cargo.toml"

    if not cargo_toml.exists():
        return findings

    try:
        content = cargo_toml.read_text(encoding="utf-8", errors="replace")
        deps = _parse_cargo_toml(content)
        logger.info(f"Found {len(deps)} Rust dependencies")

        for name, version in deps:
            vulns = _query_osv(name, version, "crates.io")
            for vuln in vulns:
                line = _find_dep_line(cargo_toml, name)
                findings.append({
                    "path": "Cargo.toml",
                    "line": line,
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable crate: {name}@{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": name,
                        "ecosystem": "crates.io",
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                    },
                })

    except Exception as e:
        logger.error(f"Rust dependency scan failed: {e}")

    logger.info(f"Rust dependency scan found {len(findings)} vulnerabilities")
    return findings


def _parse_cargo_toml(content: str) -> List[tuple]:
    """Parse Cargo.toml dependencies."""
    import re
    deps = []
    in_deps = False

    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r'\[(.*dependencies.*)\]', stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped:
            match = re.match(r'(\w[\w-]*)\s*=\s*"([^"]+)"', stripped)
            if match:
                deps.append((match.group(1), match.group(2)))
            else:
                # version = "x.y.z" format
                match = re.match(r'(\w[\w-]*)\s*=\s*\{.*version\s*=\s*"([^"]+)"', stripped)
                if match:
                    deps.append((match.group(1), match.group(2)))

    return deps


# =============================================================================
# RUBY / BUNDLER DEPENDENCY SCANNING
# =============================================================================

def scan_ruby_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan Ruby/Bundler dependencies for known CVEs.
    Parses Gemfile.lock and checks against OSV.dev API.
    """
    findings = []
    repo = Path(repo_path)
    gemfile_lock = repo / "Gemfile.lock"

    if not gemfile_lock.exists():
        return findings

    try:
        content = gemfile_lock.read_text(encoding="utf-8", errors="replace")
        deps = _parse_gemfile_lock(content)
        logger.info(f"Found {len(deps)} Ruby gems")

        for name, version in deps:
            vulns = _query_osv(name, version, "RubyGems")
            for vuln in vulns:
                findings.append({
                    "path": "Gemfile.lock",
                    "line": _find_dep_line(gemfile_lock, name),
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable gem: {name}@{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": name,
                        "ecosystem": "RubyGems",
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                    },
                })

    except Exception as e:
        logger.error(f"Ruby dependency scan failed: {e}")

    logger.info(f"Ruby dependency scan found {len(findings)} vulnerabilities")
    return findings


def _parse_gemfile_lock(content: str) -> List[tuple]:
    """Parse Gemfile.lock for gem versions."""
    import re
    deps = []
    in_specs = False

    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not line.startswith("    "):
                in_specs = False
                continue
            match = re.match(r'\s{4}(\S+)\s+\(([^)]+)\)', line)
            if match:
                deps.append((match.group(1), match.group(2)))

    return deps


# =============================================================================
# PHP / COMPOSER DEPENDENCY SCANNING
# =============================================================================

def scan_php_dependencies(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan PHP/Composer dependencies for known CVEs.
    Parses composer.lock and checks against OSV.dev API.
    """
    findings = []
    repo = Path(repo_path)
    composer_lock = repo / "composer.lock"

    if not composer_lock.exists():
        return findings

    try:
        data = json.loads(composer_lock.read_text(encoding="utf-8", errors="replace"))
        packages = data.get("packages", []) + data.get("packages-dev", [])
        logger.info(f"Found {len(packages)} PHP packages")

        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")

            if not name or not version:
                continue

            vulns = _query_osv(name, version, "Packagist")
            for vuln in vulns:
                findings.append({
                    "path": "composer.lock",
                    "line": None,
                    "end_line": None,
                    "rule_id": vuln.get("id", "unknown"),
                    "message": (
                        f"Vulnerable PHP package: {name}@{version} — "
                        f"{vuln.get('id')}: {vuln.get('summary', 'No description')}"
                    ),
                    "severity": _osv_severity(vuln),
                    "metadata": {
                        "scanner": "osv-api",
                        "category": "dependency",
                        "package": name,
                        "ecosystem": "Packagist",
                        "installed_version": version,
                        "cve_id": vuln.get("id"),
                    },
                })

    except Exception as e:
        logger.error(f"PHP dependency scan failed: {e}")

    logger.info(f"PHP dependency scan found {len(findings)} vulnerabilities")
    return findings
