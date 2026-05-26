"""
Best Practices & Outdated Dependency Scanner.

Detects issues that don't have CVEs but are still security/maintenance risks:
- Deprecated artifacts (mysql-connector-java → mysql-connector-j)
- EOL/obsolete versions (JUnit 3, Python 2, etc.)
- Missing configurations (no Java version, no encoding)
- Outdated major versions (2+ majors behind latest)

This fills the gap between CVE-only scanning and full code review.
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


# Deprecated artifacts — old name → new name (versions fetched dynamically)
DEPRECATED_ARTIFACTS = {
    # Java/Maven
    "mysql:mysql-connector-java": {
        "replacement": "com.mysql:mysql-connector-j",
        "reason": "mysql-connector-java is deprecated. Use mysql-connector-j instead.",
        "severity": "MEDIUM",
    },
    "junit:junit": {
        "replacement": "org.junit.jupiter:junit-jupiter",
        "reason": "JUnit 4 is in maintenance mode. JUnit 5 has better security and features.",
        "severity": "MEDIUM",
    },
    "log4j:log4j": {
        "replacement": "org.apache.logging.log4j:log4j-core",
        "reason": "Log4j 1.x is EOL and has critical vulnerabilities (Log4Shell).",
        "severity": "CRITICAL",
    },
    "commons-logging:commons-logging": {
        "replacement": "org.slf4j:slf4j-api",
        "reason": "Commons Logging is outdated. Use SLF4J for modern logging.",
        "severity": "LOW",
    },
    "javax.servlet:javax.servlet-api": {
        "replacement": "jakarta.servlet:jakarta.servlet-api",
        "reason": "javax.servlet is deprecated. Jakarta EE is the successor.",
        "severity": "MEDIUM",
    },
    "javax.persistence:javax.persistence-api": {
        "replacement": "jakarta.persistence:jakarta.persistence-api",
        "reason": "javax.persistence is deprecated. Use Jakarta Persistence.",
        "severity": "MEDIUM",
    },
    # Python
    "nose": {
        "replacement": "pytest",
        "reason": "nose is unmaintained since 2015. Use pytest.",
        "severity": "LOW",
        "ecosystem": "python",
    },
    "pycrypto": {
        "replacement": "pycryptodome",
        "reason": "pycrypto is unmaintained and has vulnerabilities. Use pycryptodome.",
        "severity": "HIGH",
        "ecosystem": "python",
    },
    # Node.js
    "request": {
        "replacement": "axios or node-fetch",
        "reason": "request is deprecated since 2020. Use axios or node-fetch.",
        "severity": "MEDIUM",
        "ecosystem": "npm",
    },
    "moment": {
        "replacement": "dayjs or date-fns",
        "reason": "moment.js is in maintenance mode. Use dayjs (2KB) or date-fns.",
        "severity": "LOW",
        "ecosystem": "npm",
    },
}

# Known EOL thresholds (major versions that are end-of-life)
# These are just major version thresholds — actual latest is fetched dynamically
EOL_THRESHOLDS = {
    "junit:junit": {"eol_major": 3, "message": "JUnit 3.x is extremely old and unsupported"},
    "org.springframework.boot:spring-boot-starter-parent": {"eol_major": 1, "message": "Spring Boot 1.x is EOL"},
}

# How many major versions behind = "outdated"
MAJOR_VERSION_LAG_THRESHOLD = 2  # 2+ majors behind latest = flagged


def _fetch_latest_maven_version(group_id: str, artifact_id: str) -> str:
    """Fetch latest version from Maven Central (real-time)."""
    import requests
    try:
        url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            docs = resp.json().get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("latestVersion", "")
    except Exception:
        pass
    return ""


def _fetch_latest_pypi_version(package: str) -> str:
    """Fetch latest version from PyPI (real-time)."""
    import requests
    try:
        resp = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=8)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version", "")
    except Exception:
        pass
    return ""


def _fetch_latest_npm_version(package: str) -> str:
    """Fetch latest version from npm registry (real-time)."""
    import requests
    try:
        resp = requests.get(f"https://registry.npmjs.org/{package}/latest", timeout=8)
        if resp.status_code == 200:
            return resp.json().get("version", "")
    except Exception:
        pass
    return ""


def _get_major_version(version: str) -> int:
    """Extract major version number."""
    try:
        return int(re.findall(r'\d+', version)[0])
    except (IndexError, ValueError):
        return 0


def _is_outdated(current_version: str, latest_version: str) -> bool:
    """Check if current version is significantly behind latest (2+ majors)."""
    current_major = _get_major_version(current_version)
    latest_major = _get_major_version(latest_version)

    if current_major == 0 or latest_major == 0:
        return False

    return (latest_major - current_major) >= MAJOR_VERSION_LAG_THRESHOLD

# Missing configuration checks
MISSING_CONFIGS = {
    "pom.xml": [
        {
            "check": "maven.compiler.source",
            "pattern": r"<maven\.compiler\.source>|<java\.version>|<release>",
            "message": "No Java version specified. This can cause inconsistent builds and unsupported runtime issues.",
            "fix": '<properties>\n    <maven.compiler.source>17</maven.compiler.source>\n    <maven.compiler.target>17</maven.compiler.target>\n</properties>',
            "severity": "MEDIUM",
        },
        {
            "check": "encoding",
            "pattern": r"<project\.build\.sourceEncoding>",
            "message": "No source encoding specified. May cause platform-dependent build issues.",
            "fix": '<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>',
            "severity": "LOW",
        },
    ],
    "package.json": [
        {
            "check": "engines",
            "pattern": r'"engines"',
            "message": "No Node.js engine version specified. May run on unsupported Node versions.",
            "severity": "LOW",
        },
    ],
}


def run_best_practices_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan for best practice violations, deprecated dependencies, and outdated versions.
    Returns findings in the standard format.
    """
    logger.info("Running best practices scan...")
    repo = Path(repo_path)
    findings = []

    # Check Maven (pom.xml)
    pom_files = list(repo.rglob("pom.xml"))
    for pom in pom_files:
        rel_path = str(pom.relative_to(repo))
        if any(skip in rel_path for skip in ["node_modules", ".git", "target"]):
            continue
        findings.extend(_check_maven_best_practices(pom, rel_path))

    # Check Python (requirements.txt, setup.py)
    for req_file in repo.rglob("requirements*.txt"):
        rel_path = str(req_file.relative_to(repo))
        if "node_modules" in rel_path or ".venv" in rel_path:
            continue
        findings.extend(_check_python_best_practices(req_file, rel_path))

    # Check Node.js (package.json)
    pkg_files = list(repo.rglob("package.json"))
    for pkg in pkg_files:
        rel_path = str(pkg.relative_to(repo))
        if "node_modules" in rel_path:
            continue
        findings.extend(_check_node_best_practices(pkg, rel_path))

    logger.info(f"Best practices scan found {len(findings)} issues")
    return findings


def _check_maven_best_practices(pom_path: Path, rel_path: str) -> List[Dict]:
    """Check Maven pom.xml for best practice violations with dynamic version lookup."""
    findings = []

    try:
        content = pom_path.read_text(encoding="utf-8", errors="replace")

        # Check deprecated artifacts
        for artifact_key, info in DEPRECATED_ARTIFACTS.items():
            if info.get("ecosystem") and info["ecosystem"] != "maven":
                continue

            parts = artifact_key.split(":")
            if len(parts) != 2:
                continue

            group_id, artifact_id = parts
            if f"<artifactId>{artifact_id}</artifactId>" in content and f"<groupId>{group_id}</groupId>" in content:
                # Fetch latest version of the replacement dynamically
                replacement = info["replacement"]
                rep_parts = replacement.split(":")
                latest_version = ""
                if len(rep_parts) == 2:
                    latest_version = _fetch_latest_maven_version(rep_parts[0], rep_parts[1])

                line = _find_line(content, artifact_id)
                version_text = f"@{latest_version}" if latest_version else ""

                findings.append({
                    "path": rel_path,
                    "line": line,
                    "end_line": line,
                    "rule_id": f"deprecated-artifact-{artifact_id}",
                    "message": (
                        f"Deprecated: {artifact_key} — {info['reason']} "
                        f"Replace with: {replacement}{version_text}"
                    ),
                    "severity": info["severity"],
                    "metadata": {
                        "scanner": "best-practices",
                        "category": "best-practice",
                        "package": artifact_key,
                        "replacement": replacement,
                        "recommended_version": latest_version,
                        "fix_guidance": f"Replace {artifact_key} with {replacement} version {latest_version}" if latest_version else f"Replace {artifact_key} with {replacement}",
                    },
                })

        # Also check <parent> section (Spring Boot parent POM)
        import xml.etree.ElementTree as ET
        try:
            tree = ET.parse(str(pom_path))
            root = tree.getroot()
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            # Check parent
            parent = root.find(f"{ns}parent")
            if parent is not None:
                p_group = parent.findtext(f"{ns}groupId", "")
                p_artifact = parent.findtext(f"{ns}artifactId", "")
                p_version = parent.findtext(f"{ns}version", "")

                if p_group and p_artifact and p_version:
                    full_key = f"{p_group}:{p_artifact}"
                    clean_ver = re.sub(r'[.\-](RELEASE|Final|GA|SNAPSHOT)$', '', p_version, flags=re.IGNORECASE).rstrip(".")

                    # Fetch latest version
                    latest = _fetch_latest_maven_version(p_group, p_artifact)
                    if latest and _is_outdated(clean_ver, latest):
                        findings.append({
                            "path": rel_path,
                            "line": _find_line(content, p_artifact),
                            "end_line": None,
                            "rule_id": f"outdated-parent-{p_artifact}",
                            "message": (
                                f"Outdated parent: {full_key}@{p_version} — Latest is {latest}. "
                                f"Upgrade recommended for security patches and bug fixes."
                            ),
                            "severity": "HIGH",
                            "metadata": {
                                "scanner": "best-practices",
                                "category": "best-practice",
                                "package": full_key,
                                "installed_version": p_version,
                                "latest_version": latest,
                                "fix_versions": [latest],
                            },
                        })

            deps = root.findall(f".//{ns}dependency")
            for dep in deps:
                g = dep.findtext(f"{ns}groupId", "")
                a = dep.findtext(f"{ns}artifactId", "")
                v = dep.findtext(f"{ns}version", "")

                if not g or not a or not v or v.startswith("${"):
                    continue

                # Clean version suffix (.RELEASE, .Final, etc.)
                clean_v = re.sub(r'[.\-](RELEASE|Final|GA|SNAPSHOT)$', '', v, flags=re.IGNORECASE).rstrip(".")

                # Check EOL thresholds
                full_key = f"{g}:{a}"
                eol_info = EOL_THRESHOLDS.get(full_key)
                if eol_info:
                    current_major = _get_major_version(clean_v)
                    if current_major <= eol_info["eol_major"]:
                        findings.append({
                            "path": rel_path,
                            "line": _find_line(content, a),
                            "end_line": None,
                            "rule_id": f"eol-version-{a}",
                            "message": f"EOL: {full_key}@{v} — {eol_info['message']}",
                            "severity": "HIGH",
                            "metadata": {
                                "scanner": "best-practices",
                                "category": "best-practice",
                                "package": full_key,
                                "installed_version": v,
                            },
                        })
                    continue

                # Fetch latest and check if significantly outdated
                latest = _fetch_latest_maven_version(g, a)
                if latest and _is_outdated(clean_v, latest):
                    findings.append({
                        "path": rel_path,
                        "line": _find_line(content, a),
                        "end_line": None,
                        "rule_id": f"outdated-version-{a}",
                        "message": (
                            f"Outdated: {full_key}@{v} — Latest is {latest} "
                            f"({_get_major_version(latest) - _get_major_version(v)} major versions behind)"
                        ),
                        "severity": "MEDIUM",
                        "metadata": {
                            "scanner": "best-practices",
                            "category": "best-practice",
                            "package": full_key,
                            "installed_version": v,
                            "latest_version": latest,
                            "fix_versions": [latest],
                        },
                    })

        except ET.ParseError:
            pass

        # Check missing configurations
        for config_check in MISSING_CONFIGS.get("pom.xml", []):
            if not re.search(config_check["pattern"], content):
                findings.append({
                    "path": rel_path,
                    "line": 1,
                    "end_line": 1,
                    "rule_id": f"missing-config-{config_check['check']}",
                    "message": config_check["message"],
                    "severity": config_check["severity"],
                    "metadata": {
                        "scanner": "best-practices",
                        "category": "best-practice",
                        "fix_guidance": config_check.get("fix", ""),
                    },
                })

    except Exception as e:
        logger.warning(f"Maven best practices check failed for {rel_path}: {e}")

    return findings


def _check_python_best_practices(req_path: Path, rel_path: str) -> List[Dict]:
    """Check Python requirements for deprecated and outdated packages (dynamic)."""
    findings = []

    try:
        content = req_path.read_text(encoding="utf-8", errors="replace")

        for line_num, line in enumerate(content.splitlines(), 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("-"):
                continue

            # Parse package name and version
            match = re.match(r'([a-zA-Z0-9_-]+)\s*[=<>!~]=?\s*([\d.]+)?', line_stripped)
            if not match:
                continue

            pkg_name = match.group(1).lower()
            current_version = match.group(2) or ""

            # Check deprecated
            for artifact_key, info in DEPRECATED_ARTIFACTS.items():
                if info.get("ecosystem") != "python":
                    continue
                if pkg_name == artifact_key.lower():
                    findings.append({
                        "path": rel_path,
                        "line": line_num,
                        "end_line": line_num,
                        "rule_id": f"deprecated-package-{pkg_name}",
                        "message": f"Deprecated: {pkg_name} — {info['reason']} Replace with: {info['replacement']}",
                        "severity": info["severity"],
                        "metadata": {
                            "scanner": "best-practices",
                            "category": "best-practice",
                            "package": pkg_name,
                            "replacement": info["replacement"],
                        },
                    })
                    break

            # Check if significantly outdated (fetch latest from PyPI)
            if current_version and pkg_name not in [k.lower() for k in DEPRECATED_ARTIFACTS if DEPRECATED_ARTIFACTS[k].get("ecosystem") == "python"]:
                latest = _fetch_latest_pypi_version(pkg_name)
                if latest and _is_outdated(current_version, latest):
                    findings.append({
                        "path": rel_path,
                        "line": line_num,
                        "end_line": line_num,
                        "rule_id": f"outdated-package-{pkg_name}",
                        "message": (
                            f"Outdated: {pkg_name}@{current_version} — Latest is {latest} "
                            f"({_get_major_version(latest) - _get_major_version(current_version)} major versions behind)"
                        ),
                        "severity": "MEDIUM",
                        "metadata": {
                            "scanner": "best-practices",
                            "category": "best-practice",
                            "package": pkg_name,
                            "installed_version": current_version,
                            "latest_version": latest,
                            "fix_versions": [latest],
                        },
                    })

    except Exception as e:
        logger.warning(f"Python best practices check failed: {e}")

    return findings


def _check_node_best_practices(pkg_path: Path, rel_path: str) -> List[Dict]:
    """Check Node.js package.json for deprecated and outdated packages (dynamic)."""
    findings = []

    try:
        content = pkg_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

        for pkg_name, version_spec in all_deps.items():
            # Clean version
            current_version = version_spec.lstrip("^~>=<")

            # Check deprecated
            for artifact_key, info in DEPRECATED_ARTIFACTS.items():
                if info.get("ecosystem") != "npm":
                    continue
                if pkg_name.lower() == artifact_key.lower():
                    findings.append({
                        "path": rel_path,
                        "line": _find_line(content, pkg_name),
                        "end_line": None,
                        "rule_id": f"deprecated-package-{pkg_name}",
                        "message": f"Deprecated: {pkg_name} — {info['reason']} Replace with: {info['replacement']}",
                        "severity": info["severity"],
                        "metadata": {
                            "scanner": "best-practices",
                            "category": "best-practice",
                            "package": pkg_name,
                            "replacement": info["replacement"],
                        },
                    })
                    break
            else:
                # Check if significantly outdated (fetch latest from npm)
                if current_version and current_version != "*":
                    latest = _fetch_latest_npm_version(pkg_name)
                    if latest and _is_outdated(current_version, latest):
                        findings.append({
                            "path": rel_path,
                            "line": _find_line(content, pkg_name),
                            "end_line": None,
                            "rule_id": f"outdated-package-{pkg_name}",
                            "message": (
                                f"Outdated: {pkg_name}@{current_version} — Latest is {latest} "
                                f"({_get_major_version(latest) - _get_major_version(current_version)} major versions behind)"
                            ),
                            "severity": "MEDIUM",
                            "metadata": {
                                "scanner": "best-practices",
                                "category": "best-practice",
                                "package": pkg_name,
                                "installed_version": current_version,
                                "latest_version": latest,
                                "fix_versions": [latest],
                            },
                        })

        # Check missing configs
        for config_check in MISSING_CONFIGS.get("package.json", []):
            if not re.search(config_check["pattern"], content):
                findings.append({
                    "path": rel_path,
                    "line": 1,
                    "end_line": 1,
                    "rule_id": f"missing-config-{config_check['check']}",
                    "message": config_check["message"],
                    "severity": config_check["severity"],
                    "metadata": {
                        "scanner": "best-practices",
                        "category": "best-practice",
                    },
                })

    except Exception as e:
        logger.warning(f"Node best practices check failed: {e}")

    return findings


def _find_line(content: str, search: str) -> int:
    """Find line number of a string in content."""
    for i, line in enumerate(content.splitlines(), 1):
        if search in line:
            return i
    return 1


def _version_less_than(current: str, threshold: str) -> bool:
    """Simple version comparison."""
    try:
        current_parts = [int(x) for x in re.findall(r'\d+', current)[:3]]
        threshold_parts = [int(x) for x in re.findall(r'\d+', threshold)[:3]]

        # Pad to same length
        while len(current_parts) < 3:
            current_parts.append(0)
        while len(threshold_parts) < 3:
            threshold_parts.append(0)

        return current_parts < threshold_parts
    except (ValueError, IndexError):
        return False
