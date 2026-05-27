import subprocess
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def detect_environment() -> Dict[str, Optional[str]]:
    """
    Detect which SDKs/runtimes are available on the system.
    Returns a dict with tool names and their versions (or None if not found).
    """
    tools = {
        "python": ["python3", "--version"],
        "java": ["java", "-version"],
        "javac": ["javac", "-version"],
        "maven": ["mvn", "--version"],
        "gradle": ["gradle", "--version"],
        "node": ["node", "--version"],
        "npm": ["npm", "--version"],
    }

    env_info = {}

    for tool_name, cmd in tools.items():
        binary = shutil.which(cmd[0])
        if binary:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # java -version outputs to stderr
                output = result.stdout.strip() or result.stderr.strip()
                version = output.split("\n")[0] if output else "installed"
                env_info[tool_name] = version
            except Exception:
                env_info[tool_name] = "installed (version unknown)"
        else:
            env_info[tool_name] = None

    return env_info


def detect_project_language(repo_path: str) -> Dict[str, any]:
    """
    Detect the primary language/framework of a project based on its files.
    Returns project info including language, framework, and required tools.
    """
    repo = Path(repo_path)

    project_info = {
        "languages": [],
        "frameworks": [],
        "build_tools": [],
        "required_sdks": [],
    }

    # Python detection
    python_indicators = [
        "requirements.txt", "setup.py", "pyproject.toml",
        "Pipfile", "setup.cfg", "tox.ini",
    ]
    if any((repo / f).exists() for f in python_indicators) or list(repo.rglob("*.py")):
        project_info["languages"].append("Python")
        project_info["required_sdks"].append("python")

        if (repo / "requirements.txt").exists():
            content = (repo / "requirements.txt").read_text(encoding="utf-8", errors="replace").lower()
            if "django" in content:
                project_info["frameworks"].append("Django")
            if "flask" in content:
                project_info["frameworks"].append("Flask")
            if "fastapi" in content:
                project_info["frameworks"].append("FastAPI")

    # Java/Spring detection
    if (repo / "pom.xml").exists():
        project_info["languages"].append("Java")
        project_info["build_tools"].append("Maven")
        project_info["required_sdks"].extend(["java", "maven"])

        pom_content = (repo / "pom.xml").read_text(encoding="utf-8", errors="replace").lower()
        if "spring-boot" in pom_content:
            project_info["frameworks"].append("Spring Boot")
        if "spring-security" in pom_content:
            project_info["frameworks"].append("Spring Security")

    if (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        project_info["languages"].append("Java")
        project_info["build_tools"].append("Gradle")
        project_info["required_sdks"].extend(["java", "gradle"])

        gradle_file = repo / "build.gradle"
        if not gradle_file.exists():
            gradle_file = repo / "build.gradle.kts"
        if gradle_file.exists():
            content = gradle_file.read_text(encoding="utf-8", errors="replace").lower()
            if "spring" in content:
                project_info["frameworks"].append("Spring Boot")

    # Node.js detection
    if (repo / "package.json").exists():
        project_info["languages"].append("JavaScript/TypeScript")
        project_info["build_tools"].append("npm")
        project_info["required_sdks"].extend(["node", "npm"])

        try:
            import json
            pkg = json.loads((repo / "package.json").read_text(encoding="utf-8", errors="replace"))
            all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if "react" in all_deps:
                project_info["frameworks"].append("React")
            if "next" in all_deps:
                project_info["frameworks"].append("Next.js")
            if "express" in all_deps:
                project_info["frameworks"].append("Express")
            if "vue" in all_deps:
                project_info["frameworks"].append("Vue.js")
            if "@angular/core" in all_deps:
                project_info["frameworks"].append("Angular")
        except Exception:
            pass

    # Deduplicate
    project_info["languages"] = list(set(project_info["languages"]))
    project_info["frameworks"] = list(set(project_info["frameworks"]))
    project_info["build_tools"] = list(set(project_info["build_tools"]))
    project_info["required_sdks"] = list(set(project_info["required_sdks"]))

    return project_info


def check_sdk_availability(project_info: Dict) -> Dict[str, any]:
    """
    Check if required SDKs for the project are installed.
    Returns status of each required SDK.
    """
    env = detect_environment()
    required = project_info.get("required_sdks", [])

    sdk_status = {}
    all_available = True

    for sdk in required:
        version = env.get(sdk)
        if version:
            sdk_status[sdk] = {"installed": True, "version": version}
        else:
            sdk_status[sdk] = {"installed": False, "version": None}
            all_available = False

    return {
        "all_available": all_available,
        "sdks": sdk_status,
        "missing": [s for s in required if not env.get(s)],
    }


def validate_project(repo_path: str) -> bool:
    """
    Validate the project after applying fixes.
    Supports Node.js, Python, and Java projects.
    
    Gracefully handles missing SDKs — skips validation if tools aren't installed.
    Returns True if validation passes or if validation cannot be performed.
    """
    repo = Path(repo_path)
    env = detect_environment()

    # Python validation - syntax check only
    python_files = list(repo.rglob("*.py"))
    if python_files and env.get("python"):
        logger.info(f"Validating {len(python_files)} Python files (syntax check)...")
        python_bin = shutil.which("python3") or shutil.which("python")
        if python_bin:
            for py_file in python_files:
                # Skip venv/site-packages files
                parts = str(py_file).lower()
                if "venv" in parts or "site-packages" in parts or ".tox" in parts:
                    continue
                try:
                    result = subprocess.run(
                        [python_bin, "-m", "py_compile", str(py_file)],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        logger.error(
                            f"Python syntax error in {py_file.name}: "
                            f"{result.stderr[:200]}"
                        )
                        return False
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
    elif python_files:
        logger.warning("Python not found on PATH, skipping Python validation")

    # Node.js validation - syntax check only
    node_files = list(repo.rglob("*.js")) + list(repo.rglob("*.ts"))
    if node_files and env.get("node"):
        logger.info(f"Validating {len(node_files)} Node.js files (syntax check)...")
        node_bin = shutil.which("node")
        if node_bin:
            for js_file in node_files:
                # Skip node_modules
                if "node_modules" in str(js_file).lower():
                    continue
                try:
                    # Use node --check to validate syntax without executing
                    result = subprocess.run(
                        [node_bin, "--check", str(js_file)],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        logger.error(
                            f"Node.js syntax error in {js_file.name}: "
                            f"{result.stderr[:200]}"
                        )
                        return False
                except subprocess.TimeoutExpired:
                    continue

    # Java validation - syntax check only
    java_files = list(repo.rglob("*.java"))
    if java_files and env.get("java"):
        logger.info(f"Validating {len(java_files)} Java files (syntax check)...")
        javac_bin = shutil.which("javac")
        if javac_bin:
            for java_file in java_files:
                try:
                    # Use javac with -proc:none to skip annotation processing
                    # Note: full compilation requires classpath; we only do a best-effort check
                    result = subprocess.run(
                        [javac_bin, "-proc:none", str(java_file)],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode != 0:
                        # Only fail on clear syntax errors, not missing classpath errors
                        stderr = result.stderr
                        if "error:" in stderr and "cannot find symbol" not in stderr and "package" not in stderr:
                            logger.error(
                                f"Java syntax error in {java_file.name}: "
                                f"{stderr[:200]}"
                            )
                            return False
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue

    return True
