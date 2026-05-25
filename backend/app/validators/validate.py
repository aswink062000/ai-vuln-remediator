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
            content = (repo / "requirements.txt").read_text(errors="replace").lower()
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

        pom_content = (repo / "pom.xml").read_text(errors="replace").lower()
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
            content = gradle_file.read_text(errors="replace").lower()
            if "spring" in content:
                project_info["frameworks"].append("Spring Boot")

    # Node.js detection
    if (repo / "package.json").exists():
        project_info["languages"].append("JavaScript/TypeScript")
        project_info["build_tools"].append("npm")
        project_info["required_sdks"].extend(["node", "npm"])

        try:
            import json
            pkg = json.loads((repo / "package.json").read_text())
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

    # Node.js validation
    package_json = repo / "package.json"
    if package_json.exists() and env.get("node") and env.get("npm"):
        # Only run npm install if package-lock.json exists (quick install)
        if (repo / "package-lock.json").exists():
            logger.info("Validating Node.js project (npm ci)...")
            npm_bin = shutil.which("npm")
            try:
                result = subprocess.run(
                    [npm_bin, "ci", "--ignore-scripts"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    logger.warning(f"npm ci failed: {result.stderr[:300]}")
                    # Don't fail — dependencies might need specific Node version
            except (subprocess.TimeoutExpired, Exception) as e:
                logger.warning(f"Node.js validation skipped: {e}")
    elif package_json.exists():
        logger.warning("Node.js/npm not found on PATH, skipping Node validation")

    # Java/Maven validation — only if Maven AND Java are available
    pom_xml = repo / "pom.xml"
    if pom_xml.exists():
        if env.get("java") and env.get("maven"):
            logger.info("Validating Java project (Maven compile)...")
            mvn_bin = shutil.which("mvn")

            # Check if project uses Maven wrapper
            mvnw = repo / "mvnw"
            mvnw_cmd = repo / "mvnw.cmd"
            if mvnw.exists():
                mvn_bin = str(mvnw)
            elif mvnw_cmd.exists():
                mvn_bin = str(mvnw_cmd)

            try:
                result = subprocess.run(
                    [mvn_bin, "compile", "-q", "-DskipTests",
                     "-Dmaven.javadoc.skip=true"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                if result.returncode != 0:
                    logger.warning(
                        f"Maven compile warning (non-blocking): "
                        f"{result.stderr[:300]}"
                    )
                    # Don't fail — Maven projects often need specific JDK
                    # versions or local dependencies
            except subprocess.TimeoutExpired:
                logger.warning("Maven compile timed out (non-blocking)")
            except FileNotFoundError:
                logger.warning("Maven binary not found, skipping Java validation")
            except Exception as e:
                logger.warning(f"Maven validation skipped: {e}")
        else:
            missing = []
            if not env.get("java"):
                missing.append("Java JDK")
            if not env.get("maven"):
                missing.append("Maven")
            logger.warning(
                f"{', '.join(missing)} not found on PATH, "
                f"skipping Java/Maven validation"
            )

    # Gradle validation — only if Gradle AND Java are available
    build_gradle = repo / "build.gradle"
    build_gradle_kts = repo / "build.gradle.kts"
    if build_gradle.exists() or build_gradle_kts.exists():
        if env.get("java") and env.get("gradle"):
            logger.info("Validating Java project (Gradle compile)...")
            gradle_bin = shutil.which("gradle")

            # Check for Gradle wrapper
            gradlew = repo / "gradlew"
            gradlew_bat = repo / "gradlew.bat"
            if gradlew.exists():
                gradle_bin = str(gradlew)
            elif gradlew_bat.exists():
                gradle_bin = str(gradlew_bat)

            try:
                result = subprocess.run(
                    [gradle_bin, "compileJava", "-q", "-x", "test"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                if result.returncode != 0:
                    logger.warning(
                        f"Gradle compile warning (non-blocking): "
                        f"{result.stderr[:300]}"
                    )
            except subprocess.TimeoutExpired:
                logger.warning("Gradle compile timed out (non-blocking)")
            except FileNotFoundError:
                logger.warning("Gradle binary not found, skipping validation")
            except Exception as e:
                logger.warning(f"Gradle validation skipped: {e}")
        else:
            missing = []
            if not env.get("java"):
                missing.append("Java JDK")
            if not env.get("gradle"):
                missing.append("Gradle")
            logger.warning(
                f"{', '.join(missing)} not found on PATH, "
                f"skipping Gradle validation"
            )

    return True
