import subprocess
import json
import os
import sys
import shutil
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

PLATFORM = platform.system()  # "Windows", "Darwin", "Linux"
IS_WINDOWS = PLATFORM == "Windows"


def _get_semgrep_path():
    """
    Find the semgrep binary across Windows, macOS, and Linux.
    Checks:
    1. Same venv/env as the running Python interpreter
    2. Platform-specific common install locations
    3. System PATH
    """
    binary_name = "semgrep.exe" if IS_WINDOWS else "semgrep"

    # 1. Check in the same directory as the running Python interpreter
    python_dir = Path(sys.executable).parent
    semgrep_in_env = python_dir / binary_name
    if semgrep_in_env.exists():
        return str(semgrep_in_env)

    # On Windows, also check the Scripts subdirectory
    if IS_WINDOWS:
        scripts_dir = python_dir / "Scripts"
        semgrep_in_scripts = scripts_dir / binary_name
        if semgrep_in_scripts.exists():
            return str(semgrep_in_scripts)

        # User site-packages Scripts (pip install --user)
        user_scripts = (
            Path.home() / "AppData" / "Roaming" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts" / binary_name
        )
        if user_scripts.exists():
            return str(user_scripts)

        # Local Programs install
        local_scripts = (
            Path.home() / "AppData" / "Local" / "Programs" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts" / binary_name
        )
        if local_scripts.exists():
            return str(local_scripts)

    else:
        # macOS / Linux: check common locations
        common_paths = [
            Path.home() / ".local" / "bin" / binary_name,       # pip install --user
            Path("/usr/local/bin") / binary_name,                # system-wide
            Path("/opt/homebrew/bin") / binary_name,             # macOS Homebrew ARM
            Path("/usr/local/opt/semgrep/bin") / binary_name,   # macOS Homebrew Intel
        ]
        for p in common_paths:
            if p.exists():
                return str(p)

    # 2. Fall back to system PATH
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        return semgrep_path

    raise FileNotFoundError(
        "semgrep not found. Install it with: pip install semgrep\n"
        + (
            "On Windows, ensure the Python Scripts folder is in your PATH.\n"
            "Typical: C:\\Users\\<user>\\AppData\\Local\\Programs\\Python\\Python3x\\Scripts\\"
            if IS_WINDOWS
            else "On macOS/Linux, ensure ~/.local/bin is in your PATH.\n"
            "Or install via: brew install semgrep (macOS) / pip install semgrep"
        )
    )


def _get_subprocess_env():
    """
    Build environment for subprocess calls.
    Ensures companion binaries (like pysemgrep) are discoverable
    by prepending relevant directories to PATH.
    Works on Windows, macOS, and Linux.
    """
    env = os.environ.copy()
    extra_paths = []
    separator = ";" if IS_WINDOWS else ":"

    # Always include the directory of the current Python interpreter
    python_dir = Path(sys.executable).parent
    extra_paths.append(str(python_dir))

    if IS_WINDOWS:
        # Windows: Scripts folder is where pip puts executables
        extra_paths.append(str(python_dir / "Scripts"))

        user_scripts = (
            Path.home() / "AppData" / "Roaming" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts"
        )
        if user_scripts.exists():
            extra_paths.append(str(user_scripts))

        local_scripts = (
            Path.home() / "AppData" / "Local" / "Programs" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts"
        )
        if local_scripts.exists():
            extra_paths.append(str(local_scripts))

    else:
        # macOS / Linux
        home_local_bin = Path.home() / ".local" / "bin"
        if home_local_bin.exists():
            extra_paths.append(str(home_local_bin))

        # macOS Homebrew paths
        if PLATFORM == "Darwin":
            for brew_path in ["/opt/homebrew/bin", "/usr/local/bin"]:
                if Path(brew_path).exists():
                    extra_paths.append(brew_path)

    current_path = env.get("PATH", "")
    env["PATH"] = separator.join(extra_paths) + separator + current_path

    logger.debug(f"Subprocess PATH prepended with: {extra_paths}")
    return env


def _run_semgrep_cmd(cmd: list, env: dict, description: str = ""):
    """
    Execute a semgrep command and return parsed JSON output or None on failure.
    """
    logger.info(f"Running semgrep ({description}): {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env=env
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep timed out ({description})")
        return None
    except Exception as e:
        logger.error(f"Failed to execute semgrep ({description}): {e}")
        return None

    logger.info(f"Semgrep exit code ({description}): {result.returncode}")

    if result.stderr:
        logger.warning(f"Semgrep stderr ({description}): {result.stderr[:2000]}")

    if not result.stdout.strip():
        return None

    try:
        output = json.loads(result.stdout)
        results = output.get("results", [])
        logger.info(f"Semgrep found {len(results)} findings ({description})")
        return output
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse semgrep output ({description}): {e}")
        logger.error(f"Stdout (first 500 chars): {result.stdout[:500]}")
        return None


def run_semgrep(repo_path: str):
    """
    Run semgrep scan on the given repository path.
    Uses --config=auto for broad language coverage (Python, Java, JS, etc.)
    Falls back to specific rulesets if auto config fails.
    Works on Windows, macOS, and Linux.
    """
    semgrep_bin = _get_semgrep_path()
    logger.info(f"Using semgrep at: {semgrep_bin}")
    logger.info(f"Platform: {PLATFORM}")

    env = _get_subprocess_env()

    # --- Attempt 1: --config=auto ---
    cmd = [
        semgrep_bin, "scan",
        "--config", "auto",
        "--json",
        "--no-git-ignore",
        repo_path
    ]

    output = _run_semgrep_cmd(cmd, env, "auto config")
    if output and output.get("results"):
        return output

    # --- Attempt 2: language-specific rulesets ---
    logger.info("Auto config returned no results, trying language-specific rulesets...")

    fallback_configs = [
        "p/python",
        "p/java",
        "p/javascript",
        "p/typescript",
        "p/security-audit",
        "p/owasp-top-ten",
    ]

    all_results = []

    for config in fallback_configs:
        fallback_cmd = [
            semgrep_bin, "scan",
            "--config", config,
            "--json",
            "--no-git-ignore",
            repo_path
        ]

        fallback_output = _run_semgrep_cmd(fallback_cmd, env, f"config={config}")
        if fallback_output:
            results = fallback_output.get("results", [])
            if results:
                all_results.extend(results)

    if all_results:
        return {"results": all_results, "errors": []}

    # --- Attempt 3: legacy command format (older semgrep versions) ---
    logger.info("Trying legacy semgrep command format (without 'scan' subcommand)...")

    legacy_cmd = [
        semgrep_bin,
        "--config=auto",
        "--json",
        repo_path
    ]

    legacy_output = _run_semgrep_cmd(legacy_cmd, env, "legacy format")
    if legacy_output:
        return legacy_output

    logger.error("All semgrep scan attempts returned no results")
    return {"results": [], "errors": [], "scan_info": "all_attempts_failed"}
