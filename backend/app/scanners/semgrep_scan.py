import subprocess
import json
import sys
import shutil
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


def _get_semgrep_path():
    """
    Find the semgrep binary. Checks:
    1. Same venv as the running Python interpreter (handles .exe on Windows)
    2. System PATH
    3. Common pip install locations on Windows (Scripts folder)
    """
    # Determine the correct binary name for the platform
    binary_name = "semgrep.exe" if IS_WINDOWS else "semgrep"

    # Check in the same venv bin/Scripts directory as the current Python
    venv_bin = Path(sys.executable).parent
    semgrep_in_venv = venv_bin / binary_name
    if semgrep_in_venv.exists():
        return str(semgrep_in_venv)

    # On Windows, also check the Scripts subdirectory
    if IS_WINDOWS:
        scripts_dir = venv_bin / "Scripts"
        semgrep_in_scripts = scripts_dir / binary_name
        if semgrep_in_scripts.exists():
            return str(semgrep_in_scripts)

        # Check user site-packages Scripts
        user_scripts = Path.home() / "AppData" / "Roaming" / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts" / binary_name
        if user_scripts.exists():
            return str(user_scripts)

    # Fall back to system PATH
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        return semgrep_path

    raise FileNotFoundError(
        "semgrep not found. Install it with: pip install semgrep\n"
        "On Windows, ensure the Python Scripts folder is in your PATH.\n"
        "Typical location: C:\\Users\\<user>\\AppData\\Local\\Programs\\Python\\Python3x\\Scripts\\\n"
        "Or use: python -m pip install semgrep && python -m semgrep"
    )


def run_semgrep(repo_path: str):
    """
    Run semgrep scan on the given repository path.
    Uses --config=auto for broad language coverage (Python, Java, JS, etc.)
    Falls back to specific rulesets if auto config fails.
    """
    semgrep_bin = _get_semgrep_path()
    logger.info(f"Using semgrep at: {semgrep_bin}")

    # Primary scan with auto config
    cmd = [
        semgrep_bin,
        "scan",
        "--config", "auto",
        "--json",
        "--no-git-ignore",
        repo_path
    ]

    logger.info(f"Running semgrep command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out (600s)")
        return {"results": [], "errors": [{"message": "Scan timed out"}]}
    except Exception as e:
        logger.error(f"Failed to execute semgrep: {e}")
        return {"results": [], "errors": [{"message": str(e)}]}

    logger.info(f"Semgrep exit code: {result.returncode}")

    if result.stderr:
        logger.warning(f"Semgrep stderr: {result.stderr[:2000]}")

    # Try to parse JSON output
    try:
        output = json.loads(result.stdout)
        results = output.get("results", [])
        logger.info(f"Semgrep found {len(results)} findings with --config=auto")

        if results:
            return output
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse semgrep output: {e}")
        logger.error(f"Stdout (first 1000 chars): {result.stdout[:1000]}")

    # Fallback: try with specific language rulesets for Python and Java
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
            semgrep_bin,
            "scan",
            "--config", config,
            "--json",
            "--no-git-ignore",
            repo_path
        ]

        logger.info(f"Trying fallback config: {config}")

        try:
            fallback_result = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if fallback_result.stdout:
                try:
                    fallback_output = json.loads(fallback_result.stdout)
                    fallback_results = fallback_output.get("results", [])
                    if fallback_results:
                        logger.info(
                            f"Found {len(fallback_results)} findings with config: {config}"
                        )
                        all_results.extend(fallback_results)
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout with config: {config}")
            continue
        except Exception as e:
            logger.warning(f"Error with config {config}: {e}")
            continue

    if all_results:
        return {"results": all_results, "errors": []}

    # Final fallback: run without 'scan' subcommand for older semgrep versions
    logger.info("Trying legacy semgrep command format (without 'scan' subcommand)...")

    legacy_cmd = [
        semgrep_bin,
        "--config=auto",
        "--json",
        repo_path
    ]

    try:
        legacy_result = subprocess.run(
            legacy_cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if legacy_result.stdout:
            try:
                legacy_output = json.loads(legacy_result.stdout)
                legacy_results = legacy_output.get("results", [])
                logger.info(
                    f"Legacy command found {len(legacy_results)} findings"
                )
                return legacy_output
            except json.JSONDecodeError:
                logger.error(
                    f"Failed to parse legacy output: {legacy_result.stdout[:500]}"
                )
    except subprocess.TimeoutExpired:
        logger.error("Legacy semgrep command timed out")
    except Exception as e:
        logger.error(f"Legacy semgrep command failed: {e}")

    logger.error("All semgrep scan attempts returned no results")
    return {"results": [], "errors": [], "scan_info": "all_attempts_failed"}
