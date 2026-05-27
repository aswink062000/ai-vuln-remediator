"""
Cross-platform Semgrep SAST scanner.

Supports: Windows, macOS, Linux
Auto-installs: semgrep, certifi, pip-system-certs (Windows)

Handles:
- Binary discovery across all platforms
- PATH issues (pysemgrep not found on Windows)
- SSL/TLS certificate errors (corporate proxies)
- UTF-8 encoding issues (Windows cp1252 default)
- Metrics requirement for --config=auto
- Fallback to language-specific rulesets
"""

import subprocess
import json
import os
import sys
import shutil
import logging
import platform
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

PLATFORM = platform.system()  # "Windows", "Darwin", "Linux"
IS_WINDOWS = PLATFORM == "Windows"


# =============================================================================
# AUTO-INSTALL
# =============================================================================

def _pip_install(package: str) -> bool:
    """
    Install a Python package using pip.
    Works on system Python (no venv), venv, Docker, Mac, Windows, Linux.
    Returns True if installation succeeded.
    """
    logger.info(f"Auto-installing: {package}")
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", package]

        # If not in a venv, handle system Python restrictions
        if not _is_in_venv():
            # Try --user first, fall back to --break-system-packages (PEP 668)
            cmd.insert(4, "--user")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            timeout=120
        )
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""

        if result.returncode == 0:
            logger.info(f"Successfully installed: {package}")
            return True

        # If --user failed due to PEP 668 (externally-managed), retry with --break-system-packages
        if "externally-managed" in stderr.lower() or "PEP 668" in stderr:
            logger.info(f"Retrying {package} install with --break-system-packages...")
            cmd_retry = [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", package]
            result2 = subprocess.run(cmd_retry, capture_output=True, text=False, timeout=120)
            if result2.returncode == 0:
                logger.info(f"Successfully installed: {package} (system-wide)")
                return True

        logger.warning(f"Failed to install {package}: {stderr[:500]}")
        return False
    except Exception as e:
        logger.warning(f"Exception installing {package}: {e}")
        return False


def _is_in_venv() -> bool:
    """Check if running inside a virtual environment."""
    return (
        hasattr(sys, "real_prefix") or  # virtualenv
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)  # venv
    )


def _ensure_dependencies():
    """
    Ensure all required dependencies are installed.
    Prefers OpenGrep over Semgrep (license-free).
    Auto-installs missing packages.
    """
    # Check if either opengrep or semgrep is available
    if not shutil.which("opengrep") and not shutil.which("semgrep") and not _find_semgrep_binary():
        logger.info("No SAST scanner found, attempting auto-install...")
        # Try semgrep (available on PyPI; opengrep not yet on PyPI)
        _pip_install("semgrep")

    # Check and install certifi (for SSL certificate handling)
    try:
        import certifi  # noqa: F401
    except ImportError:
        _pip_install("certifi")

    # On Windows, install pip-system-certs to trust corporate proxy CAs
    if IS_WINDOWS:
        try:
            import pip_system_certs  # noqa: F401
        except ImportError:
            logger.info("Installing pip-system-certs for Windows SSL compatibility...")
            _pip_install("pip-system-certs")


def _find_semgrep_binary() -> Optional[str]:
    """
    Find the SAST scanner binary across Windows, macOS, and Linux.
    Prefers OpenGrep (fully open-source fork) over Semgrep.
    Works with or without a virtual environment.
    Priority: opengrep → semgrep (system PATH → user bin → common locations).
    """
    # Try OpenGrep first (LGPL-2.1, no license restrictions)
    opengrep_name = "opengrep.exe" if IS_WINDOWS else "opengrep"
    opengrep_path = shutil.which(opengrep_name)
    if opengrep_path:
        logger.info(f"Using OpenGrep (open-source): {opengrep_path}")
        return opengrep_path

    # Check common OpenGrep install locations
    if not IS_WINDOWS:
        for p in [
            Path.home() / ".local" / "bin" / opengrep_name,
            Path("/usr/local/bin") / opengrep_name,
            Path("/opt/homebrew/bin") / opengrep_name,
        ]:
            if p.exists():
                logger.info(f"Using OpenGrep (open-source): {p}")
                return str(p)

    # Fall back to Semgrep
    binary_name = "semgrep.exe" if IS_WINDOWS else "semgrep"

    # 1. Check system PATH first (works for Docker, system installs, brew, etc.)
    path_bin = shutil.which(binary_name)
    if path_bin:
        return path_bin

    # 2. Check user bin directory (pip install --user puts binaries here)
    if not IS_WINDOWS:
        user_bin = Path.home() / ".local" / "bin" / binary_name
        if user_bin.exists():
            return str(user_bin)
    else:
        # Windows user Scripts
        user_scripts = (
            Path.home() / "AppData" / "Roaming" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts" / binary_name
        )
        if user_scripts.exists():
            return str(user_scripts)

        local_scripts = (
            Path.home() / "AppData" / "Local" / "Programs" / "Python"
            / f"Python{sys.version_info.major}{sys.version_info.minor}"
            / "Scripts" / binary_name
        )
        if local_scripts.exists():
            return str(local_scripts)

    # 3. Check in the same directory as the running Python interpreter
    python_dir = Path(sys.executable).parent
    semgrep_in_env = python_dir / binary_name
    if semgrep_in_env.exists():
        return str(semgrep_in_env)

    if IS_WINDOWS:
        scripts_dir = python_dir / "Scripts"
        semgrep_in_scripts = scripts_dir / binary_name
        if semgrep_in_scripts.exists():
            return str(semgrep_in_scripts)

    # 4. macOS / Linux: check common system locations
    if not IS_WINDOWS:
        common_paths = [
            Path("/usr/local/bin") / binary_name,
            Path("/opt/homebrew/bin") / binary_name,
            Path("/usr/bin") / binary_name,
            Path("/usr/local/opt/semgrep/bin") / binary_name,
        ]
        for p in common_paths:
            if p.exists():
                return str(p)

    # 5. Final fallback — re-check PATH (in case it was updated)
    return shutil.which("semgrep")


def _get_semgrep_path() -> str:
    """
    Get SAST scanner binary path (OpenGrep or Semgrep).
    Auto-installs if not found.
    Raises FileNotFoundError if neither can be found or installed.
    """
    path = _find_semgrep_binary()
    if path:
        return path

    # Try auto-install
    logger.info("No SAST scanner found, attempting auto-install...")
    if _pip_install("semgrep"):
        # Re-check after install
        path = _find_semgrep_binary()
        if path:
            return path

    raise FileNotFoundError(
        "Neither OpenGrep nor Semgrep found, and auto-install failed.\n"
        "Please install one of:\n"
        "  Option 1 (recommended): Download OpenGrep from https://github.com/opengrep/opengrep/releases\n"
        "  Option 2: pip install semgrep\n"
        + (
            "On Windows, ensure the Scripts folder is in your PATH.\n"
            if IS_WINDOWS
            else "On macOS: brew install semgrep\n"
            "On Linux: pip install --user semgrep (ensure ~/.local/bin is in PATH)\n"
        )
    )


# =============================================================================
# ENVIRONMENT SETUP
# =============================================================================

def _get_subprocess_env() -> dict:
    """
    Build environment for subprocess calls.
    Handles:
    - PATH: ensures pysemgrep and other companion binaries are discoverable
    - SSL: configures CA bundles for corporate proxy environments
    - Metrics: enables metrics (required for --config=auto)
    - Encoding: forces UTF-8 output
    Works on Windows, macOS, and Linux.
    """
    env = os.environ.copy()
    extra_paths = []
    separator = ";" if IS_WINDOWS else ":"

    # --- Metrics ---
    # Semgrep's --config=auto REQUIRES metrics to be enabled.
    env["SEMGREP_SEND_METRICS"] = "on"

    # --- SSL/TLS ---
    # Corporate proxies intercept HTTPS with custom CA certs.
    # Configure Python/requests to trust them.
    if "REQUESTS_CA_BUNDLE" not in env and "SSL_CERT_FILE" not in env:
        try:
            import certifi
            ca_bundle = certifi.where()
            env["REQUESTS_CA_BUNDLE"] = ca_bundle
            env["SSL_CERT_FILE"] = ca_bundle
        except ImportError:
            if IS_WINDOWS:
                # On Windows without certifi, disable verification as last resort
                env["PYTHONHTTPSVERIFY"] = "0"

    # --- Encoding ---
    # Force UTF-8 for any Python subprocesses spawned by semgrep
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    # --- PATH ---
    # Ensure companion binaries (pysemgrep, osemgrep) are discoverable
    python_dir = Path(sys.executable).parent
    extra_paths.append(str(python_dir))

    if IS_WINDOWS:
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

        # Common system paths
        for sys_path in ["/usr/local/bin", "/usr/bin"]:
            if Path(sys_path).exists() and sys_path not in extra_paths:
                extra_paths.append(sys_path)

        if PLATFORM == "Darwin":
            for brew_path in ["/opt/homebrew/bin"]:
                if Path(brew_path).exists() and brew_path not in extra_paths:
                    extra_paths.append(brew_path)

    current_path = env.get("PATH", "")
    env["PATH"] = separator.join(extra_paths) + separator + current_path

    logger.debug(f"Subprocess PATH prepended with: {extra_paths}")
    return env


# =============================================================================
# COMMAND EXECUTION
# =============================================================================

def _run_semgrep_cmd(cmd: List[str], env: dict, description: str = "") -> Optional[Dict[str, Any]]:
    """
    Execute a semgrep command and return parsed JSON output or None on failure.
    Uses raw bytes mode to avoid Windows cp1252 encoding issues.
    """
    logger.info(f"Running semgrep ({description}): {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,  # Raw bytes — avoids Windows cp1252 UnicodeDecodeError
            timeout=600,
            env=env
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep timed out ({description})")
        return None
    except FileNotFoundError as e:
        logger.error(f"Semgrep binary not found ({description}): {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to execute semgrep ({description}): {e}")
        return None

    # Decode output as UTF-8, replacing any invalid bytes
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""

    logger.info(f"Semgrep exit code ({description}): {result.returncode}")

    if stderr:
        logger.warning(f"Semgrep stderr ({description}): {stderr[:2000]}")

    if not stdout.strip():
        return None

    try:
        output = json.loads(stdout)
        results = output.get("results", [])
        logger.info(f"Semgrep found {len(results)} findings ({description})")
        return output
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Failed to parse semgrep output ({description}): {e}")
        logger.error(f"Stdout (first 500 chars): {stdout[:500]}")
        return None


# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

def run_semgrep(repo_path: str) -> Dict[str, Any]:
    """
    Run semgrep scan on the given repository path.

    Strategy:
    1. Auto-install dependencies if missing
    2. Try --config=auto (broadest coverage)
    3. If SSL fails, retry with SSL verification disabled
    4. Fallback to language-specific rulesets (p/python, p/java, etc.)
    5. Fallback to legacy command format (older semgrep versions)

    Works on Windows, macOS, and Linux.
    """
    # Step 0: Ensure all dependencies are available
    _ensure_dependencies()

    # Step 1: Find semgrep binary
    semgrep_bin = _get_semgrep_path()
    logger.info(f"Using semgrep at: {semgrep_bin}")
    logger.info(f"Platform: {PLATFORM} (Python {sys.version_info.major}.{sys.version_info.minor})")

    # Step 2: Build environment
    env = _get_subprocess_env()

    # Exclude directories that are never useful to scan (speeds up large repos significantly)
    exclude_args = [
        "--exclude", "node_modules",
        "--exclude", "vendor",
        "--exclude", "target",
        "--exclude", "build",
        "--exclude", "dist",
        "--exclude", ".git",
        "--exclude", "*.min.js",
        "--exclude", "*.min.css",
        "--exclude", "*.map",
    ]

    # --- Attempt 1: --config=auto (best coverage) ---
    cmd = [
        semgrep_bin, "scan",
        "--config", "auto",
        "--json",
        *exclude_args,
        repo_path
    ]

    output = _run_semgrep_cmd(cmd, env, "auto config")
    if output and output.get("results"):
        return output

    # --- Attempt 1b: Retry with SSL disabled (corporate proxy) ---
    if not output or not output.get("results"):
        env_no_ssl = env.copy()
        env_no_ssl["PYTHONHTTPSVERIFY"] = "0"
        env_no_ssl["REQUESTS_CA_BUNDLE"] = ""
        env_no_ssl["CURL_CA_BUNDLE"] = ""
        env_no_ssl["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        logger.warning("Retrying auto config with SSL verification disabled")
        output = _run_semgrep_cmd(cmd, env_no_ssl, "auto config (no SSL verify)")
        if output and output.get("results"):
            return output
        # Use the no-SSL env for subsequent attempts too
        env = env_no_ssl

    # --- Attempt 2: Language-specific rulesets ---
    logger.info("Auto config failed, trying language-specific rulesets...")

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
            *exclude_args,
            repo_path
        ]

        fallback_output = _run_semgrep_cmd(fallback_cmd, env, f"config={config}")
        if fallback_output:
            results = fallback_output.get("results", [])
            if results:
                all_results.extend(results)

    if all_results:
        return {"results": all_results, "errors": []}

    # --- Attempt 3: Legacy command format (older semgrep versions) ---
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
