"""
Prerequisite Auto-Installer.

Checks and installs all required tools on first run.
Only installs what's needed — detects the platform and installs accordingly.

Required (always):
- Git CLI (for cloning repos)
- OpenGrep or Semgrep (SAST scanner)

Optional (installed based on scanned repo type):
- pip-audit (Python dependency scanning)
- npm (Node.js dependency scanning) — user must install Node.js manually

Platform support: macOS, Linux, Windows, Docker
"""

import os
import sys
import shutil
import subprocess
import platform
import logging
from pathlib import Path
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

PLATFORM = platform.system()  # "Darwin", "Linux", "Windows"
IS_WINDOWS = PLATFORM == "Windows"
IS_MAC = PLATFORM == "Darwin"
IS_LINUX = PLATFORM == "Linux"


def check_all_prerequisites() -> Dict[str, any]:
    """
    Check all prerequisites and auto-install missing ones.
    Called on app startup. Returns status report.
    """
    logger.info("=" * 50)
    logger.info("Checking prerequisites...")
    logger.info(f"Platform: {PLATFORM} ({platform.machine()})")
    logger.info(f"Python: {sys.version}")
    logger.info("=" * 50)

    results = {
        "platform": PLATFORM,
        "architecture": platform.machine(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "checks": {},
        "installed": [],
        "failed": [],
    }

    # 1. Git (required — cannot scan without it)
    results["checks"]["git"] = _check_and_install_git()

    # 2. OpenGrep / Semgrep (required — SAST scanner)
    results["checks"]["sast_scanner"] = _check_and_install_sast_scanner()

    # 3. pip-audit (for Python dependency scanning)
    results["checks"]["pip_audit"] = _check_pip_audit()

    # Log summary
    installed = [k for k, v in results["checks"].items() if v.get("status") == "installed"]
    failed = [k for k, v in results["checks"].items() if v.get("status") == "failed"]
    ok = [k for k, v in results["checks"].items() if v.get("status") == "ok"]

    results["installed"] = installed
    results["failed"] = failed

    if installed:
        logger.info(f"Auto-installed: {', '.join(installed)}")
    if failed:
        logger.warning(f"Failed to install: {', '.join(failed)}")
    if ok:
        logger.info(f"Already available: {', '.join(ok)}")

    logger.info("Prerequisite check complete.")
    return results


# =============================================================================
# GIT
# =============================================================================

def _check_and_install_git() -> Dict:
    """Check if Git is installed. Cannot auto-install — user must do it."""
    git_path = shutil.which("git")
    if git_path:
        try:
            result = subprocess.run([git_path, "--version"], capture_output=True, text=True, timeout=5)
            version = result.stdout.strip().replace("git version ", "")
            logger.info(f"✓ Git: {version} ({git_path})")
            return {"status": "ok", "version": version, "path": git_path}
        except Exception:
            pass

    logger.error("✗ Git not found. Please install Git:")
    logger.error("  macOS: xcode-select --install  OR  brew install git")
    logger.error("  Linux: sudo apt install git  OR  sudo yum install git")
    logger.error("  Windows: https://git-scm.com/download/win")
    return {
        "status": "failed",
        "error": "Git not installed",
        "install_instructions": {
            "macOS": "xcode-select --install",
            "Linux": "sudo apt install git",
            "Windows": "https://git-scm.com/download/win",
        },
    }


# =============================================================================
# OPENGREP / SEMGREP (SAST SCANNER)
# =============================================================================

def _check_and_install_sast_scanner() -> Dict:
    """Check for OpenGrep or Semgrep. Auto-installs OpenGrep if missing."""

    # Check OpenGrep first
    opengrep_path = shutil.which("opengrep")
    if opengrep_path:
        version = _get_tool_version(opengrep_path)
        logger.info(f"✓ OpenGrep: {version} ({opengrep_path})")
        return {"status": "ok", "tool": "opengrep", "version": version, "path": opengrep_path}

    # Check Semgrep
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        version = _get_tool_version(semgrep_path)
        logger.info(f"✓ Semgrep: {version} ({semgrep_path})")
        return {"status": "ok", "tool": "semgrep", "version": version, "path": semgrep_path}

    # Neither found — try to install OpenGrep
    logger.info("No SAST scanner found. Installing OpenGrep...")

    if _install_opengrep():
        opengrep_path = shutil.which("opengrep")
        if opengrep_path:
            version = _get_tool_version(opengrep_path)
            logger.info(f"✓ OpenGrep installed: {version}")
            return {"status": "installed", "tool": "opengrep", "version": version, "path": opengrep_path}

    # OpenGrep install failed — try Semgrep via pip
    logger.info("OpenGrep install failed. Trying Semgrep via pip...")
    if _install_semgrep_pip():
        semgrep_path = shutil.which("semgrep")
        if not semgrep_path:
            # Check common locations
            for p in [
                Path.home() / ".local" / "bin" / "semgrep",
                Path("/opt/homebrew/bin/semgrep"),
                Path("/usr/local/bin/semgrep"),
            ]:
                if p.exists():
                    semgrep_path = str(p)
                    break

        if semgrep_path:
            version = _get_tool_version(semgrep_path)
            logger.info(f"✓ Semgrep installed: {version}")
            return {"status": "installed", "tool": "semgrep", "version": version, "path": semgrep_path}

    logger.error("✗ Failed to install SAST scanner. Please install manually:")
    logger.error("  OpenGrep: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash")
    logger.error("  Semgrep:  pip install semgrep  OR  brew install semgrep")
    return {
        "status": "failed",
        "error": "No SAST scanner available",
        "install_instructions": {
            "opengrep_mac_linux": "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash",
            "opengrep_windows": "irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex",
            "semgrep_pip": "pip install semgrep",
            "semgrep_brew": "brew install semgrep",
        },
    }


def _install_opengrep() -> bool:
    """Install OpenGrep using the official install script."""
    try:
        if IS_WINDOWS:
            # Windows: PowerShell install
            cmd = [
                "powershell", "-Command",
                "irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex"
            ]
        else:
            # macOS / Linux: bash install
            cmd = [
                "bash", "-c",
                "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"
            ]

        logger.info(f"Running OpenGrep installer...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "PATH": os.environ.get("PATH", "") + ":/usr/local/bin:/opt/homebrew/bin"},
        )

        if result.returncode == 0:
            logger.info("OpenGrep installer completed successfully")
            return True
        else:
            logger.warning(f"OpenGrep installer failed: {result.stderr[:300]}")
            return False

    except subprocess.TimeoutExpired:
        logger.warning("OpenGrep installer timed out")
        return False
    except Exception as e:
        logger.warning(f"OpenGrep installer error: {e}")
        return False


def _install_semgrep_pip() -> bool:
    """Install Semgrep via pip as fallback."""
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", "semgrep"]

        # Handle externally-managed environments (PEP 668)
        if not _is_in_venv():
            cmd.append("--break-system-packages")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return result.returncode == 0
    except Exception as e:
        logger.warning(f"pip install semgrep failed: {e}")
        return False


# =============================================================================
# PIP-AUDIT (Python dependency scanning)
# =============================================================================

def _check_pip_audit() -> Dict:
    """Check if pip-audit is available. Auto-installs if missing."""
    pip_audit_path = shutil.which("pip-audit")
    if pip_audit_path:
        version = _get_tool_version(pip_audit_path)
        logger.info(f"✓ pip-audit: {version}")
        return {"status": "ok", "version": version, "path": pip_audit_path}

    # Try to install
    logger.info("pip-audit not found. Installing...")
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", "pip-audit"]
        if not _is_in_venv():
            cmd.append("--break-system-packages")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            pip_audit_path = shutil.which("pip-audit")
            if pip_audit_path:
                logger.info(f"✓ pip-audit installed")
                return {"status": "installed", "path": pip_audit_path}
    except Exception:
        pass

    # Not critical — OSV.dev API fallback exists
    logger.info("○ pip-audit not available (will use OSV.dev API fallback for Python deps)")
    return {"status": "optional_missing", "note": "Will use OSV.dev API fallback"}


# =============================================================================
# UTILITIES
# =============================================================================

def _get_tool_version(binary_path: str) -> str:
    """Get version string from a tool."""
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return "unknown"


def _is_in_venv() -> bool:
    """Check if running inside a virtual environment."""
    return (
        hasattr(sys, "real_prefix") or
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )


def get_prerequisite_status() -> Dict:
    """Get current status of all prerequisites (without installing)."""
    status = {}

    # Git
    git_path = shutil.which("git")
    status["git"] = {"installed": bool(git_path), "path": git_path}

    # SAST Scanner
    opengrep_path = shutil.which("opengrep")
    semgrep_path = shutil.which("semgrep")
    if opengrep_path:
        status["sast_scanner"] = {"installed": True, "tool": "opengrep", "path": opengrep_path}
    elif semgrep_path:
        status["sast_scanner"] = {"installed": True, "tool": "semgrep", "path": semgrep_path}
    else:
        status["sast_scanner"] = {"installed": False}

    # Trivy
    trivy_path = shutil.which("trivy")
    status["trivy"] = {"installed": bool(trivy_path), "path": trivy_path}

    # Gitleaks
    gitleaks_path = shutil.which("gitleaks")
    status["gitleaks"] = {"installed": bool(gitleaks_path), "path": gitleaks_path}

    # pip-audit
    pip_audit_path = shutil.which("pip-audit")
    status["pip_audit"] = {"installed": bool(pip_audit_path), "path": pip_audit_path}

    # npm (for Node.js scanning)
    npm_path = shutil.which("npm")
    status["npm"] = {"installed": bool(npm_path), "path": npm_path}

    # Node.js
    node_path = shutil.which("node")
    status["node"] = {"installed": bool(node_path), "path": node_path}

    return status
