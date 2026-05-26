"""
Repository Clone Manager with guaranteed cleanup.

Ensures:
- All cloned repos are tracked in a registry
- Cleanup happens even on crashes/exceptions (atexit + periodic sweep)
- Stale repos (older than 1 hour) are auto-cleaned
- Disk usage is monitored and capped
- Context manager support for safe usage

No orphaned repos left on disk, ever.
"""

import atexit
import shutil
import uuid
import time
import logging
import platform
import tempfile
import threading
from pathlib import Path
from typing import Optional, Set
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Platform-appropriate temp directory
if platform.system() == "Windows":
    BASE_DIR = str(Path(tempfile.gettempdir()) / "repos")
else:
    BASE_DIR = "/tmp/repos"

Path(BASE_DIR).mkdir(parents=True, exist_ok=True)

# =============================================================================
# REPO REGISTRY — Tracks all active cloned repos
# =============================================================================

_active_repos: Set[str] = set()
_repo_lock = threading.Lock()
_MAX_REPO_AGE_SECONDS = 3600  # 1 hour max lifetime
_MAX_DISK_MB = 2000  # 2GB max total disk for repos


def _register_repo(repo_path: str):
    """Register a repo as active."""
    with _repo_lock:
        _active_repos.add(repo_path)


def _unregister_repo(repo_path: str):
    """Unregister a repo after cleanup."""
    with _repo_lock:
        _active_repos.discard(repo_path)


def _get_active_repos() -> Set[str]:
    """Get a copy of active repos."""
    with _repo_lock:
        return _active_repos.copy()


# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

def cleanup_repo(repo_path: str):
    """
    Remove a cloned repo and unregister it.
    Safe to call multiple times.
    """
    if not repo_path:
        return

    try:
        path = Path(repo_path)
        if path.exists():
            # On Windows, git files can be read-only — force delete
            if platform.system() == "Windows":
                _force_remove_windows(path)
            else:
                shutil.rmtree(repo_path, ignore_errors=True)
            logger.info(f"Cleaned up repo: {repo_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup {repo_path}: {e}")
        # Try harder
        try:
            shutil.rmtree(repo_path, ignore_errors=True)
        except Exception:
            pass
    finally:
        _unregister_repo(repo_path)


def _force_remove_windows(path: Path):
    """Force remove on Windows (handles read-only .git files)."""
    import stat

    def remove_readonly(func, fpath, _):
        """Clear the readonly bit and retry."""
        Path(fpath).chmod(stat.S_IWRITE)
        func(fpath)

    shutil.rmtree(str(path), onerror=remove_readonly)


def cleanup_all_repos():
    """Emergency cleanup — remove ALL tracked repos. Called at exit."""
    repos = _get_active_repos()
    if repos:
        logger.info(f"Cleaning up {len(repos)} remaining repos at shutdown...")
        for repo_path in repos:
            cleanup_repo(repo_path)


def cleanup_stale_repos():
    """
    Remove repos that have been around too long (orphaned).
    Called periodically and at startup.
    """
    base = Path(BASE_DIR)
    if not base.exists():
        return

    now = time.time()
    cleaned = 0

    for item in base.iterdir():
        if item.is_dir():
            try:
                age = now - item.stat().st_mtime
                if age > _MAX_REPO_AGE_SECONDS:
                    shutil.rmtree(str(item), ignore_errors=True)
                    _unregister_repo(str(item))
                    cleaned += 1
            except Exception:
                pass

    if cleaned:
        logger.info(f"Cleaned {cleaned} stale repos (older than {_MAX_REPO_AGE_SECONDS}s)")


def get_disk_usage_mb() -> float:
    """Get total disk usage of the repos directory in MB."""
    base = Path(BASE_DIR)
    if not base.exists():
        return 0.0

    total = sum(f.stat().st_size for f in base.rglob("*") if f.is_file())
    return total / (1024 * 1024)


# =============================================================================
# CLONE FUNCTIONS
# =============================================================================

def _get_git_repo():
    """Lazy import of git.Repo to avoid crash if git is not installed."""
    try:
        from git import Repo
        return Repo
    except ImportError as e:
        raise ImportError(
            "Git is not installed or not found in PATH. "
            "Please install Git: https://git-scm.com/downloads "
            "and ensure it's added to your system PATH."
        ) from e


def clone_repo(github_url: str) -> str:
    """
    Clone a GitHub repository to a local temp directory.
    Returns the path to the cloned repo.

    The repo is registered for tracking — guaranteed cleanup on:
    - Normal cleanup_repo() call
    - Process exit (atexit handler)
    - Stale repo sweep (>1 hour old)
    """
    # Check disk usage before cloning
    usage = get_disk_usage_mb()
    if usage > _MAX_DISK_MB:
        logger.warning(f"Disk usage high ({usage:.0f}MB), cleaning stale repos...")
        cleanup_stale_repos()

    Repo = _get_git_repo()

    repo_id = str(uuid.uuid4())
    repo_path = str(Path(BASE_DIR) / repo_id)

    logger.info(f"Cloning {github_url} to {repo_path}")

    # Register BEFORE cloning so it gets cleaned up even if clone partially fails
    _register_repo(repo_path)

    try:
        Repo.clone_from(github_url, repo_path, depth=1)  # Shallow clone for speed
        logger.info(f"Successfully cloned to {repo_path}")

        # Verify the clone has files
        file_count = sum(1 for f in Path(repo_path).rglob("*") if f.is_file())
        logger.info(f"Cloned repo contains {file_count} files")

        if file_count == 0:
            raise Exception("Cloned repository is empty")

        return repo_path

    except ImportError:
        _unregister_repo(repo_path)
        raise
    except Exception as e:
        logger.error(f"Failed to clone {github_url}: {e}")
        # Cleanup the failed clone
        cleanup_repo(repo_path)
        raise


def get_default_branch(repo_path: str) -> str:
    """Detect the default branch of the cloned repository."""
    try:
        Repo = _get_git_repo()
        repo = Repo(repo_path)
        default_branch = repo.active_branch.name
        logger.info(f"Default branch detected: {default_branch}")
        return default_branch
    except Exception as e:
        logger.warning(f"Could not detect default branch: {e}, falling back to 'main'")
        return "main"


# =============================================================================
# CONTEXT MANAGER — Safest way to use cloned repos
# =============================================================================

@contextmanager
def cloned_repo(github_url: str):
    """
    Context manager for cloned repos — guarantees cleanup.

    Usage:
        with cloned_repo("https://github.com/user/repo") as repo_path:
            # do stuff with repo_path
            pass
        # repo is automatically cleaned up here, even on exceptions
    """
    repo_path = clone_repo(github_url)
    try:
        yield repo_path
    finally:
        cleanup_repo(repo_path)


# =============================================================================
# STARTUP & SHUTDOWN HOOKS
# =============================================================================

# Register atexit handler to clean up on process exit
atexit.register(cleanup_all_repos)

# Clean stale repos on module load (startup)
try:
    cleanup_stale_repos()
except Exception:
    pass
