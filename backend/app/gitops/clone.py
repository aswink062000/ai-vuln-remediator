import shutil
import uuid
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = "/tmp/repos"

# Use platform-appropriate temp dir on Windows
import platform
if platform.system() == "Windows":
    import tempfile
    BASE_DIR = str(Path(tempfile.gettempdir()) / "repos")

Path(BASE_DIR).mkdir(parents=True, exist_ok=True)


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


def clone_repo(github_url: str):
    """
    Clone a GitHub repository to a local temp directory.
    Returns the path to the cloned repo.
    """
    Repo = _get_git_repo()

    repo_id = str(uuid.uuid4())
    repo_path = str(Path(BASE_DIR) / repo_id)

    logger.info(f"Cloning {github_url} to {repo_path}")

    try:
        Repo.clone_from(github_url, repo_path)
        logger.info(f"Successfully cloned to {repo_path}")

        # Verify the clone has files
        files = list(Path(repo_path).rglob("*"))
        file_count = len([f for f in files if f.is_file()])
        logger.info(f"Cloned repo contains {file_count} files")

        if file_count == 0:
            raise Exception("Cloned repository is empty")

        return repo_path

    except ImportError:
        raise
    except Exception as e:
        logger.error(f"Failed to clone {github_url}: {e}")
        if Path(repo_path).exists():
            shutil.rmtree(repo_path, ignore_errors=True)
        raise


def get_default_branch(repo_path: str) -> str:
    """
    Detect the default branch of the cloned repository.
    """
    try:
        Repo = _get_git_repo()
        repo = Repo(repo_path)
        default_branch = repo.active_branch.name
        logger.info(f"Default branch detected: {default_branch}")
        return default_branch
    except Exception as e:
        logger.warning(f"Could not detect default branch: {e}, falling back to 'main'")
        return "main"


def cleanup_repo(repo_path: str):
    """Remove cloned repo after processing."""
    try:
        if Path(repo_path).exists():
            shutil.rmtree(repo_path, ignore_errors=True)
            logger.info(f"Cleaned up {repo_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup {repo_path}: {e}")
