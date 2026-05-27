import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def patch_file(repo_path: str, relative_path: str, new_content: str) -> None:
    """Write fixed content back to a file in the repository."""
    full_path = Path(repo_path) / relative_path

    if not full_path.exists():
        raise FileNotFoundError(f"Cannot patch non-existent file: {full_path}")

    try:
        full_path.write_text(new_content, encoding="utf-8")
        logger.info(f"Patched file: {relative_path}")
    except Exception as e:
        logger.error(f"Failed to patch {relative_path}: {e}")
        raise
