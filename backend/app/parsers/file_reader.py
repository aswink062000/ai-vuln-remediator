import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def read_file(repo_path, relative_path):
    """
    Read a file from the cloned repository.
    Handles both absolute and relative paths from semgrep output.
    """
    # If the path is absolute and already points to a valid file, use it directly
    if os.path.isabs(relative_path) and os.path.isfile(relative_path):
        full_path = Path(relative_path)
    else:
        full_path = Path(repo_path) / relative_path

    if not full_path.exists():
        logger.error(f"File not found: {full_path}")
        raise FileNotFoundError(f"File not found: {full_path}")

    logger.info(f"Reading file: {full_path}")
    return full_path.read_text(encoding="utf-8", errors="replace")
