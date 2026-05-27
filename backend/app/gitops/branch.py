import uuid
import logging

logger = logging.getLogger(__name__)


def generate_branch_name() -> str:
    """Generate a default branch name for remediation."""
    short_id = str(uuid.uuid4())[:8]
    return f"fix/vuln-remediation-{short_id}"


def create_branch(repo_path: str, branch_name: str = "") -> str:
    """
    Create a new branch for the vulnerability fix.

    Args:
        repo_path: Path to the cloned repository.
        branch_name: Custom branch name. If empty, generates a default name.

    Returns:
        The branch name that was created.
    """
    from git import Repo

    repo = Repo(repo_path)

    if not branch_name:
        branch_name = generate_branch_name()

    repo.git.checkout("-b", branch_name)
    logger.info(f"Created branch: {branch_name}")

    return branch_name
