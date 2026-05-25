import uuid
import logging

logger = logging.getLogger(__name__)


def create_branch(repo_path: str) -> str:
    """
    Create a new branch for the vulnerability fix.
    """
    from git import Repo

    repo = Repo(repo_path)

    short_id = str(uuid.uuid4())[:8]
    branch_name = f"fix/vuln-remediation-{short_id}"

    repo.git.checkout("-b", branch_name)
    logger.info(f"Created branch: {branch_name}")

    return branch_name
