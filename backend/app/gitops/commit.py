import logging

logger = logging.getLogger(__name__)


def commit_changes(repo_path: str):
    """Commit all changes in the repo."""
    from git import Repo

    repo = Repo(repo_path)
    repo.git.add(A=True)
    repo.index.commit("fix(security): auto remediation by AI")
    logger.info("Changes committed")
