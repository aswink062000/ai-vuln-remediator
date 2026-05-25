import os
import logging

logger = logging.getLogger(__name__)


def push_changes(repo_path: str, branch_name: str):
    """
    Push the branch to the remote origin.
    Uses GITHUB_TOKEN for authentication if the remote is HTTPS.
    """
    from git import Repo

    repo = Repo(repo_path)
    origin = repo.remote(name="origin")

    # If using HTTPS remote, inject token for auth
    token = os.getenv("GITHUB_TOKEN")
    if token:
        remote_url = origin.url
        if remote_url.startswith("https://github.com/"):
            auth_url = remote_url.replace(
                "https://github.com/",
                f"https://x-access-token:{token}@github.com/"
            )
            repo.git.remote("set-url", "origin", auth_url)
            logger.info("Set authenticated remote URL")

    logger.info(f"Pushing branch: {branch_name}")
    origin.push(branch_name)
    logger.info(f"Successfully pushed {branch_name}")
