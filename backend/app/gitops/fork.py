import os
import time
import logging

logger = logging.getLogger(__name__)


def fork_repo(repo_name: str):
    """
    Fork a repository to the authenticated user's account.
    Returns (fork_full_name, is_forked).
    """
    from github import Github

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise Exception("GITHUB_TOKEN not set in .env")

    g = Github(token)
    user = g.get_user()

    logger.info(f"Authenticated as: {user.login}")

    source_repo = g.get_repo(repo_name)

    # Check if we already have push access
    if source_repo.permissions and source_repo.permissions.push:
        logger.info(f"Already have push access to {repo_name}, no fork needed")
        return repo_name, False

    # Check if fork already exists
    fork_name = f"{user.login}/{source_repo.name}"
    try:
        existing_fork = g.get_repo(fork_name)
        if existing_fork.fork and existing_fork.parent.full_name == repo_name:
            logger.info(f"Fork already exists: {fork_name}")
            return fork_name, True
    except Exception:
        pass

    # Create the fork
    logger.info(f"Forking {repo_name} to {user.login}...")
    fork = user.create_fork(source_repo)

    # Wait for fork to be ready
    for i in range(10):
        time.sleep(2)
        try:
            g.get_repo(fork.full_name)
            logger.info(f"Fork ready: {fork.full_name}")
            break
        except Exception:
            logger.info(f"Waiting for fork... ({i+1}/10)")

    return fork.full_name, True


def get_repo_clone_url(repo_name: str) -> str:
    """Get the HTTPS clone URL with token auth."""
    token = os.getenv("GITHUB_TOKEN")
    return f"https://x-access-token:{token}@github.com/{repo_name}.git"
