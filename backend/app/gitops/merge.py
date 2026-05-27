"""
GitHub Merge Manager — Handles merging remediation branches.
"""

import os
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def merge_remediation_branch(repo_name: str, branch_name: str, base_branch: str = "main") -> Tuple[bool, str]:
    """
    Merge a remediation branch into the base branch.
    Returns (success, message).
    """
    from github import Github

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return False, "GITHUB_TOKEN not set in environment"

    try:
        g = Github(token)
        repo = g.get_repo(repo_name)

        # Find the PR associated with this branch
        prs = repo.get_pulls(state='open', head=f"{repo.owner.login}:{branch_name}")
        pr_list = list(prs)
        if not pr_list:
            # If no PR exists, we try to merge directly (though PR is preferred)
            logger.info(f"No open PR found for branch {branch_name}, attempting direct merge.")
            branch = repo.get_branch(branch_name)
            repo.merge(base_branch, branch.commit.sha)
            return True, f"Branch {branch_name} merged directly into {base_branch}."

        pr = pr_list[0]
        # Merge the PR
        pr.merge()
        return True, f"PR #{pr.number} merged successfully into {base_branch}."

    except Exception as e:
        logger.error(f"Merge failed for {repo_name} branch {branch_name}: {e}")
        return False, str(e)
