import os
import logging

logger = logging.getLogger(__name__)


def run_remediation(github_url):
    # Lazy imports — so the app starts even without git installed
    from app.gitops.clone import clone_repo, cleanup_repo, get_default_branch
    from app.gitops.fork import fork_repo, get_repo_clone_url
    from app.scanners.multi_scanner import run_all_scanners
    from app.parsers.file_reader import read_file
    from app.llm.analyzer import analyze_and_fix
    from app.patchers.file_patcher import patch_file
    from app.validators.validate import (
        validate_project,
        detect_project_language,
        check_sdk_availability,
    )
    from app.gitops.branch import create_branch
    from app.gitops.commit import commit_changes
    from app.gitops.push import push_changes
    from app.gitops.pull_request import create_pr

    repo_path = None

    try:
        # Step 1: Clone the repository for scanning
        logger.info(f"Starting remediation for: {github_url}")
        repo_path = clone_repo(github_url)

        # Step 2: Detect project language and check SDK availability
        project_info = detect_project_language(repo_path)
        sdk_check = check_sdk_availability(project_info)

        logger.info(
            f"Project: languages={project_info['languages']}, "
            f"frameworks={project_info['frameworks']}, "
            f"build_tools={project_info['build_tools']}"
        )

        # Step 3: Run all scanners (SAST + Dependency)
        logger.info(f"Running multi-scanner on: {repo_path}")
        scan_result = run_all_scanners(repo_path)

        findings = scan_result["findings"]
        summary = scan_result["summary"]
        errors = scan_result["errors"]

        logger.info(f"Found {len(findings)} total vulnerabilities")

        if not findings:
            return {
                "status": "clean",
                "message": "No vulnerabilities found",
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
                "errors": errors,
            }

        # Step 4: Get all SAST findings (fixable via code changes)
        remediable = [
            f for f in findings
            if f.get("path")
            and f.get("metadata", {}).get("category") == "sast"
        ]

        if not remediable:
            return {
                "status": "vulnerabilities_found",
                "message": (
                    f"Found {len(findings)} vulnerabilities "
                    f"({summary['by_category']}). "
                    "Dependency vulnerabilities require manual version upgrades."
                ),
                "total_findings": len(findings),
                "findings": findings[:50],
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }

        # Step 5: Fix ALL SAST findings, grouped by file
        # Group findings by file path to fix each file once
        files_to_fix = {}
        for f in remediable:
            path = f["path"]
            if path not in files_to_fix:
                files_to_fix[path] = []
            files_to_fix[path].append(f)

        logger.info(
            f"Remediating {len(remediable)} SAST findings "
            f"across {len(files_to_fix)} files"
        )

        fixed_files = []
        failed_files = []

        for file_path, file_findings in files_to_fix.items():
            try:
                code = read_file(repo_path, file_path)

                # Build a combined issue description for all findings in this file
                issues = []
                for f in file_findings:
                    issues.append(
                        f"- Line {f.get('line', '?')}: [{f['severity']}] "
                        f"{f['rule_id']}: {f['message']}"
                    )
                combined_issue = "\n".join(issues)

                logger.info(
                    f"Fixing {len(file_findings)} issues in {file_path}"
                )

                fixed_code = analyze_and_fix(code, combined_issue)
                patch_file(repo_path, file_path, fixed_code)
                fixed_files.append({
                    "path": file_path,
                    "findings_fixed": len(file_findings),
                })

            except Exception as e:
                logger.error(f"Failed to fix {file_path}: {e}")
                failed_files.append({
                    "path": file_path,
                    "error": str(e)[:200],
                })

        if not fixed_files:
            return {
                "status": "fix_failed",
                "message": "Failed to generate fixes for all files",
                "total_findings": len(findings),
                "failed_files": failed_files,
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }

        # Step 6: Validate
        valid = validate_project(repo_path)

        if not valid:
            return {
                "status": "validation_failed",
                "message": "Validation failed after applying fixes",
                "fixed_files": fixed_files,
                "total_findings": len(findings),
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }

        # Step 7: Git operations — fork if needed, push and create PR
        cleanup_repo(repo_path)
        repo_path = None

        repo_name = github_url.replace(
            "https://github.com/", ""
        ).replace(".git", "")

        # Fork if we don't have push access
        logger.info(f"Checking push access to {repo_name}...")
        fork_name, is_forked = fork_repo(repo_name)

        # Clone with auth
        clone_url = get_repo_clone_url(fork_name)
        repo_path = clone_repo(clone_url)

        default_branch = get_default_branch(repo_path)

        # Re-apply ALL fixes on the fresh clone
        for file_path, file_findings in files_to_fix.items():
            try:
                code = read_file(repo_path, file_path)
                issues = []
                for f in file_findings:
                    issues.append(
                        f"- Line {f.get('line', '?')}: [{f['severity']}] "
                        f"{f['rule_id']}: {f['message']}"
                    )
                combined_issue = "\n".join(issues)
                fixed_code = analyze_and_fix(code, combined_issue)
                patch_file(repo_path, file_path, fixed_code)
            except Exception as e:
                logger.warning(f"Re-apply failed for {file_path}: {e}")

        # Create branch, commit, push
        branch_name = create_branch(repo_path)
        commit_changes(repo_path)
        push_changes(repo_path, branch_name)

        # Create PR
        if is_forked:
            pr_url = create_pr(
                repo_name=repo_name,
                branch_name=f"{fork_name.split('/')[0]}:{branch_name}",
                default_branch=default_branch,
            )
        else:
            pr_url = create_pr(
                repo_name=repo_name,
                branch_name=branch_name,
                default_branch=default_branch,
            )

        total_fixed = sum(f["findings_fixed"] for f in fixed_files)

        return {
            "status": "success",
            "pull_request": pr_url,
            "total_findings": len(findings),
            "sast_findings_fixed": total_fixed,
            "files_fixed": fixed_files,
            "files_failed": failed_files,
            "remaining_dependency_findings": len(findings) - len(remediable),
            "scan_summary": summary,
            "project_info": project_info,
            "sdk_status": sdk_check,
            "all_findings": findings[:50],
            "forked": is_forked,
            "fork_repo": fork_name if is_forked else None,
        }

    except Exception as e:
        logger.error(f"Remediation failed: {e}", exc_info=True)
        return {
            "status": "error",
            "message": str(e),
        }

    finally:
        if repo_path:
            cleanup_repo(repo_path)
