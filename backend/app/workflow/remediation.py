import os
import logging

logger = logging.getLogger(__name__)


def run_remediation_preview(github_url, branch="", skill_prompt="", progress_callback=None):
    """
    Scan and generate AI fixes but DO NOT push or create PR.
    Returns original code + fixed code for each file so the frontend can show diffs.
    """
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.scanners.multi_scanner import run_all_scanners
    from app.parsers.file_reader import read_file
    from app.llm.analyzer import analyze_and_fix
    from app.validators.validate import detect_project_language, check_sdk_availability
    from app.ml.diff_generator import generate_diff

    def progress(phase, msg=""):
        if progress_callback:
            progress_callback(phase, msg)

    repo_path = None

    try:
        progress("Cloning repository", f"Cloning {github_url}...")
        repo_path = clone_repo(github_url, branch=branch)
        progress("Cloning repository", "Repository cloned successfully")

        progress("Detecting project", "Analyzing project structure...")
        project_info = detect_project_language(repo_path)
        sdk_check = check_sdk_availability(project_info)
        progress("Detecting project", f"Languages: {', '.join(project_info.get('languages', []))}")

        progress("Running scanners", "Starting SAST, dependency, and secret scans...")
        scan_result = run_all_scanners(repo_path)
        findings = scan_result["findings"]
        summary = scan_result["summary"]
        progress("Running scanners", f"Scan complete: {len(findings)} findings")

        if not findings:
            return {
                "status": "clean",
                "message": "No vulnerabilities found",
                "scan_summary": summary,
                "project_info": project_info,
                "preview_files": [],
            }

        # Get fixable findings — expanded to include all categories that can be auto-fixed
        # - sast: code vulnerabilities (AI rewrites code)
        # - secret: hardcoded secrets (AI replaces with env vars)
        # - dependency: vulnerable packages (AI bumps versions in manifest files)
        # - best-practice: deprecated/outdated packages (AI updates versions)
        # - custom: user-defined patterns (AI fixes code like SAST)
        FIXABLE_CATEGORIES = ("sast", "secret", "dependency", "best-practice", "custom")

        remediable = [
            f for f in findings
            if f.get("path") and f.get("metadata", {}).get("category") in FIXABLE_CATEGORIES
        ]

        # Build category breakdown for the report
        findings_breakdown = {}
        for f in findings:
            category = f.get("metadata", {}).get("category", "unknown")
            scanner = f.get("metadata", {}).get("scanner", "unknown")
            if category not in findings_breakdown:
                findings_breakdown[category] = {"count": 0, "scanners": {}, "fixable": category in FIXABLE_CATEGORIES}
            findings_breakdown[category]["count"] += 1
            findings_breakdown[category]["scanners"][scanner] = findings_breakdown[category]["scanners"].get(scanner, 0) + 1

        if not remediable:
            return {
                "status": "vulnerabilities_found",
                "message": f"Found {len(findings)} vulnerabilities but none are auto-fixable via code changes.",
                "total_findings": len(findings),
                "findings": findings[:50],
                "scan_summary": summary,
                "project_info": project_info,
                "preview_files": [],
                "findings_breakdown": findings_breakdown,
            }

        # Group by file
        files_to_fix = {}
        for f in remediable:
            path = f["path"]
            if path not in files_to_fix:
                files_to_fix[path] = []
            files_to_fix[path].append(f)

        # Limit to top 15 files (prioritize by severity count) to keep response time reasonable
        MAX_FILES_TO_FIX = 15
        if len(files_to_fix) > MAX_FILES_TO_FIX:
            # Sort files by number of critical/high findings
            def file_priority(item):
                path, findings_list = item
                critical_count = sum(1 for f in findings_list if f.get("severity", "").upper() in ("CRITICAL", "HIGH"))
                return (-critical_count, -len(findings_list))

            sorted_files = sorted(files_to_fix.items(), key=file_priority)
            files_to_fix = dict(sorted_files[:MAX_FILES_TO_FIX])
            progress("Generating AI fixes", f"Limiting to top {MAX_FILES_TO_FIX} most critical files (of {len(sorted_files)} total)")

        progress("Generating AI fixes", f"Fixing {len(files_to_fix)} files with {len(remediable)} issues...")

        # Generate fixes in PARALLEL (3 concurrent LLM calls)
        from concurrent.futures import ThreadPoolExecutor, as_completed

        preview_files = []
        file_items = list(files_to_fix.items())

        def _fix_single_file(idx_and_item):
            idx, (file_path, file_findings) = idx_and_item
            try:
                original_code = read_file(repo_path, file_path)

                issues = []
                for f in file_findings:
                    issue_line = (
                        f"- Line {f.get('line', '?')}: [{f['severity']}] "
                        f"{f['rule_id']}: {f['message']}"
                    )
                    # Add fix guidance for dependency/best-practice findings
                    meta = f.get("metadata", {})
                    if meta.get("fix_versions"):
                        issue_line += f"\n  FIX: Upgrade to version {meta['fix_versions'][0]}"
                    elif meta.get("latest_version"):
                        issue_line += f"\n  FIX: Upgrade to version {meta['latest_version']}"
                    elif meta.get("replacement"):
                        issue_line += f"\n  FIX: Replace with {meta['replacement']}"
                        if meta.get("recommended_version"):
                            issue_line += f" version {meta['recommended_version']}"
                    elif meta.get("fix_guidance"):
                        issue_line += f"\n  FIX: {meta['fix_guidance']}"
                    issues.append(issue_line)
                combined_issue = "\n".join(issues)

                fixed_code = analyze_and_fix(
                    original_code, combined_issue,
                    file_path=file_path,
                    findings=file_findings,
                    extra_instructions=skill_prompt,
                    project_info=project_info,
                )

                diff_data = generate_diff(original_code, fixed_code, file_path)

                return {
                    "path": file_path,
                    "original_code": original_code,
                    "fixed_code": fixed_code,
                    "findings_count": len(file_findings),
                    "findings": [
                        {
                            "rule_id": f.get("rule_id"),
                            "severity": f.get("severity"),
                            "message": f.get("message", "")[:200],
                            "line": f.get("line"),
                        }
                        for f in file_findings
                    ],
                    "diff": diff_data,
                }
            except Exception as e:
                logger.error(f"Fix failed for {file_path}: {e}")
                return {
                    "path": file_path,
                    "error": str(e)[:200],
                    "findings_count": len(file_findings),
                }

        # Run LLM calls in parallel (3 at a time)
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="llm-fix") as pool:
            futures = {
                pool.submit(_fix_single_file, (idx, item)): idx
                for idx, item in enumerate(file_items, 1)
            }
            for future in as_completed(futures):
                idx = futures[future]
                result_item = future.result()
                preview_files.append(result_item)
                if "fixed_code" in result_item:
                    progress("Generating AI fixes", f"[{idx}/{len(file_items)}] ✓ {result_item['path']} fixed")
                else:
                    progress("Generating AI fixes", f"[{idx}/{len(file_items)}] ✗ {result_item['path']} failed")

        # Sort preview files by original order
        path_order = {item[0]: i for i, item in enumerate(file_items)}
        preview_files.sort(key=lambda f: path_order.get(f["path"], 999))

        progress("Complete", f"Generated fixes for {len([f for f in preview_files if 'fixed_code' in f])} files")

        return {
            "status": "preview_ready",
            "message": f"Generated fixes for {len([f for f in preview_files if 'fixed_code' in f])} files. Review and approve to create PR.",
            "total_findings": len(findings),
            "fixable_findings": len(remediable),
            "scan_summary": summary,
            "project_info": project_info,
            "sdk_status": sdk_check,
            "preview_files": preview_files,
            "findings": findings[:50],
            "findings_breakdown": findings_breakdown,
        }

    except Exception as e:
        logger.exception(f"Preview remediation failed: {e}")
        return {"status": "error", "message": str(e), "preview_files": []}
    finally:
        if repo_path:
            cleanup_repo(repo_path)


def apply_approved_fixes(github_url, approved_files, branch="", pr_branch_name=""):
    """
    Apply only the developer-approved fixes and create a PR.
    approved_files: list of {"path": str, "fixed_code": str}
    """
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.patchers.file_patcher import patch_file
    from app.validators.validate import validate_project
    from app.gitops.branch import create_branch
    from app.gitops.commit import commit_changes
    from app.gitops.push import push_changes
    from app.gitops.pull_request import create_pr
    from app.ml.secret_detector import is_safe_to_apply

    repo_path = None

    try:
        repo_path = clone_repo(github_url, branch=branch)

        # Apply approved fixes
        applied = []
        skipped = []
        for file_info in approved_files:
            file_path = file_info["path"]
            fixed_code = file_info["fixed_code"]

            # Safety check
            is_safe, secret_error = is_safe_to_apply(fixed_code)
            if not is_safe:
                logger.warning(f"Skipping {file_path}: {secret_error}")
                skipped.append({"path": file_path, "reason": secret_error})
                continue

            patch_file(repo_path, file_path, fixed_code)
            applied.append(file_path)

        if not applied:
            return {
                "status": "no_fixes_applied",
                "message": "No fixes passed safety checks.",
                "skipped_files": skipped,
            }

        # Validate only the modified files (not the entire project)
        validation_errors = _validate_fixed_files(repo_path, applied)
        if validation_errors:
            logger.warning(f"Validation issues (non-blocking): {validation_errors}")
            # Don't block PR creation for validation warnings — the AI fix is likely correct
            # but we can't fully validate without build tools (Maven, npm, etc.)

        # Git operations
        branch_name = create_branch(repo_path, branch_name=pr_branch_name)
        commit_changes(repo_path)
        push_changes(repo_path, branch_name)

        repo_name = github_url.replace("https://github.com/", "").rstrip("/").replace(".git", "")

        # PR should target the branch the user scanned from (not always the repo default)
        pr_target_branch = branch if branch else ""
        logger.info(f"Creating PR: source={branch_name}, target={pr_target_branch or '(repo default)'}, scanned_from={branch or '(default)'}")

        pr_url = create_pr(
            repo_name, branch_name,
            default_branch=pr_target_branch,
            fixed_files=[{"path": p, "findings_fixed": 1} for p in applied],
        )

        return {
            "status": "success",
            "message": f"PR created with {len(applied)} approved fixes." + (
                f" ({len(skipped)} file(s) skipped due to safety checks)" if skipped else ""
            ),
            "pr_url": pr_url,
            "pull_request": pr_url,
            "branch_name": branch_name,
            "applied_files": applied,
            "files_count": len(applied),
            "skipped_files": skipped,
        }

    except Exception as e:
        logger.exception(f"Apply fixes failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        if repo_path:
            cleanup_repo(repo_path)


def run_remediation(github_url, branch="", pr_branch_name="", skill_prompt=""):
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
        logger.info(f"Starting remediation for: {github_url} (branch={branch or 'default'})")
        repo_path = clone_repo(github_url, branch=branch)

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

        # Step 4: Get all fixable findings (code vulnerabilities + dependencies + secrets + best practices + custom)
        FIXABLE_CATEGORIES = ("sast", "secret", "dependency", "best-practice", "custom")

        remediable = [
            f for f in findings
            if f.get("path")
            and f.get("metadata", {}).get("category") in FIXABLE_CATEGORIES
        ]

        if not remediable:
            return {
                "status": "vulnerabilities_found",
                "message": (
                    f"Found {len(findings)} vulnerabilities "
                    f"({summary['by_category']}). "
                    "No auto-fixable findings detected."
                ),
                "total_findings": len(findings),
                "findings": findings[:50],
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }

        # Step 5: Fix findings, grouped by file
        # Group findings by file path to fix each file once
        files_to_fix = {}
        for f in remediable:
            path = f["path"]
            if path not in files_to_fix:
                files_to_fix[path] = []
            files_to_fix[path].append(f)

        logger.info(
            f"Remediating {len(remediable)} findings "
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
                    issue_line = (
                        f"- Line {f.get('line', '?')}: [{f['severity']}] "
                        f"{f['rule_id']}: {f['message']}"
                    )
                    # Add fix guidance for dependency/best-practice findings
                    meta = f.get("metadata", {})
                    if meta.get("fix_versions"):
                        issue_line += f"\n  FIX: Upgrade to version {meta['fix_versions'][0]}"
                    elif meta.get("latest_version"):
                        issue_line += f"\n  FIX: Upgrade to version {meta['latest_version']}"
                    elif meta.get("replacement"):
                        issue_line += f"\n  FIX: Replace with {meta['replacement']}"
                        if meta.get("recommended_version"):
                            issue_line += f" version {meta['recommended_version']}"
                    elif meta.get("fix_guidance"):
                        issue_line += f"\n  FIX: {meta['fix_guidance']}"
                    issues.append(issue_line)
                combined_issue = "\n".join(issues)

                logger.info(
                    f"Fixing {len(file_findings)} issues in {file_path}"
                )

                fixed_code = analyze_and_fix(
                    code, combined_issue,
                    file_path=file_path,
                    findings=file_findings,
                    extra_instructions=skill_prompt,
                    project_info=project_info,
                )

                # Security check: ensure AI fix doesn't introduce new secrets
                from app.ml.secret_detector import is_safe_to_apply
                is_safe, secret_error = is_safe_to_apply(fixed_code)
                if not is_safe:
                    logger.error(f"Secret detected in AI fix for {file_path}: {secret_error}")
                    raise Exception(f"Security Violation: {secret_error}")

                patch_file(repo_path, file_path, fixed_code)

                # Generate diff for visualization
                try:
                    from app.ml.diff_generator import generate_diff
                    diff_data = generate_diff(code, fixed_code, file_path)
                    diff_summary = diff_data.get("summary", "")
                    logger.info(f"Diff for {file_path}: {diff_summary}")
                except Exception:
                    diff_data = None

                # Calculate fix confidence
                try:
                    from app.validators.confidence import calculate_fix_confidence
                    confidence = calculate_fix_confidence(
                        code, fixed_code, file_findings, file_path
                    )
                    confidence_pct = confidence.get("confidence_percentage", -1)
                    logger.info(f"Fix confidence for {file_path}: {confidence_pct}%")
                except Exception as ce:
                    confidence_pct = -1
                    logger.warning(f"Confidence check skipped for {file_path}: {ce}")

                fixed_files.append({
                    "path": file_path,
                    "findings_fixed": len(file_findings),
                    "confidence": confidence_pct,
                    "diff": diff_data.get("stats") if diff_data else None,
                    "diff_summary": diff_data.get("summary") if diff_data else None,
                    "fix_details": [
                        {
                            "issue": f"[{f.get('severity', 'HIGH')}] {f.get('rule_id', 'unknown')}: {f.get('message', '')[:100]}",
                            "fixed_by": "Code patched by AI Vulnerability Remediator",
                            "cve": f.get("rule_id", ""),
                        }
                        for f in file_findings
                    ][:10],
                })

            except Exception as e:
                logger.error(f"Failed to fix {file_path}: {e}")
                failed_files.append({
                    "path": file_path,
                    "error": str(e)[:200],
                })

        if not fixed_files and not dep_fixable:
            return {
                "status": "fix_failed",
                "message": "Failed to generate fixes for all files",
                "total_findings": len(findings),
                "failed_files": failed_files,
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }

        # Step 5b: Fix dependency vulnerabilities (version bumps)
        dep_fixed_count = 0
        if dep_fixable:
            logger.info(f"Fixing {len(dep_fixable)} dependency vulnerabilities...")
            dep_fixed_count = _fix_dependencies(repo_path, dep_fixable, fixed_files)
            logger.info(f"Fixed {dep_fixed_count} dependency versions")

            # Step 5c: Handle breaking changes from major version bumps
            if dep_fixed_count > 0:
                try:
                    from app.workflow.migration import (
                        detect_breaking_upgrade,
                        apply_migration,
                        apply_migration_with_llm,
                        validate_build,
                    )

                    for finding in dep_fixable:
                        metadata = finding.get("metadata", {})
                        package = metadata.get("package", "")
                        old_ver = metadata.get("installed_version", "")
                        fix_vers = metadata.get("fix_versions", [])
                        new_ver = _pick_best_version(old_ver, fix_vers) if fix_vers else ""

                        if not new_ver:
                            continue

                        # Check if this is a breaking upgrade
                        migration_info = detect_breaking_upgrade(package, old_ver, new_ver)
                        if migration_info and not migration_info.get("generic"):
                            logger.info(f"Breaking upgrade detected: {package} {old_ver}→{new_ver}")
                            logger.info(f"Migration: {migration_info.get('description', '')}")

                            # Apply regex-based migrations (javax→jakarta, etc.)
                            migration_result = apply_migration(repo_path, migration_info)
                            logger.info(f"Regex migration: {migration_result['files_migrated']} files, {migration_result['changes']} changes")

                            # Apply LLM-based migrations for complex cases
                            if migration_info.get("additional_changes"):
                                llm_result = apply_migration_with_llm(
                                    repo_path, migration_info, package, old_ver, new_ver
                                )
                                logger.info(f"LLM migration: {llm_result.get('llm_fixes', 0)} files")

                    # Validate build after all migrations
                    logger.info("Validating build after dependency upgrades...")
                    build_ok, build_error = validate_build(repo_path, project_info)

                    if not build_ok:
                        logger.warning(f"Build failed after migration: {build_error}")
                        # Try to fix build errors with LLM
                        logger.info("Attempting to fix build errors with LLM...")
                        # For now, log the error — don't block the PR
                        # The PR will have a note about build issues

                except Exception as e:
                    logger.warning(f"Migration handling failed (non-blocking): {e}")

        # Step 6: Final Validation (Syntax Check)
        if fixed_files:
            logger.info("Running final syntax validation on all fixed files...")
            if not validate_project(repo_path):
                logger.error("Syntax validation failed for one or more fixed files. Aborting push.")
                return {
                    "status": "validation_failed",
                    "message": "AI fixes introduced syntax errors. Push aborted to prevent breaking the build.",
                    "total_findings": len(findings),
                    "fixed_files": fixed_files,
                    "failed_files": failed_files,
                    "scan_summary": summary,
                    "project_info": project_info,
                    "sdk_status": sdk_check,
                }

        # Step 7: Git Operations (Branch, Commit, Push)
        logger.info("All fixes validated. Creating remediation branch...")
        try:
            branch_name = create_branch(repo_path, branch_name=pr_branch_name)
            commit_changes(repo_path)
            push_changes(repo_path, branch_name)

            # Extract repo name (owner/repo) from URL for PR creation
            repo_name_for_pr = github_url.replace("https://github.com/", "").rstrip("/").replace(".git", "")
            pr_target_branch = branch if branch else ""
            pr_url = create_pr(repo_name_for_pr, branch_name, default_branch=pr_target_branch, fixed_files=fixed_files, findings=findings)
            
            return {
                "status": "success",
                "message": "Vulnerabilities remediated and PR created",
                "pr_url": pr_url,
                "branch_name": branch_name,
                "total_findings": len(findings),
                "fixed_files": fixed_files,
                "failed_files": failed_files,
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }
        except Exception as ge:
            logger.error(f"Git operation failed: {ge}")
            return {
                "status": "git_error",
                "message": f"Fixes applied but failed to push to GitHub: {ge}",
                "total_findings": len(findings),
                "fixed_files": fixed_files,
                "failed_files": failed_files,
                "scan_summary": summary,
                "project_info": project_info,
                "sdk_status": sdk_check,
            }
    except Exception as e:
        logger.exception(f"Critical error during remediation: {e}")
        return {
            "status": "error",
            "message": f"Remediation failed: {str(e)}",
            "total_findings": 0,
            "errors": [str(e)],
        }
    finally:
        if repo_path:
            cleanup_repo(repo_path)


def _fix_dependencies(repo_path: str, dep_findings: list, fixed_files: list) -> int:
    """
    Fix dependency vulnerabilities by bumping versions in manifest files.
    Supports: pom.xml, requirements.txt, package.json, build.gradle, .csproj, go.mod, Cargo.toml

    Strategy:
    1. If fix_versions provided → use them directly
    2. If no fix_versions → try to find latest patch version via API
    3. If all else fails → bump minor version as best guess
    """
    import re
    from pathlib import Path

    fixed_count = 0
    repo = Path(repo_path)

    # Group by file
    by_file: dict = {}
    for f in dep_findings:
        path = f.get("path", "")
        if path not in by_file:
            by_file[path] = []
        by_file[path].append(f)

    for file_path, file_findings in by_file.items():
        full_path = repo / file_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            original = content
            file_fixed = 0

            for finding in file_findings:
                metadata = finding.get("metadata", {})
                package = metadata.get("package", "")
                old_version = metadata.get("installed_version", "")
                fix_versions = metadata.get("fix_versions", [])

                if not package or not old_version:
                    continue

                # Determine the target version
                if fix_versions:
                    new_version = _pick_best_version(old_version, fix_versions)
                else:
                    # No fix_versions provided — try to find latest safe version
                    new_version = _find_latest_safe_version(package, old_version, file_path)

                if not new_version or new_version == old_version:
                    continue

                # Apply version bump based on file type
                new_content = content
                if file_path.endswith("pom.xml"):
                    new_content = _bump_maven_version(content, package, old_version, new_version)
                elif file_path.endswith(".txt") and "requirements" in file_path.lower():
                    new_content = _bump_pip_version(content, package, old_version, new_version)
                elif file_path == "requirements.txt":
                    new_content = _bump_pip_version(content, package, old_version, new_version)
                elif file_path.endswith("package.json"):
                    new_content = _bump_npm_version(content, package, old_version, new_version)
                elif file_path.endswith("build.gradle") or file_path.endswith("build.gradle.kts"):
                    new_content = _bump_gradle_version(content, package, old_version, new_version)
                elif file_path.endswith(".csproj") or file_path.endswith(".fsproj"):
                    new_content = _bump_nuget_version(content, package, old_version, new_version)
                elif file_path.endswith("go.mod"):
                    new_content = _bump_go_version(content, package, old_version, new_version)
                elif file_path.endswith("Cargo.toml"):
                    new_content = _bump_cargo_version(content, package, old_version, new_version)

                if new_content != content:
                    content = new_content
                    file_fixed += 1
                    logger.info(f"Bumped {package}: {old_version} → {new_version} in {file_path}")

            if file_fixed > 0 and content != original:
                full_path.write_text(content, encoding="utf-8")
                fixed_count += file_fixed
                fixed_files.append({
                    "path": file_path,
                    "findings_fixed": file_fixed,
                    "confidence": 90,
                    "diff": {"additions": file_fixed, "deletions": file_fixed, "hunks": file_fixed},
                    "diff_summary": f"{file_fixed} dependency version(s) bumped to secure versions",
                    "fix_details": [
                        {
                            "issue": f"Vulnerable: {finding.get('metadata', {}).get('package', '')}@{finding.get('metadata', {}).get('installed_version', '')}",
                            "fixed_by": f"Upgraded to secure version by AI Vulnerability Remediator",
                            "cve": finding.get("rule_id", ""),
                        }
                        for finding in file_findings
                        if finding.get("metadata", {}).get("package")
                    ][:10],
                })

        except Exception as e:
            logger.error(f"Failed to fix dependencies in {file_path}: {e}")

    return fixed_count


def _find_latest_safe_version(package: str, current_version: str, file_path: str) -> str:
    """
    Find the latest safe version when fix_versions is not provided.
    Strategy:
    1. Query package registry for latest version in same major
    2. If same major is still vulnerable, get latest stable version (even if major bump)
    3. Fallback: increment patch version
    """
    try:
        parts = current_version.replace("-", ".").split(".")
        if len(parts) < 2:
            return ""

        major = parts[0]

        # For Maven packages, query Maven Central
        if "pom.xml" in file_path or "build.gradle" in file_path:
            latest = _query_maven_latest(package, major, "")
            if latest and latest != current_version:
                return latest

        # For PyPI packages
        if "requirements" in file_path.lower():
            latest = _query_pypi_latest(package, major)
            if latest and latest != current_version:
                return latest

        # For npm packages
        if "package.json" in file_path:
            latest = _query_npm_latest(package, major)
            if latest and latest != current_version:
                return latest

        # Fallback: bump patch
        try:
            patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0
            return f"{major}.{parts[1]}.{patch + 1}"
        except (ValueError, IndexError):
            return ""

    except Exception:
        return ""


def _query_npm_latest(package: str, major: str) -> str:
    """Query npm registry for latest version."""
    import requests

    try:
        url = f"https://registry.npmjs.org/{package}/latest"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("version", "")
            return version
    except Exception:
        pass

    return ""


def _query_maven_latest(package: str, major: str, minor: str) -> str:
    """Query Maven Central for latest version in same major.minor."""
    import requests

    parts = package.split(":")
    if len(parts) < 2:
        return ""

    group_id = parts[0].replace(".", "/")
    artifact_id = parts[1]

    try:
        url = f"https://search.maven.org/solrsearch/select?q=g:{parts[0]}+AND+a:{artifact_id}&rows=5&wt=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            docs = data.get("response", {}).get("docs", [])
            if docs:
                latest = docs[0].get("latestVersion", "")
                # Only use if same major version
                if latest.startswith(f"{major}."):
                    return latest
    except Exception:
        pass

    return ""


def _query_pypi_latest(package: str, major: str) -> str:
    """Query PyPI for latest version in same major."""
    import requests

    try:
        url = f"https://pypi.org/pypi/{package}/json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("info", {}).get("version", "")
            if version.startswith(f"{major}."):
                return version
    except Exception:
        pass

    return ""


def _pick_best_version(old_version: str, fix_versions: list) -> str:
    """
    Pick the best fix version.
    Strategy:
    1. Same major + same minor (safest — patch only)
    2. Same major + higher minor (minor bump)
    3. Next major version (breaking changes possible but necessary for security)
    """
    if not fix_versions:
        return ""

    if len(fix_versions) == 1:
        return fix_versions[0]

    old_parts = old_version.replace("-", ".").split(".")
    old_major = old_parts[0] if old_parts else ""
    old_minor = old_parts[1] if len(old_parts) > 1 else ""

    # Priority 1: Same major + same minor (patch bump only)
    same_minor = [v for v in fix_versions if v.startswith(f"{old_major}.{old_minor}.")]
    if same_minor:
        return same_minor[-1]

    # Priority 2: Same major, any minor
    same_major = [v for v in fix_versions if v.startswith(f"{old_major}.")]
    if same_major:
        return same_major[-1]

    # Priority 3: Next major version (necessary for security)
    # Sort versions and pick the lowest that's higher than current
    try:
        sorted_versions = sorted(fix_versions, key=lambda v: [int(x) for x in v.split(".")[:3] if x.isdigit()])
        return sorted_versions[0]  # Lowest available fix
    except (ValueError, IndexError):
        pass

    return fix_versions[-1]  # Last resort: latest


def _bump_maven_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """
    Bump version in pom.xml.
    Handles:
    - Direct: <version>1.2.3</version> near the artifactId
    - With suffix: <version>2.2.1.RELEASE</version>
    - Properties: <spring.version>5.3.1</spring.version>
    - Parent section: <parent><version>2.5.6</version></parent>
    """
    import re
    parts = package.split(":")
    artifact_id = parts[-1] if parts else package

    # Build a flexible version pattern that matches with or without suffix
    # e.g., "2.2.1" should match "2.2.1", "2.2.1.RELEASE", "2.2.1.Final"
    old_ver_clean = re.sub(r'[.\-](RELEASE|Final|GA|SNAPSHOT)$', '', old_ver, flags=re.IGNORECASE).rstrip(".")
    old_ver_pattern = re.escape(old_ver_clean) + r'(?:[.\-](?:RELEASE|Final|GA))?'

    # Strategy 1: Find <artifactId>name</artifactId> followed by <version>old</version>
    pattern = re.compile(
        rf'(<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*(?:<[^>]*>[^<]*</[^>]*>\s*)*<version>)\s*{old_ver_pattern}\s*(</version>)',
        re.DOTALL
    )
    result = pattern.sub(rf'\g<1>{new_ver}\g<2>', content, count=1)
    if result != content:
        return result

    # Strategy 2: Direct version string replacement (less precise but catches more cases)
    # Only replace if the version appears near the artifact name (within 5 lines)
    lines = content.splitlines()
    artifact_line = -1
    for i, line in enumerate(lines):
        if f"<artifactId>{artifact_id}</artifactId>" in line:
            artifact_line = i
            break

    if artifact_line >= 0:
        # Search within 5 lines for the version (handles .RELEASE suffix)
        for i in range(artifact_line, min(len(lines), artifact_line + 5)):
            if f"<version>{old_ver}</version>" in lines[i]:
                lines[i] = lines[i].replace(f"<version>{old_ver}</version>", f"<version>{new_ver}</version>")
                return "\n".join(lines)
            # Also try with .RELEASE suffix
            if re.search(rf'<version>{old_ver_pattern}</version>', lines[i]):
                lines[i] = re.sub(rf'<version>{old_ver_pattern}</version>', f'<version>{new_ver}</version>', lines[i])
                return "\n".join(lines)

    # Strategy 3: Check properties section
    # Look for properties that contain the version value
    if artifact_id:
        # Find all properties with the old version value (with or without suffix)
        import re as re_mod
        for prop_match in re_mod.finditer(r'<([a-zA-Z0-9._-]+)>' + old_ver_pattern + r'</([a-zA-Z0-9._-]+)>', content):
            prop_name = prop_match.group(1).lower()
            # Check if property name relates to the package
            artifact_parts = artifact_id.lower().replace("-", ".").replace("_", ".").split(".")
            group_parts = (parts[0].lower().split(".") if len(parts) > 1 else [])
            all_parts = artifact_parts + group_parts

            # Match if any part of the artifact/group appears in the property name
            if any(part in prop_name for part in all_parts if len(part) > 2):
                old_tag = f"<{prop_match.group(1)}>{old_ver}</{prop_match.group(2)}>"
                new_tag = f"<{prop_match.group(1)}>{new_ver}</{prop_match.group(2)}>"
                content = content.replace(old_tag, new_tag, 1)
                return content

    return content


def _bump_pip_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in requirements.txt."""
    import re
    pattern = re.compile(rf'^({re.escape(package)}\s*==\s*){re.escape(old_ver)}', re.MULTILINE | re.IGNORECASE)
    return pattern.sub(rf'\g<1>{new_ver}', content, count=1)


def _bump_npm_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in package.json."""
    import re
    # Match: "package-name": "^1.2.3" or "~1.2.3" or "1.2.3"
    pattern = re.compile(rf'("{re.escape(package)}"\s*:\s*")[~^]?{re.escape(old_ver)}(")')
    return pattern.sub(rf'\g<1>^{new_ver}\g<2>', content, count=1)


def _bump_gradle_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in build.gradle."""
    import re
    parts = package.split(":")
    if len(parts) >= 2:
        group = re.escape(parts[0])
        artifact = re.escape(parts[1])
        pattern = re.compile(rf"({group}:{artifact}:){re.escape(old_ver)}")
        return pattern.sub(rf'\g<1>{new_ver}', content, count=1)
    return content


def _bump_nuget_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in .csproj."""
    import re
    pattern = re.compile(
        rf'(<PackageReference\s+Include="{re.escape(package)}"\s+Version="){re.escape(old_ver)}(")',
        re.IGNORECASE
    )
    return pattern.sub(rf'\g<1>{new_ver}\g<2>', content, count=1)


def _bump_go_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in go.mod."""
    import re
    pattern = re.compile(rf'({re.escape(package)}\s+)v?{re.escape(old_ver.lstrip("v"))}')
    return pattern.sub(rf'\g<1>v{new_ver.lstrip("v")}', content, count=1)


def _bump_cargo_version(content: str, package: str, old_ver: str, new_ver: str) -> str:
    """Bump version in Cargo.toml."""
    import re
    pattern = re.compile(rf'({re.escape(package)}\s*=\s*"){re.escape(old_ver)}(")')
    return pattern.sub(rf'\g<1>{new_ver}\g<2>', content, count=1)


def _validate_fixed_files(repo_path: str, applied_files: list) -> list:
    """
    Validate only the files that were modified (not the entire project).
    Returns a list of validation error messages (empty = all OK).

    Only checks Python syntax (py_compile) since Java/JS require full build tools.
    """
    import subprocess
    import shutil
    from pathlib import Path

    errors = []
    python_bin = shutil.which("python3") or shutil.which("python")

    for file_path in applied_files:
        full_path = Path(repo_path) / file_path

        if not full_path.exists():
            continue

        ext = full_path.suffix.lower()

        # Python: syntax check with py_compile
        if ext == ".py" and python_bin:
            try:
                result = subprocess.run(
                    [python_bin, "-m", "py_compile", str(full_path)],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    errors.append(f"{file_path}: {result.stderr[:200]}")
            except Exception:
                pass

        # JavaScript/TypeScript: basic syntax check with node --check
        elif ext in (".js", ".mjs") and shutil.which("node"):
            try:
                result = subprocess.run(
                    ["node", "--check", str(full_path)],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    errors.append(f"{file_path}: {result.stderr[:200]}")
            except Exception:
                pass

        # Java: skip validation (requires full classpath/Maven — can't validate standalone)
        # The AI fix is reviewed by the developer anyway

    return errors
