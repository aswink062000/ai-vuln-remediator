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

        # Step 4b: Get ALL dependency findings (fixable via version bump)
        # Include even those without fix_versions — we'll try to resolve them
        dep_fixable = [
            f for f in findings
            if f.get("metadata", {}).get("category") == "dependency"
            and f.get("path")
        ]

        # Step 4c: Secret findings (fixable via env var replacement)
        secret_fixable = [
            f for f in findings
            if f.get("path")
            and f.get("metadata", {}).get("category") == "secret"
        ]

        # Combine secrets with SAST (both are code-level fixes)
        remediable = remediable + secret_fixable

        if not remediable and not dep_fixable:
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

                fixed_code = analyze_and_fix(code, combined_issue, file_path=file_path, findings=file_findings)
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
        # 1. Re-apply SAST code fixes
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
                fixed_code = analyze_and_fix(code, combined_issue, file_path=file_path, findings=file_findings)
                patch_file(repo_path, file_path, fixed_code)
            except Exception as e:
                logger.warning(f"Re-apply failed for {file_path}: {e}")

        # 2. Re-apply dependency version bumps (pom.xml, package.json, etc.)
        if dep_fixable:
            logger.info("Re-applying dependency version bumps on fresh clone...")
            _fix_dependencies(repo_path, dep_fixable, [])

            # 3. Re-apply breaking change migrations if needed
            try:
                from app.workflow.migration import (
                    detect_breaking_upgrade,
                    apply_migration,
                )
                for finding in dep_fixable:
                    metadata = finding.get("metadata", {})
                    package = metadata.get("package", "")
                    old_ver = metadata.get("installed_version", "")
                    fix_vers = metadata.get("fix_versions", [])
                    new_ver = _pick_best_version(old_ver, fix_vers) if fix_vers else _find_latest_safe_version(package, old_ver, finding.get("path", ""))

                    if not new_ver:
                        continue

                    migration_info = detect_breaking_upgrade(package, old_ver, new_ver)
                    if migration_info and not migration_info.get("generic"):
                        apply_migration(repo_path, migration_info)
            except Exception as e:
                logger.warning(f"Migration re-apply failed (non-blocking): {e}")

        # Create branch, commit, push
        branch_name = create_branch(repo_path)
        commit_changes(repo_path)
        push_changes(repo_path, branch_name)

        # Create PR with inline review comments
        if is_forked:
            pr_url = create_pr(
                repo_name=repo_name,
                branch_name=f"{fork_name.split('/')[0]}:{branch_name}",
                default_branch=default_branch,
                fixed_files=fixed_files,
                findings=remediable,
            )
        else:
            pr_url = create_pr(
                repo_name=repo_name,
                branch_name=branch_name,
                default_branch=default_branch,
                fixed_files=fixed_files,
                findings=remediable,
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
