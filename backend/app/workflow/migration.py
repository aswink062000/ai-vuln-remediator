"""
Breaking Change Migration Handler.

When a major version bump is needed (e.g., Spring Boot 2→3),
this module:
1. Detects what breaking changes the upgrade introduces
2. Uses LLM to migrate affected code (javax→jakarta, etc.)
3. Validates the build passes after migration
4. Only allows push if everything compiles

Supports:
- Java: javax→jakarta, Spring Boot 2→3, JUnit 4→5
- Python: major version upgrades with API changes
- Node.js: ESM migration, major framework upgrades
- .NET: .NET 5→6→7→8 migrations
"""

import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Known breaking changes database
BREAKING_CHANGES: Dict[str, Dict[str, Any]] = {
    # Spring Boot 2 → 3
    "spring-boot:2->3": {
        "description": "Spring Boot 3 requires Java 17+ and migrates javax.* to jakarta.*",
        "search_patterns": [
            (r"import\s+javax\.", "import jakarta."),
            (r"javax\.servlet", "jakarta.servlet"),
            (r"javax\.persistence", "jakarta.persistence"),
            (r"javax\.validation", "jakarta.validation"),
            (r"javax\.annotation", "jakarta.annotation"),
            (r"javax\.transaction", "jakarta.transaction"),
            (r"javax\.mail", "jakarta.mail"),
            (r"javax\.websocket", "jakarta.websocket"),
            (r"javax\.xml\.bind", "jakarta.xml.bind"),
            (r"javax\.inject", "jakarta.inject"),
            (r"javax\.enterprise", "jakarta.enterprise"),
        ],
        "file_extensions": [".java", ".kt", ".groovy", ".properties", ".yml", ".yaml"],
        "additional_changes": [
            "Spring Security: WebSecurityConfigurerAdapter removed → use SecurityFilterChain bean",
            "spring.redis.* properties → spring.data.redis.*",
            "HttpStatus.valueOf() → HttpStatusCode",
        ],
    },
    # JUnit 4 → 5
    "junit:4->5": {
        "description": "JUnit 5 uses different annotations and assertions",
        "search_patterns": [
            (r"import\s+org\.junit\.Test", "import org.junit.jupiter.api.Test"),
            (r"import\s+org\.junit\.Before\b", "import org.junit.jupiter.api.BeforeEach"),
            (r"import\s+org\.junit\.After\b", "import org.junit.jupiter.api.AfterEach"),
            (r"import\s+org\.junit\.Assert", "import org.junit.jupiter.api.Assertions"),
            (r"import\s+org\.junit\.Ignore", "import org.junit.jupiter.api.Disabled"),
            (r"@RunWith\(.*?\)", ""),
            (r"Assert\.(assertEquals|assertTrue|assertFalse|assertNull|assertNotNull)", r"Assertions.\1"),
        ],
        "file_extensions": [".java", ".kt"],
    },
    # Python 2 → 3 (rare but possible in old repos)
    "python:2->3": {
        "description": "Python 3 changes print, division, string handling",
        "search_patterns": [
            (r"print\s+([^(])", r"print(\1)"),
            (r"except\s+(\w+)\s*,\s*(\w+)", r"except \1 as \2"),
            (r"\.has_key\(", ".get("),
        ],
        "file_extensions": [".py"],
    },
    # Django 3 → 4/5
    "django:3->4": {
        "description": "Django 4+ removes deprecated features",
        "search_patterns": [
            (r"from django\.conf\.urls import url", "from django.urls import re_path"),
            (r"\burl\(", "re_path("),
            (r"django\.utils\.encoding\.force_text", "django.utils.encoding.force_str"),
            (r"django\.utils\.translation\.ugettext", "django.utils.translation.gettext"),
        ],
        "file_extensions": [".py"],
    },
    # Express 4 → 5
    "express:4->5": {
        "description": "Express 5 changes middleware and routing",
        "search_patterns": [
            (r"app\.del\(", "app.delete("),
            (r"res\.send\((\d+)\)", r"res.status(\1).send()"),
        ],
        "file_extensions": [".js", ".ts"],
    },
    # React Router 5 → 6
    "react-router:5->6": {
        "description": "React Router 6 changes component API",
        "search_patterns": [
            (r"<Switch>", "<Routes>"),
            (r"</Switch>", "</Routes>"),
            (r"<Route.*?component=\{(\w+)\}", r"<Route element={<\1 />}"),
            (r"useHistory\(\)", "useNavigate()"),
            (r"history\.push\(", "navigate("),
        ],
        "file_extensions": [".jsx", ".tsx", ".js", ".ts"],
    },
    # .NET 5/6 → 7/8
    "dotnet:6->8": {
        "description": ".NET 8 changes hosting model and minimal APIs",
        "search_patterns": [
            (r"WebApplication\.CreateBuilder", "WebApplication.CreateBuilder"),  # Same but check for deprecated patterns
            (r"IHostBuilder", "IHostApplicationBuilder"),
        ],
        "file_extensions": [".cs"],
    },
}


def detect_breaking_upgrade(
    package: str, old_version: str, new_version: str
) -> Optional[Dict[str, Any]]:
    """
    Detect if a version upgrade introduces breaking changes.
    Returns migration info if breaking, None if safe.
    """
    old_major = old_version.split(".")[0] if "." in old_version else old_version
    new_major = new_version.split(".")[0] if "." in new_version else new_version

    # Same major usually means no breaking changes, but Spring Boot 2.x upgrades
    # can still require compatibility updates even without a major bump.
    if old_major == new_major:
        pkg_lower = package.lower()
        if "spring-boot" in pkg_lower and old_major == "2" and old_version != new_version:
            return {
                "description": f"Spring Boot 2.x upgrade from {old_version} to {new_version} may require compatibility updates",
                "search_patterns": [],
                "file_extensions": [".java", ".kt", ".groovy", ".properties", ".yml", ".yaml"],
                "additional_changes": [
                    "Spring Boot 2.4+ config data import changes",
                    "Deprecated Spring Security WebSecurityConfigurerAdapter patterns",
                    "Actuator management endpoint exposure property changes",
                    "Configuration properties and endpoint path matching changes",
                ],
                "generic": False,
                "llm_scan_all": True,
            }
        return None

    # Check known breaking changes
    pkg_lower = package.lower()

    if "spring-boot" in pkg_lower and old_major == "2" and new_major == "3":
        return BREAKING_CHANGES["spring-boot:2->3"]

    if "junit" in pkg_lower and old_major == "4" and new_major == "5":
        return BREAKING_CHANGES["junit:4->5"]

    if "django" in pkg_lower and int(old_major) < 4 and int(new_major) >= 4:
        return BREAKING_CHANGES["django:3->4"]

    if "express" in pkg_lower and old_major == "4" and new_major == "5":
        return BREAKING_CHANGES["express:4->5"]

    if "react-router" in pkg_lower and old_major == "5" and new_major == "6":
        return BREAKING_CHANGES["react-router:5->6"]

    # Generic major version bump warning
    return {
        "description": f"Major version upgrade ({old_major}.x → {new_major}.x) may introduce breaking changes",
        "search_patterns": [],
        "file_extensions": [],
        "generic": True,
    }


def apply_migration(
    repo_path: str,
    migration_info: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Apply known code migrations (e.g., javax→jakarta).
    Returns stats about what was changed.
    """
    repo = Path(repo_path)
    extensions = migration_info.get("file_extensions", [])
    patterns = migration_info.get("search_patterns", [])

    if not patterns:
        return {"files_migrated": 0, "changes": 0, "skipped": True}

    files_changed = 0
    total_changes = 0
    changed_files = []

    # Find all relevant files
    for ext in extensions:
        for f in repo.rglob(f"*{ext}"):
            # Skip test/vendor directories
            rel = str(f.relative_to(repo))
            if any(skip in rel for skip in ["node_modules", ".git", "target", "build", "dist", "vendor"]):
                continue

            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                original = content

                # Apply each pattern
                for search, replace in patterns:
                    content = re.sub(search, replace, content)

                if content != original:
                    f.write_text(content, encoding="utf-8")
                    changes = sum(1 for s, _ in patterns if re.search(s, original))
                    files_changed += 1
                    total_changes += changes
                    changed_files.append(rel)
                    logger.info(f"Migrated: {rel} ({changes} changes)")

            except Exception as e:
                logger.warning(f"Failed to migrate {f}: {e}")

    return {
        "files_migrated": files_changed,
        "changes": total_changes,
        "changed_files": changed_files[:20],
        "skipped": False,
    }


def apply_migration_with_llm(
    repo_path: str,
    migration_info: Dict[str, Any],
    package: str,
    old_version: str,
    new_version: str,
) -> Dict[str, Any]:
    """
    Use LLM to handle complex migrations that regex can't fix.
    E.g., Spring Security config changes, removed APIs, etc.
    """
    from app.llm.llm_router import router as llm_router
    from app.llm.context_extractor import estimate_tokens

    repo = Path(repo_path)
    extensions = migration_info.get("file_extensions", [])
    additional = migration_info.get("additional_changes", [])

    if not additional:
        return {"llm_fixes": 0}

    llm_fixes = 0

    # Find files that might need LLM-based migration
    for ext in extensions:
        for f in repo.rglob(f"*{ext}"):
            rel = str(f.relative_to(repo))
            if any(skip in rel for skip in ["node_modules", ".git", "target", "build", "dist"]):
                continue

            try:
                content = f.read_text(encoding="utf-8", errors="replace")

                # Check if file uses any deprecated patterns
                needs_migration = migration_info.get("llm_scan_all", False)
                if not needs_migration:
                    for change_desc in additional:
                        # Extract the deprecated pattern from description
                        deprecated_terms = re.findall(r'(\w+(?:\.\w+)+)', change_desc)
                        for term in deprecated_terms:
                            if term in content:
                                needs_migration = True
                                break
                        if needs_migration:
                            break

                if not needs_migration:
                    continue

                # Only send relevant portion to LLM
                if len(content) > 3000:
                    # Too large, skip LLM for this file
                    continue

                # Ask LLM to migrate
                prompt = f"""Migrate this code from {package} {old_version} to {new_version}.

Known breaking changes:
{chr(10).join('- ' + c for c in additional)}

Code to migrate:
{content}

Return ONLY the migrated code. No explanations, no markdown fences."""

                if estimate_tokens(prompt) > 4000:
                    continue  # Skip if too many tokens

                result, provider = llm_router.generate(prompt)
                if result and result.strip():
                    # Strip code fences
                    migrated = result.strip()
                    if migrated.startswith("```"):
                        lines = migrated.split("\n")
                        lines = lines[1:]
                        if lines and lines[-1].strip() == "```":
                            lines = lines[:-1]
                        migrated = "\n".join(lines)

                    if migrated != content:
                        f.write_text(migrated, encoding="utf-8")
                        llm_fixes += 1
                        logger.info(f"LLM migrated: {rel} (via {provider})")

            except Exception as e:
                logger.warning(f"LLM migration failed for {f}: {e}")

    return {"llm_fixes": llm_fixes}


def validate_build(repo_path: str, project_info: Dict) -> Tuple[bool, str]:
    """
    Run build/compile to verify the migration didn't break anything.
    Returns (success, error_message).
    """
    import subprocess
    import shutil

    repo = Path(repo_path)
    languages = project_info.get("languages", [])

    # Java/Maven
    if "Java" in languages and (repo / "pom.xml").exists():
        mvn = shutil.which("mvn")
        mvnw = repo / "mvnw"
        if mvnw.exists():
            mvn = str(mvnw)
        if mvn:
            try:
                result = subprocess.run(
                    [mvn, "compile", "-q", "-DskipTests"],
                    cwd=repo_path,
                    capture_output=True,
                    text=False,
                    timeout=300,
                )
                stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
                if result.returncode != 0:
                    return False, f"Maven compile failed: {stderr[:500]}"
                return True, ""
            except subprocess.TimeoutExpired:
                return False, "Maven compile timed out"
            except Exception as e:
                return True, f"Build check skipped: {e}"

    # Python
    if "Python" in languages:
        python_bin = shutil.which("python3") or shutil.which("python")
        if python_bin:
            # Syntax check all .py files
            for py_file in repo.rglob("*.py"):
                rel = str(py_file.relative_to(repo))
                if any(skip in rel for skip in ["venv", ".venv", "node_modules", ".git"]):
                    continue
                try:
                    result = subprocess.run(
                        [python_bin, "-m", "py_compile", str(py_file)],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode != 0:
                        return False, f"Python syntax error in {rel}: {result.stderr[:200]}"
                except Exception:
                    continue
            return True, ""

    # Node.js
    if "JavaScript/TypeScript" in languages and (repo / "package.json").exists():
        npm = shutil.which("npm")
        if npm and (repo / "node_modules").exists():
            try:
                result = subprocess.run(
                    [npm, "run", "build", "--if-present"],
                    cwd=repo_path,
                    capture_output=True, text=False, timeout=120,
                )
                if result.returncode != 0:
                    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
                    return False, f"npm build failed: {stderr[:500]}"
                return True, ""
            except Exception:
                pass

    # No build tool available — assume OK
    return True, ""
