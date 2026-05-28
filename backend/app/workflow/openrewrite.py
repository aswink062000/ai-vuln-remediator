"""
OpenRewrite Integration for Dependency Upgrades and Major Migrations.

Uses OpenRewrite recipes to perform safe, AST-aware dependency version bumps
and breaking-change migrations for Java/Maven/Gradle projects.

OpenRewrite handles:
- Dependency version upgrades (pom.xml, build.gradle)
- Breaking API migrations (javax→jakarta, Spring Boot 2→3, JUnit 4→5)
- Code transformations that accompany major version bumps

This module is invoked when:
1. A Maven/Gradle project needs dependency version bumps
2. A major version upgrade is detected (breaking changes)

References:
- https://docs.openrewrite.org/recipes/java/dependencies/upgradedependencyversion
- https://docs.openrewrite.org/running-recipes/running-rewrite-on-a-maven-project-without-modifying-the-build
"""

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# OpenRewrite recipe mappings for known major migrations
OPENREWRITE_MIGRATION_RECIPES: Dict[str, Dict[str, Any]] = {
    # Spring Boot 2 → 3
    "spring-boot:2->3": {
        "recipe": "org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0",
        "artifact": "org.openrewrite.recipe:rewrite-spring:LATEST",
        "description": "Migrates Spring Boot 2.x to 3.0 (javax→jakarta, config changes, etc.)",
    },
    # Spring Boot 3.0 → 3.2
    "spring-boot:3.0->3.2": {
        "recipe": "org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_2",
        "artifact": "org.openrewrite.recipe:rewrite-spring:LATEST",
        "description": "Migrates Spring Boot 3.0 to 3.2",
    },
    # Spring Boot 3.2 → 3.3
    "spring-boot:3.2->3.3": {
        "recipe": "org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_3",
        "artifact": "org.openrewrite.recipe:rewrite-spring:LATEST",
        "description": "Migrates Spring Boot 3.2 to 3.3",
    },
    # JUnit 4 → 5
    "junit:4->5": {
        "recipe": "org.openrewrite.java.testing.junit5.JUnit4to5Migration",
        "artifact": "org.openrewrite.recipe:rewrite-testing-frameworks:LATEST",
        "description": "Migrates JUnit 4 tests to JUnit 5 (Jupiter)",
    },
    # Java 8 → 11
    "java:8->11": {
        "recipe": "org.openrewrite.java.migrate.Java8toJava11",
        "artifact": "org.openrewrite.recipe:rewrite-migrate-java:LATEST",
        "description": "Migrates Java 8 code to Java 11",
    },
    # Java 11 → 17
    "java:11->17": {
        "recipe": "org.openrewrite.java.migrate.UpgradeToJava17",
        "artifact": "org.openrewrite.recipe:rewrite-migrate-java:LATEST",
        "description": "Migrates Java 11 code to Java 17",
    },
    # Java 17 → 21
    "java:17->21": {
        "recipe": "org.openrewrite.java.migrate.UpgradeToJava21",
        "artifact": "org.openrewrite.recipe:rewrite-migrate-java:LATEST",
        "description": "Migrates Java 17 code to Java 21",
    },
    # Jakarta EE 9 migration (javax → jakarta)
    "jakarta:javax->jakarta": {
        "recipe": "org.openrewrite.java.migrate.jakarta.JavaxMigrationToJakarta",
        "artifact": "org.openrewrite.recipe:rewrite-migrate-java:LATEST",
        "description": "Migrates javax.* imports to jakarta.*",
    },
    # Log4j 1 → 2
    "log4j:1->2": {
        "recipe": "org.openrewrite.java.logging.log4j.Log4j1ToLog4j2",
        "artifact": "org.openrewrite.recipe:rewrite-logging-frameworks:LATEST",
        "description": "Migrates Log4j 1.x to Log4j 2.x",
    },
    # Micronaut 3 → 4
    "micronaut:3->4": {
        "recipe": "org.openrewrite.java.micronaut.Micronaut3to4Migration",
        "artifact": "org.openrewrite.recipe:rewrite-micronaut:LATEST",
        "description": "Migrates Micronaut 3 to Micronaut 4",
    },
}


def is_openrewrite_available(repo_path: str) -> Tuple[bool, str]:
    """
    Check if OpenRewrite can be used for this project.
    Returns (available, reason).
    
    OpenRewrite works with:
    - Maven projects (pom.xml) — via rewrite-maven-plugin CLI invocation
    - Gradle projects (build.gradle) — via init script
    """
    repo = Path(repo_path)

    # Check for Maven
    if (repo / "pom.xml").exists():
        mvn = shutil.which("mvn")
        mvnw = repo / "mvnw"
        if mvnw.exists() or mvn:
            return True, "maven"
        return False, "maven_not_found"

    # Check for Gradle
    if (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        gradle = shutil.which("gradle")
        gradlew = repo / "gradlew"
        if gradlew.exists() or gradle:
            return True, "gradle"
        return False, "gradle_not_found"

    return False, "not_java_project"


def run_openrewrite_dependency_upgrade(
    repo_path: str,
    group_id: str,
    artifact_id: str,
    new_version: str,
    project_info: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Use OpenRewrite to upgrade a specific dependency version.
    This is AST-aware and handles:
    - Direct version in pom.xml
    - Version properties (e.g., <spring.version>)
    - Managed dependencies
    - Gradle version catalogs
    
    Args:
        repo_path: Path to the cloned repository
        group_id: Maven groupId (e.g., "org.springframework.boot")
        artifact_id: Maven artifactId or "*" for all in group
        new_version: Target version (e.g., "3.2.5")
        project_info: Optional project info dict
        
    Returns:
        Dict with success status and details
    """
    repo = Path(repo_path)
    available, build_tool = is_openrewrite_available(repo_path)

    if not available:
        return {
            "success": False,
            "method": "openrewrite",
            "error": f"OpenRewrite not available: {build_tool}",
            "fallback": True,
        }

    logger.info(
        f"OpenRewrite: Upgrading {group_id}:{artifact_id} to {new_version} "
        f"(build_tool={build_tool})"
    )

    try:
        if build_tool == "maven":
            return _run_maven_rewrite(repo_path, group_id, artifact_id, new_version)
        elif build_tool == "gradle":
            return _run_gradle_rewrite(repo_path, group_id, artifact_id, new_version)
        else:
            return {"success": False, "error": "Unsupported build tool", "fallback": True}
    except Exception as e:
        logger.error(f"OpenRewrite execution failed: {e}")
        return {"success": False, "error": str(e), "fallback": True}


def run_openrewrite_migration(
    repo_path: str,
    migration_key: str,
    project_info: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Run a full OpenRewrite migration recipe (e.g., Spring Boot 2→3).
    
    Args:
        repo_path: Path to the cloned repository
        migration_key: Key from OPENREWRITE_MIGRATION_RECIPES
        project_info: Optional project info dict
        
    Returns:
        Dict with success status and details
    """
    if migration_key not in OPENREWRITE_MIGRATION_RECIPES:
        return {
            "success": False,
            "error": f"No OpenRewrite recipe for migration: {migration_key}",
            "fallback": True,
        }

    recipe_info = OPENREWRITE_MIGRATION_RECIPES[migration_key]
    available, build_tool = is_openrewrite_available(repo_path)

    if not available:
        return {
            "success": False,
            "error": f"OpenRewrite not available: {build_tool}",
            "fallback": True,
        }

    logger.info(
        f"OpenRewrite migration: {migration_key} → {recipe_info['recipe']} "
        f"({recipe_info['description']})"
    )

    try:
        if build_tool == "maven":
            return _run_maven_recipe(
                repo_path,
                recipe_info["recipe"],
                recipe_info["artifact"],
            )
        elif build_tool == "gradle":
            return _run_gradle_recipe(
                repo_path,
                recipe_info["recipe"],
                recipe_info["artifact"],
            )
        else:
            return {"success": False, "error": "Unsupported build tool", "fallback": True}
    except Exception as e:
        logger.error(f"OpenRewrite migration failed: {e}")
        return {"success": False, "error": str(e), "fallback": True}


def detect_openrewrite_migration_key(
    package: str, old_version: str, new_version: str
) -> Optional[str]:
    """
    Detect if a package upgrade maps to a known OpenRewrite migration recipe.
    
    Returns the migration key if found, None otherwise.
    """
    old_major = old_version.split(".")[0] if old_version else ""
    new_major = new_version.split(".")[0] if new_version else ""

    pkg_lower = package.lower()

    # Spring Boot
    if "spring-boot" in pkg_lower or "org.springframework.boot" in pkg_lower:
        if old_major == "2" and new_major == "3":
            return "spring-boot:2->3"
        if old_version.startswith("3.0") and (new_version.startswith("3.2") or new_version.startswith("3.3")):
            return "spring-boot:3.0->3.2"
        if old_version.startswith("3.2") and new_version.startswith("3.3"):
            return "spring-boot:3.2->3.3"

    # JUnit
    if "junit" in pkg_lower:
        if old_major == "4" and new_major == "5":
            return "junit:4->5"

    # Log4j
    if "log4j" in pkg_lower:
        if old_major == "1" and new_major == "2":
            return "log4j:1->2"

    # Micronaut
    if "micronaut" in pkg_lower:
        if old_major == "3" and new_major == "4":
            return "micronaut:3->4"

    # javax → jakarta (any package triggering this)
    if "javax" in pkg_lower and new_major >= "5":
        return "jakarta:javax->jakarta"

    return None


# ─── Internal: Maven execution ───────────────────────────────────────────────


def _get_maven_cmd(repo_path: str) -> str:
    """Get the Maven command (mvnw or mvn)."""
    repo = Path(repo_path)
    mvnw = repo / "mvnw"
    if mvnw.exists():
        mvnw.chmod(0o755)
        return str(mvnw)
    return shutil.which("mvn") or "mvn"


def _run_maven_rewrite(
    repo_path: str, group_id: str, artifact_id: str, new_version: str
) -> Dict[str, Any]:
    """
    Run OpenRewrite UpgradeDependencyVersion via Maven CLI without modifying pom.xml.
    
    Command:
        mvn -U org.openrewrite.maven:rewrite-maven-plugin:run \
            -Drewrite.recipeArtifactCoordinates=org.openrewrite.recipe:rewrite-java-dependencies:LATEST \
            -Drewrite.activeRecipes=org.openrewrite.java.dependencies.UpgradeDependencyVersion \
            -Drewrite.options="groupId=<group>,artifactId=<artifact>,newVersion=<version>"
    """
    mvn = _get_maven_cmd(repo_path)

    # Build the options string
    options = f"groupId={group_id},artifactId={artifact_id},newVersion={new_version}"

    cmd = [
        mvn, "-U", "-B", "-q",
        "org.openrewrite.maven:rewrite-maven-plugin:run",
        "-Drewrite.recipeArtifactCoordinates=org.openrewrite.recipe:rewrite-java-dependencies:LATEST",
        "-Drewrite.activeRecipes=org.openrewrite.java.dependencies.UpgradeDependencyVersion",
        f"-Drewrite.options={options}",
    ]

    logger.info(f"Running OpenRewrite dependency upgrade: {group_id}:{artifact_id} → {new_version}")
    result = _execute_cmd(cmd, repo_path, timeout=300)

    if result["success"]:
        logger.info(f"OpenRewrite successfully upgraded {group_id}:{artifact_id} to {new_version}")
    else:
        logger.warning(f"OpenRewrite dependency upgrade failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "openrewrite",
        "recipe": "UpgradeDependencyVersion",
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


def _run_maven_recipe(
    repo_path: str, recipe: str, artifact_coords: str
) -> Dict[str, Any]:
    """
    Run a full OpenRewrite recipe via Maven CLI.
    
    Command:
        mvn -U org.openrewrite.maven:rewrite-maven-plugin:run \
            -Drewrite.recipeArtifactCoordinates=<artifact> \
            -Drewrite.activeRecipes=<recipe>
    """
    mvn = _get_maven_cmd(repo_path)

    cmd = [
        mvn, "-U", "-B",
        "org.openrewrite.maven:rewrite-maven-plugin:run",
        f"-Drewrite.recipeArtifactCoordinates={artifact_coords}",
        f"-Drewrite.activeRecipes={recipe}",
    ]

    logger.info(f"Running OpenRewrite migration recipe: {recipe}")
    result = _execute_cmd(cmd, repo_path, timeout=600)  # Migrations can take longer

    if result["success"]:
        logger.info(f"OpenRewrite migration {recipe} completed successfully")
    else:
        logger.warning(f"OpenRewrite migration {recipe} failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "openrewrite",
        "recipe": recipe,
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


# ─── Internal: Gradle execution ──────────────────────────────────────────────


def _get_gradle_cmd(repo_path: str) -> str:
    """Get the Gradle command (gradlew or gradle)."""
    repo = Path(repo_path)
    gradlew = repo / "gradlew"
    if gradlew.exists():
        gradlew.chmod(0o755)
        return str(gradlew)
    return shutil.which("gradle") or "gradle"


def _create_gradle_init_script(
    repo_path: str, recipe: str, artifact_coords: str
) -> str:
    """Create a Gradle init script for running OpenRewrite without modifying build.gradle."""
    repo = Path(repo_path)
    init_script = repo / "openrewrite-init.gradle"

    script_content = f"""
initscript {{
    repositories {{
        maven {{ url = uri("https://plugins.gradle.org/m2/") }}
    }}
    dependencies {{
        classpath("org.openrewrite:plugin:latest.release")
    }}
}}

rootProject {{
    plugins.apply(org.openrewrite.gradle.RewritePlugin)
    dependencies {{
        rewrite("{artifact_coords}")
    }}
    rewrite {{
        activeRecipe("{recipe}")
    }}
}}
"""
    init_script.write_text(script_content, encoding="utf-8")
    return str(init_script)


def _run_gradle_rewrite(
    repo_path: str, group_id: str, artifact_id: str, new_version: str
) -> Dict[str, Any]:
    """Run OpenRewrite UpgradeDependencyVersion via Gradle init script."""
    recipe = "org.openrewrite.java.dependencies.UpgradeDependencyVersion"
    artifact = "org.openrewrite.recipe:rewrite-java-dependencies:LATEST"

    init_script = _create_gradle_init_script(repo_path, recipe, artifact)
    gradle = _get_gradle_cmd(repo_path)

    # Note: Gradle recipe options are set via rewrite.yml for parameterized recipes
    # Create a rewrite.yml for this
    repo = Path(repo_path)
    rewrite_yml = repo / "rewrite.yml"
    rewrite_yml_content = f"""---
type: specs.openrewrite.org/v1beta/recipe
name: com.vuln-remediator.UpgradeDep
recipeList:
  - org.openrewrite.java.dependencies.UpgradeDependencyVersion:
      groupId: {group_id}
      artifactId: {artifact_id}
      newVersion: {new_version}
"""
    rewrite_yml.write_text(rewrite_yml_content, encoding="utf-8")

    # Update init script to use our custom recipe
    init_script_path = _create_gradle_init_script(
        repo_path,
        "com.vuln-remediator.UpgradeDep",
        artifact,
    )

    cmd = [
        gradle, "--no-daemon", "--init-script", init_script_path,
        "rewriteRun",
    ]

    logger.info(f"Running OpenRewrite (Gradle) dependency upgrade: {group_id}:{artifact_id} → {new_version}")
    result = _execute_cmd(cmd, repo_path, timeout=300)

    # Cleanup temp files
    try:
        Path(init_script_path).unlink(missing_ok=True)
        rewrite_yml.unlink(missing_ok=True)
    except Exception:
        pass

    if result["success"]:
        logger.info(f"OpenRewrite (Gradle) successfully upgraded {group_id}:{artifact_id} to {new_version}")
    else:
        logger.warning(f"OpenRewrite (Gradle) upgrade failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "openrewrite",
        "recipe": "UpgradeDependencyVersion",
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


def _run_gradle_recipe(
    repo_path: str, recipe: str, artifact_coords: str
) -> Dict[str, Any]:
    """Run a full OpenRewrite recipe via Gradle init script."""
    init_script = _create_gradle_init_script(repo_path, recipe, artifact_coords)
    gradle = _get_gradle_cmd(repo_path)

    cmd = [
        gradle, "--no-daemon", "--init-script", init_script,
        "rewriteRun",
    ]

    logger.info(f"Running OpenRewrite (Gradle) migration: {recipe}")
    result = _execute_cmd(cmd, repo_path, timeout=600)

    # Cleanup
    try:
        Path(init_script).unlink(missing_ok=True)
    except Exception:
        pass

    if result["success"]:
        logger.info(f"OpenRewrite (Gradle) migration {recipe} completed successfully")
    else:
        logger.warning(f"OpenRewrite (Gradle) migration failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "openrewrite",
        "recipe": recipe,
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


# ─── Internal: Command execution ─────────────────────────────────────────────


def _execute_cmd(cmd: list, cwd: str, timeout: int = 300) -> Dict[str, Any]:
    """Execute a command and return result."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=False,
            timeout=timeout,
        )
        stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
        output = (stdout + "\n" + stderr).strip()

        return {
            "success": result.returncode == 0,
            "output": output[-2000:],  # Last 2000 chars
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": f"Command timed out after {timeout}s",
            "returncode": -1,
        }
    except FileNotFoundError as e:
        return {
            "success": False,
            "output": f"Command not found: {e}",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "output": str(e)[:500],
            "returncode": -1,
        }
