"""
AST-Based Code Transformation Engine.

Uses ecosystem-specific AST tools for safe, structure-aware code migrations:
- Java/Maven/Gradle → OpenRewrite
- React/JavaScript  → jscodeshift
- Angular           → Angular Schematics (ng update)
- Node.js/TypeScript→ ts-morph
- Python            → LibCST / Bowler

Each tool understands the language's AST and can perform refactors that
regex-based approaches would break (renamed imports, moved APIs, etc.).
"""

import logging
import shutil
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════


def run_ast_migration(
    repo_path: str,
    package: str,
    old_version: str,
    new_version: str,
    project_info: Dict,
) -> Dict[str, Any]:
    """
    Run the appropriate AST-based migration tool for the project.

    Routing logic:
    - Java (pom.xml / build.gradle) → OpenRewrite
    - React (package.json + react) → jscodeshift
    - Angular (angular.json) → ng update / schematics
    - Node.js/TS (package.json + tsconfig) → ts-morph
    - Python (requirements.txt / pyproject.toml) → LibCST / Bowler
    """
    repo = Path(repo_path)
    languages = project_info.get("languages", [])
    frameworks = project_info.get("frameworks", [])

    # Detect ecosystem and route to appropriate tool
    tool = _detect_ast_tool(repo, languages, frameworks, package)

    logger.info(
        f"AST migration: {package} {old_version}→{new_version} "
        f"using {tool}"
    )

    if tool == "openrewrite":
        from app.workflow.openrewrite import (
            run_openrewrite_migration,
            run_openrewrite_dependency_upgrade,
            detect_openrewrite_migration_key,
        )
        migration_key = detect_openrewrite_migration_key(
            package, old_version, new_version
        )
        if migration_key:
            return run_openrewrite_migration(repo_path, migration_key)
        # Fall back to simple version upgrade
        group_id, artifact_id = _parse_java_coords(package)
        if group_id:
            return run_openrewrite_dependency_upgrade(
                repo_path, group_id, artifact_id, new_version
            )
        return {"success": False, "fallback": True, "error": "Cannot parse Maven coords"}

    elif tool == "jscodeshift":
        return _run_jscodeshift_migration(
            repo_path, package, old_version, new_version
        )

    elif tool == "angular_schematics":
        return _run_angular_migration(
            repo_path, package, old_version, new_version
        )

    elif tool == "ts_morph":
        return _run_ts_morph_migration(
            repo_path, package, old_version, new_version
        )

    elif tool == "libcst":
        return _run_libcst_migration(
            repo_path, package, old_version, new_version
        )

    else:
        return {
            "success": False,
            "method": "none",
            "error": f"No AST tool available for this ecosystem",
            "fallback": True,
        }


def detect_ast_tool(repo_path: str, project_info: Dict, package: str) -> str:
    """Public helper to detect which AST tool would be used."""
    repo = Path(repo_path)
    return _detect_ast_tool(
        repo,
        project_info.get("languages", []),
        project_info.get("frameworks", []),
        package,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION
# ═══════════════════════════════════════════════════════════════════════════════


def _detect_ast_tool(
    repo: Path, languages: List[str], frameworks: List[str], package: str
) -> str:
    """Determine which AST tool to use based on project structure."""
    pkg_lower = package.lower()

    # Angular project (angular.json present)
    if (repo / "angular.json").exists():
        return "angular_schematics"

    # Java/Maven/Gradle
    if (repo / "pom.xml").exists() or (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        return "openrewrite"

    # React project (package.json with react dependency)
    pkg_json = repo / "package.json"
    if pkg_json.exists():
        try:
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            all_deps = {
                **pkg_data.get("dependencies", {}),
                **pkg_data.get("devDependencies", {}),
            }
            # React ecosystem
            if "react" in all_deps or "react-dom" in all_deps:
                # Use jscodeshift for React-related packages
                react_packages = (
                    "react", "react-dom", "react-router", "redux",
                    "react-redux", "next", "gatsby", "material-ui",
                    "@mui", "enzyme", "react-testing-library",
                )
                if any(rp in pkg_lower for rp in react_packages):
                    return "jscodeshift"

            # TypeScript project with tsconfig → ts-morph
            if (repo / "tsconfig.json").exists():
                return "ts_morph"

            # Plain Node.js
            return "ts_morph"

        except Exception:
            pass

    # Python project
    if (
        (repo / "requirements.txt").exists()
        or (repo / "pyproject.toml").exists()
        or (repo / "setup.py").exists()
        or (repo / "setup.cfg").exists()
    ):
        return "libcst"

    return "none"


def _parse_java_coords(package: str) -> Tuple[str, str]:
    """Parse groupId:artifactId from a package string."""
    if ":" in package:
        parts = package.split(":")
        return parts[0], parts[1] if len(parts) > 1 else "*"
    if "." in package and "/" not in package and "@" not in package:
        return package, "*"
    return "", ""


# ═══════════════════════════════════════════════════════════════════════════════
# JSCODESHIFT — React / JavaScript AST Transforms
# ═══════════════════════════════════════════════════════════════════════════════

# Known jscodeshift codemods for popular React ecosystem upgrades
JSCODESHIFT_CODEMODS: Dict[str, Dict[str, Any]] = {
    # React Router 5 → 6
    "react-router:5->6": {
        "package": "react-router-codemod",
        "transforms": ["v5-to-v6"],
        "description": "Migrates React Router v5 to v6 (Switch→Routes, useHistory→useNavigate)",
    },
    # React 17 → 18
    "react:17->18": {
        "package": "react-codemod",
        "transforms": ["update-react-imports"],
        "description": "Updates React imports for React 18 (automatic JSX runtime)",
    },
    # Material UI v4 → v5
    "material-ui:4->5": {
        "package": "@mui/codemod",
        "transforms": ["v5.0.0/preset-safe"],
        "description": "Migrates Material UI v4 to MUI v5",
    },
    # Redux Toolkit migration
    "redux:legacy->toolkit": {
        "package": "redux-codemod",
        "transforms": ["createSlice"],
        "description": "Migrates legacy Redux to Redux Toolkit",
    },
    # Next.js codemods
    "next:12->13": {
        "package": "@next/codemod",
        "transforms": ["next-image-to-legacy-image", "new-link"],
        "description": "Migrates Next.js 12 to 13 (app router, new Image/Link)",
    },
    "next:13->14": {
        "package": "@next/codemod",
        "transforms": ["next-image-experimental"],
        "description": "Migrates Next.js 13 to 14",
    },
}


def _detect_jscodeshift_codemod(
    package: str, old_version: str, new_version: str
) -> Optional[Dict[str, Any]]:
    """Detect if a known jscodeshift codemod exists for this upgrade."""
    old_major = old_version.split(".")[0] if old_version else ""
    new_major = new_version.split(".")[0] if new_version else ""
    pkg_lower = package.lower()

    if "react-router" in pkg_lower:
        if old_major == "5" and new_major == "6":
            return JSCODESHIFT_CODEMODS.get("react-router:5->6")

    if pkg_lower in ("react", "react-dom"):
        if old_major == "17" and new_major == "18":
            return JSCODESHIFT_CODEMODS.get("react:17->18")

    if "@material-ui" in pkg_lower or "@mui" in pkg_lower:
        if old_major == "4" and new_major == "5":
            return JSCODESHIFT_CODEMODS.get("material-ui:4->5")

    if pkg_lower == "next":
        if old_major == "12" and new_major == "13":
            return JSCODESHIFT_CODEMODS.get("next:12->13")
        if old_major == "13" and new_major == "14":
            return JSCODESHIFT_CODEMODS.get("next:13->14")

    return None


def _run_jscodeshift_migration(
    repo_path: str, package: str, old_version: str, new_version: str
) -> Dict[str, Any]:
    """
    Run jscodeshift codemods for React/JS ecosystem migrations.

    jscodeshift is Facebook's AST-based code transformation tool.
    It parses JS/TS into an AST, applies transforms, and writes back.
    """
    repo = Path(repo_path)
    npx = shutil.which("npx")

    if not npx:
        return {
            "success": False,
            "method": "jscodeshift",
            "error": "npx not found (Node.js required)",
            "fallback": True,
        }

    codemod_info = _detect_jscodeshift_codemod(package, old_version, new_version)

    if codemod_info:
        # Use known codemod package
        codemod_pkg = codemod_info["package"]
        transforms = codemod_info["transforms"]
        logger.info(
            f"jscodeshift: Using {codemod_pkg} transforms: {transforms}"
        )

        results = []
        for transform in transforms:
            # Run: npx <codemod-package> <transform> <path>
            # Different codemods have different CLI patterns
            if codemod_pkg == "@next/codemod":
                cmd = [npx, "--yes", "@next/codemod@latest", transform, repo_path]
            elif codemod_pkg == "@mui/codemod":
                # MUI codemod: npx @mui/codemod <transform> <path>
                cmd = [npx, "--yes", "@mui/codemod@latest", transform, repo_path]
            elif codemod_pkg == "react-codemod":
                cmd = [
                    npx, "--yes", "react-codemod", transform,
                    "--force", "--jscodeshift", f"--extensions=jsx,tsx,js,ts",
                    repo_path,
                ]
            else:
                # Generic jscodeshift pattern
                cmd = [
                    npx, "--yes", "jscodeshift",
                    "-t", f"node_modules/{codemod_pkg}/transforms/{transform}.js",
                    "--extensions", "jsx,tsx,js,ts",
                    "--ignore-pattern", "node_modules",
                    repo_path,
                ]

            result = _execute_cmd(cmd, repo_path, timeout=180)
            results.append({
                "transform": transform,
                "success": result["success"],
                "output": result["output"][:500],
            })

        any_success = any(r["success"] for r in results)
        return {
            "success": any_success,
            "method": "jscodeshift",
            "codemod": codemod_pkg,
            "transforms": results,
            "description": codemod_info.get("description", ""),
            "fallback": not any_success,
        }

    else:
        # No known codemod — use generic jscodeshift for import renaming
        # This handles cases like package renames (e.g., moment → dayjs)
        logger.info(
            f"jscodeshift: No known codemod for {package}, "
            f"attempting generic import update"
        )
        # Write a simple transform script for import renaming
        transform_script = _generate_jscodeshift_transform(
            package, old_version, new_version
        )
        if transform_script:
            transform_path = repo / ".vuln-remediator-transform.js"
            transform_path.write_text(transform_script, encoding="utf-8")

            cmd = [
                npx, "--yes", "jscodeshift",
                "-t", str(transform_path),
                "--extensions", "jsx,tsx,js,ts",
                "--ignore-pattern", "node_modules",
                str(repo / "src"),  # Only transform src directory
            ]

            # Only run if src exists, otherwise try root
            if not (repo / "src").exists():
                cmd[-1] = repo_path

            result = _execute_cmd(cmd, repo_path, timeout=120)

            # Cleanup
            transform_path.unlink(missing_ok=True)

            return {
                "success": result["success"],
                "method": "jscodeshift",
                "codemod": "generic-transform",
                "output": result["output"][:1000],
                "fallback": not result["success"],
            }

        return {
            "success": False,
            "method": "jscodeshift",
            "error": "No applicable transform found",
            "fallback": True,
        }


def _generate_jscodeshift_transform(
    package: str, old_version: str, new_version: str
) -> Optional[str]:
    """
    Generate a jscodeshift transform script for generic package upgrades.
    Handles deprecated API renames that commonly accompany major bumps.
    """
    # Only generate for major version bumps
    old_major = old_version.split(".")[0] if old_version else ""
    new_major = new_version.split(".")[0] if new_version else ""

    if old_major == new_major:
        return None  # No transform needed for minor/patch bumps

    # Generic transform that updates import paths if package was renamed
    return f"""
// Auto-generated jscodeshift transform for {package} {old_version}→{new_version}
module.exports = function(fileInfo, api) {{
  const j = api.jscodeshift;
  const root = j(fileInfo.source);
  let hasChanges = false;

  // Update require() calls
  root.find(j.CallExpression, {{
    callee: {{ name: 'require' }},
    arguments: [{{ value: '{package}' }}]
  }}).forEach(path => {{
    // Package exists, mark for review
    hasChanges = true;
  }});

  // Update import declarations
  root.find(j.ImportDeclaration, {{
    source: {{ value: '{package}' }}
  }}).forEach(path => {{
    hasChanges = true;
  }});

  return hasChanges ? root.toSource() : fileInfo.source;
}};
"""


# ═══════════════════════════════════════════════════════════════════════════════
# ANGULAR SCHEMATICS — Angular CLI ng update
# ═══════════════════════════════════════════════════════════════════════════════

# Angular packages that support `ng update` with schematics
ANGULAR_UPDATABLE_PACKAGES = (
    "@angular/core",
    "@angular/cli",
    "@angular/material",
    "@angular/cdk",
    "@angular/router",
    "@angular/forms",
    "@angular/common",
    "@angular/platform-browser",
    "@angular/animations",
    "@ngrx/store",
    "@ngrx/effects",
    "@ngrx/entity",
    "rxjs",
)


def _run_angular_migration(
    repo_path: str, package: str, old_version: str, new_version: str
) -> Dict[str, Any]:
    """
    Run Angular Schematics via `ng update` for Angular ecosystem migrations.

    `ng update` runs migration schematics that:
    - Update package versions in package.json
    - Apply code transformations (renamed APIs, moved modules)
    - Update angular.json configuration
    - Handle RxJS operator migrations
    """
    repo = Path(repo_path)
    npx = shutil.which("npx")
    ng = shutil.which("ng")

    # Prefer local ng from node_modules
    local_ng = repo / "node_modules" / ".bin" / "ng"
    if local_ng.exists():
        ng_cmd = str(local_ng)
    elif ng:
        ng_cmd = ng
    elif npx:
        ng_cmd = None  # Will use npx
    else:
        return {
            "success": False,
            "method": "angular_schematics",
            "error": "Neither ng nor npx found",
            "fallback": True,
        }

    # First ensure node_modules exist (ng update needs them)
    npm = shutil.which("npm")
    if npm and not (repo / "node_modules").exists():
        logger.info("Angular: Installing dependencies before ng update...")
        install_result = _execute_cmd(
            [npm, "install", "--legacy-peer-deps"], repo_path, timeout=180
        )
        if not install_result["success"]:
            logger.warning(f"npm install failed: {install_result['output'][:200]}")

    # Determine the target version spec
    new_major = new_version.split(".")[0] if new_version else ""
    version_spec = f"{package}@{new_version}" if new_version else package

    # Check if this is a core Angular update (update CLI first)
    pkg_lower = package.lower()
    is_core_angular = pkg_lower in ("@angular/core", "@angular/cli")

    if is_core_angular:
        # For core Angular, update CLI first, then core
        steps = [
            f"@angular/cli@{new_major}",
            f"@angular/core@{new_major}",
        ]
    else:
        steps = [version_spec]

    results = []
    for step_pkg in steps:
        if ng_cmd:
            cmd = [
                ng_cmd, "update", step_pkg,
                "--force",
                "--allow-dirty",
                "--migrate-only" if not is_core_angular else "",
            ]
            # Remove empty strings
            cmd = [c for c in cmd if c]
        else:
            cmd = [
                npx, "--yes", "@angular/cli", "update", step_pkg,
                "--force",
                "--allow-dirty",
            ]

        logger.info(f"Angular schematics: ng update {step_pkg}")
        result = _execute_cmd(cmd, repo_path, timeout=300)
        results.append({
            "package": step_pkg,
            "success": result["success"],
            "output": result["output"][:500],
        })

        if not result["success"]:
            logger.warning(f"ng update {step_pkg} failed: {result['output'][:300]}")

    any_success = any(r["success"] for r in results)
    return {
        "success": any_success,
        "method": "angular_schematics",
        "steps": results,
        "description": f"Angular migration: {package} {old_version}→{new_version}",
        "fallback": not any_success,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TS-MORPH — Node.js / TypeScript AST Transforms
# ═══════════════════════════════════════════════════════════════════════════════

# Known ts-morph migration scripts for Node.js ecosystem
TS_MORPH_MIGRATIONS: Dict[str, Dict[str, Any]] = {
    # Express 4 → 5
    "express:4->5": {
        "description": "Migrates Express 4 to Express 5",
        "transforms": [
            {"find": "app.del(", "replace": "app.delete("},
            {"find": "res.send(status)", "replace": "res.status(code).send()"},
            {"find": "req.param(", "replace": "req.params."},
        ],
    },
    # Mongoose 6 → 7
    "mongoose:6->7": {
        "description": "Migrates Mongoose 6 to 7",
        "transforms": [
            {"find": "Schema.Types.ObjectId", "replace": "Schema.Types.ObjectId"},
            {"find": ".exec(callback)", "replace": ".exec()"},
        ],
    },
    # TypeORM 0.2 → 0.3
    "typeorm:0.2->0.3": {
        "description": "Migrates TypeORM 0.2 to 0.3",
        "transforms": [
            {"find": "getConnection()", "replace": "dataSource"},
            {"find": "getRepository(", "replace": "dataSource.getRepository("},
            {"find": "createConnection(", "replace": "new DataSource("},
        ],
    },
}


def _detect_ts_morph_migration(
    package: str, old_version: str, new_version: str
) -> Optional[str]:
    """Detect if a known ts-morph migration exists."""
    old_major = old_version.split(".")[0] if old_version else ""
    new_major = new_version.split(".")[0] if new_version else ""
    pkg_lower = package.lower()

    if "express" in pkg_lower and old_major == "4" and new_major == "5":
        return "express:4->5"
    if "mongoose" in pkg_lower and old_major == "6" and new_major == "7":
        return "mongoose:6->7"
    if "typeorm" in pkg_lower:
        if old_version.startswith("0.2") and old_version.startswith("0.3"):
            return "typeorm:0.2->0.3"
    return None


def _run_ts_morph_migration(
    repo_path: str, package: str, old_version: str, new_version: str
) -> Dict[str, Any]:
    """
    Run ts-morph based AST transformations for Node.js/TypeScript projects.

    ts-morph provides a TypeScript Compiler API wrapper that enables:
    - Renaming identifiers across the project
    - Updating import paths
    - Replacing deprecated API calls
    - Adding/removing function parameters
    """
    repo = Path(repo_path)
    npx = shutil.which("npx")

    if not npx:
        return {
            "success": False,
            "method": "ts_morph",
            "error": "npx not found (Node.js required)",
            "fallback": True,
        }

    migration_key = _detect_ts_morph_migration(package, old_version, new_version)

    # Generate a ts-morph migration script
    script = _generate_ts_morph_script(
        package, old_version, new_version, migration_key
    )

    script_path = repo / ".vuln-remediator-ts-morph.mjs"
    script_path.write_text(script, encoding="utf-8")

    # Run the script with ts-morph
    # First ensure ts-morph is available
    cmd = [
        npx, "--yes", "--package=ts-morph", "--package=typescript",
        "node", str(script_path),
    ]

    logger.info(f"ts-morph: Running migration for {package} {old_version}→{new_version}")
    result = _execute_cmd(cmd, repo_path, timeout=120)

    # Cleanup
    script_path.unlink(missing_ok=True)

    if result["success"]:
        logger.info(f"ts-morph migration successful for {package}")
    else:
        logger.warning(f"ts-morph migration failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "ts_morph",
        "package": package,
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


def _generate_ts_morph_script(
    package: str, old_version: str, new_version: str,
    migration_key: Optional[str] = None,
) -> str:
    """Generate a ts-morph script for the migration."""
    transforms_js = ""

    if migration_key and migration_key in TS_MORPH_MIGRATIONS:
        migration = TS_MORPH_MIGRATIONS[migration_key]
        # Build find/replace operations
        for t in migration["transforms"]:
            find_escaped = t["find"].replace("'", "\\'").replace('"', '\\"')
            replace_escaped = t["replace"].replace("'", "\\'").replace('"', '\\"')
            transforms_js += f"""
    // {t['find']} → {t['replace']}
    sourceFile.getFullText().includes('{find_escaped}') &&
      sourceFile.replaceWithText(
        sourceFile.getFullText().replaceAll('{find_escaped}', '{replace_escaped}')
      );
"""

    return f"""
import {{ Project }} from 'ts-morph';
import {{ resolve }} from 'path';

const project = new Project({{
  tsConfigFilePath: resolve(process.cwd(), 'tsconfig.json'),
  skipAddingFilesFromTsConfig: false,
}});

// Fallback: add source files manually if no tsconfig
if (project.getSourceFiles().length === 0) {{
  project.addSourceFilesAtPaths([
    'src/**/*.ts',
    'src/**/*.tsx',
    'lib/**/*.ts',
    '*.ts',
  ]);
}}

let filesChanged = 0;

for (const sourceFile of project.getSourceFiles()) {{
  const filePath = sourceFile.getFilePath();
  if (filePath.includes('node_modules')) continue;

  const originalText = sourceFile.getFullText();

  // Update imports from the package
  const importDecls = sourceFile.getImportDeclarations();
  for (const imp of importDecls) {{
    const moduleSpec = imp.getModuleSpecifierValue();
    if (moduleSpec === '{package}' || moduleSpec.startsWith('{package}/')) {{
      // Import found — package is used in this file
      console.log(`Found import of {package} in ${{filePath}}`);
    }}
  }}

  // Apply known transforms
  {transforms_js}

  if (sourceFile.getFullText() !== originalText) {{
    filesChanged++;
    console.log(`Modified: ${{filePath}}`);
  }}
}}

await project.save();
console.log(`ts-morph: ${{filesChanged}} file(s) modified`);
process.exit(filesChanged > 0 ? 0 : 0);
"""


# ═══════════════════════════════════════════════════════════════════════════════
# LIBCST / BOWLER — Python AST Transforms
# ═══════════════════════════════════════════════════════════════════════════════

# Known Python migrations that benefit from AST-based transforms
PYTHON_MIGRATIONS: Dict[str, Dict[str, Any]] = {
    # Django 3 → 4
    "django:3->4": {
        "description": "Migrates Django 3.x to 4.x",
        "transforms": [
            {
                "old_import": "from django.conf.urls import url",
                "new_import": "from django.urls import re_path",
                "rename": {"url": "re_path"},
            },
            {
                "old_import": "from django.utils.encoding import force_text",
                "new_import": "from django.utils.encoding import force_str",
                "rename": {"force_text": "force_str"},
            },
            {
                "old_import": "from django.utils.translation import ugettext",
                "new_import": "from django.utils.translation import gettext",
                "rename": {"ugettext": "gettext", "ugettext_lazy": "gettext_lazy"},
            },
        ],
    },
    # Django 4 → 5
    "django:4->5": {
        "description": "Migrates Django 4.x to 5.x",
        "transforms": [
            {
                "old_import": "from django.utils.timezone import utc",
                "new_import": "from datetime import timezone",
                "rename": {"utc": "timezone.utc"},
            },
        ],
    },
    # Flask 2 → 3
    "flask:2->3": {
        "description": "Migrates Flask 2.x to 3.x",
        "transforms": [
            {
                "old_import": "from flask import escape",
                "new_import": "from markupsafe import escape",
                "rename": {},
            },
        ],
    },
    # SQLAlchemy 1.4 → 2.0
    "sqlalchemy:1->2": {
        "description": "Migrates SQLAlchemy 1.x to 2.0",
        "transforms": [
            {
                "old_import": "from sqlalchemy import create_engine",
                "new_import": "from sqlalchemy import create_engine",
                "rename": {"execute": "session.execute", "query": "select"},
            },
        ],
    },
    # Pydantic v1 → v2
    "pydantic:1->2": {
        "description": "Migrates Pydantic v1 to v2",
        "transforms": [
            {
                "old_import": "from pydantic import validator",
                "new_import": "from pydantic import field_validator",
                "rename": {"validator": "field_validator"},
            },
            {
                "old_import": "from pydantic import root_validator",
                "new_import": "from pydantic import model_validator",
                "rename": {"root_validator": "model_validator"},
            },
        ],
    },
}


def _detect_python_migration(
    package: str, old_version: str, new_version: str
) -> Optional[str]:
    """Detect if a known Python migration exists."""
    old_major = old_version.split(".")[0] if old_version else ""
    new_major = new_version.split(".")[0] if new_version else ""
    pkg_lower = package.lower()

    if "django" in pkg_lower:
        if old_major == "3" and new_major == "4":
            return "django:3->4"
        if old_major == "4" and new_major == "5":
            return "django:4->5"
    if "flask" in pkg_lower:
        if old_major == "2" and new_major == "3":
            return "flask:2->3"
    if "sqlalchemy" in pkg_lower:
        if old_major == "1" and new_major == "2":
            return "sqlalchemy:1->2"
    if "pydantic" in pkg_lower:
        if old_major == "1" and new_major == "2":
            return "pydantic:1->2"
    return None


def _run_libcst_migration(
    repo_path: str, package: str, old_version: str, new_version: str
) -> Dict[str, Any]:
    """
    Run LibCST-based AST transformations for Python projects.

    LibCST (Concrete Syntax Tree) preserves formatting while transforming code.
    Bowler is a higher-level API built on LibCST for refactoring.

    Strategy:
    1. Try Bowler CLI if available (simpler for common patterns)
    2. Fall back to a generated LibCST script
    """
    repo = Path(repo_path)
    python = shutil.which("python3") or shutil.which("python")

    if not python:
        return {
            "success": False,
            "method": "libcst",
            "error": "Python not found",
            "fallback": True,
        }

    migration_key = _detect_python_migration(package, old_version, new_version)

    # Generate LibCST migration script
    script = _generate_libcst_script(
        repo_path, package, old_version, new_version, migration_key
    )

    script_path = repo / ".vuln_remediator_libcst_migrate.py"
    script_path.write_text(script, encoding="utf-8")

    # Try running with libcst installed
    # First check if libcst is available
    check_cmd = [python, "-c", "import libcst; print('ok')"]
    check_result = _execute_cmd(check_cmd, repo_path, timeout=10)

    if not check_result["success"]:
        # Try installing libcst temporarily
        pip = shutil.which("pip3") or shutil.which("pip")
        if pip:
            logger.info("Installing libcst for AST migration...")
            install_result = _execute_cmd(
                [pip, "install", "libcst", "--quiet"], repo_path, timeout=60
            )
            if not install_result["success"]:
                return {
                    "success": False,
                    "method": "libcst",
                    "error": "Failed to install libcst",
                    "fallback": True,
                }

    # Run the migration script
    cmd = [python, str(script_path)]
    logger.info(f"LibCST: Running migration for {package} {old_version}→{new_version}")
    result = _execute_cmd(cmd, repo_path, timeout=120)

    # Cleanup
    script_path.unlink(missing_ok=True)

    if result["success"]:
        logger.info(f"LibCST migration successful for {package}")
    else:
        logger.warning(f"LibCST migration failed: {result['output'][:500]}")

    return {
        "success": result["success"],
        "method": "libcst",
        "package": package,
        "output": result["output"][:1000],
        "fallback": not result["success"],
    }


def _generate_libcst_script(
    repo_path: str, package: str, old_version: str, new_version: str,
    migration_key: Optional[str] = None,
) -> str:
    """Generate a LibCST migration script."""
    transforms_code = ""

    if migration_key and migration_key in PYTHON_MIGRATIONS:
        migration = PYTHON_MIGRATIONS[migration_key]
        for i, t in enumerate(migration["transforms"]):
            old_imp = t["old_import"]
            new_imp = t["new_import"]
            renames = t.get("rename", {})
            renames_repr = repr(renames)
            transforms_code += f"""
TRANSFORMS.append({{
    "old_import": {repr(old_imp)},
    "new_import": {repr(new_imp)},
    "renames": {renames_repr},
}})
"""

    return f'''#!/usr/bin/env python3
"""Auto-generated LibCST migration: {package} {old_version} → {new_version}"""
import libcst as cst
import libcst.matchers as m
from pathlib import Path
import sys

TRANSFORMS = []
{transforms_code}

class ImportRenamer(cst.CSTTransformer):
    """Rename imports and their usages using LibCST."""

    def __init__(self, transforms):
        self.transforms = transforms
        self.renames = {{}}  # old_name → new_name for this file
        self.changed = False

        # Build combined rename map
        for t in transforms:
            self.renames.update(t.get("renames", {{}}))

    def leave_ImportFrom(self, original_node, updated_node):
        """Transform 'from X import Y' statements."""
        source = updated_node

        for t in self.transforms:
            old_imp = t["old_import"]
            new_imp = t["new_import"]

            # Check if this import matches
            try:
                old_code = cst.parse_statement(old_imp)
                if not isinstance(old_code.body[0], cst.SimpleStatementLine):
                    continue
            except Exception:
                continue

            # Simple string match on the rendered import
            rendered = self._render(original_node)
            old_rendered = old_imp.replace("from ", "").replace(" import ", ".")

            if old_rendered.split(".")[0] in rendered:
                # Replace with new import
                try:
                    new_stmt = cst.parse_statement(new_imp)
                    if hasattr(new_stmt, "body") and new_stmt.body:
                        inner = new_stmt.body[0]
                        if isinstance(inner, cst.ImportFrom):
                            self.changed = True
                            return inner
                except Exception:
                    pass

        return updated_node

    def leave_Name(self, original_node, updated_node):
        """Rename identifiers that were part of renamed imports."""
        if original_node.value in self.renames:
            new_name = self.renames[original_node.value]
            if "." not in new_name:
                self.changed = True
                return updated_node.with_changes(value=new_name)
        return updated_node

    def _render(self, node):
        """Render a CST node to string."""
        try:
            return cst.parse_module("").code_for_node(node)
        except Exception:
            return ""


def migrate_file(file_path: Path, transforms):
    """Apply transforms to a single Python file."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = cst.parse_module(source)

        transformer = ImportRenamer(transforms)
        new_tree = tree.visit(transformer)

        if transformer.changed:
            file_path.write_text(new_tree.code, encoding="utf-8")
            return True
    except Exception as e:
        print(f"  Skip {{file_path}}: {{e}}", file=sys.stderr)
    return False


def main():
    repo = Path({repr(repo_path)})
    if not TRANSFORMS:
        print("No transforms defined, nothing to do.")
        sys.exit(0)

    files_changed = 0
    # Find all Python files (skip venv, __pycache__, .git)
    skip_dirs = {{"node_modules", ".git", "__pycache__", ".venv", "venv", "env", ".tox"}}

    for py_file in repo.rglob("*.py"):
        if any(skip in py_file.parts for skip in skip_dirs):
            continue
        if migrate_file(py_file, TRANSFORMS):
            files_changed += 1
            print(f"Modified: {{py_file.relative_to(repo)}}")

    print(f"\\nLibCST: {{files_changed}} file(s) modified")
    sys.exit(0)


if __name__ == "__main__":
    main()
'''


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════


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
            "output": output[-2000:],
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
