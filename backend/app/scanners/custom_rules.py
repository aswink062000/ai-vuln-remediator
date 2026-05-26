"""
Custom Rule Engine — User-defined security rules.

Allows users to create custom Semgrep rules via the UI.
Rules are stored in SQLite and applied alongside default scans.

This is a major differentiator — SonarQube charges for custom rules.
"""

import json
import logging
import tempfile
import subprocess
import os
import sys
import platform
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Default custom rules directory
RULES_DIR = Path(__file__).parent.parent.parent / "data" / "custom_rules"
RULES_DIR.mkdir(parents=True, exist_ok=True)


def get_custom_rules() -> List[Dict[str, Any]]:
    """Get all custom rules from the store."""
    from app.store import _get_db

    try:
        conn = _get_db()
        # Create table if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                language TEXT NOT NULL,
                severity TEXT DEFAULT 'WARNING',
                pattern TEXT NOT NULL,
                message TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()

        rows = conn.execute(
            "SELECT * FROM custom_rules ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get custom rules: {e}")
        return []


def save_custom_rule(rule: Dict[str, Any]) -> int:
    """Save a new custom rule. Returns the rule ID."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                language TEXT NOT NULL,
                severity TEXT DEFAULT 'WARNING',
                pattern TEXT NOT NULL,
                message TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        now = datetime.now().isoformat()
        cursor = conn.execute(
            """INSERT INTO custom_rules (name, description, language, severity, pattern, message, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule.get("name", "Custom Rule"),
                rule.get("description", ""),
                rule.get("language", "python"),
                rule.get("severity", "WARNING"),
                rule.get("pattern", ""),
                rule.get("message", "Custom rule violation"),
                1,
                now,
                now,
            )
        )
        conn.commit()
        rule_id = cursor.lastrowid
        conn.close()
        logger.info(f"Custom rule saved: {rule.get('name')} (id={rule_id})")
        return rule_id
    except Exception as e:
        logger.error(f"Failed to save custom rule: {e}")
        return -1


def delete_custom_rule(rule_id: int) -> bool:
    """Delete a custom rule."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def toggle_custom_rule(rule_id: int, enabled: bool) -> bool:
    """Enable or disable a custom rule."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute(
            "UPDATE custom_rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, datetime.now().isoformat(), rule_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def run_custom_rules(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run all enabled custom rules against the repository.
    Generates a temporary Semgrep YAML config and executes it.
    """
    rules = get_custom_rules()
    enabled_rules = [r for r in rules if r.get("enabled")]

    if not enabled_rules:
        return []

    logger.info(f"Running {len(enabled_rules)} custom rules...")

    # Generate Semgrep YAML config
    semgrep_rules = []
    for rule in enabled_rules:
        semgrep_rule = {
            "id": f"custom-{rule['id']}-{rule['name'].lower().replace(' ', '-')}",
            "patterns": [{"pattern": rule["pattern"]}],
            "message": rule["message"],
            "languages": [rule["language"]],
            "severity": rule["severity"],
            "metadata": {
                "category": "custom",
                "scanner": "custom-rules",
                "custom_rule_id": rule["id"],
            },
        }
        semgrep_rules.append(semgrep_rule)

    # Write temp config
    config = {"rules": semgrep_rules}
    config_path = Path(tempfile.mktemp(suffix=".yml"))

    try:
        config_path.write_text(
            json.dumps(config, indent=2).replace('"patterns"', '"pattern"'),
            encoding="utf-8"
        )

        # Actually write proper YAML
        yaml_content = _rules_to_yaml(semgrep_rules)
        config_path.write_text(yaml_content, encoding="utf-8")

        # Run semgrep with custom config
        from app.scanners.semgrep_scan import _find_semgrep_binary, _get_subprocess_env, _run_semgrep_cmd

        semgrep_bin = _find_semgrep_binary()
        if not semgrep_bin:
            logger.warning("Semgrep not found, skipping custom rules")
            return []

        env = _get_subprocess_env()
        cmd = [
            semgrep_bin, "scan",
            "--config", str(config_path),
            "--json",
            "--no-git-ignore",
            repo_path,
        ]

        output = _run_semgrep_cmd(cmd, env, "custom rules")
        if not output:
            return []

        # Parse results
        findings = []
        for item in output.get("results", []):
            findings.append({
                "path": item.get("path", ""),
                "line": item.get("start", {}).get("line"),
                "end_line": item.get("end", {}).get("line"),
                "rule_id": item.get("check_id", "custom"),
                "message": item.get("extra", {}).get("message", ""),
                "severity": item.get("extra", {}).get("severity", "WARNING"),
                "metadata": {
                    "scanner": "custom-rules",
                    "category": "custom",
                },
            })

        logger.info(f"Custom rules found {len(findings)} issues")
        return findings

    except Exception as e:
        logger.error(f"Custom rules execution failed: {e}")
        return []
    finally:
        config_path.unlink(missing_ok=True)


def _rules_to_yaml(rules: List[Dict]) -> str:
    """Convert rules to Semgrep YAML format."""
    lines = ["rules:"]
    for rule in rules:
        lines.append(f"  - id: {rule['id']}")
        lines.append(f"    pattern: |")
        for pline in rule["patterns"][0]["pattern"].splitlines():
            lines.append(f"      {pline}")
        lines.append(f"    message: {rule['message']}")
        lines.append(f"    languages: [{', '.join(rule['languages'])}]")
        lines.append(f"    severity: {rule['severity']}")
        lines.append("")
    return "\n".join(lines)
