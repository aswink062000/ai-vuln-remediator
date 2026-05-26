"""
Baseline / Suppress Findings.

Allows users to:
- Mark findings as "accepted risk" or "false positive"
- Set a baseline scan — future scans only show NEW findings
- Track suppression history

Stored in SQLite. No external dependencies.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _ensure_table():
    """Create suppressed_findings table if not exists."""
    from app.store import _get_db
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS suppressed_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            path TEXT,
            reason TEXT NOT NULL,
            suppressed_by TEXT DEFAULT 'user',
            created_at TEXT NOT NULL,
            UNIQUE(rule_id, path)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_url TEXT NOT NULL,
            finding_hashes TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def suppress_finding(rule_id: str, path: Optional[str], reason: str) -> bool:
    """Suppress a finding (mark as accepted risk or false positive)."""
    from app.store import _get_db
    _ensure_table()

    try:
        conn = _get_db()
        conn.execute(
            """INSERT OR REPLACE INTO suppressed_findings (rule_id, path, reason, created_at)
               VALUES (?, ?, ?, ?)""",
            (rule_id, path or "*", reason, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        logger.info(f"Suppressed: {rule_id} in {path or '*'} ({reason})")
        return True
    except Exception as e:
        logger.error(f"Failed to suppress finding: {e}")
        return False


def unsuppress_finding(rule_id: str, path: Optional[str] = None) -> bool:
    """Remove a suppression."""
    from app.store import _get_db
    _ensure_table()

    try:
        conn = _get_db()
        if path:
            conn.execute("DELETE FROM suppressed_findings WHERE rule_id = ? AND path = ?", (rule_id, path))
        else:
            conn.execute("DELETE FROM suppressed_findings WHERE rule_id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_suppressions() -> List[Dict[str, Any]]:
    """Get all suppressed findings."""
    from app.store import _get_db
    _ensure_table()

    try:
        conn = _get_db()
        rows = conn.execute("SELECT * FROM suppressed_findings ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def is_suppressed(rule_id: str, path: str) -> bool:
    """Check if a finding is suppressed."""
    from app.store import _get_db
    _ensure_table()

    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT 1 FROM suppressed_findings WHERE (rule_id = ? AND (path = ? OR path = '*'))",
            (rule_id, path)
        ).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False


def filter_suppressed(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Filter out suppressed findings from scan results.
    Returns both filtered findings and suppression stats.
    """
    _ensure_table()

    # Load all suppressions into memory for fast lookup
    suppressions = get_suppressions()
    suppression_set = set()
    for s in suppressions:
        suppression_set.add((s["rule_id"], s["path"]))
        if s["path"] == "*":
            suppression_set.add((s["rule_id"], "*"))

    active = []
    suppressed = []

    for f in findings:
        rule_id = f.get("rule_id", "")
        path = f.get("path", "")

        if (rule_id, path) in suppression_set or (rule_id, "*") in suppression_set:
            suppressed.append(f)
        else:
            active.append(f)

    return {
        "active_findings": active,
        "suppressed_findings": suppressed,
        "suppressed_count": len(suppressed),
        "active_count": len(active),
    }


def set_baseline(repo_url: str, findings: List[Dict[str, Any]]) -> int:
    """
    Set a baseline for a repository.
    Future scans will highlight only NEW findings not in this baseline.
    """
    from app.store import _get_db
    _ensure_table()

    # Create hashes of current findings
    hashes = set()
    for f in findings:
        h = f"{f.get('rule_id', '')}|{f.get('path', '')}|{f.get('line', '')}"
        hashes.add(h)

    try:
        conn = _get_db()
        conn.execute(
            """INSERT INTO scan_baselines (repo_url, finding_hashes, created_at)
               VALUES (?, ?, ?)""",
            (repo_url, json.dumps(list(hashes)), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        logger.info(f"Baseline set for {repo_url}: {len(hashes)} findings")
        return len(hashes)
    except Exception as e:
        logger.error(f"Failed to set baseline: {e}")
        return -1


def get_new_findings(repo_url: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare findings against the baseline.
    Returns only NEW findings that weren't in the baseline.
    """
    from app.store import _get_db
    _ensure_table()

    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT finding_hashes FROM scan_baselines WHERE repo_url = ? ORDER BY id DESC LIMIT 1",
            (repo_url,)
        ).fetchone()
        conn.close()

        if not row:
            return {"new_findings": findings, "baseline_count": 0, "has_baseline": False}

        baseline_hashes = set(json.loads(row["finding_hashes"]))

        new_findings = []
        existing = []
        for f in findings:
            h = f"{f.get('rule_id', '')}|{f.get('path', '')}|{f.get('line', '')}"
            if h in baseline_hashes:
                existing.append(f)
            else:
                new_findings.append(f)

        return {
            "new_findings": new_findings,
            "existing_findings": len(existing),
            "baseline_count": len(baseline_hashes),
            "has_baseline": True,
            "new_count": len(new_findings),
        }
    except Exception:
        return {"new_findings": findings, "baseline_count": 0, "has_baseline": False}
