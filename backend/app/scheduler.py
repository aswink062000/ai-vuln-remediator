"""
Scheduled/Recurring Scan Scheduler.

Allows users to set up recurring scans on repositories.
Uses APScheduler (MIT license) for cron-like scheduling.
Stores schedules in SQLite.

Features:
- Daily/weekly/monthly scan schedules
- Stores results in scan history
- Trend tracking (is the codebase improving?)
"""

import logging
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# In-memory scheduler state (lightweight, no Redis needed)
_schedules: Dict[int, Dict] = {}
_scheduler_thread: Optional[threading.Thread] = None
_running = False


def get_schedules() -> List[Dict[str, Any]]:
    """Get all configured scan schedules."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                mode TEXT DEFAULT 'scan-only',
                frequency TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                next_run TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()

        rows = conn.execute("SELECT * FROM scan_schedules ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get schedules: {e}")
        return []


def add_schedule(url: str, frequency: str, mode: str = "scan-only") -> int:
    """
    Add a new scan schedule.
    frequency: 'daily', 'weekly', 'monthly'
    """
    from app.store import _get_db

    valid_frequencies = {"daily", "weekly", "monthly"}
    if frequency not in valid_frequencies:
        raise ValueError(f"Invalid frequency. Must be one of: {valid_frequencies}")

    try:
        conn = _get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                mode TEXT DEFAULT 'scan-only',
                frequency TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                next_run TEXT,
                created_at TEXT NOT NULL
            )
        """)

        now = datetime.now().isoformat()
        next_run = _calculate_next_run(frequency)

        cursor = conn.execute(
            """INSERT INTO scan_schedules (url, mode, frequency, enabled, next_run, created_at)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (url, mode, frequency, next_run, now)
        )
        conn.commit()
        schedule_id = cursor.lastrowid
        conn.close()

        logger.info(f"Schedule added: {url} ({frequency}), id={schedule_id}")
        return schedule_id
    except Exception as e:
        logger.error(f"Failed to add schedule: {e}")
        return -1


def delete_schedule(schedule_id: int) -> bool:
    """Delete a scan schedule."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def toggle_schedule(schedule_id: int, enabled: bool) -> bool:
    """Enable or disable a schedule."""
    from app.store import _get_db

    try:
        conn = _get_db()
        conn.execute(
            "UPDATE scan_schedules SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, schedule_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def run_scheduled_scan(schedule_id: int) -> Dict[str, Any]:
    """Manually trigger a scheduled scan."""
    from app.store import _get_db, save_scan_history
    from app.gitops.clone import clone_repo, cleanup_repo
    from app.scanners.multi_scanner import run_all_scanners
    from app.validators.validate import detect_project_language, check_sdk_availability

    try:
        conn = _get_db()
        row = conn.execute("SELECT * FROM scan_schedules WHERE id = ?", (schedule_id,)).fetchone()
        conn.close()

        if not row:
            return {"error": "Schedule not found"}

        schedule = dict(row)
        url = schedule["url"]

        logger.info(f"Running scheduled scan for: {url}")

        repo_path = clone_repo(url)
        try:
            project_info = detect_project_language(repo_path)
            sdk_check = check_sdk_availability(project_info)
            scan_result = run_all_scanners(repo_path)

            result = {
                "status": "success",
                "repo": url,
                "total_findings": scan_result["summary"]["total"],
                "scan_summary": scan_result["summary"],
                "findings": scan_result["findings"],
                "errors": scan_result["errors"],
                "project_info": project_info,
                "sdk_status": sdk_check,
                "code_quality": scan_result.get("code_quality", {}),
                "scheduled": True,
                "schedule_id": schedule_id,
            }

            # Save to history
            save_scan_history(url, "scheduled", result)

            # Update schedule
            conn = _get_db()
            next_run = _calculate_next_run(schedule["frequency"])
            conn.execute(
                "UPDATE scan_schedules SET last_run = ?, next_run = ? WHERE id = ?",
                (datetime.now().isoformat(), next_run, schedule_id)
            )
            conn.commit()
            conn.close()

            return result

        finally:
            cleanup_repo(repo_path)

    except Exception as e:
        logger.error(f"Scheduled scan failed: {e}")
        return {"status": "error", "message": str(e)}


def get_scan_trends(url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get scan trend data for a repository.
    Shows how findings count changes over time.
    """
    from app.store import _get_db

    try:
        conn = _get_db()
        rows = conn.execute(
            """SELECT timestamp, total_findings, status
               FROM scan_history
               WHERE url = ?
               ORDER BY id DESC
               LIMIT ?""",
            (url, limit)
        ).fetchall()
        conn.close()

        trends = [dict(r) for r in rows]
        trends.reverse()  # Oldest first for charting

        return trends
    except Exception:
        return []


def _calculate_next_run(frequency: str) -> str:
    """Calculate the next run time based on frequency."""
    from datetime import timedelta

    now = datetime.now()
    if frequency == "daily":
        next_time = now + timedelta(days=1)
    elif frequency == "weekly":
        next_time = now + timedelta(weeks=1)
    elif frequency == "monthly":
        next_time = now + timedelta(days=30)
    else:
        next_time = now + timedelta(days=1)

    return next_time.isoformat()
