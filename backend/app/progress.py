"""
Simple in-memory progress tracker for long-running operations.
Frontend polls GET /api/v1/progress/{task_id} to get real-time updates.
"""

import time
import threading
from typing import Dict, List, Optional

_progress_store: Dict[str, Dict] = {}
_lock = threading.Lock()


def create_task(task_id: str) -> None:
    """Create a new progress task."""
    with _lock:
        _progress_store[task_id] = {
            "task_id": task_id,
            "status": "running",
            "phase": "Starting...",
            "logs": [],
            "started_at": time.time(),
            "completed_at": None,
        }


def update_progress(task_id: str, phase: str, message: str = "") -> None:
    """Update the current phase and add a log message."""
    with _lock:
        task = _progress_store.get(task_id)
        if task:
            task["phase"] = phase
            if message:
                task["logs"].append({
                    "time": time.strftime("%H:%M:%S"),
                    "message": message,
                })
                # Keep only last 50 logs
                if len(task["logs"]) > 50:
                    task["logs"] = task["logs"][-50:]


def complete_task(task_id: str, status: str = "complete") -> None:
    """Mark a task as complete."""
    with _lock:
        task = _progress_store.get(task_id)
        if task:
            task["status"] = status
            task["completed_at"] = time.time()


def get_progress(task_id: str) -> Optional[Dict]:
    """Get current progress for a task."""
    with _lock:
        task = _progress_store.get(task_id)
        if task:
            elapsed = time.time() - task["started_at"]
            return {**task, "elapsed_seconds": round(elapsed, 1)}
    return None


def cleanup_old_tasks(max_age_seconds: int = 300) -> None:
    """Remove tasks older than max_age_seconds."""
    now = time.time()
    with _lock:
        to_remove = [
            tid for tid, t in _progress_store.items()
            if t.get("completed_at") and (now - t["completed_at"]) > max_age_seconds
        ]
        for tid in to_remove:
            del _progress_store[tid]
