"""
WebSocket endpoint for real-time scan progress streaming.

Sends structured log messages to the frontend terminal UI:
- install: dependency installation progress
- log: general scan progress
- phase: major phase transitions (clone, scan, fix, etc.)
- sdk_check: SDK availability results
- result: final scan/remediation result
- error: error messages
"""

import asyncio
import logging
import json
import queue
import threading
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# Thread-safe queue for passing log messages from sync code to async WebSocket
_log_queues: dict = {}  # session_id -> queue.Queue


class WebSocketLogHandler(logging.Handler):
    """Custom logging handler that pushes log records to a queue for WebSocket streaming."""

    def __init__(self, session_id: str):
        super().__init__()
        self.session_id = session_id

    def emit(self, record):
        try:
            q = _log_queues.get(self.session_id)
            if q:
                msg = self.format(record)
                q.put({
                    "type": "log",
                    "level": record.levelname.lower(),
                    "message": msg,
                    "logger": record.name,
                })
        except Exception:
            pass


def send_progress(session_id: str, msg_type: str, message: str, data: Optional[dict] = None):
    """Send a structured progress message to the WebSocket client."""
    q = _log_queues.get(session_id)
    if q:
        payload = {"type": msg_type, "message": message}
        if data:
            payload["data"] = data
        q.put(payload)


def run_scan_with_logging(session_id: str, github_url: str, mode: str):
    """
    Run the scan/remediation pipeline in a thread, streaming logs via queue.
    """
    from app.validators.validate import (
        detect_environment,
        detect_project_language,
        check_sdk_availability,
    )

    q = _log_queues[session_id]

    try:
        # Phase 1: Environment check
        send_progress(session_id, "phase", "Checking system environment...")
        env = detect_environment()

        # Report SDK status
        send_progress(session_id, "sdk_check", "SDK availability check complete", data=env)

        # Check for missing critical tools
        missing_tools = []
        if not env.get("python"):
            missing_tools.append({"name": "Python", "install_cmd": "Download from https://python.org"})
        if not env.get("node"):
            missing_tools.append({"name": "Node.js", "install_cmd": "Download from https://nodejs.org"})
        if not env.get("java"):
            missing_tools.append({"name": "Java JDK", "install_cmd": "Download from https://adoptium.net"})

        if missing_tools:
            send_progress(session_id, "missing_sdk", "Some SDKs are not installed", data={"missing": missing_tools})

        # Phase 2: Clone
        send_progress(session_id, "phase", "Cloning repository...")
        from app.gitops.clone import clone_repo, cleanup_repo
        repo_path = clone_repo(github_url)
        send_progress(session_id, "log", f"Repository cloned to temporary directory")

        try:
            # Phase 3: Project detection
            send_progress(session_id, "phase", "Detecting project type...")
            project_info = detect_project_language(repo_path)
            sdk_check = check_sdk_availability(project_info)
            send_progress(session_id, "log", f"Languages: {', '.join(project_info.get('languages', []))}")
            send_progress(session_id, "log", f"Frameworks: {', '.join(project_info.get('frameworks', []))}")

            if mode == "scan-only":
                # Phase 4: Scanning
                send_progress(session_id, "phase", "Installing scan dependencies...")
                send_progress(session_id, "install", "Checking semgrep installation...")

                from app.scanners.multi_scanner import run_all_scanners
                send_progress(session_id, "phase", "Running security scanners...")
                send_progress(session_id, "log", "Starting SAST scan (Semgrep)...")

                scan_result = run_all_scanners(repo_path)

                total = scan_result["summary"]["total"]
                send_progress(session_id, "log", f"Scan complete: {total} findings")

                # Report code quality gate
                cq = scan_result.get("code_quality", {})
                if cq:
                    gate = cq.get("quality_gate_details", {})
                    gate_status = "PASSED" if gate.get("passed") else "FAILED"
                    send_progress(session_id, "log", f"Quality Gate: {gate_status}")
                    debt = cq.get("metrics", {}).get("technical_debt", {})
                    if debt:
                        send_progress(session_id, "log", f"Technical Debt: {debt.get('total_hours', 0)}h (Rating: {debt.get('rating', 'N/A')})")

                send_progress(session_id, "phase", "Scan complete!")

                result = {
                    "status": "success",
                    "repo": github_url,
                    "total_findings": total,
                    "scan_summary": scan_result["summary"],
                    "findings": scan_result["findings"],
                    "errors": scan_result["errors"],
                    "project_info": project_info,
                    "sdk_status": sdk_check,
                    "code_quality": cq,
                }

            else:
                # Full remediation
                send_progress(session_id, "phase", "Running full remediation pipeline...")
                from app.workflow.remediation import run_remediation
                result = run_remediation(github_url)

            # Send final result
            send_progress(session_id, "result", "Done", data=result)

        finally:
            if repo_path:
                cleanup_repo(repo_path)

    except Exception as e:
        send_progress(session_id, "error", str(e))
        send_progress(session_id, "result", "Error", data={
            "status": "error",
            "message": str(e),
        })


@router.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """
    WebSocket endpoint for real-time scan progress.
    
    Client sends: {"github_url": "...", "mode": "scan-only" | "scan-fix"}
    Server streams: {"type": "phase|log|install|sdk_check|result|error", "message": "...", "data": {...}}
    """
    await websocket.accept()

    session_id = None

    try:
        # Wait for the scan request from client
        data = await websocket.receive_text()
        request = json.loads(data)

        github_url = request.get("github_url", "")
        mode = request.get("mode", "scan-only")

        if not github_url.startswith("https://github.com/"):
            await websocket.send_json({
                "type": "error",
                "message": "Only GitHub HTTPS URLs are supported"
            })
            await websocket.close()
            return

        # Create session
        session_id = f"ws_{id(websocket)}"
        _log_queues[session_id] = queue.Queue()

        # Attach log handler to capture all app logs
        log_handler = WebSocketLogHandler(session_id)
        log_handler.setLevel(logging.INFO)
        log_handler.setFormatter(logging.Formatter("%(message)s"))

        # Attach to root logger to capture all app.* logs
        root_logger = logging.getLogger("app")
        root_logger.addHandler(log_handler)

        # Send initial acknowledgment
        await websocket.send_json({
            "type": "phase",
            "message": f"Starting {'scan' if mode == 'scan-only' else 'remediation'} for {github_url}..."
        })

        # Run scan in a background thread
        scan_thread = threading.Thread(
            target=run_scan_with_logging,
            args=(session_id, github_url, mode),
            daemon=True
        )
        scan_thread.start()

        # Stream messages from queue to WebSocket
        while True:
            try:
                # Check for messages with a short timeout
                try:
                    msg = _log_queues[session_id].get(timeout=0.1)
                    await websocket.send_json(msg)

                    # If we got the final result, we're done
                    if msg.get("type") == "result":
                        break

                except queue.Empty:
                    # No message yet, check if thread is still alive
                    if not scan_thread.is_alive():
                        # Thread finished, drain remaining messages
                        while not _log_queues[session_id].empty():
                            msg = _log_queues[session_id].get_nowait()
                            await websocket.send_json(msg)
                        break

                # Small yield to prevent blocking
                await asyncio.sleep(0.05)

            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except json.JSONDecodeError:
        await websocket.send_json({"type": "error", "message": "Invalid JSON request"})
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        # Cleanup
        if session_id:
            # Remove log handler
            root_logger = logging.getLogger("app")
            for handler in root_logger.handlers[:]:
                if isinstance(handler, WebSocketLogHandler) and handler.session_id == session_id:
                    root_logger.removeHandler(handler)
            # Remove queue
            _log_queues.pop(session_id, None)

        try:
            await websocket.close()
        except Exception:
            pass
