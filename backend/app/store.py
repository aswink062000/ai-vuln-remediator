"""
Secure credential store using SQLite + Fernet encryption.

- Credentials are encrypted at rest using AES-128 (Fernet)
- Encryption key is derived from a machine-specific secret
- Scan history is stored for persistence across restarts
- No plaintext secrets ever written to disk

Dependencies: cryptography (BSD license — commercial use OK)
"""

import os
import sqlite3
import hashlib
import logging
import platform
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)

# Database location
DB_DIR = Path(__file__).parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "store.db"


def _get_encryption_key() -> bytes:
    """
    Derive a machine-specific encryption key.
    Uses a combination of machine ID + app secret to generate a stable key.
    If ENCRYPTION_SECRET env var is set, uses that (for deployments).
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64

    # Use env var if set (for Docker/cloud deployments)
    secret = os.getenv("ENCRYPTION_SECRET", "")

    if not secret:
        # Generate machine-specific seed
        machine_parts = [
            platform.node(),
            platform.machine(),
            str(Path.home()),
            os.getenv("USERNAME", os.getenv("USER", "default")),
        ]
        secret = "|".join(machine_parts)

    # Derive a proper Fernet key using PBKDF2
    salt = b"ai-vuln-remediator-v2"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return key


def _get_fernet():
    """Get Fernet cipher instance."""
    from cryptography.fernet import Fernet
    key = _get_encryption_key()
    return Fernet(key)


def _get_db() -> sqlite3.Connection:
    """Get database connection, creating tables if needed."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    # Create tables
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS credentials (
            key TEXT PRIMARY KEY,
            encrypted_value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            mode TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            result_json TEXT,
            total_findings INTEGER DEFAULT 0,
            status TEXT DEFAULT 'unknown'
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn


# =============================================================================
# CREDENTIAL MANAGEMENT (Encrypted)
# =============================================================================

def save_credential(key: str, value: str) -> bool:
    """Save an encrypted credential."""
    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(value.encode()).decode()

        conn = _get_db()
        conn.execute(
            "INSERT OR REPLACE INTO credentials (key, encrypted_value, updated_at) VALUES (?, ?, ?)",
            (key, encrypted, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

        # Also set in runtime environment
        os.environ[key] = value
        logger.info(f"Credential saved: {key}")
        return True
    except Exception as e:
        logger.error(f"Failed to save credential {key}: {e}")
        return False


def get_credential(key: str) -> Optional[str]:
    """Retrieve and decrypt a credential."""
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT encrypted_value FROM credentials WHERE key = ?", (key,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        fernet = _get_fernet()
        decrypted = fernet.decrypt(row["encrypted_value"].encode()).decode()
        return decrypted
    except Exception as e:
        logger.error(f"Failed to retrieve credential {key}: {e}")
        return None


def delete_credential(key: str) -> bool:
    """Delete a credential."""
    try:
        conn = _get_db()
        conn.execute("DELETE FROM credentials WHERE key = ?", (key,))
        conn.commit()
        conn.close()
        os.environ.pop(key, None)
        return True
    except Exception as e:
        logger.error(f"Failed to delete credential {key}: {e}")
        return False


def list_credentials() -> List[Dict[str, str]]:
    """List all stored credential keys (not values)."""
    try:
        conn = _get_db()
        rows = conn.execute("SELECT key, updated_at FROM credentials").fetchall()
        conn.close()
        return [{"key": r["key"], "updated_at": r["updated_at"]} for r in rows]
    except Exception:
        return []


def load_credentials_to_env():
    """Load all stored credentials into environment variables on startup."""
    try:
        conn = _get_db()
        rows = conn.execute("SELECT key, encrypted_value FROM credentials").fetchall()
        conn.close()

        fernet = _get_fernet()
        loaded = 0
        for row in rows:
            try:
                value = fernet.decrypt(row["encrypted_value"].encode()).decode()
                os.environ[row["key"]] = value
                loaded += 1
            except Exception:
                logger.warning(f"Failed to decrypt credential: {row['key']}")

        if loaded:
            logger.info(f"Loaded {loaded} credentials from secure store")
    except Exception as e:
        logger.warning(f"Could not load credentials from store: {e}")


# =============================================================================
# SCAN HISTORY
# =============================================================================

def save_scan_history(url: str, mode: str, result: Dict[str, Any]) -> int:
    """Save a scan result to history. Returns the history ID."""
    try:
        conn = _get_db()
        cursor = conn.execute(
            """INSERT INTO scan_history (url, mode, timestamp, result_json, total_findings, status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                url,
                mode,
                datetime.now().isoformat(),
                json.dumps(result),
                result.get("total_findings", 0),
                result.get("status", "unknown"),
            )
        )
        conn.commit()
        history_id = cursor.lastrowid
        conn.close()
        return history_id
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")
        return -1


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get scan history (most recent first)."""
    try:
        conn = _get_db()
        rows = conn.execute(
            """SELECT id, url, mode, timestamp, total_findings, status
               FROM scan_history ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_scan_history_detail(history_id: int) -> Optional[Dict[str, Any]]:
    """Get full scan result by history ID."""
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id = ?", (history_id,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        result = dict(row)
        if result.get("result_json"):
            result["result"] = json.loads(result["result_json"])
            del result["result_json"]
        return result
    except Exception:
        return None


def clear_scan_history() -> int:
    """Clear all scan history. Returns number of deleted records."""
    try:
        conn = _get_db()
        cursor = conn.execute("DELETE FROM scan_history")
        count = cursor.rowcount
        conn.commit()
        conn.close()
        logger.info(f"Cleared {count} scan history records")
        return count
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        return 0
