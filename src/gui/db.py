"""
CloudSpider — SQLite database layer for user management and snapshot metadata.
"""

import os
import sqlite3
import secrets
import string
import logging
import time
from contextlib import contextmanager
from typing import Optional, Dict, Any, List

import bcrypt

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("CLOUDSPIDER_DB", "/app/data/cloudspider.db")

# ── Schema ────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT  NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'full'
                        CHECK(role IN ('admin', 'full', 'readonly')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by  TEXT    DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS snapshots_meta (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL,
    filename            TEXT    NOT NULL UNIQUE,
    created_by          TEXT    NOT NULL,
    visibility          TEXT    NOT NULL DEFAULT 'private'
                                CHECK(visibility IN ('private', 'public')),
    public_password_hash TEXT   DEFAULT NULL,
    node_count          INTEGER DEFAULT 0,
    link_count          INTEGER DEFAULT 0,
    profile             TEXT    DEFAULT '',
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (created_by) REFERENCES users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


# ── Connection ────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    """Context manager yielding a sqlite3 connection with auto-commit."""
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Initialization ────────────────────────────────────────────────────

def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def init_db():
    """Create tables and seed the default admin account on first run.

    Returns the admin password if it was just created (first run), else None.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with get_db() as conn:
        conn.executescript(_SCHEMA)

        # Check if this is the first initialization
        row = conn.execute(
            "SELECT value FROM app_state WHERE key = 'initialized'"
        ).fetchone()

        if row is not None:
            return None  # already initialized

        # First run — create admin account
        admin_password = _generate_password()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_by) VALUES (?, ?, 'admin', 'system')",
            ("admin", _hash_password(admin_password)),
        )
        conn.execute(
            "INSERT INTO app_state (key, value) VALUES ('initialized', ?)",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),),
        )

        return admin_password


# ── User CRUD ─────────────────────────────────────────────────────────

def get_user(username: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, created_at, created_by FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row:
            return dict(row)
    return None


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify credentials and return user dict or None."""
    user = get_user(username)
    if user and verify_password(password, user["password_hash"]):
        return user
    return None


def create_user(username: str, password: str, role: str, created_by: str = "admin") -> Dict[str, Any]:
    if role not in ("full", "readonly"):
        raise ValueError("Role must be 'full' or 'readonly'.")
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    if not password or len(password) < 4:
        raise ValueError("Password must be at least 4 characters.")

    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_by) VALUES (?, ?, ?, ?)",
                (username.strip(), _hash_password(password), role, created_by),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{username}' already exists.")

    return get_user(username)


def update_password(username: str, new_password: str):
    if not new_password or len(new_password) < 4:
        raise ValueError("Password must be at least 4 characters.")
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (_hash_password(new_password), username),
        )


def update_role(username: str, new_role: str):
    if new_role not in ("full", "readonly"):
        raise ValueError("Role must be 'full' or 'readonly'.")
    # Prevent changing admin's own role
    user = get_user(username)
    if user and user["role"] == "admin":
        raise ValueError("Cannot change the admin's role.")
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (new_role, username),
        )


def delete_user(username: str):
    user = get_user(username)
    if not user:
        raise ValueError(f"User '{username}' not found.")
    if user["role"] == "admin":
        raise ValueError("Cannot delete the admin account.")
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


def list_users() -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at, created_by FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


# ── Snapshot Metadata CRUD ────────────────────────────────────────────

def create_snapshot_meta(
    name: str, filename: str, created_by: str,
    node_count: int = 0, link_count: int = 0, profile: str = ""
) -> Dict[str, Any]:
    with get_db() as conn:
        conn.execute(
            """INSERT INTO snapshots_meta
               (name, filename, created_by, node_count, link_count, profile)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, filename, created_by, node_count, link_count, profile),
        )
        row = conn.execute(
            "SELECT * FROM snapshots_meta WHERE filename = ?", (filename,)
        ).fetchone()
        return dict(row)


def get_snapshot_meta(filename: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots_meta WHERE filename = ?", (filename,)
        ).fetchone()
        return dict(row) if row else None


def get_snapshot_meta_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Get snapshot metadata by display name. Returns the most recent if duplicates exist."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots_meta WHERE name = ? ORDER BY created_at DESC LIMIT 1",
            (name,),
        ).fetchone()
        return dict(row) if row else None


def list_snapshots_for_user(username: str) -> Dict[str, List[Dict[str, Any]]]:
    """Return own snapshots and public snapshots from others."""
    with get_db() as conn:
        own_rows = conn.execute(
            "SELECT * FROM snapshots_meta WHERE created_by = ? ORDER BY created_at DESC",
            (username,),
        ).fetchall()
        public_rows = conn.execute(
            "SELECT * FROM snapshots_meta WHERE visibility = 'public' AND created_by != ? ORDER BY created_at DESC",
            (username,),
        ).fetchall()
    return {
        "own": [dict(r) for r in own_rows],
        "public": [dict(r) for r in public_rows],
    }


def update_snapshot_visibility(
    filename: str, visibility: str, public_password: Optional[str] = None
):
    if visibility not in ("private", "public"):
        raise ValueError("Visibility must be 'private' or 'public'.")
    pw_hash = None
    if visibility == "public":
        if not public_password:
            raise ValueError("A password is required when making a snapshot public.")
        pw_hash = _hash_password(public_password)
    with get_db() as conn:
        conn.execute(
            "UPDATE snapshots_meta SET visibility = ?, public_password_hash = ? WHERE filename = ?",
            (visibility, pw_hash, filename),
        )


def verify_snapshot_password(filename: str, password: str) -> bool:
    meta = get_snapshot_meta(filename)
    if not meta or not meta.get("public_password_hash"):
        return False
    return verify_password(password, meta["public_password_hash"])


def delete_snapshot_meta(filename: str):
    with get_db() as conn:
        conn.execute("DELETE FROM snapshots_meta WHERE filename = ?", (filename,))
