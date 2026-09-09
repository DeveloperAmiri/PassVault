"""SQLite storage layer for PassVault.

The database stores metadata in plain text (site name, username, URL, notes)
and the password itself only as a Fernet-encrypted token. For a personal,
offline vault this is a good trade-off: you can search and list entries
without unlocking every secret, while passwords never touch disk as plain text.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    username     TEXT    NOT NULL,
    url          TEXT    NOT NULL DEFAULT '',
    password_enc TEXT    NOT NULL,
    notes        TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VaultDB:
    """Thin wrapper around sqlite3 with helpers for entries and metadata."""

    def __init__(self, path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- meta -----------------------------------------------------------
    def get_meta(self, key):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key, value):
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    # -- entries ----------------------------------------------------------
    def add_entry(self, name, username, url, password_enc, notes="") -> int:
        now = _utcnow()
        cur = self.conn.execute(
            "INSERT INTO entries (name, username, url, password_enc, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, username, url, password_enc, notes, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_entries(self, search=None):
        if search:
            like = f"%{search}%"
            rows = self.conn.execute(
                "SELECT * FROM entries WHERE name LIKE ? OR username LIKE ? ORDER BY name COLLATE NOCASE",
                (like, like),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM entries ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [dict(r) for r in rows]

    def find_by_name(self, name):
        """Case-insensitive exact-name lookup."""
        rows = self.conn.execute(
            "SELECT * FROM entries WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_entry(self, entry_id) -> bool:
        cur = self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def close(self):
        self.conn.close()
