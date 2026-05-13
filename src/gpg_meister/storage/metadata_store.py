"""SQLite metadata store for key labels, vault records, and app preferences.

Uses only the built-in sqlite3 module. No ORM. No private keys, passphrases,
or decrypted content are stored here (planv2.md §4.7).

All timestamps are stored as UTC ISO 8601 strings.
"""

from __future__ import annotations

import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path


class MetadataStoreError(Exception):
    """Raised on schema or constraint violations."""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS key_metadata (
    fingerprint         TEXT PRIMARY KEY,
    label               TEXT NOT NULL DEFAULT '',
    import_timestamp    TEXT NOT NULL,
    last_used_timestamp TEXT
);

CREATE TABLE IF NOT EXISTS vault_record (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    filename            TEXT NOT NULL,
    creation_timestamp  TEXT NOT NULL,
    key_count           INTEGER NOT NULL DEFAULT 0,
    description         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS app_preferences (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""


class MetadataStore:
    """Thin wrapper over a SQLite database file.

    Open with a context manager or keep alive for the process lifetime. Concurrent
    access from multiple threads is safe; WAL mode allows one writer + many readers.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if sys.platform != "win32":
            import os
            os.chmod(path, 0o600)
            for sidecar in (path.parent / (path.name + "-wal"), path.parent / (path.name + "-shm")):
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)
        with self._conn:
            self._conn.executescript(_SCHEMA)

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        with self._conn:
            yield self._conn

    # ------------------------------------------------------------------
    # key_metadata
    # ------------------------------------------------------------------

    def upsert_key(self, fingerprint: str, *, label: str = "") -> None:
        """Insert or update a key metadata row."""
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT fingerprint FROM key_metadata WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE key_metadata SET label = ? WHERE fingerprint = ?",
                    (label, fingerprint),
                )
            else:
                conn.execute(
                    "INSERT INTO key_metadata (fingerprint, label, import_timestamp)"
                    " VALUES (?, ?, ?)",
                    (fingerprint, label, _utc_now()),
                )

    def touch_key(self, fingerprint: str) -> None:
        """Update last_used_timestamp to now."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE key_metadata SET last_used_timestamp = ? WHERE fingerprint = ?",
                (_utc_now(), fingerprint),
            )

    def delete_key(self, fingerprint: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM key_metadata WHERE fingerprint = ?", (fingerprint,))

    def get_key(self, fingerprint: str) -> dict[str, str | None] | None:
        row = self._conn.execute(
            "SELECT * FROM key_metadata WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return dict(row) if row else None

    def list_keys(self) -> list[dict[str, str | None]]:
        rows = self._conn.execute(
            "SELECT * FROM key_metadata ORDER BY import_timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # vault_record
    # ------------------------------------------------------------------

    def add_vault_record(
        self, filename: str, *, key_count: int, description: str = ""
    ) -> int:
        """Insert a vault record and return its row id."""
        with self._tx() as conn:
            cursor = conn.execute(
                "INSERT INTO vault_record (filename, creation_timestamp, key_count, description)"
                " VALUES (?, ?, ?, ?)",
                (filename, _utc_now(), key_count, description),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def list_vault_records(self) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM vault_record ORDER BY creation_timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_vault_timestamp(self) -> str | None:
        """Return the creation_timestamp of the most recent vault record, or None."""
        row = self._conn.execute(
            "SELECT creation_timestamp FROM vault_record ORDER BY creation_timestamp DESC LIMIT 1"
        ).fetchone()
        return row["creation_timestamp"] if row else None

    # ------------------------------------------------------------------
    # app_preferences
    # ------------------------------------------------------------------

    def set_preference(self, key: str, value: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO app_preferences (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def get_preference(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM app_preferences WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def delete_preference(self, key: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM app_preferences WHERE key = ?", (key,))

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> MetadataStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
