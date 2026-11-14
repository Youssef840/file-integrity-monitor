"""SQLite persistence for baselines and the integrity event log."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Alert, EventType, FileRecord, RootInfo, now_iso

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS roots (
    root        TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL,
    excludes    TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline (
    root   TEXT    NOT NULL REFERENCES roots(root) ON DELETE CASCADE,
    path   TEXT    NOT NULL,
    hash   TEXT    NOT NULL,
    size   INTEGER NOT NULL,
    mtime  REAL    NOT NULL,
    PRIMARY KEY (root, path)
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    root        TEXT NOT NULL,
    path        TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    old_hash    TEXT,
    new_hash    TEXT,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_root_id ON events(root, id);
"""


class DatabaseError(Exception):
    """Base class for database related errors."""


class BaselineExistsError(DatabaseError):
    """A baseline already exists and ``force`` was not requested."""


class IntegrityDB:
    """Thread-safe wrapper around the SQLite database.

    The watchdog observer delivers events on a background thread, so a single
    connection is shared behind a lock (``check_same_thread=False``).
    """

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Cannot open database '{self.path}': {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    # ------------------------------------------------------------- lifecycle
    def _migrate(self) -> None:
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise DatabaseError(
                    f"Database schema v{version} is newer than this tool supports "
                    f"(v{SCHEMA_VERSION}). Please upgrade."
                )
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> IntegrityDB:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def sidecar_paths(self) -> Tuple[Path, ...]:
        """The DB file plus SQLite's temporary companions (never monitor these)."""
        return tuple(Path(str(self.path) + suffix) for suffix in ("", "-journal", "-wal", "-shm"))

    # ---------------------------------------------------------------- roots
    def get_root(self, root: str) -> Optional[RootInfo]:
        with self._lock:
            row = self._conn.execute(
                """SELECT r.root, r.algorithm, r.excludes, r.created_at,
                          (SELECT COUNT(*) FROM baseline b WHERE b.root = r.root) AS n
                   FROM roots r WHERE r.root = ?""",
                (root,),
            ).fetchone()
        if row is None:
            return None
        return RootInfo(row["root"], row["algorithm"], tuple(json.loads(row["excludes"])),
                        row["created_at"], row["n"])

    def list_roots(self) -> List[RootInfo]:
        with self._lock:
            names = [r[0] for r in self._conn.execute("SELECT root FROM roots ORDER BY root")]
        return [info for info in (self.get_root(n) for n in names) if info is not None]

    # ------------------------------------------------------------- baseline
    def create_baseline(
        self,
        root: str,
        algorithm: str,
        excludes: Iterable[str],
        records: Iterable[FileRecord],
        *,
        force: bool = False,
    ) -> int:
        """Store a fresh baseline for ``root``. Returns the number of files saved."""
        rows = [(root, r.path, r.hash, r.size, r.mtime) for r in records]
        with self._lock, self._conn:
            exists = self._conn.execute("SELECT 1 FROM roots WHERE root = ?", (root,)).fetchone()
            if exists and not force:
                raise BaselineExistsError(
                    f"A baseline for '{root}' already exists. Use --force to rebuild it."
                )
            self._conn.execute("DELETE FROM baseline WHERE root = ?", (root,))
            self._conn.execute(
                """INSERT INTO roots (root, algorithm, excludes, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(root) DO UPDATE SET
                       algorithm = excluded.algorithm,
                       excludes = excluded.excludes,
                       created_at = excluded.created_at""",
                (root, algorithm, json.dumps(sorted(set(excludes))), now_iso()),
            )
            self._conn.executemany(
                "INSERT INTO baseline (root, path, hash, size, mtime) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def get_baseline(self, root: str) -> Dict[str, FileRecord]:
        with self._lock:
            cursor = self._conn.execute(
                "SELECT path, hash, size, mtime FROM baseline WHERE root = ?", (root,)
            )
            return {
                row["path"]: FileRecord(row["path"], row["hash"], row["size"], row["mtime"])
                for row in cursor
            }

    # --------------------------------------------------------------- events
    def log_events(self, root: str, alerts: Iterable[Alert]) -> None:
        rows = [
            (a.timestamp, root, a.path, a.event_type.value, a.old_hash, a.new_hash, a.detail)
            for a in alerts
        ]
        if not rows:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                """INSERT INTO events (timestamp, root, path, event_type, old_hash, new_hash, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def log_event(self, root: str, alert: Alert) -> None:
        self.log_events(root, [alert])

    def get_events(self, root: Optional[str] = None, limit: int = 50) -> List[Tuple[str, Alert]]:
        """Most recent events first, as ``(root, Alert)`` pairs."""
        query = "SELECT * FROM events"
        params: list = []
        if root is not None:
            query += " WHERE root = ?"
            params.append(root)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, int(limit)))
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            (
                row["root"],
                Alert(EventType(row["event_type"]), row["path"], row["timestamp"],
                      row["old_hash"], row["new_hash"], row["detail"]),
            )
            for row in rows
        ]
