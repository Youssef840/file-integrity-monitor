"""Core data structures shared across the package."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    """Kinds of integrity events the monitor can raise."""

    CREATED = "CREATED"  # a file that is not part of the baseline appeared
    MODIFIED = "MODIFIED"  # content no longer matches the baseline hash
    DELETED = "DELETED"  # a file disappeared
    MOVED = "MOVED"  # a file was renamed / moved inside the monitored tree
    RESTORED = "RESTORED"  # a changed file matches its baseline hash again

    @property
    def severity(self) -> Severity:
        return _SEVERITY[self]


_SEVERITY = {
    EventType.CREATED: Severity.WARNING,
    EventType.MODIFIED: Severity.CRITICAL,
    EventType.DELETED: Severity.CRITICAL,
    EventType.MOVED: Severity.WARNING,
    EventType.RESTORED: Severity.INFO,
}


def now_iso() -> str:
    """Current local time as an ISO-8601 string with UTC offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass(frozen=True)
class FileRecord:
    """Hash and metadata of a single file, relative to the monitored root."""

    path: str  # POSIX-style path relative to the root, e.g. "conf/app.ini"
    hash: str
    size: int
    mtime: float


@dataclass(frozen=True)
class RootInfo:
    """A monitored directory registered in the database."""

    root: str
    algorithm: str
    excludes: Tuple[str, ...]
    created_at: str
    file_count: int


@dataclass(frozen=True)
class Alert:
    """A single integrity event."""

    event_type: EventType
    path: str
    timestamp: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    detail: Optional[str] = None

    @property
    def severity(self) -> Severity:
        return self.event_type.severity
