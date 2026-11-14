from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from fim.database import IntegrityDB
from fim.models import Alert


class CollectingReporter:
    """Test double that records every alert/message instead of printing."""

    def __init__(self) -> None:
        self.alerts: List[Alert] = []
        self.messages: List[str] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def warning(self, message: str) -> None:
        self.messages.append(message)

    info = success = error = warning

    def types(self) -> List[str]:
        return [a.event_type.value for a in self.alerts]


@pytest.fixture
def reporter() -> CollectingReporter:
    return CollectingReporter()


@pytest.fixture
def protected(tmp_path: Path) -> Path:
    """A small directory tree to monitor."""
    root = tmp_path / "protected"
    (root / "config").mkdir(parents=True)
    (root / "index.html").write_text("<h1>hello</h1>", encoding="utf-8")
    (root / "config" / "app.ini").write_text("debug=false\n", encoding="utf-8")
    (root / "notes.txt").write_text("v1", encoding="utf-8")
    return root


@pytest.fixture
def db(tmp_path: Path):
    database = IntegrityDB(tmp_path / "fim.db")
    yield database
    database.close()
