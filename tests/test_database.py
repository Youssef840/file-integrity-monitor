import pytest

from fim.database import BaselineExistsError, IntegrityDB
from fim.models import Alert, EventType, FileRecord, now_iso

ROOT = "/srv/www"
RECORDS = [FileRecord("a.txt", "aa" * 32, 1, 1.0), FileRecord("b/c.txt", "bb" * 32, 2, 2.0)]


def test_create_and_read_baseline(db):
    assert db.create_baseline(ROOT, "sha256", ["*.log"], RECORDS) == 2
    info = db.get_root(ROOT)
    assert info.algorithm == "sha256"
    assert info.excludes == ("*.log",)
    assert info.file_count == 2
    assert db.get_baseline(ROOT)["b/c.txt"].hash == "bb" * 32


def test_existing_baseline_requires_force(db):
    db.create_baseline(ROOT, "sha256", [], RECORDS)
    with pytest.raises(BaselineExistsError):
        db.create_baseline(ROOT, "sha256", [], RECORDS)
    db.create_baseline(ROOT, "sha512", [], RECORDS[:1], force=True)
    assert db.get_root(ROOT).algorithm == "sha512"
    assert list(db.get_baseline(ROOT)) == ["a.txt"]


def test_roots_are_isolated(db):
    db.create_baseline(ROOT, "sha256", [], RECORDS)
    db.create_baseline("/etc", "sha256", [], RECORDS[:1])
    assert len(db.get_baseline(ROOT)) == 2
    assert len(db.get_baseline("/etc")) == 1
    assert [r.root for r in db.list_roots()] == ["/etc", ROOT]


def test_event_log_newest_first(db):
    db.log_event(ROOT, Alert(EventType.CREATED, "x", now_iso()))
    db.log_event(ROOT, Alert(EventType.MODIFIED, "y", now_iso(), "old", "new", "changed"))
    db.log_event("/other", Alert(EventType.DELETED, "z", now_iso()))
    events = db.get_events(ROOT)
    assert [a.path for _, a in events] == ["y", "x"]
    assert events[0][1].old_hash == "old"
    assert len(db.get_events(limit=10)) == 3


def test_persists_across_connections(tmp_path):
    path = tmp_path / "persist.db"
    with IntegrityDB(path) as first:
        first.create_baseline(ROOT, "sha256", [], RECORDS)
    with IntegrityDB(path) as second:
        assert second.get_root(ROOT).file_count == 2
