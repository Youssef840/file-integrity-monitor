"""Monitor tests: deterministic logic tests + a real watchdog end-to-end test."""

import time

import pytest

from fim.monitor import Debouncer, IntegrityMonitor
from fim.scanner import FileScanner


def make_monitor(protected, db, reporter, **kwargs):
    scanner = FileScanner(protected, ignore_paths=db.sidecar_paths)
    db.create_baseline(str(scanner.root), scanner.algorithm, [], scanner.snapshot().values(),
                       force=True)
    return IntegrityMonitor(scanner, db, reporter, **kwargs)


def test_modify_then_restore(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    target = protected / "index.html"
    original = target.read_text(encoding="utf-8")

    target.write_text("<h1>defaced</h1>", encoding="utf-8")
    assert mon.check_path("index.html").event_type.value == "MODIFIED"
    assert mon.check_path("index.html") is None  # duplicate event -> no second alert

    target.write_text(original, encoding="utf-8")
    assert mon.check_path("index.html").event_type.value == "RESTORED"
    assert reporter.types() == ["MODIFIED", "RESTORED"]


def test_create_modify_delete_untracked_file(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    # Benign content on purpose: real webshell strings get quarantined by antivirus.
    new = protected / "upload.php"
    new.write_text("first version", encoding="utf-8")
    mon.check_path("upload.php")
    new.write_text("second version", encoding="utf-8")
    mon.check_path("upload.php")
    new.unlink()
    mon.check_path("upload.php")
    assert reporter.types() == ["CREATED", "MODIFIED", "DELETED"]
    assert reporter.alerts[2].detail == "untracked file deleted"


def test_baseline_file_deleted(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    (protected / "notes.txt").unlink()
    alert = mon.check_path("notes.txt")
    assert alert.event_type.value == "DELETED"
    assert alert.old_hash is not None


def test_directory_removal_reports_children(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    for f in (protected / "config").iterdir():
        f.unlink()
    (protected / "config").rmdir()
    mon.schedule_path(str(protected / "config"), include_children=True)
    assert reporter.types() == ["DELETED"]
    assert reporter.alerts[0].path == "config/app.ini"


def test_move_reports_single_moved_event(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    (protected / "notes.txt").rename(protected / "renamed.txt")
    mon.handle_move(str(protected / "notes.txt"), str(protected / "renamed.txt"), False)
    assert reporter.types() == ["MOVED"]
    assert reporter.alerts[0].path == "notes.txt -> renamed.txt"


def test_atomic_save_from_temp_file_is_modified(protected, db, reporter):
    """Editors write `file.swp`/temp then rename it over the original."""
    mon = make_monitor(protected, db, reporter)
    tmp = protected / "index.html.swp"
    tmp.write_text("<h1>new</h1>", encoding="utf-8")
    tmp.replace(protected / "index.html")
    mon.handle_move(str(tmp), str(protected / "index.html"), False)
    assert reporter.types() == ["MODIFIED"]


def test_initial_scan_catches_offline_changes(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    (protected / "notes.txt").write_text("changed while offline", encoding="utf-8")
    (protected / "new.txt").write_text("x", encoding="utf-8")
    assert mon.initial_scan() == 2
    assert sorted(reporter.types()) == ["CREATED", "MODIFIED"]


def test_alerts_are_persisted(protected, db, reporter):
    mon = make_monitor(protected, db, reporter)
    (protected / "notes.txt").write_text("v2", encoding="utf-8")
    mon.check_path("notes.txt")
    events = db.get_events(mon.root_key)
    assert events[0][1].event_type.value == "MODIFIED"


def test_debouncer_collapses_bursts():
    calls = []
    deb = Debouncer(0.2, lambda key, moved: calls.append(key))
    for _ in range(10):
        deb.submit("a")
    deb.submit("b")
    time.sleep(0.6)
    deb.stop()
    assert sorted(calls) == ["a", "b"]


def test_debouncer_flushes_on_stop():
    calls = []
    deb = Debouncer(10, lambda key, moved: calls.append(key))
    deb.submit("late")
    deb.stop()
    assert calls == ["late"]


def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@pytest.mark.integration
def test_real_time_watchdog_end_to_end(protected, db, reporter):
    mon = make_monitor(protected, db, reporter, debounce=0.2)
    mon.start()
    try:
        time.sleep(0.5)  # let the OS watcher settle
        (protected / "config" / "app.ini").write_text("debug=true\n", encoding="utf-8")
        assert wait_for(lambda: "MODIFIED" in reporter.types()), reporter.types()

        (protected / "dropper.exe").write_bytes(b"MZ")
        assert wait_for(lambda: "CREATED" in reporter.types()), reporter.types()

        (protected / "notes.txt").unlink()
        assert wait_for(lambda: "DELETED" in reporter.types()), reporter.types()
    finally:
        mon.stop()
