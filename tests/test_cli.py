import json

from fim.cli import EXIT_CHANGES, EXIT_ERROR, EXIT_OK, main


def run(*args):
    return main([*map(str, args), "--no-color"])


def test_init_then_clean_scan(protected, tmp_path, capsys):
    db = tmp_path / "cli.db"
    assert run("init", protected, "--db", db) == EXIT_OK
    assert run("scan", protected, "--db", db) == EXIT_OK
    assert "Integrity OK: 3 file(s)" in capsys.readouterr().out


def test_scan_detects_tampering_with_json(protected, tmp_path, capsys):
    db = tmp_path / "cli.db"
    run("init", protected, "--db", db)
    (protected / "index.html").write_text("pwned", encoding="utf-8")
    capsys.readouterr()
    assert main(["scan", str(protected), "--db", str(db), "--json"]) == EXIT_CHANGES
    report = json.loads(capsys.readouterr().out)
    assert report["modified"] == ["index.html"]
    assert report["clean"] is False


def test_init_twice_needs_force(protected, tmp_path):
    db = tmp_path / "cli.db"
    assert run("init", protected, "--db", db) == EXIT_OK
    assert run("init", protected, "--db", db) == EXIT_ERROR
    assert run("init", protected, "--db", db, "--force") == EXIT_OK


def test_scan_without_baseline_is_error(protected, tmp_path, capsys):
    assert run("scan", protected, "--db", tmp_path / "empty.db") == EXIT_ERROR
    assert "No baseline found" in capsys.readouterr().out


def test_missing_directory_is_error(tmp_path):
    assert run("init", tmp_path / "missing", "--db", tmp_path / "x.db") == EXIT_ERROR


def test_db_inside_protected_dir_is_ignored(protected, capsys):
    db = protected / "fim.db"
    assert run("init", protected, "--db", db) == EXIT_OK
    assert run("scan", protected, "--db", db) == EXIT_OK


def test_events_and_status(protected, tmp_path, capsys):
    db = tmp_path / "cli.db"
    run("init", protected, "--db", db)
    (protected / "notes.txt").unlink()
    run("scan", protected, "--db", db)
    capsys.readouterr()
    assert main(["events", "--db", str(db), "--json"]) == EXIT_OK
    events = json.loads(capsys.readouterr().out)
    assert events[0]["event"] == "DELETED" and events[0]["path"] == "notes.txt"
    assert run("status", "--db", db) == EXIT_OK
