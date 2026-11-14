from fim.scanner import FileScanner, compare, is_excluded


def test_snapshot_lists_all_files(protected):
    snap = FileScanner(protected).snapshot()
    assert sorted(snap) == ["config/app.ini", "index.html", "notes.txt"]
    assert all(len(r.hash) == 64 for r in snap.values())


def test_exclude_patterns(protected):
    (protected / ".git").mkdir()
    (protected / ".git" / "HEAD").write_text("ref", encoding="utf-8")
    (protected / "debug.log").write_text("x", encoding="utf-8")
    (protected / "notes.txt.swp").write_text("x", encoding="utf-8")  # default exclude
    snap = FileScanner(protected, excludes=[".git", "*.log"]).snapshot()
    assert sorted(snap) == ["config/app.ini", "index.html", "notes.txt"]


def test_is_excluded_matches_components_and_paths():
    assert is_excluded("a/node_modules/x.js", ["node_modules"])
    assert is_excluded("logs/2024/app.log", ["logs/*"])
    assert is_excluded("dir/file.tmp", ["*.tmp"])
    assert not is_excluded("src/app.py", ["*.tmp", "build"])


def test_ignore_paths_skips_database(protected):
    db_file = protected / "fim.db"
    db_file.write_bytes(b"sqlite")
    snap = FileScanner(protected, ignore_paths=[db_file]).snapshot()
    assert "fim.db" not in snap


def test_compare_detects_all_change_types(protected):
    scanner = FileScanner(protected)
    before = scanner.snapshot()
    (protected / "index.html").write_text("<h1>hacked</h1>", encoding="utf-8")
    (protected / "notes.txt").unlink()
    (protected / "shell.php").write_text("<?php ?>", encoding="utf-8")
    result = compare(before, scanner.snapshot())
    assert result.modified == ["index.html"]
    assert result.deleted == ["notes.txt"]
    assert result.added == ["shell.php"]
    assert result.has_changes and result.total == 3


def test_relative_rejects_outside_paths(protected, tmp_path):
    scanner = FileScanner(protected)
    assert scanner.relative(protected / "config" / "app.ini") == "config/app.ini"
    assert scanner.relative(tmp_path / "elsewhere.txt") is None
    assert scanner.relative(protected) is None
