"""Command-line interface: ``fim init | scan | watch | events``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .database import DatabaseError, IntegrityDB
from .hasher import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
from .models import EventType
from .reporter import ConsoleReporter, FileLogReporter, MultiReporter
from .scanner import FileScanner, compare, result_to_alerts

DEFAULT_DB = "fim.db"

EXIT_OK = 0
EXIT_CHANGES = 1  # `scan` found integrity violations
EXIT_ERROR = 2


class CLIError(Exception):
    """A user-facing error that should be printed without a traceback."""


# --------------------------------------------------------------------- utils
def _resolve_dir(path: str) -> Path:
    directory = Path(path).expanduser().resolve()
    if not directory.exists():
        raise CLIError(f"Directory not found: {directory}")
    if not directory.is_dir():
        raise CLIError(f"Not a directory: {directory}")
    return directory


def _open_db(path: str) -> IntegrityDB:
    try:
        return IntegrityDB(path)
    except DatabaseError as exc:
        raise CLIError(str(exc)) from exc


def _build_scanner(directory: Path, db: IntegrityDB, algorithm: str, excludes: Sequence[str],
                   extra_ignores: Sequence[str] = ()) -> FileScanner:
    return FileScanner(directory, algorithm, excludes,
                       ignore_paths=[*db.sidecar_paths, *extra_ignores])


def _require_baseline(db: IntegrityDB, directory: Path):
    info = db.get_root(str(directory))
    if info is None:
        raise CLIError(
            f"No baseline found for {directory}.\n"
            f"    Create one first:  python -m fim init \"{directory}\" --db \"{db.path}\""
        )
    return info


# ------------------------------------------------------------------ commands
def cmd_init(args: argparse.Namespace, out: ConsoleReporter) -> int:
    directory = _resolve_dir(args.path)
    with _open_db(args.db) as db:
        scanner = _build_scanner(directory, db, args.algorithm, args.exclude)
        out.info(f"Hashing files in {directory} using {scanner.algorithm.upper()} ...")
        started = time.perf_counter()
        records = scanner.snapshot(
            on_error=lambda rel, exc: out.warning(f"Skipped unreadable file {rel}: {exc}")
        )
        try:
            count = db.create_baseline(str(directory), scanner.algorithm, args.exclude,
                                       records.values(), force=args.force)
        except DatabaseError as exc:
            raise CLIError(str(exc)) from exc
        elapsed = time.perf_counter() - started
        out.success(f"Baseline saved: {count} file(s) in {elapsed:.2f}s -> {db.path}")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace, out: ConsoleReporter) -> int:
    directory = _resolve_dir(args.path)
    with _open_db(args.db) as db:
        info = _require_baseline(db, directory)
        excludes = [*info.excludes, *args.exclude]
        scanner = _build_scanner(directory, db, info.algorithm, excludes)
        baseline = db.get_baseline(info.root)
        errors: List[str] = []
        current = scanner.snapshot(on_error=lambda rel, exc: errors.append(f"{rel}: {exc}"))
        result = compare(baseline, current)
        alerts = result_to_alerts(result, baseline, current)
        db.log_events(info.root, alerts)

    if args.json:
        print(json.dumps({
            "root": info.root,
            "algorithm": info.algorithm,
            "files_checked": len(current),
            "added": result.added,
            "modified": result.modified,
            "deleted": result.deleted,
            "errors": errors,
            "clean": not result.has_changes,
        }, indent=2))
    else:
        for message in errors:
            out.warning(f"Skipped unreadable file {message}")
        for alert in alerts:
            out.emit(alert)
        if result.has_changes:
            out.error(
                f"Integrity check FAILED: {len(result.modified)} modified, "
                f"{len(result.deleted)} deleted, {len(result.added)} new "
                f"({len(current)} files checked)"
            )
        else:
            out.success(f"Integrity OK: {len(current)} file(s) match the baseline")
    return EXIT_CHANGES if result.has_changes else EXIT_OK


def cmd_watch(args: argparse.Namespace, out: ConsoleReporter) -> int:
    from .monitor import IntegrityMonitor  # imported lazily: watchdog only needed here

    directory = _resolve_dir(args.path)
    if args.init:
        with _open_db(args.db) as db:
            missing = db.get_root(str(directory)) is None
        if missing:
            out.info("No baseline yet, creating one (--init) ...")
            cmd_init(argparse.Namespace(path=args.path, db=args.db, exclude=args.exclude,
                                        algorithm=args.algorithm, force=False), out)

    with _open_db(args.db) as db:
        info = _require_baseline(db, directory)
        excludes = [*info.excludes, *args.exclude]
        log_reporter = FileLogReporter(args.log_file) if args.log_file else None
        extra_ignores = [log_reporter.path] if log_reporter else []
        scanner = _build_scanner(directory, db, info.algorithm, excludes, extra_ignores)
        reporter = MultiReporter(out, log_reporter)
        monitor = IntegrityMonitor(scanner, db, reporter, debounce=args.debounce)

        out.banner("File Integrity Monitor", [
            ("Directory", str(directory)),
            ("Baseline", f"{info.file_count} file(s), {info.algorithm.upper()}, created {info.created_at}"),
            ("Database", str(db.path)),
            ("Log file", log_reporter.path if log_reporter else "-"),
            ("Excludes", ", ".join(scanner.excludes)),
        ])

        def ready(changes: int) -> None:
            if args.no_initial_scan:
                out.info("Initial scan skipped.")
            elif changes:
                out.warning(f"Initial scan found {changes} change(s) since the baseline.")
            else:
                out.success("Initial scan clean: all files match the baseline.")
            out.info("Watching for changes in real time... press Ctrl+C to stop.")

        try:
            monitor.run_forever(initial_scan=not args.no_initial_scan, on_ready=ready)
        finally:
            if log_reporter:
                log_reporter.close()

        summary = ", ".join(f"{e.value.lower()}={monitor.stats[e]}" for e in EventType if monitor.stats[e])
        print()
        out.info(f"Monitor stopped. Alerts this session: {summary or 'none'}")
    return EXIT_OK


def cmd_events(args: argparse.Namespace, out: ConsoleReporter) -> int:
    with _open_db(args.db) as db:
        root = str(_resolve_dir(args.path)) if args.path else None
        events = db.get_events(root, args.limit)
    if args.json:
        print(json.dumps([
            {"root": r, "timestamp": a.timestamp, "event": a.event_type.value,
             "severity": a.severity.value, "path": a.path, "old_hash": a.old_hash,
             "new_hash": a.new_hash, "detail": a.detail}
            for r, a in events
        ], indent=2))
        return EXIT_OK
    if not events:
        out.info("No events recorded yet.")
        return EXIT_OK
    for _, alert in reversed(events):  # oldest first, like a log
        out.emit(alert)
    out.info(f"Showing {len(events)} most recent event(s).")
    return EXIT_OK


def cmd_status(args: argparse.Namespace, out: ConsoleReporter) -> int:
    with _open_db(args.db) as db:
        roots = db.list_roots()
    if not roots:
        out.info(f"No baselines in {Path(args.db).resolve()}")
        return EXIT_OK
    for info in roots:
        out.banner(info.root, [
            ("Files", info.file_count),
            ("Algorithm", info.algorithm.upper()),
            ("Created", info.created_at),
            ("Excludes", ", ".join(info.excludes) or "-"),
        ])
    return EXIT_OK


# -------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor - detect tampering using cryptographic "
                    "hash baselines and real-time file-system alerts.",
        epilog="Example:  python -m fim init ./site   then   python -m fim watch ./site",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    display = argparse.ArgumentParser(add_help=False)
    display.add_argument("--no-color", action="store_true", help="disable colored output")
    display.add_argument("--db", default=DEFAULT_DB,
                         help=f"SQLite database file (default: ./{DEFAULT_DB})")

    target = argparse.ArgumentParser(add_help=False)
    target.add_argument("path", help="directory to protect")
    target.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB",
                        help="glob to ignore, repeatable (e.g. -e '*.log' -e .git)")

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    p = sub.add_parser("init", parents=[target, display], help="create the trusted baseline")
    p.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM, choices=SUPPORTED_ALGORITHMS,
                   help=f"hash algorithm (default: {DEFAULT_ALGORITHM})")
    p.add_argument("-f", "--force", action="store_true",
                   help="overwrite an existing baseline (accept current state as trusted)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", parents=[target, display],
                       help="one-shot integrity check (exit code 1 if changes found)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("watch", parents=[target, display], help="monitor in real time")
    p.add_argument("--debounce", type=float, default=0.5, metavar="SEC",
                   help="wait this long after the last event before hashing (default: 0.5)")
    p.add_argument("--log-file", metavar="FILE", help="also append alerts to this log file")
    p.add_argument("--no-initial-scan", action="store_true",
                   help="skip checking for changes made while the monitor was off")
    p.add_argument("--init", action="store_true", help="create the baseline if it does not exist")
    p.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM, choices=SUPPORTED_ALGORITHMS,
                   help="hash algorithm used with --init")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("events", parents=[display], help="show the alert history")
    p.add_argument("path", nargs="?", help="only show events for this directory")
    p.add_argument("-n", "--limit", type=int, default=50, help="number of events (default: 50)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("status", parents=[display], help="list baselines stored in the database")
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out = ConsoleReporter(use_color=False if args.no_color else None)
    try:
        return args.func(args, out)
    except CLIError as exc:
        out.error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
