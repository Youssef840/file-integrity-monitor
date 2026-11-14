"""Real-time integrity monitoring built on :mod:`watchdog`.

Design notes
------------
* Watchdog callbacks run on the observer thread. They only *schedule* work;
  hashing happens on a single worker thread after a short debounce, so a
  file that is being written in several chunks raises one alert, not five.
* Every path has a "last known hash". A check only alerts when the state
  actually changed, which makes duplicate OS events harmless.
* The trusted baseline is never modified while watching: an alert stays
  meaningful until an operator re-approves the state with ``fim init --force``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from typing import Callable, Dict, Optional, Protocol, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .database import IntegrityDB
from .hasher import HashError, hash_file
from .models import Alert, EventType, now_iso
from .scanner import FileScanner, compare

logger = logging.getLogger(__name__)

class Reporter(Protocol):
    def emit(self, alert: Alert) -> None: ...
    def warning(self, message: str) -> None: ...


class Debouncer:
    """Collapses bursts of events per key and runs ``callback`` once per key."""

    def __init__(self, delay: float, callback: Callable[[str, bool], None]) -> None:
        self.delay = max(0.0, delay)
        self._callback = callback
        self._pending: Dict[str, tuple] = {}  # key -> (deadline, moved_flag)
        self._cond = threading.Condition()
        self._stopped = False
        self._thread = threading.Thread(target=self._run, name="fim-debouncer", daemon=True)
        self._thread.start()

    def submit(self, key: str, moved: bool = False) -> None:
        with self._cond:
            previous = self._pending.get(key)
            moved = moved or (previous[1] if previous else False)
            self._pending[key] = (time.monotonic() + self.delay, moved)
            self._cond.notify()

    def _take_due(self, flush: bool = False) -> list:
        now = time.monotonic()
        due = [(k, m) for k, (deadline, m) in self._pending.items() if flush or deadline <= now]
        for key, _ in due:
            del self._pending[key]
        return due

    def _run(self) -> None:
        while True:
            with self._cond:
                while True:
                    if self._stopped:
                        due, stopping = self._take_due(flush=True), True
                        break
                    due, stopping = self._take_due(), False
                    if due:
                        break
                    if self._pending:
                        next_deadline = min(d for d, _ in self._pending.values())
                        self._cond.wait(max(0.01, next_deadline - time.monotonic()))
                    else:
                        self._cond.wait()
            for key, moved in sorted(due):
                try:
                    self._callback(key, moved)
                except Exception:  # never let one bad file kill the worker
                    logger.exception("Unhandled error while checking %s", key)
            if stopping:
                return

    def stop(self, timeout: float = 5.0) -> None:
        """Process everything still pending, then stop the worker."""
        with self._cond:
            self._stopped = True
            self._cond.notify_all()
        self._thread.join(timeout)


class _WatchdogHandler(FileSystemEventHandler):
    """Translates raw watchdog events into monitor actions."""

    def __init__(self, monitor: IntegrityMonitor) -> None:
        super().__init__()
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        self.monitor.schedule_path(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:  # directory mtime changes are noise
            self.monitor.schedule_path(event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.monitor.schedule_path(event.src_path, include_children=True)

    def on_moved(self, event: FileSystemEvent) -> None:
        self.monitor.handle_move(event.src_path, event.dest_path, event.is_directory)


class IntegrityMonitor:
    """Compares live file-system activity against the stored baseline."""

    def __init__(
        self,
        scanner: FileScanner,
        db: IntegrityDB,
        reporter: Reporter,
        *,
        debounce: float = 0.5,
        observer_factory: Callable[[], object] = Observer,
    ) -> None:
        self.scanner = scanner
        self.db = db
        self.reporter = reporter
        self.root_key = str(scanner.root)
        self.baseline = db.get_baseline(self.root_key)
        self.stats: Counter = Counter()
        self._known: Dict[str, Optional[str]] = {}  # path -> last observed hash (None = absent)
        self._lock = threading.RLock()  # protects _known
        self._check_lock = threading.RLock()  # serializes check_path()
        self._debounce = debounce
        self._observer_factory = observer_factory
        self._observer = None
        self._debouncer: Optional[Debouncer] = None

    # ------------------------------------------------------------ helpers
    def _last_known(self, rel: str) -> Optional[str]:
        if rel in self._known:
            return self._known[rel]
        base = self.baseline.get(rel)
        return base.hash if base else None

    def tracked_paths(self) -> Set[str]:
        """Every path we currently believe exists (baseline + newly seen)."""
        with self._lock:
            present = {p for p in self.baseline if self._last_known(p) is not None}
            present |= {p for p, h in self._known.items() if h is not None}
            return present

    def _emit(self, alert: Alert) -> None:
        self.stats[alert.event_type] += 1
        self.reporter.emit(alert)
        try:
            self.db.log_event(self.root_key, alert)
        except Exception as exc:  # pragma: no cover - logging must not stop monitoring
            self.reporter.warning(f"Could not write event to database: {exc}")

    # -------------------------------------------------------- core logic
    def check_path(self, rel: str, moved: bool = False) -> Optional[Alert]:
        """Re-hash ``rel`` and raise an alert if its state changed.

        Safe to call any number of times for the same path, from any thread.
        """
        with self._check_lock:  # hash+compare must be atomic per check
            return self._check_path_locked(rel, moved)

    def _check_path_locked(self, rel: str, moved: bool) -> Optional[Alert]:
        absolute = self.scanner.absolute(rel)
        if absolute.is_dir():
            for child in self.scanner.iter_files(rel):
                self.check_path(child, moved=moved)
            return None

        try:
            current = hash_file(absolute, self.scanner.algorithm)
        except HashError as exc:
            self.reporter.warning(f"Skipping unreadable file {rel}: {exc}")
            return None

        with self._lock:
            base = self.baseline.get(rel)
            base_hash = base.hash if base else None
            previous = self._last_known(rel)
            if current == previous:
                return None  # duplicate event / nothing new
            self._known[rel] = current

        ts = now_iso()
        if current is None:
            detail = "baseline file deleted" if base_hash else "untracked file deleted"
            alert = Alert(EventType.DELETED, rel, ts, previous, None, detail)
        elif base_hash is None:
            if previous is None:
                if moved:
                    return None  # already reported as MOVED
                alert = Alert(EventType.CREATED, rel, ts, None, current, "file not in baseline")
            else:
                alert = Alert(EventType.MODIFIED, rel, ts, previous, current,
                              "untracked file changed")
        elif current == base_hash:
            alert = Alert(EventType.RESTORED, rel, ts, previous, current,
                          "content matches baseline again")
        else:
            alert = Alert(EventType.MODIFIED, rel, ts, base_hash, current,
                          "content differs from baseline")

        self._emit(alert)
        return alert

    def initial_scan(self) -> int:
        """Detect changes that happened while the monitor was not running."""
        current = self.scanner.snapshot(
            on_error=lambda rel, exc: self.reporter.warning(f"Skipping unreadable file {rel}: {exc}")
        )
        result = compare(self.baseline, current)
        changes = 0
        for rel in result.changed_paths():
            if self.check_path(rel) is not None:
                changes += 1
        return changes

    # ----------------------------------------------- watchdog integration
    def _safe_check(self, rel: str, moved: bool) -> None:
        try:
            self.check_path(rel, moved)
        except Exception as exc:
            self.reporter.warning(f"Error while checking {rel}: {exc}")

    def _schedule(self, rel: str, moved: bool = False) -> None:
        if self._debouncer is None:
            self.check_path(rel, moved)
        else:
            self._debouncer.submit(rel, moved)

    def schedule_path(self, path: str, include_children: bool = False) -> None:
        if self.scanner.should_ignore(path):
            return
        rel = self.scanner.relative(path)
        if rel is None:
            return
        self._schedule(rel)
        if include_children:  # a whole directory may have been removed
            prefix = rel + "/"
            for tracked in self.tracked_paths():
                if tracked.startswith(prefix):
                    self._schedule(tracked)

    def handle_move(self, src: str, dest: str, is_directory: bool) -> None:
        src_ignored = self.scanner.should_ignore(src)
        dest_ignored = self.scanner.should_ignore(dest)
        src_rel = self.scanner.relative(src)
        dest_rel = self.scanner.relative(dest)

        if is_directory:
            if src_rel and not src_ignored:
                self.schedule_path(src, include_children=True)
            if dest_rel and not dest_ignored:
                self._schedule(dest_rel)
            return

        # Atomic "save": editor writes a temp file then renames it over the original.
        if src_ignored or src_rel is None:
            if dest_rel and not dest_ignored:
                self._schedule(dest_rel)
            return
        if dest_ignored or dest_rel is None:
            self._schedule(src_rel)  # behaves like a deletion
            return

        with self._lock:
            previous = self._last_known(src_rel)
            if previous is None:
                # We never saw the source; just evaluate the destination.
                self._schedule(dest_rel)
                return
            self._known[src_rel] = None
        self._emit(Alert(EventType.MOVED, f"{src_rel} -> {dest_rel}", now_iso(), previous, None,
                         "file renamed/moved"))
        self._schedule(dest_rel, moved=True)

    # --------------------------------------------------------- lifecycle
    def start(self, initial_scan: bool = True) -> int:
        """Start watching. Returns the number of changes found by the initial scan."""
        self._debouncer = Debouncer(self._debounce, self._safe_check)
        self._observer = self._observer_factory()
        self._observer.schedule(_WatchdogHandler(self), str(self.scanner.root), recursive=True)
        self._observer.start()  # start first so nothing is missed during the scan
        return self.initial_scan() if initial_scan else 0

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._debouncer is not None:
            self._debouncer.stop()
            self._debouncer = None

    def run_forever(self, initial_scan: bool = True, on_ready: Optional[Callable[[int], None]] = None) -> None:
        """Block until Ctrl+C."""
        try:
            changes = self.start(initial_scan=initial_scan)
            if on_ready:
                on_ready(changes)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
