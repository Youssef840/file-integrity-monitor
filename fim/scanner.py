"""Directory walking, exclusion rules and baseline comparison."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Mapping, Optional

from .hasher import DEFAULT_ALGORITHM, HashError, hash_file, validate_algorithm
from .models import Alert, EventType, FileRecord, now_iso

# Temporary/lock files created by common editors. They change constantly and
# would only produce noise. Users can add more with ``--exclude``.
DEFAULT_EXCLUDES = (
    "*.swp",  # vim
    "*.swx",  # vim
    "*~",  # emacs / gedit backups
    ".~lock.*#",  # LibreOffice
    "~$*",  # Microsoft Office owner files
)


def is_excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    """Check a POSIX relative path against glob ``patterns``.

    A pattern matches when it matches the full relative path
    (``logs/*.log``), the file name (``*.tmp``) or any directory component
    (``.git`` or ``node_modules``).
    """
    parts = rel_path.split("/")
    for pattern in patterns:
        pattern = pattern.strip().replace("\\", "/").rstrip("/")
        if not pattern:
            continue
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


@dataclass
class ScanResult:
    """Differences between a baseline and the current state of the tree."""

    added: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.modified) + len(self.deleted)

    def changed_paths(self) -> List[str]:
        return sorted(set(self.added) | set(self.modified) | set(self.deleted))


def compare(baseline: Mapping[str, FileRecord], current: Mapping[str, FileRecord]) -> ScanResult:
    """Compute what was added, modified or deleted relative to the baseline."""
    base_keys, cur_keys = set(baseline), set(current)
    return ScanResult(
        added=sorted(cur_keys - base_keys),
        modified=sorted(p for p in base_keys & cur_keys if baseline[p].hash != current[p].hash),
        deleted=sorted(base_keys - cur_keys),
    )


def result_to_alerts(
    result: ScanResult,
    baseline: Mapping[str, FileRecord],
    current: Mapping[str, FileRecord],
) -> List[Alert]:
    """Turn a :class:`ScanResult` into alerts suitable for reporting/logging."""
    ts = now_iso()
    alerts: List[Alert] = []
    for path in result.modified:
        alerts.append(
            Alert(EventType.MODIFIED, path, ts, baseline[path].hash, current[path].hash,
                  "content differs from baseline")
        )
    for path in result.deleted:
        alerts.append(Alert(EventType.DELETED, path, ts, baseline[path].hash, None,
                            "baseline file is missing"))
    for path in result.added:
        alerts.append(Alert(EventType.CREATED, path, ts, None, current[path].hash,
                            "file not in baseline"))
    return alerts


class FileScanner:
    """Walks a directory tree and hashes the files that are not excluded."""

    def __init__(
        self,
        root: os.PathLike | str,
        algorithm: str = DEFAULT_ALGORITHM,
        excludes: Iterable[str] = (),
        ignore_paths: Iterable[os.PathLike | str] = (),
    ) -> None:
        self.root = Path(root).resolve()
        self.algorithm = validate_algorithm(algorithm)
        self.excludes = tuple(dict.fromkeys([*DEFAULT_EXCLUDES, *excludes]))
        # Absolute paths that must never be monitored (our own DB / log file).
        self._ignored = {os.path.normcase(os.path.abspath(p)) for p in ignore_paths}

    # ------------------------------------------------------------------ paths
    def relative(self, path: os.PathLike | str) -> Optional[str]:
        """Path relative to the root in POSIX form, or ``None`` if outside it."""
        try:
            rel = os.path.relpath(os.fsdecode(path), self.root)
        except ValueError:  # different drive on Windows
            return None
        if rel == "." or rel == ".." or rel.startswith(".." + os.sep):
            return None
        return Path(rel).as_posix()

    def absolute(self, rel_path: str) -> Path:
        return self.root.joinpath(*rel_path.split("/"))

    def should_ignore(self, path: os.PathLike | str) -> bool:
        absolute = os.path.abspath(os.fsdecode(path))
        if os.path.normcase(absolute) in self._ignored:
            return True
        rel = self.relative(absolute)
        return rel is None or is_excluded(rel, self.excludes)

    # ---------------------------------------------------------------- walking
    def iter_files(self, subdir: Optional[str] = None) -> Iterator[str]:
        """Yield relative paths of every monitored file (sorted, deterministic)."""
        top = self.root if subdir is None else self.absolute(subdir)
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(
                d for d in dirnames if not self.should_ignore(os.path.join(dirpath, d))
            )
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if self.should_ignore(full):
                    continue
                rel = self.relative(full)
                if rel:
                    yield rel

    def record(self, rel_path: str) -> Optional[FileRecord]:
        """Hash one file. Returns ``None`` if it no longer exists."""
        full = self.absolute(rel_path)
        try:
            stat = full.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        digest = hash_file(full, self.algorithm)
        if digest is None:
            return None
        return FileRecord(rel_path, digest, stat.st_size, stat.st_mtime)

    def snapshot(
        self, on_error: Optional[Callable[[str, Exception], None]] = None
    ) -> Dict[str, FileRecord]:
        """Hash the whole tree and return ``{relative_path: FileRecord}``."""
        records: Dict[str, FileRecord] = {}
        for rel in self.iter_files():
            try:
                rec = self.record(rel)
            except HashError as exc:
                if on_error:
                    on_error(rel, exc)
                continue
            if rec is not None:
                records[rel] = rec
        return records
