"""Human-friendly terminal output and optional log-file output."""

from __future__ import annotations

import logging
import os
import sys
from typing import IO, Iterable, Optional

from .models import Alert, EventType, Severity

try:  # colorama makes ANSI colors work on legacy Windows consoles
    import colorama

    colorama.just_fix_windows_console()
except Exception:  # pragma: no cover - colorama is optional at runtime
    colorama = None

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
}

_EVENT_COLOR = {
    EventType.MODIFIED: "red",
    EventType.DELETED: "magenta",
    EventType.CREATED: "yellow",
    EventType.MOVED: "cyan",
    EventType.RESTORED: "green",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "green",
}


def short_hash(value: Optional[str], length: int = 12) -> str:
    return value[:length] if value else "-"


def _display_time(iso_ts: str) -> str:
    return iso_ts[:19].replace("T", " ")


def _supports_color(stream: IO[str]) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class ConsoleReporter:
    """Prints alerts and status messages to the terminal."""

    def __init__(self, stream: Optional[IO[str]] = None, use_color: Optional[bool] = None,
                 show_hashes: bool = True) -> None:
        self.stream = stream or sys.stdout
        self.use_color = _supports_color(self.stream) if use_color is None else use_color
        self.show_hashes = show_hashes

    # ------------------------------------------------------------- helpers
    def _c(self, text: str, color: Optional[str] = None, *, bold: bool = False,
           dim: bool = False) -> str:
        if not self.use_color:
            return text
        prefix = (_BOLD if bold else "") + (_DIM if dim else "") + _COLORS.get(color or "", "")
        return f"{prefix}{text}{_RESET}" if prefix else text

    def _write(self, line: str = "") -> None:
        try:
            self.stream.write(line + "\n")
        except UnicodeEncodeError:  # e.g. redirected output on a legacy code page
            encoding = getattr(self.stream, "encoding", None) or "ascii"
            self.stream.write(line.encode(encoding, "replace").decode(encoding) + "\n")
        self.stream.flush()

    # ---------------------------------------------------------- messages
    def banner(self, title: str, rows: Iterable[tuple]) -> None:
        self._write(self._c(f"== {title} ==", "blue", bold=True))
        for key, value in rows:
            self._write(f"  {self._c(f'{key:<10}', dim=True)} {value}")
        self._write()

    def info(self, message: str) -> None:
        self._write(f"{self._c('[*]', 'blue', bold=True)} {message}")

    def success(self, message: str) -> None:
        self._write(f"{self._c('[+]', 'green', bold=True)} {message}")

    def warning(self, message: str) -> None:
        self._write(f"{self._c('[!]', 'yellow', bold=True)} {message}")

    def error(self, message: str) -> None:
        self._write(f"{self._c('[x]', 'red', bold=True)} {message}")

    # ------------------------------------------------------------- alerts
    def emit(self, alert: Alert) -> None:
        color = _EVENT_COLOR[alert.event_type]
        severity = alert.severity
        line = (
            f"{self._c('[' + _display_time(alert.timestamp) + ']', dim=True)} "
            f"{self._c(f'{severity.value:<8}', _SEVERITY_COLOR[severity], bold=True)} "
            f"{self._c(f'{alert.event_type.value:<8}', color, bold=True)} "
            f"{self._c(alert.path, bold=True)}"
        )
        self._write(line)
        details = []
        if alert.detail:
            details.append(alert.detail)
        if self.show_hashes and (alert.old_hash or alert.new_hash):
            details.append(f"baseline {short_hash(alert.old_hash)} -> current {short_hash(alert.new_hash)}")
        if details:
            self._write(" " * 22 + self._c(" | ".join(details), dim=True))


class FileLogReporter:
    """Appends alerts to a plain-text log file (SIEM / grep friendly)."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        self._logger = logging.getLogger(f"fim.file.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = logging.FileHandler(self.path, encoding="utf-8")
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._handler)

    def emit(self, alert: Alert) -> None:
        self._logger.info(
            "%s severity=%s event=%s path=%s old=%s new=%s detail=%s",
            alert.timestamp, alert.severity.value, alert.event_type.value, alert.path,
            alert.old_hash or "-", alert.new_hash or "-", alert.detail or "-",
        )

    def close(self) -> None:
        self._logger.removeHandler(self._handler)
        self._handler.close()


class MultiReporter:
    """Fan-out an alert to several reporters."""

    def __init__(self, *reporters: object) -> None:
        self.reporters = [r for r in reporters if r is not None]

    def emit(self, alert: Alert) -> None:
        for reporter in self.reporters:
            reporter.emit(alert)  # type: ignore[attr-defined]

    def __getattr__(self, name: str):
        # Delegate info()/warning()/... to the first reporter that has them.
        for reporter in self.reporters:
            if hasattr(reporter, name):
                return getattr(reporter, name)
        raise AttributeError(name)
