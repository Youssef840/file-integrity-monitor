"""Streaming file hashing built on :mod:`hashlib`."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

CHUNK_SIZE = 64 * 1024  # 64 KiB keeps memory flat even for multi-GB files
DEFAULT_ALGORITHM = "sha256"
SUPPORTED_ALGORITHMS = ("sha256", "sha512", "sha3_256", "blake2b", "sha1", "md5")


class HashError(OSError):
    """Raised when a file exists but cannot be read."""


def validate_algorithm(name: str) -> str:
    """Return the normalized algorithm name or raise :class:`ValueError`."""
    key = name.strip().lower().replace("-", "").replace("_", "")
    lookup = {algo.replace("_", ""): algo for algo in SUPPORTED_ALGORITHMS}
    if key not in lookup:
        supported = ", ".join(SUPPORTED_ALGORITHMS)
        raise ValueError(f"Unsupported hash algorithm '{name}'. Choose one of: {supported}")
    return lookup[key]


def hash_bytes(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Hash an in-memory buffer (handy for tests and tooling)."""
    return hashlib.new(validate_algorithm(algorithm), data).hexdigest()


def hash_file(
    path: PathLike,
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    retries: int = 3,
    retry_delay: float = 0.2,
) -> Optional[str]:
    """Return the hex digest of ``path``.

    Returns ``None`` when the file does not exist (or is a directory), so
    callers can treat "vanished while we were looking" as a deletion.

    ``PermissionError`` is retried a few times because on Windows a file is
    often locked for a split second while another program is saving it.

    :raises HashError: the file exists but stays unreadable.
    """
    algorithm = validate_algorithm(algorithm)
    if os.path.isdir(path):
        return None

    last_error: Optional[BaseException] = None
    for attempt in range(retries + 1):
        try:
            digest = hashlib.new(algorithm)
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None
        except PermissionError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(retry_delay)
        except OSError as exc:
            raise HashError(f"Cannot read '{path}': {exc}") from exc

    raise HashError(f"Permission denied reading '{path}': {last_error}") from last_error
