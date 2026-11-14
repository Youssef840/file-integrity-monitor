"""File Integrity Monitor (FIM).

Detects unauthorized changes to files by comparing cryptographic hashes
against a trusted baseline stored in SQLite, with real-time alerts powered
by watchdog.
"""

__all__ = ["__version__"]
__version__ = "1.0.0"
