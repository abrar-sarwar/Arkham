"""Storage construction."""

from __future__ import annotations

from arkham.config import Settings
from arkham.storage.base import Storage
from arkham.storage.sqlite import SQLiteStorage

__all__ = ["SQLiteStorage", "Storage", "open_storage"]


def open_storage(settings: Settings) -> SQLiteStorage:
    """Construct the configured local storage backend.

    Initialization remains in the context-manager boundary so callers get a
    consistent lifecycle for CLI, runner, and Lambda execution.
    """
    return SQLiteStorage(settings.db_path)
