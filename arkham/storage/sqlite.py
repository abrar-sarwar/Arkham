"""SQLite persistence for source state, event memory, runs, and delivery metadata."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from arkham.models import (
    CyberEvent,
    DeliveryResult,
    DeliveryStatus,
    EventUpdate,
    RawItem,
    RunRecord,
    SourceState,
    StoredEvent,
)
from arkham.storage.base import Storage

log = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS source_state (
    source_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_items (
    raw_hash TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    external_id TEXT,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    published_at TEXT,
    updated_at TEXT,
    first_run_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    search_text TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_briefed INTEGER NOT NULL DEFAULT 0,
    last_briefed_at TEXT,
    fingerprint TEXT NOT NULL DEFAULT '',
    last_run_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_search_text_idx ON events(search_text);
CREATE INDEX IF NOT EXISTS events_last_seen_idx ON events(last_seen DESC);
CREATE TABLE IF NOT EXISTS event_updates (
    update_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    description TEXT NOT NULL,
    old_fingerprint TEXT,
    new_fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS event_updates_event_idx ON event_updates(event_id, occurred_at);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    started_at TEXT NOT NULL,
    status TEXT NOT NULL,
    delivery_status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_started_idx ON runs(started_at DESC);
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    provider TEXT NOT NULL,
    recipient_masked TEXT NOT NULL,
    message_ids TEXT NOT NULL,
    messages_sent INTEGER NOT NULL,
    segments INTEGER NOT NULL,
    error TEXT,
    briefing_hash TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS deliveries_sent_idx ON deliveries(sent_at DESC);
"""

#: Columns added after the first release; applied idempotently to databases created by older versions.
_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("deliveries", "attempts", "INTEGER NOT NULL DEFAULT 0"),
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _search_text(event: CyberEvent) -> str:
    values = [
        event.title,
        event.summary,
        event.publisher,
        event.source_name,
        *event.cves,
        *event.cwes,
        *event.threat_actors,
        *event.malware_families,
        *event.products,
        *event.organizations,
        *event.countries,
        *event.regions,
        *event.sectors,
    ]
    return " ".join(value.casefold() for value in values if value)


def _like_term(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


class SQLiteStorage(Storage):
    """Small, transactional SQLite implementation of Arkham's storage contract."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self._connection: sqlite3.Connection | None = None

    @property
    def db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("storage is not initialized")
        return self._connection

    def _connect(self) -> None:
        self._connection = sqlite3.connect(str(self.path), timeout=20)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 20000")
        if str(self.path) != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")

    def initialize(self) -> None:
        if self._connection is not None:
            return
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connect()
            check = self.db.execute("PRAGMA quick_check").fetchone()
            if check is not None and check[0] != "ok":
                raise sqlite3.DatabaseError(f"quick_check failed: {check[0]}")
            self.db.executescript(_SCHEMA)
            self._migrate()
            self.db.commit()
        except sqlite3.DatabaseError as exc:
            self.close()
            if str(self.path) == ":memory:" or not self.path.exists():
                raise
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
            self.path.replace(backup)
            log.error("corrupt Arkham state preserved at %s; starting a clean database (%s)", backup, exc)
            self._connect()
            self.db.executescript(_SCHEMA)
            self._migrate()
            self.db.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was created (``CREATE TABLE IF NOT EXISTS`` never alters)."""
        for table, column, definition in _MIGRATIONS:
            existing = {row["name"] for row in self.db.execute(f"PRAGMA table_info({table})")}  # noqa: S608
            if column not in existing:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")  # noqa: S608
                log.info("storage migration: added %s.%s", table, column)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def get_source_state(self, source_id: str) -> SourceState | None:
        row = self.db.execute("SELECT payload FROM source_state WHERE source_id = ?", (source_id,)).fetchone()
        return SourceState.model_validate_json(row["payload"]) if row else None

    def save_source_state(self, state: SourceState) -> None:
        self.db.execute(
            "INSERT INTO source_state(source_id, payload) VALUES (?, ?) "
            "ON CONFLICT(source_id) DO UPDATE SET payload = excluded.payload",
            (state.source_id, state.model_dump_json()),
        )
        self.db.commit()

    def raw_hash_known(self, raw_hash: str) -> bool:
        return self.db.execute("SELECT 1 FROM raw_items WHERE raw_hash = ?", (raw_hash,)).fetchone() is not None

    def save_raw_items(self, items: list[RawItem], run_id: str) -> int:
        inserted = 0
        for item in items:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO raw_items("
                "raw_hash, source_id, external_id, title, url, published_at, updated_at, first_run_id, first_seen_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    item.raw_hash,
                    item.source_id,
                    item.external_id,
                    item.title,
                    item.url,
                    _iso(item.published_at),
                    _iso(item.updated_at),
                    run_id,
                    _iso(item.fetched_at),
                ),
            )
            inserted += cursor.rowcount
        self.db.commit()
        return inserted

    def get_event(self, event_id: str) -> StoredEvent | None:
        row = self.db.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return self._stored(row) if row else None

    @staticmethod
    def _stored(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            event=CyberEvent.model_validate_json(row["payload"]),
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            times_briefed=int(row["times_briefed"]),
            last_briefed_at=_datetime(row["last_briefed_at"]),
            fingerprint=row["fingerprint"],
        )

    def upsert_event(self, event: CyberEvent, run_id: str, seen_at: datetime) -> StoredEvent:
        previous = self.get_event(event.id)
        first_seen = previous.first_seen if previous else (event.first_seen or seen_at)
        times_briefed = previous.times_briefed if previous else 0
        last_briefed = previous.last_briefed_at if previous else event.last_briefed_at
        persisted = event.model_copy(deep=True)
        persisted.first_seen = first_seen
        persisted.last_seen = seen_at
        persisted.last_briefed_at = last_briefed
        persisted.previously_briefed = times_briefed > 0
        self.db.execute(
            "INSERT INTO events(event_id, payload, search_text, first_seen, last_seen, times_briefed, "
            "last_briefed_at, fingerprint, last_run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload, search_text=excluded.search_text, "
            "last_seen=excluded.last_seen, fingerprint=excluded.fingerprint, last_run_id=excluded.last_run_id",
            (
                event.id,
                persisted.model_dump_json(),
                _search_text(persisted),
                _iso(first_seen),
                _iso(seen_at),
                times_briefed,
                _iso(last_briefed),
                event.fingerprint,
                run_id,
            ),
        )
        self.db.commit()
        stored = self.get_event(event.id)
        assert stored is not None
        return stored

    def add_event_update(self, update: EventUpdate) -> None:
        self.db.execute(
            "INSERT INTO event_updates(event_id, run_id, occurred_at, description, old_fingerprint, new_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                update.event_id,
                update.run_id,
                _iso(update.occurred_at),
                update.description,
                update.old_fingerprint,
                update.new_fingerprint,
            ),
        )
        self.db.commit()

    def get_event_updates(self, event_id: str) -> list[EventUpdate]:
        rows = self.db.execute(
            "SELECT * FROM event_updates WHERE event_id = ? ORDER BY occurred_at, update_id", (event_id,)
        ).fetchall()
        return [
            EventUpdate(
                event_id=row["event_id"],
                run_id=row["run_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                description=row["description"],
                old_fingerprint=row["old_fingerprint"],
                new_fingerprint=row["new_fingerprint"],
            )
            for row in rows
        ]

    def mark_briefed(self, event_ids: list[str], run_id: str, briefed_at: datetime) -> None:
        del run_id
        for event_id in event_ids:
            row = self.db.execute("SELECT payload FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if row is None:
                continue
            event = CyberEvent.model_validate_json(row["payload"])
            event.previously_briefed = True
            event.last_briefed_at = briefed_at
            self.db.execute(
                "UPDATE events SET times_briefed = times_briefed + 1, last_briefed_at = ?, payload = ? "
                "WHERE event_id = ?",
                (_iso(briefed_at), event.model_dump_json(), event_id),
            )
        self.db.commit()

    def search_events(
        self,
        query: str,
        *,
        limit: int = 20,
        since: datetime | None = None,
    ) -> list[StoredEvent]:
        terms = [term.casefold() for term in query.split() if term]
        if not terms or limit <= 0:
            return []
        where = " AND ".join("search_text LIKE ? ESCAPE '\\'" for _ in terms)
        params: list[object] = [_like_term(term) for term in terms]
        if since is not None:
            where += " AND last_seen >= ?"
            params.append(_iso(since))
        params.append(limit)
        rows = self.db.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY last_seen DESC, event_id LIMIT ?",  # noqa: S608
            params,
        ).fetchall()
        return [self._stored(row) for row in rows]

    def save_run(self, run: RunRecord) -> None:
        self.db.execute(
            "INSERT INTO runs(run_id, payload, started_at, status, delivery_status) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload, status=excluded.status, "
            "delivery_status=excluded.delivery_status",
            (run.run_id, run.model_dump_json(), _iso(run.started_at), run.status, run.delivery_status.value),
        )
        self.db.commit()

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self.db.execute("SELECT payload FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return RunRecord.model_validate_json(row["payload"]) if row else None

    def get_last_successful_run(self, *, delivered_only: bool = False) -> RunRecord | None:
        sql = "SELECT payload FROM runs WHERE status = 'success'"
        params: tuple[object, ...] = ()
        if delivered_only:
            sql += " AND delivery_status = ?"
            params = (DeliveryStatus.SENT.value,)
        sql += " ORDER BY started_at DESC LIMIT 1"
        row = self.db.execute(sql, params).fetchone()
        return RunRecord.model_validate_json(row["payload"]) if row else None

    def list_runs(self, limit: int = 20) -> list[RunRecord]:
        rows = self.db.execute("SELECT payload FROM runs ORDER BY started_at DESC LIMIT ?", (max(0, limit),)).fetchall()
        return [RunRecord.model_validate_json(row["payload"]) for row in rows]

    def record_delivery(
        self,
        run_id: str,
        result: DeliveryResult,
        briefing_hash: str,
        sent_at: datetime,
    ) -> None:
        self.db.execute(
            "INSERT INTO deliveries(run_id, status, provider, recipient_masked, message_ids, messages_sent, "
            "segments, error, briefing_hash, sent_at, attempts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                result.status.value,
                result.provider,
                result.recipient_masked,
                json.dumps(result.message_ids),
                result.messages_sent,
                result.segments,
                result.error,
                briefing_hash,
                _iso(sent_at),
                result.attempts,
            ),
        )
        self.db.commit()

    def list_deliveries(self, limit: int = 20) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM deliveries ORDER BY sent_at DESC, delivery_id DESC LIMIT ?", (max(0, limit),)
        ).fetchall()
        return [
            {
                "run_id": row["run_id"],
                "status": row["status"],
                "provider": row["provider"],
                "recipient_masked": row["recipient_masked"],
                "message_ids": json.loads(row["message_ids"]),
                "messages_sent": row["messages_sent"],
                "segments": row["segments"],
                "attempts": row["attempts"],
                "error": row["error"],
                "briefing_hash": row["briefing_hash"],
                "sent_at": row["sent_at"],
            }
            for row in rows
        ]
