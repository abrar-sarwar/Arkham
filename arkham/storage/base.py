"""Storage interface. Business logic depends only on this ABC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from arkham.models import (
    CyberEvent,
    DeliveryResult,
    EventUpdate,
    RawItem,
    RunRecord,
    SourceState,
    StoredEvent,
)


class Storage(ABC):
    @abstractmethod
    def initialize(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    # ---- per-source fetch state (conditional GET, health)
    @abstractmethod
    def get_source_state(self, source_id: str) -> SourceState | None: ...

    @abstractmethod
    def save_source_state(self, state: SourceState) -> None: ...

    # ---- raw items
    @abstractmethod
    def raw_hash_known(self, raw_hash: str) -> bool: ...

    @abstractmethod
    def save_raw_items(self, items: list[RawItem], run_id: str) -> int:
        """Persist items; return how many were not previously known (by raw_hash)."""

    # ---- events
    @abstractmethod
    def get_event(self, event_id: str) -> StoredEvent | None: ...

    @abstractmethod
    def upsert_event(self, event: CyberEvent, run_id: str, seen_at: datetime) -> StoredEvent:
        """Insert or update; keeps first_seen, updates last_seen, stores the latest fingerprint."""

    @abstractmethod
    def add_event_update(self, update: EventUpdate) -> None: ...

    @abstractmethod
    def get_event_updates(self, event_id: str) -> list[EventUpdate]: ...

    @abstractmethod
    def mark_briefed(self, event_ids: list[str], run_id: str, briefed_at: datetime) -> None: ...

    @abstractmethod
    def search_events(self, query: str, *, limit: int = 20, since: datetime | None = None) -> list[StoredEvent]:
        """Simple text search over title/summary/cves/actors — the seed for future `arkham ask`."""

    # ---- runs and delivery
    @abstractmethod
    def save_run(self, run: RunRecord) -> None: ...

    @abstractmethod
    def get_run(self, run_id: str) -> RunRecord | None: ...

    @abstractmethod
    def get_last_successful_run(self, *, delivered_only: bool = False) -> RunRecord | None: ...

    @abstractmethod
    def list_runs(self, limit: int = 20) -> list[RunRecord]: ...

    @abstractmethod
    def record_delivery(self, run_id: str, result: DeliveryResult, briefing_hash: str, sent_at: datetime) -> None: ...

    @abstractmethod
    def list_deliveries(self, limit: int = 20) -> list[dict]: ...

    def __enter__(self) -> Storage:
        self.initialize()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
