from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from arkham.config import Settings
from arkham.models import (
    CyberEvent,
    DeliveryResult,
    DeliveryStatus,
    EventType,
    EventUpdate,
    RawItem,
    RunRecord,
    SourceCategory,
    SourceState,
    SourceTier,
)
from arkham.storage import open_storage

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def event(event_id: str = "event-1") -> CyberEvent:
    return CyberEvent(
        id=event_id,
        title="Microsoft Chrome CVE-2026-12345 ransomware update",
        summary="A China-nexus campaign targeted cloud users.",
        event_type=EventType.THREAT_ACTIVITY,
        source_name="Google Threat Intelligence",
        source_url="https://example.com/report",
        source_tier=SourceTier.RESEARCH,
        publisher="Google",
        cves=["CVE-2026-12345"],
        threat_actors=["APT29"],
        products=["Microsoft Chrome"],
        fingerprint="fp-1",
        final_priority_score=72,
    )


def test_sqlite_persists_source_state_event_updates_runs_and_search(tmp_path) -> None:
    path = tmp_path / "state" / "arkham.db"
    settings = Settings(db_path=str(path), llm_provider="template")
    with open_storage(settings) as storage:
        storage.save_source_state(SourceState(source_id="cisa", etag='"abc"', last_success_at=NOW))
        stored = storage.upsert_event(event(), "run-1", NOW)
        assert stored.first_seen == NOW and stored.times_briefed == 0
        storage.add_event_update(
            EventUpdate(event_id="event-1", run_id="run-2", occurred_at=NOW, description="added to CISA KEV")
        )
        storage.mark_briefed(["event-1"], "run-2", NOW)
        run = RunRecord(
            run_id="run-2",
            mode="scheduled",
            started_at=NOW,
            finished_at=NOW + timedelta(seconds=2),
            status="success",
            delivery_status=DeliveryStatus.SENT,
        )
        storage.save_run(run)
        storage.record_delivery(
            "run-2",
            DeliveryResult(
                status=DeliveryStatus.SENT,
                provider="twilio",
                recipient_masked="+1******0143",
                message_ids=["SM1"],
                messages_sent=1,
                segments=3,
            ),
            "brief-hash",
            NOW,
        )

    with open_storage(settings) as storage:
        assert storage.get_source_state("cisa").etag == '"abc"'
        loaded = storage.get_event("event-1")
        assert loaded is not None and loaded.times_briefed == 1 and loaded.last_briefed_at == NOW
        assert storage.get_event_updates("event-1")[0].description == "added to CISA KEV"
        assert storage.get_last_successful_run(delivered_only=True).run_id == "run-2"
        assert storage.list_deliveries()[0]["segments"] == 3
        for query in ("CVE-2026-12345", "ransomware", "China", "Microsoft", "Chrome", "APT29"):
            assert [item.event.id for item in storage.search_events(query)] == ["event-1"]


def test_raw_hash_dedup_persists_only_metadata_not_article_bodies(tmp_path) -> None:
    path = tmp_path / "arkham.db"
    item = RawItem(
        source_id="source",
        source_name="Source",
        source_tier=SourceTier.RESEARCH,
        source_category=SourceCategory.RESEARCH,
        title="Research title",
        url="https://example.com/research",
        summary="private bounded summary",
        content="large raw article body that should not be retained",
        fetched_at=NOW,
    )
    with open_storage(Settings(db_path=str(path), llm_provider="template")) as storage:
        assert storage.save_raw_items([item], "run-1") == 1
        assert storage.save_raw_items([item], "run-2") == 0
        assert storage.raw_hash_known(item.raw_hash)

    connection = sqlite3.connect(path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(raw_items)")}
        payload = " ".join(str(value) for row in connection.execute("SELECT * FROM raw_items") for value in row)
    finally:
        connection.close()
    assert "summary" not in columns and "content" not in columns
    assert "private bounded summary" not in payload
    assert "large raw article body" not in payload


def test_corrupt_database_is_preserved_and_recovered(tmp_path) -> None:
    path = tmp_path / "arkham.db"
    path.write_bytes(b"not a sqlite database")
    settings = Settings(db_path=str(path), llm_provider="template")
    with open_storage(settings) as storage:
        storage.save_run(RunRecord(run_id="recovered", mode="dry-run", started_at=NOW))
        assert storage.get_run("recovered") is not None
    backups = list(tmp_path.glob("arkham.db.corrupt-*") )
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"not a sqlite database"
