"""Tests for the parallel collector: isolation, ordering, timeouts, state persistence, extra merging."""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta

import pytest

from arkham.models import (
    CyberEvent,
    DeliveryResult,
    EventUpdate,
    RawItem,
    RunRecord,
    SourceCategory,
    SourceState,
    SourceStatus,
    SourceTier,
    StoredEvent,
)
from arkham.sources import collector
from arkham.sources.base import FetchContext, FetchResult, Source, SourceAdapter
from arkham.sources.collector import CollectionResult, collect_all, format_source_table
from arkham.sources.registry import RegistryError
from arkham.storage.base import Storage
from tests.conftest import RouteTable

# ------------------------------------------------------------------------------ test doubles


class MemoryStorage(Storage):
    """Only what the collector needs: per-source state. Everything else is deliberately unimplemented."""

    def __init__(self, states: dict[str, SourceState] | None = None) -> None:
        self.states: dict[str, SourceState] = dict(states or {})
        self.reads: list[str] = []
        self.saves: list[SourceState] = []
        self.read_threads: list[str] = []
        self.save_threads: list[str] = []

    def initialize(self) -> None:
        return None

    def close(self) -> None:
        return None

    def get_source_state(self, source_id: str) -> SourceState | None:
        self.reads.append(source_id)
        self.read_threads.append(threading.current_thread().name)
        state = self.states.get(source_id)
        return state.model_copy() if state else None

    def save_source_state(self, state: SourceState) -> None:
        self.save_threads.append(threading.current_thread().name)
        self.saves.append(state)
        self.states[state.source_id] = state

    def raw_hash_known(self, raw_hash: str) -> bool:
        raise NotImplementedError

    def save_raw_items(self, items: list[RawItem], run_id: str) -> int:
        raise NotImplementedError

    def get_event(self, event_id: str) -> StoredEvent | None:
        raise NotImplementedError

    def upsert_event(self, event: CyberEvent, run_id: str, seen_at: datetime) -> StoredEvent:
        raise NotImplementedError

    def add_event_update(self, update: EventUpdate) -> None:
        raise NotImplementedError

    def get_event_updates(self, event_id: str) -> list[EventUpdate]:
        raise NotImplementedError

    def mark_briefed(self, event_ids: list[str], run_id: str, briefed_at: datetime) -> None:
        raise NotImplementedError

    def search_events(
        self, query: str, *, limit: int = 20, since: datetime | None = None
    ) -> list[StoredEvent]:
        raise NotImplementedError

    def save_run(self, run: RunRecord) -> None:
        raise NotImplementedError

    def get_run(self, run_id: str) -> RunRecord | None:
        raise NotImplementedError

    def get_last_successful_run(self, *, delivered_only: bool = False) -> RunRecord | None:
        raise NotImplementedError

    def list_runs(self, limit: int = 20) -> list[RunRecord]:
        raise NotImplementedError

    def record_delivery(
        self, run_id: str, result: DeliveryResult, briefing_hash: str, sent_at: datetime
    ) -> None:
        raise NotImplementedError

    def list_deliveries(self, limit: int = 20) -> list[dict]:
        raise NotImplementedError


class RecordingAdapter(SourceAdapter):
    """Base double that records the context it was given and the thread it ran on."""

    def __init__(self, source: Source) -> None:
        super().__init__(source)
        self.ctx: FetchContext | None = None
        self.thread: str = ""

    def _record(self, ctx: FetchContext) -> None:
        self.ctx = ctx
        self.thread = threading.current_thread().name


class OkAdapter(RecordingAdapter):
    item_count = 2
    extra_key = "kev_catalog"
    extra_value: object = {"CVE-2026-0001": "listed"}

    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        ctx.extra[self.extra_key] = self.extra_value
        items = [
            self.base_item(
                title=f"{self.source.name} item {i}",
                url=f"{self.source.url}item-{i}",
                published_at=ctx.now - timedelta(hours=i),
                fetched_at=ctx.now,
            )
            for i in range(self.item_count)
        ]
        status = SourceStatus(
            source_id=self.source.id,
            name=self.source.name,
            ok=True,
            status="OK",
            items=len(items),
            elapsed_ms=812,
        )
        return FetchResult(
            items=items,
            status=status,
            new_state=self._new_state('"etag-new"', "Wed, 26 Aug 2026 11:00:00 GMT", ctx),
        )


class SecondOkAdapter(OkAdapter):
    item_count = 1
    extra_key = "nvd_stats"
    extra_value = {"fetched": 1}


class FailAdapter(RecordingAdapter):
    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        status = SourceStatus(
            source_id=self.source.id,
            name=self.source.name,
            ok=False,
            status="HTTP 500",
            error="HTTP 500 from upstream",
        )
        return FetchResult(items=[], status=status)


class NotModifiedNoStateAdapter(RecordingAdapter):
    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        status = SourceStatus(source_id=self.source.id, name=self.source.name, ok=True, status="NOT MODIFIED")
        return FetchResult(items=[], status=status)


class RaisingAdapter(RecordingAdapter):
    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        raise RuntimeError("adapter exploded")


class HangingAdapter(RecordingAdapter):
    release = threading.Event()

    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        HangingAdapter.release.wait(timeout=10)
        status = SourceStatus(source_id=self.source.id, name=self.source.name, ok=True, status="OK")
        return FetchResult(items=[], status=status)


class HostConcurrencyAdapter(RecordingAdapter):
    lock = threading.Lock()
    active_by_host: dict[str, int] = {}
    max_by_host: dict[str, int] = {}

    def fetch(self, ctx: FetchContext) -> FetchResult:
        self._record(ctx)
        host = self.source.url.split("/", 3)[2]
        with self.lock:
            self.active_by_host[host] = self.active_by_host.get(host, 0) + 1
            self.max_by_host[host] = max(self.max_by_host.get(host, 0), self.active_by_host[host])
        time.sleep(0.03)
        with self.lock:
            self.active_by_host[host] -= 1
        return FetchResult(
            items=[],
            status=SourceStatus(source_id=self.source.id, name=self.source.name, ok=True, status="OK"),
        )


ADAPTERS: dict[str, type[RecordingAdapter]] = {
    "ok": OkAdapter,
    "ok2": SecondOkAdapter,
    "fail": FailAdapter,
    "not_modified": NotModifiedNoStateAdapter,
    "raise": RaisingAdapter,
    "hang": HangingAdapter,
    "host_concurrency": HostConcurrencyAdapter,
}


def make_source(source_id: str, adapter: str, **overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": source_id,
        "name": source_id.upper().replace("-", " "),
        "type": "rss",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.ADVISORY,
        "url": f"https://example.com/{source_id}/",
        "adapter": adapter,
        "publisher": source_id,
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


@pytest.fixture
def built(monkeypatch: pytest.MonkeyPatch) -> dict[str, RecordingAdapter]:
    """Route build_adapter to the doubles above and expose every constructed adapter by source id."""
    instances: dict[str, RecordingAdapter] = {}

    def fake_build(source: Source) -> SourceAdapter:
        if source.adapter == "broken":
            raise RegistryError(f"adapter module for {source.id} is missing")
        adapter = ADAPTERS[source.adapter](source)
        instances[source.id] = adapter
        return adapter

    monkeypatch.setattr(collector, "build_adapter", fake_build)
    return instances


@pytest.fixture
def http(routes: RouteTable):
    client = routes.client(timeout_seconds=0.5)
    yield client
    client.close()


def run(
    sources: list[Source], storage: MemoryStorage, http, now: datetime, **kwargs: object
) -> CollectionResult:
    return collect_all(
        sources,
        http=http,
        storage=storage,
        window_start=now - timedelta(hours=24),
        window_end=now,
        now=now,
        **kwargs,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------------------------ tests


def test_failures_are_isolated_and_statuses_keep_registry_order(built, http, now: datetime) -> None:
    sources = [
        make_source("alpha", "ok"),
        make_source("bravo", "fail"),
        make_source("charlie", "raise"),
        make_source("delta", "broken"),
        make_source("echo", "ok2"),
    ]
    storage = MemoryStorage()
    result = run(sources, storage, http, now)

    assert isinstance(result, CollectionResult)
    assert [s.source_id for s in result.statuses] == ["alpha", "bravo", "charlie", "delta", "echo"]
    assert [s.status for s in result.statuses] == ["OK", "HTTP 500", "ERROR", "ADAPTER ERROR", "OK"]
    assert [s.ok for s in result.statuses] == [True, False, False, False, True]
    assert result.statuses[2].error is not None and "adapter exploded" in result.statuses[2].error
    assert result.statuses[3].error is not None and "missing" in result.statuses[3].error
    assert result.statuses[3].name == "DELTA"
    assert all(s.elapsed_ms >= 0 for s in result.statuses)
    assert [i.source_id for i in result.items] == ["alpha", "alpha", "echo"]
    assert result.extra == {"kev_catalog": {"CVE-2026-0001": "listed"}, "nvd_stats": {"fetched": 1}}
    assert result.elapsed_ms >= 0
    assert result.sources_checked == 5
    assert result.sources_ok == 2
    assert "delta" not in built  # never constructed


def test_hanging_adapter_reports_timeout_without_blocking_others(built, http, now: datetime) -> None:
    HangingAdapter.release.clear()
    sources = [
        make_source("slow", "hang", timeout_seconds=0.05),
        make_source("quick", "ok", url="https://quick.example.org/quick/"),
    ]
    storage = MemoryStorage()
    started = time.monotonic()
    try:
        result = run(sources, storage, http, now, grace_seconds=0.1)
    finally:
        HangingAdapter.release.set()
    elapsed = time.monotonic() - started

    assert elapsed < 5
    assert [s.status for s in result.statuses] == ["TIMEOUT", "OK"]
    assert result.statuses[0].ok is False
    assert result.statuses[0].error is not None and "0.15" in result.statuses[0].error
    assert [i.source_id for i in result.items] == ["quick", "quick"]
    assert storage.states["slow"].consecutive_failures == 1
    assert storage.states["slow"].last_status == "TIMEOUT"
    assert storage.states["quick"].last_status == "OK"


def test_fetches_for_same_host_are_serialized_while_other_hosts_remain_parallel(built, http, now: datetime) -> None:
    HostConcurrencyAdapter.active_by_host = {}
    HostConcurrencyAdapter.max_by_host = {}
    sources = [
        make_source("same-a", "host_concurrency", url="https://publisher.example/feed-a"),
        make_source("same-b", "host_concurrency", url="https://publisher.example/feed-b"),
        make_source("other", "host_concurrency", url="https://other.example/feed"),
    ]
    result = run(sources, MemoryStorage(), http, now, max_workers=3)
    assert result.sources_ok == 3
    assert HostConcurrencyAdapter.max_by_host["publisher.example"] == 1
    assert HostConcurrencyAdapter.max_by_host["other.example"] == 1


def test_disabled_sources_are_skipped_entirely(built, http, now: datetime) -> None:
    sources = [
        make_source("on", "ok"),
        make_source("off", "raise", enabled=False),
        make_source("also-off", "broken", enabled=False),
    ]
    storage = MemoryStorage()
    result = run(sources, storage, http, now)

    assert [s.source_id for s in result.statuses] == ["on"]
    assert "off" not in built
    assert storage.reads == ["on"]
    assert set(storage.states) == {"on"}


def test_state_is_read_in_main_thread_and_passed_to_adapters(built, http, now: datetime) -> None:
    existing = SourceState(
        source_id="alpha", etag='"old"', last_modified="Tue, 25 Aug 2026 11:00:00 GMT", last_status="OK"
    )
    storage = MemoryStorage({"alpha": existing})
    sources = [make_source("alpha", "ok"), make_source("bravo", "ok2")]
    run(sources, storage, http, now, nvd_api_key="test-key-value")

    main = threading.current_thread().name
    assert storage.read_threads == [main, main]
    assert storage.save_threads == [main, main]
    alpha = built["alpha"]
    assert alpha.ctx is not None
    assert alpha.ctx.state is not None and alpha.ctx.state.etag == '"old"'
    assert alpha.ctx.nvd_api_key == "test-key-value"
    assert alpha.ctx.window_start == now - timedelta(hours=24)
    assert alpha.ctx.window_end == now
    assert alpha.ctx.now == now
    assert alpha.ctx.http is http
    assert alpha.thread != main
    bravo = built["bravo"]
    assert bravo.ctx is not None and bravo.ctx.state is None
    assert bravo.ctx.extra is not alpha.ctx.extra  # one context per source


def test_successful_fetch_persists_new_state(built, http, now: datetime) -> None:
    storage = MemoryStorage()
    run([make_source("alpha", "ok")], storage, http, now)

    state = storage.states["alpha"]
    assert state.etag == '"etag-new"'
    assert state.last_modified == "Wed, 26 Aug 2026 11:00:00 GMT"
    assert state.last_success_at == now
    assert state.last_status == "OK"
    assert state.consecutive_failures == 0


def test_failure_increments_existing_state_and_keeps_validators(built, http, now: datetime) -> None:
    previous = now - timedelta(days=1)
    existing = SourceState(
        source_id="bravo",
        etag='"keep"',
        last_modified="Mon",
        last_success_at=previous,
        last_status="OK",
        consecutive_failures=2,
    )
    storage = MemoryStorage({"bravo": existing})
    run([make_source("bravo", "fail")], storage, http, now)

    state = storage.states["bravo"]
    assert state.consecutive_failures == 3
    assert state.last_status == "HTTP 500"
    assert state.etag == '"keep"'
    assert state.last_modified == "Mon"
    assert state.last_success_at == previous


def test_failure_creates_state_when_absent(built, http, now: datetime) -> None:
    storage = MemoryStorage()
    run([make_source("charlie", "raise"), make_source("delta", "broken")], storage, http, now)

    assert storage.states["charlie"].consecutive_failures == 1
    assert storage.states["charlie"].last_status == "ERROR"
    assert storage.states["charlie"].last_success_at is None
    assert storage.states["delta"].consecutive_failures == 1
    assert storage.states["delta"].last_status == "ADAPTER ERROR"


def test_success_without_new_state_resets_failure_counter(built, http, now: datetime) -> None:
    existing = SourceState(source_id="nm", etag='"e"', last_status="HTTP 500", consecutive_failures=4)
    storage = MemoryStorage({"nm": existing, "fresh": SourceState(source_id="fresh", consecutive_failures=1)})
    run([make_source("nm", "not_modified"), make_source("fresh", "not_modified")], storage, http, now)

    state = storage.states["nm"]
    assert state.consecutive_failures == 0
    assert state.last_status == "NOT MODIFIED"
    assert state.etag == '"e"'
    assert state.last_success_at == now
    fresh = storage.states["fresh"]
    assert fresh.consecutive_failures == 0 and fresh.last_status == "NOT MODIFIED"


def test_storage_save_failure_does_not_lose_items(
    built, http, now: datetime, caplog: pytest.LogCaptureFixture
) -> None:
    class BrokenSaveStorage(MemoryStorage):
        def save_source_state(self, state: SourceState) -> None:
            raise RuntimeError("disk full")

    storage = BrokenSaveStorage()
    with caplog.at_level(logging.WARNING, logger="arkham.sources.collector"):
        result = run([make_source("alpha", "ok")], storage, http, now)
    assert len(result.items) == 2
    assert result.statuses[0].status == "OK"
    assert any("disk full" in rec.getMessage() for rec in caplog.records)


def test_extra_is_merged_from_every_context(built, http, now: datetime) -> None:
    sources = [make_source("a", "ok"), make_source("b", "ok2"), make_source("c", "fail")]
    result = run(sources, MemoryStorage(), http, now)
    assert result.extra == {"kev_catalog": {"CVE-2026-0001": "listed"}, "nvd_stats": {"fetched": 1}}


def test_empty_source_list(built, http, now: datetime) -> None:
    result = run([], MemoryStorage(), http, now)
    assert result.items == [] and result.statuses == [] and result.extra == {}
    assert result.elapsed_ms >= 0


def test_single_worker_preserves_order(built, http, now: datetime) -> None:
    sources = [make_source(f"s{i}", "ok" if i % 2 else "fail") for i in range(6)]
    result = run(sources, MemoryStorage(), http, now, max_workers=1)
    assert [s.source_id for s in result.statuses] == [f"s{i}" for i in range(6)]
    assert [s.ok for s in result.statuses] == [False, True] * 3


def test_logs_one_info_line_per_source(built, http, now: datetime, caplog: pytest.LogCaptureFixture) -> None:
    sources = [
        make_source("alpha", "ok"),
        make_source("bravo", "fail"),
        make_source("zulu", "ok2", enabled=False),
    ]
    with caplog.at_level(logging.INFO, logger="arkham.sources.collector"):
        run(sources, MemoryStorage(), http, now)
    lines = [
        rec.getMessage()
        for rec in caplog.records
        if rec.levelno == logging.INFO and rec.getMessage().startswith("source ")
    ]
    assert len(lines) == 2
    assert "alpha" in lines[0] and "OK" in lines[0] and "items=2" in lines[0] and "ms" in lines[0]
    assert "bravo" in lines[1] and "HTTP 500" in lines[1]
    assert not any("zulu" in line for line in lines)


# ------------------------------------------------------------------------- format_source_table


def test_format_source_table_aligns_columns_and_summarises() -> None:
    statuses = [
        SourceStatus(source_id="cisa-kev", name="CISA KEV", ok=True, status="OK", items=12, elapsed_ms=812),
        SourceStatus(
            source_id="nvd",
            name="NIST National Vulnerability Database",
            ok=False,
            status="HTTP 503",
            items=0,
            elapsed_ms=20345,
        ),
        SourceStatus(
            source_id="unit42", name="Unit 42", ok=True, status="NOT MODIFIED", items=0, elapsed_ms=95
        ),
    ]
    text = format_source_table(statuses)
    lines = text.splitlines()

    assert len(lines) == 4
    assert re.fullmatch(r"CISA KEV\s+OK\s+12 items\s+812ms", lines[0])
    assert re.fullmatch(r"NIST National Vulnerability Database\s+HTTP 503\s+0 items\s+20345ms", lines[1])
    assert re.fullmatch(r"Unit 42\s+NOT MODIFIED\s+0 items\s+95ms", lines[2])
    assert lines[3] == "Sources: 2/3"
    # status column starts at the same offset on every row; "items" and "ms" end at the same offsets
    status_cols = {line.index(s.status) for line, s in zip(lines[:3], statuses, strict=True)}
    assert len(status_cols) == 1
    assert len({line.index(" items") for line in lines[:3]}) == 1
    assert len({len(line) for line in lines[:3]}) == 1
    assert "\t" not in text


def test_format_source_table_empty() -> None:
    assert format_source_table([]) == "Sources: 0/0"
