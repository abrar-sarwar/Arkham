"""Parallel source collection.

One adapter fetch per enabled source runs in a thread pool. Every fetch is isolated: a crashing
adapter, an adapter that cannot even be built, or one that hangs past its wall-clock budget becomes
a failed :class:`SourceStatus` — never an exception out of :func:`collect_all`. Storage is only
touched from the calling thread: per-source state is read before submission and persisted after
every future has settled.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from arkham.http import SafeHttpClient
from arkham.models import RawItem, SourceState, SourceStatus
from arkham.sources.base import FetchContext, FetchResult, Source, SourceAdapter
from arkham.sources.registry import build_adapter
from arkham.storage.base import Storage

log = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 6
#: Added on top of a source's own HTTP timeout before a fetch is declared hung.
DEFAULT_GRACE_SECONDS = 30.0
_ERROR_MAX = 300
_NAME_COLUMN_MIN = 24
_STATUS_COLUMN_MIN = 12


@dataclass
class CollectionResult:
    """Everything one collection pass produced, with statuses in registry order."""

    items: list[RawItem] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)  # merged FetchContext.extra (e.g. the KEV catalog)
    elapsed_ms: int = 0

    @property
    def sources_checked(self) -> int:
        return len(self.statuses)

    @property
    def sources_ok(self) -> int:
        return sum(1 for s in self.statuses if s.ok)


@dataclass
class _Job:
    source: Source
    ctx: FetchContext
    adapter: SourceAdapter | None = None
    build_error: str | None = None
    future: Future[FetchResult] | None = None
    submitted_at: float | None = None


def collect_all(
    sources: list[Source],
    *,
    http: SafeHttpClient,
    storage: Storage,
    window_start: datetime,
    window_end: datetime,
    now: datetime,
    nvd_api_key: str | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
) -> CollectionResult:
    """Fetch every enabled source concurrently and return items, per-source statuses and merged extras.

    Disabled sources are skipped entirely (no status, no state). Each fetch gets a wall-clock budget of
    the source's timeout (or the HTTP client's default) plus ``grace_seconds``; exceeding it yields a
    ``TIMEOUT`` status. Source state is persisted afterwards: the adapter's ``new_state`` when it gave one,
    otherwise the existing state with its failure counter incremented (failure) or reset (success).
    """
    started = time.monotonic()
    jobs = _prepare_jobs(
        sources,
        http=http,
        storage=storage,
        window_start=window_start,
        window_end=window_end,
        now=now,
        nvd_api_key=nvd_api_key,
    )
    results = _run_jobs(
        jobs, max_workers=max_workers, default_timeout=http.timeout_seconds, grace_seconds=grace_seconds
    )
    collected = CollectionResult()
    for job, result in zip(jobs, results, strict=True):
        collected.items.extend(result.items)
        collected.statuses.append(result.status)
        collected.extra.update(job.ctx.extra)
        _persist_state(storage, job, result, now)
        _log_status(result.status)
    collected.elapsed_ms = int((time.monotonic() - started) * 1000)
    log.info(
        "collection finished: %d/%d sources ok, %d items, %dms",
        collected.sources_ok,
        collected.sources_checked,
        len(collected.items),
        collected.elapsed_ms,
    )
    return collected


# ------------------------------------------------------------------------------- preparation


def _prepare_jobs(
    sources: list[Source],
    *,
    http: SafeHttpClient,
    storage: Storage,
    window_start: datetime,
    window_end: datetime,
    now: datetime,
    nvd_api_key: str | None,
) -> list[_Job]:
    """Build one job per enabled source in the caller's thread (state reads and adapter construction)."""
    jobs: list[_Job] = []
    for source in sources:
        if not source.enabled:
            log.debug("source %s: disabled, skipped", source.id)
            continue
        try:
            state = storage.get_source_state(source.id)
        except Exception as exc:
            log.warning("source %s: could not read stored state, continuing without it: %s", source.id, exc)
            state = None
        ctx = FetchContext(
            http=http,
            window_start=window_start,
            window_end=window_end,
            now=now,
            state=state,
            nvd_api_key=nvd_api_key,
        )
        job = _Job(source=source, ctx=ctx)
        try:
            job.adapter = build_adapter(source)
        except Exception as exc:
            job.build_error = f"{exc.__class__.__name__}: {exc}"
        jobs.append(job)
    return jobs


# --------------------------------------------------------------------------------- execution


def _run_jobs(
    jobs: list[_Job], *, max_workers: int, default_timeout: float, grace_seconds: float
) -> list[FetchResult]:
    """Submit every buildable job, then collect results in submission order with per-source budgets."""
    executor = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="arkham-fetch")
    host_locks: dict[str, threading.Lock] = {}
    try:
        for job in jobs:
            if job.adapter is not None:
                job.submitted_at = time.monotonic()
                host = (urlsplit(job.source.url).hostname or job.source.id).casefold()
                lock = host_locks.setdefault(host, threading.Lock())
                job.future = executor.submit(_fetch_with_host_lock, job.adapter, job.ctx, lock)
        return [_await_job(job, default_timeout=default_timeout, grace_seconds=grace_seconds) for job in jobs]
    finally:
        # Never block on a hung adapter thread; anything still queued is dropped.
        executor.shutdown(wait=False, cancel_futures=True)


def _fetch_with_host_lock(
    adapter: SourceAdapter,
    ctx: FetchContext,
    lock: threading.Lock,
) -> FetchResult:
    """Avoid concurrent requests to one publisher while retaining cross-host parallelism."""
    with lock:
        return adapter.fetch(ctx)


def _await_job(job: _Job, *, default_timeout: float, grace_seconds: float) -> FetchResult:
    if job.future is None:
        return _error_result(job, "ADAPTER ERROR", job.build_error or "adapter could not be built")
    budget = (job.source.timeout_seconds or default_timeout) + grace_seconds
    try:
        result = job.future.result(timeout=budget)
    except TimeoutError as exc:
        if job.future.done():  # the adapter itself raised a TimeoutError
            return _error_result(job, "ERROR", f"{exc.__class__.__name__}: {exc}")
        return _error_result(job, "TIMEOUT", f"no result within {budget:.2f}s (adapter still running)")
    except Exception as exc:
        return _error_result(job, "ERROR", f"{exc.__class__.__name__}: {exc}")
    if not isinstance(result, FetchResult):
        return _error_result(job, "ERROR", f"adapter returned {type(result).__name__}, expected FetchResult")
    return result


def _error_result(job: _Job, status: str, error: str) -> FetchResult:
    elapsed_ms = int((time.monotonic() - job.submitted_at) * 1000) if job.submitted_at is not None else 0
    return FetchResult(
        items=[],
        status=SourceStatus(
            source_id=job.source.id,
            name=job.source.name,
            ok=False,
            status=status,
            items=0,
            elapsed_ms=elapsed_ms,
            error=error[:_ERROR_MAX],
        ),
    )


# ------------------------------------------------------------------------------- persistence


def _next_state(job: _Job, result: FetchResult, now: datetime) -> SourceState:
    """State to persist: the adapter's own, or the prior state advanced by this outcome."""
    status = result.status
    if result.new_state is not None:
        state = result.new_state
        if state.source_id != job.source.id:
            state = state.model_copy(update={"source_id": job.source.id})
        return state
    existing = job.ctx.state
    if status.ok:
        if existing is None:
            return SourceState(
                source_id=job.source.id,
                last_success_at=now,
                last_status=status.status,
                consecutive_failures=0,
            )
        return existing.model_copy(
            update={"last_success_at": now, "last_status": status.status, "consecutive_failures": 0}
        )
    if existing is None:
        return SourceState(source_id=job.source.id, last_status=status.status, consecutive_failures=1)
    return existing.model_copy(
        update={"last_status": status.status, "consecutive_failures": existing.consecutive_failures + 1}
    )


def _persist_state(storage: Storage, job: _Job, result: FetchResult, now: datetime) -> None:
    state = _next_state(job, result, now)
    try:
        storage.save_source_state(state)
    except Exception as exc:
        log.warning("source %s: could not persist source state: %s", job.source.id, exc)


# ---------------------------------------------------------------------------------- reporting


def _log_status(status: SourceStatus) -> None:
    detail = f" error={status.error}" if status.error else ""
    log.info(
        "source %-24s %-13s items=%d elapsed=%dms%s",
        status.source_id,
        status.status,
        status.items,
        status.elapsed_ms,
        detail,
    )


def format_source_table(statuses: list[SourceStatus]) -> str:
    """Aligned per-source lines (name, status, items, elapsed) followed by a ``Sources: ok/checked`` summary."""
    ok = sum(1 for s in statuses if s.ok)
    summary = f"Sources: {ok}/{len(statuses)}"
    if not statuses:
        return summary
    name_w = max(_NAME_COLUMN_MIN, max(len(s.name) for s in statuses))
    status_w = max(_STATUS_COLUMN_MIN, max(len(s.status) for s in statuses))
    items_w = max(len(str(s.items)) for s in statuses) + 2
    ms_w = max(len(str(s.elapsed_ms)) for s in statuses) + 2
    lines = [
        f"{s.name:<{name_w}} {s.status:<{status_w}}{s.items:>{items_w}} items {s.elapsed_ms:>{ms_w}}ms"
        for s in statuses
    ]
    lines.append(summary)
    return "\n".join(lines)
