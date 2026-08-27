"""Source registry entry, adapter interface and shared parsing helpers."""

from __future__ import annotations

import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from pydantic import BaseModel, Field

from arkham.http import HttpError, HttpStatusError, HttpTimeout, ResponseTooLarge, SafeHttpClient
from arkham.models import RawItem, SourceCategory, SourceState, SourceStatus, SourceTier

log = logging.getLogger(__name__)

_TZ_ABBREV = {
    "UTC": 0, "GMT": 0, "Z": 0,
    "CET": 60, "CEST": 120, "EET": 120, "EEST": 180, "BST": 60, "IST": 60, "WET": 0, "WEST": 60,
    "EST": -300, "EDT": -240, "CST": -360, "CDT": -300, "MST": -420, "MDT": -360, "PST": -480, "PDT": -420,
    "JST": 540, "KST": 540, "AEST": 600, "AEDT": 660,
}
_ABBREV_RE = re.compile(r"\s([A-Z]{1,5})\s*$")


class Source(BaseModel):
    """Declarative description of one feed/API in the registry."""

    id: str
    name: str
    type: str  # json | rss | atom | api
    tier: SourceTier
    category: SourceCategory
    url: str
    enabled: bool = True
    adapter: str = "rss"  # key in the adapter table (see registry.py)
    publisher: str = ""  # short label used in citations, e.g. "CISA", "Microsoft"
    max_bytes: int | None = None
    timeout_seconds: float | None = None
    regions: list[str] = Field(default_factory=list)  # geographic hint for the publisher
    notes: str = ""
    max_items: int = 200


@dataclass
class FetchContext:
    """Everything an adapter may need for a fetch. No secrets except what the adapter itself requires."""

    http: SafeHttpClient
    window_start: datetime
    window_end: datetime
    now: datetime
    state: SourceState | None = None
    nvd_api_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class FetchResult:
    items: list[RawItem]
    status: SourceStatus
    new_state: SourceState | None = None


class SourceAdapter(ABC):
    """Fetch + parse one source into :class:`RawItem` objects. Must never raise; report via status."""

    def __init__(self, source: Source) -> None:
        self.source = source

    @abstractmethod
    def fetch(self, ctx: FetchContext) -> FetchResult:  # pragma: no cover - interface
        ...

    # ---------------------------------------------------------------- helpers
    def _status(self, ok: bool, status: str, *, items: int = 0, error: str | None = None, started: float) -> SourceStatus:
        return SourceStatus(
            source_id=self.source.id,
            name=self.source.name,
            ok=ok,
            status=status,
            items=items,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            error=error,
        )

    def _failure(self, exc: Exception, started: float) -> FetchResult:
        if isinstance(exc, HttpTimeout):
            status = "TIMEOUT"
        elif isinstance(exc, HttpStatusError):
            status = f"HTTP {exc.status_code}"
        elif isinstance(exc, ResponseTooLarge):
            status = "TOO LARGE"
        elif isinstance(exc, HttpError):
            status = "NETWORK ERROR"
        else:
            status = "PARSE ERROR"
        msg = f"{exc.__class__.__name__}: {exc}"[:300]
        log.warning("source %s failed: %s %s", self.source.id, status, msg)
        return FetchResult(items=[], status=self._status(False, status, error=msg, started=started))

    def _not_modified(self, started: float) -> FetchResult:
        return FetchResult(items=[], status=self._status(True, "NOT MODIFIED", started=started))

    def _new_state(self, etag: str | None, last_modified: str | None, ctx: FetchContext, status: str = "OK") -> SourceState:
        return SourceState(
            source_id=self.source.id,
            etag=etag,
            last_modified=last_modified,
            last_success_at=ctx.now,
            last_status=status,
            consecutive_failures=0,
        )

    def base_item(self, **kwargs: Any) -> RawItem:
        """Create a RawItem pre-filled with this source's identity."""
        return RawItem(
            source_id=self.source.id,
            source_name=self.source.name,
            source_tier=self.source.tier,
            source_category=self.source.category,
            **kwargs,
        )


# ------------------------------------------------------------------ date helpers


def parse_datetime(value: str | datetime | date | None) -> datetime | None:
    """Parse RFC 2822, ISO 8601 (with/without Z, fractional seconds), date-only, and common tz abbreviations.

    Naive results are assumed UTC. Returns None when unparseable.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    # ISO 8601
    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # RFC 2822 with possibly unknown tz abbreviation (e.g. CEST)
    offset_minutes: int | None = None
    m = _ABBREV_RE.search(s)
    if m and m.group(1) in _TZ_ABBREV:
        offset_minutes = _TZ_ABBREV[m.group(1)]
        s_rfc = s[: m.start()].rstrip()
    else:
        s_rfc = s
    try:
        dt = parsedate_to_datetime(s_rfc)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is not None:
        if dt.tzinfo is None:
            tz = timezone(timedelta(minutes=offset_minutes)) if offset_minutes is not None else timezone.utc
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d %B %Y", "%B %d, %Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def in_window(dt: datetime | None, ctx: FetchContext, *, allow_missing: bool = False) -> bool:
    """True when ``dt`` falls inside the collection window (end bound is inclusive with 1h slack for clock skew)."""
    if dt is None:
        return allow_missing
    return ctx.window_start <= dt <= ctx.window_end + timedelta(hours=1)
