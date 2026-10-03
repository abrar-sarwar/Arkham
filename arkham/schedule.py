"""Delivery-time logic. All decisions are made in the configured IANA timezone so DST is handled by zoneinfo."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from arkham.config import Settings
from arkham.models import RunRecord


def local_now(now: datetime, tz: ZoneInfo) -> datetime:
    return now.astimezone(tz)


def next_run_time(now: datetime, tz: ZoneInfo, hour: int) -> datetime:
    """Next occurrence of ``hour``:00 local time strictly after ``now`` (DST-safe)."""
    local = now.astimezone(tz)
    candidate = local.replace(hour=hour, minute=0, second=0, microsecond=0)
    if candidate <= local:
        next_day = (local + timedelta(days=1)).date()
        candidate = datetime(next_day.year, next_day.month, next_day.day, hour, tzinfo=tz)
    return candidate


def delivery_slot_start(now: datetime, tz: ZoneInfo, hour: int) -> datetime:
    """Most recent ``hour``:00 local time at or before ``now``; one briefing is owed per slot (DST-safe)."""
    local = now.astimezone(tz)
    start = local.replace(hour=hour, minute=0, second=0, microsecond=0)
    if start > local:
        prev_day = (local - timedelta(days=1)).date()
        start = datetime(prev_day.year, prev_day.month, prev_day.day, hour, tzinfo=tz)
    return start


def utc_hours_for_local_hour(tz: ZoneInfo, hour: int, year: int) -> list[int]:
    """All UTC hours at which ``hour``:00 local occurs during ``year`` (2 for DST zones, 1 otherwise)."""
    hours: set[int] = set()
    day = datetime(year, 1, 1, tzinfo=tz)
    while day.year == year:
        local = day.replace(hour=hour, minute=0, second=0, microsecond=0)
        hours.add(local.astimezone(timezone.utc).hour)
        day += timedelta(days=1)
    return sorted(hours)


def github_cron_lines(tz: ZoneInfo, hour: int, year: int) -> list[str]:
    return [f"0 {h} * * *" for h in utc_hours_for_local_hour(tz, hour, year)]


def already_delivered(last_delivered: RunRecord | None, now: datetime, tz: ZoneInfo, hour: int) -> bool:
    """True when a briefing has gone out since the current delivery slot opened."""
    if last_delivered is None or last_delivered.finished_at is None:
        return False
    return last_delivered.finished_at >= delivery_slot_start(now, tz, hour)


def should_run(now: datetime, settings: Settings, last_delivered: RunRecord | None) -> tuple[bool, str]:
    """Gate used by external schedulers that can only fire in UTC (e.g. GitHub Actions).

    Such schedulers start late (GitHub cron routinely by hours), so the gate opens at the delivery hour
    and stays open for the rest of the local day until that day's briefing has gone out.
    """
    tz = settings.tzinfo
    local = now.astimezone(tz)
    if local.hour < settings.delivery_hour:
        return False, f"local time is {local:%H:%M %Z}; delivery hour is {settings.delivery_hour:02d}:00"
    if already_delivered(last_delivered, now, tz, settings.delivery_hour):
        assert last_delivered is not None and last_delivered.finished_at is not None
        return False, f"already delivered at {last_delivered.finished_at.astimezone(tz):%Y-%m-%d %H:%M %Z}"
    return True, f"local time is {local:%H:%M %Z}; today's briefing has not been delivered"
