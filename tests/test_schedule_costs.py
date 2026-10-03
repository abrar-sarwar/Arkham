from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from arkham.config import load_settings
from arkham.costs import compute_costs, format_cost_report
from arkham.models import DeliveryStatus, LLMUsage, RunRecord
from arkham.schedule import (
    github_cron_lines,
    next_run_time,
    should_run,
    utc_hours_for_local_hour,
)

NY = ZoneInfo("America/New_York")


def test_next_run_time_handles_dst_transitions():
    # 2026-03-08 is spring-forward; 12:30 UTC is 08:30 EDT, so the next run is tomorrow 08:00 EDT (12:00 UTC)
    nxt = next_run_time(datetime(2026, 3, 8, 12, 30, tzinfo=timezone.utc), NY, 8)
    assert nxt == datetime(2026, 3, 9, 8, 0, tzinfo=NY) and nxt.utcoffset() == timedelta(hours=-4)
    # 2026-11-01 is fall-back; 12:30 UTC is 07:30 EST, so today 08:00 EST (13:00 UTC)
    nxt = next_run_time(datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc), NY, 8)
    assert nxt == datetime(2026, 11, 1, 8, 0, tzinfo=NY) and nxt.utcoffset() == timedelta(hours=-5)


def test_utc_hours_and_cron_lines_cover_both_offsets():
    assert utc_hours_for_local_hour(NY, 8, 2026) == [12, 13]
    assert github_cron_lines(NY, 8, 2026) == ["0 12 * * *", "0 13 * * *"]
    assert utc_hours_for_local_hour(ZoneInfo("Asia/Tokyo"), 8, 2026) == [23]


def _delivered(finished_at: datetime) -> RunRecord:
    return RunRecord(run_id="r1", mode="scheduled", started_at=finished_at - timedelta(minutes=3), finished_at=finished_at, status="success", delivery_status=DeliveryStatus.SENT)


def test_should_run_gate_opens_at_local_delivery_hour_and_stays_open():
    settings = load_settings({}, dotenv_path=None)
    summer_1200_utc = datetime(2026, 7, 1, 12, 5, tzinfo=timezone.utc)  # 08:05 EDT
    winter_1200_utc = datetime(2026, 1, 15, 12, 5, tzinfo=timezone.utc)  # 07:05 EST — the EDT cron, on time
    winter_1300_utc = datetime(2026, 1, 15, 13, 5, tzinfo=timezone.utc)  # 08:05 EST
    assert should_run(summer_1200_utc, settings, None)[0] is True
    assert should_run(winter_1200_utc, settings, None)[0] is False
    assert should_run(winter_1300_utc, settings, None)[0] is True


def test_should_run_tolerates_scheduler_starting_hours_late():
    # GitHub starts the 12:00 UTC cron hours late (observed 14:08-21:34 UTC); the briefing is still owed.
    settings = load_settings({}, dotenv_path=None)
    for late in (datetime(2026, 10, 3, 15, 20, tzinfo=timezone.utc), datetime(2026, 8, 28, 21, 34, tzinfo=timezone.utc)):
        ok, reason = should_run(late, settings, None)
        assert ok, reason


def test_should_run_refuses_double_delivery():
    settings = load_settings({}, dotenv_path=None)
    now = datetime(2026, 7, 1, 12, 55, tzinfo=timezone.utc)  # 08:55 EDT
    ok, reason = should_run(now, settings, _delivered(now - timedelta(minutes=50)))
    assert not ok and "already delivered" in reason
    # the second cron of the day, hours after the first one delivered
    assert not should_run(now + timedelta(hours=5), settings, _delivered(now - timedelta(minutes=50)))[0]
    assert should_run(now, settings, _delivered(now - timedelta(hours=23)))[0]


def test_should_run_after_late_delivery_yesterday():
    # Yesterday's briefing went out late (17:34 EDT); today's cron starting 16.5h later must still deliver.
    settings = load_settings({}, dotenv_path=None)
    yesterday = _delivered(datetime(2026, 8, 28, 21, 34, tzinfo=timezone.utc))
    ok, reason = should_run(datetime(2026, 8, 29, 14, 8, tzinfo=timezone.utc), settings, yesterday)
    assert ok, reason


def test_costs_unpriced_when_pricing_missing():
    settings = load_settings({}, dotenv_path=None)
    cost = compute_costs(LLMUsage(calls=1, input_tokens=4000, output_tokens=500), sms_messages=1, sms_segments=9, settings=settings)
    assert cost.llm_cost_usd is None and cost.sms_cost_usd is None and cost.run_cost_usd is None
    report = format_cost_report(cost, sms_sent=False)
    assert "unpriced" in report and "Input tokens: 4,000" in report and "not sent" in report


def test_costs_priced_from_configuration():
    settings = load_settings({"LLM_INPUT_PRICE_PER_1M": "0.15", "LLM_OUTPUT_PRICE_PER_1M": "0.60", "SMS_PRICE_PER_SEGMENT": "0.0083"}, dotenv_path=None)
    cost = compute_costs(LLMUsage(calls=1, input_tokens=1_000_000, output_tokens=1_000_000), sms_messages=1, sms_segments=10, settings=settings)
    assert cost.llm_cost_usd == 0.75 and cost.sms_cost_usd == 0.083
    assert abs(cost.run_cost_usd - 0.833) < 1e-9 and abs(cost.monthly_estimate_usd - 24.99) < 1e-9
    assert "$0.8330" in format_cost_report(cost, sms_sent=True)


def test_template_provider_costs_zero():
    settings = load_settings({}, dotenv_path=None)
    cost = compute_costs(LLMUsage(), sms_messages=0, sms_segments=0, settings=settings)
    assert cost.run_cost_usd == 0.0 and cost.monthly_estimate_usd == 0.0
