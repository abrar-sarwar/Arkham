from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from arkham.config import load_settings
from arkham.costs import compute_costs, format_cost_report
from arkham.models import DeliveryStatus, LLMUsage, RunRecord
from arkham.schedule import (
    github_cron_lines,
    is_delivery_hour,
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


def test_should_run_gate_only_at_local_delivery_hour():
    settings = load_settings({}, dotenv_path=None)
    summer_1200_utc = datetime(2026, 7, 1, 12, 5, tzinfo=timezone.utc)  # 08:05 EDT
    summer_1300_utc = datetime(2026, 7, 1, 13, 5, tzinfo=timezone.utc)  # 09:05 EDT
    winter_1300_utc = datetime(2026, 1, 15, 13, 5, tzinfo=timezone.utc)  # 08:05 EST
    assert should_run(summer_1200_utc, settings, None)[0] is True
    assert should_run(summer_1300_utc, settings, None)[0] is False
    assert should_run(winter_1300_utc, settings, None)[0] is True
    assert is_delivery_hour(winter_1300_utc, NY, 8)


def test_should_run_refuses_double_delivery():
    settings = load_settings({}, dotenv_path=None)
    now = datetime(2026, 7, 1, 12, 5, tzinfo=timezone.utc)
    last = RunRecord(run_id="r1", mode="scheduled", started_at=now - timedelta(hours=1), finished_at=now - timedelta(minutes=50), status="success", delivery_status=DeliveryStatus.SENT)
    ok, reason = should_run(now, settings, last)
    assert not ok and "already delivered" in reason
    old = last.model_copy(update={"finished_at": now - timedelta(hours=23)})
    assert should_run(now, settings, old)[0]


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
