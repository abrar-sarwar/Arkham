"""Run cost accounting. Pricing is configuration, never a guess: unpriced items are reported as such."""

from __future__ import annotations

from arkham.config import Settings
from arkham.models import CostMetrics, LLMUsage


def compute_costs(
    usage: LLMUsage,
    *,
    sms_messages: int,
    sms_segments: int,
    settings: Settings,
    delivery_provider: str = "",
    delivery_messages: int = 0,
) -> CostMetrics:
    """LLM cost from configured unit prices; SMS from segments; Discord webhooks are free (0, priced)."""
    cost = CostMetrics(
        llm_calls=usage.calls,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        delivery_provider=delivery_provider or settings.delivery_provider,
        delivery_messages=delivery_messages,
        sms_messages=sms_messages,
        sms_segments=sms_segments,
    )
    if usage.calls == 0:
        cost.llm_cost_usd = 0.0
        cost.llm_priced = True
    elif settings.llm_input_price_per_1m is not None and settings.llm_output_price_per_1m is not None:
        cost.llm_cost_usd = (
            usage.input_tokens * settings.llm_input_price_per_1m + usage.output_tokens * settings.llm_output_price_per_1m
        ) / 1_000_000
        cost.llm_priced = True
    if sms_segments == 0:
        cost.sms_cost_usd = 0.0
        cost.sms_priced = True
    elif settings.sms_price_per_segment is not None:
        cost.sms_cost_usd = sms_segments * settings.sms_price_per_segment
        cost.sms_priced = True
    if cost.llm_priced and cost.sms_priced:
        cost.run_cost_usd = (cost.llm_cost_usd or 0.0) + (cost.sms_cost_usd or 0.0)
        cost.monthly_estimate_usd = cost.run_cost_usd * 30
    return cost


def _usd(value: float | None, priced: bool) -> str:
    if not priced or value is None:
        return "unpriced (set pricing in .env)"
    return f"${value:,.4f}"


def format_cost_report(cost: CostMetrics, *, sms_sent: bool) -> str:
    sent_note = "" if sms_sent else ", not sent"
    if cost.delivery_provider == "twilio":
        delivery_lines = [
            f"SMS messages: {cost.sms_messages} ({cost.sms_segments} segments{sent_note})",
            f"SMS cost: {_usd(cost.sms_cost_usd, cost.sms_priced)}",
        ]
    else:
        delivery_lines = [
            f"Discord webhook: {cost.delivery_messages} message(s){sent_note}",
            "Discord cost: $0.0000 (incoming webhooks are free)",
        ]
    lines = [
        "ARKHAM COST REPORT",
        f"LLM calls: {cost.llm_calls}",
        f"Input tokens: {cost.input_tokens:,}",
        f"Output tokens: {cost.output_tokens:,}",
        f"LLM cost: {_usd(cost.llm_cost_usd, cost.llm_priced)}",
        *delivery_lines,
        f"Estimated run cost: {_usd(cost.run_cost_usd, cost.llm_priced and cost.sms_priced)}",
        f"Estimated monthly cost at 1 run/day: {_usd(cost.monthly_estimate_usd, cost.llm_priced and cost.sms_priced)}",
        "Feeds/APIs: $0 (CISA, NVD, CERTs and vendor feeds are free)",
    ]
    return "\n".join(lines)
