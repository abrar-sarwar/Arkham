"""Pipeline orchestration: collect -> normalize -> enrich -> dedupe -> verify -> score -> select -> synthesize
-> validate -> render (per transport) -> deliver -> account.

The runner is the only module that touches every layer; each layer is independently testable.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from arkham.config import ConfigError, Settings
from arkham.costs import compute_costs
from arkham.http import SafeHttpClient
from arkham.models import (
    Briefing,
    CostMetrics,
    CyberEvent,
    DeliveryResult,
    DeliveryStatus,
    EventUpdate,
    EvidencePack,
    LLMUsage,
    RunRecord,
)
from arkham.schedule import recently_delivered
from arkham.storage.base import Storage

log = logging.getLogger(__name__)

MAX_WINDOW_HOURS = 168
WINDOW_OVERLAP = timedelta(hours=1)
MIN_SUCCESSFUL_SOURCES = 3
WATCH_ITEMS = 4


class InsufficientEvidence(Exception):
    """Raised when too few trustworthy sources succeeded to build a meaningful briefing."""


@dataclass
class RunOptions:
    dry_run: bool = False
    force: bool = False
    since_hours: int | None = None
    show_evidence: bool = False


@dataclass
class RunOutcome:
    run: RunRecord
    briefing: Briefing | None = None
    pack: EvidencePack | None = None
    cost: CostMetrics | None = None
    selected: list[CyberEvent] = field(default_factory=list)
    source_table: str = ""
    delivery: DeliveryResult | None = None

    @property
    def sent(self) -> bool:
        return self.delivery is not None and self.delivery.status == DeliveryStatus.SENT


def _run_id(now: datetime) -> str:
    return f"{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"


def compute_window(now: datetime, settings: Settings, last_delivered: RunRecord | None, since_hours: int | None) -> tuple[datetime, datetime]:
    """Window = since the last delivered briefing (with 1h overlap), capped, else the configured lookback."""
    if since_hours:
        return now - timedelta(hours=min(since_hours, MAX_WINDOW_HOURS)), now
    start = now - timedelta(hours=settings.lookback_hours)
    if last_delivered and last_delivered.window_end:
        candidate = last_delivered.window_end - WINDOW_OVERLAP
        if now - candidate <= timedelta(hours=MAX_WINDOW_HOURS):
            start = min(candidate, start) if candidate < start else candidate
    return start, now


@dataclass
class Components:
    """Pipeline stages as injectable callables (tests substitute fakes; production uses the real modules)."""

    enabled_sources: Callable[..., Any]
    collect_all: Callable[..., Any]
    format_source_table: Callable[..., str]
    normalize_items: Callable[..., Any]
    enrich_events: Callable[..., Any]
    is_security_relevant: Callable[..., bool]
    deduplicate: Callable[..., Any]
    assign_confidence: Callable[..., Any]
    reconcile_with_history: Callable[..., Any]
    score_event: Callable[..., Any]
    select_events: Callable[..., Any]
    date_label_for: Callable[..., str]
    build_evidence_pack: Callable[..., Any]
    build_model: Callable[..., Any]
    synthesize: Callable[..., Any]
    sanitize_learn: Callable[..., Any]
    validate_draft: Callable[..., list[str]]
    render_briefing: Callable[..., Any]  # (settings, draft, pack, *, generated_by, now) -> Briefing
    validate_rendered: Callable[..., list[str]]
    validate_recipient: Callable[..., list[str]]
    build_provider: Callable[..., Any]
    message_stats: Callable[..., Any]

    @classmethod
    def default(cls) -> Components:
        # Imported lazily so `check-config` and friends start even if an optional layer is broken.
        from arkham.delivery import build_provider, render_for_delivery
        from arkham.delivery.sms import message_stats
        from arkham.intelligence.brief import date_label_for
        from arkham.intelligence.deduplicate import deduplicate
        from arkham.intelligence.enrich import enrich_events, is_security_relevant
        from arkham.intelligence.llm import build_model
        from arkham.intelligence.normalize import normalize_items
        from arkham.intelligence.score import score_event
        from arkham.intelligence.synthesize import build_evidence_pack, synthesize
        from arkham.intelligence.verify import assign_confidence, reconcile_with_history, select_events
        from arkham.security.validation import (
            sanitize_learn,
            validate_draft,
            validate_recipient,
            validate_rendered,
        )
        from arkham.sources.collector import collect_all, format_source_table
        from arkham.sources.registry import enabled_sources

        return cls(
            enabled_sources=enabled_sources,
            collect_all=collect_all,
            format_source_table=format_source_table,
            normalize_items=normalize_items,
            enrich_events=enrich_events,
            is_security_relevant=is_security_relevant,
            deduplicate=deduplicate,
            assign_confidence=assign_confidence,
            reconcile_with_history=reconcile_with_history,
            score_event=score_event,
            select_events=select_events,
            date_label_for=date_label_for,
            build_evidence_pack=build_evidence_pack,
            build_model=build_model,
            synthesize=synthesize,
            sanitize_learn=sanitize_learn,
            validate_draft=validate_draft,
            render_briefing=render_for_delivery,
            validate_rendered=validate_rendered,
            validate_recipient=validate_recipient,
            build_provider=build_provider,
            message_stats=message_stats,
        )


class ValidationFailure(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def execute_run(
    settings: Settings,
    options: RunOptions,
    *,
    storage: Storage,
    now: datetime | None = None,
    components: Components | None = None,
) -> RunOutcome:
    """Run the full pipeline once. Never sends unless validation passes and ``options.dry_run`` is False."""
    c = components or Components.default()
    now = now or datetime.now(timezone.utc)
    mode = "dry-run" if options.dry_run else ("force" if options.force else "scheduled")
    started = time.monotonic()
    run = RunRecord(run_id=_run_id(now), mode=mode, started_at=now)
    outcome = RunOutcome(run=run)
    storage.save_run(run)
    log.info("run %s started (mode=%s)", run.run_id, mode)

    http = SafeHttpClient(timeout_seconds=settings.http_timeout_seconds, max_bytes=settings.http_max_bytes, user_agent=settings.user_agent)
    try:
        # ---- fail fast on configuration the run will need later (before spending network/LLM budget)
        llm_problems = settings.validate_llm()
        if llm_problems:
            raise ConfigError("LLM configuration incomplete:\n  - " + "\n  - ".join(llm_problems))
        if not options.dry_run:
            delivery_problems = settings.validate_delivery()
            if delivery_problems:
                raise ConfigError("Delivery configuration incomplete:\n  - " + "\n  - ".join(delivery_problems))
            last_delivered = storage.get_last_successful_run(delivered_only=True)
            if recently_delivered(last_delivered, now) and not options.force:
                raise ConfigError("A briefing was already delivered in the last 20 hours; use --force to send another.")

        # ---- window
        last_delivered = storage.get_last_successful_run(delivered_only=True)
        run.window_start, run.window_end = compute_window(now, settings, last_delivered, options.since_hours)
        log.info("collection window %s -> %s", run.window_start.isoformat(timespec="minutes"), run.window_end.isoformat(timespec="minutes"))

        # ---- collect
        sources = c.enabled_sources(settings.disabled_sources)
        collection = c.collect_all(
            sources,
            http=http,
            storage=storage,
            window_start=run.window_start,
            window_end=run.window_end,
            now=now,
            nvd_api_key=settings.nvd_api_key,
        )
        run.source_statuses = collection.statuses
        run.sources_checked = len(collection.statuses)
        run.sources_successful = sum(1 for s in collection.statuses if s.ok)
        run.raw_items = len(collection.items)
        outcome.source_table = c.format_source_table(collection.statuses)
        new_raw = storage.save_raw_items(collection.items, run.run_id)
        log.info("collected %d raw items (%d new) from %d/%d sources", run.raw_items, new_raw, run.sources_successful, run.sources_checked)
        if run.sources_successful < MIN_SUCCESSFUL_SOURCES:
            raise InsufficientEvidence(
                f"only {run.sources_successful}/{run.sources_checked} sources succeeded; refusing to build a briefing from insufficient evidence"
            )

        # ---- normalize, enrich, dedupe
        events = c.normalize_items(collection.items)
        run.normalized_items = len(events)
        events = c.enrich_events(events, collection.extra.get("kev_catalog"), now)
        relevant = [e for e in events if c.is_security_relevant(e)]
        off_topic = len(events) - len(relevant)
        run.off_topic_items = off_topic
        relevant_count = len(relevant)
        events = c.deduplicate(relevant, now=now)
        run.duplicates_removed = max(0, relevant_count - len(events))
        run.correlated_events = len(events)
        run.unique_events = len(events)
        log.info("normalized %d items -> %d relevant -> %d unique events (%d off-topic dropped)", len(collection.items), len(relevant), len(events), off_topic)

        # ---- verify, history, score (dry runs never mutate intelligence state)
        for event in events:
            c.assign_confidence(event)
            previous = storage.get_event(event.id)
            c.reconcile_with_history(event, previous, now=now)
            c.score_event(event, now=now)
            if not options.dry_run:
                storage.upsert_event(event, run.run_id, now)
                if event.material_update:
                    storage.add_event_update(
                        EventUpdate(
                            event_id=event.id,
                            run_id=run.run_id,
                            occurred_at=now,
                            description=event.material_update,
                            old_fingerprint=previous.fingerprint if previous else None,
                            new_fingerprint=event.fingerprint,
                        )
                    )
        run.events_scored = len(events)

        # ---- select
        selection = c.select_events(events, max_events=settings.max_events, min_priority=settings.min_priority_score, now=now)
        run.candidate_events = len(selection.candidates)
        run.events_selected = len(selection.selected)
        outcome.selected = selection.selected
        log.info(
            "candidates %d, selected %d (suppressed already-briefed %d, below threshold %d)",
            len(selection.candidates), len(selection.selected), selection.suppressed_briefed, selection.below_threshold,
        )

        # ---- evidence pack (quiet day -> watch items from the best sub-threshold events)
        quiet = not selection.selected
        pack_events = selection.selected
        if quiet:
            eligible = [e for e in events if not (e.previously_briefed and not e.material_update)]
            pack_events = sorted(eligible, key=lambda e: e.final_priority_score, reverse=True)[:WATCH_ITEMS]
        pack = c.build_evidence_pack(
            pack_events,
            date_label=c.date_label_for(now, settings.tzinfo),
            sources_checked=run.sources_checked,
            sources_ok=run.sources_successful,
            events_analyzed=len(events),
            max_events=settings.max_events,
            max_chars=settings.brief_char_budget,
            quiet=quiet,
        )
        outcome.pack = pack
        run.evidence_items = len(pack.items)

        # ---- synthesize (one model call) and validate (fail closed)
        model = c.build_model(settings, http)
        output = c.synthesize(pack, model)
        usage: LLMUsage = output.usage
        run.llm_calls, run.llm_tokens_in, run.llm_tokens_out = usage.calls, usage.input_tokens, usage.output_tokens
        draft = output.draft
        notes = c.sanitize_learn(draft, pack)
        problems = c.validate_draft(draft, pack, max_events=settings.max_events)
        if problems:
            raise ValidationFailure(list(problems))
        briefing = c.render_briefing(settings, draft, pack, generated_by=model.label, now=now)
        if notes:
            briefing.validation_notes.extend(notes if isinstance(notes, list) else [str(notes)])
        problems = c.validate_rendered(briefing, pack, max_chars=settings.rendered_size_limit)
        if problems:
            raise ValidationFailure(list(problems))
        outcome.briefing = briefing
        rendered_event_ids = [
            pack.refs[item.ref].event_id
            for item in briefing.draft.items
            if item.ref in pack.refs
        ]
        selected_by_id = {event.id: event for event in selection.selected}
        outcome.selected = [selected_by_id[event_id] for event_id in rendered_event_ids if event_id in selected_by_id]
        run.events_selected = len(outcome.selected)
        run.briefing_chars = len(briefing.text)
        run.briefing_messages = len(briefing.messages)
        run.briefing_hash = hashlib.sha256(briefing.text.encode("utf-8")).hexdigest()

        # ---- cost accounting (SMS segments only exist for the legacy Twilio transport)
        sms_segments = c.message_stats(briefing.messages).segments if settings.delivery_is_sms else 0
        run.sms_segments = sms_segments
        run.delivery_provider = settings.delivery_provider
        run.delivery_messages = len(briefing.messages)
        outcome.cost = compute_costs(
            usage,
            sms_messages=len(briefing.messages) if settings.delivery_is_sms else 0,
            sms_segments=sms_segments,
            settings=settings,
            delivery_provider=settings.delivery_provider,
            delivery_messages=len(briefing.messages),
        )
        run.estimated_llm_cost = outcome.cost.llm_cost_usd
        run.cost = outcome.cost

        # ---- deliver
        if options.dry_run:
            run.delivery_status = DeliveryStatus.DRY_RUN
            outcome.delivery = DeliveryResult(
                status=DeliveryStatus.DRY_RUN, provider="none", recipient_masked=settings.recipient_masked
            )
            run.status = "success"
        else:
            provider = c.build_provider(settings, http)
            recipient_problems = c.validate_recipient(settings, provider.recipient_masked)
            if recipient_problems:
                raise ValidationFailure(list(recipient_problems))
            result = provider.deliver(briefing)
            outcome.delivery = result
            run.delivery_status = result.status
            run.delivery_provider = result.provider or settings.delivery_provider
            run.delivery_messages = result.messages_sent
            run.delivery_attempts = result.attempts
            run.sms_segments = result.segments if result.segments else sms_segments
            storage.record_delivery(run.run_id, result, run.briefing_hash, now)
            if result.status == DeliveryStatus.SENT:
                storage.mark_briefed(rendered_event_ids, run.run_id, now)
                run.status = "success"
                log.info(
                    "briefing delivered via %s to %s (%d message(s), %d attempt(s))",
                    result.provider, result.recipient_masked, result.messages_sent, result.attempts,
                )
            else:
                run.status = "failed"
                run.error = f"delivery failed: {result.error}"
                log.error("delivery failed: %s", result.error)
    except ValidationFailure as exc:
        run.status = "no-send"
        run.delivery_status = DeliveryStatus.BLOCKED_VALIDATION
        run.error = "validation blocked delivery: " + "; ".join(exc.problems)
        log.error(run.error)
    except (ConfigError, InsufficientEvidence) as exc:
        run.status = "failed"
        run.error = str(exc)
        log.error("run aborted: %s", exc)
    except Exception as exc:  # noqa: BLE001 - record and surface, never send
        run.status = "failed"
        run.error = f"{exc.__class__.__name__}: {exc}"
        log.exception("run failed")
    finally:
        http.close()
        run.finished_at = now + timedelta(seconds=time.monotonic() - started)
        storage.save_run(run)
    return outcome


def format_run_summary(run: RunRecord) -> str:
    lines = [
        "Arkham Run",
        f"Run id: {run.run_id} ({run.mode})",
        f"Status: {run.status}" + (f" — {run.error}" if run.error else ""),
        f"Window: {run.window_start.isoformat(timespec='minutes') if run.window_start else '?'} -> {run.window_end.isoformat(timespec='minutes') if run.window_end else '?'}",
        f"Sources: {run.sources_successful}/{run.sources_checked}",
        f"Raw: {run.raw_items}",
        f"Normalized: {run.normalized_items}",
        f"Duplicates removed: {run.duplicates_removed}",
        f"Unique: {run.unique_events}",
        f"Evidence items: {run.evidence_items}",
        f"Candidates: {run.candidate_events}",
        f"Selected: {run.events_selected}",
        f"Briefing: {run.briefing_chars} chars ({run.briefing_messages} messages)",
        f"LLM calls: {run.llm_calls} ({run.llm_tokens_in} in / {run.llm_tokens_out} out tokens)",
        _delivery_line(run),
    ]
    return "\n".join(lines)


def _delivery_line(run: RunRecord) -> str:
    provider = run.delivery_provider or "delivery"
    detail = f"{run.delivery_messages} message(s), {run.delivery_attempts} attempt(s)"
    if run.delivery_provider == "twilio" or run.sms_segments:
        detail += f", {run.sms_segments} SMS segment(s)"
    return f"Delivery: {provider} {run.delivery_status.value} ({detail})"
