"""Runner safety behaviour with in-memory fakes: dry-run never sends or mutates, validation blocks delivery,
insufficient sources abort, re-delivery guard, --force, delivery failure handling, quiet days."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from arkham.config import load_settings, mask_webhook_url
from arkham.models import (
    Briefing,
    BriefingDraft,
    BriefItem,
    BriefSection,
    Confidence,
    CyberEvent,
    DeliveryResult,
    DeliveryStatus,
    EventType,
    EventUpdate,
    EvidenceItem,
    EvidencePack,
    EvidenceSource,
    LLMUsage,
    ModelOutput,
    RawItem,
    RunRecord,
    SourceCategory,
    SourceState,
    SourceStatus,
    SourceTier,
    StoredEvent,
)
from arkham.runner import Components, RunOptions, execute_run
from arkham.storage.base import Storage

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz0123"
WEBHOOK_MASKED = mask_webhook_url(WEBHOOK)
FULL_ENV = {
    "DISCORD_WEBHOOK_URL": WEBHOOK,
    "LLM_PROVIDER": "template",
}


class MemoryStorage(Storage):
    def __init__(self) -> None:
        self.source_state: dict[str, SourceState] = {}
        self.raw: dict[str, RawItem] = {}
        self.events: dict[str, StoredEvent] = {}
        self.updates: list[EventUpdate] = []
        self.briefed: list[tuple[list[str], str]] = []
        self.runs: dict[str, RunRecord] = {}
        self.deliveries: list[dict] = []

    def initialize(self) -> None: ...
    def close(self) -> None: ...
    def get_source_state(self, source_id): return self.source_state.get(source_id)
    def save_source_state(self, state): self.source_state[state.source_id] = state
    def raw_hash_known(self, raw_hash): return raw_hash in self.raw
    def save_raw_items(self, items, run_id):
        new = [i for i in items if i.raw_hash not in self.raw]
        for i in new:
            self.raw[i.raw_hash] = i
        return len(new)
    def get_event(self, event_id): return self.events.get(event_id)
    def upsert_event(self, event, run_id, seen_at):
        prev = self.events.get(event.id)
        stored = StoredEvent(event=event, first_seen=prev.first_seen if prev else seen_at, last_seen=seen_at,
                             times_briefed=prev.times_briefed if prev else 0, last_briefed_at=prev.last_briefed_at if prev else None,
                             fingerprint=event.fingerprint)
        self.events[event.id] = stored
        return stored
    def add_event_update(self, update): self.updates.append(update)
    def get_event_updates(self, event_id): return [u for u in self.updates if u.event_id == event_id]
    def mark_briefed(self, event_ids, run_id, briefed_at):
        self.briefed.append((list(event_ids), run_id))
        for eid in event_ids:
            if eid in self.events:
                self.events[eid].times_briefed += 1
    def search_events(self, query, *, limit=20, since=None): return []
    def save_run(self, run): self.runs[run.run_id] = run.model_copy(deep=True)
    def get_run(self, run_id): return self.runs.get(run_id)
    def get_last_successful_run(self, *, delivered_only=False):
        runs = [r for r in self.runs.values() if r.status == "success" and (not delivered_only or r.delivery_status == DeliveryStatus.SENT)]
        return max(runs, key=lambda r: r.started_at) if runs else None
    def list_runs(self, limit=20): return sorted(self.runs.values(), key=lambda r: r.started_at, reverse=True)[:limit]
    def record_delivery(self, run_id, result, briefing_hash, sent_at):
        self.deliveries.append({"run_id": run_id, "status": result.status.value, "hash": briefing_hash})
    def list_deliveries(self, limit=20): return self.deliveries[-limit:]


def make_item(i: int) -> RawItem:
    return RawItem(source_id=f"src{i}", source_name=f"Source {i}", source_tier=SourceTier.PRIMARY, source_category=SourceCategory.ADVISORY,
                   title=f"Item {i}", url=f"https://example.org/item-{i}", summary="summary", published_at=NOW - timedelta(hours=2))


def make_event(i: int, score: float = 80.0) -> CyberEvent:
    return CyberEvent(id=f"ev{i}", title=f"Event {i}", summary="Something happened.", event_type=EventType.VULNERABILITY,
                      source_name="CISA", source_url=f"https://www.cisa.gov/e{i}", source_tier=SourceTier.PRIMARY, publisher="CISA",
                      published_at=NOW - timedelta(hours=3), final_priority_score=score, cves=[f"CVE-2026-{1000 + i}"])


@dataclass
class FakeProvider:
    recipient_masked: str = WEBHOOK_MASKED
    sent: list[list[str]] = field(default_factory=list)
    fail: bool = False
    name: str = "fake"

    def deliver(self, briefing):
        self.sent.append(list(briefing.messages))
        if self.fail:
            return DeliveryResult(status=DeliveryStatus.FAILED, provider="fake", recipient_masked=self.recipient_masked, error="carrier rejected", attempts=4)
        return DeliveryResult(status=DeliveryStatus.SENT, provider="fake", recipient_masked=self.recipient_masked, message_ids=["SM1"], messages_sent=len(briefing.messages), segments=9, attempts=1)

    def deliver_notice(self, text):
        self.sent.append([text])
        return DeliveryResult(status=DeliveryStatus.SENT, provider="fake", recipient_masked=self.recipient_masked, messages_sent=1, attempts=1)


@dataclass
class Harness:
    provider: FakeProvider
    calls: dict[str, int]
    components: Components


def build_components(*, ok_sources: int = 5, events: list[CyberEvent] | None = None, select_all: bool = True,
                     draft_problems: list[str] | None = None, provider: FakeProvider | None = None) -> Harness:
    provider = provider or FakeProvider()
    events = events if events is not None else [make_event(1), make_event(2)]
    calls: dict[str, int] = {"model": 0, "collect": 0}

    def collect_all(sources, **kw):
        calls["collect"] += 1
        statuses = [SourceStatus(source_id=f"s{i}", name=f"S{i}", ok=i < ok_sources, status="OK" if i < ok_sources else "TIMEOUT", items=1) for i in range(6)]
        return SimpleNamespace(items=[make_item(i) for i in range(6)], statuses=statuses, extra={"kev_catalog": {}}, elapsed_ms=10)

    def select_events(evs, *, max_events, min_priority, now):
        chosen = [e for e in evs if select_all and e.final_priority_score >= min_priority][:max_events]
        return SimpleNamespace(candidates=list(evs), selected=chosen, suppressed_briefed=0, below_threshold=0, off_topic=0)

    def build_pack(evs, *, date_label, sources_checked, sources_ok, events_analyzed, max_events, max_chars, quiet=False):
        items = [EvidenceItem(ref=f"E{i+1}", event_id=e.id, title=e.title, summary=e.summary, event_type=e.event_type,
                              sources=[EvidenceSource(label="CISA", url=e.source_url, tier=SourceTier.PRIMARY)], cves=e.cves,
                              confidence=Confidence.CONFIRMED) for i, e in enumerate(evs)]
        return EvidencePack(date_label=date_label, items=items, sources_checked=sources_checked, sources_ok=sources_ok,
                            events_analyzed=events_analyzed, max_events=max_events, max_chars=max_chars, quiet=quiet)

    def synthesize(pack, model):
        calls["model"] += 1
        items = [BriefItem(ref=it.ref, section=BriefSection.CRITICAL, headline=it.title, why_it_matters="Patch it.",
                           confidence=Confidence.CONFIRMED, source_label="CISA", source_url=it.sources[0].url) for it in pack.items]
        return ModelOutput(draft=BriefingDraft(items=items, prep=["Patch"], watch=["w1", "w2"]), raw_text="{}", usage=LLMUsage(provider="fake", calls=1, input_tokens=100, output_tokens=20))

    def render(settings, draft, pack, *, generated_by, now):
        text = f"ARKHAM // {pack.date_label}\n" + "\n".join(i.headline for i in draft.items)
        evidence = [pack.refs[i.ref] for i in draft.items if i.ref in pack.refs]
        return Briefing(date_label=pack.date_label, draft=draft, evidence=evidence, text=text, messages=[text], quiet=pack.quiet, generated_by=generated_by)

    comps = Components(
        enabled_sources=lambda disabled: ["s"] * 6,
        collect_all=collect_all,
        format_source_table=lambda statuses: "table",
        normalize_items=lambda items: list(events),
        enrich_events=lambda evs, cat, now: evs,
        is_security_relevant=lambda e: True,
        deduplicate=lambda evs, now: evs,
        assign_confidence=lambda e: e,
        reconcile_with_history=lambda e, prev, now: e,
        score_event=lambda e, now: e,
        select_events=select_events,
        date_label_for=lambda now, tz: "AUG 26",
        build_evidence_pack=build_pack,
        build_model=lambda settings, http: SimpleNamespace(label="fake:model"),
        synthesize=synthesize,
        sanitize_learn=lambda draft, pack: [],
        validate_draft=lambda draft, pack, max_events: list(draft_problems or []),
        render_briefing=render,
        validate_rendered=lambda briefing, pack, max_chars: [],
        validate_recipient=lambda settings, masked: [] if masked == WEBHOOK_MASKED else ["recipient mismatch"],
        build_provider=lambda settings, http: provider,
        message_stats=lambda parts: SimpleNamespace(messages=len(parts), segments=9, chars=sum(map(len, parts)), encoding="UCS-2"),
    )
    return Harness(provider=provider, calls=calls, components=comps)


def test_dry_run_generates_brief_but_never_sends_or_mutates_state():
    settings = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)  # no delivery config at all
    storage = MemoryStorage()
    h = build_components()
    outcome = execute_run(settings, RunOptions(dry_run=True), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "success"
    assert outcome.run.delivery_status == DeliveryStatus.DRY_RUN
    assert outcome.briefing is not None and outcome.briefing.text.startswith("ARKHAM // AUG 26")
    assert h.provider.sent == []
    assert storage.events == {} and storage.briefed == [] and storage.deliveries == []
    assert storage.get_last_successful_run(delivered_only=True) is None
    assert outcome.run.raw_items == 6 and outcome.run.sources_successful == 5 and outcome.run.events_selected == 2
    assert outcome.run.normalized_items == 2
    assert outcome.run.off_topic_items == 0
    assert outcome.run.duplicates_removed == 0
    assert outcome.run.correlated_events == 2
    assert outcome.run.events_scored == 2
    assert outcome.run.evidence_items == 2
    assert outcome.run.briefing_chars == len(outcome.briefing.text)
    assert outcome.run.briefing_messages == len(outcome.briefing.messages)
    assert outcome.cost is not None and outcome.cost.llm_calls == 1


def test_live_run_sends_once_marks_briefed_and_records_delivery():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    storage = MemoryStorage()
    h = build_components()
    outcome = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "success" and outcome.sent
    assert len(h.provider.sent) == 1 and h.provider.sent[0][0].startswith("ARKHAM // AUG 26")
    assert storage.briefed == [(["ev1", "ev2"], outcome.run.run_id)]
    assert storage.events["ev1"].times_briefed == 1
    assert storage.deliveries[0]["status"] == "sent" and storage.deliveries[0]["hash"] == outcome.run.briefing_hash
    assert storage.get_last_successful_run(delivered_only=True).run_id == outcome.run.run_id
    assert outcome.run.sms_segments == 9
    assert outcome.run.delivery_provider == "fake"
    assert outcome.run.delivery_messages == 1 and outcome.run.delivery_attempts == 1
    assert outcome.cost is not None and outcome.cost.delivery_provider == "discord" and outcome.cost.delivery_messages == 1


def test_live_run_marks_only_rendered_event_cards_as_briefed():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    storage = MemoryStorage()
    h = build_components()
    original_render = h.components.render_briefing

    def render_one(settings, draft, pack, **kwargs):
        rendered = original_render(settings, draft, pack, **kwargs)
        rendered.draft = draft.model_copy(update={"items": draft.items[:1]})
        return rendered

    h.components.render_briefing = render_one
    outcome = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "success"
    assert outcome.run.events_selected == 1
    assert [event.id for event in outcome.selected] == ["ev1"]
    assert storage.briefed == [(["ev1"], outcome.run.run_id)]


def test_validation_failure_blocks_delivery_and_is_recorded():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    storage = MemoryStorage()
    h = build_components(draft_problems=["item E1 cites URL not in evidence"])
    outcome = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "no-send"
    assert outcome.run.delivery_status == DeliveryStatus.BLOCKED_VALIDATION
    assert "URL not in evidence" in outcome.run.error
    assert h.provider.sent == [] and storage.briefed == []
    assert storage.get_run(outcome.run.run_id).status == "no-send"


def test_insufficient_sources_aborts_before_model_call():
    settings = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)
    h = build_components(ok_sources=2)
    outcome = execute_run(settings, RunOptions(dry_run=True), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "failed" and "insufficient evidence" in outcome.run.error
    assert h.calls["model"] == 0 and outcome.briefing is None


def test_missing_llm_config_fails_before_collection():
    settings = load_settings({"LLM_PROVIDER": "openai"}, dotenv_path=None)
    h = build_components()
    outcome = execute_run(settings, RunOptions(dry_run=True), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "failed" and "LLM_MODEL" in outcome.run.error
    assert h.calls["collect"] == 0


def test_missing_delivery_config_blocks_live_run_but_not_dry_run():
    settings = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)
    h = build_components()
    live = execute_run(settings, RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert live.run.status == "failed" and "DISCORD_WEBHOOK_URL" in live.run.error and h.calls["collect"] == 0
    dry = execute_run(settings, RunOptions(dry_run=True), storage=MemoryStorage(), now=NOW, components=h.components)
    assert dry.run.status == "success"


def test_redelivery_guard_and_force():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    storage = MemoryStorage()
    h = build_components()
    first = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert first.sent
    second = execute_run(settings, RunOptions(), storage=storage, now=NOW + timedelta(hours=2), components=h.components)
    assert second.run.status == "failed" and "already delivered" in second.run.error and len(h.provider.sent) == 1
    forced = execute_run(settings, RunOptions(force=True), storage=storage, now=NOW + timedelta(hours=2), components=h.components)
    assert forced.sent and forced.run.mode == "force" and len(h.provider.sent) == 2
    tomorrow = execute_run(settings, RunOptions(), storage=storage, now=NOW + timedelta(hours=24), components=h.components)
    assert tomorrow.sent and tomorrow.run.window_start == forced.run.window_end - timedelta(hours=1)


def test_delivery_failure_is_recorded_and_events_not_marked_briefed():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    storage = MemoryStorage()
    h = build_components(provider=FakeProvider(fail=True))
    outcome = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "failed" and "carrier rejected" in outcome.run.error
    assert outcome.run.delivery_status == DeliveryStatus.FAILED
    assert outcome.run.delivery_attempts == 4 and outcome.run.delivery_messages == 0
    assert storage.briefed == [] and storage.deliveries[0]["status"] == "failed"


def test_recipient_mismatch_blocks_send():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    h = build_components(provider=FakeProvider(recipient_masked="https://discord.com/api/webhooks/9999****9999/***"))
    outcome = execute_run(settings, RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "no-send" and "recipient mismatch" in outcome.run.error
    assert h.provider.sent == []


def test_quiet_day_builds_watch_pack_from_best_events():
    settings = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)
    events = [make_event(1, score=20.0), make_event(2, score=10.0)]
    h = build_components(events=events, select_all=False)
    outcome = execute_run(settings, RunOptions(dry_run=True), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "success" and outcome.run.events_selected == 0
    assert outcome.pack is not None and outcome.pack.quiet and [i.event_id for i in outcome.pack.items] == ["ev1", "ev2"]


def test_unexpected_exception_is_recorded_and_nothing_sent():
    settings = load_settings(FULL_ENV, dotenv_path=None)
    h = build_components()

    def boom(*a, **k):
        raise RuntimeError("dedupe exploded")

    h.components.deduplicate = boom
    outcome = execute_run(settings, RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "failed" and "dedupe exploded" in outcome.run.error
    assert h.provider.sent == [] and outcome.run.finished_at is not None


@pytest.mark.parametrize("since,expected_hours", [(6, 6), (500, 168)])
def test_since_override_and_cap(since, expected_hours):
    settings = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)
    h = build_components()
    outcome = execute_run(settings, RunOptions(dry_run=True, since_hours=since), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.window_start == NOW - timedelta(hours=expected_hours)
