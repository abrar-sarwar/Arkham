"""End-to-end runner/storage/CLI behaviour with the Discord transport (mocked HTTP, no network)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from arkham import cli
from arkham.config import load_settings
from arkham.costs import compute_costs, format_cost_report
from arkham.delivery import render_for_delivery
from arkham.delivery.discord_webhook import DiscordWebhookProvider
from arkham.http import SafeHttpClient
from arkham.intelligence.llm.template import TemplateModel
from arkham.models import Briefing, BriefingDraft, DeliveryResult, DeliveryStatus, LLMUsage, RunRecord
from arkham.runner import RunOptions, execute_run, format_run_summary
from arkham.security.validation import validate_recipient, validate_rendered
from arkham.storage import open_storage
from tests.test_discord_webhook import WEBHOOK, WEBHOOK_ID, WEBHOOK_TOKEN, Recorder
from tests.test_runner import NOW, MemoryStorage, build_components, make_event
from tests.test_synthesize import build_pack, citrix_kev_event, gitea_event

DISCORD_ENV = {"DISCORD_WEBHOOK_URL": WEBHOOK, "LLM_PROVIDER": "template"}
TWILIO_ENV = {
    "ARKHAM_DELIVERY_PROVIDER": "twilio",
    "ARKHAM_TO_PHONE": "+12025550143",
    "TWILIO_ACCOUNT_SID": "AC" + "a" * 32,
    "TWILIO_AUTH_TOKEN": "t" * 32,
    "TWILIO_FROM_PHONE": "+12025550199",
    "LLM_PROVIDER": "template",
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    from arkham.delivery import discord_webhook

    monkeypatch.setattr(discord_webhook, "_sleep", lambda _s: None)


def real_discord_harness(recorder: Recorder, **kwargs):
    """Runner harness whose delivery stages are the real Discord renderer/validators/provider."""
    h = build_components(**kwargs)
    h.components.render_briefing = render_for_delivery
    h.components.validate_rendered = validate_rendered
    h.components.validate_recipient = validate_recipient
    h.components.build_provider = lambda settings, http: DiscordWebhookProvider(webhook_url=WEBHOOK, http=recorder.client())
    return h


# ---------------------------------------------------------------------------- rendering dispatch


def test_render_for_delivery_dispatches_on_transport() -> None:
    pack = build_pack([citrix_kev_event(), gitea_event()])
    draft = TemplateModel().synthesize(pack).draft
    discord = render_for_delivery(load_settings(DISCORD_ENV, dotenv_path=None), draft, pack, generated_by="template", now=NOW)
    sms = render_for_delivery(load_settings(TWILIO_ENV, dotenv_path=None), draft, pack, generated_by="template", now=NOW)
    assert discord.text.startswith("**ARKHAM**") and discord.title.endswith("Intelligence Brief")
    assert len(discord.draft.items) == 2 and [e.ref for e in discord.evidence] == ["E1", "E2"]
    assert sms.text.startswith("ARKHAM // AUG 26") and len(sms.text) <= 900
    assert all(len(part) <= 900 for part in sms.messages)
    assert [e.ref for e in sms.evidence] == [i.ref for i in sms.draft.items]


def test_discord_brief_budget_is_not_the_sms_budget() -> None:
    discord = load_settings(DISCORD_ENV, dotenv_path=None)
    twilio = load_settings(TWILIO_ENV, dotenv_path=None)
    assert discord.brief_char_budget > 900 and discord.rendered_size_limit is None
    assert twilio.brief_char_budget == 900 and twilio.rendered_size_limit == 900


# ---------------------------------------------------------------------------- validation


def test_validate_rendered_without_size_limit_still_checks_grounding() -> None:
    pack = build_pack([citrix_kev_event()])
    draft = TemplateModel().synthesize(pack).draft
    briefing = render_for_delivery(load_settings(DISCORD_ENV, dotenv_path=None), draft, pack, generated_by="template", now=NOW)
    assert validate_rendered(briefing, pack, max_chars=None) == []
    assert len(briefing.text) > 900  # would have failed the SMS limit
    briefing.text += "\nCVE-2026-99999 https://attacker.example/fake"
    problems = validate_rendered(briefing, pack, max_chars=None)
    assert any("CVE-2026-99999" in p for p in problems) and any("attacker.example" in p for p in problems)


def test_validate_recipient_compares_masked_webhook() -> None:
    settings = load_settings(DISCORD_ENV, dotenv_path=None)
    assert validate_recipient(settings, settings.recipient_masked) == []
    assert validate_recipient(settings, "https://discord.com/api/webhooks/9999****9999/***") == [
        "delivery provider destination does not match the configured DISCORD_WEBHOOK_URL"
    ]
    twilio = load_settings(TWILIO_ENV, dotenv_path=None)
    assert validate_recipient(twilio, "+1******0143") == []
    assert validate_recipient(twilio, "+1******9999") == ["delivery provider destination does not match the configured ARKHAM_TO_PHONE"]


# ---------------------------------------------------------------------------- runner


def test_dry_run_with_discord_config_never_posts() -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder)
    outcome = execute_run(load_settings(DISCORD_ENV, dotenv_path=None), RunOptions(dry_run=True), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "success" and outcome.run.delivery_status == DeliveryStatus.DRY_RUN
    assert recorder.requests == []
    assert outcome.briefing is not None and outcome.briefing.text.startswith("**ARKHAM**")
    assert outcome.delivery is not None and WEBHOOK_TOKEN not in outcome.delivery.recipient_masked


def test_live_run_delivers_through_discord_and_records_safe_metadata() -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder)
    storage = MemoryStorage()
    outcome = execute_run(load_settings(DISCORD_ENV, dotenv_path=None), RunOptions(), storage=storage, now=NOW, components=h.components)
    assert outcome.run.status == "success" and outcome.sent
    assert len(recorder.requests) == 1
    body = json.loads(recorder.requests[0].content)
    assert body["allowed_mentions"] == {"parse": []}
    assert body["content"].startswith("**ARKHAM**")
    assert [e["author"]["name"] for e in body["embeds"] if "author" in e] == ["CRITICAL", "CRITICAL"]
    run = outcome.run
    assert run.delivery_provider == "discord"
    assert run.delivery_messages == 1 == run.briefing_messages
    assert run.delivery_attempts == 1
    assert run.sms_segments == 0
    assert run.delivery_status == DeliveryStatus.SENT
    assert storage.briefed == [(["ev1", "ev2"], run.run_id)]
    dumped = run.model_dump_json() + json.dumps(storage.deliveries)
    assert WEBHOOK_TOKEN not in dumped and WEBHOOK_ID not in dumped
    assert outcome.delivery is not None and outcome.delivery.message_ids == ["msg1"]
    assert outcome.cost is not None and outcome.cost.delivery_provider == "discord" and outcome.cost.sms_segments == 0
    assert "Delivery: discord sent (1 message(s), 1 attempt(s))" in format_run_summary(run)


def test_rerun_inside_guard_window_does_not_post_again() -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder)
    storage = MemoryStorage()
    settings = load_settings(DISCORD_ENV, dotenv_path=None)
    first = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert first.sent and len(recorder.requests) == 1
    rerun = execute_run(settings, RunOptions(), storage=storage, now=NOW + timedelta(minutes=5), components=h.components)
    assert rerun.run.status == "failed" and "already delivered" in rerun.run.error
    assert len(recorder.requests) == 1  # nothing else was posted
    tomorrow = execute_run(settings, RunOptions(), storage=storage, now=NOW + timedelta(hours=24), components=h.components)
    assert tomorrow.sent and len(recorder.requests) == 2


def test_failed_delivery_is_recorded_and_a_rerun_delivers_exactly_once() -> None:
    recorder = Recorder([(503, {}, b"down")] * 4)
    h = real_discord_harness(recorder)
    storage = MemoryStorage()
    settings = load_settings(DISCORD_ENV, dotenv_path=None)
    failed = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
    assert failed.run.status == "failed" and failed.run.delivery_status == DeliveryStatus.FAILED
    assert "503" in failed.run.error and WEBHOOK_TOKEN not in failed.run.error
    assert failed.run.delivery_attempts == 4 and failed.run.delivery_messages == 0
    assert storage.briefed == [] and storage.deliveries[-1]["status"] == "failed"
    assert len(recorder.requests) == 4
    rerun = execute_run(settings, RunOptions(), storage=storage, now=NOW + timedelta(minutes=10), components=h.components)
    assert rerun.sent and len(recorder.requests) == 5
    assert storage.briefed == [(["ev1", "ev2"], rerun.run.run_id)]


def test_quiet_run_sends_one_short_message() -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder, events=[make_event(1, score=20.0), make_event(2, score=10.0)], select_all=False)
    outcome = execute_run(load_settings(DISCORD_ENV, dotenv_path=None), RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "success" and outcome.sent
    assert outcome.briefing is not None and outcome.briefing.quiet
    assert len(recorder.requests) == 1
    body = json.loads(recorder.requests[0].content)
    assert "No material updates" in body["content"]
    assert all("author" not in e for e in body.get("embeds", []))
    assert sum(len(json.dumps(e)) for e in body.get("embeds", [])) < 2000


def test_rendered_url_outside_evidence_blocks_delivery_before_any_post() -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder)
    original_render = h.components.render_briefing

    def poisoned(settings, draft, pack, *, generated_by, now):
        briefing = original_render(settings, draft, pack, generated_by=generated_by, now=now)
        briefing.text += "\nhttps://attacker.example/exfil"
        return briefing

    h.components.render_briefing = poisoned
    outcome = execute_run(load_settings(DISCORD_ENV, dotenv_path=None), RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.run.status == "no-send" and outcome.run.delivery_status == DeliveryStatus.BLOCKED_VALIDATION
    assert recorder.requests == []


# ---------------------------------------------------------------------------- storage


def test_sqlite_stores_attempts_and_never_the_webhook(tmp_path) -> None:
    path = tmp_path / "arkham.db"
    settings = load_settings({**DISCORD_ENV, "ARKHAM_DB_PATH": str(path)}, dotenv_path=None)
    recorder = Recorder()
    h = real_discord_harness(recorder)
    with open_storage(settings) as storage:
        outcome = execute_run(settings, RunOptions(), storage=storage, now=NOW, components=h.components)
        assert outcome.sent
        delivery = storage.list_deliveries()[0]
        assert delivery["provider"] == "discord" and delivery["attempts"] == 1 and delivery["messages_sent"] == 1
        assert delivery["segments"] == 0 and delivery["message_ids"] == ["msg1"]
        assert WEBHOOK_TOKEN not in delivery["recipient_masked"]
    raw = path.read_bytes()
    assert WEBHOOK_TOKEN.encode() not in raw and WEBHOOK_ID.encode() not in raw


def test_sqlite_migrates_a_pre_discord_deliveries_table(tmp_path) -> None:
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE deliveries (
            delivery_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, status TEXT NOT NULL,
            provider TEXT NOT NULL, recipient_masked TEXT NOT NULL, message_ids TEXT NOT NULL,
            messages_sent INTEGER NOT NULL, segments INTEGER NOT NULL, error TEXT, briefing_hash TEXT NOT NULL,
            sent_at TEXT NOT NULL
        );
        INSERT INTO deliveries(run_id, status, provider, recipient_masked, message_ids, messages_sent, segments, error, briefing_hash, sent_at)
        VALUES ('r1', 'sent', 'twilio', '+1******0143', '["SM1"]', 1, 3, NULL, 'h', '2026-08-25T12:00:00+00:00');
        """
    )
    db.commit()
    db.close()
    settings = load_settings({**DISCORD_ENV, "ARKHAM_DB_PATH": str(path)}, dotenv_path=None)
    with open_storage(settings) as storage:
        old = storage.list_deliveries()[0]
        assert old["provider"] == "twilio" and old["attempts"] == 0
        storage.record_delivery(
            "r2",
            DeliveryResult(status=DeliveryStatus.SENT, provider="discord", recipient_masked="masked", messages_sent=2, attempts=3),
            "hash",
            NOW,
        )
        assert storage.list_deliveries()[0]["attempts"] == 3


# ---------------------------------------------------------------------------- costs and summary


def test_cost_report_treats_discord_as_free() -> None:
    settings = load_settings({**DISCORD_ENV, "LLM_INPUT_PRICE_PER_1M": "0.10", "LLM_OUTPUT_PRICE_PER_1M": "0.40"}, dotenv_path=None)
    cost = compute_costs(
        LLMUsage(calls=1, input_tokens=1_000_000, output_tokens=1_000_000),
        sms_messages=0,
        sms_segments=0,
        settings=settings,
        delivery_provider="discord",
        delivery_messages=2,
    )
    assert cost.delivery_provider == "discord" and cost.delivery_messages == 2
    assert cost.run_cost_usd == 0.5 and cost.monthly_estimate_usd == 15.0
    report = format_cost_report(cost, sms_sent=True)
    assert "Discord" in report and "2 message(s)" in report and "$0" in report
    assert "SMS" not in report


def test_run_summary_shows_provider_and_messages() -> None:
    run = RunRecord(
        run_id="r", mode="scheduled", started_at=NOW, status="success", delivery_status=DeliveryStatus.SENT,
        delivery_provider="discord", delivery_messages=3, delivery_attempts=4,
    )
    assert "Delivery: discord sent (3 message(s), 4 attempt(s))" in format_run_summary(run)
    assert "SMS" not in format_run_summary(run)


# ---------------------------------------------------------------------------- CLI


def test_cli_test_delivery_sends_one_labelled_message(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    recorder = Recorder()
    for key, value in DISCORD_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cli, "_http_client", lambda settings: recorder.client())
    code = cli.main(["--env-file", "/dev/null", "test-delivery"])
    assert code == 0
    assert len(recorder.requests) == 1
    body = json.loads(recorder.requests[0].content)
    assert body["content"].startswith("Arkham delivery test")
    assert "Discord delivery is configured correctly" in body["content"]
    assert body["allowed_mentions"] == {"parse": []}
    out = capsys.readouterr().out
    assert "sent" in out.lower() and WEBHOOK_TOKEN not in out


def test_cli_test_delivery_fails_cleanly_without_config(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "template")
    called = []
    monkeypatch.setattr(cli, "_http_client", lambda settings: called.append(1))
    code = cli.main(["--env-file", "/dev/null", "test-delivery"])
    assert code == 2 and called == []
    assert "DISCORD_WEBHOOK_URL" in capsys.readouterr().err


def test_cli_check_config_reports_discord_delivery_ready(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    for key, value in DISCORD_ENV.items():
        monkeypatch.setenv(key, value)
    assert cli.main(["--env-file", "/dev/null", "check-config"]) == 0
    out = capsys.readouterr().out
    assert "Delivery: ready" in out and "delivery_provider=discord" in out
    assert WEBHOOK_TOKEN not in out and WEBHOOK_ID not in out


def test_cli_run_dry_run_prints_discord_shaped_brief(monkeypatch: pytest.MonkeyPatch, capsys, tmp_path) -> None:
    recorder = Recorder()
    h = real_discord_harness(recorder)
    for key, value in {**DISCORD_ENV, "ARKHAM_DB_PATH": str(tmp_path / "db.sqlite")}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("arkham.runner.Components.default", classmethod(lambda cls: h.components))
    code = cli.main(["--env-file", "/dev/null", "run", "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0 and recorder.requests == []
    assert "**ARKHAM**" in out and "Dry run: nothing was sent" in out
    assert WEBHOOK_TOKEN not in out and WEBHOOK_ID not in out


def test_twilio_briefing_still_flows_through_message_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"sid": "SM1", "status": "queued", "num_segments": "2"})

    from arkham.delivery import build_provider

    settings = load_settings(TWILIO_ENV, dotenv_path=None)
    h = build_components()
    h.components.render_briefing = render_for_delivery
    h.components.validate_rendered = validate_rendered
    h.components.validate_recipient = validate_recipient
    h.components.build_provider = lambda s, http: build_provider(s, SafeHttpClient(transport=httpx.MockTransport(handler)))
    outcome = execute_run(settings, RunOptions(), storage=MemoryStorage(), now=NOW, components=h.components)
    assert outcome.sent and len(seen) == len(outcome.briefing.messages) >= 1
    assert outcome.run.delivery_provider == "twilio" and outcome.run.sms_segments >= 1
    assert outcome.cost is not None and outcome.cost.delivery_provider == "twilio"


def test_briefing_model_defaults_are_transport_neutral() -> None:
    briefing = Briefing(date_label="AUG 26", draft=BriefingDraft())
    assert briefing.evidence == [] and briefing.messages == [] and briefing.title == "Intelligence Brief"
    assert datetime.now(timezone.utc).tzinfo is not None
