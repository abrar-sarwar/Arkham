"""Discord webhook provider: HTTP contract, retries, masking, metadata, redirect refusal. No network."""

from __future__ import annotations

import inspect
import json
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import httpx
import pytest

from arkham.config import ConfigError, load_settings, mask_webhook_url
from arkham.delivery import build_provider, discord_webhook
from arkham.delivery.base import DeliveryProvider
from arkham.delivery.discord_format import render_discord_briefing
from arkham.delivery.discord_webhook import (
    BACKOFF_BASE_SECONDS,
    INTER_MESSAGE_PAUSE_SECONDS,
    MAX_ATTEMPTS_PER_MESSAGE,
    MAX_RETRY_AFTER_SECONDS,
    DiscordWebhookProvider,
)
from arkham.delivery.twilio_sms import TwilioMessageProvider
from arkham.http import SafeHttpClient
from arkham.intelligence.llm.template import TemplateModel
from arkham.models import Briefing, BriefingDraft, DeliveryStatus, EvidencePack
from tests.test_synthesize import all_events, build_pack, citrix_kev_event, gitea_event

WEBHOOK_ID = "123456789012345678"
WEBHOOK_TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz0123"
WEBHOOK = f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}"
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
NY = ZoneInfo("America/New_York")


class Recorder:
    """Scripted webhook endpoint: a list of responses (status, headers, body) consumed in order."""

    def __init__(self, script: list[tuple[int, dict[str, str], object]] | None = None) -> None:
        self.script = list(script or [])
        self.requests: list[httpx.Request] = []
        self.raise_next: list[Exception] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_next:
            raise self.raise_next.pop(0)
        if self.script:
            status, headers, body = self.script.pop(0)
        else:
            status, headers, body = 200, {}, {"id": f"msg{len(self.requests)}"}
        content = json.dumps(body).encode() if isinstance(body, dict | list) else body
        return httpx.Response(status, headers=headers, content=content, request=request)

    def client(self) -> SafeHttpClient:
        return SafeHttpClient(transport=httpx.MockTransport(self.handler))

    def bodies(self) -> list[dict]:
        return [json.loads(request.content) for request in self.requests]


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []
    monkeypatch.setattr(discord_webhook, "_sleep", delays.append)
    return delays


def briefing_for(pack: EvidencePack, draft: BriefingDraft | None = None) -> Briefing:
    draft = draft or TemplateModel().synthesize(pack).draft
    return render_discord_briefing(draft, pack, generated_by="template", now=NOW, tz=NY)


def make_provider(http: SafeHttpClient, url: str = WEBHOOK) -> DiscordWebhookProvider:
    return DiscordWebhookProvider(webhook_url=url, http=http)


# ---------------------------------------------------------------------------- happy path


def test_successful_delivery_posts_embeds_with_mentions_disabled(sleeps, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()
    provider = make_provider(recorder.client())
    briefing = briefing_for(build_pack([citrix_kev_event(), gitea_event()]))

    result = provider.deliver(briefing)

    assert result.status == DeliveryStatus.SENT
    assert result.provider == "discord" == provider.name
    assert result.messages_sent == 1 == len(briefing.messages)
    assert result.attempts == 1
    assert result.message_ids == ["msg1"]
    assert result.segments == 0
    assert result.error is None
    assert result.delivered_at is not None and result.delivered_at.tzinfo is not None
    assert result.recipient_masked == mask_webhook_url(WEBHOOK) == provider.recipient_masked
    assert WEBHOOK_TOKEN not in result.recipient_masked

    request = recorder.requests[0]
    assert request.method == "POST"
    assert str(request.url) == WEBHOOK + "?wait=true"
    assert request.headers["content-type"] == "application/json"
    body = recorder.bodies()[0]
    assert body["allowed_mentions"] == {"parse": []}
    assert body["content"].startswith("**ARKHAM**")
    assert len(body["embeds"]) == 3  # two stories + prep/learn
    assert body["embeds"][0]["author"]["name"] == "CRITICAL"
    assert sleeps == []
    own_logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("arkham"))
    assert own_logs and WEBHOOK_TOKEN not in own_logs and WEBHOOK_ID not in own_logs


def test_multiple_messages_are_posted_in_order_with_a_pause(sleeps) -> None:
    events = []
    for index in range(8):
        event = citrix_kev_event() if index % 2 == 0 else gitea_event()
        event.id = f"{event.id}-{index}"
        event.summary = (f"Sentence {index} of a long advisory body with detail. " * 20).strip()
        event.products = [f"Product {index} " + "x" * 60 for _ in range(5)]
        events.append(event)
    briefing = briefing_for(build_pack(events, max_events=8))
    assert len(briefing.messages) >= 2
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver(briefing)
    assert result.status == DeliveryStatus.SENT
    assert result.messages_sent == len(briefing.messages) == len(recorder.requests)
    assert result.attempts == len(briefing.messages)
    assert result.message_ids == [f"msg{i}" for i in range(1, len(briefing.messages) + 1)]
    bodies = recorder.bodies()
    assert bodies[0]["content"].startswith("**ARKHAM**")
    assert "continued 2/" in bodies[1]["content"]
    assert all(body["allowed_mentions"] == {"parse": []} for body in bodies)
    assert sleeps == [INTER_MESSAGE_PAUSE_SECONDS] * (len(briefing.messages) - 1)


def test_deliver_notice_sends_a_small_content_only_message(sleeps) -> None:
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver_notice("Arkham delivery test\n\nDiscord delivery is configured correctly.")
    assert result.status == DeliveryStatus.SENT and result.messages_sent == 1
    body = recorder.bodies()[0]
    assert body["content"].startswith("Arkham delivery test")
    assert "embeds" not in body
    assert body["allowed_mentions"] == {"parse": []}


def test_notice_with_mentions_is_neutralized(sleeps) -> None:
    recorder = Recorder()
    make_provider(recorder.client()).deliver_notice("@everyone @here <@&1>")
    content = recorder.bodies()[0]["content"]
    assert "@everyone" not in content and "@here" not in content and "<@&" not in content


def test_accepted_without_json_body_still_counts_as_sent(sleeps) -> None:
    recorder = Recorder([(204, {}, b"")])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT and result.message_ids == [] and result.messages_sent == 1


# ---------------------------------------------------------------------------- retries


def test_rate_limit_honours_retry_after_header(sleeps) -> None:
    recorder = Recorder([(429, {"retry-after": "3"}, {"message": "rate limited", "retry_after": 3.0}), (200, {}, {"id": "m"})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT
    assert result.attempts == 2 and len(recorder.requests) == 2
    assert sleeps == [3.0]


def test_rate_limit_without_header_uses_exponential_backoff(sleeps) -> None:
    recorder = Recorder([(429, {}, b""), (429, {}, b""), (200, {}, {"id": "m"})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT and result.attempts == 3
    assert sleeps == [BACKOFF_BASE_SECONDS, BACKOFF_BASE_SECONDS * 2]


def test_retry_after_is_capped(sleeps) -> None:
    recorder = Recorder([(429, {"retry-after": "999"}, b""), (200, {}, {"id": "m"})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT
    assert sleeps == [MAX_RETRY_AFTER_SECONDS]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_server_errors_are_retried(sleeps, status: int) -> None:
    recorder = Recorder([(status, {}, b"oops"), (200, {}, {"id": "m"})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT and result.attempts == 2
    assert sleeps == [BACKOFF_BASE_SECONDS]


def test_timeout_is_retried(sleeps) -> None:
    recorder = Recorder()
    recorder.raise_next.append(httpx.ReadTimeout("slow"))
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT and result.attempts == 2


def test_connection_error_is_retried(sleeps) -> None:
    recorder = Recorder()
    recorder.raise_next.append(httpx.ConnectError("refused"))
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.SENT and result.attempts == 2


def test_bounded_retries_then_failure_without_leaking_the_webhook(sleeps, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder([(503, {}, b"down")] * 10)
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 0
    assert result.attempts == MAX_ATTEMPTS_PER_MESSAGE == len(recorder.requests)
    assert len(sleeps) == MAX_ATTEMPTS_PER_MESSAGE - 1
    assert result.error and "503" in result.error and "attempts" in result.error
    assert WEBHOOK_TOKEN not in result.error and WEBHOOK_ID not in result.error
    own_logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("arkham"))
    assert WEBHOOK_TOKEN not in own_logs and WEBHOOK_ID not in own_logs
    assert "503" in own_logs


@pytest.mark.parametrize(("status", "hint"), [(400, "rejected"), (401, "token"), (403, "token"), (404, "not found"), (413, "too large")])
def test_client_errors_are_not_retried_and_are_explained(sleeps, status: int, hint: str) -> None:
    recorder = Recorder([(status, {}, {"message": "nope", "code": 50027})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.FAILED
    assert result.attempts == 1 and len(recorder.requests) == 1
    assert sleeps == []
    assert result.error and str(status) in result.error and hint in result.error.lower()
    assert WEBHOOK_TOKEN not in result.error


def test_partial_delivery_is_reported_honestly(sleeps) -> None:
    events = []
    for index in range(8):
        event = citrix_kev_event() if index % 2 == 0 else gitea_event()
        event.id = f"{event.id}-{index}"
        event.summary = (f"Sentence {index} of a long advisory body with detail. " * 20).strip()
        event.products = [f"Product {index} " + "x" * 60 for _ in range(5)]
        events.append(event)
    briefing = briefing_for(build_pack(events, max_events=8))
    script = [(200, {}, {"id": "first"})] + [(400, {}, b"bad")]
    recorder = Recorder(script)
    result = make_provider(recorder.client()).deliver(briefing)
    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 1 and result.message_ids == ["first"]
    assert result.attempts == 2
    assert result.error and "message 2" in result.error


def test_redirects_are_refused_not_followed(sleeps) -> None:
    recorder = Recorder([(307, {"location": "https://evil.example/collect"}, b""), (200, {}, {"id": "m"})])
    result = make_provider(recorder.client()).deliver_notice("hi")
    assert result.status == DeliveryStatus.FAILED
    assert len(recorder.requests) == 1
    assert all("evil.example" not in str(r.url) for r in recorder.requests)
    assert result.error and "redirect" in result.error.lower()
    assert "evil.example" not in result.error


def test_unexpected_exception_is_contained_and_scrubbed(sleeps) -> None:
    class Exploding(SafeHttpClient):
        def post(self, url: str, **kwargs: object):  # type: ignore[override]
            raise RuntimeError(f"boom {WEBHOOK} and {WEBHOOK_TOKEN}")

    result = make_provider(Exploding()).deliver_notice("hi")
    assert result.status == DeliveryStatus.FAILED
    assert result.error and "RuntimeError" in result.error
    assert WEBHOOK_TOKEN not in result.error and WEBHOOK not in result.error
    assert "[REDACTED]" in result.error


# ---------------------------------------------------------------------------- grounding guard


def test_payload_with_non_evidence_url_is_refused_before_sending(sleeps) -> None:
    briefing = briefing_for(build_pack([citrix_kev_event()]))
    briefing.draft.items[0].source_url = "https://attacker.example/x"  # simulate a bypassed validator
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver(briefing)
    assert result.status == DeliveryStatus.FAILED
    assert recorder.requests == []
    assert result.error and "not in evidence" in result.error


def test_empty_briefing_is_refused_without_a_request(sleeps) -> None:
    briefing = Briefing(date_label="AUG 26", draft=BriefingDraft())
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver(briefing)
    assert result.status == DeliveryStatus.FAILED and recorder.requests == []


@pytest.mark.parametrize("text", ["", "   \n"])
def test_empty_notice_is_refused(sleeps, text: str) -> None:
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver_notice(text)
    assert result.status == DeliveryStatus.FAILED and recorder.requests == []


# ---------------------------------------------------------------------------- construction & masking


@pytest.mark.parametrize(
    "bad",
    [
        f"http://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://127.0.0.1/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://example.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        "",
    ],
)
def test_invalid_webhook_rejected_at_construction(bad: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        make_provider(Recorder().client(), url=bad)
    assert WEBHOOK_TOKEN not in str(excinfo.value)


def test_provider_never_exposes_the_webhook() -> None:
    provider = make_provider(Recorder().client())
    assert isinstance(provider, DeliveryProvider)
    for text in (repr(provider), str(provider), provider.recipient_masked):
        assert WEBHOOK_TOKEN not in text and WEBHOOK_ID not in text
    assert provider.recipient_masked.startswith("https://discord.com/api/webhooks/")


def test_deliver_has_no_destination_parameter() -> None:
    assert list(inspect.signature(DiscordWebhookProvider.deliver).parameters) == ["self", "briefing"]
    assert list(inspect.signature(DeliveryProvider.deliver).parameters) == ["self", "briefing"]
    assert list(inspect.signature(DeliveryProvider.deliver_notice).parameters) == ["self", "text"]


# ---------------------------------------------------------------------------- factory


def test_build_provider_returns_discord_by_default() -> None:
    settings = load_settings({"DISCORD_WEBHOOK_URL": WEBHOOK}, dotenv_path=None)
    provider = build_provider(settings, Recorder().client())
    assert isinstance(provider, DiscordWebhookProvider)
    assert provider.recipient_masked == settings.recipient_masked


def test_build_provider_without_webhook_raises_config_error() -> None:
    with pytest.raises(ConfigError) as excinfo:
        build_provider(load_settings({}, dotenv_path=None), Recorder().client())
    assert "DISCORD_WEBHOOK_URL" in str(excinfo.value)


def test_build_provider_still_builds_twilio_when_selected() -> None:
    settings = load_settings(
        {
            "ARKHAM_DELIVERY_PROVIDER": "twilio",
            "ARKHAM_TO_PHONE": "+12025550143",
            "TWILIO_ACCOUNT_SID": "AC" + "0123456789abcdef" * 2,
            "TWILIO_AUTH_TOKEN": "t" * 32,
            "TWILIO_FROM_PHONE": "+12025550199",
        },
        dotenv_path=None,
    )
    provider = build_provider(settings, Recorder().client())
    assert isinstance(provider, TwilioMessageProvider) and isinstance(provider, DeliveryProvider)


def test_twilio_provider_delivers_briefing_messages_through_the_common_interface() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"sid": "SM1", "status": "queued", "num_segments": "1"})

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    provider = TwilioMessageProvider(
        account_sid="AC" + "0123456789abcdef" * 2, auth_token="t" * 32, from_phone="+12025550199", to_phone="+12025550143", http=http
    )
    briefing = Briefing(date_label="AUG 26", draft=BriefingDraft(), text="a\n\nb", messages=["a", "b"])
    result = provider.deliver(briefing)
    assert result.status == DeliveryStatus.SENT and result.messages_sent == 2 and len(seen) == 2
    assert provider.deliver_notice("test").status == DeliveryStatus.SENT


def test_no_paid_delivery_or_crawler_packages_are_required() -> None:
    from pathlib import Path

    for name in ("requirements.txt", "pyproject.toml"):
        text = Path(name).read_text(encoding="utf-8").lower()
        assert "twilio" not in text.split("description")[0] or "twilio==" not in text
        assert "firecrawl" not in text
        assert "discord.py" not in text and "discord-webhook" not in text


def test_all_events_render_and_send_cleanly(sleeps) -> None:
    recorder = Recorder()
    result = make_provider(recorder.client()).deliver(briefing_for(build_pack(all_events())))
    assert result.status == DeliveryStatus.SENT
    assert all(body["allowed_mentions"] == {"parse": []} for body in recorder.bodies())
