"""Tests for the legacy Twilio SMS provider (ARKHAM_DELIVERY_PROVIDER=twilio) and the delivery factory. No network."""

from __future__ import annotations

import base64
import inspect
import json
import logging
from urllib.parse import parse_qs

import httpx
import pytest

from arkham.config import ConfigError, Settings, load_settings, mask_phone
from arkham.delivery import build_provider, twilio_sms
from arkham.delivery.base import MessageProvider
from arkham.delivery.sms import TWILIO_MAX_BODY, count_segments
from arkham.delivery.twilio_sms import TwilioMessageProvider
from arkham.http import HttpStatusError, SafeHttpClient
from arkham.models import DeliveryStatus
from tests.conftest import RouteTable, load_fixture_json

SID = "AC" + "0123456789abcdef" * 2
TOKEN = "supersecrettoken0123456789abcdef"
FROM = "+12025550199"
TO = "+12025550143"
MESSAGES_URL = f"https://api.twilio.com/2010-04-01/Accounts/{SID}/Messages.json"
MESSAGE_SID = "SM" + "f" * 32


def kev_body() -> str:
    """A realistic SMS body built from the captured KEV feed."""
    vuln = load_fixture_json("cisa_kev_sample.json")["vulnerabilities"][1]
    return f"CRITICAL: {vuln['vulnerabilityName']}\n{vuln['cveID']} added to KEV {vuln['dateAdded']}"


def twilio_success_json(body: str, *, num_segments: str | None = "2", status: str = "queued") -> str:
    payload = {
        "account_sid": SID,
        "api_version": "2010-04-01",
        "body": body,
        "date_created": "Wed, 26 Aug 2026 12:00:00 +0000",
        "date_sent": None,
        "date_updated": "Wed, 26 Aug 2026 12:00:00 +0000",
        "direction": "outbound-api",
        "error_code": None,
        "error_message": None,
        "from": FROM,
        "messaging_service_sid": None,
        "num_media": "0",
        "price": None,
        "price_unit": "USD",
        "sid": MESSAGE_SID,
        "status": status,
        "to": TO,
        "uri": f"/2010-04-01/Accounts/{SID}/Messages/{MESSAGE_SID}.json",
    }
    if num_segments is not None:
        payload["num_segments"] = num_segments
    return json.dumps(payload)


def make_provider(http: SafeHttpClient, **overrides: object) -> TwilioMessageProvider:
    kwargs: dict[str, object] = {
        "account_sid": SID,
        "auth_token": TOKEN,
        "from_phone": FROM,
        "to_phone": TO,
        "http": http,
    }
    kwargs.update(overrides)
    return TwilioMessageProvider(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------- happy path


def test_send_success_posts_form_with_basic_auth(routes: RouteTable, caplog):
    caplog.set_level(logging.DEBUG)
    body = kev_body()
    routes.add(MESSAGES_URL, twilio_success_json(body), status=201, headers={"content-type": "application/json"})
    provider = make_provider(routes.client())

    result = provider.send(body)

    assert result.status == DeliveryStatus.SENT
    assert result.provider == "twilio" == provider.name
    assert result.message_ids == [MESSAGE_SID]
    assert result.messages_sent == 1
    assert result.segments == 2
    assert result.error is None
    assert result.recipient_masked == mask_phone(TO) == provider.recipient_masked
    assert TO not in result.recipient_masked

    assert len(routes.requests) == 1
    request = routes.requests[0]
    assert request.method == "POST"
    assert SID in str(request.url)
    assert str(request.url) == MESSAGES_URL
    form = parse_qs(request.content.decode("utf-8"))
    assert form["To"] == [TO]
    assert form["From"] == [FROM]
    assert form["Body"] == [body]
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    auth = request.headers["authorization"]
    assert auth.startswith("Basic ")
    assert base64.b64decode(auth.split(" ", 1)[1]).decode() == f"{SID}:{TOKEN}"

    assert TOKEN not in caplog.text
    assert TO not in caplog.text
    assert body not in caplog.text


def test_send_falls_back_to_local_segment_count(routes: RouteTable):
    body = "a" * 200
    routes.add(MESSAGES_URL, twilio_success_json(body, num_segments=None), status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.SENT
    assert result.segments == count_segments(body) == 2


def test_send_accepts_non_numeric_segment_count_gracefully(routes: RouteTable):
    body = "a" * 10
    routes.add(MESSAGES_URL, twilio_success_json(body, num_segments="n/a"), status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.SENT
    assert result.segments == 1


def test_accepted_response_with_unparseable_body_is_still_sent(routes: RouteTable, caplog):
    caplog.set_level(logging.WARNING)
    body = kev_body()
    routes.add(MESSAGES_URL, "<html>not json</html>", status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.SENT
    assert result.messages_sent == 1
    assert result.message_ids == []
    assert result.segments == count_segments(body)
    assert "unparseable" in caplog.text.lower() or "not json" in caplog.text.lower()


def test_api_base_trailing_slash_is_normalised(routes: RouteTable):
    body = kev_body()
    routes.add(MESSAGES_URL, twilio_success_json(body), status=201)
    provider = make_provider(routes.client(), api_base="https://api.twilio.com/")
    assert provider.send(body).status == DeliveryStatus.SENT
    assert str(routes.requests[0].url) == MESSAGES_URL


# ---------------------------------------------------------------------------- failures


def test_api_error_400_returns_failed_without_leaking_token(routes: RouteTable, caplog):
    caplog.set_level(logging.DEBUG)
    error_json = json.dumps(
        {
            "code": 21211,
            "message": f"The 'To' number {TO} is not a valid phone number.",
            "more_info": "https://www.twilio.com/docs/errors/21211",
            "status": 400,
        }
    )
    routes.add(MESSAGES_URL, error_json, status=400, headers={"content-type": "application/json"})
    result = make_provider(routes.client()).send(kev_body())

    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 0
    assert result.segments == 0
    assert result.message_ids == []
    assert result.error and "400" in result.error
    assert result.recipient_masked == mask_phone(TO)
    assert len(routes.requests) == 1
    assert TOKEN not in result.error
    assert TO not in result.error
    assert SID not in result.error
    assert TOKEN not in caplog.text
    assert TO not in caplog.text
    assert "400" in caplog.text


def test_api_error_surfaces_twilio_message_and_code_when_body_is_available():
    """SafeHttpClient discards error bodies; when a client exposes one, Twilio's message/code are reported."""
    error_json = json.dumps(
        {"code": 21211, "message": f"The 'To' number {TO} is not a valid phone number.", "status": 400}
    )

    class BodyCarryingClient(SafeHttpClient):
        def post(self, url: str, **kwargs: object):  # type: ignore[override]
            exc = HttpStatusError(400, url)
            exc.body = error_json.encode("utf-8")  # type: ignore[attr-defined]
            raise exc

    result = make_provider(BodyCarryingClient()).send(kev_body())
    assert result.status == DeliveryStatus.FAILED
    assert result.error and "400" in result.error and "21211" in result.error
    assert "not a valid phone number" in result.error
    assert TO not in result.error
    assert mask_phone(TO) in result.error
    assert TOKEN not in result.error


def test_api_error_401_is_reported_as_failure(routes: RouteTable):
    routes.add(MESSAGES_URL, json.dumps({"code": 20003, "message": "Authenticate", "status": 401}), status=401)
    result = make_provider(routes.client()).send("hello")
    assert result.status == DeliveryStatus.FAILED
    assert result.error and "401" in result.error
    assert TOKEN not in result.error


def test_rate_limit_retries_once_with_backoff(monkeypatch: pytest.MonkeyPatch):
    attempts = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, content=b"rate limited", request=request)
        return httpx.Response(201, content=twilio_success_json("hello"), request=request)

    monkeypatch.setattr(twilio_sms, "_sleep", delays.append)
    result = make_provider(SafeHttpClient(transport=httpx.MockTransport(handler))).send("hello")
    assert result.status == DeliveryStatus.SENT
    assert attempts == 2
    assert delays == [1.0]


def test_server_error_is_not_replayed_because_create_message_is_not_idempotent():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, content=b"unavailable", request=request)

    result = make_provider(SafeHttpClient(transport=httpx.MockTransport(handler))).send("hello")
    assert result.status == DeliveryStatus.FAILED
    assert attempts == 1


def test_twilio_status_failed_in_accepted_response_is_a_failure(routes: RouteTable):
    body = kev_body()
    payload = json.loads(twilio_success_json(body, status="failed"))
    payload["error_code"] = 30007
    payload["error_message"] = f"Message filtered for {TO}"
    routes.add(MESSAGES_URL, json.dumps(payload), status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 0
    assert result.error and "30007" in result.error
    assert TO not in result.error
    assert mask_phone(TO) in result.error


def test_transport_exception_returns_failed(caplog):
    caplog.set_level(logging.DEBUG)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(boom))
    result = make_provider(http).send(kev_body())
    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 0
    assert result.error and "HttpError" in result.error
    assert "ConnectError" in result.error
    assert TOKEN not in result.error
    assert SID not in result.error
    assert TOKEN not in caplog.text


def test_timeout_returns_failed():
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(slow))
    result = make_provider(http).send("hello")
    assert result.status == DeliveryStatus.FAILED
    assert result.error and "HttpTimeout" in result.error


def test_unexpected_exception_from_client_is_contained():
    class ExplodingClient(SafeHttpClient):
        def post(self, url: str, **kwargs: object):  # type: ignore[override]
            raise RuntimeError(f"unexpected {TOKEN} {TO}")

    result = make_provider(ExplodingClient()).send("hello")
    assert result.status == DeliveryStatus.FAILED
    assert result.error and result.error.startswith("RuntimeError")
    assert TOKEN not in result.error
    assert TO not in result.error


@pytest.mark.parametrize("body", ["", "   \n", "a" * (TWILIO_MAX_BODY + 1)])
def test_empty_or_oversized_body_rejected_without_request(routes: RouteTable, body):
    routes.add(MESSAGES_URL, twilio_success_json(body), status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.FAILED
    assert result.error
    assert result.messages_sent == 0
    assert routes.requests == []


def test_body_at_exact_twilio_limit_is_sent(routes: RouteTable):
    body = "b" * TWILIO_MAX_BODY
    routes.add(MESSAGES_URL, twilio_success_json(body, num_segments="11"), status=201)
    result = make_provider(routes.client()).send(body)
    assert result.status == DeliveryStatus.SENT
    assert result.segments == 11


def test_send_many_stops_at_first_failure(routes: RouteTable):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 2:
            return httpx.Response(400, content=json.dumps({"code": 21610, "message": "blocked", "status": 400}))
        return httpx.Response(201, content=twilio_success_json("x"))

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    result = make_provider(http).send_many(["one", "two", "three"])
    assert calls["n"] == 2
    assert result.status == DeliveryStatus.FAILED
    assert result.messages_sent == 1
    assert result.message_ids == [MESSAGE_SID]


# ---------------------------------------------------------------------------- recipient restriction


@pytest.mark.parametrize("bad", ["2025550143", "+1 202 555 0143", "+0123", "12025550143", "", "+1202555014312345"])
def test_invalid_to_phone_rejected_at_construction(routes: RouteTable, bad):
    with pytest.raises(ValueError):
        make_provider(routes.client(), to_phone=bad)


@pytest.mark.parametrize("bad", ["2025550199", "+1 202", ""])
def test_invalid_from_phone_rejected_at_construction(routes: RouteTable, bad):
    with pytest.raises(ValueError):
        make_provider(routes.client(), from_phone=bad)


@pytest.mark.parametrize("bad", ["", "SK" + "0" * 32, "0123456789abcdef"])
def test_malformed_account_sid_rejected(routes: RouteTable, bad):
    with pytest.raises(ValueError):
        make_provider(routes.client(), account_sid=bad)


def test_missing_auth_token_rejected(routes: RouteTable):
    with pytest.raises(ValueError):
        make_provider(routes.client(), auth_token="")


def test_insecure_api_base_rejected(routes: RouteTable):
    with pytest.raises(ValueError):
        make_provider(routes.client(), api_base="http://api.twilio.com")
    with pytest.raises(ValueError):
        make_provider(routes.client(), api_base="https://127.0.0.1")


def test_send_has_no_recipient_parameter():
    params = list(inspect.signature(TwilioMessageProvider.send).parameters)
    assert params == ["self", "message"]
    assert list(inspect.signature(MessageProvider.send).parameters) == ["self", "message"]


def test_provider_does_not_expose_raw_secrets(routes: RouteTable):
    provider = make_provider(routes.client())
    assert isinstance(provider, MessageProvider)
    assert TOKEN not in repr(provider)
    assert TO not in repr(provider)
    assert TOKEN not in str(provider)
    assert provider.recipient_masked == mask_phone(TO)


# ---------------------------------------------------------------------------- build_provider


def test_build_provider_raises_config_error_listing_missing_vars(routes: RouteTable):
    settings = load_settings({"ARKHAM_DELIVERY_PROVIDER": "twilio"}, dotenv_path=None)
    with pytest.raises(ConfigError) as excinfo:
        build_provider(settings, routes.client())
    message = str(excinfo.value)
    for key in ("ARKHAM_TO_PHONE", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_PHONE"):
        assert key in message
    assert routes.requests == []


def test_build_provider_reports_partial_config(routes: RouteTable):
    settings = load_settings(
        {"ARKHAM_DELIVERY_PROVIDER": "twilio", "ARKHAM_TO_PHONE": TO, "TWILIO_ACCOUNT_SID": SID}, dotenv_path=None
    )
    with pytest.raises(ConfigError) as excinfo:
        build_provider(settings, routes.client())
    message = str(excinfo.value)
    assert "TWILIO_AUTH_TOKEN" in message and "TWILIO_FROM_PHONE" in message
    assert "ARKHAM_TO_PHONE" not in message


def test_build_provider_returns_twilio_provider(routes: RouteTable):
    settings = load_settings(
        {
            "ARKHAM_DELIVERY_PROVIDER": "twilio",
            "ARKHAM_TO_PHONE": TO,
            "TWILIO_ACCOUNT_SID": SID,
            "TWILIO_AUTH_TOKEN": TOKEN,
            "TWILIO_FROM_PHONE": FROM,
        },
        dotenv_path=None,
    )
    provider = build_provider(settings, routes.client())
    assert isinstance(provider, TwilioMessageProvider)
    assert provider.name == "twilio"
    assert provider.recipient_masked == mask_phone(TO)

    body = kev_body()
    routes.add(MESSAGES_URL, twilio_success_json(body), status=201)
    assert provider.send(body).status == DeliveryStatus.SENT
    form = parse_qs(routes.requests[0].content.decode("utf-8"))
    assert form["To"] == [TO] and form["From"] == [FROM]


def test_build_provider_rejects_settings_with_malformed_from_phone(routes: RouteTable):
    settings = Settings(
        delivery_provider="twilio",
        to_phone=TO,
        twilio_account_sid=SID,
        twilio_auth_token=TOKEN,
        twilio_from_phone="not-a-number",
    )
    with pytest.raises(ValueError):
        build_provider(settings, routes.client())
