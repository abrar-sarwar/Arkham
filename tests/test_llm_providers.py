from __future__ import annotations

import json

import httpx
import pytest

from arkham.config import Settings
from arkham.http import SafeHttpClient
from arkham.intelligence import synthesize as synthesis
from arkham.intelligence.llm import build_model
from arkham.intelligence.llm.base import ModelError
from arkham.intelligence.llm.template import TemplateModel
from tests.test_synthesize import build_pack, citrix_kev_event, gitea_event


def draft_json() -> dict:
    return {
        "items": [
            {
                "ref": "E1",
                "section": "CRITICAL",
                "headline": "CVE-2026-8452 exploited in Citrix NetScaler",
                "why_it_matters": "Confirmed exploitation affects exposed gateways.",
                "confidence": "CONFIRMED",
                "source_label": "Citrix",
                "source_url": "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696604",
            }
        ],
        "prep": ["Patch exposed gateways"],
        "watch": [],
    }


def completion_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        request=request,
        json={
            "choices": [{"message": {"content": json.dumps(draft_json())}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10},
        },
    )


def openai_settings() -> Settings:
    return Settings(llm_provider="openai", llm_model="model", openai_api_key="secret")


def test_build_model_template_needs_no_credentials() -> None:
    with SafeHttpClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500))) as http:
        model = build_model(Settings(llm_provider="template"), http)
    assert isinstance(model, TemplateModel) and model.label == "template"


def test_openai_provider_request_and_usage() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(draft_json())}}],
                "usage": {"prompt_tokens": 111, "completion_tokens": 22},
            },
        )

    settings = Settings(
        llm_provider="openai",
        llm_model="current-model",
        llm_timeout_seconds=240.0,
        openai_api_key="secret-key",
        openai_base_url="https://llm.example/v1",
    )
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = build_model(settings, http).synthesize(build_pack([citrix_kev_event()]))
    request = seen[0]
    payload = json.loads(request.content)
    assert request.url == "https://llm.example/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer secret-key"
    assert payload["model"] == "current-model"
    assert "reasoning_effort" not in payload
    assert request.extensions["timeout"]["read"] == 240.0
    assert payload["messages"][0]["role"] == "system"
    assert "UNTRUSTED EVIDENCE" in payload["messages"][0]["content"]
    assert "<evidence>" in payload["messages"][1]["content"]
    assert output.draft.items[0].ref == "E1"
    assert (output.usage.calls, output.usage.input_tokens, output.usage.output_tokens) == (1, 111, 22)


def test_anthropic_provider_request_and_usage() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": json.dumps(draft_json())}],
                "usage": {"input_tokens": 90, "output_tokens": 17},
            },
        )

    settings = Settings(
        llm_provider="anthropic",
        llm_model="current-model",
        llm_timeout_seconds=240.0,
        anthropic_api_key="secret-key",
    )
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = build_model(settings, http).synthesize(build_pack([citrix_kev_event()]))
    request = seen[0]
    payload = json.loads(request.content)
    assert request.url == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == "secret-key"
    assert payload["model"] == "current-model"
    assert "reasoning_effort" not in payload
    assert request.extensions["timeout"]["read"] == 240.0
    assert "UNTRUSTED EVIDENCE" in payload["system"]
    assert output.usage.provider == "anthropic"
    assert (output.usage.calls, output.usage.input_tokens, output.usage.output_tokens) == (1, 90, 17)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text="provider failed"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}),
    ],
)
def test_provider_failures_are_model_errors(response: httpx.Response) -> None:
    settings = Settings(llm_provider="openai", llm_model="model", openai_api_key="secret")
    with SafeHttpClient(transport=httpx.MockTransport(lambda _request: response)) as http:
        with pytest.raises(ModelError):
            build_model(settings, http).synthesize(build_pack([citrix_kev_event()]))


def test_gemini_provider_reuses_openai_compatible_implementation() -> None:
    """LLM_PROVIDER=gemini is the OpenAI-compatible provider pointed at Google's endpoint; no duplicate class."""
    from arkham.config import DEFAULT_GEMINI_BASE_URL
    from arkham.intelligence.llm.openai import OpenAIModel

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps(draft_json())}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 10},
            },
        )

    settings = Settings(llm_provider="gemini", llm_model="gemini-model", gemini_api_key="AIza" + "k" * 35)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        model = build_model(settings, http)
        assert isinstance(model, OpenAIModel)
        assert model.label == "gemini:gemini-model"
        output = model.synthesize(build_pack([citrix_kev_event()]))
    request = seen[0]
    assert str(request.url) == DEFAULT_GEMINI_BASE_URL + "/chat/completions"
    assert request.headers["authorization"] == "Bearer AIza" + "k" * 35
    payload = json.loads(request.content)
    assert payload["model"] == "gemini-model" and payload["response_format"] == {"type": "json_object"}
    assert payload["reasoning_effort"] == "low"
    assert "UNTRUSTED EVIDENCE" in payload["messages"][0]["content"]
    assert output.usage.provider == "gemini" and output.usage.calls == 1
    assert output.draft.items[0].ref == "E1"


def test_gemini_rank_repair_is_one_reformat_call_with_stable_identity_map() -> None:
    seen: list[httpx.Request] = []
    pack = build_pack([citrix_kev_event(), gitea_event()])
    initial = draft_json()
    initial["items"].append(dict(initial["items"][0]))
    repaired = draft_json()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = initial if len(seen) == 1 else repaired
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [{"message": {"content": json.dumps(body)}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 10},
            },
        )

    settings = Settings(
        llm_provider="gemini",
        llm_model="gemini-model",
        gemini_api_key="AIza" + "k" * 35,
    )
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = synthesis.synthesize(pack, build_model(settings, http))

    assert [item.ref for item in output.draft.items] == ["E1"]
    assert len(seen) == 2
    repair_payload = json.loads(seen[1].content)
    assert repair_payload["reasoning_effort"] == "low"
    repair_prompt = repair_payload["messages"][1]["content"]
    assert "REFORMAT ONLY" in repair_prompt
    assert pack.items[0].event_id in repair_prompt
    assert pack.items[1].event_id in repair_prompt
    assert repair_prompt.count('"ref": "E1"') >= 2


def test_gemini_provider_honours_custom_base_url_and_requires_key() -> None:
    from arkham.config import ConfigError

    settings = Settings(
        llm_provider="gemini", llm_model="m", gemini_api_key="k" * 40, gemini_base_url="https://llm.example/v1/"
    )
    with SafeHttpClient(transport=httpx.MockTransport(lambda _r: httpx.Response(500))) as http:
        model = build_model(settings, http)
        assert model._url == "https://llm.example/v1/chat/completions"  # noqa: SLF001
        with pytest.raises(ConfigError):
            build_model(Settings(llm_provider="gemini", llm_model="m"), http)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_http_status_retries_then_returns_success(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(status, request=request)
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = synthesis.synthesize(
            build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
        )

    assert output.draft.items[0].ref == "E1"
    assert len(requests) == 2
    assert sleeps == [2.0]


def test_timeout_retries_then_returns_success(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = synthesis.synthesize(
            build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
        )

    assert output.draft.items[0].ref == "E1"
    assert len(requests) == 2
    assert sleeps == [2.0]


def test_connection_error_retries_then_returns_success(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            raise httpx.ConnectError("unavailable", request=request)
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = synthesis.synthesize(
            build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
        )

    assert output.draft.items[0].ref == "E1"
    assert len(requests) == 2
    assert sleeps == [2.0]


def test_oversized_model_response_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200, headers={"Content-Length": "2000001"}, request=request
            )
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ModelError):
            synthesis.synthesize(
                build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
            )

    assert len(requests) == 1
    assert sleeps == []


@pytest.mark.parametrize(("retry_after", "expected"), [("7", 7.0), ("999", 30.0)])
def test_retry_after_is_honoured_and_capped(
    monkeypatch: pytest.MonkeyPatch, retry_after: str, expected: float
) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, headers={"Retry-After": retry_after}, request=request)
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        synthesis.synthesize(build_pack([citrix_kev_event()]), build_model(openai_settings(), http))

    assert len(requests) == 2
    assert sleeps == [expected]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_permanent_http_status_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(status, request=request)
        return completion_response(request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ModelError):
            synthesis.synthesize(
                build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
            )

    assert len(requests) == 1
    assert sleeps == []


def test_transient_retries_stop_after_four_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503, request=request)

    monkeypatch.setattr(synthesis, "_sleep", sleeps.append, raising=False)
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ModelError, match="after 4 attempts"):
            synthesis.synthesize(
                build_pack([citrix_kev_event()]), build_model(openai_settings(), http)
            )

    assert len(requests) == 4
    assert sleeps == [2.0, 8.0, 20.0]
