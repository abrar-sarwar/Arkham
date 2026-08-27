from __future__ import annotations

import json

import httpx
import pytest

from arkham.config import Settings
from arkham.http import SafeHttpClient
from arkham.intelligence.llm import build_model
from arkham.intelligence.llm.base import ModelError
from arkham.intelligence.llm.template import TemplateModel
from tests.test_synthesize import build_pack, citrix_kev_event


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

    settings = Settings(llm_provider="anthropic", llm_model="current-model", anthropic_api_key="secret-key")
    with SafeHttpClient(transport=httpx.MockTransport(handler)) as http:
        output = build_model(settings, http).synthesize(build_pack([citrix_kev_event()]))
    request = seen[0]
    payload = json.loads(request.content)
    assert request.url == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == "secret-key"
    assert payload["model"] == "current-model"
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
    assert "UNTRUSTED EVIDENCE" in payload["messages"][0]["content"]
    assert output.usage.provider == "gemini" and output.usage.calls == 1
    assert output.draft.items[0].ref == "E1"


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
