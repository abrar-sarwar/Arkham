"""OpenAI-compatible Chat Completions analyst provider."""

from __future__ import annotations

import json
from typing import Any

from arkham.http import SafeHttpClient
from arkham.intelligence.llm.base import IntelligenceModel, ModelError
from arkham.intelligence.synthesize import SYSTEM_PROMPT, build_user_prompt, parse_model_json
from arkham.models import EvidencePack, LLMUsage, ModelOutput

MAX_RESPONSE_BYTES = 2_000_000
REQUEST_TIMEOUT_SECONDS = 90.0


class OpenAIModel(IntelligenceModel):
    """Any OpenAI-compatible Chat Completions endpoint (OpenAI, Gemini's OpenAI-compatible API, proxies)."""

    provider = "openai"

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        http: SafeHttpClient,
        base_url: str | None = None,
        provider: str | None = None,
    ) -> None:
        self.model = model
        if provider:
            self.provider = provider  # label only (e.g. "gemini"); the wire protocol is unchanged
        self._api_key = api_key
        self._http = http
        root = (base_url or "https://api.openai.com/v1").rstrip("/")
        self._url = root if root.endswith("/chat/completions") else root + "/chat/completions"

    def synthesize(self, evidence: EvidencePack) -> ModelOutput:
        payload = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(evidence)},
            ],
        }
        try:
            response = self._http.post(
                self._url,
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json=payload,
                max_bytes=MAX_RESPONSE_BYTES,
                timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            )
            data = json.loads(response.body)
            text = _content(data)
            draft = parse_model_json(text)
            usage = data.get("usage") if isinstance(data, dict) else {}
            return ModelOutput(
                draft=draft,
                raw_text=text,
                usage=LLMUsage(
                    provider=self.provider,
                    model=self.model,
                    calls=1,
                    input_tokens=_integer((usage or {}).get("prompt_tokens")),
                    output_tokens=_integer((usage or {}).get("completion_tokens")),
                ),
            )
        except ModelError:
            raise
        except Exception as exc:
            raise ModelError(f"{self.provider} (OpenAI-compatible) model request failed: {exc.__class__.__name__}") from exc


def _content(data: Any) -> str:
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelError("OpenAI-compatible response did not contain message content") from exc
    if not isinstance(content, str) or not content.strip():
        raise ModelError("OpenAI-compatible response content was empty")
    return content


def _integer(value: Any) -> int:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
