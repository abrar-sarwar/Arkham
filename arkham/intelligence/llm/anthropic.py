"""Anthropic Messages API analyst provider."""

from __future__ import annotations

import json
from typing import Any

from arkham.http import HttpError, HttpStatusError, HttpTimeout, SafeHttpClient
from arkham.intelligence.llm.base import (
    TRANSIENT_MODEL_HTTP_STATUSES,
    IntelligenceModel,
    ModelError,
    TransientModelError,
)
from arkham.intelligence.synthesize import SYSTEM_PROMPT, build_user_prompt, parse_model_json
from arkham.models import EvidencePack, LLMUsage, ModelOutput

MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
MAX_RESPONSE_BYTES = 2_000_000


class AnthropicModel(IntelligenceModel):
    provider = "anthropic"

    def __init__(self, *, model: str, api_key: str, http: SafeHttpClient, timeout_seconds: float) -> None:
        self.model = model
        self._api_key = api_key
        self._http = http
        self._timeout_seconds = timeout_seconds

    def synthesize(self, evidence: EvidencePack) -> ModelOutput:
        payload = {
            "model": self.model,
            "max_tokens": 1600,
            "temperature": 0,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": build_user_prompt(evidence)}],
        }
        try:
            response = self._http.post(
                MESSAGES_URL,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json=payload,
                max_bytes=MAX_RESPONSE_BYTES,
                timeout_seconds=self._timeout_seconds,
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
                    input_tokens=_integer((usage or {}).get("input_tokens")),
                    output_tokens=_integer((usage or {}).get("output_tokens")),
                ),
            )
        except ModelError:
            raise
        except HttpTimeout as exc:
            raise TransientModelError("Anthropic model request timed out") from exc
        except HttpStatusError as exc:
            message = f"Anthropic model request failed: HTTP {exc.status_code}"
            if exc.status_code in TRANSIENT_MODEL_HTTP_STATUSES:
                raise TransientModelError(
                    message, retry_after_seconds=exc.retry_after_seconds()
                ) from exc
            raise ModelError(message) from exc
        except HttpError as exc:
            if exc.transient:
                raise TransientModelError(
                    f"Anthropic model transport failed: {exc.__class__.__name__}"
                ) from exc
            raise ModelError(f"Anthropic model request failed: {exc.__class__.__name__}") from exc
        except Exception as exc:
            raise ModelError(f"Anthropic model request failed: {exc.__class__.__name__}") from exc


def _content(data: Any) -> str:
    if not isinstance(data, dict) or not isinstance(data.get("content"), list):
        raise ModelError("Anthropic response did not contain content blocks")
    text = "".join(
        str(block.get("text") or "")
        for block in data["content"]
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()
    if not text:
        raise ModelError("Anthropic response content was empty")
    return text


def _integer(value: Any) -> int:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
