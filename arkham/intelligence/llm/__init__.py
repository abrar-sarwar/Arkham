"""Analyst-model provider construction."""

from __future__ import annotations

from arkham.config import ConfigError, Settings
from arkham.http import SafeHttpClient
from arkham.intelligence.llm.base import IntelligenceModel

__all__ = ["IntelligenceModel", "build_model"]


def build_model(settings: Settings, http: SafeHttpClient) -> IntelligenceModel:
    if settings.llm_provider == "template":
        from arkham.intelligence.llm.template import TemplateModel

        return TemplateModel()
    if settings.llm_provider == "openai":
        from arkham.intelligence.llm.openai import OpenAIModel

        if not settings.llm_model or not settings.openai_api_key:
            raise ConfigError("OpenAI-compatible model configuration is incomplete")
        return OpenAIModel(
            model=settings.llm_model,
            api_key=settings.openai_api_key,
            http=http,
            base_url=settings.openai_base_url,
        )
    if settings.llm_provider == "gemini":
        # Gemini speaks the OpenAI Chat Completions dialect (JSON mode, temperature, Bearer auth), so the
        # same hardened provider is reused; only the endpoint, key and label differ.
        from arkham.config import DEFAULT_GEMINI_BASE_URL
        from arkham.intelligence.llm.openai import OpenAIModel

        if not settings.llm_model or not settings.gemini_api_key:
            raise ConfigError("Gemini model configuration is incomplete (LLM_MODEL and GEMINI_API_KEY are required)")
        return OpenAIModel(
            model=settings.llm_model,
            api_key=settings.gemini_api_key,
            http=http,
            base_url=settings.gemini_base_url or DEFAULT_GEMINI_BASE_URL,
            provider="gemini",
        )
    if settings.llm_provider == "anthropic":
        from arkham.intelligence.llm.anthropic import AnthropicModel

        if not settings.llm_model or not settings.anthropic_api_key:
            raise ConfigError("Anthropic model configuration is incomplete")
        return AnthropicModel(model=settings.llm_model, api_key=settings.anthropic_api_key, http=http)
    raise ConfigError(f"Unsupported LLM provider {settings.llm_provider!r}")
