"""Analyst-model interface. The model is an analyst, never a source."""

from __future__ import annotations

from abc import ABC, abstractmethod

from arkham.models import EvidencePack, LLMUsage, ModelOutput

TRANSIENT_MODEL_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})


class ModelError(Exception):
    """Permanent provider/configuration/response failure; never retried or hidden by fallback."""


class TransientModelError(ModelError):
    """Retryable provider outage with optional server-directed delay and billed usage."""

    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
        usage: LLMUsage | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.usage = usage


class IntelligenceModel(ABC):
    provider: str = "abstract"
    model: str = ""

    @abstractmethod
    def synthesize(self, evidence: EvidencePack) -> ModelOutput:
        """Produce a :class:`BriefingDraft` grounded ONLY in ``evidence``. Raise :class:`ModelError` on failure."""

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}" if self.model else self.provider
