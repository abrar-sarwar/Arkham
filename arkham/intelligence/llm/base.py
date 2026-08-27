"""Analyst-model interface. The model is an analyst, never a source."""

from __future__ import annotations

from abc import ABC, abstractmethod

from arkham.models import EvidencePack, ModelOutput


class ModelError(Exception):
    """Provider/network/parse failure. The pipeline treats this as 'no briefing' (fail closed)."""


class IntelligenceModel(ABC):
    provider: str = "abstract"
    model: str = ""

    @abstractmethod
    def synthesize(self, evidence: EvidencePack) -> ModelOutput:
        """Produce a :class:`BriefingDraft` grounded ONLY in ``evidence``. Raise :class:`ModelError` on failure."""

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}" if self.model else self.provider
