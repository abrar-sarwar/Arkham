"""Delivery provider interfaces.

A provider is constructed with its ONE permitted destination (a phone number, a webhook, ...).
``deliver``/``deliver_notice``/``send`` deliberately have no destination parameter so nothing in
the pipeline — including model output or article text — can redirect a briefing.

:class:`DeliveryProvider` is the transport abstraction the runner and CLI use. :class:`MessageProvider`
is the SMS-shaped specialisation (plain bodies, sent one by one) kept for the legacy Twilio transport.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from arkham.models import Briefing, DeliveryResult, DeliveryStatus


class DeliveryProvider(ABC):
    """Transport abstraction: Discord webhook today, Twilio SMS as legacy, email/push later."""

    name: str = "abstract"

    @property
    @abstractmethod
    def recipient_masked(self) -> str:
        """Masked destination for logs, results and the recipient-equality check."""

    @abstractmethod
    def deliver(self, briefing: Briefing) -> DeliveryResult:
        """Deliver a validated briefing to the configured destination. Never raises."""

    @abstractmethod
    def deliver_notice(self, text: str) -> DeliveryResult:
        """Deliver one short plain-text notice (delivery test, status line). Never raises."""


class MessageProvider(DeliveryProvider):
    """A provider that sends plain-text bodies one at a time (SMS-shaped)."""

    @abstractmethod
    def send(self, message: str) -> DeliveryResult:
        """Send one message body to the configured recipient."""

    def send_many(self, messages: list[str]) -> DeliveryResult:
        """Send bodies in order; stop at the first failure and report partial delivery."""
        combined: DeliveryResult | None = None
        for body in messages:
            result = self.send(body)
            if combined is None:
                combined = result
            else:
                combined.message_ids.extend(result.message_ids)
                combined.messages_sent += result.messages_sent
                combined.segments += result.segments
                combined.attempts += result.attempts
                combined.status = result.status
                combined.error = result.error
            if result.error:
                break
        return combined or DeliveryResult(status=DeliveryStatus.FAILED, provider=self.name, error="no messages")

    def deliver(self, briefing: Briefing) -> DeliveryResult:
        """The SMS renderer already split the briefing into bodies; send them in order."""
        return self.send_many(briefing.messages)

    def deliver_notice(self, text: str) -> DeliveryResult:
        return self.send(text)
