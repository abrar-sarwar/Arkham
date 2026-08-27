"""Delivery layer: render the validated briefing for ONE configured transport and hand it over.

:func:`build_provider` is the only factory the runner and CLI need; it refuses to construct a
provider until every setting of the *selected* transport is present, so misconfiguration surfaces
as an actionable :class:`arkham.config.ConfigError` rather than a failed API call.
:func:`render_for_delivery` picks the renderer that matches the transport (Discord embeds by
default, the phone-sized SMS renderer for the legacy Twilio transport).
"""

from __future__ import annotations

from datetime import datetime

from arkham.config import ConfigError, Settings
from arkham.delivery.base import DeliveryProvider, MessageProvider
from arkham.http import SafeHttpClient
from arkham.models import Briefing, BriefingDraft, EvidencePack

__all__ = ["DeliveryProvider", "MessageProvider", "build_provider", "render_for_delivery"]


def build_provider(settings: Settings, http: SafeHttpClient) -> DeliveryProvider:
    """Return the configured :class:`DeliveryProvider` or raise :class:`ConfigError`.

    The error message joins every problem reported by :meth:`Settings.validate_delivery`, each
    of which names the missing environment variable and where to find its value.
    """
    problems = settings.validate_delivery()
    if problems:
        raise ConfigError("Delivery configuration incomplete:\n  - " + "\n  - ".join(problems))
    if settings.delivery_provider == "discord":
        from arkham.delivery.discord_webhook import DiscordWebhookProvider

        return DiscordWebhookProvider(webhook_url=settings.discord_webhook_url or "", http=http)
    if settings.delivery_provider == "twilio":
        from arkham.delivery.twilio_sms import TwilioMessageProvider

        account_sid = settings.twilio_account_sid
        auth_token = settings.twilio_auth_token
        from_phone = settings.twilio_from_phone
        to_phone = settings.to_phone
        if not (account_sid and auth_token and from_phone and to_phone):
            raise ConfigError("Delivery configuration incomplete: Twilio credentials or phone numbers are unset.")
        return TwilioMessageProvider(
            account_sid=account_sid,
            auth_token=auth_token,
            from_phone=from_phone,
            to_phone=to_phone,
            http=http,
        )
    raise ConfigError(f"Unsupported delivery provider {settings.delivery_provider!r}")


def render_for_delivery(
    settings: Settings, draft: BriefingDraft, pack: EvidencePack, *, generated_by: str, now: datetime
) -> Briefing:
    """Render the validated draft in the shape the configured transport delivers."""
    if settings.delivery_is_sms:
        from arkham.intelligence.brief import render_briefing

        return render_briefing(
            draft, pack, emoji=settings.sms_emoji, max_chars=settings.max_sms_chars, generated_by=generated_by
        )
    from arkham.delivery.discord_format import render_discord_briefing

    return render_discord_briefing(draft, pack, generated_by=generated_by, now=now, tz=settings.tzinfo)
