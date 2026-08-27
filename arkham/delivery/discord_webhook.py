"""Discord incoming-webhook delivery provider (plain HTTPS over :class:`arkham.http.SafeHttpClient`).

No bot token, no gateway connection, no library: one ``POST`` per rendered message to a webhook URL
that was validated against Discord's host/path shape at construction. The URL is a credential:
it is masked in ``repr``/results/logs, scrubbed from every error string, and never persisted.

Retries are bounded (``MAX_ATTEMPTS_PER_MESSAGE``) and apply only to 429 (honouring ``Retry-After``),
5xx, timeouts and transport errors. Other 4xx responses and refused redirects fail immediately.
Discord webhooks have no idempotency key, so a request that timed out *after* Discord stored the
message can produce a duplicate on retry; the bound keeps that to a handful, never a storm.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from arkham.config import mask_webhook_url, webhook_token
from arkham.delivery.base import DeliveryProvider
from arkham.delivery.discord_format import (
    DISCORD_MAX_CONTENT_CHARS,
    neutralize_mentions,
    render_discord_messages,
)
from arkham.http import HttpError, HttpStatusError, HttpTimeout, RedirectRefused, SafeHttpClient
from arkham.models import Briefing, DeliveryResult, DeliveryStatus
from arkham.security.prompt_injection import sanitize_text
from arkham.security.urls import canonicalize_url, validate_discord_webhook_url

log = logging.getLogger(__name__)

MAX_ATTEMPTS_PER_MESSAGE = 4  # 1 try + 3 retries
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 30.0
MAX_RETRY_AFTER_SECONDS = 30.0
INTER_MESSAGE_PAUSE_SECONDS = 0.5  # keeps multi-message briefs in order and under the webhook rate limit
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ERROR_LENGTH = 300

_sleep = time.sleep

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_STATUS_HINTS = {
    400: "payload rejected by Discord",
    401: "webhook token rejected (URL wrong or webhook deleted)",
    403: "webhook token rejected (URL wrong or webhook deleted)",
    404: "webhook not found (deleted, or the URL is wrong)",
    413: "payload too large",
}
_URL_RE = re.compile(r"https://[^\s<>\])}]+")
_WEBHOOK_RE = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/\d+/[A-Za-z0-9_\-]+", re.I
)
_WS_RE = re.compile(r"\s+")
_ALLOWED_MENTIONS: dict[str, list[str]] = {"parse": []}


class DiscordWebhookProvider(DeliveryProvider):
    """Post rendered briefings to ONE pre-validated Discord incoming webhook."""

    name = "discord"

    def __init__(self, *, webhook_url: str, http: SafeHttpClient) -> None:
        self._url = validate_discord_webhook_url(webhook_url)  # UrlValidationError is a ValueError
        self._token = webhook_token(self._url) or ""
        self._masked = mask_webhook_url(self._url)
        self._post_url = self._url + "?wait=true"
        self._http = http

    def __repr__(self) -> str:
        return f"DiscordWebhookProvider(webhook={self._masked})"

    @property
    def recipient_masked(self) -> str:
        return self._masked

    # ------------------------------------------------------------------ public API

    def deliver(self, briefing: Briefing) -> DeliveryResult:
        """Render the briefing into webhook messages, re-check grounding, then post them in order."""
        try:
            messages = render_discord_messages(briefing)
        except Exception as exc:  # rendering must never raise into the pipeline
            return self._failed(f"rendering failed: {exc.__class__.__name__}: {exc}")
        if not messages or not any(message.embeds for message in messages):
            return self._failed("empty briefing (no stories, watch items or prep); nothing sent")
        problem = _grounding_problem(messages, briefing)
        if problem:
            return self._failed(problem)
        return self._send_all([message.payload() for message in messages])

    def deliver_notice(self, text: str) -> DeliveryResult:
        content = neutralize_mentions(sanitize_text(text, DISCORD_MAX_CONTENT_CHARS))
        if not content.strip():
            return self._failed("empty notice; nothing sent")
        return self._send_all([{"content": content}])

    # ------------------------------------------------------------------ sending

    def _send_all(self, payloads: list[dict[str, Any]]) -> DeliveryResult:
        message_ids: list[str] = []
        attempts = 0
        total = len(payloads)
        for index, payload in enumerate(payloads, start=1):
            payload["allowed_mentions"] = dict(_ALLOWED_MENTIONS)  # enforced here, whatever the renderer did
            if index > 1:
                _sleep(INTER_MESSAGE_PAUSE_SECONDS)
            message_id, used, error = self._post_with_retry(payload, index, total)
            attempts += used
            if error:
                return self._failed(
                    f"message {index}/{total}: {error}", message_ids=message_ids, messages_sent=index - 1, attempts=attempts
                )
            if message_id:
                message_ids.append(message_id)
        log.info("discord webhook %s accepted %d message(s) in %d attempt(s)", self._masked, total, attempts)
        return DeliveryResult(
            status=DeliveryStatus.SENT,
            provider=self.name,
            recipient_masked=self._masked,
            message_ids=message_ids,
            messages_sent=total,
            attempts=attempts,
            delivered_at=datetime.now(timezone.utc),
        )

    def _post_with_retry(self, payload: dict[str, Any], index: int, total: int) -> tuple[str | None, int, str | None]:
        """Return ``(message_id, attempts_used, error)``; ``error`` is set only on final failure."""
        for attempt in range(1, MAX_ATTEMPTS_PER_MESSAGE + 1):
            try:
                response = self._http.post(
                    self._post_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    max_bytes=MAX_RESPONSE_BYTES,
                    timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                    follow_redirects=False,
                )
                return _message_id(response.body), attempt, None
            except HttpStatusError as exc:
                if exc.status_code in _RETRY_STATUSES and attempt < MAX_ATTEMPTS_PER_MESSAGE:
                    delay = self._delay(exc, attempt)
                    log.warning(
                        "discord webhook %s returned HTTP %d for message %d/%d; retrying in %.1fs (attempt %d/%d)",
                        self._masked, exc.status_code, index, total, delay, attempt, MAX_ATTEMPTS_PER_MESSAGE,
                    )
                    _sleep(delay)
                    continue
                if exc.status_code in _RETRY_STATUSES:
                    return None, attempt, f"Discord API error: HTTP {exc.status_code} after {attempt} attempts"
                hint = _STATUS_HINTS.get(exc.status_code, "not retried")
                return None, attempt, f"Discord API error: HTTP {exc.status_code} ({hint})"
            except RedirectRefused:
                return None, attempt, "Discord webhook answered with a redirect; refused (redirects are never followed)"
            except (HttpTimeout, HttpError) as exc:
                if attempt < MAX_ATTEMPTS_PER_MESSAGE:
                    delay = min(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1), BACKOFF_CAP_SECONDS)
                    log.warning(
                        "discord webhook %s: %s for message %d/%d; retrying in %.1fs (attempt %d/%d)",
                        self._masked, exc.__class__.__name__, index, total, delay, attempt, MAX_ATTEMPTS_PER_MESSAGE,
                    )
                    _sleep(delay)
                    continue
                return None, attempt, f"{exc.__class__.__name__} after {attempt} attempts"
            except Exception as exc:  # never raise into the pipeline; never leak the URL
                return None, attempt, self._sanitize(f"{exc.__class__.__name__}: {exc}")
        return None, MAX_ATTEMPTS_PER_MESSAGE, "retry budget exhausted"  # pragma: no cover - loop always returns

    @staticmethod
    def _delay(exc: HttpStatusError, attempt: int) -> float:
        retry_after = exc.retry_after_seconds() if exc.status_code == 429 else None
        if retry_after is not None:
            return min(retry_after, MAX_RETRY_AFTER_SECONDS)
        return min(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1), BACKOFF_CAP_SECONDS)

    # ------------------------------------------------------------------ results

    def _failed(
        self, error: str, *, message_ids: list[str] | None = None, messages_sent: int = 0, attempts: int = 0
    ) -> DeliveryResult:
        safe = self._sanitize(error)
        log.warning("discord delivery to %s failed: %s", self._masked, safe)
        return DeliveryResult(
            status=DeliveryStatus.FAILED,
            provider=self.name,
            recipient_masked=self._masked,
            message_ids=list(message_ids or []),
            messages_sent=messages_sent,
            attempts=attempts,
            error=safe,
        )

    def _sanitize(self, text: str) -> str:
        """Remove the webhook URL/token (configured or webhook-shaped), collapse whitespace, bound length."""
        cleaned = text.replace(self._url, "[REDACTED]")
        if self._token:
            cleaned = cleaned.replace(self._token, "[REDACTED]")
        cleaned = _WEBHOOK_RE.sub("[REDACTED]", cleaned)
        cleaned = _WS_RE.sub(" ", cleaned).strip()
        if len(cleaned) > MAX_ERROR_LENGTH:
            cleaned = cleaned[: MAX_ERROR_LENGTH - 1] + "…"
        return cleaned


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _message_id(body: bytes | None) -> str | None:
    """Discord returns the created message (``?wait=true``); take its id when the body is a JSON object."""
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if isinstance(data, dict) and data.get("id"):
        return str(data["id"])
    return None


def _grounding_problem(messages: list[Any], briefing: Briefing) -> str | None:
    """Every https URL in the rendered payload must be an evidence URL of this briefing (fail closed)."""
    allowed = {canonicalize_url(url) for url in briefing.allowed_urls}
    for message in messages:
        for raw in _URL_RE.findall(message.text):
            url = raw.rstrip(").,;:")
            if canonicalize_url(url) not in allowed:
                return "rendered URL is not in evidence; refusing to send"
    return None
