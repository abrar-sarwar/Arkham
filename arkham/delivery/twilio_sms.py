"""Twilio Messages API delivery provider (REST over :class:`arkham.http.SafeHttpClient`, no SDK).

The recipient is fixed when the provider is constructed and re-validated before every send;
``send`` deliberately accepts only the message body so nothing downstream — including model
output — can redirect a briefing. Error strings never contain the auth token, and phone numbers
and the account SID are masked before they reach a log line or a :class:`DeliveryResult`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from arkham.config import E164_RE, mask_phone, mask_secret
from arkham.delivery.base import MessageProvider
from arkham.delivery.sms import TWILIO_MAX_BODY, count_segments
from arkham.http import HttpStatusError, SafeHttpClient
from arkham.models import DeliveryResult, DeliveryStatus
from arkham.security.urls import validate_public_url

log = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.twilio.com"
API_VERSION = "2010-04-01"
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_ERROR_LENGTH = 300
RATE_LIMIT_BACKOFF_SECONDS = 1.0

_sleep = time.sleep

_TERMINAL_FAILURE_STATUSES = frozenset({"failed", "undelivered", "canceled"})
_E164_ANYWHERE_RE = re.compile(r"\+[1-9]\d{6,14}")
_WS_RE = re.compile(r"\s+")


class TwilioMessageProvider(MessageProvider):
    """Send SMS bodies to one pre-configured E.164 number through Twilio's Messages resource."""

    name = "twilio"

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        from_phone: str,
        to_phone: str,
        http: SafeHttpClient,
        api_base: str = DEFAULT_API_BASE,
    ) -> None:
        if not account_sid or not account_sid.startswith("AC"):
            raise ValueError("Twilio account SID must start with 'AC' (copy it from console.twilio.com)")
        if not auth_token:
            raise ValueError("Twilio auth token must not be empty")
        if not from_phone or not E164_RE.match(from_phone):
            raise ValueError("Twilio from_phone must be an E.164 number, e.g. +12125550100")
        if not to_phone or not E164_RE.match(to_phone):
            raise ValueError("Recipient to_phone must be an E.164 number, e.g. +12125551234")
        base = validate_public_url(api_base).rstrip("/")  # UrlValidationError is a ValueError
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_phone = from_phone
        self._to_phone = to_phone
        self._http = http
        self._messages_url = validate_public_url(f"{base}/{API_VERSION}/Accounts/{account_sid}/Messages.json")

    def __repr__(self) -> str:
        return (
            f"TwilioMessageProvider(account_sid={mask_secret(self._account_sid)}, "
            f"from={mask_phone(self._from_phone)}, to={self.recipient_masked})"
        )

    @property
    def recipient_masked(self) -> str:
        """The configured recipient with the middle digits masked, safe for logs and reports."""
        return mask_phone(self._to_phone)

    # ------------------------------------------------------------------ sending

    def send(self, message: str) -> DeliveryResult:
        """POST one body to the configured recipient and translate the API response.

        Empty and oversized bodies are rejected locally without a request. Any transport, HTTP
        or unexpected error yields a ``FAILED`` result whose error text is sanitized.
        """
        if not message or not message.strip():
            return self._failed("empty message body; nothing sent")
        if len(message) > TWILIO_MAX_BODY:
            return self._failed(
                f"message body is {len(message)} characters; Twilio accepts at most {TWILIO_MAX_BODY}"
            )
        if not E164_RE.match(self._to_phone):  # defence in depth: the recipient is immutable after __init__
            return self._failed("configured recipient is not a valid E.164 number")
        for attempt in range(2):
            try:
                response = self._http.post(
                    self._messages_url,
                    data={"To": self._to_phone, "From": self._from_phone, "Body": message},
                    auth=(self._account_sid, self._auth_token),
                    timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                )
                break
            except HttpStatusError as exc:
                # Twilio explicitly documents 429 requests as unprocessed and safe to retry.
                # Other POST failures are not replayed because Message creation has no documented
                # idempotency guarantee and a retry could produce a duplicate SMS.
                if exc.status_code == 429 and attempt == 0:
                    log.warning(
                        "twilio rate-limited delivery to %s; retrying once after %.1fs",
                        self.recipient_masked,
                        RATE_LIMIT_BACKOFF_SECONDS,
                    )
                    _sleep(RATE_LIMIT_BACKOFF_SECONDS)
                    continue
                return self._failed(self._describe_http_error(exc))
            except Exception as exc:  # delivery must never raise into the pipeline
                return self._failed(f"{exc.__class__.__name__}: {exc}")
        return self._interpret(response.body, message)

    # ------------------------------------------------------------------ response handling

    def _interpret(self, body: bytes, message: str) -> DeliveryResult:
        """Turn a 2xx Messages response into a :class:`DeliveryResult`."""
        payload = _parse_json_object(body)
        if payload is None:
            log.warning(
                "twilio accepted the message but returned an unparseable body; assuming sent to %s",
                self.recipient_masked,
            )
            return self._sent(message_ids=[], segments=count_segments(message), status="unknown")
        sid = payload.get("sid")
        message_ids = [str(sid)] if sid else []
        segments = _positive_int(payload.get("num_segments")) or count_segments(message)
        status = str(payload.get("status") or "").lower()
        if status in _TERMINAL_FAILURE_STATUSES:
            code = payload.get("error_code")
            detail = payload.get("error_message")
            text = f"Twilio reported status {status!r}"
            if code:
                text += f" (code {code})"
            if detail:
                text += f": {detail}"
            return self._failed(text, message_ids=message_ids)
        return self._sent(message_ids=message_ids, segments=segments, status=status or "accepted")

    def _describe_http_error(self, exc: HttpStatusError) -> str:
        """Describe an HTTP error status, adding Twilio's JSON ``message``/``code`` when a body is available.

        :class:`arkham.http.SafeHttpClient` raises before exposing an error body, so the detail is
        only present when the exception carries a ``body`` attribute (bytes or str).
        """
        text = f"Twilio API error: HTTP {exc.status_code}"
        detail = _describe_error_body(getattr(exc, "body", None))
        return f"{text} ({detail})" if detail else text

    # ------------------------------------------------------------------ result builders

    def _sent(self, *, message_ids: list[str], segments: int, status: str) -> DeliveryResult:
        log.info(
            "twilio accepted message sid=%s status=%s segments=%d to=%s",
            message_ids[0] if message_ids else "<none>",
            status,
            segments,
            self.recipient_masked,
        )
        return DeliveryResult(
            status=DeliveryStatus.SENT,
            provider=self.name,
            recipient_masked=self.recipient_masked,
            message_ids=message_ids,
            messages_sent=1,
            segments=segments,
        )

    def _failed(self, error: str, *, message_ids: list[str] | None = None) -> DeliveryResult:
        safe = self._sanitize(error)
        log.warning("twilio delivery to %s failed: %s", self.recipient_masked, safe)
        return DeliveryResult(
            status=DeliveryStatus.FAILED,
            provider=self.name,
            recipient_masked=self.recipient_masked,
            message_ids=list(message_ids or []),
            messages_sent=0,
            segments=0,
            error=safe,
        )

    def _sanitize(self, text: str) -> str:
        """Strip the auth token, mask the SID and every phone number, collapse whitespace, bound length."""
        cleaned = text.replace(self._auth_token, "***")
        cleaned = cleaned.replace(self._account_sid, mask_secret(self._account_sid))
        for phone in (self._to_phone, self._from_phone):
            cleaned = cleaned.replace(phone, mask_phone(phone))
        cleaned = _E164_ANYWHERE_RE.sub(lambda m: mask_phone(m.group(0)), cleaned)
        cleaned = _WS_RE.sub(" ", cleaned).strip()
        if len(cleaned) > MAX_ERROR_LENGTH:
            cleaned = cleaned[: MAX_ERROR_LENGTH - 1] + "…"
        return cleaned


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _parse_json_object(body: bytes | str | None) -> dict[str, Any] | None:
    """Decode ``body`` as a JSON object; return None for empty, invalid or non-object payloads."""
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _describe_error_body(body: bytes | str | None) -> str:
    """Extract Twilio's ``message``/``code`` from an error body, or an empty string when absent."""
    payload = _parse_json_object(body)
    if payload is None:
        return ""
    parts: list[str] = []
    code = payload.get("code")
    if code:
        parts.append(f"code {code}")
    message = payload.get("message")
    if message:
        parts.append(str(message))
    return ": ".join(parts)


def _positive_int(value: Any) -> int | None:
    """Coerce Twilio's stringly-typed counters (``"2"``) to int; None when missing or unusable."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except ValueError:
        return None
    return number if number > 0 else None
