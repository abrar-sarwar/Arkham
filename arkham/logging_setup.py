"""Structured logging with secret and phone-number masking."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

_PHONE_RE = re.compile(r"\+[1-9]\d{6,14}")
_TOKEN_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_\-]{8,}|sk-ant-[A-Za-z0-9_\-]{8,}|AC[0-9a-f]{32}|SK[0-9a-f]{32}|AIza[0-9A-Za-z_\-]{30,})\b"
)
# Any Discord incoming-webhook URL (configured or not) is redacted whole: the token is the credential.
_WEBHOOK_RE = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/\d+/[A-Za-z0-9_\-]+", re.I
)


def _mask_phone_match(m: re.Match[str]) -> str:
    s = m.group(0)
    return s[:2] + "*" * (len(s) - 6) + s[-4:]


class SecretMaskingFilter(logging.Filter):
    """Redacts configured secret values, phone numbers and token-looking strings from log output."""

    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self._secrets = tuple(s for s in secrets if s and len(s) >= 6)

    def _scrub(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "[REDACTED]")
        text = _WEBHOOK_RE.sub("[REDACTED]", text)
        text = _TOKEN_RE.sub("[REDACTED]", text)
        return _PHONE_RE.sub(_mask_phone_match, text)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            msg = str(record.msg)
        record.msg = self._scrub(msg)
        record.args = ()
        if record.exc_info:
            record.exc_text = self._scrub(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        if record.stack_info:
            record.stack_info = self._scrub(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("run_id", "source_id", "event_id"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_text:
            payload["exc"] = record.exc_text
        elif record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text", secrets: tuple[str, ...] = ()) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
    handler.addFilter(SecretMaskingFilter(secrets))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # httpx logs full request URLs (a Discord webhook URL *is* a credential): quieten these loggers and
    # scrub their records at the source so even a handler without the filter never sees a secret.
    for noisy in ("httpx", "httpcore"):
        noisy_logger = logging.getLogger(noisy)
        noisy_logger.setLevel(logging.WARNING)
        for existing in list(noisy_logger.filters):
            if isinstance(existing, SecretMaskingFilter):
                noisy_logger.removeFilter(existing)
        noisy_logger.addFilter(SecretMaskingFilter(secrets))
