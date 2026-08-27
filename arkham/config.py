"""Environment-driven configuration with explicit, actionable validation.

Settings are read from the process environment, optionally pre-loaded from a ``.env`` file.
Secrets are never logged; use :func:`mask_secret` / :func:`mask_phone` / :func:`mask_webhook_url`
when printing.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from arkham.security.urls import UrlValidationError, validate_discord_webhook_url

E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")
VALID_LLM_PROVIDERS = ("openai", "anthropic", "gemini", "template")
VALID_DELIVERY_PROVIDERS = ("discord", "twilio")
DEFAULT_DELIVERY_PROVIDER = "discord"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
DEFAULT_LLM_TIMEOUT_SECONDS = 180.0
MAX_LLM_TIMEOUT_SECONDS = 300.0
DEFAULT_MIN_PRIORITY = 35.0
MAX_LOOKBACK_HOURS = 168
#: Character budget quoted to the analyst model for the Discord brief (no SMS compression needed).
DISCORD_BRIEF_CHAR_BUDGET = 3200
DISCORD_WEBHOOK_HELP = (
    "In Discord: Server Settings -> Integrations -> Webhooks -> New Webhook (pick your private Arkham "
    "channel) -> Copy Webhook URL. Put it in .env as DISCORD_WEBHOOK_URL=... and never commit it."
)


class ConfigError(Exception):
    """Raised when configuration is invalid; message contains setup instructions."""


def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> dict[str, str]:
    """Minimal .env loader (KEY=value, quotes, comments, `export` prefix). Returns loaded pairs."""
    loaded: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return loaded
    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            # strip trailing inline comment (only when preceded by whitespace)
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if override or key not in os.environ:
            os.environ[key] = value
        loaded[key] = value
    return loaded


def mask_phone(phone: str | None) -> str:
    if not phone:
        return "<unset>"
    digits = phone.strip()
    if len(digits) <= 5:
        return "*" * len(digits)
    return digits[:2] + "*" * (len(digits) - 6) + digits[-4:]


def mask_secret(value: str | None) -> str:
    if not value:
        return "<unset>"
    if len(value) <= 8:
        return "*" * len(value)
    return value[:2] + "*" * 8 + value[-2:]


def mask_webhook_url(url: str | None) -> str:
    """``https://discord.com/api/webhooks/1234****5678/***`` — host kept, id partially kept, token gone."""
    if not url:
        return "<unset>"
    parts = urlsplit(url.strip())
    segments = [segment for segment in parts.path.split("/") if segment]
    if parts.scheme != "https" or not parts.hostname or "webhooks" not in segments:
        return "<invalid webhook url>"
    index = segments.index("webhooks")
    webhook_id = segments[index + 1] if len(segments) > index + 1 else ""
    shown = webhook_id[:4] + "****" + webhook_id[-4:] if len(webhook_id) >= 12 else "****"
    prefix = "/".join(segments[:index])
    return f"https://{parts.hostname}/{prefix}/webhooks/{shown}/***"


def webhook_token(url: str | None) -> str | None:
    """The secret token segment of a webhook URL (last path segment), or None."""
    if not url:
        return None
    segments = [segment for segment in urlsplit(url.strip()).path.split("/") if segment]
    return segments[-1] if len(segments) >= 2 and "webhooks" in segments else None


def _env_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_float(value: str | None, default: float | None) -> float | None:
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"Expected a number, got {value!r}") from exc


def _env_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"Expected an integer, got {value!r}") from exc


@dataclass(frozen=True)
class Settings:
    timezone: str = "America/New_York"
    delivery_hour: int = 8

    delivery_provider: str = DEFAULT_DELIVERY_PROVIDER
    discord_webhook_url: str | None = None

    # Legacy/optional Twilio SMS transport (ARKHAM_DELIVERY_PROVIDER=twilio)
    to_phone: str | None = None
    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_from_phone: str | None = None

    nvd_api_key: str | None = None

    llm_provider: str = "openai"
    llm_model: str | None = None
    llm_timeout_seconds: float = DEFAULT_LLM_TIMEOUT_SECONDS
    openai_api_key: str | None = None
    openai_base_url: str | None = None
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
    gemini_base_url: str | None = None
    llm_input_price_per_1m: float | None = None
    llm_output_price_per_1m: float | None = None
    sms_price_per_segment: float | None = None

    max_events: int = 8
    max_sms_chars: int = 900
    min_priority_score: float = DEFAULT_MIN_PRIORITY
    sms_emoji: bool = False
    lookback_hours: int = 24

    db_path: str = "data/arkham.db"
    log_level: str = "INFO"
    log_format: str = "text"
    disabled_sources: tuple[str, ...] = field(default_factory=tuple)

    http_timeout_seconds: float = 20.0
    http_max_bytes: int = 8 * 1024 * 1024
    user_agent: str = "Arkham-CTI/1.0 (+personal threat-intelligence agent)"

    crawl_enabled: bool = True
    crawl_global_concurrency: int = 6
    crawl_per_domain_concurrency: int = 1
    crawl_domain_delay_seconds: float = 0.25
    crawl_quality_threshold: float = 0.62
    crawl_browser_enabled: bool = False
    crawl_browser_concurrency: int = 1
    crawl_browser_timeout_seconds: float = 15.0
    crawl_http_max_bytes: int = 4 * 1024 * 1024
    crawl_max_text_chars: int = 50_000
    crawl_retries: int = 2
    crawl_max_retry_after_seconds: float = 30.0
    crawl_robots_cache_hours: int = 24
    crawl_robots_failure_cache_minutes: int = 30
    crawl_feed_min_chars: int = 600
    crawl_prefetch_min_score: int = 20

    # ------------------------------------------------------------------ helpers
    @property
    def tzinfo(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider != "template"

    @property
    def delivery_is_sms(self) -> bool:
        return self.delivery_provider == "twilio"

    @property
    def recipient_masked(self) -> str:
        """Masked destination of the configured transport (phone for SMS, webhook for Discord)."""
        if self.delivery_is_sms:
            return mask_phone(self.to_phone)
        return mask_webhook_url(self.discord_webhook_url)

    @property
    def brief_char_budget(self) -> int:
        """Character budget quoted to the analyst model; only SMS needs the tight phone-sized budget."""
        return self.max_sms_chars if self.delivery_is_sms else DISCORD_BRIEF_CHAR_BUDGET

    @property
    def rendered_size_limit(self) -> int | None:
        """Hard size limit enforced on the rendered brief (None: the transport renderer enforces its own)."""
        return self.max_sms_chars if self.delivery_is_sms else None

    def validate_base(self) -> list[str]:
        problems: list[str] = []
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            problems.append(f"ARKHAM_TIMEZONE={self.timezone!r} is not a valid IANA timezone (e.g. America/New_York).")
        if not 0 <= self.delivery_hour <= 23:
            problems.append("ARKHAM_DELIVERY_HOUR must be between 0 and 23.")
        if self.llm_provider not in VALID_LLM_PROVIDERS:
            problems.append(f"LLM_PROVIDER must be one of {', '.join(VALID_LLM_PROVIDERS)} (got {self.llm_provider!r}).")
        if (
            not isfinite(self.llm_timeout_seconds)
            or self.llm_timeout_seconds < 1
            or self.llm_timeout_seconds > MAX_LLM_TIMEOUT_SECONDS
        ):
            problems.append(
                f"ARKHAM_LLM_TIMEOUT_SECONDS must be between 1 and {MAX_LLM_TIMEOUT_SECONDS:g}."
            )
        if self.delivery_provider not in VALID_DELIVERY_PROVIDERS:
            problems.append(
                f"ARKHAM_DELIVERY_PROVIDER must be one of {', '.join(VALID_DELIVERY_PROVIDERS)} "
                f"(got {self.delivery_provider!r})."
            )
        if self.max_events < 1 or self.max_events > 15:
            problems.append("ARKHAM_MAX_EVENTS must be between 1 and 15.")
        if self.max_sms_chars < 300 or self.max_sms_chars > 4800:
            problems.append("ARKHAM_MAX_SMS_CHARS must be between 300 and 4800.")
        if self.lookback_hours < 1 or self.lookback_hours > MAX_LOOKBACK_HOURS:
            problems.append(f"ARKHAM_LOOKBACK_HOURS must be between 1 and {MAX_LOOKBACK_HOURS}.")
        crawl_ranges = (
            ("ARKHAM_CRAWL_GLOBAL_CONCURRENCY", self.crawl_global_concurrency, 1, 32),
            ("ARKHAM_CRAWL_PER_DOMAIN_CONCURRENCY", self.crawl_per_domain_concurrency, 1, 8),
            ("ARKHAM_CRAWL_DOMAIN_DELAY_SECONDS", self.crawl_domain_delay_seconds, 0, 60),
            ("ARKHAM_CRAWL_QUALITY_THRESHOLD", self.crawl_quality_threshold, 0, 1),
            ("ARKHAM_CRAWL_BROWSER_CONCURRENCY", self.crawl_browser_concurrency, 1, 4),
            ("ARKHAM_CRAWL_BROWSER_TIMEOUT_SECONDS", self.crawl_browser_timeout_seconds, 1, 60),
            ("ARKHAM_CRAWL_HTTP_MAX_BYTES", self.crawl_http_max_bytes, 64 * 1024, 16 * 1024 * 1024),
            ("ARKHAM_CRAWL_MAX_TEXT_CHARS", self.crawl_max_text_chars, 1_000, 200_000),
            ("ARKHAM_CRAWL_RETRIES", self.crawl_retries, 0, 3),
            ("ARKHAM_CRAWL_MAX_RETRY_AFTER_SECONDS", self.crawl_max_retry_after_seconds, 1, 300),
            ("ARKHAM_CRAWL_ROBOTS_CACHE_HOURS", self.crawl_robots_cache_hours, 1, 168),
            ("ARKHAM_CRAWL_ROBOTS_FAILURE_CACHE_MINUTES", self.crawl_robots_failure_cache_minutes, 1, 1440),
            ("ARKHAM_CRAWL_FEED_MIN_CHARS", self.crawl_feed_min_chars, 100, 10_000),
            ("ARKHAM_CRAWL_PREFETCH_MIN_SCORE", self.crawl_prefetch_min_score, 0, 100),
        )
        for name, value, minimum, maximum in crawl_ranges:
            if value < minimum or value > maximum:
                problems.append(f"{name} must be between {minimum} and {maximum}.")
        if self.to_phone and not E164_RE.match(self.to_phone):
            problems.append("ARKHAM_TO_PHONE must be E.164, e.g. +12125551234 (country code, digits only).")
        if self.twilio_from_phone and not E164_RE.match(self.twilio_from_phone):
            problems.append("TWILIO_FROM_PHONE must be E.164, e.g. +12125550100.")
        return problems

    def validate_llm(self) -> list[str]:
        problems: list[str] = []
        if self.llm_provider == "template":
            return problems
        if not self.llm_model:
            problems.append(
                "LLM_MODEL is not set. Choose a current, inexpensive model id from your provider's documentation "
                "and set LLM_MODEL=<model-id> in .env (or set LLM_PROVIDER=template for a no-API dry run)."
            )
        if self.llm_provider == "openai" and not self.openai_api_key:
            problems.append(
                "OPENAI_API_KEY is not set. Create a key at https://platform.openai.com/api-keys and put it in .env "
                "(or set LLM_PROVIDER=template for a no-API dry run)."
            )
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            problems.append(
                "ANTHROPIC_API_KEY is not set. Create a key at https://console.anthropic.com/ and put it in .env "
                "(or set LLM_PROVIDER=template for a no-API dry run)."
            )
        if self.llm_provider == "gemini" and not self.gemini_api_key:
            problems.append(
                "GEMINI_API_KEY is not set. Create a key at https://aistudio.google.com/apikey and put it in .env "
                "(or set LLM_PROVIDER=template for a no-API dry run)."
            )
        return problems

    def validate_delivery(self) -> list[str]:
        """Problems with the *selected* transport only; the other transport's settings are irrelevant."""
        if self.delivery_provider == "discord":
            return self._validate_discord()
        return self._validate_twilio()

    def _validate_discord(self) -> list[str]:
        if not self.discord_webhook_url:
            return [f"DISCORD_WEBHOOK_URL is not set. {DISCORD_WEBHOOK_HELP}"]
        try:
            validate_discord_webhook_url(self.discord_webhook_url)
        except UrlValidationError as exc:  # the message never contains the URL
            return [
                "DISCORD_WEBHOOK_URL is not a valid Discord incoming webhook URL "
                f"(expected https://discord.com/api/webhooks/<id>/<token>): {exc}. {DISCORD_WEBHOOK_HELP}"
            ]
        return []

    def _validate_twilio(self) -> list[str]:
        problems: list[str] = []
        if not self.to_phone:
            problems.append("ARKHAM_TO_PHONE is not set. Put your personal number in E.164 form, e.g. ARKHAM_TO_PHONE=+12125551234.")
        if not self.twilio_account_sid or not self.twilio_account_sid.startswith("AC"):
            problems.append("TWILIO_ACCOUNT_SID is missing or malformed. Copy the Account SID (starts with 'AC') from https://console.twilio.com.")
        if not self.twilio_auth_token:
            problems.append("TWILIO_AUTH_TOKEN is not set. Copy the Auth Token from https://console.twilio.com (Account Info).")
        if not self.twilio_from_phone:
            problems.append("TWILIO_FROM_PHONE is not set. Use an SMS-capable Twilio number in E.164 form (Phone Numbers -> Manage -> Active numbers).")
        return problems

    def summary_lines(self) -> list[str]:
        """Human-readable, secret-free configuration summary."""
        lines = [
            f"timezone={self.timezone} delivery_hour={self.delivery_hour:02d}:00",
            f"delivery_provider={self.delivery_provider} discord_webhook={mask_webhook_url(self.discord_webhook_url)}",
        ]
        if self.delivery_is_sms:
            lines += [
                f"to_phone={mask_phone(self.to_phone)} twilio_from={mask_phone(self.twilio_from_phone)}",
                f"twilio_sid={mask_secret(self.twilio_account_sid)} twilio_token={'set' if self.twilio_auth_token else '<unset>'}",
            ]
        return lines + [
            f"llm_provider={self.llm_provider} llm_model={self.llm_model or '<unset>'} "
            f"llm_timeout={self.llm_timeout_seconds:g}s "
            f"openai_key={'set' if self.openai_api_key else '<unset>'} "
            f"anthropic_key={'set' if self.anthropic_api_key else '<unset>'} "
            f"gemini_key={'set' if self.gemini_api_key else '<unset>'}",
            f"nvd_api_key={'set' if self.nvd_api_key else '<unset>'}",
            f"max_events={self.max_events} max_sms_chars={self.max_sms_chars} min_priority={self.min_priority_score} emoji={self.sms_emoji}",
            f"db_path={self.db_path} lookback_hours={self.lookback_hours} disabled_sources={list(self.disabled_sources) or '[]'}",
            f"crawl_enabled={self.crawl_enabled} crawl_concurrency={self.crawl_global_concurrency}/"
            f"{self.crawl_per_domain_concurrency} browser={self.crawl_browser_enabled} "
            f"quality_threshold={self.crawl_quality_threshold}",
        ]

    @property
    def secret_values(self) -> tuple[str, ...]:
        return tuple(
            value
            for value in (
                self.discord_webhook_url,
                webhook_token(self.discord_webhook_url),
                self.twilio_account_sid,
                self.twilio_auth_token,
                self.openai_api_key,
                self.anthropic_api_key,
                self.gemini_api_key,
                self.nvd_api_key,
            )
            if value
        )


def load_settings(env: Mapping[str, str] | None = None, *, dotenv_path: str | os.PathLike[str] | None = ".env") -> Settings:
    """Build :class:`Settings` from ``env`` (default: process env after loading ``.env``)."""
    if env is None:
        if dotenv_path is not None:
            load_dotenv(dotenv_path)
        env = os.environ

    def get(key: str) -> str | None:
        v = env.get(key)
        if v is None:
            return None
        v = v.strip()
        return v or None

    disabled = tuple(s.strip() for s in (get("ARKHAM_DISABLED_SOURCES") or "").split(",") if s.strip())
    settings = Settings(
        timezone=get("ARKHAM_TIMEZONE") or "America/New_York",
        delivery_hour=_env_int(get("ARKHAM_DELIVERY_HOUR"), 8),
        delivery_provider=(get("ARKHAM_DELIVERY_PROVIDER") or DEFAULT_DELIVERY_PROVIDER).lower(),
        discord_webhook_url=get("DISCORD_WEBHOOK_URL"),
        to_phone=get("ARKHAM_TO_PHONE"),
        twilio_account_sid=get("TWILIO_ACCOUNT_SID"),
        twilio_auth_token=get("TWILIO_AUTH_TOKEN"),
        twilio_from_phone=get("TWILIO_FROM_PHONE"),
        nvd_api_key=get("NVD_API_KEY"),
        llm_provider=(get("LLM_PROVIDER") or "openai").lower(),
        llm_model=get("LLM_MODEL"),
        llm_timeout_seconds=_env_float(
            get("ARKHAM_LLM_TIMEOUT_SECONDS"), DEFAULT_LLM_TIMEOUT_SECONDS
        ),
        openai_api_key=get("OPENAI_API_KEY"),
        openai_base_url=get("OPENAI_BASE_URL"),
        anthropic_api_key=get("ANTHROPIC_API_KEY"),
        gemini_api_key=get("GEMINI_API_KEY"),
        gemini_base_url=get("GEMINI_BASE_URL"),
        llm_input_price_per_1m=_env_float(get("LLM_INPUT_PRICE_PER_1M"), None),
        llm_output_price_per_1m=_env_float(get("LLM_OUTPUT_PRICE_PER_1M"), None),
        sms_price_per_segment=_env_float(get("SMS_PRICE_PER_SEGMENT"), None),
        max_events=_env_int(get("ARKHAM_MAX_EVENTS"), 8),
        max_sms_chars=_env_int(get("ARKHAM_MAX_SMS_CHARS"), 900),
        min_priority_score=_env_float(get("ARKHAM_MIN_PRIORITY_SCORE"), DEFAULT_MIN_PRIORITY) or DEFAULT_MIN_PRIORITY,
        sms_emoji=_env_bool(get("ARKHAM_SMS_EMOJI"), False),
        lookback_hours=_env_int(get("ARKHAM_LOOKBACK_HOURS"), 24),
        db_path=get("ARKHAM_DB_PATH") or "data/arkham.db",
        log_level=(get("ARKHAM_LOG_LEVEL") or "INFO").upper(),
        log_format=(get("ARKHAM_LOG_FORMAT") or "text").lower(),
        disabled_sources=disabled,
        http_timeout_seconds=_env_float(get("ARKHAM_HTTP_TIMEOUT"), 20.0) or 20.0,
        http_max_bytes=_env_int(get("ARKHAM_HTTP_MAX_BYTES"), 8 * 1024 * 1024),
        crawl_enabled=_env_bool(get("ARKHAM_CRAWL_ENABLED"), True),
        crawl_global_concurrency=_env_int(get("ARKHAM_CRAWL_GLOBAL_CONCURRENCY"), 6),
        crawl_per_domain_concurrency=_env_int(get("ARKHAM_CRAWL_PER_DOMAIN_CONCURRENCY"), 1),
        crawl_domain_delay_seconds=_env_float(get("ARKHAM_CRAWL_DOMAIN_DELAY_SECONDS"), 0.25) or 0.0,
        crawl_quality_threshold=_env_float(get("ARKHAM_CRAWL_QUALITY_THRESHOLD"), 0.62) or 0.0,
        crawl_browser_enabled=_env_bool(get("ARKHAM_CRAWL_BROWSER_ENABLED"), False),
        crawl_browser_concurrency=_env_int(get("ARKHAM_CRAWL_BROWSER_CONCURRENCY"), 1),
        crawl_browser_timeout_seconds=_env_float(get("ARKHAM_CRAWL_BROWSER_TIMEOUT_SECONDS"), 15.0) or 0.0,
        crawl_http_max_bytes=_env_int(get("ARKHAM_CRAWL_HTTP_MAX_BYTES"), 4 * 1024 * 1024),
        crawl_max_text_chars=_env_int(get("ARKHAM_CRAWL_MAX_TEXT_CHARS"), 50_000),
        crawl_retries=_env_int(get("ARKHAM_CRAWL_RETRIES"), 2),
        crawl_max_retry_after_seconds=_env_float(get("ARKHAM_CRAWL_MAX_RETRY_AFTER_SECONDS"), 30.0) or 0.0,
        crawl_robots_cache_hours=_env_int(get("ARKHAM_CRAWL_ROBOTS_CACHE_HOURS"), 24),
        crawl_robots_failure_cache_minutes=_env_int(get("ARKHAM_CRAWL_ROBOTS_FAILURE_CACHE_MINUTES"), 30),
        crawl_feed_min_chars=_env_int(get("ARKHAM_CRAWL_FEED_MIN_CHARS"), 600),
        crawl_prefetch_min_score=_env_int(get("ARKHAM_CRAWL_PREFETCH_MIN_SCORE"), 20),
    )
    base_problems = settings.validate_base()
    if base_problems:
        raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(base_problems))
    return settings
