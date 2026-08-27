"""Discord webhook configuration: URL allow-listing, masking, secret handling, provider selection."""

from __future__ import annotations

import logging

import pytest

from arkham.config import ConfigError, Settings, load_settings, mask_webhook_url
from arkham.logging_setup import SecretMaskingFilter
from arkham.security.urls import UrlValidationError, validate_discord_webhook_url

WEBHOOK_ID = "123456789012345678"
WEBHOOK_TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz0123"
WEBHOOK = f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}"


# ---------------------------------------------------------------------------- URL allow-list


@pytest.mark.parametrize(
    "url",
    [
        WEBHOOK,
        f"https://discordapp.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://ptb.discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://canary.discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://discord.com/api/v10/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"  {WEBHOOK}  ",
    ],
)
def test_valid_discord_webhook_urls_are_accepted(url: str) -> None:
    assert validate_discord_webhook_url(url) == url.strip()


@pytest.mark.parametrize(
    "url",
    [
        f"http://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # plain http
        f"https://localhost/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://127.0.0.1/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://10.0.0.5/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://169.254.169.254/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://metadata.google.internal/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",
        f"https://example.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # arbitrary domain
        f"https://discord.com.evil.example/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # suffix trick
        f"https://evil.example/discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # path trick
        f"https://user:pass@discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # credentials
        f"https://discord.com:8443/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}",  # odd port
        f"https://discord.com/api/webhooks/{WEBHOOK_ID}",  # no token
        f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}?wait=true",  # query
        f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}#frag",
        f"https://discord.com/api/channels/{WEBHOOK_ID}/messages",  # not a webhook path
        f"https://discord.com/api/webhooks/not-a-snowflake/{WEBHOOK_TOKEN}",
        f"https://discord.com/api/webhooks/{WEBHOOK_ID}/short",
        f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}/extra",
        "",
        "not a url",
    ],
)
def test_invalid_discord_webhook_urls_are_rejected(url: str) -> None:
    with pytest.raises(UrlValidationError) as excinfo:
        validate_discord_webhook_url(url)
    # The error text never echoes the token.
    assert WEBHOOK_TOKEN not in str(excinfo.value)


# ---------------------------------------------------------------------------- masking


def test_mask_webhook_url_hides_token_and_most_of_the_id() -> None:
    masked = mask_webhook_url(WEBHOOK)
    assert masked.startswith("https://discord.com/api/webhooks/")
    assert WEBHOOK_TOKEN not in masked
    assert WEBHOOK_ID not in masked
    assert masked.endswith("/***")
    assert mask_webhook_url(None) == "<unset>"
    assert mask_webhook_url("") == "<unset>"
    assert WEBHOOK_TOKEN not in mask_webhook_url("garbage/" + WEBHOOK_TOKEN)


# ---------------------------------------------------------------------------- settings


def test_discord_is_the_default_delivery_provider() -> None:
    settings = load_settings({}, dotenv_path=None)
    assert settings.delivery_provider == "discord"
    assert settings.discord_webhook_url is None


def test_missing_webhook_reports_actionable_problem_without_twilio_noise() -> None:
    problems = load_settings({}, dotenv_path=None).validate_delivery()
    joined = "\n".join(problems)
    assert "DISCORD_WEBHOOK_URL" in joined
    assert "Integrations" in joined  # where to find it in Discord
    assert "TWILIO" not in joined
    assert "ARKHAM_TO_PHONE" not in joined


def test_invalid_webhook_is_reported_without_echoing_it() -> None:
    bad = f"https://example.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}"
    problems = load_settings({"DISCORD_WEBHOOK_URL": bad}, dotenv_path=None).validate_delivery()
    assert problems and "DISCORD_WEBHOOK_URL" in problems[0]
    assert WEBHOOK_TOKEN not in "\n".join(problems)


def test_valid_webhook_config_is_ready() -> None:
    settings = load_settings({"DISCORD_WEBHOOK_URL": WEBHOOK}, dotenv_path=None)
    assert settings.validate_delivery() == []
    assert settings.recipient_masked == mask_webhook_url(WEBHOOK)


def test_twilio_stays_selectable_as_legacy_provider() -> None:
    settings = load_settings({"ARKHAM_DELIVERY_PROVIDER": "twilio"}, dotenv_path=None)
    assert settings.delivery_provider == "twilio"
    joined = "\n".join(settings.validate_delivery())
    for key in ("ARKHAM_TO_PHONE", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_PHONE"):
        assert key in joined
    assert "DISCORD_WEBHOOK_URL" not in joined
    ready = load_settings(
        {
            "ARKHAM_DELIVERY_PROVIDER": "twilio",
            "ARKHAM_TO_PHONE": "+12025550143",
            "TWILIO_ACCOUNT_SID": "AC" + "a" * 32,
            "TWILIO_AUTH_TOKEN": "tok" * 8,
            "TWILIO_FROM_PHONE": "+12025550199",
        },
        dotenv_path=None,
    )
    assert ready.validate_delivery() == []
    assert ready.recipient_masked == "+1******0143"


def test_unknown_delivery_provider_is_rejected() -> None:
    with pytest.raises(ConfigError, match="ARKHAM_DELIVERY_PROVIDER"):
        load_settings({"ARKHAM_DELIVERY_PROVIDER": "pigeon"}, dotenv_path=None)


def test_discord_config_does_not_require_twilio_or_phone_number() -> None:
    settings = load_settings({"DISCORD_WEBHOOK_URL": WEBHOOK}, dotenv_path=None)
    assert settings.to_phone is None and settings.twilio_account_sid is None
    assert settings.validate_delivery() == []


def test_webhook_url_and_token_are_secrets_and_never_in_summary() -> None:
    settings = load_settings({"DISCORD_WEBHOOK_URL": WEBHOOK}, dotenv_path=None)
    assert WEBHOOK in settings.secret_values
    assert WEBHOOK_TOKEN in settings.secret_values
    summary = "\n".join(settings.summary_lines())
    assert WEBHOOK_TOKEN not in summary
    assert "delivery_provider=discord" in summary
    assert "discord_webhook=" in summary


def test_settings_is_still_immutable() -> None:
    settings = Settings(discord_webhook_url=WEBHOOK)
    with pytest.raises(AttributeError):
        settings.discord_webhook_url = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------- logging redaction


def _scrub(text: str, secrets: tuple[str, ...] = ()) -> str:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, text, (), None)
    SecretMaskingFilter(secrets).filter(record)
    return record.getMessage()


def test_logging_filter_redacts_configured_webhook_and_bare_token() -> None:
    settings = load_settings({"DISCORD_WEBHOOK_URL": WEBHOOK}, dotenv_path=None)
    scrubbed = _scrub(f"posting to {WEBHOOK} failed; token {WEBHOOK_TOKEN}", settings.secret_values)
    assert WEBHOOK_TOKEN not in scrubbed and WEBHOOK not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_logging_filter_redacts_any_webhook_shaped_url_even_when_unconfigured() -> None:
    other = f"https://discordapp.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}"
    scrubbed = _scrub(f"HTTP 404 from {other}")
    assert WEBHOOK_TOKEN not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_configured_logging_scrubs_httpx_request_lines(capsys) -> None:
    """httpx logs the full request URL (token included); the configured filter must catch it on the way out."""
    from arkham.logging_setup import configure_logging

    root = logging.getLogger()
    saved = list(root.handlers)
    try:
        configure_logging("INFO", "text", (WEBHOOK,))
        logging.getLogger("httpx").warning("HTTP Request: POST %s?wait=true \"HTTP/1.1 200 OK\"", WEBHOOK)
        logging.getLogger("httpx").info("HTTP Request: POST %s?wait=true", WEBHOOK)
        for handler in root.handlers:
            handler.flush()
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved:
            root.addHandler(handler)
    err = capsys.readouterr().err
    assert WEBHOOK_TOKEN not in err and WEBHOOK_ID not in err
    assert "[REDACTED]" in err


def test_logging_filter_redacts_gemini_style_keys() -> None:
    key = "AIza" + "x" * 35
    assert key not in _scrub(f"key={key}")


# ---------------------------------------------------------------------------- gemini


def test_gemini_provider_requires_key_and_model_and_is_a_secret() -> None:
    settings = load_settings({"LLM_PROVIDER": "gemini"}, dotenv_path=None)
    joined = "\n".join(settings.validate_llm())
    assert "GEMINI_API_KEY" in joined and "LLM_MODEL" in joined
    ready = load_settings(
        {"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "AIza" + "k" * 35, "LLM_MODEL": "gemini-model"},
        dotenv_path=None,
    )
    assert ready.validate_llm() == []
    assert ready.llm_enabled
    assert "AIza" + "k" * 35 in ready.secret_values
    assert "AIza" + "k" * 35 not in "\n".join(ready.summary_lines())
