from __future__ import annotations

import pytest

from arkham.config import ConfigError, Settings, load_dotenv, load_settings, mask_phone, mask_secret


def test_load_settings_defaults_from_empty_env():
    s = load_settings({}, dotenv_path=None)
    assert s.timezone == "America/New_York"
    assert s.delivery_hour == 8
    assert s.max_events == 8
    assert s.max_sms_chars == 900
    assert s.min_priority_score == 35.0
    assert s.llm_provider == "openai"
    assert s.llm_timeout_seconds == 180.0
    assert s.http_timeout_seconds == 20.0
    assert s.sms_emoji is False
    assert s.crawl_enabled is True
    assert s.crawl_global_concurrency == 6
    assert s.crawl_per_domain_concurrency == 1
    assert s.crawl_domain_delay_seconds == 0.25
    assert s.crawl_quality_threshold == 0.62
    assert s.crawl_browser_enabled is False
    assert s.crawl_browser_concurrency == 1
    assert s.crawl_retries == 2
    assert s.crawl_max_text_chars == 50_000


def test_load_settings_reads_llm_timeout_without_changing_source_timeout() -> None:
    settings = load_settings({"ARKHAM_LLM_TIMEOUT_SECONDS": "240"}, dotenv_path=None)
    assert settings.llm_timeout_seconds == 240.0
    assert settings.http_timeout_seconds == 20.0


@pytest.mark.parametrize("value", ["0", "-1", "301", "nan"])
def test_out_of_range_llm_timeout_is_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="ARKHAM_LLM_TIMEOUT_SECONDS"):
        load_settings({"ARKHAM_LLM_TIMEOUT_SECONDS": value}, dotenv_path=None)


def test_non_numeric_llm_timeout_is_rejected_cleanly() -> None:
    with pytest.raises(ConfigError, match="Expected a number"):
        load_settings({"ARKHAM_LLM_TIMEOUT_SECONDS": "slow"}, dotenv_path=None)


def test_load_settings_reads_crawl_limits() -> None:
    settings = load_settings(
        {
            "ARKHAM_CRAWL_ENABLED": "false",
            "ARKHAM_CRAWL_GLOBAL_CONCURRENCY": "4",
            "ARKHAM_CRAWL_PER_DOMAIN_CONCURRENCY": "2",
            "ARKHAM_CRAWL_DOMAIN_DELAY_SECONDS": "1.5",
            "ARKHAM_CRAWL_QUALITY_THRESHOLD": "0.7",
            "ARKHAM_CRAWL_BROWSER_ENABLED": "true",
            "ARKHAM_CRAWL_BROWSER_CONCURRENCY": "2",
            "ARKHAM_CRAWL_BROWSER_TIMEOUT_SECONDS": "12",
            "ARKHAM_CRAWL_HTTP_MAX_BYTES": "1048576",
            "ARKHAM_CRAWL_MAX_TEXT_CHARS": "20000",
            "ARKHAM_CRAWL_RETRIES": "1",
            "ARKHAM_CRAWL_MAX_RETRY_AFTER_SECONDS": "9",
            "ARKHAM_CRAWL_ROBOTS_CACHE_HOURS": "12",
            "ARKHAM_CRAWL_ROBOTS_FAILURE_CACHE_MINUTES": "10",
            "ARKHAM_CRAWL_FEED_MIN_CHARS": "400",
            "ARKHAM_CRAWL_PREFETCH_MIN_SCORE": "25",
        },
        dotenv_path=None,
    )
    assert settings.crawl_enabled is False
    assert settings.crawl_global_concurrency == 4
    assert settings.crawl_per_domain_concurrency == 2
    assert settings.crawl_domain_delay_seconds == 1.5
    assert settings.crawl_quality_threshold == 0.7
    assert settings.crawl_browser_enabled is True
    assert settings.crawl_browser_concurrency == 2
    assert settings.crawl_browser_timeout_seconds == 12
    assert settings.crawl_http_max_bytes == 1_048_576
    assert settings.crawl_max_text_chars == 20_000
    assert settings.crawl_retries == 1
    assert settings.crawl_max_retry_after_seconds == 9
    assert settings.crawl_robots_cache_hours == 12
    assert settings.crawl_robots_failure_cache_minutes == 10
    assert settings.crawl_feed_min_chars == 400
    assert settings.crawl_prefetch_min_score == 25


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ARKHAM_CRAWL_GLOBAL_CONCURRENCY", "0"),
        ("ARKHAM_CRAWL_PER_DOMAIN_CONCURRENCY", "0"),
        ("ARKHAM_CRAWL_DOMAIN_DELAY_SECONDS", "-1"),
        ("ARKHAM_CRAWL_QUALITY_THRESHOLD", "1.1"),
        ("ARKHAM_CRAWL_BROWSER_CONCURRENCY", "0"),
        ("ARKHAM_CRAWL_BROWSER_TIMEOUT_SECONDS", "0"),
        ("ARKHAM_CRAWL_HTTP_MAX_BYTES", "1024"),
        ("ARKHAM_CRAWL_MAX_TEXT_CHARS", "100"),
        ("ARKHAM_CRAWL_RETRIES", "5"),
        ("ARKHAM_CRAWL_MAX_RETRY_AFTER_SECONDS", "0"),
        ("ARKHAM_CRAWL_ROBOTS_CACHE_HOURS", "0"),
        ("ARKHAM_CRAWL_ROBOTS_FAILURE_CACHE_MINUTES", "0"),
        ("ARKHAM_CRAWL_FEED_MIN_CHARS", "20"),
        ("ARKHAM_CRAWL_PREFETCH_MIN_SCORE", "101"),
    ],
)
def test_invalid_crawl_limits_are_rejected(key: str, value: str) -> None:
    with pytest.raises(ConfigError, match=key):
        load_settings({key: value}, dotenv_path=None)


def test_validate_llm_lists_actionable_instructions():
    s = load_settings({"LLM_PROVIDER": "openai"}, dotenv_path=None)
    problems = s.validate_llm()
    assert any("LLM_MODEL" in p for p in problems)
    assert any("OPENAI_API_KEY" in p for p in problems)
    assert any("platform.openai.com" in p for p in problems)


def test_template_provider_needs_no_credentials():
    s = load_settings({"LLM_PROVIDER": "template"}, dotenv_path=None)
    assert s.validate_llm() == []
    assert not s.llm_enabled


def test_validate_delivery_requires_all_twilio_settings():
    s = load_settings({"ARKHAM_DELIVERY_PROVIDER": "twilio"}, dotenv_path=None)
    problems = s.validate_delivery()
    joined = "\n".join(problems)
    for key in ("ARKHAM_TO_PHONE", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_PHONE"):
        assert key in joined


def test_delivery_ready_with_complete_config():
    env = {
        "ARKHAM_DELIVERY_PROVIDER": "twilio",
        "ARKHAM_TO_PHONE": "+12025550143",
        "TWILIO_ACCOUNT_SID": "AC" + "a" * 32,
        "TWILIO_AUTH_TOKEN": "tok" * 8,
        "TWILIO_FROM_PHONE": "+12025550199",
    }
    assert load_settings(env, dotenv_path=None).validate_delivery() == []


@pytest.mark.parametrize("phone", ["2025550143", "+1 202 555 0143", "+0123", "12025550143"])
def test_invalid_phone_rejected(phone):
    with pytest.raises(ConfigError):
        load_settings({"ARKHAM_TO_PHONE": phone}, dotenv_path=None)


def test_invalid_timezone_and_provider_rejected():
    with pytest.raises(ConfigError, match="ARKHAM_TIMEZONE"):
        load_settings({"ARKHAM_TIMEZONE": "Mars/Olympus"}, dotenv_path=None)
    with pytest.raises(ConfigError, match="LLM_PROVIDER"):
        load_settings({"LLM_PROVIDER": "magic"}, dotenv_path=None)


def test_dotenv_loader_handles_quotes_comments_and_export(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nexport ARKHAM_TIMEZONE='Europe/Berlin'\nARKHAM_MAX_EVENTS=5 # inline\nLLM_MODEL=\"model-x\"\nBAD LINE\n"
    )
    monkeypatch.delenv("ARKHAM_TIMEZONE", raising=False)
    monkeypatch.delenv("ARKHAM_MAX_EVENTS", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    loaded = load_dotenv(env_file)
    assert loaded == {"ARKHAM_TIMEZONE": "Europe/Berlin", "ARKHAM_MAX_EVENTS": "5", "LLM_MODEL": "model-x"}
    s = load_settings(dotenv_path=env_file)
    assert s.timezone == "Europe/Berlin" and s.max_events == 5


def test_dotenv_does_not_override_existing_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ARKHAM_MAX_EVENTS", "3")
    (tmp_path / ".env").write_text("ARKHAM_MAX_EVENTS=9\n")
    load_dotenv(tmp_path / ".env")
    assert load_settings(dotenv_path=None).max_events == 3


def test_masking_and_summary_never_expose_secrets():
    env = {
        "ARKHAM_TO_PHONE": "+12025550143",
        "TWILIO_ACCOUNT_SID": "AC" + "b" * 32,
        "TWILIO_AUTH_TOKEN": "supersecrettoken123",
        "OPENAI_API_KEY": "sk-verysecretkey",
        "LLM_MODEL": "m",
    }
    s = load_settings(env, dotenv_path=None)
    text = "\n".join(s.summary_lines())
    assert "supersecrettoken123" not in text
    assert "sk-verysecretkey" not in text
    assert "+12025550143" not in text
    assert mask_phone("+12025550143") == "+1******0143"
    assert mask_secret("supersecrettoken123").startswith("su") and "secret" not in mask_secret("supersecrettoken123")
    assert set(s.secret_values) == {
        "AC" + "b" * 32,
        "supersecrettoken123",
        "sk-verysecretkey",
    }


def test_settings_is_immutable():
    s = Settings()
    with pytest.raises(AttributeError):
        s.max_events = 2  # type: ignore[misc]
