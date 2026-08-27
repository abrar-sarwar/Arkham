from __future__ import annotations

import pytest

from arkham.crawl.models import CrawlFailureReason, CrawlMetrics, FetchMethod
from arkham.crawl.normalize import accept_canonical_url, normalize_crawl_url
from arkham.models import RunRecord
from arkham.security.urls import UrlValidationError


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            " HTTPS://WWW.Example.COM//security/post/?utm_source=rss&utm_medium=email&id=7#details ",
            "https://example.com/security/post?id=7",
        ),
        (
            "https://example.com/advisory?source=archive&ref=GHSA-abcd-1234-zzzz&fbclid=noise",
            "https://example.com/advisory?ref=GHSA-abcd-1234-zzzz&source=archive",
        ),
        (
            "https://example.com/download?file=patch.zip&mc_cid=campaign&mc_eid=person",
            "https://example.com/download?file=patch.zip",
        ),
    ],
)
def test_normalize_crawl_url_removes_marketing_noise_but_keeps_resource_parameters(
    raw: str, expected: str
) -> None:
    assert normalize_crawl_url(raw) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not a url",
        "http://example.com/article",
        "https://127.0.0.1/admin",
        "https://metadata.google.internal/latest",
        "https://user:password@example.com/article",
    ],
)
def test_normalize_crawl_url_rejects_malformed_or_unsafe_urls(url: str) -> None:
    with pytest.raises(UrlValidationError):
        normalize_crawl_url(url)


def test_accept_canonical_url_requires_public_related_host() -> None:
    response = "https://news.example.com/story/old"
    assert accept_canonical_url(response, "https://www.news.example.com/story/current") == (
        "https://news.example.com/story/current"
    )
    assert accept_canonical_url(response, "https://attacker.example.net/copy") is None
    assert accept_canonical_url(response, "http://news.example.com/story/current") is None
    assert accept_canonical_url(response, "https://127.0.0.1/story/current") is None


def test_crawl_contract_defaults_are_safe_and_persistable(now) -> None:
    metrics = CrawlMetrics(feed_api_items_discovered=3, urls_normalized=2)
    run = RunRecord(run_id="r1", mode="dry-run", started_at=now, crawl=metrics)
    loaded = RunRecord.model_validate_json(run.model_dump_json())
    assert loaded.crawl.feed_api_items_discovered == 3
    assert loaded.crawl.browser_renders_attempted == 0
    assert FetchMethod.FEED.value == "feed"
    assert CrawlFailureReason.ROBOTS_DENIED.value == "robots_denied"

