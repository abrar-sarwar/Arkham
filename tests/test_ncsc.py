"""Tests for the UK NCSC adapter against trimmed live feed samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import SourceCategory, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.ncsc import NcscAdapter, ncsc_kind
from tests.conftest import RouteTable, load_fixture_text

ALL_URL = "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
REPORT_URL = "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"
NEWS_URL = "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"
UTC = timezone.utc


def make_source(url: str = ALL_URL, source_id: str = "ncsc_all", **overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": source_id,
        "name": "UK NCSC",
        "type": "rss",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.ADVISORY,
        "url": url,
        "adapter": "ncsc",
        "publisher": "NCSC",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(routes: RouteTable, now: datetime, hours: int = 24) -> FetchContext:
    return FetchContext(http=routes.client(), window_start=now - timedelta(hours=hours), window_end=now, now=now)


def fetch_all(routes: RouteTable, url: str, fixture: str, source_id: str = "ncsc_all"):
    routes.add(url, load_fixture_text(fixture))
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = NcscAdapter(make_source(url, source_id)).fetch(make_ctx(routes, now, hours=24 * 365 * 5))
    assert result.status.ok, result.status
    return result


def test_parses_all_feed(routes: RouteTable) -> None:
    result = fetch_all(routes, ALL_URL, "ncsc_all.xml")
    assert len(result.items) == 5
    first = result.items[0]
    assert first.title == "Managing the cyber risk of agentic AI"
    assert first.url == "https://www.ncsc.gov.uk/blogs/managing-the-cyber-risk-of-agentic-ai"
    assert first.external_id == first.url
    assert first.published_at == datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    assert first.extra["publisher"] == "NCSC"
    assert first.extra["ncsc_kind"] == "blog"
    assert first.extra["ncsc_alert"] is False
    assert first.extra["cve_ids"] == []
    assert [item.extra["ncsc_kind"] for item in result.items] == ["blog", "blog", "news", "news", "news"]
    assert all(item.published_at is not None and item.published_at.tzinfo is not None for item in result.items)


def test_report_feed_kind(routes: RouteTable) -> None:
    result = fetch_all(routes, REPORT_URL, "ncsc_report.xml", source_id="ncsc_report")
    assert len(result.items) == 3
    assert {item.extra["ncsc_kind"] for item in result.items} == {"report"}
    assert result.items[0].url == "https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027"
    assert result.items[0].published_at == datetime(2025, 5, 7, 12, 0, tzinfo=UTC)
    assert result.items[-1].title == "Malware analysis report on SparrowDoor malware"


def test_news_feed_kind_and_alert_flag(routes: RouteTable) -> None:
    result = fetch_all(routes, NEWS_URL, "ncsc_news.xml", source_id="ncsc_news")
    assert len(result.items) == 4
    assert {item.extra["ncsc_kind"] for item in result.items} == {"news"}
    by_url = {item.url: item for item in result.items}
    fortinet = by_url["https://www.ncsc.gov.uk/news/advice-following-global-targeting-of-fortinet-firewalls-and-vpn-gateways"]
    assert fortinet.extra["ncsc_alert"] is True
    assert fortinet.title.startswith("Alert:")
    f5 = by_url["https://www.ncsc.gov.uk/news/vulnerability-affecting-f5-big-ip-apm"]
    assert f5.extra["ncsc_alert"] is False


def test_all_feed_contains_news_items_in_its_date_range(routes: RouteTable) -> None:
    """The all-rss-feed carries blog and news entries; news within its range appears in both."""
    all_result = fetch_all(routes, ALL_URL, "ncsc_all.xml")
    news_result = fetch_all(routes, NEWS_URL, "ncsc_news.xml", source_id="ncsc_news")
    all_urls = {item.url for item in all_result.items}
    oldest_all = min(item.published_at for item in all_result.items if item.published_at)
    recent_news = {item.url for item in news_result.items if item.published_at and item.published_at >= oldest_all}
    assert recent_news
    assert recent_news <= all_urls
    # report items are not part of the all feed sample
    report_result = fetch_all(routes, REPORT_URL, "ncsc_report.xml", source_id="ncsc_report")
    assert not {item.url for item in report_result.items} & all_urls


def test_window_filtering(routes: RouteTable) -> None:
    routes.add(ALL_URL, load_fixture_text("ncsc_all.xml"))
    now = datetime(2026, 8, 21, 0, 0, tzinfo=UTC)
    result = NcscAdapter(make_source()).fetch(make_ctx(routes, now, hours=24))
    assert result.status.ok
    assert [item.title for item in result.items] == ["Managing the cyber risk of agentic AI"]


def test_text_is_sanitized(routes: RouteTable) -> None:
    result = fetch_all(routes, ALL_URL, "ncsc_all.xml")
    for item in result.items:
        assert "<" not in item.summary and ">" not in item.summary
        assert "<" not in item.title and ">" not in item.title
    bitlocker = result.items[1]
    assert bitlocker.summary.startswith("Using a PIN mitigates many BitLocker vulnerabilities.")


def test_http_500_reports_failure(routes: RouteTable) -> None:
    routes.add(ALL_URL, "server error", status=500)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = NcscAdapter(make_source()).fetch(make_ctx(routes, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []


def test_ncsc_kind_helper() -> None:
    assert ncsc_kind("https://www.ncsc.gov.uk/news/some-story") == "news"
    assert ncsc_kind("https://www.ncsc.gov.uk/report/some-report") == "report"
    assert ncsc_kind("https://www.ncsc.gov.uk/guidance/some-guidance") == "guidance"
    assert ncsc_kind("https://www.ncsc.gov.uk/blogs/some-post") == "blog"
    assert ncsc_kind("https://www.ncsc.gov.uk/blog-post/some-post") == "blog"
    assert ncsc_kind("https://www.ncsc.gov.uk/collection/device-security-guidance") == "collection"
    assert ncsc_kind("https://www.ncsc.gov.uk/") == "other"
    assert ncsc_kind("https://www.ncsc.gov.uk/section/keep-up-to-date") == "other"
