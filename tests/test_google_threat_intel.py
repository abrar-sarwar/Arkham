"""Tests for the Google Threat Intelligence blog adapter against trimmed live feed samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import SourceCategory, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.google_threat_intel import GoogleThreatIntelAdapter, parse_authors
from arkham.sources.rss import CONTENT_MAX, SUMMARY_MAX
from tests.conftest import RouteTable, load_fixture_text

FEED_URL = "https://cloud.google.com/blog/topics/threat-intelligence/rss"
UTC = timezone.utc


def make_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "google_threat_intel",
        "name": "Google Threat Intelligence",
        "type": "rss",
        "tier": SourceTier.RESEARCH,
        "category": SourceCategory.THREAT_INTEL,
        "url": FEED_URL,
        "adapter": "google_threat_intel",
        "publisher": "Google",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(routes: RouteTable, now: datetime, hours: int = 24) -> FetchContext:
    return FetchContext(http=routes.client(), window_start=now - timedelta(hours=hours), window_end=now, now=now)


def fetch_all(routes: RouteTable):
    routes.add(FEED_URL, load_fixture_text("gtig_blog.xml"))
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = GoogleThreatIntelAdapter(make_source()).fetch(make_ctx(routes, now, hours=24 * 365))
    assert result.status.ok, result.status
    return result


def test_parses_real_posts(routes: RouteTable) -> None:
    result = fetch_all(routes)
    assert len(result.items) == 4
    item = result.items[0]
    assert item.title == "Batten Down Your Packages: Mitigation Guidance for Supply Chain Compromise"
    assert item.url == (
        "https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise/"
    )
    assert item.published_at == datetime(2026, 7, 30, 14, 0, tzinfo=UTC)
    assert item.source_tier == SourceTier.RESEARCH
    assert item.extra["publisher"] == "Google"
    assert item.extra["author"] == "Mandiant"
    assert item.extra["authors"] == ["Kelli Vanderlee", "Stuart Carrera"]
    assert item.extra["categories"] == ["Threat Intelligence"]
    assert "APT29" in item.extra["actor_mentions"]
    assert "UNC4736" in item.extra["actor_mentions"]
    assert item.extra["exploitation_hint"] == "active"
    assert item.extra["referenced_links"]


def test_summary_is_trimmed_sanitized_body_without_byline(routes: RouteTable) -> None:
    result = fetch_all(routes)
    item = result.items[0]
    assert 0 < len(item.summary) <= SUMMARY_MAX
    assert not item.summary.startswith("Written by")
    assert item.summary.startswith("For years, the cybersecurity industry's understanding of software supply chain compromise")
    assert "<" not in item.summary and ">" not in item.summary
    assert 0 < len(item.content) <= CONTENT_MAX
    assert len(item.content) > len(item.summary)
    assert "<" not in item.content and ">" not in item.content
    assert not item.content.startswith("Written by")


def test_cves_and_multiple_authors(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_title = {item.title: item for item in result.items}
    cisco = by_title["Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager"]
    assert cisco.extra["cve_ids"][0] == "CVE-2026-20245"
    assert set(cisco.extra["cve_ids"]) >= {"CVE-2026-20245", "CVE-2026-20127", "CVE-2026-20182"}
    assert cisco.extra["authors"] == ["Chester Sng", "Pete Boonyakarn", "Logeswaran Nadarajan", "Lukasz Lamparski"]
    assert cisco.published_at == datetime(2026, 6, 24, 11, 0, tzinfo=UTC)

    lms = by_title["Exploitation of KnowledgeDeliver via ViewState Deserialization Vulnerability"]
    assert lms.extra["cve_ids"] == ["CVE-2026-5426"]
    assert lms.extra["authors"] == ["Takahiro Sugiyama", "Peter Revelant", "Mathew Potaczek"]
    assert lms.extra["author"] == "Google Threat Intelligence Group"


def test_post_without_byline(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_title = {item.title: item for item in result.items}
    proxy = by_title["Google’s Continued Disruption of Malicious Residential Proxy Networks"]
    assert proxy.extra["authors"] == []
    assert proxy.extra["actor_mentions"] == []
    assert proxy.extra["cve_ids"] == []
    assert proxy.extra["exploitation_hint"] is None
    assert proxy.summary.startswith("Background")


def test_window_filtering(routes: RouteTable) -> None:
    routes.add(FEED_URL, load_fixture_text("gtig_blog.xml"))
    now = datetime(2026, 7, 31, 0, 0, tzinfo=UTC)
    result = GoogleThreatIntelAdapter(make_source()).fetch(make_ctx(routes, now, hours=24))
    assert result.status.ok
    assert [item.published_at for item in result.items] == [datetime(2026, 7, 30, 14, 0, tzinfo=UTC)]


def test_http_500_reports_failure(routes: RouteTable) -> None:
    routes.add(FEED_URL, "nope", status=500)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = GoogleThreatIntelAdapter(make_source()).fetch(make_ctx(routes, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []


def test_parse_authors_helper() -> None:
    assert parse_authors("Written by: Gabby Roncone, Wesley Shields\n\nOverview\n...") == ["Gabby Roncone", "Wesley Shields"]
    assert parse_authors("Written by: Jules Czarniak") == ["Jules Czarniak"]
    assert parse_authors("Written by Alice Example and Bob Example\nIntroduction") == ["Alice Example", "Bob Example"]
    assert parse_authors("Background\n\nToday Google took action") == []
    assert parse_authors("") == []
