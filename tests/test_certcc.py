"""Tests for the CERT/CC Vulnerability Notes adapter against trimmed live feed samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import SourceCategory, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.certcc import CertCcAdapter, overview_section, strip_boilerplate, vu_id_from_title
from arkham.sources.rss import CONTENT_MAX, SUMMARY_MAX
from tests.conftest import RouteTable, load_fixture_text

FEED_URL = "https://kb.cert.org/vuls/atomfeed/"
UTC = timezone.utc


def make_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "certcc",
        "name": "CERT/CC Vulnerability Notes",
        "type": "atom",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.VULNERABILITY,
        "url": FEED_URL,
        "adapter": "certcc",
        "publisher": "CERT/CC",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(routes: RouteTable, now: datetime, hours: int = 24) -> FetchContext:
    return FetchContext(http=routes.client(), window_start=now - timedelta(hours=hours), window_end=now, now=now)


def fetch_all(routes: RouteTable):
    routes.add(FEED_URL, load_fixture_text("certcc_atom.xml"))
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = CertCcAdapter(make_source()).fetch(make_ctx(routes, now, hours=24 * 365))
    assert result.status.ok, result.status
    return result


def test_parses_real_notes(routes: RouteTable) -> None:
    result = fetch_all(routes)
    assert len(result.items) == 4
    item = result.items[0]
    assert item.title == "VU#308749: Remote Code Execution and Arbitrary File Read Vulnerabilities in Kaltura Servers"
    assert item.url == "https://kb.cert.org/vuls/id/308749"
    assert item.external_id == "https://kb.cert.org/vuls/id/308749"
    assert item.published_at == datetime(2026, 8, 25, 16, 11, 49, 36497, tzinfo=UTC)
    assert item.updated_at == datetime(2026, 8, 25, 16, 58, 54, 824143, tzinfo=UTC)
    assert item.extra["publisher"] == "CERT/CC"
    assert item.extra["vu_id"] == "VU#308749"
    assert set(item.extra["cve_ids"]) == {"CVE-2026-19912", "CVE-2026-19913"}
    assert item.extra["exploitation_hint"] is None
    assert item.extra["date_public"] == "2026-08-25"
    assert item.extra["document_revision"] == "3"
    assert [i.extra["vu_id"] for i in result.items] == ["VU#308749", "VU#728712", "VU#431093", "VU#487613"]


def test_summary_is_the_overview_section(routes: RouteTable) -> None:
    result = fetch_all(routes)
    item = result.items[0]
    assert item.summary.startswith("The Kaltura HTML5 Player Library (mwEmbed / html5lib) contains two vulnerabilities")
    assert item.summary.endswith("restrict access to the affected endpoint or disable it entirely.")
    assert "Overview" not in item.summary
    assert "Description" not in item.summary
    assert len(item.summary) <= SUMMARY_MAX
    for entry in result.items:
        assert "<" not in entry.summary and ">" not in entry.summary
        assert "<" not in entry.title and ">" not in entry.title
        assert entry.summary and not entry.summary.startswith("Overview")


def test_content_is_sanitized_and_free_of_boilerplate(routes: RouteTable) -> None:
    result = fetch_all(routes)
    for item in result.items:
        assert item.content
        assert len(item.content) <= CONTENT_MAX
        assert "<" not in item.content and ">" not in item.content
        assert "About vulnerability notes" not in item.content
        assert "Contact us about this vulnerability" not in item.content
        assert "Solution" in item.content


def test_exploitation_hint_from_note_text(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_vu = {item.extra["vu_id"]: item for item in result.items}
    sogo = by_vu["VU#487613"]
    assert sogo.extra["exploitation_hint"] == "active"
    assert sogo.extra["cve_ids"] == ["CVE-2026-8496"]
    assert sogo.published_at == datetime(2026, 8, 6, 18, 36, 37, 747196, tzinfo=UTC)
    assert sogo.updated_at == datetime(2026, 8, 18, 19, 57, 56, 920153, tzinfo=UTC)
    tpm = by_vu["VU#431093"]
    assert set(tpm.extra["cve_ids"]) == {"CVE-2026-6726", "CVE-2026-6727"}
    assert tpm.extra["exploitation_hint"] is None


def test_window_filtering_uses_default_window(routes: RouteTable, now: datetime) -> None:
    routes.add(FEED_URL, load_fixture_text("certcc_atom.xml"))
    result = CertCcAdapter(make_source()).fetch(make_ctx(routes, now, hours=24))
    assert result.status.ok
    assert [item.extra["vu_id"] for item in result.items] == ["VU#308749"]


def test_http_500_reports_failure(routes: RouteTable) -> None:
    routes.add(FEED_URL, "gateway error", status=500)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = CertCcAdapter(make_source()).fetch(make_ctx(routes, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []


def test_helpers() -> None:
    assert vu_id_from_title("VU#308749: Remote Code Execution in Kaltura") == "VU#308749"
    assert vu_id_from_title("Remote Code Execution in Kaltura") is None
    text = "Overview\n\nFirst paragraph.\n\nSecond paragraph.\n\nDescription\n\nDetails here.\n\nImpact\n\nBad."
    assert overview_section(text) == "First paragraph.\n\nSecond paragraph."
    assert overview_section("No headings at all") == ""
    assert strip_boilerplate("Solution\n\nApply an update.\n\nAbout vulnerability notes\n\nContact us") == (
        "Solution\n\nApply an update."
    )
    assert strip_boilerplate("Nothing to strip") == "Nothing to strip"
