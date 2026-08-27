"""Tests for the CERT-EU adapter against trimmed live feed samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import SourceCategory, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.cert_eu import CertEuAdapter, exploitation_hint, extract_cve_ids, split_products
from tests.conftest import RouteTable, load_fixture_text

ADVISORIES_URL = "https://cert.europa.eu/publications/security-advisories-rss"
THREAT_INTEL_URL = "https://cert.europa.eu/publications/threat-intelligence-rss"
UTC = timezone.utc


def make_source(url: str = ADVISORIES_URL, **overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "cert_eu_advisories",
        "name": "CERT-EU Security Advisories",
        "type": "rss",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.ADVISORY,
        "url": url,
        "adapter": "cert_eu",
        "publisher": "CERT-EU",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(routes: RouteTable, now: datetime, hours: int = 24) -> FetchContext:
    return FetchContext(http=routes.client(), window_start=now - timedelta(hours=hours), window_end=now, now=now)


def fetch_all(routes: RouteTable, url: str = ADVISORIES_URL, fixture: str = "certeu_advisories.xml"):
    """Fetch with a window wide enough to keep every fixture entry."""
    routes.add(url, load_fixture_text(fixture))
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = CertEuAdapter(make_source(url)).fetch(make_ctx(routes, now, hours=24 * 365))
    assert result.status.ok, result.status
    return result


def test_parses_real_advisories(routes: RouteTable) -> None:
    result = fetch_all(routes)
    assert result.status.status == "OK"
    assert len(result.items) == 5
    item = result.items[0]
    assert item.title == "2026-010: Critical Vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway"
    assert item.url == "https://cert.europa.eu/publications/security-advisories/2026-010/"
    assert item.external_id == "security-advisories-10947"
    assert item.source_id == "cert_eu_advisories"
    assert item.source_tier == SourceTier.PRIMARY
    assert item.extra["publisher"] == "CERT-EU"
    assert item.extra["advisory_id"] == "2026-010"
    assert item.extra["products"] == ["Citrix NetScaler ADC", "NetScaler Gateway"]
    assert item.extra["cve_ids"] == []
    assert item.extra["exploitation_hint"] is None
    assert item.extra["advisory_updated"] is False
    assert item.summary.startswith("On 19 August 2026, Citrix published a security advisory")


def test_links_padded_with_whitespace_are_stripped(routes: RouteTable) -> None:
    result = fetch_all(routes)
    expected = [
        "https://cert.europa.eu/publications/security-advisories/2026-010/",
        "https://cert.europa.eu/publications/security-advisories/2026-009/",
        "https://cert.europa.eu/publications/security-advisories/2026-007/",
        "https://cert.europa.eu/publications/security-advisories/2026-005/",
        "https://cert.europa.eu/publications/security-advisories/2026-002/",
    ]
    assert [item.url for item in result.items] == expected
    assert all(not any(ch.isspace() for ch in item.url) for item in result.items)


def test_cest_and_cet_dates_become_utc(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_id = {item.extra["advisory_id"]: item for item in result.items}
    # Wed, 19 Aug 2026 18:13:47 CEST (UTC+2)
    assert by_id["2026-010"].published_at == datetime(2026, 8, 19, 16, 13, 47, tzinfo=UTC)
    # Thu, 26 Feb 2026 19:38:52 CET (UTC+1)
    assert by_id["2026-002"].published_at == datetime(2026, 2, 26, 18, 38, 52, tzinfo=UTC)
    assert all(item.published_at is not None and item.published_at.tzinfo is not None for item in result.items)


def test_exploitation_hint_cves_and_products(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_id = {item.extra["advisory_id"]: item for item in result.items}

    sharepoint = by_id["2026-009"]
    assert sharepoint.extra["exploitation_hint"] == "active"
    assert sharepoint.extra["cve_ids"] == [
        "CVE-2026-50522",
        "CVE-2026-32201",
        "CVE-2026-45659",
        "CVE-2026-56164",
        "CVE-2026-58644",
    ]
    assert sharepoint.extra["products"] == ["Microsoft SharePoint"]
    assert sharepoint.extra["advisory_updated"] is True

    cisco = by_id["2026-002"]
    assert cisco.extra["exploitation_hint"] == "active"  # "exploited in the wild"
    assert cisco.extra["cve_ids"] == ["CVE-2026-20127"]
    assert cisco.extra["products"] == ["Cisco Products"]

    kernel = by_id["2026-005"]
    assert kernel.extra["cve_ids"] == ["CVE-2026-31431"]
    assert kernel.extra["exploitation_hint"] == "poc"
    assert kernel.extra["products"] == ["Linux Kernel"]
    assert '"Copy Fail"' in kernel.title

    assert by_id["2026-007"].extra["products"] == ["Windows Netlogon"]


def test_window_filtering(routes: RouteTable) -> None:
    routes.add(ADVISORIES_URL, load_fixture_text("certeu_advisories.xml"))
    now = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    result = CertEuAdapter(make_source()).fetch(make_ctx(routes, now, hours=24))
    assert result.status.ok
    assert [item.extra["advisory_id"] for item in result.items] == ["2026-010"]
    assert result.status.items == 1
    assert result.new_state is not None and result.new_state.source_id == "cert_eu_advisories"


def test_summary_is_sanitized_plain_text(routes: RouteTable) -> None:
    result = fetch_all(routes)
    for item in result.items:
        assert "<" not in item.summary and ">" not in item.summary
        assert "<" not in item.title and ">" not in item.title
        assert "&lt;" not in item.summary
    assert "CERT-EU recommends updating affected devices as soon as possible." in result.items[0].summary


def test_threat_intelligence_feed_has_no_advisory_ids(routes: RouteTable) -> None:
    result = fetch_all(routes, url=THREAT_INTEL_URL, fixture="certeu_threatintel.xml")
    assert len(result.items) == 3
    assert result.items[0].title == "Cyber Brief 26-08 - July 2026"
    assert result.items[0].url == "https://cert.europa.eu/publications/threat-intelligence/cb26-08/"
    for item in result.items:
        assert item.extra["publisher"] == "CERT-EU"
        assert item.extra["advisory_id"] is None
        assert item.extra["products"] == []
        assert item.published_at is not None and item.published_at.tzinfo is not None


def test_http_500_reports_failure(routes: RouteTable) -> None:
    routes.add(ADVISORIES_URL, "boom", status=500)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = CertEuAdapter(make_source()).fetch(make_ctx(routes, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []
    assert result.new_state is None


def test_exploitation_hint_helper_ignores_negations() -> None:
    assert exploitation_hint("This vulnerability was not exploited in the wild.") is None
    assert exploitation_hint("There is no evidence it has been actively exploited.") is None
    assert exploitation_hint("The flaw is under active exploitation by several groups.") == "active"
    assert exploitation_hint("A public proof-of-concept exploit has been released.") == "poc"
    assert exploitation_hint("PoC available", "and it is actively exploited") == "active"
    assert exploitation_hint("") is None


def test_extract_cve_ids_helper_dedupes_and_normalises() -> None:
    text = "cve-2026-1234 was fixed alongside CVE-2026-1234 and CVE-2025-99999; see CVE-2026-0001."
    assert extract_cve_ids(text) == ["CVE-2026-1234", "CVE-2025-99999", "CVE-2026-0001"]
    assert extract_cve_ids("", None) == []


def test_split_products_helper() -> None:
    assert split_products("Critical Vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway") == [
        "Citrix NetScaler ADC",
        "NetScaler Gateway",
    ]
    assert split_products("Critical Vulnerability in SharePoint Exploited") == ["SharePoint"]
    assert split_products('High Vulnerability in the Linux Kernel ("Copy Fail")') == ["Linux Kernel"]
    assert split_products("Vulnerabilities in Ivanti EPMM, Ivanti Sentry and Ivanti CSA") == [
        "Ivanti EPMM",
        "Ivanti Sentry",
        "Ivanti CSA",
    ]
    assert split_products("Cyber Brief 26-08 - July 2026") == []
