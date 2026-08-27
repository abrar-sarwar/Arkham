"""Tests for the Microsoft MSRC Security Update Guide adapter against trimmed live feed samples."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import SourceCategory, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.microsoft import (
    MsrcUpdateGuideAdapter,
    is_informational_only,
    parse_msrc_title,
    revisions_in_order,
)
from tests.conftest import RouteTable, load_fixture_text

FEED_URL = "https://api.msrc.microsoft.com/update-guide/rss"
UTC = timezone.utc


def make_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "msrc_update_guide",
        "name": "Microsoft Security Update Guide",
        "type": "rss",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.VULNERABILITY,
        "url": FEED_URL,
        "adapter": "msrc_update_guide",
        "publisher": "Microsoft",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(routes: RouteTable, now: datetime, hours: int = 24) -> FetchContext:
    return FetchContext(http=routes.client(), window_start=now - timedelta(hours=hours), window_end=now, now=now)


def fetch_all(routes: RouteTable, **source_overrides: object):
    routes.add(FEED_URL, load_fixture_text("msrc_update_guide.xml"))
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    adapter = MsrcUpdateGuideAdapter(make_source(**source_overrides))
    result = adapter.fetch(make_ctx(routes, now, hours=24 * 365))
    assert result.status.ok, result.status
    return result


def test_parses_real_entries_and_drops_informational_revisions(routes: RouteTable) -> None:
    result = fetch_all(routes)
    # 11 fixture items: 5 informational-only revisions are dropped, 6 substantive entries remain.
    assert len(result.items) == 6
    keys = [(item.external_id, item.extra["revision"]) for item in result.items]
    assert keys == [
        ("CVE-2026-47292", "2.0"),
        ("CVE-2026-62834", "1.0"),
        ("CVE-2026-69836", "1.0"),
        ("CVE-2026-55015", "1.0"),
        ("CVE-2026-55013", "1.0"),
        ("CVE-2026-59132", "1.0"),
    ]
    assert all(item.extra["informational_only"] is False for item in result.items)
    assert all(item.extra["publisher"] == "Microsoft" for item in result.items)


def test_new_cve_entry_fields(routes: RouteTable) -> None:
    result = fetch_all(routes)
    by_id = {(item.external_id, item.extra["revision"]): item for item in result.items}
    adf = by_id[("CVE-2026-62834", "1.0")]
    assert adf.title == "CVE-2026-62834 Azure Data Factory Elevation of Privilege Vulnerability"
    assert adf.url == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62834"
    assert adf.extra["cve_ids"] == ["CVE-2026-62834"]
    assert adf.extra["products"] == ["Azure Data Factory"]
    assert adf.extra["vuln_class"] == "Elevation of Privilege"
    assert adf.extra["new_cve"] is True
    assert adf.extra["categories"] == ["CVE"]
    # Thu, 20 Aug 2026 07:00:00 -0700 -> 14:00 UTC
    assert adf.published_at == datetime(2026, 8, 20, 14, 0, tzinfo=UTC)
    assert adf.summary == (
        "Improper verification of cryptographic signature in Azure Data Factory allows an unauthorized "
        "attacker to elevate privileges over a network."
    )
    assert "<" not in adf.summary and ">" not in adf.summary

    vscode = by_id[("CVE-2026-47292", "2.0")]
    assert vscode.extra["products"] == ["Visual Studio Code MSSQL Extension"]
    assert vscode.extra["vuln_class"] == "Remote Code Execution"
    assert vscode.extra["new_cve"] is False

    assert by_id[("CVE-2026-55015", "1.0")].extra["vuln_class"] == "Denial of Service"
    assert by_id[("CVE-2026-55015", "1.0")].extra["products"] == ["Microsoft Remote Help"]
    assert by_id[("CVE-2026-55013", "1.0")].extra["vuln_class"] == "Spoofing"
    assert by_id[("CVE-2026-55013", "1.0")].extra["products"] == ["Windows Remote Help Defense"]
    assert by_id[("CVE-2026-59132", "1.0")].extra["products"] == ["Windows TCP/IP"]
    assert by_id[("CVE-2026-59132", "1.0")].summary == "Information published."


def test_window_filtering(routes: RouteTable) -> None:
    routes.add(FEED_URL, load_fixture_text("msrc_update_guide.xml"))
    now = datetime(2026, 8, 22, 0, 0, tzinfo=UTC)
    result = MsrcUpdateGuideAdapter(make_source()).fetch(make_ctx(routes, now, hours=48))
    assert result.status.ok
    assert [item.external_id for item in result.items] == [
        "CVE-2026-62834",
        "CVE-2026-69836",
        "CVE-2026-55015",
        "CVE-2026-55013",
    ]
    assert result.status.items == 4


def test_never_looks_past_max_items(routes: RouteTable) -> None:
    # The first three feed items are informational-only revisions -> nothing survives.
    assert fetch_all(routes, max_items=3).items == []
    # The fifth item is the first substantive one; revisions stay aligned after slicing.
    routes2 = RouteTable()
    items = fetch_all(routes2, max_items=5).items
    assert [(item.external_id, item.extra["revision"]) for item in items] == [("CVE-2026-47292", "2.0")]


def test_http_500_reports_failure(routes: RouteTable) -> None:
    routes.add(FEED_URL, "unavailable", status=500)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    result = MsrcUpdateGuideAdapter(make_source()).fetch(make_ctx(routes, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []


def test_revisions_in_order_helper() -> None:
    body = load_fixture_text("msrc_update_guide.xml").encode("utf-8")
    pairs = revisions_in_order(body, limit=4)
    assert pairs == [
        ("1.1", "CVE-2026-62890"),
        ("1.3", "CVE-2026-62747"),
        ("2.2", "CVE-2026-70337"),
        ("1.1", "CVE-2026-59130"),
    ]
    assert len(revisions_in_order(body, limit=100)) == 11
    assert revisions_in_order(b"<rss><channel><item><guid>x</guid></item></channel></rss>", limit=5) == []


def test_is_informational_only_helper() -> None:
    assert is_informational_only("Updated an acknowledgement. This is an informational change only.")
    assert is_informational_only("Acknowledgement Updated")
    assert is_informational_only("Updated the build numbers.  This is an informational update only.")
    assert is_informational_only(
        "Corrected **Exploited** to **No**. This vulnerability was not exploited in the wild. "
        "This is an informational change only."
    )
    assert not is_informational_only("Information published.")
    assert not is_informational_only("Affected software updated with new package information.")
    assert not is_informational_only("")


def test_parse_msrc_title_helper() -> None:
    parsed = parse_msrc_title("CVE-2026-62890 Windows GDI+ Elevation of Privilege Vulnerability")
    assert parsed == (["CVE-2026-62890"], ["Windows GDI+"], "Elevation of Privilege")
    assert parse_msrc_title("CVE-2026-50342 Windows MIDI Service Module Elevation of Privileges Vulnerability") == (
        ["CVE-2026-50342"],
        ["Windows MIDI Service Module"],
        "Elevation of Privilege",
    )
    assert parse_msrc_title("CVE-2026-48566 Windows DWM Core Library Information Disclosure  Vulnerability") == (
        ["CVE-2026-48566"],
        ["Windows DWM Core Library"],
        "Information Disclosure",
    )
    assert parse_msrc_title("CVE-2026-50661 Windows BitLocker Security Feature Bypass Vulnerability") == (
        ["CVE-2026-50661"],
        ["Windows BitLocker"],
        "Security Feature Bypass",
    )
    assert parse_msrc_title("CVE-2026-45639 Windows Remote Desktop Protocol (RDP) Information Disclosure Vulnerability") == (
        ["CVE-2026-45639"],
        ["Windows Remote Desktop Protocol (RDP)"],
        "Information Disclosure",
    )
    assert parse_msrc_title("Chromium: CVE-2026-19151 Use after free in V8") == (["CVE-2026-19151"], ["Chromium"], None)
    assert parse_msrc_title("CVE-2026-19137 Use after free in WebGL") == (["CVE-2026-19137"], [], None)
    assert parse_msrc_title("Some advisory without an identifier") == ([], [], None)
