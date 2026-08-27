"""Tests for the CISA KEV adapter. Fixture-driven; never touches the network."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from arkham.http import SafeHttpClient
from arkham.models import SourceCategory, SourceState, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.cisa import (
    KEV_CATALOG_URL,
    CisaKevAdapter,
    build_kev_catalog,
    extract_note_urls,
    kev_lookup,
)
from tests.conftest import RouteTable, load_fixture_json, load_fixture_text

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UTC = timezone.utc

FIXTURE_IDS = {
    "CVE-2021-23758",
    "CVE-2026-8452",
    "CVE-2019-1068",
    "CVE-2026-60004",
    "CVE-2026-15409",
    "CVE-2014-6278",
    "CVE-2014-8361",
}


def make_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "type": "json",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.VULNERABILITY,
        "url": KEV_FEED_URL,
        "adapter": "cisa_kev",
        "publisher": "CISA",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(
    http: SafeHttpClient,
    window: tuple[datetime, datetime],
    now: datetime,
    *,
    state: SourceState | None = None,
) -> FetchContext:
    return FetchContext(http=http, window_start=window[0], window_end=window[1], now=now, state=state)


@pytest.fixture
def kev_body() -> str:
    return load_fixture_text("cisa_kev_sample.json")


@pytest.fixture
def kev_data() -> dict:
    return load_fixture_json("cisa_kev_sample.json")


def fetch_with(
    routes: RouteTable,
    body: str,
    window: tuple[datetime, datetime],
    now: datetime,
    *,
    source: Source | None = None,
    state: SourceState | None = None,
    status: int = 200,
):
    routes.add(KEV_FEED_URL, body, status=status, headers={"etag": '"kev-etag"'})
    adapter = CisaKevAdapter(source or make_source())
    ctx = make_ctx(routes.client(), window, now, state=state)
    return adapter, ctx, adapter.fetch(ctx)


# ---------------------------------------------------------------------------- happy path


def test_fetch_populates_catalog_and_emits_window_items(routes, window, now, kev_body):
    adapter, ctx, result = fetch_with(routes, kev_body, window, now)

    assert result.status.ok is True
    assert result.status.status == "OK"
    assert result.status.items == 4
    assert set(adapter.catalog) == FIXTURE_IDS
    assert adapter.catalog_version == "2026.08.26"
    assert ctx.extra["kev_catalog"] is adapter.catalog
    assert ctx.extra["kev_catalog_version"] == "2026.08.26"
    # Window is 2026-08-25T12:00Z .. 2026-08-26T12:00Z => dates 2026-08-25 and 2026-08-26, newest first.
    assert [i.external_id for i in result.items] == [
        "CVE-2021-23758",
        "CVE-2026-8452",
        "CVE-2019-1068",
        "CVE-2026-60004",
    ]
    dates = [i.published_at for i in result.items]
    assert dates == sorted(dates, reverse=True)
    assert result.new_state is not None
    assert result.new_state.last_success_at == now
    assert result.new_state.last_status == "OK"


def test_item_fields_match_fixture_entry(routes, window, now, kev_body, kev_data):
    _, _, result = fetch_with(routes, kev_body, window, now)
    item = next(i for i in result.items if i.external_id == "CVE-2026-8452")
    entry = next(e for e in kev_data["vulnerabilities"] if e["cveID"] == "CVE-2026-8452")

    assert item.title == (
        "Citrix NetScaler ADC and NetScaler Gateway: Citrix NetScaler ADC and NetScaler Gateway Improper "
        "Restriction of Operations within the Bounds of a Memory Buffer Vulnerability (CVE-2026-8452) "
        "added to CISA KEV"
    )
    assert item.url == KEV_CATALOG_URL == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    assert item.published_at == datetime(2026, 8, 26, tzinfo=UTC)
    assert item.updated_at is None
    assert item.fetched_at == now
    assert item.summary.startswith(
        "Citrix NetScaler ADC and NetScaler Gateway contain an improper restriction of operations"
    )
    assert "Required action: Apply mitigations in accordance with vendor instructions" in item.summary
    assert "Known ransomware campaign use" not in item.summary
    assert "  " not in item.summary  # whitespace normalised (the source has a trailing space)

    extra = item.extra
    assert extra["publisher"] == "CISA"
    assert extra["cve_ids"] == ["CVE-2026-8452"]
    assert extra["cwes"] == ["CWE-119"]
    assert extra["products"] == ["Citrix NetScaler ADC and NetScaler Gateway"]
    assert extra["exploitation_hint"] == "active"
    kev = extra["kev"]
    assert kev["date_added"] == "2026-08-26"
    assert kev["due_date"] == "2026-08-29"
    assert kev["ransomware_use"] == "Unknown"
    assert kev["vendor"] == "Citrix"
    assert kev["product"] == "NetScaler ADC and NetScaler Gateway"
    assert kev["vulnerability_name"] == entry["vulnerabilityName"]
    assert kev["required_action"].startswith("Apply mitigations in accordance with vendor instructions")
    assert extra["references"] == [
        "https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696604",
        "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk",
        "https://www.cisa.gov/news-events/directives/"
        "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-8452",
    ]


def test_entry_without_cwes_yields_empty_list(routes, window, now, kev_body):
    _, _, result = fetch_with(routes, kev_body, window, now)
    item = next(i for i in result.items if i.external_id == "CVE-2019-1068")
    assert item.extra["cwes"] == []
    assert item.extra["products"] == ["Microsoft SQL Server"]
    assert item.extra["references"][0] == (
        "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1068"
    )


def test_known_ransomware_use_is_appended_to_summary(routes, now, kev_body):
    window = (datetime(2026, 7, 14, tzinfo=UTC), datetime(2026, 7, 15, tzinfo=UTC))
    _, _, result = fetch_with(routes, kev_body, window, now)
    assert [i.external_id for i in result.items] == ["CVE-2026-15409"]
    item = result.items[0]
    assert item.summary.endswith("Known ransomware campaign use: Known.")
    assert item.extra["kev"]["ransomware_use"] == "Known"
    assert item.extra["products"] == ["SonicWall SMA1000 Appliances"]


# ---------------------------------------------------------------------------- window semantics


def test_window_filter_uses_date_granularity(routes, now, kev_body):
    # Window opens at 10:00 UTC on the 26th; entries added "2026-08-26" (midnight) must still count.
    window = (datetime(2026, 8, 26, 10, tzinfo=UTC), datetime(2026, 8, 26, 12, tzinfo=UTC))
    _, _, result = fetch_with(routes, kev_body, window, now)
    assert [i.external_id for i in result.items] == ["CVE-2021-23758", "CVE-2026-8452", "CVE-2019-1068"]


def test_window_entirely_after_catalog_dates_emits_nothing(routes, now, kev_body):
    window = (datetime(2026, 8, 27, tzinfo=UTC), datetime(2026, 8, 28, tzinfo=UTC))
    adapter, ctx, result = fetch_with(routes, kev_body, window, now)
    assert result.status.ok is True
    assert result.items == []
    # The catalog is still exposed for enrichment even when nothing is new.
    assert set(ctx.extra["kev_catalog"]) == FIXTURE_IDS


def test_window_bounds_are_converted_to_utc_dates(routes, now, kev_body):
    # 2026-08-25T21:00-05:00 == 2026-08-26T02:00Z, so the window starts on the 26th in UTC.
    from datetime import timedelta

    minus5 = timezone(timedelta(hours=-5))
    window = (datetime(2026, 8, 25, 21, tzinfo=minus5), datetime(2026, 8, 26, 7, tzinfo=minus5))
    _, _, result = fetch_with(routes, kev_body, window, now)
    assert "CVE-2026-60004" not in [i.external_id for i in result.items]
    assert len(result.items) == 3


def test_respects_max_items(routes, window, now, kev_body):
    _, _, result = fetch_with(routes, kev_body, window, now, source=make_source(max_items=2))
    assert [i.external_id for i in result.items] == ["CVE-2021-23758", "CVE-2026-8452"]


# ---------------------------------------------------------------------------- HTTP behaviour


def test_never_sends_conditional_headers(routes, window, now, kev_body):
    state = SourceState(source_id="cisa_kev", etag='"old"', last_modified="Tue, 25 Aug 2026 17:00:00 GMT")
    _, _, result = fetch_with(routes, kev_body, window, now, state=state)
    assert result.status.ok is True
    request = routes.requests[0]
    assert "if-none-match" not in request.headers
    assert "if-modified-since" not in request.headers
    assert str(request.url) == KEV_FEED_URL


def test_http_error_is_reported_not_raised(routes, window, now):
    adapter, ctx, result = fetch_with(routes, "service unavailable", window, now, status=500)
    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.items == []
    assert adapter.catalog == {}
    assert "kev_catalog" not in ctx.extra


def test_malformed_json_is_parse_error(routes, window, now):
    _, _, result = fetch_with(routes, "{not json", window, now)
    assert result.status.ok is False
    assert result.status.status == "PARSE ERROR"


def test_missing_vulnerabilities_key_is_parse_error(routes, window, now):
    _, _, result = fetch_with(routes, json.dumps({"catalogVersion": "2026.08.26"}), window, now)
    assert result.status.ok is False
    assert result.status.status == "PARSE ERROR"
    assert result.status.error is not None and "vulnerabilities" in result.status.error


def test_timeout_reports_timeout_status(window, now):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    adapter = CisaKevAdapter(make_source())
    result = adapter.fetch(make_ctx(http, window, now))
    assert result.status.ok is False
    assert result.status.status == "TIMEOUT"


def test_entry_with_unparseable_date_is_skipped(routes, window, now, kev_data):
    broken = json.loads(json.dumps(kev_data))
    broken["vulnerabilities"][0]["dateAdded"] = "not-a-date"
    _, _, result = fetch_with(routes, json.dumps(broken), window, now)
    assert result.status.ok is True
    assert [i.external_id for i in result.items] == ["CVE-2026-8452", "CVE-2019-1068", "CVE-2026-60004"]


# ---------------------------------------------------------------------------- references from notes


def test_references_drop_non_https_urls(routes, now, kev_body):
    window = (datetime(2025, 10, 2, tzinfo=UTC), datetime(2025, 10, 3, tzinfo=UTC))
    _, _, result = fetch_with(routes, kev_body, window, now)
    assert [i.external_id for i in result.items] == ["CVE-2014-6278"]
    refs = result.items[0].extra["references"]
    assert all(r.startswith("https://") for r in refs)
    assert "http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-027" not in refs
    assert refs == [
        "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/"
        "SecurityAdvisories/0/23467",
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash",
        "https://www.ibm.com/support/pages/security-bulletin-update-vulnerabilities-bash-affect-aix-toolbox-"
        "linux-applications-cve-2014-6271-cve-2014-6277-cve-2014-6278-cve-2014-7169-cve-2014-7186-and-cve-2014-7187",
        "https://nvd.nist.gov/vuln/detail/CVE-2014-6278",
    ]


def test_extract_note_urls_splits_on_semicolon_without_spaces(kev_data):
    entry = next(e for e in kev_data["vulnerabilities"] if e["cveID"] == "CVE-2014-8361")
    assert extract_note_urls(entry["notes"]) == [
        "https://web.archive.org/web/20150831100501/http://securityadvisories.dlink.com/security/"
        "publication.aspx?name=SAP10055",
        "https://nvd.nist.gov/vuln/detail/CVE-2014-8361",
    ]


def test_extract_note_urls_ignores_prose_and_empty():
    assert extract_note_urls("") == []
    assert extract_note_urls(None) == []
    assert extract_note_urls("Apply mitigations per vendor instructions.") == []


def test_extract_note_urls_dedupes_and_limits():
    url = "https://nvd.nist.gov/vuln/detail/CVE-2014-8361"
    assert extract_note_urls(f"{url} ; {url}") == [url]
    many = " ; ".join(f"https://example.com/advisory/{n}" for n in range(30))
    assert len(extract_note_urls(many)) == 15
    assert len(extract_note_urls(many, limit=3)) == 3


# ---------------------------------------------------------------------------- catalog helpers


def test_build_kev_catalog_indexes_by_upper_cve(kev_data):
    catalog = build_kev_catalog(kev_data["vulnerabilities"])
    assert set(catalog) == FIXTURE_IDS
    assert catalog["CVE-2026-60004"]["vendorProject"] == "Gitea"


def test_build_kev_catalog_skips_entries_without_valid_cve(kev_data):
    entries = [*kev_data["vulnerabilities"], {"vendorProject": "nobody"}, {"cveID": "not-a-cve"}, "junk"]
    assert set(build_kev_catalog(entries)) == FIXTURE_IDS


def test_kev_lookup_is_case_insensitive(kev_data):
    catalog = build_kev_catalog(kev_data["vulnerabilities"])
    assert kev_lookup(catalog, "cve-2026-8452")["vendorProject"] == "Citrix"
    assert kev_lookup(catalog, " CVE-2026-8452 ")["product"] == "NetScaler ADC and NetScaler Gateway"
    assert kev_lookup(catalog, "CVE-1999-0001") is None
    assert kev_lookup(catalog, "") is None
    assert kev_lookup({}, "CVE-2026-8452") is None
    assert kev_lookup(None, "CVE-2026-8452") is None


def test_kev_lookup_tolerates_lower_case_catalog_keys(kev_data):
    entry = next(e for e in kev_data["vulnerabilities"] if e["cveID"] == "CVE-2026-8452")
    assert kev_lookup({"cve-2026-8452": entry}, "CVE-2026-8452") is entry
