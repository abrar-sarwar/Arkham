"""Tests for the NVD CVE API 2.0 adapter. Fixture-driven; never touches the network and never sleeps."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest

from arkham.http import SafeHttpClient
from arkham.models import SourceCategory, SourceTier
from arkham.sources import nvd
from arkham.sources.base import FetchContext, Source
from arkham.sources.nvd import (
    NvdAdapter,
    accept_cve,
    build_nvd_params,
    cpe_to_product,
    extract_cwes,
    extract_products,
    extract_references,
    select_cvss,
)
from tests.conftest import RouteTable, load_fixture_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UTC = timezone.utc
TEST_API_KEY = "unit-test-key-not-real"


# ---------------------------------------------------------------------------- helpers


def make_source(**overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": "nvd",
        "name": "NVD CVE API",
        "type": "api",
        "tier": SourceTier.PRIMARY,
        "category": SourceCategory.VULNERABILITY,
        "url": NVD_URL,
        "adapter": "nvd",
        "publisher": "NVD",
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(
    http: SafeHttpClient,
    window: tuple[datetime, datetime],
    now: datetime,
    *,
    api_key: str | None = None,
) -> FetchContext:
    return FetchContext(http=http, window_start=window[0], window_end=window[1], now=now, nvd_api_key=api_key)


def window_2017() -> tuple[datetime, datetime]:
    """A window in which CVE-2017-10039 (published 2017-08-08T15:29) counts as newly published."""
    return datetime(2017, 8, 8, tzinfo=UTC), datetime(2017, 8, 9, tzinfo=UTC)


class PagedTransport:
    """Serve NVD pages keyed by the ``startIndex`` query parameter and record every request."""

    def __init__(self, pages: dict[int, dict[str, Any]]) -> None:
        self.pages = pages
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        index = int(request.url.params.get("startIndex", "0"))
        page = self.pages[index]
        return httpx.Response(200, json=page, request=request)

    def client(self) -> SafeHttpClient:
        return SafeHttpClient(transport=httpx.MockTransport(self.handler))


class SequenceTransport:
    """Return scripted (status, body) responses in order; the last one repeats."""

    def __init__(self, responses: list[tuple[int, bytes]]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]
        return httpx.Response(status, content=body, request=request)

    def client(self) -> SafeHttpClient:
        return SafeHttpClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Capture every rate-limit/retry sleep instead of actually sleeping."""
    calls: list[float] = []
    monkeypatch.setattr(nvd, "_sleep", calls.append)
    return calls


@pytest.fixture
def nvd_page() -> dict[str, Any]:
    return load_fixture_json("nvd_sample.json")


@pytest.fixture
def single_page(nvd_page: dict[str, Any]) -> dict[str, Any]:
    """The captured response with ``totalResults`` matching the two records it carries."""
    return {**nvd_page, "totalResults": len(nvd_page["vulnerabilities"])}


@pytest.fixture
def tomcat(nvd_page: dict[str, Any]) -> dict[str, Any]:
    return next(v["cve"] for v in nvd_page["vulnerabilities"] if v["cve"]["id"] == "CVE-2016-8735")


@pytest.fixture
def oracle(nvd_page: dict[str, Any]) -> dict[str, Any]:
    return next(v["cve"] for v in nvd_page["vulnerabilities"] if v["cve"]["id"] == "CVE-2017-10039")


def fetch_single(
    routes: RouteTable,
    page: dict[str, Any],
    window: tuple[datetime, datetime],
    now: datetime,
    *,
    source: Source | None = None,
    api_key: str | None = None,
):
    routes.add(NVD_URL, json.dumps(page))
    adapter = NvdAdapter(source or make_source())
    ctx = make_ctx(routes.client(), window, now, api_key=api_key)
    return adapter, ctx, adapter.fetch(ctx)


# ---------------------------------------------------------------------------- query parameters


def test_build_nvd_params_formats_utc_without_offset():
    start = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    end = datetime(2026, 8, 26, 14, 30, tzinfo=ZoneInfo("Europe/Berlin"))  # 12:30 UTC
    assert build_nvd_params(start, end) == {
        "lastModStartDate": "2026-08-25T12:00:00.000",
        "lastModEndDate": "2026-08-26T12:30:00.000",
        "resultsPerPage": "2000",
        "startIndex": "0",
    }
    assert build_nvd_params(start, end, 4000)["startIndex"] == "4000"


def test_build_nvd_params_clamps_range_to_120_days():
    end = datetime(2026, 8, 26, 12, tzinfo=UTC)
    params = build_nvd_params(end - timedelta(days=200), end)
    assert params["lastModStartDate"] == (end - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
    assert params["lastModStartDate"] == "2026-04-28T12:00:00.000"
    untouched = build_nvd_params(end - timedelta(days=119), end)
    assert untouched["lastModStartDate"] == "2026-04-29T12:00:00.000"


def test_build_nvd_params_treats_naive_datetimes_as_utc():
    params = build_nvd_params(datetime(2026, 8, 25, 12), datetime(2026, 8, 26, 12))
    assert params["lastModStartDate"] == "2026-08-25T12:00:00.000"


# ---------------------------------------------------------------------------- fixture parsing


def test_cve_to_item_parses_high_cvss_kev_record(routes, window, now, tomcat):
    adapter = NvdAdapter(make_source())
    item = adapter.cve_to_item(tomcat, make_ctx(routes.client(), window, now))
    assert item.external_id == "CVE-2016-8735"
    assert item.url == "https://nvd.nist.gov/vuln/detail/CVE-2016-8735"
    assert item.title.startswith("CVE-2016-8735: Remote code execution is possible with Apache Tomcat before 6.0.48")
    assert item.title.endswith("(CVSS 9.8 CRITICAL)")
    assert len(item.title) < 160
    assert item.summary.startswith("Remote code execution is possible with Apache Tomcat")
    assert "ejecución" not in item.summary  # English description chosen, not Spanish
    assert item.published_at == datetime(2017, 4, 6, 21, 59, 0, 243000, tzinfo=UTC)
    assert item.updated_at == datetime(2026, 8, 25, 16, 28, 27, 310000, tzinfo=UTC)
    assert item.fetched_at == now

    extra = item.extra
    assert extra["publisher"] == "NVD"
    assert extra["cve_ids"] == ["CVE-2016-8735"]
    assert extra["cvss_score"] == 9.8
    assert extra["cvss_severity"] == "CRITICAL"
    assert extra["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert extra["cwes"] == []  # NVD-CWE-noinfo is skipped
    assert extra["vuln_status"] == "Analyzed"
    assert extra["exploitation_hint"] == "active"
    assert extra["kev"] == {
        "date_added": "2023-05-12",
        "due_date": "2023-06-02",
        "required_action": "Apply updates per vendor instructions.",
        "vulnerability_name": "Apache Tomcat Remote Code Execution Vulnerability",
    }
    assert extra["products"] == [
        "Apache Tomcat",
        "Canonical Ubuntu Linux",
        "Netapp 7-Mode Transition Tool",
        "Netapp Oncommand Insight",
        "Netapp Oncommand Shift",
    ]
    refs = extra["references"]
    assert len(refs) == 15
    assert len(set(refs)) == 15
    assert all(r.startswith("https://") for r in refs)
    assert refs[0] == "https://access.redhat.com/errata/RHSA-2017:0455"
    assert extra["reference_tags"][0] == ["Third Party Advisory"]
    assert len(extra["reference_tags"]) == len(refs)


def test_low_cvss_cve_outside_window_is_dropped(routes, window, now, single_page):
    _, _, result = fetch_single(routes, single_page, window, now)
    assert result.items == []


def test_published_in_window_keeps_low_cvss_cve(routes, now, single_page):
    _, _, result = fetch_single(routes, single_page, window_2017(), now)
    assert [i.external_id for i in result.items] == ["CVE-2017-10039"]
    oracle_item = result.items[0]
    assert oracle_item.extra["cvss_score"] == 6.8
    assert oracle_item.extra["cvss_severity"] == "MEDIUM"
    assert oracle_item.extra["kev"] is None
    assert oracle_item.extra["exploitation_hint"] is None
    assert oracle_item.extra["vuln_status"] == "Modified"
    assert oracle_item.extra["products"] == ["Oracle Agile Product Lifecycle Management"]
    assert oracle_item.title.endswith("(CVSS 6.8 MEDIUM)")


def test_references_drop_non_https(routes, now, single_page):
    _, _, result = fetch_single(routes, single_page, window_2017(), now)
    oracle_item = next(i for i in result.items if i.external_id == "CVE-2017-10039")
    # Every reference on this record is plain http:// and therefore not citable.
    assert oracle_item.extra["references"] == []
    assert oracle_item.extra["reference_tags"] == []


def test_max_items_cap_keeps_highest_priority(routes, now, single_page, caplog):
    caplog.set_level("INFO", logger="arkham.sources.nvd")
    page = json.loads(json.dumps(single_page))
    page["vulnerabilities"][0]["cve"]["published"] = "2017-08-08T16:00:00.000"
    _, _, result = fetch_single(routes, page, window_2017(), now, source=make_source(max_items=1))
    assert [i.external_id for i in result.items] == ["CVE-2016-8735"]
    assert any("dropped 1" in record.getMessage() for record in caplog.records)


def test_unknown_or_malformed_records_are_skipped(routes, window, now, single_page):
    page = json.loads(json.dumps(single_page))
    page["vulnerabilities"].extend([{"cve": {"id": "not-a-cve"}}, {"nope": 1}, "junk"])
    page["totalResults"] = len(page["vulnerabilities"])
    _, _, result = fetch_single(routes, page, window, now)
    assert result.status.ok is True
    assert result.items == []


# ---------------------------------------------------------------------------- selection rules


def test_accept_cve_keeps_kev_added_in_window_without_cvss(tomcat, window, now):
    no_metrics = {k: v for k, v in tomcat.items() if k != "metrics"}
    kev_window = (datetime(2023, 5, 12, tzinfo=UTC), datetime(2023, 5, 13, tzinfo=UTC))
    http = SafeHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404, request=r)))
    assert accept_cve(no_metrics, make_ctx(http, kev_window, now)) is True
    # KEV date outside the window, nothing else qualifying -> dropped
    assert accept_cve(no_metrics, make_ctx(http, window, now)) is False
    # KEV date on the window's start day still counts (date granularity)
    start_day = (datetime(2023, 5, 12, 23, tzinfo=UTC), datetime(2023, 5, 13, 23, tzinfo=UTC))
    assert accept_cve(no_metrics, make_ctx(http, start_day, now)) is True
    http.close()


def test_accept_cve_rejected_status_is_dropped(tomcat, window, now):
    rejected = {**tomcat, "vulnStatus": "Rejected"}
    http = SafeHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404, request=r)))
    published_window = (datetime(2017, 4, 6, tzinfo=UTC), datetime(2017, 4, 7, tzinfo=UTC))
    assert accept_cve(tomcat, make_ctx(http, published_window, now)) is True
    assert accept_cve(rejected, make_ctx(http, published_window, now)) is False
    http.close()


def test_accept_cve_cvss_threshold(tomcat, oracle, window, now):
    http = SafeHttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(404, request=r)))
    ctx = make_ctx(http, window, now)
    # A high CVSS score does not make an old CVE newly relevant merely because
    # NVD refreshed metadata during the collection window.
    assert accept_cve(tomcat, ctx) is False  # 9.8, but published/KEV-added years ago
    assert accept_cve(oracle, ctx) is False  # 6.8, old, not in KEV
    http.close()


# ---------------------------------------------------------------------------- CVSS selection


def test_select_cvss_prefers_newer_metric_families(tomcat):
    metrics = tomcat["metrics"]
    chosen = select_cvss(metrics)
    assert chosen is not None
    assert (chosen.score, chosen.version, chosen.severity) == (9.8, "3.1", "CRITICAL")

    # The v4.0 list wins over v3.1 regardless of dict order or score.
    v40_over_v31 = {"cvssMetricV31": metrics["cvssMetricV31"], "cvssMetricV40": metrics["cvssMetricV2"]}
    assert select_cvss(v40_over_v31).vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    # v3.0 wins over v2.
    v30_over_v2 = {"cvssMetricV2": metrics["cvssMetricV31"], "cvssMetricV30": metrics["cvssMetricV2"]}
    assert select_cvss(v30_over_v2).score == 7.5
    # v3.1 wins over v3.0.
    v31_over_v30 = {"cvssMetricV30": metrics["cvssMetricV2"], "cvssMetricV31": metrics["cvssMetricV31"]}
    assert select_cvss(v31_over_v30).score == 9.8

    assert select_cvss({}) is None
    assert select_cvss(None) is None
    assert select_cvss({"cvssMetricV31": []}) is None
    assert select_cvss({"cvssMetricV31": [{"cvssData": {}}]}) is None


def test_select_cvss_prefers_primary_entry(tomcat):
    entries = list(reversed(tomcat["metrics"]["cvssMetricV31"]))  # Secondary listed first
    assert entries[0]["type"] == "Secondary"
    chosen = select_cvss({"cvssMetricV31": entries})
    assert chosen is not None
    assert chosen.metric_type == "Primary"
    assert chosen.source == "nvd@nist.gov"
    # Without any Primary entry the first one is used.
    secondary_only = select_cvss({"cvssMetricV31": [entries[0]]})
    assert secondary_only is not None and secondary_only.metric_type == "Secondary"


def test_select_cvss_v2_reads_metric_level_severity(tomcat):
    chosen = select_cvss({"cvssMetricV2": tomcat["metrics"]["cvssMetricV2"]})
    assert chosen is not None
    assert (chosen.score, chosen.severity, chosen.version) == (7.5, "HIGH", "2.0")
    assert chosen.vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P"


# ---------------------------------------------------------------------------- field extraction helpers


def test_extract_products_from_cpe_configurations(tomcat, oracle):
    assert extract_products(tomcat) == [
        "Apache Tomcat",
        "Canonical Ubuntu Linux",
        "Netapp 7-Mode Transition Tool",
        "Netapp Oncommand Insight",
        "Netapp Oncommand Shift",
    ]
    assert extract_products(tomcat, limit=2) == ["Apache Tomcat", "Canonical Ubuntu Linux"]
    assert extract_products(oracle) == ["Oracle Agile Product Lifecycle Management"]
    assert extract_products({}) == []


def test_cpe_to_product_parsing():
    assert cpe_to_product("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*") == "Apache Tomcat"
    assert cpe_to_product("cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:esm:*:*:*") == "Canonical Ubuntu Linux"
    assert cpe_to_product("cpe:2.3:a:netapp:7-mode_transition_tool:-:*:*:*:*:*:*:*") == "Netapp 7-Mode Transition Tool"
    assert cpe_to_product("cpe:2.3:a:*:something:*:*:*:*:*:*:*:*") == "Something"
    assert cpe_to_product("cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*") is None
    assert cpe_to_product("cpe:/a:apache:tomcat") is None
    assert cpe_to_product(None) is None


def test_extract_cwes_skips_nvd_placeholders(tomcat):
    assert extract_cwes(tomcat) == []
    weaknesses = {
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "NVD-CWE-Other"}]},
            {"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "cwe-94"}]},
        ]
    }
    assert extract_cwes(weaknesses) == ["CWE-502", "CWE-94"]
    assert extract_cwes({}) == []


def test_extract_references_validates_dedupes_and_caps(tomcat, oracle):
    urls, tags = extract_references(tomcat)
    assert len(urls) == 15 and len(tags) == 15
    assert len(set(urls)) == 15
    assert all(u.startswith("https://") for u in urls)
    urls5, tags5 = extract_references(tomcat, limit=5)
    assert urls5 == urls[:5] and tags5 == tags[:5]
    assert extract_references(oracle) == ([], [])


# ---------------------------------------------------------------------------- pagination and rate limiting


def two_pages(nvd_page: dict[str, Any]) -> dict[int, dict[str, Any]]:
    first, second = nvd_page["vulnerabilities"]
    meta = {k: v for k, v in nvd_page.items() if k != "vulnerabilities"}
    return {
        0: {**meta, "resultsPerPage": 1, "startIndex": 0, "totalResults": 2, "vulnerabilities": [first]},
        1: {**meta, "resultsPerPage": 1, "startIndex": 1, "totalResults": 2, "vulnerabilities": [second]},
    }


def test_pagination_walks_pages_and_sleeps_without_key(nvd_page, now, sleeps):
    transport = PagedTransport(two_pages(nvd_page))
    adapter = NvdAdapter(make_source())
    result = adapter.fetch(make_ctx(transport.client(), window_2017(), now))

    assert result.status.ok is True
    assert [i.external_id for i in result.items] == ["CVE-2017-10039"]
    assert [int(r.url.params["startIndex"]) for r in transport.requests] == [0, 1]
    assert {r.url.params["resultsPerPage"] for r in transport.requests} == {"2000"}
    assert sleeps == [6.0]
    assert all("apiKey" not in r.headers for r in transport.requests)


def test_pagination_with_api_key_uses_short_delay_and_header(nvd_page, now, sleeps):
    transport = PagedTransport(two_pages(nvd_page))
    adapter = NvdAdapter(make_source())
    result = adapter.fetch(make_ctx(transport.client(), window_2017(), now, api_key=TEST_API_KEY))

    assert result.status.ok is True
    assert len(transport.requests) == 2
    assert sleeps == [0.7]
    assert all(r.headers["apiKey"] == TEST_API_KEY for r in transport.requests)


def test_single_page_does_not_sleep(routes, window, now, single_page, sleeps):
    fetch_single(routes, single_page, window, now)
    assert len(routes.requests) == 1
    assert sleeps == []


def test_pagination_stops_after_max_pages(nvd_page, now, sleeps, caplog):
    caplog.set_level("WARNING", logger="arkham.sources.nvd")
    first = nvd_page["vulnerabilities"][0]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        index = int(request.url.params["startIndex"])
        page = {**nvd_page, "resultsPerPage": 1, "startIndex": index, "totalResults": 10_000, "vulnerabilities": [first]}
        return httpx.Response(200, json=page, request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    published_window = (datetime(2017, 4, 6, tzinfo=UTC), datetime(2017, 4, 7, tzinfo=UTC))
    result = NvdAdapter(make_source()).fetch(make_ctx(http, published_window, now))
    assert result.status.ok is True
    assert [int(r.url.params["startIndex"]) for r in requests] == [0, 1, 2, 3, 4]
    assert sleeps == [6.0] * 4
    assert [i.external_id for i in result.items] == ["CVE-2016-8735"]  # de-duplicated across pages
    assert any("stopped after 5 pages" in rec.getMessage() for rec in caplog.records)


def test_empty_result_set_is_ok(routes, window, now, nvd_page):
    empty = {**nvd_page, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    _, _, result = fetch_single(routes, empty, window, now)
    assert result.status.ok is True
    assert result.items == []
    assert len(routes.requests) == 1


# ---------------------------------------------------------------------------- retries and failures


def test_retries_once_after_503(single_page, now, sleeps):
    transport = SequenceTransport([(503, b"busy"), (200, json.dumps(single_page).encode())])
    result = NvdAdapter(make_source()).fetch(make_ctx(transport.client(), window_2017(), now))
    assert result.status.ok is True
    assert len(transport.requests) == 2
    assert sleeps == [6.0]
    assert [i.external_id for i in result.items] == ["CVE-2017-10039"]


@pytest.mark.parametrize("status", [503, 429, 403])
def test_gives_up_after_second_retryable_error(status, window, now, sleeps):
    transport = SequenceTransport([(status, b"nope"), (status, b"nope")])
    result = NvdAdapter(make_source()).fetch(make_ctx(transport.client(), window, now))
    assert result.status.ok is False
    assert result.status.status == f"HTTP {status}"
    assert result.items == []
    assert len(transport.requests) == 2
    assert sleeps == [6.0]


def test_no_retry_for_non_retryable_status(single_page, window, now, sleeps):
    transport = SequenceTransport([(404, b"missing"), (200, json.dumps(single_page).encode())])
    result = NvdAdapter(make_source()).fetch(make_ctx(transport.client(), window, now))
    assert result.status.ok is False
    assert result.status.status == "HTTP 404"
    assert len(transport.requests) == 1
    assert sleeps == []


def test_timeout_reports_timeout_status(window, now, sleeps):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    result = NvdAdapter(make_source(timeout_seconds=5.0)).fetch(make_ctx(http, window, now))
    assert result.status.ok is False
    assert result.status.status == "TIMEOUT"
    assert result.items == []
    assert sleeps == []


def test_malformed_json_is_parse_error(routes, window, now):
    routes.add(NVD_URL, "<html>not json</html>")
    result = NvdAdapter(make_source()).fetch(make_ctx(routes.client(), window, now))
    assert result.status.ok is False
    assert result.status.status == "PARSE ERROR"


def test_missing_vulnerabilities_is_parse_error(routes, window, now):
    routes.add(NVD_URL, json.dumps({"totalResults": 1}))
    result = NvdAdapter(make_source()).fetch(make_ctx(routes.client(), window, now))
    assert result.status.ok is False
    assert result.status.status == "PARSE ERROR"
