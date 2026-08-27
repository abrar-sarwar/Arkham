"""Level-1 secure fetch + robots policy over the hardened HTTP client. No network: httpx.MockTransport only."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from arkham.config import load_settings
from arkham.crawl import fetcher
from arkham.crawl.fetcher import CrawlLimits, RobotsPolicy, crawl_limits, fetch_and_extract, fetch_page
from arkham.crawl.models import CrawlFailureReason, FetchMethod
from arkham.http import SafeHttpClient

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
PAGE = "https://security.example.org/advisories/gateway-flaw"
ROBOTS = "https://security.example.org/robots.txt"
HTML = (
    "<html><head><title>Vendor fixes exploited gateway flaw</title></head><body><main><article>"
    "<h1>Vendor fixes exploited gateway flaw</h1>"
    "<p>Attackers are exploiting CVE-2026-12345 in internet-facing Example Gateway appliances today.</p>"
    "<p>The flaw allows unauthenticated remote code execution and is tracked as CWE-787 by the vendor.</p>"
    "<p>Administrators should update supported appliances and inspect authentication logs for anomalies.</p>"
    "<p>Indicators include the C2 domain evil.example and the address 203.0.113.42 observed in logs.</p>"
    "</article></main></body></html>"
)


class Site:
    """Scripted origin: per-URL response lists consumed in order (last one repeats)."""

    def __init__(self) -> None:
        self.routes: dict[str, list[tuple[int, dict[str, str], bytes]]] = {}
        self.requests: list[httpx.Request] = []
        self.raise_for: dict[str, Exception] = {}

    def add(self, url: str, status: int = 200, body: str | bytes = HTML, headers: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        hdrs = {"content-type": "text/html; charset=utf-8"}
        hdrs.update(headers or {})
        self.routes.setdefault(url, []).append((status, hdrs, data))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url in self.raise_for:
            raise self.raise_for[url]
        script = self.routes.get(url)
        if not script:
            return httpx.Response(404, content=b"missing", headers={"content-type": "text/plain"}, request=request)
        status, headers, body = script.pop(0) if len(script) > 1 else script[0]
        return httpx.Response(status, content=body, headers=headers, request=request)

    def client(self) -> SafeHttpClient:
        return SafeHttpClient(transport=httpx.MockTransport(self.handler))

    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []
    monkeypatch.setattr(fetcher, "_sleep", delays.append)
    return delays


LIMITS = CrawlLimits(max_bytes=64 * 1024, timeout_seconds=5.0, retries=2, max_retry_after_seconds=30.0, max_text_chars=20_000)


# ---------------------------------------------------------------------------- fetch_page


def test_fetch_page_returns_decoded_html_and_lowercase_headers(sleeps) -> None:
    site = Site()
    site.add(PAGE, headers={"etag": '"v1"', "last-modified": "Wed, 26 Aug 2026 09:30:00 GMT"})
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None and result.status_code == 200 and not result.not_modified
    assert result.url == PAGE and result.final_url == PAGE
    assert "CVE-2026-12345" in result.body
    assert result.headers["etag"] == '"v1"' and result.headers["last-modified"].startswith("Wed")
    assert result.retries == 0
    request = site.requests[0]
    assert request.method == "GET"
    assert "text/html" in request.headers["accept"]
    assert sleeps == []


def test_conditional_headers_are_sent_and_304_is_reported_as_not_modified() -> None:
    site = Site()
    site.add(PAGE, status=304, body=b"", headers={"content-type": ""})
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS, etag='"v1"', last_modified="Wed, 26 Aug 2026 09:30:00 GMT")
    assert result.not_modified and result.body == "" and result.failure_reason is None
    request = site.requests[0]
    assert request.headers["if-none-match"] == '"v1"'
    assert request.headers["if-modified-since"] == "Wed, 26 Aug 2026 09:30:00 GMT"


@pytest.mark.parametrize("content_type", ["application/json", "application/pdf", "image/png", "application/octet-stream"])
def test_non_text_content_types_are_rejected(content_type: str) -> None:
    site = Site()
    site.add(PAGE, body=b"\x00\x01binary", headers={"content-type": content_type})
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.INVALID_CONTENT_TYPE
    assert result.body == ""


def test_plain_text_is_accepted_and_legacy_charset_is_decoded() -> None:
    site = Site()
    site.add(PAGE, body="Résumé of the advisory.".encode("latin-1"), headers={"content-type": "text/plain; charset=iso-8859-1"})
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None and result.body == "Résumé of the advisory."


def test_oversized_response_is_categorised() -> None:
    site = Site()
    site.add(PAGE, body="x" * (LIMITS.max_bytes + 1))
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.OVERSIZED_RESPONSE


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (401, CrawlFailureReason.AUTHENTICATION_REQUIRED),
        (403, CrawlFailureReason.BLOCKED_BY_SITE),
        (404, CrawlFailureReason.NOT_FOUND),
        (410, CrawlFailureReason.NOT_FOUND),
        (500, CrawlFailureReason.HTTP_ERROR),
        (418, CrawlFailureReason.HTTP_ERROR),
    ],
)
def test_http_errors_are_categorised_without_retry(sleeps, status: int, reason: CrawlFailureReason) -> None:
    site = Site()
    site.add(PAGE, status=status, body=b"nope")
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == reason and result.status_code == status
    assert len(site.requests) == 1 and sleeps == []
    assert result.failure_detail and len(result.failure_detail) <= 300


@pytest.mark.parametrize("status", [502, 503, 504])
def test_transient_server_errors_are_retried_with_backoff(sleeps, status: int) -> None:
    site = Site()
    site.add(PAGE, status=status, body=b"down")
    site.add(PAGE)
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None and result.retries == 1
    assert len(site.requests) == 2 and sleeps == [fetcher.BACKOFF_BASE_SECONDS]


def test_rate_limit_honours_retry_after_and_caps_it(sleeps) -> None:
    site = Site()
    site.add(PAGE, status=429, body=b"slow down", headers={"retry-after": "2"})
    site.add(PAGE, status=429, body=b"slow down", headers={"retry-after": "999"})
    site.add(PAGE)
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None and result.retries == 2
    assert sleeps == [2.0, LIMITS.max_retry_after_seconds]


def test_retries_are_bounded_and_rate_limit_is_reported(sleeps) -> None:
    site = Site()
    site.add(PAGE, status=429, body=b"slow down")
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.RATE_LIMITED
    assert len(site.requests) == LIMITS.retries + 1
    assert len(sleeps) == LIMITS.retries
    assert result.retries == LIMITS.retries


def test_timeout_is_not_retried(sleeps) -> None:
    site = Site()
    site.raise_for[PAGE] = httpx.ReadTimeout("slow")
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.TIMEOUT and len(site.requests) == 1 and sleeps == []


def test_transport_error_is_an_http_error(sleeps) -> None:
    site = Site()
    site.raise_for[PAGE] = httpx.ConnectError("refused")
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.HTTP_ERROR and len(site.requests) == 1


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("", CrawlFailureReason.INVALID_URL),
        ("not a url", CrawlFailureReason.INVALID_URL),
        ("ftp://example.org/x", CrawlFailureReason.INVALID_URL),
        ("http://security.example.org/advisories/x", CrawlFailureReason.UNSAFE_URL),
        ("https://127.0.0.1/admin", CrawlFailureReason.UNSAFE_URL),
        ("https://10.0.0.8/internal", CrawlFailureReason.UNSAFE_URL),
        ("https://169.254.169.254/latest/meta-data", CrawlFailureReason.UNSAFE_URL),
        ("https://localhost/x", CrawlFailureReason.UNSAFE_URL),
        ("https://user:pw@security.example.org/x", CrawlFailureReason.UNSAFE_URL),
        ("file:///etc/passwd", CrawlFailureReason.INVALID_URL),
    ],
)
def test_unsafe_or_invalid_urls_never_reach_the_network(url: str, reason: CrawlFailureReason) -> None:
    site = Site()
    result = fetch_page(url, http=site.client(), limits=LIMITS)
    assert result.failure_reason == reason and site.requests == []


def test_redirect_to_private_target_is_refused() -> None:
    site = Site()
    site.add(PAGE, status=302, body=b"", headers={"location": "https://10.0.0.5/steal"})
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.UNSAFE_URL
    assert all("10.0.0.5" not in url for url in site.urls())


def test_public_redirect_is_followed_and_final_url_recorded() -> None:
    site = Site()
    site.add(PAGE, status=301, body=b"", headers={"location": "https://security.example.org/advisories/gateway-flaw-2"})
    site.add("https://security.example.org/advisories/gateway-flaw-2")
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None
    assert result.final_url == "https://security.example.org/advisories/gateway-flaw-2"


# ---------------------------------------------------------------------------- robots


def robots_policy(site: Site) -> RobotsPolicy:
    return RobotsPolicy(http=site.client(), limits=LIMITS)


def test_robots_disallow_blocks_the_fetch_before_any_page_request() -> None:
    site = Site()
    site.add(ROBOTS, body="User-agent: *\nDisallow: /advisories/\nCrawl-delay: 5\n", headers={"content-type": "text/plain"})
    site.add(PAGE)
    policy = robots_policy(site)
    decision = policy.check(PAGE, now=NOW)
    assert not decision.allowed and decision.crawl_delay == 5.0 and decision.record is not None
    result = fetch_page(PAGE, http=site.client(), limits=LIMITS, robots=policy, now=NOW)
    assert result.failure_reason == CrawlFailureReason.ROBOTS_DENIED
    assert site.urls() == [ROBOTS]
    # A strict "text/plain" Accept makes some hosts (NVD) answer 406; the request must accept anything.
    assert "*/*" in site.requests[0].headers["accept"]


def test_robots_allow_is_cached_per_host() -> None:
    site = Site()
    site.add(ROBOTS, body="User-agent: *\nDisallow: /private/\n", headers={"content-type": "text/plain"})
    site.add(PAGE)
    policy = robots_policy(site)
    assert policy.check(PAGE, now=NOW).allowed
    assert policy.check("https://security.example.org/advisories/other", now=NOW + timedelta(hours=1)).allowed
    assert site.urls().count(ROBOTS) == 1
    assert not policy.check("https://security.example.org/private/x", now=NOW).allowed
    assert policy.check(PAGE, now=NOW + timedelta(hours=LIMITS.robots_cache_hours + 1)).allowed
    assert site.urls().count(ROBOTS) == 2  # expired and re-fetched


@pytest.mark.parametrize("status", [404, 410])
def test_missing_robots_means_no_policy_and_allows_fetching(status: int) -> None:
    site = Site()
    site.add(ROBOTS, status=status, body=b"", headers={"content-type": "text/plain"})
    decision = robots_policy(site).check(PAGE, now=NOW)
    assert decision.allowed and "no robots policy" in decision.reason


@pytest.mark.parametrize("status", [401, 403, 500])
def test_robots_denial_or_failure_fails_closed(status: int) -> None:
    site = Site()
    site.add(ROBOTS, status=status, body=b"", headers={"content-type": "text/plain"})
    policy = robots_policy(site)
    first = policy.check(PAGE, now=NOW)
    assert not first.allowed
    second = policy.check(PAGE, now=NOW + timedelta(minutes=1))
    assert not second.allowed and site.urls().count(ROBOTS) == 1  # failure cached
    third = policy.check(PAGE, now=NOW + timedelta(minutes=LIMITS.robots_failure_cache_minutes + 1))
    assert not third.allowed and site.urls().count(ROBOTS) == 2


def test_robots_timeout_fails_closed_temporarily() -> None:
    site = Site()
    site.raise_for[ROBOTS] = httpx.ReadTimeout("slow")
    decision = robots_policy(site).check(PAGE, now=NOW)
    assert not decision.allowed and decision.record is not None and decision.record.error


def test_robots_is_only_consulted_for_safe_urls() -> None:
    site = Site()
    policy = robots_policy(site)
    assert not policy.check("https://127.0.0.1/x", now=NOW).allowed
    assert site.requests == []


def test_robots_user_agent_specific_rules_and_dirty_records() -> None:
    site = Site()
    site.add(
        ROBOTS,
        body="User-agent: Arkham-CTI\nDisallow: /advisories/\n\nUser-agent: *\nDisallow:\n",
        headers={"content-type": "text/plain"},
    )
    policy = robots_policy(site)
    assert not policy.check(PAGE, now=NOW).allowed
    records = policy.dirty_records()
    assert len(records) == 1 and records[0].host == "security.example.org" and records[0].status_code == 200
    assert policy.dirty_records() == []  # drained


# ---------------------------------------------------------------------------- fetch_and_extract


def test_fetch_and_extract_returns_a_scored_article(sleeps) -> None:
    site = Site()
    site.add(PAGE)
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason is None and article is not None
    assert article.title == "Vendor fixes exploited gateway flaw"
    assert article.quality_score >= 0.6 and article.article_container
    assert {(i.type, i.value) for i in article.indicators} >= {("cve", "CVE-2026-12345"), ("ipv4", "203.0.113.42"), ("domain", "evil.example")}
    assert article.canonical_url == PAGE


def test_fetch_and_extract_recognises_a_challenge_page() -> None:
    site = Site()
    site.add(
        PAGE,
        status=200,
        body="<html><head><title>Just a moment...</title></head><body><div id='cf-wrapper'>"
        "<p>Checking your browser before accessing security.example.org.</p><p>Enable JavaScript and cookies to continue</p>"
        "</div><script src='/cdn-cgi/challenge.js'></script></body></html>",
    )
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.CAPTCHA_DETECTED and article is None


def test_fetch_and_extract_recognises_a_login_wall() -> None:
    site = Site()
    site.add(PAGE, body="<html><body><main><h1>Members area</h1><p>Please sign in to continue reading this report.</p></main></body></html>")
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.AUTHENTICATION_REQUIRED and article is None


def test_fetch_and_extract_on_not_modified_returns_no_article() -> None:
    site = Site()
    site.add(PAGE, status=304, body=b"", headers={"content-type": ""})
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS, etag='"v1"')
    assert result.not_modified and article is None and result.failure_reason is None


def test_fetch_and_extract_reports_javascript_shell_as_browser_disabled() -> None:
    """A JS bootstrap page (as served by nvd.nist.gov detail URLs) needs a renderer v1 does not have."""
    site = Site()
    site.add(
        PAGE,
        body="<html><head><title>NVD - Home</title><script src='/a.js'></script><script src='/b.js'></script></head>"
        "<body><div id='app'></div><script>window.__boot=1</script></body></html>",
    )
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.BROWSER_DISABLED
    assert article is not None and article.js_shell and article.article_text == ""
    assert "renderer" in (result.failure_detail or "")


def test_fetch_and_extract_flags_extraction_failure_on_empty_page() -> None:
    site = Site()
    site.add(PAGE, body="<html><body></body></html>")
    result, article = fetch_and_extract(PAGE, http=site.client(), limits=LIMITS)
    assert result.failure_reason == CrawlFailureReason.EXTRACTION_FAILED and article is not None
    assert article.article_text == "" and article.quality_score == 0.0


def test_crawl_limits_come_from_settings() -> None:
    settings = load_settings(
        {
            "ARKHAM_CRAWL_HTTP_MAX_BYTES": "1048576",
            "ARKHAM_CRAWL_MAX_TEXT_CHARS": "20000",
            "ARKHAM_CRAWL_RETRIES": "1",
            "ARKHAM_CRAWL_MAX_RETRY_AFTER_SECONDS": "9",
            "ARKHAM_CRAWL_ROBOTS_CACHE_HOURS": "12",
            "ARKHAM_CRAWL_ROBOTS_FAILURE_CACHE_MINUTES": "10",
            "ARKHAM_HTTP_TIMEOUT": "7",
        },
        dotenv_path=None,
    )
    limits = crawl_limits(settings)
    assert limits.max_bytes == 1_048_576 and limits.max_text_chars == 20_000 and limits.retries == 1
    assert limits.max_retry_after_seconds == 9 and limits.robots_cache_hours == 12
    assert limits.robots_failure_cache_minutes == 10 and limits.timeout_seconds == 7
    assert limits.user_agent == settings.user_agent


def test_fetch_method_constant_is_http() -> None:
    assert fetcher.FETCH_METHOD is FetchMethod.HTTP
