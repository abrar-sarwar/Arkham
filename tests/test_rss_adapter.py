"""Tests for the generic RSS/Atom adapter using trimmed copies of live feeds captured 2026-08-26."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from arkham.http import SafeHttpClient
from arkham.models import SourceCategory, SourceState, SourceTier
from arkham.sources.base import FetchContext, Source
from arkham.sources.rss import CONTENT_MAX, SUMMARY_MAX, RssAdapter, extract_links
from tests.conftest import RouteTable, load_fixture_text

UNIT42_URL = "https://unit42.paloaltonetworks.com/feed/"
BLEEPING_URL = "https://www.bleepingcomputer.com/feed/"
THERECORD_URL = "https://therecord.media/feed"
TALOS_URL = "https://blog.talosintelligence.com/rss/"

UTC = timezone.utc


def make_source(source_id: str, url: str, **overrides: object) -> Source:
    fields: dict[str, object] = {
        "id": source_id,
        "name": source_id.title(),
        "type": "rss",
        "tier": SourceTier.RESEARCH,
        "category": SourceCategory.THREAT_INTEL,
        "url": url,
        "adapter": "rss",
        "publisher": source_id.title(),
    }
    fields.update(overrides)
    return Source(**fields)  # type: ignore[arg-type]


def make_ctx(
    http: SafeHttpClient,
    now: datetime,
    window: tuple[datetime, datetime],
    state: SourceState | None = None,
) -> FetchContext:
    return FetchContext(http=http, window_start=window[0], window_end=window[1], now=now, state=state)


# --------------------------------------------------------------------------------- Unit 42


@pytest.fixture
def unit42_routes(routes: RouteTable) -> RouteTable:
    routes.add(
        UNIT42_URL, load_fixture_text("rss_unit42.xml"), headers={"content-type": "application/rss+xml"}
    )
    return routes


@pytest.fixture
def wide_window(now: datetime) -> tuple[datetime, datetime]:
    """48h window: the newest Unit 42 post (25 Aug 10:00 UTC) is inside, the 21/20 Aug posts are outside."""
    return now - timedelta(hours=48), now


def test_unit42_only_items_inside_window(
    unit42_routes: RouteTable, now: datetime, wide_window: tuple[datetime, datetime]
) -> None:
    source = make_source("unit42", UNIT42_URL, name="Palo Alto Networks Unit 42", publisher="Unit 42")
    result = RssAdapter(source).fetch(make_ctx(unit42_routes.client(), now, wide_window))

    assert result.status.ok is True
    assert result.status.status == "OK"
    assert result.status.items == 1
    assert result.status.elapsed_ms >= 0
    assert len(result.items) == 1  # the 21 Aug and 20 Aug posts are outside the 48h window
    item = result.items[0]
    assert item.title == "The State of AI-Enabled Malware August 2026: From Brand Abuse to Agentic Execution"
    assert item.url == "https://unit42.paloaltonetworks.com/ai-enabled-malware-analysis/"
    assert item.external_id == "https://unit42.paloaltonetworks.com/?p=186148"
    assert item.published_at == datetime(2026, 8, 25, 10, 0, 57, tzinfo=UTC)
    # feedparser 6.x falls back to pubDate for a missing <updated>, so both stamps agree
    assert item.updated_at == item.published_at
    assert item.effective_time == item.published_at
    assert item.fetched_at == now
    assert item.source_id == "unit42"
    assert item.source_name == "Palo Alto Networks Unit 42"
    assert item.source_tier is SourceTier.RESEARCH
    assert item.source_category is SourceCategory.THREAT_INTEL
    assert item.extra["publisher"] == "Unit 42"
    assert item.extra["author"] == "Sara McBroom"
    assert "Malware" in item.extra["categories"]
    assert "Threat Research" in item.extra["categories"]
    assert item.raw_hash


def test_unit42_summary_is_sanitized_plain_text(
    unit42_routes: RouteTable, now: datetime, wide_window: tuple[datetime, datetime]
) -> None:
    source = make_source("unit42", UNIT42_URL)
    result = RssAdapter(source).fetch(make_ctx(unit42_routes.client(), now, wide_window))

    summary = result.items[0].summary
    assert "<" not in summary and ">" not in summary
    assert "href" not in summary
    assert summary.startswith("Explore Unit 42 research on AI-enabled malware.")
    assert "appeared first on Unit 42" in summary
    assert len(summary) <= SUMMARY_MAX
    assert result.items[0].content == ""  # feed carries no content:encoded


def test_unit42_referenced_links_extracted_from_description(
    unit42_routes: RouteTable, now: datetime, wide_window: tuple[datetime, datetime]
) -> None:
    source = make_source("unit42", UNIT42_URL)
    result = RssAdapter(source).fetch(make_ctx(unit42_routes.client(), now, wide_window))

    assert result.items[0].extra["referenced_links"] == [
        "https://unit42.paloaltonetworks.com/ai-enabled-malware-analysis/",
        "https://unit42.paloaltonetworks.com",
    ]


def test_unit42_max_items_caps_entries_considered(
    unit42_routes: RouteTable, now: datetime, wide_window: tuple[datetime, datetime]
) -> None:
    source = make_source("unit42", UNIT42_URL, max_items=1)
    result = RssAdapter(source).fetch(make_ctx(unit42_routes.client(), now, wide_window))
    assert [i.external_id for i in result.items] == ["https://unit42.paloaltonetworks.com/?p=186148"]


def test_entries_without_dates_are_rejected(
    routes: RouteTable, now: datetime, wide_window: tuple[datetime, datetime]
) -> None:
    body = load_fixture_text("rss_unit42.xml").replace(
        "<pubDate>Tue, 25 Aug 2026 10:00:57 +0000</pubDate>", ""
    )
    routes.add(UNIT42_URL, body)
    result = RssAdapter(make_source("unit42", UNIT42_URL)).fetch(make_ctx(routes.client(), now, wide_window))
    assert result.status.ok is True
    assert result.items == []  # the only in-window post lost its date, so nothing is accepted


# --------------------------------------------------------------------------- BleepingComputer


def test_bleeping_timezone_offsets_and_window_upper_bound(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(BLEEPING_URL, load_fixture_text("rss_bleeping.xml"))
    source = make_source(
        "bleepingcomputer", BLEEPING_URL, tier=SourceTier.JOURNALISM, category=SourceCategory.NEWS
    )
    result = RssAdapter(source).fetch(make_ctx(routes.client(), now, window))

    titles = [i.title for i in result.items]
    # 10:47 -0400 == 14:47 UTC is beyond window_end (12:00) + 1h slack; 08:06 -0400 == 12:06 UTC is inside the slack.
    assert "Hackers target Microsoft SharePoint RCE chain with PoC exploit" not in titles
    assert titles == [
        "Microsoft tests new privacy controls for Windows 11 desktop apps",
        "Hackers now exploit critical Gitea flaw in code injection attacks",
        "LACMA data breach last year exposed social security and medical data",
    ]
    gitea = result.items[1]
    assert gitea.published_at == datetime(2026, 8, 26, 11, 7, 48, tzinfo=UTC)
    assert all(
        i.published_at is not None and i.published_at.utcoffset() == timedelta(0) for i in result.items
    )
    assert all(i.source_tier is SourceTier.JOURNALISM for i in result.items)
    assert gitea.extra["author"] == "Sergiu Gatlan"
    assert gitea.extra["categories"] == ["Security"]
    assert gitea.extra["referenced_links"] == []  # plain-text description, no anchors


def test_bleeping_max_items_counts_entries_not_accepted_items(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(BLEEPING_URL, load_fixture_text("rss_bleeping.xml"))
    # The first feed entry is outside the window, so max_items=1 yields nothing and max_items=2 yields one item.
    one = RssAdapter(make_source("bleepingcomputer", BLEEPING_URL, max_items=1)).fetch(
        make_ctx(routes.client(), now, window)
    )
    two = RssAdapter(make_source("bleepingcomputer", BLEEPING_URL, max_items=2)).fetch(
        make_ctx(routes.client(), now, window)
    )
    assert one.items == []
    assert [i.title for i in two.items] == [
        "Microsoft tests new privacy controls for Windows 11 desktop apps"
    ]


# ------------------------------------------------------------------------------- The Record


def test_therecord_items_after_window_are_excluded(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(THERECORD_URL, load_fixture_text("rss_therecord.xml"))
    source = make_source(
        "the-record", THERECORD_URL, tier=SourceTier.JOURNALISM, category=SourceCategory.NEWS
    )
    result = RssAdapter(source).fetch(make_ctx(routes.client(), now, window))

    assert [i.title for i in result.items] == [
        "58 arrested in international cybercrime crackdown",
        "Employee benefits platform Paylogix says hackers stole financial and health data",
    ]
    paylogix = result.items[1]
    assert (
        paylogix.external_id
        == paylogix.url
        == "https://therecord.media/paylogix-cyberattack-akira-ransomware"
    )
    assert paylogix.published_at == datetime(2026, 8, 25, 18, 45, tzinfo=UTC)
    assert paylogix.summary.startswith("The benefits management firm Paylogix told regulators")
    assert paylogix.extra["author"] == ""
    assert paylogix.extra["categories"] == ["News", "Privacy", "Cybercrime"]


def test_invalid_link_entries_are_skipped(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    body = load_fixture_text("rss_therecord.xml").replace(
        "<link>https://therecord.media/58-arrested-international-cybercrime-crackdown-interpol</link>",
        "<link>http://localhost/58-arrested-international-cybercrime-crackdown-interpol</link>",
    )
    routes.add(THERECORD_URL, body)
    result = RssAdapter(make_source("the-record", THERECORD_URL)).fetch(
        make_ctx(routes.client(), now, window)
    )
    assert result.status.ok is True
    assert [i.title for i in result.items] == [
        "Employee benefits platform Paylogix says hackers stole financial and health data"
    ]


# ------------------------------------------------------------------------------------ Talos


def test_talos_content_encoded_is_sanitized_and_links_extracted(routes: RouteTable, now: datetime) -> None:
    routes.add(TALOS_URL, load_fixture_text("rss_talos.xml"))
    source = make_source("cisco-talos", TALOS_URL, name="Cisco Talos Intelligence", publisher="Talos")
    window = (now - timedelta(hours=48), now)  # 25 Aug 10:00 UTC post is inside, 19 Aug post is outside
    result = RssAdapter(source).fetch(make_ctx(routes.client(), now, window))

    assert len(result.items) == 1
    item = result.items[0]
    assert item.title == "The safety penalty: Reclaiming operational sovereignty in the age of AI"
    assert item.external_id == "6a8c42f9a4773e00014cdf4e"
    assert item.published_at == datetime(2026, 8, 25, 10, 0, 22, tzinfo=UTC)
    assert item.summary.startswith("As frontier AI models become increasingly restrictive")
    assert item.content
    assert len(item.content) <= CONTENT_MAX
    for fragment in ("<ul>", "<li>", "<p>", "<img", "href", "&#x", "&quot;"):
        assert fragment not in item.content
    assert (
        "As frontier models advance in cyber capability, their guardrails also become more restrictive."
        in item.content
    )
    assert "“safety penalty”" in item.content  # entities decoded to real characters
    links = item.extra["referenced_links"]
    assert links[:3] == [
        "https://openai.com/index/hugging-face-model-evaluation-security-incident/",
        "https://unit42.paloaltonetworks.com/ai-insights-incident-response-report/",
        "https://arxiv.org/abs/2603.01246",
    ]
    assert "https://aws.amazon.com/bedrock/" in links
    assert len(links) == len(set(links))
    assert item.extra["author"] == "David J. Bianco"
    assert item.extra["publisher"] == "Talos"


# ---------------------------------------------------------------------- conditional GET / state


def test_success_records_new_state_from_response_headers(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(
        THERECORD_URL,
        load_fixture_text("rss_therecord.xml"),
        headers={"ETag": '"abc123"', "Last-Modified": "Wed, 26 Aug 2026 18:35:00 GMT"},
    )
    result = RssAdapter(make_source("the-record", THERECORD_URL)).fetch(
        make_ctx(routes.client(), now, window)
    )

    assert result.new_state is not None
    assert result.new_state.source_id == "the-record"
    assert result.new_state.etag == '"abc123"'
    assert result.new_state.last_modified == "Wed, 26 Aug 2026 18:35:00 GMT"
    assert result.new_state.last_success_at == now
    assert result.new_state.last_status == "OK"
    assert result.new_state.consecutive_failures == 0


def test_conditional_get_sends_validators_and_304_keeps_state(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(THERECORD_URL, b"", status=304)
    state = SourceState(
        source_id="the-record",
        etag='"abc123"',
        last_modified="Wed, 26 Aug 2026 18:35:00 GMT",
        last_success_at=now - timedelta(hours=24),
        last_status="OK",
        consecutive_failures=2,
    )
    result = RssAdapter(make_source("the-record", THERECORD_URL)).fetch(
        make_ctx(routes.client(), now, window, state)
    )

    request = routes.requests[-1]
    assert request.headers["If-None-Match"] == '"abc123"'
    assert request.headers["If-Modified-Since"] == "Wed, 26 Aug 2026 18:35:00 GMT"
    assert result.status.ok is True
    assert result.status.status == "NOT MODIFIED"
    assert result.status.items == 0
    assert result.items == []
    assert result.new_state is not None
    assert result.new_state.etag == '"abc123"'
    assert result.new_state.last_modified == "Wed, 26 Aug 2026 18:35:00 GMT"
    assert result.new_state.last_status == "NOT MODIFIED"
    assert result.new_state.last_success_at == now
    assert result.new_state.consecutive_failures == 0


def test_304_without_prior_state_yields_no_new_state(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(THERECORD_URL, b"", status=304)
    result = RssAdapter(make_source("the-record", THERECORD_URL)).fetch(
        make_ctx(routes.client(), now, window)
    )
    assert result.status.status == "NOT MODIFIED"
    assert result.new_state is None
    assert "If-None-Match" not in routes.requests[-1].headers


# ------------------------------------------------------------------------------- failure modes


def test_http_500_reports_failure_without_raising(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(BLEEPING_URL, "<html>upstream error</html>", status=500)
    result = RssAdapter(make_source("bleepingcomputer", BLEEPING_URL)).fetch(
        make_ctx(routes.client(), now, window)
    )

    assert result.status.ok is False
    assert result.status.status == "HTTP 500"
    assert result.status.items == 0
    assert result.status.error is not None and "500" in result.status.error
    assert result.items == []
    assert result.new_state is None


def test_read_timeout_reports_timeout_status(now: datetime, window: tuple[datetime, datetime]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(handler), timeout_seconds=0.5)
    result = RssAdapter(make_source("bleepingcomputer", BLEEPING_URL)).fetch(make_ctx(http, now, window))

    assert result.status.ok is False
    assert result.status.status == "TIMEOUT"
    assert result.items == []
    assert result.new_state is None


def test_garbage_body_reports_parse_error(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(TALOS_URL, b"\x00\x01this is not a feed {{{ <<<")
    result = RssAdapter(make_source("cisco-talos", TALOS_URL)).fetch(make_ctx(routes.client(), now, window))

    assert result.status.ok is False
    assert result.status.status == "PARSE ERROR"
    assert result.status.error is not None and "feed parse error" in result.status.error
    assert result.items == []
    assert result.new_state is None


def test_oversized_body_reports_too_large(
    routes: RouteTable, now: datetime, window: tuple[datetime, datetime]
) -> None:
    routes.add(TALOS_URL, load_fixture_text("rss_talos.xml"))
    source = make_source("cisco-talos", TALOS_URL, max_bytes=1024)
    result = RssAdapter(source).fetch(make_ctx(routes.client(), now, window))

    assert result.status.ok is False
    assert result.status.status == "TOO LARGE"
    assert result.items == []


def test_transport_error_reports_network_error(now: datetime, window: tuple[datetime, datetime]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = SafeHttpClient(transport=httpx.MockTransport(handler))
    result = RssAdapter(make_source("bleepingcomputer", BLEEPING_URL)).fetch(make_ctx(http, now, window))
    assert result.status.ok is False
    assert result.status.status == "NETWORK ERROR"


# ------------------------------------------------------------------------------- extract_links


def test_extract_links_validates_and_deduplicates() -> None:
    html = (
        '<p>See <a href="https://openai.com/index/hugging-face-model-evaluation-security-incident/">this</a>, '
        '<a href="http://insecure.example.com/x">plain http</a>, '
        '<a href="https://localhost/private">loopback</a>, '
        '<a href="https://openai.com/index/hugging-face-model-evaluation-security-incident/">again</a> '
        'and <a href="https://arxiv.org/abs/2603.01246">a paper</a>.</p>'
    )
    assert extract_links(html) == [
        "https://openai.com/index/hugging-face-model-evaluation-security-incident/",
        "https://arxiv.org/abs/2603.01246",
    ]
    assert extract_links("") == []
    assert extract_links("no anchors here") == []
    assert len(extract_links(html * 40, limit=2)) == 2
