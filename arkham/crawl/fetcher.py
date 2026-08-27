"""Level-1 article fetching: one hardened HTTPS GET per URL, categorised failures, robots.txt respect.

Everything goes through :class:`arkham.http.SafeHttpClient` (https-only public hosts, redirect
re-validation, streaming size cap, timeouts); this module adds only crawl semantics: URL
normalisation, robots policy, conditional requests, content-type gating, charset decoding, bounded
retries for 429/502/503/504 (``Retry-After`` honoured up to a cap) and mapping every outcome to a
:class:`~arkham.crawl.models.CrawlFailureReason`. Nothing here executes page content or follows
links found in pages; ``fetch_and_extract`` merely hands the body to :mod:`arkham.crawl.extract`.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from arkham.config import Settings
from arkham.crawl.extract import extract_article
from arkham.crawl.models import (
    CrawlFailureReason,
    CrawlFetchResult,
    ExtractedArticle,
    FetchMethod,
    RobotsDecision,
    RobotsRecord,
)
from arkham.crawl.normalize import normalize_crawl_url
from arkham.crawl.quality import classify_interstitial
from arkham.http import HttpError, HttpStatusError, HttpTimeout, ResponseTooLarge, SafeHttpClient
from arkham.security.urls import UrlValidationError, validate_public_url

log = logging.getLogger(__name__)

FETCH_METHOD = FetchMethod.HTTP
ACCEPT_HEADER = "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.8"
ACCEPTED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "application/xml", "text/xml")
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 30.0
ROBOTS_ACCEPT_HEADER = "text/plain, */*;q=0.5"  # some hosts (e.g. NVD) answer 406 to a strict text/plain Accept
ROBOTS_MAX_BYTES = 512 * 1024
ROBOTS_TIMEOUT_SECONDS = 10.0
MAX_DETAIL = 300
_RETRY_STATUSES = frozenset({429, 502, 503, 504})
_CHARSET_RE = re.compile(r"charset=\"?([A-Za-z0-9_\-]+)", re.I)
_WS_RE = re.compile(r"\s+")

_sleep = time.sleep


@dataclass(frozen=True)
class CrawlLimits:
    """Bounds for one crawl call; built from :class:`Settings` by :func:`crawl_limits`."""

    max_bytes: int = 4 * 1024 * 1024
    timeout_seconds: float = 20.0
    retries: int = 2
    max_retry_after_seconds: float = 30.0
    max_text_chars: int = 50_000
    robots_cache_hours: int = 24
    robots_failure_cache_minutes: int = 30
    user_agent: str = "Arkham-CTI/1.0 (+personal threat-intelligence agent)"


def crawl_limits(settings: Settings) -> CrawlLimits:
    return CrawlLimits(
        max_bytes=settings.crawl_http_max_bytes,
        timeout_seconds=settings.http_timeout_seconds,
        retries=settings.crawl_retries,
        max_retry_after_seconds=settings.crawl_max_retry_after_seconds,
        max_text_chars=settings.crawl_max_text_chars,
        robots_cache_hours=settings.crawl_robots_cache_hours,
        robots_failure_cache_minutes=settings.crawl_robots_failure_cache_minutes,
        user_agent=settings.user_agent,
    )


def _detail(text: str) -> str:
    cleaned = _WS_RE.sub(" ", text).strip()
    return cleaned[: MAX_DETAIL - 1] + "…" if len(cleaned) > MAX_DETAIL else cleaned


def _decode(body: bytes, content_type: str) -> str:
    match = _CHARSET_RE.search(content_type)
    encodings = [match.group(1)] if match else []
    encodings += ["utf-8"]
    for encoding in encodings:
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def _content_type_ok(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return any(media == accepted for accepted in ACCEPTED_CONTENT_TYPES)


# --------------------------------------------------------------------------------------
# robots.txt
# --------------------------------------------------------------------------------------


class RobotsPolicy:
    """Per-host robots.txt evaluation with an in-memory TTL cache (fail closed on denial or error).

    ``404``/``410`` mean "no published policy" (allowed). ``401``/``403``, parse failures, timeouts
    and other errors deny crawling for ``robots_failure_cache_minutes``. Successful policies are
    cached for ``robots_cache_hours``. ``dirty_records()`` drains records a store may persist.
    """

    def __init__(self, *, http: SafeHttpClient, limits: CrawlLimits) -> None:
        self._http = http
        self._limits = limits
        self._records: dict[str, RobotsRecord] = {}
        self._parsers: dict[str, RobotFileParser | None] = {}
        self._dirty: list[RobotsRecord] = []

    def check(self, url: str, *, now: datetime | None = None) -> RobotsDecision:
        now = now or datetime.now(timezone.utc)
        try:
            safe = validate_public_url(url)
        except UrlValidationError as exc:
            return RobotsDecision(allowed=False, reason=f"unsafe url: {exc}")
        host = (urlsplit(safe).hostname or "").lower()
        record = self._records.get(host)
        if record is None or record.expires_at <= now:
            record = self._fetch(host, now)
            self._records[host] = record
            self._dirty.append(record)
        parser = self._parsers.get(host)
        if record.error:
            return RobotsDecision(allowed=False, reason=f"robots unavailable ({record.error}); failing closed", record=record)
        if parser is None:
            return RobotsDecision(allowed=True, reason="no robots policy published", record=record)
        agent = self._limits.user_agent.split("/", 1)[0].split(" ", 1)[0] or "*"
        allowed = parser.can_fetch(agent, safe)
        delay = parser.crawl_delay(agent)
        if delay is None:
            rate = parser.request_rate(agent)
            delay = (rate.seconds / rate.requests) if rate and rate.requests else 0.0
        return RobotsDecision(
            allowed=bool(allowed),
            crawl_delay=float(delay or 0.0),
            reason="allowed by robots.txt" if allowed else "disallowed by robots.txt",
            record=record,
        )

    def dirty_records(self) -> list[RobotsRecord]:
        records, self._dirty = self._dirty, []
        return records

    def _fetch(self, host: str, now: datetime) -> RobotsRecord:
        url = f"https://{host}/robots.txt"
        ok_until = now + timedelta(hours=self._limits.robots_cache_hours)
        fail_until = now + timedelta(minutes=self._limits.robots_failure_cache_minutes)
        self._parsers[host] = None
        try:
            response = self._http.get(
                url,
                headers={"Accept": ROBOTS_ACCEPT_HEADER},
                max_bytes=ROBOTS_MAX_BYTES,
                timeout_seconds=min(ROBOTS_TIMEOUT_SECONDS, self._limits.timeout_seconds),
            )
        except HttpStatusError as exc:
            if exc.status_code in (404, 410):
                return RobotsRecord(host=host, status_code=exc.status_code, fetched_at=now, expires_at=ok_until)
            return RobotsRecord(
                host=host, status_code=exc.status_code, fetched_at=now, expires_at=fail_until,
                error=f"HTTP {exc.status_code}",
            )
        except HttpError as exc:
            return RobotsRecord(host=host, fetched_at=now, expires_at=fail_until, error=_detail(exc.__class__.__name__))
        except Exception as exc:  # never let robots evaluation raise into a collector
            return RobotsRecord(host=host, fetched_at=now, expires_at=fail_until, error=_detail(exc.__class__.__name__))
        body = _decode(response.body, response.headers.get("content-type", "")) if response.body else ""
        parser = RobotFileParser()
        try:
            parser.parse(body.splitlines())
        except Exception as exc:  # malformed robots: fail closed for the failure window
            return RobotsRecord(host=host, status_code=response.status_code, fetched_at=now, expires_at=fail_until, error=_detail(f"parse error: {exc.__class__.__name__}"))
        self._parsers[host] = parser
        return RobotsRecord(
            host=host,
            body=body[:ROBOTS_MAX_BYTES],
            status_code=response.status_code,
            fetched_at=now,
            expires_at=ok_until,
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
        )


# --------------------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------------------


def _failure(url: str, reason: CrawlFailureReason, detail: str, *, status: int | None = None, retries: int = 0) -> CrawlFetchResult:
    return CrawlFetchResult(url=url, status_code=status, failure_reason=reason, failure_detail=_detail(detail), retries=retries)


def fetch_page(
    url: str,
    *,
    http: SafeHttpClient,
    limits: CrawlLimits,
    etag: str | None = None,
    last_modified: str | None = None,
    robots: RobotsPolicy | None = None,
    now: datetime | None = None,
) -> CrawlFetchResult:
    """Fetch one public HTTPS page as text. Never raises; every outcome is a :class:`CrawlFetchResult`."""
    raw = (url or "").strip()
    try:
        target = normalize_crawl_url(raw)
    except UrlValidationError as exc:
        scheme = urlsplit(raw).scheme.lower() if raw else ""
        reason = CrawlFailureReason.UNSAFE_URL if scheme == "http" or (scheme == "https") else CrawlFailureReason.INVALID_URL
        return _failure(raw, reason, f"rejected before fetch: {exc}")
    except ValueError as exc:
        return _failure(raw, CrawlFailureReason.INVALID_URL, f"rejected before fetch: {exc}")
    if robots is not None:
        decision = robots.check(target, now=now)
        if not decision.allowed:
            return _failure(target, CrawlFailureReason.ROBOTS_DENIED, decision.reason)

    retries = 0
    while True:
        try:
            response = http.get(
                target,
                headers={"Accept": ACCEPT_HEADER},
                etag=etag,
                last_modified=last_modified,
                max_bytes=limits.max_bytes,
                timeout_seconds=limits.timeout_seconds,
            )
        except HttpStatusError as exc:
            if exc.status_code in _RETRY_STATUSES and retries < limits.retries:
                retries += 1
                delay = exc.retry_after_seconds() if exc.status_code == 429 else None
                if delay is None:
                    delay = min(BACKOFF_BASE_SECONDS * 2 ** (retries - 1), BACKOFF_CAP_SECONDS)
                delay = min(delay, limits.max_retry_after_seconds)
                log.debug("crawl retry %d/%d after HTTP %d (%.1fs)", retries, limits.retries, exc.status_code, delay)
                _sleep(delay)
                continue
            return _failure(target, _status_reason(exc.status_code), f"HTTP {exc.status_code}", status=exc.status_code, retries=retries)
        except ResponseTooLarge as exc:
            return _failure(target, CrawlFailureReason.OVERSIZED_RESPONSE, str(exc), retries=retries)
        except HttpTimeout:
            return _failure(target, CrawlFailureReason.TIMEOUT, f"timeout after {limits.timeout_seconds}s", retries=retries)
        except HttpError as exc:
            message = str(exc)
            reason = CrawlFailureReason.UNSAFE_URL if "unsafe" in message.lower() or "redirect" in message.lower() else CrawlFailureReason.HTTP_ERROR
            return _failure(target, reason, message, retries=retries)
        except Exception as exc:  # defence in depth: a collector must never die on one page
            return _failure(target, CrawlFailureReason.HTTP_ERROR, f"{exc.__class__.__name__}: {exc}", retries=retries)

        headers = {k.lower(): v for k, v in response.headers.items()}
        if response.not_modified:
            return CrawlFetchResult(url=target, final_url=response.url, status_code=304, headers=headers, not_modified=True, retries=retries)
        content_type = headers.get("content-type", "")
        if content_type and not _content_type_ok(content_type):
            return _failure(target, CrawlFailureReason.INVALID_CONTENT_TYPE, f"content-type {content_type.split(';', 1)[0]}", status=response.status_code, retries=retries)
        body = _decode(response.body, content_type)
        return CrawlFetchResult(url=target, final_url=response.url, status_code=response.status_code, headers=headers, body=body, retries=retries)


def _status_reason(status: int) -> CrawlFailureReason:
    if status == 401:
        return CrawlFailureReason.AUTHENTICATION_REQUIRED
    if status == 403:
        return CrawlFailureReason.BLOCKED_BY_SITE
    if status in (404, 410):
        return CrawlFailureReason.NOT_FOUND
    if status == 429:
        return CrawlFailureReason.RATE_LIMITED
    return CrawlFailureReason.HTTP_ERROR


def fetch_and_extract(
    url: str,
    *,
    http: SafeHttpClient,
    limits: CrawlLimits,
    etag: str | None = None,
    last_modified: str | None = None,
    robots: RobotsPolicy | None = None,
    now: datetime | None = None,
) -> tuple[CrawlFetchResult, ExtractedArticle | None]:
    """``fetch_page`` followed by deterministic extraction; interstitials become categorised failures."""
    result = fetch_page(url, http=http, limits=limits, etag=etag, last_modified=last_modified, robots=robots, now=now)
    if result.failure_reason is not None or result.not_modified:
        return result, None
    article = extract_article(
        result.body,
        response_url=result.final_url or result.url,
        headers=result.headers,
        max_text_chars=limits.max_text_chars,
        max_html_chars=limits.max_bytes,
    )
    blocked = classify_interstitial(article.title, article.article_text or result.body[:2000])
    if blocked is not None and article.quality_score < 0.62:
        return result.model_copy(update={"failure_reason": blocked, "failure_detail": "interstitial page detected", "body": ""}), None
    if article.js_shell and not article.article_text:
        detail = "javascript shell; a Level-2 renderer is not part of v1"
        return result.model_copy(update={"failure_reason": CrawlFailureReason.BROWSER_DISABLED, "failure_detail": detail}), article
    if not article.article_text:
        return result.model_copy(update={"failure_reason": CrawlFailureReason.EXTRACTION_FAILED, "failure_detail": "no readable text"}), article
    return result, article
