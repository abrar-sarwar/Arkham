"""Typed contracts shared by the native crawl subsystem and run history."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class FetchMethod(str, Enum):
    FEED = "feed"
    HTTP = "http"
    BROWSER = "browser"
    CACHE = "cache"
    NONE = "none"


class CrawlFailureReason(str, Enum):
    INVALID_URL = "invalid_url"
    UNSAFE_URL = "unsafe_url"
    ROBOTS_DENIED = "robots_denied"
    AUTHENTICATION_REQUIRED = "authentication_required"
    CAPTCHA_DETECTED = "captcha_detected"
    BLOCKED_BY_SITE = "blocked_by_site"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    HTTP_ERROR = "http_error"
    TIMEOUT = "timeout"
    OVERSIZED_RESPONSE = "oversized_response"
    INVALID_CONTENT_TYPE = "invalid_content_type"
    EXTRACTION_FAILED = "extraction_failed"
    RENDER_FAILED = "render_failed"
    BROWSER_DISABLED = "browser_disabled"


class IndicatorCandidate(BaseModel):
    """An observed CTI-shaped value. Presence is not a maliciousness verdict."""

    type: str
    value: str
    context: str = Field(default="", max_length=300)
    source_url: str


class ExtractedArticle(BaseModel):
    original_url: str
    canonical_url: str
    source_domain: str
    title: str = ""
    description: str = ""
    author: str = ""
    published_at: datetime | None = None
    updated_at: datetime | None = None
    article_text: str = ""
    headings: list[str] = Field(default_factory=list)
    relevant_links: list[str] = Field(default_factory=list)
    language: str | None = None
    paragraph_count: int = 0
    visible_text_chars: int = 0
    article_container: bool = False
    js_shell: bool = False
    duplicate_text_ratio: float = 0.0
    quality_score: float = 0.0
    content_hash: str = ""
    indicators: list[IndicatorCandidate] = Field(default_factory=list)
    injection_flagged: bool = False

    @field_validator("quality_score", "duplicate_text_ratio")
    @classmethod
    def _ratio(cls, value: float) -> float:
        return min(1.0, max(0.0, value))


class CrawlRecord(BaseModel):
    original_url: str
    canonical_url: str
    source_domain: str
    etag: str | None = None
    last_modified: str | None = None
    content_hash: str = ""
    first_seen_at: datetime
    last_checked_at: datetime
    last_changed_at: datetime | None = None
    http_status: int | None = None
    fetch_method: FetchMethod = FetchMethod.NONE
    extraction_quality: float = 0.0
    article_title: str = ""
    description: str = ""
    author: str = ""
    published_at: datetime | None = None
    updated_at: datetime | None = None
    extracted_text: str = ""
    headings: list[str] = Field(default_factory=list)
    relevant_links: list[str] = Field(default_factory=list)
    indicators: list[IndicatorCandidate] = Field(default_factory=list)
    source_raw_hash: str = ""
    failure_reason: CrawlFailureReason | None = None
    failure_detail: str | None = Field(default=None, max_length=300)


class RobotsRecord(BaseModel):
    host: str
    body: str = ""
    status_code: int | None = None
    fetched_at: datetime
    expires_at: datetime
    etag: str | None = None
    last_modified: str | None = None
    error: str | None = Field(default=None, max_length=300)


class CrawlMetrics(BaseModel):
    feed_api_items_discovered: int = 0
    feed_items_accepted: int = 0
    urls_normalized: int = 0
    invalid_urls: int = 0
    in_run_duplicates: int = 0
    historical_cache_hits: int = 0
    rejected_before_fetch: int = 0
    conditional_requests: int = 0
    not_modified: int = 0
    http_pages_fetched: int = 0
    browser_renders_attempted: int = 0
    browser_renders_succeeded: int = 0
    robots_denied: int = 0
    rate_limited: int = 0
    extraction_failures: int = 0
    content_changed: int = 0
    enriched_items: int = 0

    def add(self, other: CrawlMetrics) -> None:
        for name in type(self).model_fields:
            setattr(self, name, getattr(self, name) + getattr(other, name))


class CrawlBatchResult(BaseModel):
    items: list[Any] = Field(default_factory=list)
    metrics: CrawlMetrics = Field(default_factory=CrawlMetrics)


class FetchDecision(BaseModel):
    method: FetchMethod
    reason: str
    metadata_score: int = 0


class CrawlFetchResult(BaseModel):
    url: str
    final_url: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    not_modified: bool = False
    failure_reason: CrawlFailureReason | None = None
    failure_detail: str | None = Field(default=None, max_length=300)
    retries: int = 0


class RobotsDecision(BaseModel):
    allowed: bool
    crawl_delay: float = 0.0
    reason: str = ""
    record: RobotsRecord | None = None


class BrowserResult(BaseModel):
    url: str
    final_url: str | None = None
    html: str = ""
    failure_reason: CrawlFailureReason | None = None
    failure_detail: str | None = Field(default=None, max_length=300)

