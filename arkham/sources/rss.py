"""Generic RSS/Atom adapter. Most Tier-2/3 sources use it directly; several Tier-1 adapters subclass it."""

from __future__ import annotations

import logging
import time
from html.parser import HTMLParser
from typing import Any

import feedparser

from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text
from arkham.security.urls import UrlValidationError, validate_public_url
from arkham.sources.base import FetchContext, FetchResult, SourceAdapter, in_window, parse_datetime

log = logging.getLogger(__name__)

SUMMARY_MAX = 1500
CONTENT_MAX = 6000
TITLE_MAX = 300


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.links.append(value.strip())


def extract_links(raw_html: str | None, limit: int = 25) -> list[str]:
    """Return validated public https links referenced inside HTML content (used to find primary sources)."""
    if not raw_html or "href" not in raw_html:
        return []
    parser = _LinkExtractor()
    try:
        parser.feed(raw_html)
    except Exception:  # pragma: no cover - lenient parser
        return []
    out: list[str] = []
    for link in parser.links:
        try:
            u = validate_public_url(link)
        except UrlValidationError:
            continue
        if u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    return out


class RssAdapter(SourceAdapter):
    """Fetch a feed with conditional GET, parse with feedparser, emit window-filtered RawItems."""

    def fetch(self, ctx: FetchContext) -> FetchResult:
        started = time.monotonic()
        state = ctx.state
        try:
            resp = ctx.http.get(
                self.source.url,
                max_bytes=self.source.max_bytes,
                etag=state.etag if state else None,
                last_modified=state.last_modified if state else None,
                timeout_seconds=self.source.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - one broken feed must never abort the run
            return self._failure(exc, started)
        if resp.not_modified:
            result = self._not_modified(started)
            if state:
                result.new_state = self._new_state(state.etag, state.last_modified, ctx, status="NOT MODIFIED")
            return result
        try:
            items = self.parse(resp.body, ctx)
        except Exception as exc:  # noqa: BLE001
            return self._failure(exc, started)
        status = self._status(True, "OK", items=len(items), started=started)
        return FetchResult(items=items, status=status, new_state=self._new_state(resp.etag, resp.last_modified, ctx))

    # ------------------------------------------------------------------ parsing
    def parse(self, body: bytes, ctx: FetchContext) -> list[RawItem]:
        feed = feedparser.parse(body)
        if not feed.entries:
            if getattr(feed, "bozo", False):
                raise ValueError(f"feed parse error: {getattr(feed, 'bozo_exception', 'unknown')}")
            return []
        items: list[RawItem] = []
        for entry in feed.entries[: self.source.max_items]:
            try:
                item = self.entry_to_item(entry, ctx)
            except Exception as exc:  # noqa: BLE001 - skip a malformed entry, keep the rest
                log.debug("%s: skipping entry: %s", self.source.id, exc)
                continue
            if item is None:
                continue
            if not self.accept(item, ctx):
                continue
            items.append(item)
        return items

    def accept(self, item: RawItem, ctx: FetchContext) -> bool:
        """Window filter. Subclasses may loosen/tighten (e.g. missing dates)."""
        return in_window(item.effective_time, ctx, allow_missing=False)

    def entry_to_item(self, entry: Any, ctx: FetchContext) -> RawItem | None:
        title = sanitize_text(entry.get("title"), TITLE_MAX)
        link = (entry.get("link") or "").strip()
        if not title or not link:
            return None
        try:
            link = validate_public_url(link)
        except UrlValidationError:
            return None
        raw_summary = entry.get("summary") or entry.get("description") or ""
        raw_content = ""
        if entry.get("content"):
            raw_content = entry.content[0].get("value") or ""
        published = parse_datetime(entry.get("published") or entry.get("pubDate") or entry.get("created"))
        updated = parse_datetime(entry.get("updated"))
        if updated and published and updated < published:
            updated = None
        categories = [sanitize_text(t.get("term"), 60) for t in entry.get("tags", []) if t.get("term")]
        author = sanitize_text(entry.get("author"), 120)
        external_id = (entry.get("id") or entry.get("guid") or link).strip()
        extra: dict[str, Any] = {
            "categories": categories[:15],
            "author": author,
            "referenced_links": extract_links(raw_summary + " " + raw_content),
            "publisher": self.source.publisher or self.source.name,
        }
        extra.update(self.extra_fields(entry))
        return self.base_item(
            external_id=external_id[:500],
            title=title,
            url=link,
            summary=sanitize_text(raw_summary, SUMMARY_MAX),
            content=sanitize_text(raw_content, CONTENT_MAX) if raw_content else "",
            published_at=published,
            updated_at=updated,
            fetched_at=ctx.now,
            extra=extra,
        )

    def extra_fields(self, entry: Any) -> dict[str, Any]:
        """Hook for subclasses to add structured fields."""
        return {}
