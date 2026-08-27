"""Google Threat Intelligence (GTIG / Mandiant) blog feed adapter.

The feed at ``https://cloud.google.com/blog/topics/threat-intelligence/rss`` embeds the full
HTML article in ``<description>``; there is no separate ``<content:encoded>``. Articles open
with a ``"Written by: ..."`` byline and frequently name threat clusters (``UNC1234``,
``APT29``) and CVE identifiers, which are surfaced as structured ``extra`` fields.
"""

from __future__ import annotations

import re
from typing import Any

from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text, truncate
from arkham.sources.base import FetchContext
from arkham.sources.cert_eu import FULL_TEXT_MAX, exploitation_hint, extract_cve_ids
from arkham.sources.rss import CONTENT_MAX, SUMMARY_MAX, TITLE_MAX, RssAdapter

PUBLISHER = "Google"
MAX_AUTHORS = 12
MAX_ACTORS = 25

_BYLINE_RE = re.compile(r"^[ \t]*Written by:?[ \t]*(?P<names>.+?)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_AUTHOR_SPLIT_RE = re.compile(r"\s*,\s*|\s+and\s+|\s*&\s*")
_ACTOR_RE = re.compile(r"\b(?:UNC\d{3,5}|APT\d{1,3})\b")
_ARTICLE_TEXT_KEY = "arkham_article_text"


def parse_authors(text: str | None) -> list[str]:
    """Return the author names from a ``"Written by: A, B and C"`` byline (empty when absent)."""
    match = _BYLINE_RE.search(text or "")
    if not match:
        return []
    names = [name.strip(" .") for name in _AUTHOR_SPLIT_RE.split(match.group("names"))]
    return [name for name in names if name][:MAX_AUTHORS]


def strip_byline(text: str) -> str:
    """Remove the first ``"Written by"`` line so summaries start with the article body."""
    match = _BYLINE_RE.search(text)
    if not match:
        return text
    return (text[: match.start()] + text[match.end() :]).strip()


def actor_mentions(text: str) -> list[str]:
    """Unique ``UNCnnnn`` / ``APTnn`` cluster names in order of first appearance."""
    found: list[str] = []
    for actor in _ACTOR_RE.findall(text):
        if actor not in found:
            found.append(actor)
        if len(found) >= MAX_ACTORS:
            break
    return found


class GoogleThreatIntelAdapter(RssAdapter):
    """Google Threat Intelligence blog adapter (Tier 2 research)."""

    def entry_to_item(self, entry: Any, ctx: FetchContext) -> RawItem | None:
        """Build the base item, then replace summary/content with the byline-free article text."""
        item = super().entry_to_item(entry, ctx)
        if item is None:
            return None
        text = strip_byline(self._article_text(entry))
        if text:
            item.summary = truncate(text, SUMMARY_MAX)
            item.content = truncate(text, CONTENT_MAX)
        return item

    def extra_fields(self, entry: Any) -> dict[str, Any]:
        """Authors, CVE ids, exploitation hint and threat-cluster mentions from the article."""
        title = sanitize_text(entry.get("title"), TITLE_MAX)
        text = self._article_text(entry)
        full = f"{title}\n{text}"
        return {
            "publisher": self.source.publisher or PUBLISHER,
            "authors": parse_authors(text),
            "cve_ids": extract_cve_ids(full),
            "exploitation_hint": exploitation_hint(full),
            "actor_mentions": actor_mentions(full),
        }

    @staticmethod
    def _article_text(entry: Any) -> str:
        """Sanitized plain text of the whole article (description plus any content block), cached per entry."""
        cached = entry.get(_ARTICLE_TEXT_KEY)
        if cached is not None:
            return cached
        raw = entry.get("summary") or entry.get("description") or ""
        if entry.get("content"):
            raw = f"{raw}\n{entry.content[0].get('value') or ''}"
        text = sanitize_text(raw, FULL_TEXT_MAX)
        entry[_ARTICLE_TEXT_KEY] = text
        return text
