"""UK National Cyber Security Centre (NCSC) feed adapter.

NCSC exposes several RSS 2.0 feeds under ``https://www.ncsc.gov.uk/api/1/services/v1/``
(``all-rss-feed.xml``, ``news-rss-feed.xml``, ``report-rss-feed.xml`` ...). Items carry a
short description, a UTC ``pubDate`` and a permalink whose first path segment identifies the
publication type (``/news/``, ``/blogs/``, ``/report/``, ``/guidance/``, ``/collection/``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from arkham.security.prompt_injection import sanitize_text
from arkham.sources.cert_eu import FULL_TEXT_MAX, exploitation_hint, extract_cve_ids
from arkham.sources.rss import TITLE_MAX, RssAdapter

PUBLISHER = "NCSC"

_KIND_BY_SEGMENT = {
    "news": "news",
    "report": "report",
    "reports": "report",
    "guidance": "guidance",
    "blog": "blog",
    "blogs": "blog",
    "blog-post": "blog",
    "collection": "collection",
    "collections": "collection",
}


def ncsc_kind(url: str) -> str:
    """Classify an NCSC URL by its first path segment.

    Returns one of ``"news"``, ``"report"``, ``"guidance"``, ``"blog"``, ``"collection"`` or
    ``"other"``.
    """
    path = urlsplit((url or "").strip()).path
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return "other"
    return _KIND_BY_SEGMENT.get(segments[0].lower(), "other")


class NcscAdapter(RssAdapter):
    """UK NCSC RSS adapter (Tier 1)."""

    def extra_fields(self, entry: Any) -> dict[str, Any]:
        """Publication kind, alert flag, CVE ids and exploitation hint."""
        title = sanitize_text(entry.get("title"), TITLE_MAX)
        summary = sanitize_text(entry.get("summary") or entry.get("description") or "", FULL_TEXT_MAX)
        link = (entry.get("link") or "").strip()
        return {
            "publisher": self.source.publisher or PUBLISHER,
            "ncsc_kind": ncsc_kind(link),
            "ncsc_alert": title.lower().startswith("alert:"),
            "cve_ids": extract_cve_ids(title, summary),
            "exploitation_hint": exploitation_hint(title, summary),
        }
