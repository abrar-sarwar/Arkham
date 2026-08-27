"""CERT/CC Vulnerability Notes Atom adapter.

The CERT/CC feed embeds the whole note in each Atom entry.  Keep the useful
overview and bounded note text, while dropping navigation/footer boilerplate.
"""

from __future__ import annotations

import re
from typing import Any

from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text, truncate
from arkham.sources.base import FetchContext
from arkham.sources.cert_eu import exploitation_hint, extract_cve_ids
from arkham.sources.rss import CONTENT_MAX, SUMMARY_MAX, RssAdapter

_VU_RE = re.compile(r"\bVU#\d{6}\b", re.IGNORECASE)
_DATE_PUBLIC_RE = re.compile(r"\bDate Public:\s*(\d{4}-\d{2}-\d{2})\b", re.IGNORECASE)
_REVISION_RE = re.compile(r"\bDocument Revision:\s*([0-9.]+)\b", re.IGNORECASE)
_SECTION_HEADING_RE = re.compile(
    r"^(Overview|Description|Impact|Solution|Acknowledgements?|Vendor Information|References?|Other Information)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_BOILERPLATE_RE = re.compile(
    r"\n*About vulnerability notes\b.*$|\n*Contact us about this vulnerability\b.*$",
    re.IGNORECASE | re.DOTALL,
)


def vu_id_from_title(title: str) -> str | None:
    """Return a normalized ``VU#NNNNNN`` identifier from a note title."""
    match = _VU_RE.search(title or "")
    return match.group(0).upper() if match else None


def overview_section(text: str) -> str:
    """Extract the text between the Overview heading and the next note section."""
    if not text:
        return ""
    matches = list(_SECTION_HEADING_RE.finditer(text))
    overview_index = next((index for index, match in enumerate(matches) if match.group(1).lower() == "overview"), None)
    if overview_index is None:
        return ""
    start = matches[overview_index].end()
    end = matches[overview_index + 1].start() if overview_index + 1 < len(matches) else len(text)
    return text[start:end].strip()


def strip_boilerplate(text: str) -> str:
    """Remove CERT/CC footer/navigation text from sanitized note content."""
    return _BOILERPLATE_RE.sub("", text or "").strip()


def _entry_html(entry: Any) -> tuple[str, str]:
    summary = entry.get("summary") or entry.get("description") or ""
    content = ""
    if entry.get("content"):
        content = entry.content[0].get("value") or ""
    return str(summary), str(content or summary)


class CertCcAdapter(RssAdapter):
    """Parse CERT/CC notes into bounded, structured :class:`RawItem` records."""

    def entry_to_item(self, entry: Any, ctx: FetchContext) -> RawItem | None:
        item = super().entry_to_item(entry, ctx)
        if item is None:
            return None
        raw_summary, raw_content = _entry_html(entry)
        summary_text = sanitize_text(raw_summary, 50_000)
        content_text = strip_boilerplate(sanitize_text(raw_content, 50_000))
        # Vulnerability descriptions legitimately quote payloads such as
        # ``<animate onrepeat=...>``.  They are evidence text, not markup, but
        # retaining tag delimiters would blur the trust boundary downstream.
        content_text = sanitize_text(content_text.replace("<", " ").replace(">", " "), 50_000)
        overview = overview_section(summary_text) or overview_section(content_text)
        item.summary = truncate(overview or item.summary, SUMMARY_MAX)
        item.content = truncate(content_text, CONTENT_MAX)

        searchable = "\n".join((item.title, summary_text, content_text))
        date_match = _DATE_PUBLIC_RE.search(content_text)
        revision_match = _REVISION_RE.search(content_text)
        item.extra.update(
            {
                "publisher": "CERT/CC",
                "vu_id": vu_id_from_title(item.title),
                "cve_ids": extract_cve_ids(searchable),
                "exploitation_hint": exploitation_hint(searchable),
                "date_public": date_match.group(1) if date_match else None,
                "document_revision": revision_match.group(1) if revision_match else None,
            }
        )
        return item
