"""Microsoft Security Response Center Update Guide RSS adapter."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

import feedparser

from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text
from arkham.sources.base import FetchContext
from arkham.sources.rss import RssAdapter

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_INFO_ONLY_RE = re.compile(
    r"\b(?:informational (?:change|update) only|acknowledg(?:e)?ment updated)\b",
    re.IGNORECASE,
)
_VULN_CLASSES: tuple[tuple[str, str], ...] = (
    ("Elevation of Privileges", "Elevation of Privilege"),
    ("Elevation of Privilege", "Elevation of Privilege"),
    ("Remote Code Execution", "Remote Code Execution"),
    ("Information Disclosure", "Information Disclosure"),
    ("Security Feature Bypass", "Security Feature Bypass"),
    ("Denial of Service", "Denial of Service"),
    ("Spoofing", "Spoofing"),
    ("Tampering", "Tampering"),
)
_ITEM_REVISION_RE = re.compile(
    rb"<item\b[^>]*\bRevision=[\"']([^\"']+)[\"'][^>]*>(.*?)</item\s*>",
    re.IGNORECASE | re.DOTALL,
)
_GUID_RE = re.compile(rb"<guid\b[^>]*>(.*?)</guid\s*>", re.IGNORECASE | re.DOTALL)


def _revision_label(value: str) -> str | None:
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError):
        return None
    rendered = format(number.normalize(), "f")
    return rendered if "." in rendered else rendered + ".0"


def revisions_in_order(body: bytes, *, limit: int) -> list[tuple[str, str]]:
    """Return ``(revision, guid)`` pairs in the same order as RSS items."""
    pairs: list[tuple[str, str]] = []
    for match in list(_ITEM_REVISION_RE.finditer(body))[: max(0, limit)]:
        revision = _revision_label(match.group(1).decode("ascii", errors="ignore"))
        guid_match = _GUID_RE.search(match.group(2))
        guid = guid_match.group(1).decode("utf-8", errors="replace").strip() if guid_match else ""
        if revision and guid:
            pairs.append((revision, guid))
    return pairs


def is_informational_only(summary: str) -> bool:
    """True for MSRC revisions that change metadata but add no security facts."""
    return bool(_INFO_ONLY_RE.search(sanitize_text(summary, 1000)))


def parse_msrc_title(title: str) -> tuple[list[str], list[str], str | None]:
    """Extract CVE ids, product label, and vulnerability class from an MSRC title."""
    clean = sanitize_text(title, 400)
    cves = list(dict.fromkeys(match.group(0).upper() for match in _CVE_RE.finditer(clean)))
    if not cves:
        return [], [], None

    first = _CVE_RE.search(clean)
    assert first is not None
    prefix = clean[: first.start()].strip(" :-")
    remainder = clean[first.end() :].strip(" :-")
    remainder = re.sub(r"\s+Vulnerability\s*$", "", remainder, flags=re.IGNORECASE).strip()

    products: list[str] = [prefix] if prefix else []
    vuln_class: str | None = None
    if not prefix:
        for phrase, normalized in _VULN_CLASSES:
            if remainder.lower().endswith(phrase.lower()):
                product = remainder[: -len(phrase)].strip()
                if product:
                    products = [product]
                vuln_class = normalized
                break
    return cves, products, vuln_class


class MsrcUpdateGuideAdapter(RssAdapter):
    """Keep substantive MSRC vulnerability publications and revision updates."""

    def parse(self, body: bytes, ctx: FetchContext) -> list[RawItem]:
        feed = feedparser.parse(body)
        if not feed.entries:
            if getattr(feed, "bozo", False):
                raise ValueError(f"feed parse error: {getattr(feed, 'bozo_exception', 'unknown')}")
            return []
        entries = feed.entries[: self.source.max_items]
        revisions = revisions_in_order(body, limit=self.source.max_items)
        revision_by_position = [revision for revision, _guid in revisions]
        items: list[RawItem] = []
        for index, entry in enumerate(entries):
            entry["arkham_revision"] = revision_by_position[index] if index < len(revision_by_position) else None
            item = self.entry_to_item(entry, ctx)
            if item is not None and self.accept(item, ctx):
                items.append(item)
        return items

    def entry_to_item(self, entry: Any, ctx: FetchContext) -> RawItem | None:
        raw_summary = entry.get("summary") or entry.get("description") or ""
        if is_informational_only(str(raw_summary)):
            return None
        item = super().entry_to_item(entry, ctx)
        if item is None:
            return None
        cves, products, vuln_class = parse_msrc_title(item.title)
        revision = entry.get("arkham_revision")
        categories = [sanitize_text(tag.get("term"), 60) for tag in entry.get("tags", []) if tag.get("term")]
        item.extra.update(
            {
                "publisher": "Microsoft",
                "revision": revision,
                "cve_ids": cves,
                "products": products,
                "vuln_class": vuln_class,
                "new_cve": revision == "1.0",
                "informational_only": False,
                "categories": categories[:15],
            }
        )
        return item
