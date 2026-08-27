"""CISA Known Exploited Vulnerabilities (KEV) catalog adapter.

The KEV catalog is one JSON document (about 1.7 MB) listing every vulnerability CISA has confirmed
as exploited in the wild. This adapter does two things with it:

1. Emits a :class:`~arkham.models.RawItem` for each vulnerability *added* inside the collection
   window. The comparison is done at **date** granularity because CISA publishes around 17:00 UTC
   while window boundaries fall at delivery time; an entry dated today must be picked up even when
   the window opened after midnight.
2. Exposes the whole catalog for enrichment of every other source's items through
   ``ctx.extra["kev_catalog"]`` (``cveID -> entry``) plus ``ctx.extra["kev_catalog_version"]``,
   and the module-level :func:`kev_lookup` helper.

Because the full catalog is needed on every run for enrichment, the adapter deliberately **never
sends conditional-GET headers** (``If-None-Match`` / ``If-Modified-Since``): a ``304 Not Modified``
would leave the catalog empty for the rest of the pipeline. The ETag/Last-Modified the server
returns are still recorded in the new :class:`~arkham.models.SourceState` for diagnostics only.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text
from arkham.security.urls import UrlValidationError, validate_public_url
from arkham.sources.base import FetchContext, FetchResult, Source, SourceAdapter

log = logging.getLogger(__name__)

KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
PUBLISHER = "CISA"
TITLE_MAX = 300
SUMMARY_MAX = 1500
FIELD_MAX = 600
MAX_REFERENCES = 15

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_NOTE_SPLIT_RE = re.compile(r"[\s;]+")


# ------------------------------------------------------------------ module-level helpers


def extract_note_urls(notes: str | None, limit: int = MAX_REFERENCES) -> list[str]:
    """Return the unique public https URLs mentioned in a KEV ``notes`` string.

    Notes are free text such as ``"https://vendor.example/advisory ; BOD 26-04: https://www.cisa.gov/..."``.
    Tokens are split on whitespace and semicolons, trailing sentence punctuation is dropped, and only
    tokens accepted by :func:`arkham.security.urls.validate_public_url` (https, public host) survive.
    """
    if not notes:
        return []
    urls: list[str] = []
    for token in _NOTE_SPLIT_RE.split(str(notes)):
        candidate = token.strip().rstrip(".,")
        if not candidate:
            continue
        try:
            url = validate_public_url(candidate)
        except UrlValidationError:
            continue
        if url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def build_kev_catalog(entries: Iterable[Any]) -> dict[str, dict[str, Any]]:
    """Index raw catalog entries by upper-case CVE id. Entries without a well-formed ``cveID`` are skipped."""
    catalog: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            log.debug("KEV: skipping non-object catalog entry")
            continue
        cve = str(entry.get("cveID") or "").strip().upper()
        if not _CVE_RE.match(cve):
            log.debug("KEV: skipping entry with malformed cveID %r", cve[:40])
            continue
        catalog[cve] = entry
    return catalog


def kev_lookup(catalog: Mapping[str, dict[str, Any]] | None, cve_id: str | None) -> dict[str, Any] | None:
    """Case-insensitive lookup of ``cve_id`` in a KEV catalog (as built by :func:`build_kev_catalog`).

    Returns the raw catalog entry (``vendorProject``, ``product``, ``dateAdded``, ``dueDate``,
    ``knownRansomwareCampaignUse`` ...) or ``None`` when the CVE is not listed.
    """
    if not catalog or not cve_id:
        return None
    key = cve_id.strip().upper()
    if not key:
        return None
    hit = catalog.get(key)
    if hit is not None:
        return hit
    for candidate, entry in catalog.items():
        if candidate.strip().upper() == key:
            return entry
    return None


def _parse_day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value).strip())
    except (TypeError, ValueError):
        return None


def _clean(value: Any, max_len: int = FIELD_MAX) -> str:
    return sanitize_text(str(value), max_len) if value else ""


# ------------------------------------------------------------------ adapter


class CisaKevAdapter(SourceAdapter):
    """Fetch the KEV catalog, expose it for enrichment, and emit items for entries added in the window."""

    def __init__(self, source: Source) -> None:
        super().__init__(source)
        self.catalog: dict[str, dict[str, Any]] = {}
        self.catalog_version: str | None = None

    def fetch(self, ctx: FetchContext) -> FetchResult:
        """Unconditionally GET the catalog (see module docstring), parse it, and report status."""
        started = time.monotonic()
        try:
            resp = ctx.http.get(
                self.source.url,
                max_bytes=self.source.max_bytes,
                timeout_seconds=self.source.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - one broken source must never abort the run
            return self._failure(exc, started)
        if resp.not_modified:
            # Cannot happen because no validators are sent, but keep the contract honest.
            log.warning("%s: unexpected 304 without conditional headers; catalog unavailable", self.source.id)
            return self._not_modified(started)
        try:
            items = self.parse(resp.body, ctx)
        except Exception as exc:  # noqa: BLE001
            return self._failure(exc, started)
        status = self._status(True, "OK", items=len(items), started=started)
        return FetchResult(items=items, status=status, new_state=self._new_state(resp.etag, resp.last_modified, ctx))

    # ------------------------------------------------------------------ parsing

    def parse(self, body: bytes, ctx: FetchContext) -> list[RawItem]:
        """Decode the catalog JSON, publish it on ``ctx.extra``, and build the window-filtered items."""
        data = json.loads(body)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("KEV catalog JSON is missing the 'vulnerabilities' list")
        self.catalog = build_kev_catalog(data["vulnerabilities"])
        version = data.get("catalogVersion")
        self.catalog_version = _clean(version, 40) or None
        ctx.extra["kev_catalog"] = self.catalog
        ctx.extra["kev_catalog_version"] = self.catalog_version
        log.info("%s: catalog %s loaded with %d entries", self.source.id, self.catalog_version, len(self.catalog))

        start_day = ctx.window_start.astimezone(timezone.utc).date()
        end_day = ctx.window_end.astimezone(timezone.utc).date()
        selected: list[tuple[date, dict[str, Any]]] = []
        for cve, entry in self.catalog.items():
            added = _parse_day(entry.get("dateAdded"))
            if added is None:
                log.debug("%s: skipping %s with unparseable dateAdded %r", self.source.id, cve, entry.get("dateAdded"))
                continue
            if start_day <= added <= end_day:
                selected.append((added, entry))
        selected.sort(key=lambda pair: pair[0], reverse=True)
        if len(selected) > self.source.max_items:
            log.info(
                "%s: %d entries added in window, keeping newest %d (dropped %d)",
                self.source.id,
                len(selected),
                self.source.max_items,
                len(selected) - self.source.max_items,
            )
            selected = selected[: self.source.max_items]

        items: list[RawItem] = []
        for added, entry in selected:
            try:
                items.append(self.entry_to_item(entry, added, ctx))
            except Exception as exc:  # noqa: BLE001 - skip a malformed entry, keep the rest
                log.debug("%s: skipping entry %s: %s", self.source.id, entry.get("cveID"), exc)
        return items

    def entry_to_item(self, entry: dict[str, Any], added: date, ctx: FetchContext) -> RawItem:
        """Convert one catalog entry into a :class:`RawItem` (all text passed through ``sanitize_text``)."""
        cve = str(entry["cveID"]).strip().upper()
        vendor = _clean(entry.get("vendorProject"), 120)
        product = _clean(entry.get("product"), 160)
        name = _clean(entry.get("vulnerabilityName"), 240)
        description = _clean(entry.get("shortDescription"), SUMMARY_MAX)
        action = _clean(entry.get("requiredAction"), FIELD_MAX)
        ransomware = _clean(entry.get("knownRansomwareCampaignUse"), 40) or "Unknown"
        due = _parse_day(entry.get("dueDate"))

        summary_parts = [description]
        if action:
            summary_parts.append(f"Required action: {action}")
        if ransomware == "Known":
            summary_parts.append("Known ransomware campaign use: Known.")
        summary = sanitize_text(" ".join(part for part in summary_parts if part), SUMMARY_MAX)
        title = sanitize_text(f"{vendor} {product}: {name} ({cve}) added to CISA KEV", TITLE_MAX)

        cwes: list[str] = []
        for raw_cwe in entry.get("cwes") or []:
            cwe = str(raw_cwe).strip().upper()
            if _CWE_RE.match(cwe) and cwe not in cwes:
                cwes.append(cwe)
        product_label = f"{vendor} {product}".strip()

        extra: dict[str, Any] = {
            "publisher": PUBLISHER,
            "cve_ids": [cve],
            "cwes": cwes,
            "kev": {
                "date_added": added.isoformat(),
                "due_date": due.isoformat() if due else None,
                "ransomware_use": ransomware,
                "required_action": action,
                "vendor": vendor,
                "product": product,
                "vulnerability_name": name,
            },
            "products": [product_label] if product_label else [],
            "references": extract_note_urls(entry.get("notes")),
            "exploitation_hint": "active",
        }
        return self.base_item(
            external_id=cve,
            title=title,
            url=KEV_CATALOG_URL,
            summary=summary,
            published_at=datetime(added.year, added.month, added.day, tzinfo=timezone.utc),
            updated_at=None,
            fetched_at=ctx.now,
            extra=extra,
        )
