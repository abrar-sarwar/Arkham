"""Evidence-preserving deterministic enrichment and relevance tagging."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime, timedelta
from typing import Any

from arkham.models import CyberEvent, EventType, ExploitationStatus, KevStatus
from arkham.security.prompt_injection import sanitize_text
from arkham.security.urls import UrlValidationError, canonicalize_url, validate_public_url
from arkham.sources.cisa import extract_note_urls

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d{1,6}$", re.IGNORECASE)
_SECURITY_TERMS = (
    "cyber",
    "security",
    "vulnerab",
    "exploit",
    "malware",
    "ransomware",
    "phishing",
    "breach",
    "hack",
    "threat",
    "cve-",
    "zero-day",
    "botnet",
    "espionage",
)


def _append(values: list[str], additions: list[str], *, limit: int = 30) -> None:
    known = {value.casefold() for value in values}
    for value in additions:
        clean = sanitize_text(str(value), 120)
        if clean and clean.casefold() not in known:
            values.append(clean)
            known.add(clean.casefold())
        if len(values) >= limit:
            return


def _day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _tag(event: CyberEvent, name: str) -> None:
    if name not in event.keywords:
        event.keywords.append(name)


def _tag_text(event: CyberEvent) -> None:
    text = " ".join((event.title, event.summary, *event.sectors)).casefold()
    if "ransomware" in text:
        _tag(event, "tag:ransomware")
    if any(term in text for term in ("state-backed", "state sponsored", "nation-state", "espionage")):
        _tag(event, "tag:state-backed")
    if "supply chain" in text or "supply-chain" in text:
        _tag(event, "tag:supply-chain")
    if any(term in text for term in ("critical infrastructure", "energy sector", "water utility")):
        _tag(event, "tag:critical-infrastructure")


def enrich_events(
    events: list[CyberEvent],
    kev_catalog: Mapping[str, dict[str, Any]] | None,
    now: datetime,
) -> list[CyberEvent]:
    """Apply KEV and text-derived tags using only retrieved structured evidence."""
    catalog = kev_catalog or {}
    for event in events:
        for cve in event.cves:
            if not _CVE_RE.match(cve):
                continue
            entry = catalog.get(cve) or catalog.get(cve.upper())
            if not isinstance(entry, dict):
                continue
            added = _day(entry.get("dateAdded"))
            event.kev_date_added = added
            event.kev_status = (
                KevStatus.NEWLY_ADDED
                if added is not None and now.date() - added <= timedelta(days=1)
                else KevStatus.LISTED
            )
            event.exploitation_status = max(
                event.exploitation_status,
                ExploitationStatus.ACTIVE,
                key=lambda value: value.rank,
            )
            event.exploitation_evidence = "Listed in CISA Known Exploited Vulnerabilities catalog"
            event.event_type = EventType.EXPLOITATION
            event.kev_ransomware_use = sanitize_text(str(entry.get("knownRansomwareCampaignUse") or ""), 40) or None
            cwes = [str(value).upper() for value in entry.get("cwes") or [] if _CWE_RE.match(str(value))]
            _append(event.cwes, cwes)
            vendor = sanitize_text(str(entry.get("vendorProject") or ""), 80)
            product = sanitize_text(str(entry.get("product") or ""), 100)
            product_label = product if vendor and product.casefold().startswith(vendor.casefold()) else " ".join(
                part for part in (vendor, product) if part
            )
            if product_label:
                _append(event.products, [product_label])
            references = extract_note_urls(entry.get("notes"))
            if references:
                try:
                    event.primary_source_url = canonicalize_url(validate_public_url(references[0]))
                except UrlValidationError:
                    pass
                _append(event.referenced_urls, references)
            break
        _tag_text(event)
    return events


def is_security_relevant(event: CyberEvent) -> bool:
    """Conservative topic gate for generic news feeds."""
    if event.event_type is not EventType.OTHER or event.cves:
        return True
    text = f"{event.title} {event.summary}".casefold()
    relevant = any(term in text for term in _SECURITY_TERMS)
    if not relevant:
        _tag(event, "tag:off-topic")
    return relevant
