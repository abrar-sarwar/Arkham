"""Convert bounded source records into the frozen :class:`CyberEvent` contract."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from arkham.models import (
    Attribution,
    ClaimFlag,
    Confidence,
    CyberEvent,
    EventType,
    ExploitationStatus,
    KevStatus,
    RawItem,
    SourceRef,
    sha256_hex,
)
from arkham.security.prompt_injection import sanitize_for_model, sanitize_text
from arkham.security.urls import UrlValidationError, canonicalize_url, validate_public_url

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d{1,6}\b", re.IGNORECASE)
_ACTOR_RE = re.compile(r"\b(?:APT\d{1,3}|UNC\d{3,5}|TA\d{3,5})\b", re.IGNORECASE)


def _unique_text(values: Any, *, limit: int = 25, max_len: int = 120) -> list[str]:
    if not isinstance(values, list | tuple | set):
        return []
    result: list[str] = []
    for value in values:
        clean = sanitize_text(str(value), max_len)
        if clean and clean.casefold() not in {item.casefold() for item in result}:
            result.append(clean)
        if len(result) >= limit:
            break
    return result


def _ids(pattern: re.Pattern[str], explicit: Any, *texts: str) -> list[str]:
    values = _unique_text(explicit, limit=50, max_len=40)
    for text in texts:
        values.extend(pattern.findall(text or ""))
    result: list[str] = []
    for value in values:
        match = pattern.fullmatch(value.strip())
        if match:
            normalized = match.group(0).upper()
            if normalized not in result:
                result.append(normalized)
    return result


def _urls(values: Any) -> list[str]:
    if not isinstance(values, list | tuple | set):
        return []
    result: list[str] = []
    for value in values:
        try:
            clean = canonicalize_url(validate_public_url(str(value)))
        except (UrlValidationError, ValueError):
            continue
        if clean not in result:
            result.append(clean)
    return result[:30]


def _event_type(item: RawItem, text: str, cves: list[str], exploitation: ExploitationStatus) -> EventType:
    lower = text.casefold()
    if exploitation in {ExploitationStatus.ACTIVE, ExploitationStatus.WIDESPREAD}:
        return EventType.EXPLOITATION
    if item.source_category.value == "vulnerability" or cves:
        return EventType.VULNERABILITY
    if item.source_category.value == "advisory":
        return EventType.ADVISORY
    if item.source_category.value == "threat_intel":
        return EventType.THREAT_ACTIVITY
    if item.source_category.value == "research":
        return EventType.RESEARCH
    if any(word in lower for word in ("ransomware", "data breach", "breach", "cyberattack", "disrupted", "incident")):
        return EventType.INCIDENT
    if any(word in lower for word in ("campaign", "malware", "espionage", "phishing", "threat actor", "apt")):
        return EventType.THREAT_ACTIVITY
    if any(word in lower for word in ("vulnerability", "zero-day", "exploit", "security flaw")):
        return EventType.VULNERABILITY
    return EventType.OTHER


def _exploitation(extra: dict[str, Any]) -> ExploitationStatus:
    hint = str(extra.get("exploitation_hint") or "").casefold()
    if hint in {"widespread", "mass"}:
        return ExploitationStatus.WIDESPREAD
    if hint == "active":
        return ExploitationStatus.ACTIVE
    if hint == "poc":
        return ExploitationStatus.POC_PUBLIC
    return ExploitationStatus.UNKNOWN


def _attribution(extra: dict[str, Any]) -> Attribution | None:
    raw = extra.get("attribution")
    if not isinstance(raw, dict):
        return None
    actor = sanitize_text(str(raw.get("actor") or ""), 100)
    attributed_by = sanitize_text(str(raw.get("attributed_by") or ""), 120)
    statement = sanitize_text(str(raw.get("statement") or ""), 240)
    if not actor or not attributed_by or not statement:
        return None
    try:
        confidence = Confidence(str(raw.get("confidence") or "UNVERIFIED").upper())
    except ValueError:
        confidence = Confidence.UNVERIFIED
    return Attribution(actor=actor, attributed_by=attributed_by, confidence=confidence, statement=statement)


def normalize_item(item: RawItem) -> CyberEvent:
    """Normalize one already-bounded source item without adding unsupported facts."""
    title_scan = sanitize_for_model(item.title, 300)
    summary_scan = sanitize_for_model(item.summary or item.content, 1500)
    title = title_scan.cleaned or "Untitled security item"
    summary = summary_scan.cleaned
    text = "\n".join((title, summary, sanitize_text(item.content, 6000)))
    extra = item.extra if isinstance(item.extra, dict) else {}

    cves = _ids(_CVE_RE, extra.get("cve_ids"), text)
    cwes = _ids(_CWE_RE, extra.get("cwes"), text)
    exploitation = _exploitation(extra)
    referenced = _urls(
        [
            *list(extra.get("references") or []),
            *list(extra.get("referenced_links") or []),
        ]
    )
    source_url = canonicalize_url(validate_public_url(item.url))
    primary_url = referenced[0] if referenced else None
    products = _unique_text(extra.get("products"), limit=15)
    actors = _unique_text(extra.get("actor_mentions") or extra.get("threat_actors"), limit=20)
    for actor in _ACTOR_RE.findall(text):
        normalized = actor.upper()
        if normalized not in actors:
            actors.append(normalized)

    kev = extra.get("kev") if isinstance(extra.get("kev"), dict) else None
    kev_date: date | None = None
    if kev and kev.get("date_added"):
        try:
            kev_date = date.fromisoformat(str(kev["date_added"]))
        except ValueError:
            kev_date = None
    kev_status = KevStatus.LISTED if kev else KevStatus.NOT_LISTED

    claim_flags: list[ClaimFlag] = []
    for value in _unique_text(extra.get("claim_flags"), limit=10, max_len=50):
        try:
            flag = ClaimFlag(value)
        except ValueError:
            continue
        if flag not in claim_flags:
            claim_flags.append(flag)

    event_type = _event_type(item, text, cves, exploitation)
    event_id = (
        sha256_hex("cve", cves[0].casefold())
        if len(cves) == 1
        else sha256_hex("url", source_url)
    )
    publisher = sanitize_text(str(extra.get("publisher") or item.source_name), 80)
    return CyberEvent(
        id=event_id,
        title=title,
        summary=summary,
        event_type=event_type,
        published_at=item.published_at,
        updated_at=item.updated_at,
        source_name=item.source_name,
        source_url=source_url,
        source_tier=item.source_tier,
        publisher=publisher,
        primary_source_url=primary_url,
        corroborating_sources=[
            SourceRef(
                source_id=item.source_id,
                source_name=item.source_name,
                source_tier=item.source_tier,
                url=source_url,
                title=title,
                published_at=item.published_at,
                publisher=publisher,
            )
        ],
        referenced_urls=referenced,
        countries=_unique_text(extra.get("countries")),
        regions=_unique_text(extra.get("regions")),
        sectors=_unique_text(extra.get("sectors")),
        organizations=_unique_text(extra.get("organizations")),
        products=products,
        threat_actors=actors,
        malware_families=_unique_text(extra.get("malware_families") or extra.get("malware")),
        cves=cves,
        cwes=cwes,
        cvss_score=float(extra["cvss_score"]) if isinstance(extra.get("cvss_score"), int | float) else None,
        cvss_severity=sanitize_text(str(extra.get("cvss_severity") or ""), 20) or None,
        kev_status=kev_status,
        kev_date_added=kev_date,
        kev_ransomware_use=sanitize_text(str((kev or {}).get("ransomware_use") or ""), 40) or None,
        exploitation_status=exploitation,
        exploitation_evidence=(
            sanitize_text(str(extra.get("exploitation_evidence") or ""), 300)
            or ("Source reports active exploitation" if exploitation is ExploitationStatus.ACTIVE else None)
        ),
        poc_public=exploitation is ExploitationStatus.POC_PUBLIC,
        zero_day=bool(extra.get("zero_day")),
        attribution=_attribution(extra),
        claim_flags=claim_flags,
        raw_hash=item.raw_hash,
        member_hashes=[item.raw_hash],
        injection_flagged=title_scan.flagged or summary_scan.flagged,
    )


def normalize_items(items: list[RawItem]) -> list[CyberEvent]:
    """Normalize source items independently; one malformed item does not poison peers."""
    events: list[CyberEvent] = []
    for item in items:
        try:
            events.append(normalize_item(item))
        except (ValueError, TypeError):
            continue
    return events
