"""Confidence, material-update memory, attribution safety, and selection."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from arkham.models import (
    ClaimFlag,
    Confidence,
    CyberEvent,
    EventType,
    ExploitationStatus,
    KevStatus,
    SourceTier,
    StoredEvent,
    sha256_hex,
)

_VULNERABILITY_TYPES = {EventType.VULNERABILITY, EventType.EXPLOITATION, EventType.ADVISORY}
_VICTIM_CONFIRMATION = ("company confirmed", "victim confirmed", "confirmed the incident", "regulatory filing")


def _publisher_names(event: CyberEvent) -> set[str]:
    values = {event.publisher or event.source_name}
    values.update(ref.publisher or ref.source_name for ref in event.corroborating_sources)
    return {value.strip().casefold() for value in values if value.strip()}


def _tiers(event: CyberEvent) -> set[SourceTier]:
    return {event.source_tier, *(ref.source_tier for ref in event.corroborating_sources)}


def _append_unique(values: list, value: object) -> None:
    if value not in values:
        values.append(value)


def assign_confidence(event: CyberEvent) -> CyberEvent:
    """Assign the event confidence ladder without strengthening source claims."""
    reasons: list[str] = []
    tiers = _tiers(event)
    publishers = _publisher_names(event)
    tier1 = SourceTier.PRIMARY in tiers
    tier2 = SourceTier.RESEARCH in tiers
    journalism_only = tiers == {SourceTier.JOURNALISM}

    ransomware_unconfirmed = ClaimFlag.RANSOMWARE_CLAIM in event.claim_flags and not tier1
    if ransomware_unconfirmed:
        confirmed_by_victim = any(phrase in event.summary.casefold() for phrase in _VICTIM_CONFIRMATION)
        ransomware_unconfirmed = not (confirmed_by_victim and tier2)

    if ransomware_unconfirmed:
        confidence = Confidence.UNVERIFIED
        reasons.append("claimed by criminal group; independently unconfirmed")
    elif tier1:
        confidence = Confidence.CONFIRMED if event.event_type in _VULNERABILITY_TYPES else Confidence.HIGH
        reasons.append(f"tier-1 source: {event.publisher or event.source_name}")
    elif tier2:
        confidence = Confidence.HIGH if len(publishers) >= 2 else Confidence.MODERATE
        reasons.append("research source corroborated" if len(publishers) >= 2 else "single tier-2 research source")
    elif len(publishers) >= 3:
        confidence = Confidence.MODERATE
        reasons.append("three independent journalism publishers")
    else:
        confidence = Confidence.LOW
        reasons.append("journalism-only reporting")

    if ClaimFlag.REPORTED_NOT_CONFIRMED in event.claim_flags and confidence.rank > Confidence.MODERATE.rank:
        confidence = Confidence.MODERATE
        reasons.append("reported but not confirmed; capped at MODERATE")
    if ClaimFlag.STATISTIC_UNVERIFIED in event.claim_flags:
        reasons.append("contains an unverified statistic")

    if event.attribution is not None and journalism_only:
        event.attribution.confidence = Confidence.LOW
        _append_unique(event.claim_flags, ClaimFlag.ATTRIBUTION_SUSPECTED)
        if confidence.rank > Confidence.LOW.rank:
            confidence = Confidence.LOW
        reasons.append("attribution appears only in journalism; capped at LOW")

    event.confidence = confidence
    event.confidence_reasons = reasons
    return event


def safe_attribution_sentence(event: CyberEvent) -> str | None:
    """Render attribution only from structured fields and calibrated confidence."""
    attribution = event.attribution
    if attribution is None:
        return None
    actor = " ".join(attribution.actor.split())
    source = " ".join(attribution.attributed_by.split())
    verb = {
        Confidence.CONFIRMED: "confirms",
        Confidence.HIGH: "assesses with high confidence",
        Confidence.MODERATE: "assesses",
        Confidence.LOW: "suspects",
        Confidence.UNVERIFIED: "reports",
    }[attribution.confidence]
    return f"{source} {verb} the activity is associated with {actor} ({attribution.confidence.label})."


def _cvss_band(score: float | None) -> int | None:
    return math.floor(score) if score is not None else None


def _publisher_band(event: CyberEvent) -> int:
    return min(3, len(_publisher_names(event)))


def compute_fingerprint(event: CyberEvent) -> str:
    """Hash material state only; prose rewrites do not create false updates."""
    attribution = event.attribution
    parts = [
        event.kev_status.value,
        event.exploitation_status.value,
        str(_cvss_band(event.cvss_score)),
        str(bool(event.poc_public or event.exploitation_status is ExploitationStatus.POC_PUBLIC)),
        str(event.zero_day),
        str(_publisher_band(event)),
        event.confidence.value,
        "|".join(
            (
                attribution.actor.casefold(),
                attribution.attributed_by.casefold(),
                attribution.confidence.value,
            )
        )
        if attribution
        else "",
    ]
    return sha256_hex(*parts)


def describe_material_update(previous: StoredEvent, current: CyberEvent) -> str | None:
    """Describe only changes that alter defensive understanding or confidence."""
    before = previous.event
    updates: list[str] = []
    if before.kev_status is KevStatus.NOT_LISTED and current.kev_status in {KevStatus.LISTED, KevStatus.NEWLY_ADDED}:
        updates.append("added to CISA KEV")
    if current.exploitation_status.rank > before.exploitation_status.rank:
        updates.append(
            f"exploitation escalated ({before.exploitation_status.value} -> {current.exploitation_status.value})"
        )
    if not (before.poc_public or before.exploitation_status is ExploitationStatus.POC_PUBLIC) and (
        current.poc_public or current.exploitation_status is ExploitationStatus.POC_PUBLIC
    ):
        updates.append("PoC now public")
    if not before.zero_day and current.zero_day:
        updates.append("now zero-day")
    old_band = _cvss_band(before.cvss_score)
    new_band = _cvss_band(current.cvss_score)
    if before.cvss_score is None and current.cvss_score is not None:
        updates.append(f"CVSS assigned {current.cvss_score:g}")
    elif old_band is not None and new_band is not None and new_band > old_band:
        updates.append(f"CVSS raised to {current.cvss_score:g}")
    old_publishers = _publisher_band(before)
    new_publishers = _publisher_band(current)
    if new_publishers > old_publishers:
        updates.append(f"corroboration grew to {new_publishers} publishers")
    old_attr = before.attribution
    new_attr = current.attribution
    if old_attr is None and new_attr is not None:
        updates.append(f"attribution added: {new_attr.actor} (per {new_attr.attributed_by})")
    elif old_attr is not None and new_attr is not None and old_attr.actor.casefold() != new_attr.actor.casefold():
        updates.append(f"attribution changed: {old_attr.actor} -> {new_attr.actor}")
    if current.confidence.rank > before.confidence.rank:
        updates.append(f"confidence raised to {current.confidence.value}")
    return "; ".join(updates) or None


def reconcile_with_history(event: CyberEvent, previous: StoredEvent | None, *, now: datetime) -> CyberEvent:
    """Attach persistent first/last-seen and meaningful-update state to an event."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    event.last_seen = now
    event.material_update = None
    if previous is None:
        event.first_seen = now
        event.previously_briefed = False
        event.last_briefed_at = None
    else:
        event.first_seen = previous.first_seen
        event.previously_briefed = previous.times_briefed > 0
        event.last_briefed_at = previous.last_briefed_at
        event.material_update = describe_material_update(previous, event)
    event.fingerprint = compute_fingerprint(event)
    return event


@dataclass
class SelectionResult:
    candidates: list[CyberEvent] = field(default_factory=list)
    selected: list[CyberEvent] = field(default_factory=list)
    suppressed_briefed: int = 0
    below_threshold: int = 0
    off_topic: int = 0


def _event_time(event: CyberEvent) -> float:
    values = [value for value in (event.published_at, event.updated_at) if value is not None]
    return max(values).timestamp() if values else 0.0


def _tier3_only(event: CyberEvent) -> bool:
    return _tiers(event) == {SourceTier.JOURNALISM}


def select_events(
    events: list[CyberEvent],
    *,
    max_events: int,
    min_priority: float,
    now: datetime,
) -> SelectionResult:
    """Threshold, sort, and select with restrained source/type diversity caps."""
    del now  # scores already include recency; retained for the frozen runner signature
    result = SelectionResult()
    eligible: list[CyberEvent] = []
    for event in events:
        if "tag:off-topic" in {keyword.casefold() for keyword in event.keywords}:
            result.off_topic += 1
        elif event.previously_briefed and not event.material_update:
            result.suppressed_briefed += 1
        elif event.final_priority_score < min_priority:
            result.below_threshold += 1
        else:
            eligible.append(event)
    result.candidates = sorted(eligible, key=lambda event: (-event.final_priority_score, -_event_time(event), event.id))
    if max_events <= 0:
        return result

    vuln_cap = max(3, math.ceil(max_events * 0.6))
    has_non_vuln = any(event.event_type not in {EventType.VULNERABILITY, EventType.EXPLOITATION} for event in result.candidates)
    selected: list[CyberEvent] = []
    deferred: list[CyberEvent] = []
    vuln_count = 0
    tier3_publishers: dict[str, int] = {}

    for event in result.candidates:
        if len(selected) >= max_events:
            break
        publisher_key = (event.publisher or event.source_name).casefold()
        if _tier3_only(event) and tier3_publishers.get(publisher_key, 0) >= 2:
            continue
        is_vuln = event.event_type in {EventType.VULNERABILITY, EventType.EXPLOITATION}
        if has_non_vuln and is_vuln and vuln_count >= vuln_cap:
            deferred.append(event)
            continue
        selected.append(event)
        if is_vuln:
            vuln_count += 1
        if _tier3_only(event):
            tier3_publishers[publisher_key] = tier3_publishers.get(publisher_key, 0) + 1

    if len(selected) < max_events:
        for event in deferred:
            if len(selected) >= max_events:
                break
            publisher_key = (event.publisher or event.source_name).casefold()
            if _tier3_only(event) and tier3_publishers.get(publisher_key, 0) >= 2:
                continue
            selected.append(event)
            if _tier3_only(event):
                tier3_publishers[publisher_key] = tier3_publishers.get(publisher_key, 0) + 1

    result.selected = selected
    return result
