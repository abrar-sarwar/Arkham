"""Deterministic, explainable Arkham event priority scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from arkham.models import CyberEvent, EventType, ExploitationStatus, KevStatus, SourceTier

WEIGHTS: dict[str, float] = {
    "exploitation.active": 30,
    "exploitation.widespread": 35,
    "exploitation.zero_day": 25,
    "exploitation.poc_public": 12,
    "kev.newly_added": 30,
    "kev.listed": 20,
    "severity.cvss_critical": 10,
    "severity.cvss_high": 6,
    "severity.cvss_elevated": 3,
    "severity.vuln_class": 3,
    "severity.cap": 13,
    "source.tier1": 10,
    "source.tier2": 6,
    "source.tier3": 2,
    "impact.critical_infrastructure": 15,
    "impact.supply_chain": 20,
    "impact.state_backed": 12,
    "impact.major_org": 8,
    "impact.sensitive_sector": 4,
    "impact.global_reach": 3,
    "impact.cap": 45,
    "corroboration.two_publishers": 10,
    "corroboration.three_plus_publishers": 12,
    "corroboration.tier_mix": 2,
    "novelty.material_update": 10,
    "novelty.new": 5,
    "novelty.already_briefed": -60,
    "recency.12h": 5,
    "recency.24h": 3,
    "recency.48h": 1,
    "relevance.off_topic": -50,
    "relevance.ransomware": 2,
    "relevance.injection_flagged": -10,
    "relevance.exploitation": 8,
    "relevance.incident": 6,
    "relevance.threat_activity": 6,
    "relevance.vulnerability": 5,
    "relevance.advisory": 4,
    "relevance.policy": 4,
    "relevance.research": 3,
    "relevance.other": 0,
}

_TYPE_KEYS = {
    EventType.EXPLOITATION: "relevance.exploitation",
    EventType.INCIDENT: "relevance.incident",
    EventType.THREAT_ACTIVITY: "relevance.threat_activity",
    EventType.VULNERABILITY: "relevance.vulnerability",
    EventType.ADVISORY: "relevance.advisory",
    EventType.POLICY: "relevance.policy",
    EventType.RESEARCH: "relevance.research",
    EventType.OTHER: "relevance.other",
}
_VULN_CLASS_PHRASES = (
    "remote code execution",
    "unauthenticated",
    "authentication bypass",
    "privilege escalation",
    "elevation of privilege",
    "arbitrary code execution",
)
_SENSITIVE_SECTORS = {
    "government",
    "healthcare",
    "finance",
    "financial services",
    "energy",
    "water",
    "telecommunications",
    "transportation",
    "defense",
    "education",
}


def _add(reasons: list[str], condition: bool, weight: float, reason: str) -> float:
    if not condition:
        return 0.0
    reasons.append(f"{reason} {weight:+g}")
    return weight


def _publishers(event: CyberEvent) -> set[str]:
    values = {event.publisher or event.source_name}
    values.update(ref.publisher or ref.source_name for ref in event.corroborating_sources)
    return {value.strip().casefold() for value in values if value.strip()}


def _tiers(event: CyberEvent) -> set[SourceTier]:
    return {event.source_tier, *(ref.source_tier for ref in event.corroborating_sources)}


def _latest_time(event: CyberEvent) -> datetime | None:
    values = [value for value in (event.published_at, event.updated_at) if value is not None]
    return max(values) if values else None


def score_event(event: CyberEvent, *, now: datetime) -> CyberEvent:
    """Rebuild all score components and reasons in-place, then return ``event``."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    reasons: list[str] = []

    exploitation = 0.0
    if event.exploitation_status is ExploitationStatus.WIDESPREAD:
        exploitation += _add(reasons, True, WEIGHTS["exploitation.widespread"], "widespread exploitation")
    elif event.exploitation_status is ExploitationStatus.ACTIVE:
        exploitation += _add(reasons, True, WEIGHTS["exploitation.active"], "active exploitation")
    elif event.exploitation_status is ExploitationStatus.POC_PUBLIC or event.poc_public:
        exploitation += _add(reasons, True, WEIGHTS["exploitation.poc_public"], "public PoC")
    if event.zero_day:
        exploitation += _add(reasons, True, WEIGHTS["exploitation.zero_day"], "zero-day")
    if event.kev_status is KevStatus.NEWLY_ADDED:
        exploitation += _add(reasons, True, WEIGHTS["kev.newly_added"], "CISA KEV newly added")
    elif event.kev_status is KevStatus.LISTED:
        exploitation += _add(reasons, True, WEIGHTS["kev.listed"], "CISA KEV")

    severity = 0.0
    if event.cvss_score is not None:
        if event.cvss_score >= 9.0:
            severity += _add(reasons, True, WEIGHTS["severity.cvss_critical"], "CVSS critical")
        elif event.cvss_score >= 8.0:
            severity += _add(reasons, True, WEIGHTS["severity.cvss_high"], "CVSS high")
        elif event.cvss_score >= 7.0:
            severity += _add(reasons, True, WEIGHTS["severity.cvss_elevated"], "CVSS elevated")
    title_lower = event.title.casefold()
    vuln_phrase = next((phrase for phrase in _VULN_CLASS_PHRASES if phrase in title_lower), None)
    if vuln_phrase:
        severity += _add(reasons, True, WEIGHTS["severity.vuln_class"], vuln_phrase)
    severity = min(severity, WEIGHTS["severity.cap"])

    tiers = _tiers(event)
    best_tier = min(tiers)
    tier_key = {SourceTier.PRIMARY: "source.tier1", SourceTier.RESEARCH: "source.tier2", SourceTier.JOURNALISM: "source.tier3"}[best_tier]
    tier_reason = {
        SourceTier.PRIMARY: "tier-1 primary source",
        SourceTier.RESEARCH: "tier-2 research source",
        SourceTier.JOURNALISM: "tier-3 journalism source",
    }[best_tier]
    source_quality = _add(reasons, True, WEIGHTS[tier_key], tier_reason)

    tags = {keyword.casefold() for keyword in event.keywords}
    impact = 0.0
    impact += _add(reasons, "tag:supply-chain" in tags, WEIGHTS["impact.supply_chain"], "supply-chain")
    impact += _add(
        reasons,
        "tag:critical-infrastructure" in tags,
        WEIGHTS["impact.critical_infrastructure"],
        "critical-infrastructure",
    )
    impact += _add(reasons, "tag:state-backed" in tags, WEIGHTS["impact.state_backed"], "state-backed")
    impact += _add(reasons, "tag:major-org" in tags, WEIGHTS["impact.major_org"], "major org")
    sector_hit = any(sector.casefold() in _SENSITIVE_SECTORS for sector in event.sectors)
    impact += _add(reasons, sector_hit, WEIGHTS["impact.sensitive_sector"], "sensitive sector")
    global_reach = any(region.casefold() == "global" for region in event.regions) or len(set(event.regions)) >= 3
    impact += _add(reasons, global_reach, WEIGHTS["impact.global_reach"], "global reach")
    impact = min(impact, WEIGHTS["impact.cap"])

    publishers = _publishers(event)
    corroboration = 0.0
    if len(publishers) >= 3:
        corroboration += _add(
            reasons,
            True,
            WEIGHTS["corroboration.three_plus_publishers"],
            f"{len(publishers)} publishers",
        )
    elif len(publishers) == 2:
        corroboration += _add(reasons, True, WEIGHTS["corroboration.two_publishers"], "2 publishers")
    if SourceTier.PRIMARY in tiers and SourceTier.RESEARCH in tiers:
        corroboration += _add(reasons, True, WEIGHTS["corroboration.tier_mix"], "tier-1 and tier-2 sources")

    novelty = 0.0
    if event.material_update:
        novelty += _add(reasons, True, WEIGHTS["novelty.material_update"], "material update")
    elif event.previously_briefed:
        novelty += _add(reasons, True, WEIGHTS["novelty.already_briefed"], "already briefed")
    elif event.first_seen is None or event.first_seen >= now - timedelta(hours=24):
        novelty += _add(reasons, True, WEIGHTS["novelty.new"], "new")

    recency = 0.0
    latest = _latest_time(event)
    if latest is not None:
        age = now - latest.astimezone(now.tzinfo)
        if age <= timedelta(hours=12):
            recency += _add(reasons, True, WEIGHTS["recency.12h"], "published within 12h")
        elif age <= timedelta(hours=24):
            recency += _add(reasons, True, WEIGHTS["recency.24h"], "published within 24h")
        elif age <= timedelta(hours=48):
            recency += _add(reasons, True, WEIGHTS["recency.48h"], "published within 48h")

    type_key = _TYPE_KEYS[event.event_type]
    relevance = _add(reasons, WEIGHTS[type_key] != 0, WEIGHTS[type_key], event.event_type.value.replace("_", " "))
    relevance += _add(reasons, "tag:off-topic" in tags, WEIGHTS["relevance.off_topic"], "off-topic")
    relevance += _add(reasons, "tag:ransomware" in tags, WEIGHTS["relevance.ransomware"], "ransomware")
    relevance += _add(
        reasons,
        event.injection_flagged,
        WEIGHTS["relevance.injection_flagged"],
        "prompt-injection content",
    )

    event.exploitation_score = exploitation
    event.severity_score = severity
    event.source_quality_score = source_quality
    event.global_impact_score = impact
    event.novelty_score = novelty
    event.relevance_score = relevance
    event.corroboration_score = corroboration
    event.recency_score = recency
    event.final_priority_score = max(
        0.0,
        min(100.0, exploitation + severity + source_quality + impact + novelty + relevance + corroboration + recency),
    )
    event.score_reasons = reasons
    return event


def score_events(events: list[CyberEvent], now: datetime) -> list[CyberEvent]:
    """Score a list in place without changing its order or object identity."""
    for event in events:
        score_event(event, now=now)
    return events
