"""Deterministic, network-free analyst model.

``TemplateModel`` builds a :class:`~arkham.models.BriefingDraft` directly from the evidence pack
using fixed rules. It needs no credentials, costs nothing, and is the honest fallback when no LLM
is configured: every headline, URL and action it emits is copied from the evidence.
"""

from __future__ import annotations

import json
import re

from arkham.intelligence.llm.base import IntelligenceModel
from arkham.models import (
    BriefingDraft,
    BriefItem,
    BriefSection,
    ClaimFlag,
    EventType,
    EvidenceItem,
    EvidencePack,
    ExploitationStatus,
    KevStatus,
    LearnTopic,
    LLMUsage,
    ModelOutput,
)

HEADLINE_MAX = 115
WHY_MAX = 100
WHY_HARD_MAX = 260  # BriefItem.why_it_matters limit
WATCH_MAX = 80
LABEL_MAX = 40
TOPIC_MAX = 120
PREP_MIN, PREP_MAX = 2, 4
WATCH_MIN, WATCH_MAX_ITEMS = 2, 4

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+")

#: keyword -> concept map used for the "learn" slot when no ATT&CK technique is in the evidence.
CONCEPTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ransomware",), "Ransomware initial access via exposed remote services"),
    (("phishing",), "Phishing-resistant MFA"),
    (("supply chain", "supply-chain"), "Software supply-chain attestation (SLSA)"),
    (("cloud", "identity", "token"), "OAuth token theft and session hijacking"),
    (("zero-day", "zero day", "0-day"), "Zero-day exposure management: virtual patching and WAF rules"),
)
DEFAULT_CONCEPT = "CISA KEV-driven patch prioritization"
DEFAULT_CONCEPT_WHY = "baseline practice when no specific technique appears in the evidence"
DEFAULT_PREP: tuple[str, ...] = (
    "Review CISA KEV for newly added entries affecting your stack",
    "Verify MFA and patch levels on internet-facing remote access",
    "Confirm backups are offline and restore-tested",
)
DEFAULT_WATCH: tuple[str, ...] = (
    "New CISA KEV additions and vendor out-of-band patches",
    "Active exploitation reports for internet-facing edge devices",
    "Ransomware leak-site claims against your sector",
)


def trim(text: str, limit: int) -> str:
    """Trim to ``limit`` characters on a word boundary, appending ``...`` when cut."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[: limit - 3]
    space = cut.rfind(" ")
    if space > limit * 0.5:
        cut = cut[:space]
    return cut.rstrip(" ,;:-") + "..."


def _is_exploited(item: EvidenceItem) -> bool:
    return item.kev_status is not KevStatus.NOT_LISTED or item.exploitation_status in (
        ExploitationStatus.ACTIVE,
        ExploitationStatus.WIDESPREAD,
    )


def section_for(item: EvidenceItem) -> BriefSection:
    """Section by KEV/exploitation first, then by event type."""
    if _is_exploited(item):
        return BriefSection.CRITICAL
    kind = item.event_type
    if kind in (EventType.VULNERABILITY, EventType.EXPLOITATION):
        return BriefSection.CRITICAL
    if kind is EventType.ADVISORY:
        return BriefSection.CRITICAL if item.cves else BriefSection.RESEARCH
    if kind is EventType.THREAT_ACTIVITY:
        return BriefSection.THREAT
    if kind is EventType.INCIDENT:
        return BriefSection.INCIDENT
    if kind is EventType.RESEARCH:
        return BriefSection.RESEARCH
    if kind is EventType.POLICY:
        return BriefSection.POLICY
    if any(flag in item.claim_flags for flag in (ClaimFlag.RANSOMWARE_CLAIM, ClaimFlag.VICTIM_UNCONFIRMED)):
        return BriefSection.INCIDENT
    if item.threat_actors or item.malware_families:
        return BriefSection.THREAT
    return BriefSection.RESEARCH


def _headline(item: EvidenceItem) -> str:
    title = item.title.strip()
    if item.cves and item.cves[0].lower() not in title.lower():
        title = f"{item.cves[0]}: {title}"
    return trim(title, HEADLINE_MAX)


def _why(item: EvidenceItem) -> str:
    facts: list[str] = []
    if item.kev_status is KevStatus.NEWLY_ADDED:
        facts.append("New CISA KEV: exploitation confirmed")
    elif item.kev_status is KevStatus.LISTED:
        facts.append("CISA KEV lists this as exploited")
    elif item.exploitation_status is ExploitationStatus.WIDESPREAD:
        facts.append("Evidence reports widespread exploitation")
    elif item.exploitation_status is ExploitationStatus.ACTIVE:
        facts.append("Evidence reports active exploitation")
    elif item.exploitation_status is ExploitationStatus.POC_PUBLIC:
        facts.append("Evidence reports public proof-of-concept code")

    if item.products:
        facts.append(f"Prioritize {trim(item.products[0], 42)} exposure and mitigation")
    elif item.cves:
        facts.append(f"Assess exposure to {item.cves[0]} and follow vendor mitigation")

    if facts:
        return trim(". ".join(facts) + ".", WHY_MAX)

    summary = item.summary.strip()
    first = _SENTENCE_END_RE.split(summary, maxsplit=1)[0] if summary else ""
    if not first or first.startswith("[note:"):
        first = item.title
    suffix = ""
    if ClaimFlag.RANSOMWARE_CLAIM in item.claim_flags:
        group = item.threat_actors[0] if item.threat_actors else "a ransomware group"
        suffix = f" Claimed by {group}; independently unconfirmed."
    return trim(first, min(WHY_MAX, WHY_HARD_MAX - len(suffix))) + suffix


def _brief_item(item: EvidenceItem) -> BriefItem | None:
    if not item.sources:
        return None
    source = item.sources[0]
    return BriefItem(
        ref=item.ref,
        section=section_for(item),
        headline=_headline(item),
        why_it_matters=_why(item),
        confidence=item.confidence,
        source_label=source.label[:LABEL_MAX].strip(),
        source_url=source.url,
    )


def _prep(items: list[EvidenceItem]) -> list[str]:
    actions: list[str] = []

    def add(action: str) -> None:
        if action not in actions and len(actions) < PREP_MAX:
            actions.append(action)

    for item in items:
        if _is_exploited(item):
            target = item.products[0] if item.products else (item.cves[0] if item.cves else trim(item.title, 60))
            add(f"Patch/mitigate {target} if exposed")
        for technique in item.techniques:
            add(f"Review detections for {technique.technique_id} {technique.name}".rstrip())
        for actor in item.threat_actors:
            add(f"Review {actor} TTPs and indicators")
        if item.event_type is EventType.INCIDENT or section_for(item) is BriefSection.INCIDENT:
            for sector in item.sectors:
                add(f"Check {sector} third-party exposure")
    for fallback in DEFAULT_PREP:
        if len(actions) >= PREP_MIN:
            break
        add(fallback)
    return actions


def _learn(items: list[EvidenceItem]) -> LearnTopic:
    for item in items:
        for technique in item.techniques:
            topic = f"{technique.name} - MITRE {technique.technique_id}" if technique.name else f"MITRE {technique.technique_id}"
            return LearnTopic(topic=trim(topic, TOPIC_MAX), technique_id=technique.technique_id, why="appeared in today's evidence")
    corpus = " ".join(
        " ".join(
            [
                item.title,
                item.summary,
                item.event_type.value,
                *item.sectors,
                *item.products,
                *item.malware_families,
                *(flag.value for flag in item.claim_flags),
            ]
        )
        for item in items
    ).lower()
    for keywords, topic in CONCEPTS:
        for keyword in keywords:
            if keyword in corpus:
                return LearnTopic(topic=topic, technique_id=None, why=f"'{keyword}' appeared in today's evidence")
    return LearnTopic(topic=DEFAULT_CONCEPT, technique_id=None, why=DEFAULT_CONCEPT_WHY)


def _watch(items: list[EvidenceItem]) -> list[str]:
    watch = [trim(item.title, WATCH_MAX) for item in items[:3] if item.title.strip()]
    for fallback in DEFAULT_WATCH:
        if len(watch) >= WATCH_MIN:
            break
        if fallback not in watch:
            watch.append(fallback)
    return watch[:WATCH_MAX_ITEMS]


class TemplateModel(IntelligenceModel):
    """Evidence-only draft generator: no network, no credentials, same output for the same pack."""

    provider = "template"
    model = ""

    def synthesize(self, evidence: EvidencePack) -> ModelOutput:
        items: list[BriefItem] = []
        if not evidence.quiet:
            for item in evidence.items[: max(0, evidence.max_events)]:
                brief_item = _brief_item(item)
                if brief_item is not None:
                    items.append(brief_item)
        draft = BriefingDraft(
            items=items,
            prep=_prep(evidence.items),
            learn=_learn(evidence.items),
            watch=_watch(evidence.items) if evidence.quiet else [],
        )
        raw_text = json.dumps(draft.model_dump(mode="json"), indent=1, ensure_ascii=False)
        return ModelOutput(draft=draft, raw_text=raw_text, usage=LLMUsage(provider=self.provider, model=self.model))
