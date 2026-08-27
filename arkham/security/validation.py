"""Fail-closed grounding validation between evidence, draft, rendering, and recipient."""

from __future__ import annotations

import re

from arkham.config import Settings
from arkham.models import Briefing, BriefingDraft, EvidencePack
from arkham.security.prompt_injection import detect_injection, sanitize_text
from arkham.security.urls import canonicalize_url

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https://[^\s<>\])}]+", re.IGNORECASE)


def sanitize_learn(draft: BriefingDraft, pack: EvidencePack) -> list[str]:
    """Remove an ATT&CK id the evidence does not contain; keep the educational topic."""
    if draft.learn is None or not draft.learn.technique_id:
        return []
    allowed = {technique.technique_id.upper() for item in pack.items for technique in item.techniques}
    technique = sanitize_text(draft.learn.technique_id, 20).upper()
    if technique in allowed:
        draft.learn.technique_id = technique
        return []
    draft.learn.technique_id = None
    return [f"removed unsupported learn technique {technique}"]


def _canonical_set(urls: set[str]) -> set[str]:
    return {canonicalize_url(url) for url in urls}


def validate_draft(draft: BriefingDraft, pack: EvidencePack, max_events: int) -> list[str]:
    """Validate every generated story against its exact evidence item."""
    problems: list[str] = []
    if not pack.quiet and pack.items and not draft.items:
        problems.append("draft contains no event cards for non-quiet evidence")
    if len(draft.items) > max_events:
        problems.append(f"draft contains more than {max_events} items")
    seen: set[str] = set()
    allowed_global_urls = _canonical_set(pack.allowed_urls)
    allowed_global_cves = {cve.upper() for cve in pack.allowed_cves}
    max_confidence = max((item.confidence.rank for item in pack.items), default=0)
    draft_refs = [item.ref for item in draft.items]
    expected_refs = [item.ref for item in pack.items[: len(draft_refs)]]
    if draft_refs != expected_refs:
        problems.append("draft items must preserve the ranked evidence prefix")

    for index, item in enumerate(draft.items, start=1):
        prefix = f"item {index}"
        if item.ref in seen:
            problems.append(f"{prefix}: duplicate evidence ref {item.ref}")
        seen.add(item.ref)
        evidence = pack.refs.get(item.ref)
        if evidence is None:
            problems.append(f"{prefix}: unknown evidence ref {item.ref}")
        allowed_urls = _canonical_set({source.url for source in evidence.sources}) if evidence else allowed_global_urls
        if canonicalize_url(item.source_url) not in allowed_urls:
            problems.append(f"{prefix}: source URL is not allowed by evidence {item.ref}")
        claimed_cves = {cve.upper() for cve in _CVE_RE.findall(f"{item.headline} {item.why_it_matters}")}
        item_cves = {cve.upper() for cve in evidence.cves} if evidence else allowed_global_cves
        for cve in sorted(claimed_cves - item_cves):
            problems.append(f"{prefix}: {cve} is not present in evidence {item.ref}")
        allowed_rank = evidence.confidence.rank if evidence else max_confidence
        if item.confidence.rank > allowed_rank:
            problems.append(f"{prefix}: confidence exceeds evidence confidence")
        if evidence and evidence.claim_flags and "confirmed" in item.why_it_matters.casefold():
            problems.append(f"{prefix}: confirmed language conflicts with evidence uncertainty flags")
        if detect_injection(f"{item.headline}\n{item.why_it_matters}\n{item.source_label}"):
            problems.append(f"{prefix}: instruction-like output detected")
    return problems


def validate_rendered(briefing: Briefing, pack: EvidencePack, max_chars: int | None) -> list[str]:
    """Validate the rendered text; the renderer is not trusted merely because the draft passed.

    ``max_chars`` is the SMS budget (size checks apply); ``None`` means the transport renderer enforces
    its own limits (Discord) and only the grounding/injection checks run here.
    """
    problems: list[str] = []
    if max_chars is not None:
        if len(briefing.text) > max_chars:
            problems.append(f"rendered briefing exceeds {max_chars} characters")
        hard_limit = min(max_chars, 1600)
        if any(len(message) > hard_limit for message in briefing.messages):
            problems.append(f"rendered SMS part exceeds {hard_limit} characters")
    allowed_urls = _canonical_set(pack.allowed_urls)
    for raw_url in _URL_RE.findall(briefing.text):
        url = raw_url.rstrip(".,;:")
        if canonicalize_url(url) not in allowed_urls:
            problems.append(f"rendered URL is not in evidence: {url}")
    allowed_cves = {cve.upper() for cve in pack.allowed_cves}
    for cve in sorted({value.upper() for value in _CVE_RE.findall(briefing.text)} - allowed_cves):
        problems.append(f"rendered CVE is not in evidence: {cve}")
    if detect_injection(briefing.text):
        problems.append("rendered briefing contains instruction-like text")
    return problems


def validate_recipient(settings: Settings, provider_recipient_masked: str) -> list[str]:
    """The provider cannot deliver anywhere but the configured destination (webhook or phone)."""
    configured = settings.discord_webhook_url if not settings.delivery_is_sms else settings.to_phone
    variable = "ARKHAM_TO_PHONE" if settings.delivery_is_sms else "DISCORD_WEBHOOK_URL"
    if configured and provider_recipient_masked == settings.recipient_masked:
        return []
    return [f"delivery provider destination does not match the configured {variable}"]
