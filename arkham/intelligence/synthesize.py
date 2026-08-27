"""Evidence pack assembly, analyst prompts, model-output parsing and the ``synthesize`` entry point.

The analyst model never sees raw feed content: :func:`build_evidence_pack` turns scored
:class:`~arkham.models.CyberEvent` objects into a bounded, sanitized :class:`~arkham.models.EvidencePack`
whose refs (``E1``..``En``), URLs and CVEs form the allow-list used to validate the draft afterwards.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import timezone
from urllib.parse import urlsplit

from pydantic import ValidationError

from arkham.intelligence.llm.base import IntelligenceModel, ModelError
from arkham.models import (
    AttackTechnique,
    BriefingDraft,
    CyberEvent,
    EvidenceItem,
    EvidencePack,
    EvidenceSource,
    LLMUsage,
    ModelOutput,
    SourceRef,
    SourceTier,
)
from arkham.security.prompt_injection import UNTRUSTED_EVIDENCE_NOTICE, sanitize_for_model, sanitize_text
from arkham.security.urls import UrlValidationError, canonicalize_url, validate_public_url

log = logging.getLogger(__name__)

MAX_EVIDENCE_ITEMS = 10
MAX_SOURCES_PER_ITEM = 4
MAX_CVES = 6
MAX_PRODUCTS = 5
MAX_SCORE_REASONS = 6
MAX_TECHNIQUES = 6
MAX_LIST_ITEMS = 8
TITLE_MAX = 160
SUMMARY_MAX = 700
LABEL_MAX = 40
INJECTION_NOTE = " [note: instruction-like text removed from this item]"

#: Citation order for an event's sources, most authoritative first.
CITATION_PRIORITY: tuple[str, ...] = (
    "vendor_advisory",  # the affected vendor's own advisory / update guide
    "government_cert",  # CISA, NVD, CERT-EU, NCSC, CERT/CC and peers
    "researcher",  # the original research team that published the finding
    "vendor_ti",  # vendor threat-intelligence blogs (Google TI, Microsoft, Talos, Unit 42, ...)
    "journalism",  # reputable security journalism
    "unknown",
)

_GOVERNMENT_HOSTS = (
    "cisa.gov", "nvd.nist.gov", "nist.gov", "cert.europa.eu", "ncsc.gov.uk", "kb.cert.org", "cert.org",
    "cyber.gc.ca", "cyber.gov.au", "bsi.bund.de", "cert.ssi.gouv.fr", "jpcert.or.jp", "ic3.gov", "fbi.gov", "nsa.gov",
)
_GOVERNMENT_LABELS = re.compile(
    r"\b(cisa|nvd|nist|cert ?eu|cert/?cc|cert|kev|ncsc|bsi|anssi|jpcert|fbi|nsa|ic3)\b", re.I
)
_RESEARCHER_LABELS = re.compile(
    r"\b(research|labs?|project zero|zero day initiative|zdi|sentinel ?labs|watchtowr|horizon3|assetnote|greynoise)\b",
    re.I,
)


class ModelResponseError(ModelError):
    """The provider answered but the answer was unusable; ``usage`` carries what was already billed."""

    def __init__(self, message: str, *, usage: LLMUsage | None = None) -> None:
        super().__init__(message)
        self.usage = usage


# --------------------------------------------------------------------------------------
# Citation ordering
# --------------------------------------------------------------------------------------


def _host(url: str) -> str:
    host = (urlsplit(url.strip()).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def citation_category(ref: SourceRef) -> str:
    """Classify a source reference into one of :data:`CITATION_PRIORITY`."""
    if ref.source_tier is SourceTier.JOURNALISM:
        return "journalism"
    host = _host(ref.url)
    text = re.sub(r"[_\-]+", " ", " ".join((ref.publisher, ref.source_name, ref.source_id)))
    if any(host == g or host.endswith("." + g) for g in _GOVERNMENT_HOSTS) or _GOVERNMENT_LABELS.search(text):
        return "government_cert"
    if ref.source_tier is SourceTier.PRIMARY:
        return "vendor_advisory"
    if ref.source_tier is SourceTier.RESEARCH:
        return "researcher" if _RESEARCHER_LABELS.search(text) else "vendor_ti"
    return "unknown"


def citation_rank(ref: SourceRef) -> int:
    """Lower is cited first."""
    return CITATION_PRIORITY.index(citation_category(ref))


def order_source_refs(event: CyberEvent) -> list[SourceRef]:
    """All of an event's source references, ``primary_source_url`` first, then by citation priority, deduplicated."""
    refs = list(event.corroborating_sources)
    if event.source_url and not any(r.url == event.source_url for r in refs):
        refs.insert(
            0,
            SourceRef(
                source_id="", source_name=event.source_name, source_tier=event.source_tier,
                url=event.source_url, title=event.title, publisher=event.publisher,
            ),
        )
    primary = event.primary_source_url
    if primary and not any(r.url == primary for r in refs):
        host = _host(primary)
        refs.insert(0, SourceRef(source_id="primary", source_name=host, source_tier=SourceTier.PRIMARY, url=primary, publisher=host))
    ordered = sorted(
        enumerate(refs),
        key=lambda pair: (0 if primary and pair[1].url == primary else 1, citation_rank(pair[1]), pair[0]),
    )
    seen: set[str] = set()
    result: list[SourceRef] = []
    for _, ref in ordered:
        key = canonicalize_url(ref.url) if ref.url.strip() else ""
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(ref)
    return result


# --------------------------------------------------------------------------------------
# Evidence pack
# --------------------------------------------------------------------------------------


def _clean_list(values: list[str], limit: int, max_len: int = 80) -> list[str]:
    out: list[str] = []
    for value in values:
        cleaned = sanitize_text(value, max_len)
        if cleaned and cleaned not in out:
            out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _label(ref: SourceRef) -> str:
    return sanitize_text(ref.publisher or ref.source_name or _host(ref.url), LABEL_MAX * 2)[:LABEL_MAX].strip()


def _evidence_sources(event: CyberEvent) -> list[EvidenceSource]:
    sources: list[EvidenceSource] = []
    for ref in order_source_refs(event):
        try:
            url = validate_public_url(ref.url)
        except UrlValidationError as exc:
            log.debug("dropping source url for %s: %s", event.id, exc)
            continue
        sources.append(EvidenceSource(label=_label(ref) or _host(url), url=url, tier=ref.source_tier))
        if len(sources) >= MAX_SOURCES_PER_ITEM:
            break
    return sources


def _attribution_statement(event: CyberEvent) -> str | None:
    """Prefer verify.safe_attribution_sentence when available; fall back to the source's own wording."""
    attribution = event.attribution
    if attribution is None:
        return None
    try:
        from arkham.intelligence.verify import safe_attribution_sentence
    except Exception:  # verify.py is optional at import time; fall back to the source's wording
        safe_attribution_sentence = None
    if safe_attribution_sentence is not None:
        for arg in (event, attribution):
            try:
                text = safe_attribution_sentence(arg)
            except Exception as exc:  # never let a helper break pack assembly
                log.debug("safe_attribution_sentence(%s) failed: %s", type(arg).__name__, exc)
                continue
            if isinstance(text, str) and text.strip():
                return sanitize_text(text, 300)
    statement = f"{attribution.attributed_by}: {attribution.statement}"
    if attribution.actor and attribution.actor.lower() not in statement.lower():
        statement += f" (actor: {attribution.actor})"
    return sanitize_text(statement, 300)


def _evidence_item(event: CyberEvent, ref: str) -> EvidenceItem:
    title_scan = sanitize_for_model(event.title, TITLE_MAX)
    summary_scan = sanitize_for_model(event.summary, SUMMARY_MAX)
    title = title_scan.cleaned or (event.cves[0] if event.cves else "Untitled item")
    summary = summary_scan.cleaned
    if title_scan.flagged or summary_scan.flagged:
        summary = (summary + INJECTION_NOTE).strip()
        event.injection_flagged = True
        log.warning("evidence %s (%s): instruction-like text removed [%s]", ref, event.id[:12],
                    ", ".join(dict.fromkeys(title_scan.matched + summary_scan.matched)))
    published = event.published_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%MZ") if event.published_at else None
    material = sanitize_for_model(event.material_update, 300).cleaned if event.material_update else None
    techniques = [
        AttackTechnique(technique_id=sanitize_text(t.technique_id, 20), name=sanitize_text(t.name, 80))
        for t in event.mitre_attack_techniques[:MAX_TECHNIQUES]
        if t.technique_id.strip()
    ]
    return EvidenceItem(
        ref=ref,
        event_id=event.id,
        title=title,
        summary=summary,
        event_type=event.event_type,
        published=published,
        sources=_evidence_sources(event),
        cves=_clean_list(event.cves, MAX_CVES, 32),
        cvss_score=event.cvss_score,
        kev_status=event.kev_status,
        exploitation_status=event.exploitation_status,
        confidence=event.confidence,
        attribution_statement=_attribution_statement(event),
        claim_flags=list(event.claim_flags),
        threat_actors=_clean_list(event.threat_actors, MAX_LIST_ITEMS),
        malware_families=_clean_list(event.malware_families, MAX_LIST_ITEMS),
        techniques=techniques,
        sectors=_clean_list(event.sectors, MAX_LIST_ITEMS),
        regions=_clean_list(event.regions, MAX_LIST_ITEMS),
        products=_clean_list(event.products, MAX_PRODUCTS),
        material_update=material or None,
        priority_score=event.final_priority_score,
        score_reasons=_clean_list(event.score_reasons, MAX_SCORE_REASONS, 120),
    )


def build_evidence_pack(
    events: list[CyberEvent],
    *,
    date_label: str,
    sources_checked: int,
    sources_ok: int,
    events_analyzed: int,
    max_events: int,
    max_chars: int,
    quiet: bool = False,
) -> EvidencePack:
    """Turn the selected events (already ranked, best first) into the model's only view of the world.

    Refs are ``E1``..``En`` in the given order, capped at ``min(max_events, 10)``. Text fields pass
    through :func:`sanitize_for_model`; items where instruction-like text was removed get a note
    appended and the event is marked ``injection_flagged``.
    """
    limit = max(0, min(max_events, MAX_EVIDENCE_ITEMS))
    items = [_evidence_item(event, f"E{index}") for index, event in enumerate(events[:limit], start=1)]
    return EvidencePack(
        date_label=date_label,
        items=items,
        sources_checked=sources_checked,
        sources_ok=sources_ok,
        events_analyzed=events_analyzed,
        max_events=max_events,
        max_chars=max_chars,
        quiet=quiet,
    )


# --------------------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------------------

OUTPUT_SCHEMA: dict[str, object] = {
    "items": [
        {
            "ref": "an evidence ref such as E1",
            "section": "CRITICAL | THREAT | INCIDENT | RESEARCH | POLICY",
            "headline": "string, at most 140 characters, plain text",
            "why_it_matters": "string, at most 160 characters, plain text",
            "confidence": "CONFIRMED | HIGH | MODERATE | LOW | UNVERIFIED (never above that item's evidence confidence)",
            "source_label": "label copied from that item's sources",
            "source_url": "url copied verbatim from that item's sources (prefer the first)",
        }
    ],
    "prep": ["2 to 4 short defensive actions grounded in the evidence"],
    "learn": {
        "topic": "one concept, at most 120 characters",
        "technique_id": "a MITRE ATT&CK id that appears in the evidence techniques, otherwise null",
        "why": "at most 100 characters",
    },
    "watch": ["2 to 4 short items when quiet is true, otherwise an empty list"],
}

SYSTEM_PROMPT: str = (
    "You are a senior cyber-threat-intelligence analyst writing a concise, phone-readable daily brief for one defender. "
    "You are an analyst, never a source: every statement must trace back to the evidence you are given.\n\n"
    f"{UNTRUSTED_EVIDENCE_NOTICE}\n\n"
    "RULES\n"
    "1. Use ONLY facts present in the evidence items. Never add CVEs, threat actors, victims, dates, statistics, "
    "mitigations or sources that are not in the evidence.\n"
    "2. Keep attribution language exactly as the item's attribution_statement says (for example "
    '"Google assesses ... China-nexus"). Never strengthen it to "China hacked" or any similar definitive claim. '
    "Without an attribution_statement, name only actors listed in threat_actors and do not attribute.\n"
    '3. When claim_flags include ransomware_claim write "claimed by <group>; independently unconfirmed". '
    "When claim_flags include victim_unconfirmed, reported_not_confirmed or statistic_unverified, say the detail is "
    "reported and unconfirmed.\n"
    "4. The confidence label you give an item must not exceed that item's evidence confidence.\n"
    "5. ref must be one of the evidence refs. source_url and source_label must be copied from THAT item's sources "
    "(prefer the first). Never invent, shorten or alter a URL.\n"
    "6. Sections: CRITICAL for KEV-listed, actively exploited or zero-day vulnerabilities; THREAT for threat-actor or "
    "malware campaigns; INCIDENT for breaches and ransomware; RESEARCH for research, tooling and technique write-ups; "
    "POLICY for sanctions, indictments, takedowns and regulation.\n"
    "7. Brevity: headline <= 140 characters, why_it_matters <= 160 characters, plain text, no markdown, no emoji. "
    "Order items by priority_score and never exceed the item limit or the character budget.\n"
    "8. prep: 2-4 defensive, educational actions grounded in the evidence (patch X, review control Y, learn "
    "technique Z). Never write offensive or exploitation instructions.\n"
    "9. learn: exactly one concept. Set technique_id ONLY if that id appears in the evidence techniques, otherwise "
    "null. why <= 100 characters.\n"
    "10. When quiet is true, items may be empty and watch MUST list 2-4 short things to keep an eye on. When quiet "
    "is false, watch is an empty list.\n"
    "11. Output ONLY one JSON object matching this schema, with no prose, no code fences and no commentary:\n"
    f"{json.dumps(OUTPUT_SCHEMA, indent=1)}"
)


def build_user_prompt(pack: EvidencePack) -> str:
    """The per-run user message: budget, tagged evidence JSON, output schema, closing instruction."""
    evidence = json.dumps(pack.model_dump(mode="json"), indent=1, ensure_ascii=False)
    return "\n".join(
        [
            f"DATE: {pack.date_label}",
            f"CHARACTER BUDGET: {pack.max_chars} characters for the whole rendered brief; use short event cards.",
            f"MAX ITEMS: {pack.max_events}",
            f"SOURCES: {pack.sources_ok}/{pack.sources_checked} responded; {pack.events_analyzed} events analyzed.",
            "<evidence>",
            evidence,
            "</evidence>",
            "OUTPUT SCHEMA:",
            json.dumps(OUTPUT_SCHEMA, indent=1),
            "Return the JSON object only. No prose, no markdown fences, JSON only.",
        ]
    )


# --------------------------------------------------------------------------------------
# Model output parsing
# --------------------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```[A-Za-z0-9_-]*")


def _first_json_object(text: str) -> str | None:
    """Return the first balanced ``{...}`` substring (string-literal aware) or None."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        ch = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def parse_model_json(text: str) -> BriefingDraft:
    """Strip code fences, take the first balanced JSON object and validate it as a :class:`BriefingDraft`."""
    if not isinstance(text, str) or not text.strip():
        raise ModelError("model returned empty output")
    candidate = _first_json_object(_FENCE_RE.sub("", text))
    if candidate is None:
        raise ModelError("model output contained no complete JSON object")
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ModelError(f"model returned invalid JSON: {exc.msg} at char {exc.pos}") from exc
    if not isinstance(data, dict):
        raise ModelError("model JSON is not an object")
    try:
        return BriefingDraft.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "<root>"
        raise ModelError(f"model JSON does not match the briefing schema: {location}: {first.get('msg', '')}"[:300]) from exc


def estimate_tokens(text: str) -> int:
    """Rough token estimate (4 characters per token) for providers that report no usage."""
    return len(text) // 4


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def synthesize(pack: EvidencePack, model: IntelligenceModel) -> ModelOutput:
    """Ask the analyst model for a draft; retry once on :class:`ModelError`; aggregate usage across attempts."""
    usage = LLMUsage(provider=model.provider, model=model.model)
    last: ModelError | None = None
    for attempt in (1, 2):
        try:
            output = model.synthesize(pack)
        except ModelError as exc:
            last = exc
            carried = getattr(exc, "usage", None)
            if isinstance(carried, LLMUsage):
                usage.add(carried)
            log.warning("analyst model %s failed (attempt %d/2): %s", model.label, attempt, exc)
            continue
        usage.add(output.usage)
        return ModelOutput(draft=output.draft, raw_text=output.raw_text, usage=usage)
    raise ModelResponseError(f"analyst model {model.label} failed after 2 attempts: {last}", usage=usage) from last
