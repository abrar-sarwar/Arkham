"""Normalized data model shared by every Arkham module.

Everything a source adapter produces becomes a :class:`RawItem`; the intelligence pipeline turns
groups of raw items into :class:`CyberEvent` objects; the analyst model produces a
:class:`BriefingDraft` that is validated and rendered into a :class:`Briefing`.
"""

from __future__ import annotations

import hashlib
from datetime import date, datetime, timezone
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arkham.crawl.models import CrawlMetrics


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()


# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------


class SourceTier(IntEnum):
    """Reliability tier. Lower is more authoritative."""

    PRIMARY = 1  # government / CERT / vendor advisories, NVD, KEV
    RESEARCH = 2  # vendor threat-intelligence and security research teams
    JOURNALISM = 3  # reputable security journalism (discovery, not confirmation)


class SourceCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    ADVISORY = "advisory"
    THREAT_INTEL = "threat_intel"
    RESEARCH = "research"
    NEWS = "news"


class EventType(str, Enum):
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    INCIDENT = "incident"
    THREAT_ACTIVITY = "threat_activity"
    RESEARCH = "research"
    POLICY = "policy"
    ADVISORY = "advisory"
    OTHER = "other"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"

    @property
    def label(self) -> str:
        if self is Confidence.CONFIRMED or self is Confidence.UNVERIFIED:
            return self.value
        return f"{self.value} CONFIDENCE"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK = {
    Confidence.UNVERIFIED: 0,
    Confidence.LOW: 1,
    Confidence.MODERATE: 2,
    Confidence.HIGH: 3,
    Confidence.CONFIRMED: 4,
}


class ExploitationStatus(str, Enum):
    UNKNOWN = "unknown"
    NONE_REPORTED = "none_reported"
    POC_PUBLIC = "poc_public"
    ACTIVE = "active"
    WIDESPREAD = "widespread"

    @property
    def rank(self) -> int:
        return list(ExploitationStatus).index(self)


class KevStatus(str, Enum):
    NOT_LISTED = "not_listed"
    LISTED = "listed"
    NEWLY_ADDED = "newly_added"  # added to KEV inside the current collection window


class Region(str, Enum):
    US = "US"
    CHINA = "China"
    RUSSIA = "Russia"
    UKRAINE = "Ukraine"
    ISRAEL = "Israel"
    IRAN = "Iran"
    NORTH_KOREA = "North Korea"
    EU = "EU"
    UK = "UK"
    MIDDLE_EAST = "Middle East"
    APAC = "APAC"
    AFRICA = "Africa"
    LATAM = "Latin America"
    GLOBAL = "Global"


class ClaimFlag(str, Enum):
    """Markers for statements that must not be presented as established fact."""

    RANSOMWARE_CLAIM = "ransomware_claim"  # a criminal group claims a victim; victim silent
    VICTIM_UNCONFIRMED = "victim_unconfirmed"
    ATTRIBUTION_SUSPECTED = "attribution_suspected"  # "suspected", "likely", "assessed"
    REPORTED_NOT_CONFIRMED = "reported_not_confirmed"  # journalism-only sourcing
    STATISTIC_UNVERIFIED = "statistic_unverified"  # victim counts, record counts


class BriefSection(str, Enum):
    CRITICAL = "CRITICAL"
    THREAT = "THREAT"
    INCIDENT = "INCIDENT"
    RESEARCH = "RESEARCH"
    POLICY = "POLICY"


class DeliveryStatus(str, Enum):
    SENT = "sent"
    DRY_RUN = "dry_run"
    FAILED = "failed"
    BLOCKED_VALIDATION = "blocked_validation"
    NOT_ATTEMPTED = "not_attempted"


# --------------------------------------------------------------------------------------
# Collection layer
# --------------------------------------------------------------------------------------


class RawItem(BaseModel):
    """One record emitted by a source adapter after light normalisation.

    ``summary``/``content`` MUST already be plain text (HTML stripped, control characters removed)
    — adapters call :func:`arkham.security.prompt_injection.sanitize_text`.
    ``extra`` carries structured, source-specific facts (CVSS, KEV dates, CWE ids, references).
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str
    source_name: str
    source_tier: SourceTier
    source_category: SourceCategory
    external_id: str | None = None
    title: str
    url: str
    summary: str = ""
    content: str = ""
    published_at: datetime | None = None
    updated_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utcnow)
    extra: dict[str, Any] = Field(default_factory=dict)
    raw_hash: str = ""

    @field_validator("published_at", "updated_at", "fetched_at")
    @classmethod
    def _require_tz(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("datetimes must be timezone-aware")
        return v

    def model_post_init(self, __context: Any) -> None:
        if not self.raw_hash:
            stamp = self.updated_at or self.published_at
            self.raw_hash = sha256_hex(
                self.source_id,
                self.external_id or self.url,
                self.title.strip().lower(),
                stamp.isoformat() if stamp else "",
            )

    @property
    def effective_time(self) -> datetime | None:
        return self.updated_at or self.published_at


class SourceStatus(BaseModel):
    """Outcome of one adapter fetch inside a run."""

    source_id: str
    name: str
    ok: bool
    status: str  # OK | NOT MODIFIED | TIMEOUT | HTTP 500 | PARSE ERROR | DISABLED | ERROR
    items: int = 0
    new_items: int = 0
    elapsed_ms: int = 0
    error: str | None = None


class SourceState(BaseModel):
    """Persisted per-source fetch state (conditional GET + health)."""

    source_id: str
    etag: str | None = None
    last_modified: str | None = None
    last_success_at: datetime | None = None
    last_status: str | None = None
    consecutive_failures: int = 0


# --------------------------------------------------------------------------------------
# Intelligence layer
# --------------------------------------------------------------------------------------


class SourceRef(BaseModel):
    source_id: str
    source_name: str
    source_tier: SourceTier
    url: str
    title: str = ""
    published_at: datetime | None = None
    publisher: str = ""  # short citation label, e.g. "CISA"


class AttackTechnique(BaseModel):
    technique_id: str
    name: str = ""


class Attribution(BaseModel):
    """Attribution exactly as a reliable source stated it — never stronger."""

    actor: str
    attributed_by: str  # e.g. "Google Threat Intelligence Group"
    confidence: Confidence
    statement: str  # the source's own wording, e.g. "assesses with moderate confidence"


class CyberEvent(BaseModel):
    """One deduplicated, enriched, scored intelligence event."""

    model_config = ConfigDict(validate_assignment=False)

    id: str
    title: str
    summary: str
    event_type: EventType = EventType.OTHER
    published_at: datetime | None = None
    updated_at: datetime | None = None

    source_name: str
    source_url: str
    source_tier: SourceTier
    publisher: str = ""  # short citation label of the primary source, e.g. "CISA"

    primary_source_url: str | None = None
    corroborating_sources: list[SourceRef] = Field(default_factory=list)
    referenced_urls: list[str] = Field(default_factory=list)  # links found inside the source content

    countries: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    organizations: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)

    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)

    cves: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    mitre_attack_techniques: list[AttackTechnique] = Field(default_factory=list)

    cvss_score: float | None = None
    cvss_severity: str | None = None
    kev_status: KevStatus = KevStatus.NOT_LISTED
    kev_date_added: date | None = None
    kev_ransomware_use: str | None = None

    exploitation_status: ExploitationStatus = ExploitationStatus.UNKNOWN
    exploitation_evidence: str | None = None
    poc_public: bool = False
    zero_day: bool = False

    confidence: Confidence = Confidence.UNVERIFIED
    confidence_reasons: list[str] = Field(default_factory=list)
    attribution: Attribution | None = None
    claim_flags: list[ClaimFlag] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)

    # Deterministic ranking components (0..N points each; see intelligence/score.py)
    exploitation_score: float = 0.0
    severity_score: float = 0.0
    source_quality_score: float = 0.0
    global_impact_score: float = 0.0
    novelty_score: float = 0.0
    relevance_score: float = 0.0
    corroboration_score: float = 0.0
    recency_score: float = 0.0
    final_priority_score: float = 0.0
    score_reasons: list[str] = Field(default_factory=list)

    raw_hash: str = ""
    member_hashes: list[str] = Field(default_factory=list)
    fingerprint: str = ""

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    previously_briefed: bool = False
    last_briefed_at: datetime | None = None
    material_update: str | None = None
    injection_flagged: bool = False

    @property
    def all_source_refs(self) -> list[SourceRef]:
        return list(self.corroborating_sources)

    @property
    def all_urls(self) -> list[str]:
        urls: list[str] = []
        for u in [self.primary_source_url, self.source_url, *[s.url for s in self.corroborating_sources]]:
            if u and u not in urls:
                urls.append(u)
        return urls


class EventUpdate(BaseModel):
    """A material development recorded against a previously seen event."""

    event_id: str
    run_id: str
    occurred_at: datetime
    description: str
    old_fingerprint: str | None = None
    new_fingerprint: str | None = None


class StoredEvent(BaseModel):
    event: CyberEvent
    first_seen: datetime
    last_seen: datetime
    times_briefed: int = 0
    last_briefed_at: datetime | None = None
    fingerprint: str = ""


# --------------------------------------------------------------------------------------
# Synthesis layer (LLM input / output contracts)
# --------------------------------------------------------------------------------------


class EvidenceSource(BaseModel):
    label: str  # short publisher label, e.g. "CISA", "Microsoft", "BleepingComputer"
    url: str
    tier: SourceTier


class EvidenceItem(BaseModel):
    """What the analyst model is allowed to know about one event. Text fields are sanitized."""

    ref: str  # E1, E2, ...
    event_id: str
    title: str
    summary: str
    event_type: EventType
    published: str | None = None
    sources: list[EvidenceSource]
    cves: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    kev_status: KevStatus = KevStatus.NOT_LISTED
    exploitation_status: ExploitationStatus = ExploitationStatus.UNKNOWN
    confidence: Confidence = Confidence.UNVERIFIED
    attribution_statement: str | None = None
    claim_flags: list[ClaimFlag] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    techniques: list[AttackTechnique] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    material_update: str | None = None
    priority_score: float = 0.0
    score_reasons: list[str] = Field(default_factory=list)


class EvidencePack(BaseModel):
    date_label: str  # e.g. "AUG 26"
    items: list[EvidenceItem]
    sources_checked: int
    sources_ok: int
    events_analyzed: int
    max_events: int
    max_chars: int
    quiet: bool = False  # nothing passed the priority threshold

    @property
    def allowed_urls(self) -> set[str]:
        return {s.url for item in self.items for s in item.sources}

    @property
    def allowed_cves(self) -> set[str]:
        return {c for item in self.items for c in item.cves}

    @property
    def refs(self) -> dict[str, EvidenceItem]:
        return {item.ref: item for item in self.items}


class BriefItem(BaseModel):
    """One story in the briefing. ``ref`` MUST be an evidence ref; ``source_url`` MUST be from that evidence."""

    model_config = ConfigDict(extra="ignore")

    ref: str
    section: BriefSection
    headline: str = Field(max_length=220)
    why_it_matters: str = Field(default="", max_length=260)
    confidence: Confidence = Confidence.UNVERIFIED
    source_label: str = Field(default="", max_length=40)
    source_url: str


class LearnTopic(BaseModel):
    model_config = ConfigDict(extra="ignore")

    topic: str = Field(max_length=120)
    technique_id: str | None = None
    why: str = Field(default="", max_length=200)


class BriefingDraft(BaseModel):
    """Exactly the JSON object the analyst model must return."""

    model_config = ConfigDict(extra="ignore")

    items: list[BriefItem] = Field(default_factory=list)
    prep: list[str] = Field(default_factory=list)
    learn: LearnTopic | None = None
    watch: list[str] = Field(default_factory=list)


class Briefing(BaseModel):
    """Validated, rendered briefing ready for delivery.

    This is the transport-neutral core: the validated draft (only the stories that were rendered),
    the evidence items those stories cite, run counts, and a canonical plain-text rendering used for
    hashing, validation and display. Transport renderers (SMS in :mod:`arkham.intelligence.brief`,
    Discord in :mod:`arkham.delivery.discord_format`) fill ``text``/``messages`` in their own shape;
    ``messages`` is always plain text, one entry per transport message, in send order.
    """

    date_label: str  # short, e.g. "AUG 26"
    date_long: str = ""  # e.g. "Wednesday, August 26, 2026" (rich transports)
    title: str = "Intelligence Brief"
    draft: BriefingDraft
    evidence: list[EvidenceItem] = Field(default_factory=list)  # cited evidence, same order as draft.items
    quiet: bool = False
    events_analyzed: int = 0
    sources_checked: int = 0
    sources_ok: int = 0
    generated_by: str = ""
    text: str = ""  # full rendered plain text (all messages joined with a blank line)
    messages: list[str] = Field(default_factory=list)  # plain-text delivery units in send order
    validation_notes: list[str] = Field(default_factory=list)

    @property
    def evidence_by_ref(self) -> dict[str, EvidenceItem]:
        return {item.ref: item for item in self.evidence}

    @property
    def allowed_urls(self) -> set[str]:
        return {source.url for item in self.evidence for source in item.sources}


class LLMUsage(BaseModel):
    provider: str = ""
    model: str = ""
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: LLMUsage) -> None:
        self.calls += other.calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens


class ModelOutput(BaseModel):
    draft: BriefingDraft
    raw_text: str
    usage: LLMUsage


# --------------------------------------------------------------------------------------
# Delivery and run accounting
# --------------------------------------------------------------------------------------


class DeliveryResult(BaseModel):
    """Safe delivery metadata: never a destination, credential, webhook URL or message body."""

    status: DeliveryStatus
    provider: str
    recipient_masked: str = ""
    message_ids: list[str] = Field(default_factory=list)
    messages_sent: int = 0
    segments: int = 0  # SMS only; 0 for other transports
    attempts: int = 0  # HTTP attempts across all messages, including retries
    delivered_at: datetime | None = None
    error: str | None = None


class CostMetrics(BaseModel):
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    llm_cost_usd: float | None = None
    delivery_provider: str = ""
    delivery_messages: int = 0
    sms_messages: int = 0
    sms_segments: int = 0
    sms_cost_usd: float | None = None
    run_cost_usd: float | None = None
    monthly_estimate_usd: float | None = None
    llm_priced: bool = False
    sms_priced: bool = False


class RunRecord(BaseModel):
    run_id: str
    mode: str  # scheduled | dry-run | force
    started_at: datetime
    finished_at: datetime | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    status: str = "running"  # running | success | failed | no-send
    sources_checked: int = 0
    sources_successful: int = 0
    raw_items: int = 0
    normalized_items: int = 0
    off_topic_items: int = 0
    duplicates_removed: int = 0
    correlated_events: int = 0
    unique_events: int = 0
    events_scored: int = 0
    candidate_events: int = 0
    events_selected: int = 0
    evidence_items: int = 0
    briefing_chars: int = 0
    briefing_messages: int = 0
    llm_calls: int = 0
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0
    estimated_llm_cost: float | None = None
    sms_segments: int = 0
    delivery_provider: str = ""
    delivery_messages: int = 0
    delivery_attempts: int = 0
    delivery_status: DeliveryStatus = DeliveryStatus.NOT_ATTEMPTED
    error: str | None = None
    source_statuses: list[SourceStatus] = Field(default_factory=list)
    cost: CostMetrics | None = None
    briefing_hash: str | None = None
    crawl: CrawlMetrics = Field(default_factory=CrawlMetrics)
