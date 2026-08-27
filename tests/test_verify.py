"""Tests for confidence assignment, material-update detection and selection (:mod:`arkham.intelligence.verify`).

Events are built from captured fixture data in ``tests/fixtures`` (CISA KEV catalog, NVD API, journalism
RSS feeds); rule-specific tests adjust single fields on those real records.
"""

from __future__ import annotations

import json
import math
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import feedparser

from arkham.intelligence.score import score_event
from arkham.intelligence.verify import (
    SelectionResult,
    assign_confidence,
    compute_fingerprint,
    describe_material_update,
    reconcile_with_history,
    safe_attribution_sentence,
    select_events,
)
from arkham.models import (
    Attribution,
    ClaimFlag,
    Confidence,
    CyberEvent,
    EventType,
    ExploitationStatus,
    KevStatus,
    SourceRef,
    SourceTier,
    StoredEvent,
    sha256_hex,
)
from arkham.security.prompt_injection import sanitize_text
from arkham.sources.base import parse_datetime

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 8, 26, 20, 0, tzinfo=timezone.utc)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RANSOMWARE_PHRASE = "claimed by criminal group; independently unconfirmed"


# ----------------------------------------------------------------------------- fixture builders


def _kev_record(cve_id: str) -> dict:
    catalog = json.loads((FIXTURES / "cisa_kev_sample.json").read_text(encoding="utf-8"))
    return next(v for v in catalog["vulnerabilities"] if v["cveID"] == cve_id)


def kev_event(cve_id: str, *, now: datetime = NOW) -> CyberEvent:
    rec = _kev_record(cve_id)
    added = date.fromisoformat(rec["dateAdded"])
    newly_added = (now.date() - added) <= timedelta(days=1)
    return CyberEvent(
        id=sha256_hex("cve", cve_id.lower()),
        title=rec["vulnerabilityName"],
        summary=rec["shortDescription"].strip(),
        event_type=EventType.EXPLOITATION,
        published_at=datetime(added.year, added.month, added.day, tzinfo=timezone.utc),
        source_name="CISA Known Exploited Vulnerabilities",
        source_url=KEV_URL,
        source_tier=SourceTier.PRIMARY,
        publisher="CISA",
        primary_source_url=rec["notes"].split(" ; ")[0].strip(),
        products=[f"{rec['vendorProject']} {rec['product']}"],
        cves=[cve_id],
        cwes=list(rec["cwes"]),
        kev_status=KevStatus.NEWLY_ADDED if newly_added else KevStatus.LISTED,
        kev_date_added=added,
        kev_ransomware_use=rec["knownRansomwareCampaignUse"],
        exploitation_status=ExploitationStatus.ACTIVE,
        exploitation_evidence="Listed in CISA Known Exploited Vulnerabilities catalog",
    )


def nvd_event(cve_id: str) -> CyberEvent:
    data = json.loads((FIXTURES / "nvd_sample.json").read_text(encoding="utf-8"))
    cve = next(v["cve"] for v in data["vulnerabilities"] if v["cve"]["id"] == cve_id)
    metric = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
    description = next(d["value"] for d in cve["descriptions"] if d["lang"] == "en")
    return CyberEvent(
        id=sha256_hex("cve", cve_id.lower()),
        title=f"{cve_id}: {description[:120]}",
        summary=description,
        event_type=EventType.VULNERABILITY,
        published_at=parse_datetime(cve["published"]),
        updated_at=parse_datetime(cve["lastModified"]),
        source_name="NVD",
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        source_tier=SourceTier.PRIMARY,
        publisher="NVD",
        cves=[cve_id],
        cvss_score=metric["baseScore"],
        cvss_severity=metric["baseSeverity"],
    )


def rss_event(
    fixture: str,
    index: int,
    *,
    publisher: str,
    event_type: EventType,
    tier: SourceTier = SourceTier.JOURNALISM,
) -> CyberEvent:
    feed = feedparser.parse((FIXTURES / fixture).read_text(encoding="utf-8"))
    entry = feed.entries[index]
    return CyberEvent(
        id=sha256_hex("url", entry.link),
        title=sanitize_text(entry.title),
        summary=sanitize_text(entry.summary),
        event_type=event_type,
        published_at=parse_datetime(entry.published),
        source_name=publisher,
        source_url=entry.link,
        source_tier=tier,
        publisher=publisher,
    )


def bleeping(index: int, event_type: EventType) -> CyberEvent:
    return rss_event("rss_bleeping.xml", index, publisher="BleepingComputer", event_type=event_type)


def therecord(index: int, event_type: EventType) -> CyberEvent:
    return rss_event("rss_therecord.xml", index, publisher="The Record", event_type=event_type)


def ref(publisher: str, tier: SourceTier, url: str) -> SourceRef:
    return SourceRef(source_id=publisher.lower().replace(" ", "_"), source_name=publisher, source_tier=tier, url=url, publisher=publisher)


def stored(event: CyberEvent, *, first_seen: datetime, times_briefed: int, last_briefed_at: datetime | None = None) -> StoredEvent:
    return StoredEvent(
        event=event.model_copy(deep=True),
        first_seen=first_seen,
        last_seen=first_seen,
        times_briefed=times_briefed,
        last_briefed_at=last_briefed_at,
        fingerprint=event.fingerprint or compute_fingerprint(event),
    )


def pipeline(event: CyberEvent, previous: StoredEvent | None, *, now: datetime) -> CyberEvent:
    """The runner's per-event order: confidence -> history -> score."""
    assign_confidence(event)
    reconcile_with_history(event, previous, now=now)
    score_event(event, now=now)
    return event


# ----------------------------------------------------------------------------- confidence ladder


def test_ransomware_claim_without_primary_source_is_unverified() -> None:
    event = therecord(4, EventType.INCIDENT)  # Paylogix / Akira ransomware
    event.claim_flags = [ClaimFlag.RANSOMWARE_CLAIM]
    result = assign_confidence(event)
    assert result is event
    assert event.confidence is Confidence.UNVERIFIED
    assert RANSOMWARE_PHRASE in event.confidence_reasons
    assert any("claimed by" in r for r in event.confidence_reasons)


def test_ransomware_claim_stays_unverified_with_research_source_but_no_victim_confirmation() -> None:
    event = therecord(4, EventType.INCIDENT)
    event.claim_flags = [ClaimFlag.RANSOMWARE_CLAIM]
    event.corroborating_sources = [ref("Unit 42", SourceTier.RESEARCH, "https://unit42.paloaltonetworks.com/")]
    assert "confirmed" not in event.summary.lower()
    assign_confidence(event)
    assert event.confidence is Confidence.UNVERIFIED


def test_ransomware_claim_with_victim_confirmation_from_non_journalism_source_falls_through() -> None:
    event = therecord(4, EventType.INCIDENT)
    event.claim_flags = [ClaimFlag.RANSOMWARE_CLAIM]
    event.summary = event.summary + " The company confirmed the incident in its regulatory filing."
    event.corroborating_sources = [ref("Unit 42", SourceTier.RESEARCH, "https://unit42.paloaltonetworks.com/")]
    assign_confidence(event)
    assert event.confidence is Confidence.HIGH  # tier-2 + tier-3
    assert RANSOMWARE_PHRASE not in event.confidence_reasons


def test_ransomware_claim_with_tier1_source_is_not_unverified() -> None:
    event = therecord(4, EventType.INCIDENT)
    event.claim_flags = [ClaimFlag.RANSOMWARE_CLAIM]
    event.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, "https://www.cisa.gov/news-events/alerts")]
    assign_confidence(event)
    assert event.confidence is Confidence.HIGH  # tier-1 on a non-vulnerability type


def test_tier3_only_is_low_or_moderate_with_three_publishers() -> None:
    event = bleeping(3, EventType.INCIDENT)  # LACMA breach
    assign_confidence(event)
    assert event.confidence is Confidence.LOW
    assert any("journalism" in r.lower() for r in event.confidence_reasons)

    two = bleeping(3, EventType.INCIDENT)
    two.corroborating_sources = [ref("The Record", SourceTier.JOURNALISM, "https://therecord.media/")]
    assign_confidence(two)
    assert two.confidence is Confidence.LOW

    three = bleeping(3, EventType.INCIDENT)
    three.corroborating_sources = [
        ref("The Record", SourceTier.JOURNALISM, "https://therecord.media/"),
        ref("SecurityWeek", SourceTier.JOURNALISM, "https://www.securityweek.com/"),
    ]
    assign_confidence(three)
    assert three.confidence is Confidence.MODERATE


def test_tier1_confirms_vulnerability_types_and_is_high_otherwise() -> None:
    kev = assign_confidence(kev_event("CVE-2026-8452"))
    assert kev.confidence is Confidence.CONFIRMED
    assert any("tier-1" in r and "CISA" in r for r in kev.confidence_reasons)

    nvd = assign_confidence(nvd_event("CVE-2016-8735"))
    assert nvd.confidence is Confidence.CONFIRMED

    advisory = kev_event("CVE-2019-1068")
    advisory.event_type = EventType.ADVISORY
    assert assign_confidence(advisory).confidence is Confidence.CONFIRMED

    incident = therecord(1, EventType.THREAT_ACTIVITY)  # DOJ takedown reported by The Record
    incident.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, "https://www.cisa.gov/news-events/alerts")]
    assert assign_confidence(incident).confidence is Confidence.HIGH


def test_tier2_research_moderate_alone_high_when_corroborated() -> None:
    alone = rss_event("rss_therecord.xml", 2, publisher="Recorded Future", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    assign_confidence(alone)
    assert alone.confidence is Confidence.MODERATE

    with_journalism = rss_event("rss_therecord.xml", 2, publisher="Recorded Future", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    with_journalism.corroborating_sources = [ref("The Record", SourceTier.JOURNALISM, "https://therecord.media/")]
    assign_confidence(with_journalism)
    assert with_journalism.confidence is Confidence.HIGH

    two_research = rss_event("rss_therecord.xml", 2, publisher="Recorded Future", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    two_research.corroborating_sources = [ref("Talos", SourceTier.RESEARCH, "https://blog.talosintelligence.com/")]
    assign_confidence(two_research)
    assert two_research.confidence is Confidence.HIGH


def test_reported_not_confirmed_caps_at_moderate() -> None:
    event = rss_event("rss_therecord.xml", 2, publisher="Recorded Future", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    event.corroborating_sources = [ref("The Record", SourceTier.JOURNALISM, "https://therecord.media/")]
    event.claim_flags = [ClaimFlag.REPORTED_NOT_CONFIRMED]
    assign_confidence(event)
    assert event.confidence is Confidence.MODERATE
    assert any("MODERATE" in r for r in event.confidence_reasons)

    low = bleeping(3, EventType.INCIDENT)
    low.claim_flags = [ClaimFlag.REPORTED_NOT_CONFIRMED]
    assign_confidence(low)
    assert low.confidence is Confidence.LOW  # a cap never raises


def test_statistic_unverified_adds_reason_without_changing_level() -> None:
    event = kev_event("CVE-2026-15409")  # SonicWall, ransomware use "Known"
    event.claim_flags = [ClaimFlag.STATISTIC_UNVERIFIED]
    assign_confidence(event)
    assert event.confidence is Confidence.CONFIRMED
    assert any("unverified" in r.lower() for r in event.confidence_reasons)


def test_assign_confidence_is_idempotent() -> None:
    event = bleeping(3, EventType.INCIDENT)
    assign_confidence(event)
    first = list(event.confidence_reasons)
    assign_confidence(event)
    assert event.confidence_reasons == first


# ----------------------------------------------------------------------------- attribution


def test_tier3_attribution_capped_at_low_and_flagged() -> None:
    event = therecord(1, EventType.THREAT_ACTIVITY)  # "alleged Chinese hacking tools"
    event.attribution = Attribution(
        actor="Chinese state-backed operators",
        attributed_by="US Department of Justice",
        confidence=Confidence.HIGH,
        statement="said it disrupted Chinese state-backed tools",
    )
    assign_confidence(event)
    assert event.confidence is Confidence.LOW
    assert event.attribution.confidence is Confidence.LOW
    assert ClaimFlag.ATTRIBUTION_SUSPECTED in event.claim_flags
    assert event.claim_flags.count(ClaimFlag.ATTRIBUTION_SUSPECTED) == 1
    assert any("attribution" in r.lower() for r in event.confidence_reasons)


def test_attribution_from_research_source_is_kept_and_never_raises_event_confidence() -> None:
    event = rss_event("rss_therecord.xml", 2, publisher="Google", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    event.attribution = Attribution(
        actor="an Iran-nexus actor",
        attributed_by="Google Threat Intelligence Group",
        confidence=Confidence.HIGH,
        statement="assesses with high confidence",
    )
    assign_confidence(event)
    assert event.confidence is Confidence.MODERATE  # single tier-2 source; HIGH attribution does not lift it
    assert event.attribution.confidence is Confidence.HIGH
    assert ClaimFlag.ATTRIBUTION_SUSPECTED not in event.claim_flags


def test_safe_attribution_sentence_uses_only_attribution_fields() -> None:
    event = therecord(2, EventType.THREAT_ACTIVITY)
    assert safe_attribution_sentence(event) is None
    event.attribution = Attribution(
        actor="a China-nexus actor",
        attributed_by="Google",
        confidence=Confidence.MODERATE,
        statement="assesses with moderate confidence",
    )
    assert safe_attribution_sentence(event) == "Google assesses the activity is associated with a China-nexus actor (MODERATE CONFIDENCE)."
    event.attribution.confidence = Confidence.CONFIRMED
    assert safe_attribution_sentence(event) == "Google confirms the activity is associated with a China-nexus actor (CONFIRMED)."
    event.attribution.confidence = Confidence.LOW
    event.attribution.actor = "  Iran-linked   group "
    assert safe_attribution_sentence(event) == "Google suspects the activity is associated with Iran-linked group (LOW CONFIDENCE)."


# ----------------------------------------------------------------------------- fingerprint


def test_fingerprint_is_stable_and_ignores_prose() -> None:
    a = assign_confidence(kev_event("CVE-2026-8452"))
    b = assign_confidence(kev_event("CVE-2026-8452"))
    assert compute_fingerprint(a) == compute_fingerprint(b)
    assert len(compute_fingerprint(a)) == 64
    b.summary = b.summary + " (re-worded by a second outlet)"
    b.title = b.title.upper()
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_changes_on_material_state_only() -> None:
    base = assign_confidence(nvd_event("CVE-2016-8735"))
    fp = compute_fingerprint(base)

    kev = base.model_copy(deep=True)
    kev.kev_status = KevStatus.NEWLY_ADDED
    assert compute_fingerprint(kev) != fp

    same_band = base.model_copy(deep=True)
    same_band.cvss_score = 9.1
    assert compute_fingerprint(same_band) == fp
    lower_band = base.model_copy(deep=True)
    lower_band.cvss_score = 8.9
    assert compute_fingerprint(lower_band) != fp

    two_pubs = base.model_copy(deep=True)
    two_pubs.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, KEV_URL)]
    assert compute_fingerprint(two_pubs) != fp

    attributed = base.model_copy(deep=True)
    attributed.attribution = Attribution(actor="UNC1234", attributed_by="Google", confidence=Confidence.LOW, statement="suspects")
    assert compute_fingerprint(attributed) != fp

    downgraded = base.model_copy(deep=True)
    downgraded.confidence = Confidence.LOW
    assert compute_fingerprint(downgraded) != fp


# ----------------------------------------------------------------------------- material updates


def test_describe_material_update_none_when_nothing_changed() -> None:
    event = assign_confidence(kev_event("CVE-2026-8452"))
    previous = stored(event, first_seen=NOW - timedelta(days=1), times_briefed=1)
    assert describe_material_update(previous, event) is None


def test_describe_material_update_kev_and_exploitation() -> None:
    before = assign_confidence(nvd_event("CVE-2016-8735"))
    previous = stored(before, first_seen=NOW - timedelta(days=5), times_briefed=1)
    after = before.model_copy(deep=True)
    after.kev_status = KevStatus.NEWLY_ADDED
    after.exploitation_status = ExploitationStatus.ACTIVE
    text = describe_material_update(previous, after)
    assert text is not None
    assert "added to CISA KEV" in text
    assert "exploitation escalated (unknown -> active)" in text
    assert "; " in text


def test_describe_material_update_poc_zero_day_cvss_and_confidence() -> None:
    before = bleeping(0, EventType.EXPLOITATION)  # SharePoint RCE chain
    assign_confidence(before)  # LOW: journalism only
    previous = stored(before, first_seen=NOW - timedelta(days=2), times_briefed=1)
    after = before.model_copy(deep=True)
    after.poc_public = True
    after.zero_day = True
    after.cvss_score = 9.8
    after.corroborating_sources = [ref("Microsoft", SourceTier.PRIMARY, "https://msrc.microsoft.com/update-guide")]
    assign_confidence(after)  # CONFIRMED: tier-1 on an exploitation event
    text = describe_material_update(previous, after)
    assert text is not None
    assert "PoC now public" in text
    assert "now zero-day" in text
    assert "CVSS assigned 9.8" in text
    assert "corroboration grew to 2 publishers" in text
    assert "confidence raised to CONFIRMED" in text


def test_describe_material_update_cvss_raise_needs_new_integer_band() -> None:
    before = nvd_event("CVE-2017-10039")  # CVSS 6.8
    previous = stored(before, first_seen=NOW - timedelta(days=2), times_briefed=0)
    minor = before.model_copy(deep=True)
    minor.cvss_score = 6.9
    assert describe_material_update(previous, minor) is None
    raised = before.model_copy(deep=True)
    raised.cvss_score = 8.1
    assert describe_material_update(previous, raised) == "CVSS raised to 8.1"


def test_describe_material_update_corroboration_bands_and_attribution() -> None:
    before = therecord(2, EventType.THREAT_ACTIVITY)
    before.corroborating_sources = [ref("SecurityWeek", SourceTier.JOURNALISM, "https://www.securityweek.com/")]  # 2 publishers
    previous = stored(before, first_seen=NOW - timedelta(days=1), times_briefed=1)

    still_two = before.model_copy(deep=True)
    still_two.corroborating_sources.append(ref("securityweek", SourceTier.JOURNALISM, "https://www.securityweek.com/other"))
    assert describe_material_update(previous, still_two) is None

    three = before.model_copy(deep=True)
    three.corroborating_sources.append(ref("BleepingComputer", SourceTier.JOURNALISM, "https://www.bleepingcomputer.com/"))
    assert describe_material_update(previous, three) == "corroboration grew to 3 publishers"

    attributed = before.model_copy(deep=True)
    attributed.attribution = Attribution(actor="MuddyWater", attributed_by="Recorded Future", confidence=Confidence.MODERATE, statement="assesses")
    text = describe_material_update(previous, attributed)
    assert text == "attribution added: MuddyWater (per Recorded Future)"

    changed_prev = stored(attributed, first_seen=NOW - timedelta(days=1), times_briefed=1)
    changed = attributed.model_copy(deep=True)
    changed.attribution = Attribution(actor="APT34", attributed_by="Recorded Future", confidence=Confidence.MODERATE, statement="assesses")
    assert describe_material_update(changed_prev, changed) == "attribution changed: MuddyWater -> APT34"

    four = three.model_copy(deep=True)
    four.corroborating_sources.append(ref("The Hacker News", SourceTier.JOURNALISM, "https://thehackernews.com/"))
    assert describe_material_update(stored(three, first_seen=NOW, times_briefed=0), four) is None  # 3 -> 4 is not material


# ----------------------------------------------------------------------------- history reconciliation


def test_reconcile_new_event_sets_first_seen_and_fingerprint() -> None:
    event = assign_confidence(kev_event("CVE-2026-8452"))
    result = reconcile_with_history(event, None, now=NOW)
    assert result is event
    assert event.first_seen == NOW
    assert event.last_seen == NOW
    assert event.previously_briefed is False
    assert event.last_briefed_at is None
    assert event.material_update is None
    assert event.fingerprint == compute_fingerprint(event)


def test_reconcile_previously_briefed_without_change() -> None:
    day1 = NOW - timedelta(days=1)
    event = assign_confidence(kev_event("CVE-2026-8452"))
    previous = stored(event, first_seen=day1, times_briefed=1, last_briefed_at=day1)
    today = assign_confidence(kev_event("CVE-2026-8452"))
    reconcile_with_history(today, previous, now=NOW)
    assert today.first_seen == day1
    assert today.last_seen == NOW
    assert today.previously_briefed is True
    assert today.last_briefed_at == day1
    assert today.material_update is None
    assert today.fingerprint == previous.fingerprint


def test_reconcile_seen_but_never_briefed() -> None:
    day1 = NOW - timedelta(days=1)
    event = assign_confidence(nvd_event("CVE-2017-10039"))
    previous = stored(event, first_seen=day1, times_briefed=0)
    today = assign_confidence(nvd_event("CVE-2017-10039"))
    reconcile_with_history(today, previous, now=NOW)
    assert today.previously_briefed is False
    assert today.first_seen == day1
    assert today.material_update is None


# ----------------------------------------------------------------------------- cross-day behaviour


def test_duplicate_suppression_between_days() -> None:
    day1 = NOW
    day2 = NOW + timedelta(days=1)
    event = pipeline(kev_event("CVE-2026-8452", now=day1), None, now=day1)
    first = select_events([event], max_events=8, min_priority=35, now=day1)
    assert [e.id for e in first.selected] == [event.id]

    previous = stored(event, first_seen=day1, times_briefed=1, last_briefed_at=day1)
    repeat = pipeline(kev_event("CVE-2026-8452", now=day2), previous, now=day2)
    assert repeat.previously_briefed is True
    assert repeat.material_update is None
    assert repeat.novelty_score == -60
    assert "already briefed -60" in repeat.score_reasons

    second = select_events([repeat], max_events=8, min_priority=35, now=day2)
    assert second.candidates == []
    assert second.selected == []
    assert second.suppressed_briefed == 1
    assert second.below_threshold == 0


def test_material_update_makes_briefed_event_eligible_again() -> None:
    day1 = NOW
    day5 = NOW + timedelta(days=4)
    tomcat = pipeline(nvd_event("CVE-2016-8735"), None, now=day1)  # CVSS 9.8, not exploited
    previous = stored(tomcat, first_seen=day1, times_briefed=1, last_briefed_at=day1)

    later = nvd_event("CVE-2016-8735")
    later.kev_status = KevStatus.NEWLY_ADDED
    later.kev_date_added = day5.date()
    later.exploitation_status = ExploitationStatus.ACTIVE
    later.event_type = EventType.EXPLOITATION
    later.updated_at = day5 - timedelta(hours=2)
    later.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, KEV_URL)]
    pipeline(later, previous, now=day5)

    assert later.previously_briefed is True
    assert later.material_update is not None
    assert "added to CISA KEV" in later.material_update
    assert "exploitation escalated (unknown -> active)" in later.material_update
    assert later.fingerprint != previous.fingerprint
    assert later.novelty_score == 10
    assert later.final_priority_score > tomcat.final_priority_score

    selection = select_events([later], max_events=8, min_priority=35, now=day5)
    assert [e.id for e in selection.candidates] == [later.id]
    assert [e.id for e in selection.selected] == [later.id]
    assert selection.suppressed_briefed == 0


# ----------------------------------------------------------------------------- selection


def _scored(event: CyberEvent, *, now: datetime = NOW) -> CyberEvent:
    return pipeline(event, None, now=now)


def test_select_threshold_and_off_topic_counts() -> None:
    top = _scored(kev_event("CVE-2026-8452"))
    modest = _scored(nvd_event("CVE-2017-10039"))  # CVSS 6.8, no exploitation
    off_topic = bleeping(1, EventType.OTHER)
    off_topic.keywords = ["tag:off-topic"]
    _scored(off_topic)
    events = [modest, off_topic, top]

    result = select_events(events, max_events=8, min_priority=35, now=NOW)
    assert isinstance(result, SelectionResult)
    assert top.final_priority_score >= 35 > modest.final_priority_score
    assert [e.id for e in result.candidates] == [top.id]
    assert [e.id for e in result.selected] == [top.id]
    assert result.below_threshold == 1
    assert result.off_topic == 1
    assert result.suppressed_briefed == 0

    everything = select_events(events, max_events=8, min_priority=0, now=NOW)
    assert result.candidates[0].id == top.id
    assert [e.id for e in everything.candidates] == [top.id, modest.id]
    assert everything.off_topic == 1
    assert everything.below_threshold == 0


def test_select_orders_by_score_then_recency() -> None:
    gitea = _scored(bleeping(2, EventType.EXPLOITATION))  # 11:07 UTC
    sharepoint = _scored(bleeping(0, EventType.EXPLOITATION))  # 14:47 UTC
    assert gitea.final_priority_score == sharepoint.final_priority_score
    result = select_events([gitea, sharepoint], max_events=8, min_priority=0, now=NOW)
    assert [e.id for e in result.candidates] == [sharepoint.id, gitea.id]

    stronger = _scored(kev_event("CVE-2026-8452"))
    result = select_events([gitea, stronger, sharepoint], max_events=8, min_priority=0, now=NOW)
    assert [e.id for e in result.candidates] == [stronger.id, sharepoint.id, gitea.id]


def test_select_respects_max_events() -> None:
    kev_ids = ["CVE-2021-23758", "CVE-2026-8452", "CVE-2019-1068", "CVE-2026-15409", "CVE-2014-6278"]
    events = [_scored(kev_event(c)) for c in kev_ids]
    result = select_events(events, max_events=2, min_priority=35, now=NOW)
    assert len(result.candidates) == 5
    assert len(result.selected) == 2
    assert result.selected[0].final_priority_score >= result.selected[1].final_priority_score
    assert select_events(events, max_events=0, min_priority=35, now=NOW).selected == []


def test_select_diversity_caps_vulnerability_types_when_other_types_remain() -> None:
    kev_ids = ["CVE-2021-23758", "CVE-2026-8452", "CVE-2019-1068", "CVE-2026-15409", "CVE-2014-6278", "CVE-2014-8361"]
    vulns = [_scored(kev_event(c)) for c in kev_ids]
    takedown = therecord(1, EventType.THREAT_ACTIVITY)
    takedown.corroborating_sources = [ref("US DOJ", SourceTier.PRIMARY, "https://www.justice.gov/")]
    iran = therecord(2, EventType.THREAT_ACTIVITY)
    iran.corroborating_sources = [ref("Recorded Future", SourceTier.RESEARCH, "https://www.recordedfuture.com/")]
    others = [_scored(takedown), _scored(iran)]
    assert all(v.final_priority_score > o.final_priority_score for v in vulns for o in others)

    max_events = 5
    cap = max(3, math.ceil(max_events * 0.6))
    result = select_events(vulns + others, max_events=max_events, min_priority=0, now=NOW)
    selected_vulns = [e for e in result.selected if e.event_type in (EventType.VULNERABILITY, EventType.EXPLOITATION)]
    selected_others = [e for e in result.selected if e.event_type not in (EventType.VULNERABILITY, EventType.EXPLOITATION)]
    assert len(result.selected) == max_events
    assert len(selected_vulns) == cap == 3
    assert {e.id for e in selected_others} == {takedown.id, iran.id}
    # Capped-out vulnerabilities are the lowest-scoring ones; the top vulnerabilities are kept in order.
    assert [e.id for e in selected_vulns] == [e.id for e in result.candidates if e.event_type is EventType.EXPLOITATION][:cap]

    # Without other types the cap is not applied: vulnerabilities fill every slot.
    only_vulns = select_events(vulns, max_events=max_events, min_priority=0, now=NOW)
    assert len(only_vulns.selected) == max_events
    assert all(e.event_type is EventType.EXPLOITATION for e in only_vulns.selected)

    # When the other types run out, remaining slots are filled from the deferred vulnerabilities.
    wide = select_events(vulns + others, max_events=8, min_priority=0, now=NOW)
    assert len(wide.selected) == 8
    assert len([e for e in wide.selected if e.event_type is EventType.EXPLOITATION]) == 6


def test_select_caps_tier3_only_publisher_at_two() -> None:
    stories = [_scored(therecord(i, EventType.THREAT_ACTIVITY)) for i in (1, 2, 3)]
    result = select_events(stories, max_events=8, min_priority=0, now=NOW)
    assert len(result.candidates) == 3
    assert len(result.selected) == 2
    assert all(e.publisher == "The Record" for e in result.selected)

    # A story corroborated by a non-journalism source is not "tier-3 only" and is exempt from the cap.
    corroborated = therecord(3, EventType.THREAT_ACTIVITY)
    corroborated.corroborating_sources = [ref("Europol", SourceTier.PRIMARY, "https://www.europol.europa.eu/")]
    _scored(corroborated)
    result = select_events(stories[:2] + [corroborated], max_events=8, min_priority=0, now=NOW)
    assert len(result.selected) == 3

    # Different tier-3 publishers each get their own allowance.
    mixed = stories[:2] + [_scored(bleeping(0, EventType.EXPLOITATION)), _scored(bleeping(2, EventType.EXPLOITATION))]
    result = select_events(mixed, max_events=8, min_priority=0, now=NOW)
    assert len(result.selected) == 4
