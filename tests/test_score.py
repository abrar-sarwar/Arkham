"""Tests for deterministic priority scoring (:mod:`arkham.intelligence.score`).

Every event is built from captured fixture data in ``tests/fixtures`` (CISA KEV catalog, NVD API,
journalism RSS feeds) rather than invented records; individual rule tests tweak single fields.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import feedparser
import pytest

from arkham.intelligence.score import WEIGHTS, score_event, score_events
from arkham.models import (
    Confidence,
    CyberEvent,
    EventType,
    ExploitationStatus,
    KevStatus,
    Region,
    SourceRef,
    SourceTier,
    sha256_hex,
)
from arkham.security.prompt_injection import sanitize_text
from arkham.sources.base import parse_datetime

FIXTURES = Path(__file__).parent / "fixtures"
# Live samples were captured on 2026-08-26 around 19:15 UTC; "now" sits just after them.
NOW = datetime(2026, 8, 26, 20, 0, tzinfo=timezone.utc)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ----------------------------------------------------------------------------- fixture builders


def _kev_record(cve_id: str) -> dict:
    catalog = json.loads((FIXTURES / "cisa_kev_sample.json").read_text(encoding="utf-8"))
    return next(v for v in catalog["vulnerabilities"] if v["cveID"] == cve_id)


def kev_event(cve_id: str, *, now: datetime = NOW) -> CyberEvent:
    """A CyberEvent as the KEV adapter + enrich stage would produce it for one catalog entry."""
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
        confidence=Confidence.CONFIRMED,
    )


def nvd_event(cve_id: str) -> CyberEvent:
    """A CyberEvent built from one NVD API record (no exploitation evidence)."""
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
        confidence=Confidence.CONFIRMED,
    )


def rss_event(
    fixture: str,
    index: int,
    *,
    publisher: str,
    source_name: str,
    event_type: EventType,
    tier: SourceTier = SourceTier.JOURNALISM,
) -> CyberEvent:
    """A CyberEvent built from one entry of a captured RSS fixture."""
    feed = feedparser.parse((FIXTURES / fixture).read_text(encoding="utf-8"))
    entry = feed.entries[index]
    return CyberEvent(
        id=sha256_hex("url", entry.link),
        title=sanitize_text(entry.title),
        summary=sanitize_text(entry.summary),
        event_type=event_type,
        published_at=parse_datetime(entry.published),
        source_name=source_name,
        source_url=entry.link,
        source_tier=tier,
        publisher=publisher,
    )


def bleeping(index: int, event_type: EventType) -> CyberEvent:
    return rss_event("rss_bleeping.xml", index, publisher="BleepingComputer", source_name="BleepingComputer", event_type=event_type)


def therecord(index: int, event_type: EventType) -> CyberEvent:
    return rss_event("rss_therecord.xml", index, publisher="The Record", source_name="The Record", event_type=event_type)


def ref(publisher: str, tier: SourceTier, url: str) -> SourceRef:
    return SourceRef(source_id=publisher.lower().replace(" ", "_"), source_name=publisher, source_tier=tier, url=url, publisher=publisher)


# ----------------------------------------------------------------------------- headline behaviours


def test_kev_exploited_beats_bare_cvss_98() -> None:
    """Spec: an exploited lower-CVSS vulnerability outranks an unexploited CVSS 9.8."""
    kev = score_event(kev_event("CVE-2026-8452"), now=NOW)  # Citrix NetScaler, newly added to KEV, no CVSS
    bare = score_event(nvd_event("CVE-2016-8735"), now=NOW)  # Apache Tomcat, CVSS 9.8, no exploitation

    assert kev.cvss_score is None
    assert bare.cvss_score == 9.8
    assert kev.final_priority_score > bare.final_priority_score
    assert kev.exploitation_score == WEIGHTS["exploitation.active"] + WEIGHTS["kev.newly_added"]
    assert any("CISA KEV" in reason for reason in kev.score_reasons)
    assert bare.exploitation_score == 0


def test_weight_table_matches_spec() -> None:
    expected = {
        "exploitation.active": 30,
        "kev.newly_added": 30,
        "exploitation.zero_day": 25,
        "impact.critical_infrastructure": 15,
        "impact.supply_chain": 20,
        "impact.state_backed": 12,
        "corroboration.two_publishers": 10,
        "source.tier1": 10,
        "severity.cvss_critical": 10,
        "impact.major_org": 8,
        "novelty.material_update": 10,
        "exploitation.widespread": 35,
        "exploitation.poc_public": 12,
        "kev.listed": 20,
        "severity.cvss_high": 6,
        "severity.cvss_elevated": 3,
        "severity.vuln_class": 3,
        "severity.cap": 13,
        "source.tier2": 6,
        "source.tier3": 2,
        "impact.sensitive_sector": 4,
        "impact.global_reach": 3,
        "impact.cap": 45,
        "corroboration.three_plus_publishers": 12,
        "corroboration.tier_mix": 2,
        "novelty.new": 5,
        "novelty.already_briefed": -60,
        "recency.12h": 5,
        "recency.24h": 3,
        "recency.48h": 1,
        "relevance.off_topic": -50,
        "relevance.ransomware": 2,
        "relevance.injection_flagged": -10,
    }
    for key, value in expected.items():
        assert WEIGHTS[key] == value, key
    assert WEIGHTS["relevance.exploitation"] == 8
    assert WEIGHTS["relevance.incident"] == 6
    assert WEIGHTS["relevance.threat_activity"] == 6
    assert WEIGHTS["relevance.vulnerability"] == 5
    assert WEIGHTS["relevance.advisory"] == 4
    assert WEIGHTS["relevance.policy"] == 4
    assert WEIGHTS["relevance.research"] == 3
    assert WEIGHTS["relevance.other"] == 0
    assert all(isinstance(v, int | float) for v in WEIGHTS.values())


def test_determinism_same_input_same_output() -> None:
    first = score_event(kev_event("CVE-2019-1068"), now=NOW)
    second = score_event(kev_event("CVE-2019-1068"), now=NOW)
    assert first.model_dump() == second.model_dump()
    # Re-scoring the same object is idempotent: reasons are rebuilt, not appended.
    again = score_event(first, now=NOW)
    assert again is first
    assert again.model_dump() == second.model_dump()
    assert len(again.score_reasons) == len(second.score_reasons)


def test_score_events_preserves_order_and_identity() -> None:
    events = [nvd_event("CVE-2017-10039"), kev_event("CVE-2026-8452"), bleeping(3, EventType.INCIDENT)]
    scored = score_events(events, NOW)
    assert [e.id for e in scored] == [e.id for e in events]
    assert all(a is b for a, b in zip(scored, events, strict=True))
    assert scored[1].final_priority_score > scored[0].final_priority_score
    assert scored[1].final_priority_score > scored[2].final_priority_score


# ----------------------------------------------------------------------------- exploitation component


def test_exploitation_newly_added_kev_and_active() -> None:
    event = score_event(kev_event("CVE-2026-8452"), now=NOW)
    assert event.exploitation_score == 60
    assert "active exploitation +30" in event.score_reasons
    assert "CISA KEV newly added +30" in event.score_reasons


def test_exploitation_older_kev_listing_scores_20() -> None:
    event = score_event(kev_event("CVE-2014-6278"), now=NOW)  # GNU Bash, added 2025-10-02
    assert event.kev_status is KevStatus.LISTED
    assert event.exploitation_score == 50
    assert "CISA KEV +20" in event.score_reasons


def test_exploitation_widespread_zero_day_and_poc() -> None:
    event = kev_event("CVE-2026-8452")
    event.exploitation_status = ExploitationStatus.WIDESPREAD
    event.zero_day = True
    score_event(event, now=NOW)
    assert event.exploitation_score == 35 + 25 + 30
    assert "zero-day +25" in event.score_reasons

    poc = nvd_event("CVE-2016-8735")
    poc.exploitation_status = ExploitationStatus.POC_PUBLIC
    score_event(poc, now=NOW)
    assert poc.exploitation_score == 12

    flag_only = nvd_event("CVE-2016-8735")
    flag_only.poc_public = True
    score_event(flag_only, now=NOW)
    assert flag_only.exploitation_score == 12
    assert "public PoC +12" in flag_only.score_reasons


# ----------------------------------------------------------------------------- severity component


@pytest.mark.parametrize(
    ("cvss", "expected"),
    [(9.8, 10), (9.0, 10), (8.1, 6), (8.0, 6), (7.5, 3), (7.0, 3), (6.8, 0), (None, 0)],
)
def test_severity_cvss_bands(cvss: float | None, expected: int) -> None:
    event = kev_event("CVE-2026-8452")  # title carries no vulnerability-class phrase
    event.cvss_score = cvss
    score_event(event, now=NOW)
    assert event.severity_score == expected


def test_severity_vuln_class_phrase_in_title_caps_at_13() -> None:
    event = kev_event("CVE-2019-1068")  # "Microsoft SQL Server Remote Code Execution Vulnerability"
    event.cvss_score = 9.8
    score_event(event, now=NOW)
    assert event.severity_score == 13
    assert any("remote code execution" in r for r in event.score_reasons)

    unauth = kev_event("CVE-2026-15409")  # SonicWall SSRF; summary mentions unauthenticated, title does not
    assert "unauthenticated" not in unauth.title.lower()
    score_event(unauth, now=NOW)
    assert unauth.severity_score == 0

    unauth.title = "SonicWall SMA1000 unauthenticated server-side request forgery"
    score_event(unauth, now=NOW)
    assert unauth.severity_score == 3


# ----------------------------------------------------------------------------- source quality component


def test_source_quality_uses_best_tier_present() -> None:
    assert score_event(kev_event("CVE-2026-8452"), now=NOW).source_quality_score == 10
    tier2 = rss_event("rss_therecord.xml", 2, publisher="Recorded Future", source_name="Recorded Future", event_type=EventType.THREAT_ACTIVITY, tier=SourceTier.RESEARCH)
    assert score_event(tier2, now=NOW).source_quality_score == 6
    journalism = bleeping(2, EventType.EXPLOITATION)
    assert score_event(journalism, now=NOW).source_quality_score == 2
    assert "tier-3 journalism source +2" in journalism.score_reasons

    corroborated = bleeping(2, EventType.EXPLOITATION)  # Gitea flaw, reported citing CISA
    corroborated.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, KEV_URL)]
    score_event(corroborated, now=NOW)
    assert corroborated.source_quality_score == 10
    assert "tier-1 primary source +10" in corroborated.score_reasons


# ----------------------------------------------------------------------------- global impact component


def test_global_impact_tags_sectors_regions() -> None:
    event = therecord(1, EventType.THREAT_ACTIVITY)  # DOJ takedown of Chinese state-backed tools
    event.keywords = ["tag:state-backed"]
    event.sectors = ["government"]
    event.regions = [Region.US.value, Region.CHINA.value]
    score_event(event, now=NOW)
    assert event.global_impact_score == 12 + 4
    assert "state-backed +12" in event.score_reasons
    assert any(r.startswith("sensitive sector") and r.endswith("+4") for r in event.score_reasons)

    event.regions = [Region.US.value, Region.CHINA.value, Region.EU.value]
    score_event(event, now=NOW)
    assert event.global_impact_score == 12 + 4 + 3

    event.regions = [Region.GLOBAL.value]
    score_event(event, now=NOW)
    assert event.global_impact_score == 12 + 4 + 3


def test_global_impact_caps_at_45() -> None:
    event = therecord(1, EventType.THREAT_ACTIVITY)
    event.keywords = ["tag:supply-chain", "tag:critical-infrastructure", "tag:state-backed", "tag:major-org"]
    event.sectors = ["energy", "water"]
    event.regions = [Region.GLOBAL.value]
    score_event(event, now=NOW)
    assert event.global_impact_score == 45
    assert "supply-chain +20" in event.score_reasons
    assert "critical-infrastructure +15" in event.score_reasons
    assert "major org +8" in event.score_reasons


# ----------------------------------------------------------------------------- corroboration component


def test_corroboration_distinct_publishers_and_tier_mix() -> None:
    event = bleeping(0, EventType.EXPLOITATION)  # SharePoint RCE chain, journalism
    score_event(event, now=NOW)
    assert event.corroboration_score == 0

    event.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, KEV_URL)]
    score_event(event, now=NOW)
    assert event.corroboration_score == 10
    assert "2 publishers +10" in event.score_reasons

    event.corroborating_sources.append(ref("Talos", SourceTier.RESEARCH, "https://blog.talosintelligence.com/"))
    score_event(event, now=NOW)
    assert event.corroboration_score == 12 + 2
    assert "3 publishers +12" in event.score_reasons
    assert "tier-1 and tier-2 sources +2" in event.score_reasons

    # The same publisher repeated (two CISA URLs) does not count twice.
    dup = bleeping(0, EventType.EXPLOITATION)
    dup.corroborating_sources = [ref("CISA", SourceTier.PRIMARY, KEV_URL), ref("cisa", SourceTier.PRIMARY, "https://www.cisa.gov/news-events/alerts")]
    score_event(dup, now=NOW)
    assert dup.corroboration_score == 10


# ----------------------------------------------------------------------------- novelty component


def test_novelty_new_briefed_and_material_update() -> None:
    fresh = kev_event("CVE-2026-8452")
    score_event(fresh, now=NOW)
    assert fresh.novelty_score == 5
    assert "new +5" in fresh.score_reasons

    seen_now = kev_event("CVE-2026-8452")
    seen_now.first_seen = NOW
    score_event(seen_now, now=NOW)
    assert seen_now.novelty_score == 5

    seen_before = kev_event("CVE-2026-8452")
    seen_before.first_seen = NOW - timedelta(days=3)
    score_event(seen_before, now=NOW)
    assert seen_before.novelty_score == 0

    briefed = kev_event("CVE-2026-8452")
    briefed.first_seen = NOW - timedelta(days=3)
    briefed.previously_briefed = True
    score_event(briefed, now=NOW)
    assert briefed.novelty_score == -60
    assert "already briefed -60" in briefed.score_reasons

    updated = kev_event("CVE-2026-8452")
    updated.first_seen = NOW - timedelta(days=3)
    updated.previously_briefed = True
    updated.material_update = "added to CISA KEV"
    score_event(updated, now=NOW)
    assert updated.novelty_score == 10
    assert "material update +10" in updated.score_reasons


# ----------------------------------------------------------------------------- recency component


@pytest.mark.parametrize(("hours_ago", "expected"), [(1, 5), (12, 5), (20, 3), (24, 3), (40, 1), (48, 1), (60, 0)])
def test_recency_bands(hours_ago: int, expected: int) -> None:
    event = bleeping(3, EventType.INCIDENT)
    event.published_at = NOW - timedelta(hours=hours_ago)
    event.updated_at = None
    score_event(event, now=NOW)
    assert event.recency_score == expected


def test_recency_uses_latest_of_published_and_updated() -> None:
    event = nvd_event("CVE-2016-8735")  # published 2017, lastModified 2026-08-25T16:28Z
    score_event(event, now=NOW)
    assert event.recency_score == 1  # 27.5h before NOW
    event.updated_at = None
    score_event(event, now=NOW)
    assert event.recency_score == 0
    event.published_at = None
    score_event(event, now=NOW)
    assert event.recency_score == 0


# ----------------------------------------------------------------------------- relevance component


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        (EventType.EXPLOITATION, 8),
        (EventType.INCIDENT, 6),
        (EventType.THREAT_ACTIVITY, 6),
        (EventType.VULNERABILITY, 5),
        (EventType.ADVISORY, 4),
        (EventType.POLICY, 4),
        (EventType.RESEARCH, 3),
        (EventType.OTHER, 0),
    ],
)
def test_relevance_event_type_base(event_type: EventType, expected: int) -> None:
    event = bleeping(0, event_type)
    score_event(event, now=NOW)
    assert event.relevance_score == expected


def test_relevance_off_topic_ransomware_and_injection() -> None:
    off_topic = bleeping(1, EventType.OTHER)  # Windows 11 privacy controls
    off_topic.keywords = ["tag:off-topic"]
    score_event(off_topic, now=NOW)
    assert off_topic.relevance_score == -50
    assert "off-topic -50" in off_topic.score_reasons
    assert off_topic.final_priority_score == 0

    ransomware = therecord(4, EventType.INCIDENT)  # Paylogix / Akira
    ransomware.keywords = ["tag:ransomware"]
    score_event(ransomware, now=NOW)
    assert ransomware.relevance_score == 6 + 2

    flagged = therecord(4, EventType.INCIDENT)
    flagged.injection_flagged = True
    score_event(flagged, now=NOW)
    assert flagged.relevance_score == 6 - 10
    assert "prompt-injection content -10" in flagged.score_reasons


# ----------------------------------------------------------------------------- final score


def test_final_score_is_sum_clamped_to_0_100() -> None:
    top = kev_event("CVE-2019-1068")
    top.cvss_score = 9.8
    top.zero_day = True
    top.keywords = ["tag:supply-chain", "tag:major-org"]
    score_event(top, now=NOW)
    components = (
        top.exploitation_score
        + top.severity_score
        + top.source_quality_score
        + top.global_impact_score
        + top.corroboration_score
        + top.novelty_score
        + top.recency_score
        + top.relevance_score
    )
    assert components > 100
    assert top.final_priority_score == 100

    modest = nvd_event("CVE-2017-10039")  # Oracle Agile PLM, CVSS 6.8
    score_event(modest, now=NOW)
    assert modest.final_priority_score == (
        modest.exploitation_score
        + modest.severity_score
        + modest.source_quality_score
        + modest.global_impact_score
        + modest.corroboration_score
        + modest.novelty_score
        + modest.recency_score
        + modest.relevance_score
    )
    assert 0 < modest.final_priority_score < 35

    buried = bleeping(1, EventType.OTHER)
    buried.keywords = ["tag:off-topic"]
    buried.previously_briefed = True
    buried.first_seen = NOW - timedelta(days=2)
    score_event(buried, now=NOW)
    assert buried.final_priority_score == 0
