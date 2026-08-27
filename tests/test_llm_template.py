"""Tests for the deterministic, network-free template model."""

from __future__ import annotations

import json

from arkham.intelligence.llm.template import TemplateModel
from arkham.models import AttackTechnique, BriefingDraft, BriefSection, Confidence, EventType, EvidencePack
from tests.test_synthesize import (
    CITRIX_ADVISORY_URL,
    GITEA_ADVISORY_URL,
    all_events,
    build_pack,
    citrix_kev_event,
    gitea_event,
    iran_event,
    paylogix_event,
    takedown_event,
    unit42_event,
)


def _draft(pack: EvidencePack) -> BriefingDraft:
    return TemplateModel().synthesize(pack).draft


def test_label_and_usage_are_zero() -> None:
    model = TemplateModel()
    assert model.provider == "template"
    assert model.label == "template"
    out = model.synthesize(build_pack(all_events()))
    assert out.usage.provider == "template"
    assert (out.usage.calls, out.usage.input_tokens, out.usage.output_tokens) == (0, 0, 0)
    assert json.loads(out.raw_text)["items"]


def test_kev_item_becomes_critical_with_cve_headline_and_vendor_source() -> None:
    event = citrix_kev_event()
    pack = build_pack([event])
    draft = _draft(pack)
    assert len(draft.items) == 1
    item = draft.items[0]
    assert item.ref == "E1"
    assert item.section is BriefSection.CRITICAL
    assert item.headline.startswith("CVE-2026-8452: Citrix NetScaler ADC")
    assert len(item.headline) <= 140
    assert item.confidence is Confidence.CONFIRMED
    assert item.source_url == CITRIX_ADVISORY_URL
    assert item.source_label == "Citrix"
    assert item.source_url in pack.allowed_urls
    assert item.why_it_matters.startswith("New CISA KEV: exploitation confirmed")
    assert "Citrix NetScaler" in item.why_it_matters
    assert len(item.why_it_matters) <= 100
    assert any(p.startswith("Patch/mitigate Citrix NetScaler ADC") for p in draft.prep), draft.prep


def test_headline_not_prefixed_when_title_already_names_cve() -> None:
    event = citrix_kev_event()
    event.title = "CVE-2026-8452 exploited in Citrix NetScaler appliances"
    item = _draft(build_pack([event])).items[0]
    assert item.headline == "CVE-2026-8452 exploited in Citrix NetScaler appliances"


def test_incident_with_ransomware_claim_is_marked_unconfirmed() -> None:
    draft = _draft(build_pack([paylogix_event()]))
    item = draft.items[0]
    assert item.section is BriefSection.INCIDENT
    assert item.confidence is Confidence.MODERATE
    assert item.why_it_matters.endswith("Claimed by Akira; independently unconfirmed.")
    assert item.why_it_matters.startswith("The benefits management firm Paylogix told regulators")
    assert "Check finance third-party exposure" in draft.prep
    assert "Review Akira TTPs and indicators" in draft.prep
    assert 2 <= len(draft.prep) <= 4


def test_sections_by_event_type() -> None:
    draft = _draft(build_pack([takedown_event(), iran_event(), unit42_event(), gitea_event()]))
    sections = {i.ref: i.section for i in draft.items}
    assert sections == {
        "E1": BriefSection.POLICY,
        "E2": BriefSection.THREAT,
        "E3": BriefSection.RESEARCH,
        "E4": BriefSection.CRITICAL,
    }
    # gitea cites the GitHub advisory first (vendor advisory beats KEV and journalism)
    assert draft.items[3].source_url == GITEA_ADVISORY_URL


def test_prep_mentions_technique_actor_sector_and_is_bounded() -> None:
    draft = _draft(build_pack(all_events()))
    assert 2 <= len(draft.prep) <= 4
    assert draft.prep[0].startswith("Patch/mitigate Citrix NetScaler ADC and NetScaler Gateway if exposed")
    assert "Review detections for T1190 Exploit Public-Facing Application" in draft.prep
    assert len(set(draft.prep)) == len(draft.prep)
    assert all(len(p) <= 120 for p in draft.prep)


def test_learn_uses_first_technique_in_evidence() -> None:
    draft = _draft(build_pack(all_events()))
    assert draft.learn is not None
    assert draft.learn.technique_id == "T1190"
    assert draft.learn.topic == "Exploit Public-Facing Application - MITRE T1190"
    assert draft.learn.why == "appeared in today's evidence"


def test_learn_falls_back_to_keyword_concept_without_technique() -> None:
    draft = _draft(build_pack([paylogix_event()]))
    assert draft.learn is not None
    assert draft.learn.technique_id is None
    assert draft.learn.topic == "Ransomware initial access via exposed remote services"
    assert len(draft.learn.why) <= 100

    supply = _draft(build_pack([unit42_event()]))
    assert supply.learn is not None
    assert supply.learn.topic == "Software supply-chain attestation (SLSA)"

    takedown = _draft(build_pack([takedown_event()]))
    assert takedown.learn is not None
    assert takedown.learn.topic == "CISA KEV-driven patch prioritization"


def test_learn_keyword_map_covers_phishing_cloud_and_zero_day() -> None:
    base = takedown_event()
    for text, topic in (
        ("Phishing campaign abuses OAuth consent", "Phishing-resistant MFA"),
        ("Stolen cloud identity token used in intrusion", "OAuth token theft and session hijacking"),
        ("Zero-day exploited before patch", "Zero-day exposure management: virtual patching and WAF rules"),
    ):
        event = base.model_copy(update={"title": text})
        draft = _draft(build_pack([event]))
        assert draft.learn is not None and draft.learn.topic == topic, text


def test_quiet_pack_produces_watch_list_and_no_items() -> None:
    events = all_events()
    draft = _draft(build_pack(events, quiet=True))
    assert draft.items == []
    assert 2 <= len(draft.watch) <= 4
    assert all(len(w) <= 80 for w in draft.watch)
    assert draft.watch[0].startswith("Citrix NetScaler ADC")
    assert len(draft.prep) >= 2


def test_quiet_empty_pack_still_yields_watch_and_learn() -> None:
    draft = _draft(build_pack([], quiet=True))
    assert draft.items == []
    assert 2 <= len(draft.watch) <= 4
    assert draft.learn is not None
    assert 2 <= len(draft.prep) <= 4


def test_busy_pack_has_empty_watch_and_respects_max_events() -> None:
    events = all_events()
    draft = _draft(build_pack(events, max_events=3))
    assert draft.watch == []
    assert [i.ref for i in draft.items] == ["E1", "E2", "E3"]


def test_items_without_sources_are_skipped() -> None:
    event = paylogix_event()
    event.source_url = "http://therecord.media/plain"
    event.corroborating_sources = []
    pack = build_pack([event, citrix_kev_event()])
    assert pack.items[0].sources == []
    draft = _draft(pack)
    assert [i.ref for i in draft.items] == ["E2"]


def test_long_titles_are_trimmed_on_word_boundary() -> None:
    event = citrix_kev_event()
    event.title = "CVE-2026-8452 " + " ".join(["NetScaler"] * 40)
    item = _draft(build_pack([event])).items[0]
    assert len(item.headline) <= 140
    assert item.headline.endswith("...")
    assert "NetScaler" in item.headline


def test_technique_without_name_and_other_event_type() -> None:
    event = takedown_event()
    event.event_type = EventType.OTHER
    event.mitre_attack_techniques = [AttackTechnique(technique_id="T1583")]
    draft = _draft(build_pack([event]))
    assert draft.items[0].section is BriefSection.RESEARCH
    assert draft.learn is not None and draft.learn.topic == "MITRE T1583"
    assert "Review detections for T1583" in draft.prep


def test_template_is_deterministic() -> None:
    pack = build_pack(all_events())
    first = TemplateModel().synthesize(pack)
    second = TemplateModel().synthesize(pack)
    assert first.draft == second.draft
    assert first.raw_text == second.raw_text
