"""Bridge from an ExtractedArticle into the existing RawItem -> CyberEvent pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

from arkham.crawl.apply import enrich_raw_item
from arkham.crawl.extract import extract_article
from arkham.crawl.models import FetchMethod
from arkham.intelligence.normalize import normalize_items
from arkham.models import ExploitationStatus, RawItem, SourceCategory, SourceTier

URL = "https://research.example.org/report"
HTML = (
    "<html><head><title>FogRAT campaign | Research</title>"
    '<meta property="article:published_time" content="2026-08-26T08:00:00Z"></head>'
    "<body><article><h1>FogRAT campaign hits gateways</h1>"
    "<p>APT29 is actively exploiting CVE-2026-12345 (CWE-787) in Example Gateway appliances with FogRAT malware.</p>"
    "<p>The C2 domain evil.example resolved to 203.0.113.42; a proof-of-concept exploit is public.</p>"
    "<p>See the <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'>CISA KEV catalog</a> for details.</p>"
    "<p>Microsoft Exchange Server version 15.2.1118.7 is also affected, according to the vendor advisory.</p>"
    "</article></body></html>"
)


def raw_item(**overrides: object) -> RawItem:
    base = dict(
        source_id="research_blog",
        source_name="Research Blog",
        source_tier=SourceTier.RESEARCH,
        source_category=SourceCategory.RESEARCH,
        title="FogRAT campaign hits gateways",
        url=URL,
        summary="A feed summary.",
        extra={"references": ["https://example.org/existing"]},
    )
    base.update(overrides)
    return RawItem(**base)  # type: ignore[arg-type]


def article():
    return extract_article(HTML, response_url=URL, headers={"content-type": "text/html"})


def test_enrich_copies_bounded_text_and_structured_facts_without_mutating_the_original() -> None:
    item = raw_item()
    enriched = enrich_raw_item(item, article(), method=FetchMethod.HTTP)
    assert item.content == "" and item.extra == {"references": ["https://example.org/existing"]}
    assert "CVE-2026-12345" in enriched.content and len(enriched.content) <= 6000
    assert enriched.summary == "A feed summary."
    assert enriched.published_at == datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc)
    extra = enriched.extra
    assert extra["references"] == ["https://example.org/existing"]
    assert extra["referenced_links"] == ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
    assert extra["cve_ids"] == ["CVE-2026-12345"] and extra["cwes"] == ["CWE-787"]
    assert "APT29" in extra["actor_mentions"] and "FogRAT" in extra["malware"]
    assert "Microsoft Exchange Server" in extra["products"]
    assert extra["exploitation_hint"] == "active"
    crawl = extra["crawl"]
    assert crawl["fetch_method"] == "http" and crawl["canonical_url"] == URL
    assert crawl["quality_score"] > 0 and len(crawl["content_hash"]) == 64
    assert crawl["indicators"] >= 8 and crawl["injection_flagged"] is False
    assert enriched.raw_hash == item.raw_hash  # identity is unchanged by enrichment


def test_enrich_keeps_existing_facts_and_does_not_downgrade_hints() -> None:
    item = raw_item(extra={"exploitation_hint": "widespread", "cve_ids": ["CVE-2026-00001"], "published_at": None})
    enriched = enrich_raw_item(item, article())
    assert enriched.extra["exploitation_hint"] == "widespread"
    assert enriched.extra["cve_ids"] == ["CVE-2026-00001", "CVE-2026-12345"]


def test_low_quality_article_only_records_metadata() -> None:
    poor = extract_article("<html><body><div>tiny</div></body></html>", response_url=URL, headers={})
    enriched = enrich_raw_item(raw_item(), poor, min_quality=0.5)
    assert enriched.content == "" and "cve_ids" not in enriched.extra
    assert enriched.extra["crawl"]["applied"] is False and enriched.extra["crawl"]["quality_score"] == poor.quality_score


def test_enriched_item_flows_into_normalization() -> None:
    enriched = enrich_raw_item(raw_item(summary=""), article())
    [event] = normalize_items([enriched])
    assert "CVE-2026-12345" in event.cves and "CWE-787" in event.cwes
    assert event.exploitation_status is ExploitationStatus.ACTIVE
    assert "https://cisa.gov/known-exploited-vulnerabilities-catalog" in event.referenced_urls  # canonicalised downstream
    assert any("APT29" in actor for actor in event.threat_actors)
    assert "FogRAT" in event.malware_families
    assert "CVE-2026-12345" in event.summary
