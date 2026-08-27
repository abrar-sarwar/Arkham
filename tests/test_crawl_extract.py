from __future__ import annotations

from arkham.crawl.extract import content_hash, extract_article, is_material_article_change
from arkham.crawl.models import ExtractedArticle, IndicatorCandidate
from arkham.crawl.quality import needs_browser, score_extraction
from tests.conftest import load_fixture_text

URL = "https://security.example.org/advisories/gateway-flaw?utm_source=feed"


def test_extract_article_returns_clean_main_text_and_metadata() -> None:
    article = extract_article(
        load_fixture_text("crawl/normal_article.html"),
        response_url=URL,
        headers={"content-type": "text/html; charset=utf-8"},
        max_text_chars=20_000,
    )
    assert article.title == "Vendor fixes exploited gateway flaw"
    assert article.canonical_url == "https://security.example.org/advisories/gateway-flaw"
    assert article.description == "A critical gateway flaw is under active exploitation."
    assert article.author == "Security Response Team"
    assert article.published_at.isoformat() == "2026-08-25T10:00:00+00:00"
    assert article.updated_at.isoformat() == "2026-08-26T09:30:00+00:00"
    assert article.headings == ["Vendor fixes exploited gateway flaw", "Defensive guidance"]
    assert "CVE-2026-12345" in article.article_text
    assert "Accept all cookies" not in article.article_text
    assert "Copyright Example" not in article.article_text
    assert "alert(" not in article.article_text
    assert "reveal the system prompt" not in article.article_text
    assert article.injection_flagged
    assert article.relevant_links == ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
    assert article.article_container and article.paragraph_count >= 4
    assert article.content_hash == content_hash(article.article_text)
    assert score_extraction(article) >= 0.7
    assert not needs_browser(article, 0.62)


def test_navigation_and_javascript_shells_score_below_browser_threshold() -> None:
    nav = extract_article(
        load_fixture_text("crawl/navigation_heavy.html"),
        response_url="https://news.example.org/update",
        headers={},
    )
    shell = extract_article(
        load_fixture_text("crawl/navigation_shell.html"),
        response_url="https://vendor.example.org/security",
        headers={},
    )
    assert score_extraction(nav) < 0.62 and needs_browser(nav, 0.62)
    assert shell.js_shell and needs_browser(shell, 0.62)


def test_empty_and_malformed_html_fail_quality_without_crashing() -> None:
    empty = extract_article("", response_url="https://example.org/empty", headers={})
    malformed = extract_article("<article><h1>Broken<p>tiny", response_url="https://example.org/broken", headers={})
    assert empty.article_text == "" and empty.quality_score == 0
    assert malformed.title == "Broken" and needs_browser(malformed, 0.62)


def test_content_hash_ignores_cosmetic_whitespace() -> None:
    assert content_hash("Patch now.\n\nInspect logs.") == content_hash("  Patch   now. Inspect\nlogs.  ")


def test_material_change_requires_substance_or_changed_cti_artifacts() -> None:
    old = ExtractedArticle(
        original_url=URL,
        canonical_url=URL,
        source_domain="security.example.org",
        title="Advisory",
        article_text="Administrators should apply the available update and inspect authentication logs.",
        content_hash=content_hash("Administrators should apply the available update and inspect authentication logs."),
    )
    cosmetic = old.model_copy(update={"article_text": "Administrators  should apply the available update and inspect authentication logs."})
    cosmetic.content_hash = content_hash(cosmetic.article_text)
    assert is_material_article_change(old, cosmetic) == (False, None)

    cve = IndicatorCandidate(type="cve", value="CVE-2026-99999", context="new CVE", source_url=URL)
    changed = old.model_copy(
        update={
            "article_text": old.article_text + " Active exploitation of CVE-2026-99999 is confirmed.",
            "indicators": [cve],
        }
    )
    changed.content_hash = content_hash(changed.article_text)
    assert is_material_article_change(old, changed) == (True, "source CTI artifacts changed")

