"""Edge cases for extraction, quality and indicators: malformed, hidden, huge, defanged and hostile input."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from arkham.crawl.extract import content_hash, extract_article, is_material_article_change, parse_datetime
from arkham.crawl.indicators import extract_indicators, refang
from arkham.crawl.models import CrawlFailureReason, ExtractedArticle
from arkham.crawl.quality import classify_interstitial, needs_browser, score_extraction

URL = "https://blog.example.org/posts/1"


def html(body: str, head: str = "") -> str:
    return f"<!doctype html><html lang='en'><head><title>Post | Blog</title>{head}</head><body>{body}</body></html>"


def article(body: str, head: str = "", **kwargs):
    return extract_article(html(body, head), response_url=URL, headers={"content-type": "text/html"}, **kwargs)


# ---------------------------------------------------------------------------- extraction


def test_hidden_and_noise_elements_are_excluded() -> None:
    body = (
        "<main><article><h1>Advisory title here</h1>"
        "<p style='display:none'>hidden by style</p><p hidden>hidden attribute</p><p aria-hidden='true'>aria hidden</p>"
        "<div class='cookie-consent'>We use cookies</div><div class='share-buttons'>Share on X</div>"
        "<div class='related-posts'>Related: other post</div><div role='navigation'>Home About</div>"
        "<p>Visible paragraph number one about the vulnerability that matters.</p>"
        "<p>Visible paragraph number two with the defensive guidance for admins.</p>"
        "<p>Visible paragraph number three with additional useful context here.</p>"
        "</article></main>"
    )
    result = article(body)
    for absent in ("hidden by style", "hidden attribute", "aria hidden", "We use cookies", "Share on X", "Related:", "Home About"):
        assert absent not in result.article_text
    assert "paragraph number one" in result.article_text and result.paragraph_count == 3
    assert result.title == "Advisory title here" and result.language == "en"


def test_react_style_noscript_shell_is_detected() -> None:
    body = "<div id='root'></div><noscript>You need to enable JavaScript to run this app.</noscript><script src='/static/js/main.js'></script>"
    result = article(body)
    assert result.js_shell and needs_browser(result, 0.62) and score_extraction(result) == 0.0


def test_json_ld_and_time_element_fill_missing_metadata() -> None:
    head = (
        '<script type="application/ld+json">{"@type": "NewsArticle", "headline": "Structured headline",'
        ' "datePublished": "2026-08-20T07:15:00+02:00", "dateModified": "2026-08-21", "description": "LD description",'
        ' "author": [{"@type": "Person", "name": "Ada"}, {"name": "Grace"}]}</script>'
    )
    body = "<article><p>First paragraph with enough words to count as a paragraph.</p><time datetime='2026-08-19T00:00:00Z'>Aug 19</time></article>"
    result = article(body, head)
    assert result.title == "Structured headline"
    assert result.description == "LD description" and result.author == "Ada, Grace"
    assert result.published_at == datetime(2026, 8, 20, 5, 15, tzinfo=timezone.utc)
    assert result.updated_at == datetime(2026, 8, 21, tzinfo=timezone.utc)


def test_malicious_json_ld_is_ignored_safely() -> None:
    head = '<script type="application/ld+json">{"headline": ' + '"x"' * 10 + "</script>"  # invalid JSON
    huge = '<script type="application/ld+json">' + "[" * 100_000 + "</script>"  # oversized/pathological
    result = article("<article><h1>Real title</h1><p>Body text with several words here.</p></article>", head + huge)
    assert result.title == "Real title"


def test_links_are_resolved_validated_deduplicated_and_capped() -> None:
    anchors = "".join(f"<a href='https://ref.example.org/item-{i}?utm_source=x'>ref {i}</a> " for i in range(60))
    body = (
        "<article><h1>Links</h1><p>"
        "<a href='/relative/path?fbclid=abc#frag'>rel</a> <a href='http://insecure.example.org/x'>http</a> "
        "<a href='https://127.0.0.1/private'>private</a> <a href='javascript:alert(1)'>js</a> <a href='mailto:a@b.c'>mail</a> "
        "<a href='https://ref.example.org/item-0'>dupe</a> " + anchors + "</p></article>"
    )
    result = article(body)
    assert result.relevant_links[0] == "https://blog.example.org/relative/path"
    assert "https://ref.example.org/item-0" in result.relevant_links
    assert len(result.relevant_links) == 50 and len(set(result.relevant_links)) == 50
    assert all(link.startswith("https://") for link in result.relevant_links)
    assert not any("127.0.0.1" in link or "insecure" in link or "javascript" in link for link in result.relevant_links)


def test_plain_text_documents_are_handled_without_html_parsing() -> None:
    text = "ADVISORY 2026-01\n\nCVE-2026-55555 affects Example Router firmware 3.1.\n\nUpgrade to 3.2 or later.\n\n<not html>"
    result = extract_article(text, response_url=URL, headers={"content-type": "text/plain"})
    assert result.title == "ADVISORY 2026-01" and result.paragraph_count >= 2
    assert "<not html>" not in result.article_text  # tag-like tokens are stripped by the sanitizer, never rendered
    assert ("cve", "CVE-2026-55555") in {(i.type, i.value) for i in result.indicators}


def test_binary_garbage_and_control_characters_do_not_crash() -> None:
    junk = "\x00\x01\x02" + "<html><body><p>ok\u200b text\x07 here with words</p>" + "\ufeff" * 10
    result = extract_article(junk, response_url=URL, headers={})
    assert "\x00" not in result.article_text and "\u200b" not in result.article_text and "\x07" not in result.article_text
    assert "ok text here" in result.article_text


def test_input_and_output_sizes_are_bounded() -> None:
    paragraph = "<p>" + "word " * 200 + "</p>"
    body = "<article>" + paragraph * 400 + "</article>"
    result = extract_article(html(body), response_url=URL, headers={}, max_text_chars=5_000, max_html_chars=200_000)
    assert 0 < len(result.article_text) <= 5_000
    assert result.paragraph_count > 0


def test_lists_code_and_tables_are_preserved_as_blocks() -> None:
    body = (
        "<article><h1>Hardening</h1><ul><li>Rotate credentials now</li><li>Block outbound SMB traffic</li></ul>"
        "<pre>  $ nc -zv 203.0.113.42 443\n  open</pre>"
        "<table><tr><th>Indicator</th><th>Type</th></tr><tr><td>evil.example domain</td><td>C2</td></tr></table></article>"
    )
    result = article(body)
    assert "- Rotate credentials now" in result.article_text and "- Block outbound SMB traffic" in result.article_text
    assert "$ nc -zv 203.0.113.42 443\nopen" in result.article_text
    assert "Indicator" in result.article_text and "evil.example domain" in result.article_text


def test_title_prefers_h1_then_og_then_cleaned_page_title() -> None:
    no_h1 = article("<article><p>Body with a few words in it.</p></article>", "<meta property='og:title' content='OG title'>")
    assert no_h1.title == "OG title"
    plain = article("<article><p>Body with a few words in it.</p></article>")
    assert plain.title == "Post"  # site suffix stripped
    assert article("<article><h1>H1 wins over everything</h1><p>Body text words.</p></article>").title == "H1 wins over everything"


def test_unclosed_and_nested_tags_are_tolerated() -> None:
    result = extract_article(
        "<div><p>First unclosed<p>Second unclosed<h2>Heading<p>Third<ul><li>one<li>two</div><footer>foot",
        response_url=URL,
        headers={},
    )
    assert result.headings == ["Heading"]
    assert "First unclosed" in result.article_text and "Second unclosed" in result.article_text
    assert "- one" in result.article_text and "- two" in result.article_text and "foot" not in result.article_text


def test_content_container_hint_is_used_when_no_semantic_tag_exists() -> None:
    body = (
        "<div class='site-header'>Site header text</div>"
        "<div id='post-content'><p>Main content paragraph one with many words.</p><p>Main content paragraph two with words.</p></div>"
        "<div class='sidebar'>Sidebar noise</div>"
    )
    result = article(body)
    assert "Main content paragraph one" in result.article_text
    assert "Sidebar noise" not in result.article_text and "Site header text" not in result.article_text
    assert result.article_container is False  # class hint, not a semantic container


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-08-25T10:00:00Z", datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)),
        ("2026-08-25", datetime(2026, 8, 25, tzinfo=timezone.utc)),
        ("Tue, 25 Aug 2026 10:00:00 GMT", datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)),
        ("2026-08-25T12:00:00+02:00", datetime(2026, 8, 25, 10, 0, tzinfo=timezone.utc)),
        ("not a date", None),
        ("", None),
        (None, None),
        ("x" * 100, None),
    ],
)
def test_parse_datetime(value, expected) -> None:
    parsed = parse_datetime(value)
    assert (parsed.astimezone(timezone.utc) if parsed else None) == expected


# ---------------------------------------------------------------------------- quality


def test_quality_scores_are_deterministic_and_bounded() -> None:
    empty = ExtractedArticle(original_url=URL, canonical_url=URL, source_domain="blog.example.org")
    assert score_extraction(empty) == 0.0
    tiny = empty.model_copy(update={"article_text": "tiny", "title": "T", "article_container": True, "paragraph_count": 1, "visible_text_chars": 4})
    assert 0.0 < score_extraction(tiny) <= 0.3
    rich = empty.model_copy(
        update={
            "article_text": "word " * 200,
            "title": "Title",
            "article_container": True,
            "paragraph_count": 6,
            "visible_text_chars": 1100,
            "duplicate_text_ratio": 0.0,
        }
    )
    assert score_extraction(rich) >= 0.9 and score_extraction(rich) == score_extraction(rich)
    duplicated = rich.model_copy(update={"duplicate_text_ratio": 1.0})
    assert score_extraction(duplicated) < score_extraction(rich)
    shell = rich.model_copy(update={"js_shell": True})
    assert score_extraction(shell) == 0.0 and needs_browser(shell, 0.1)


@pytest.mark.parametrize(
    ("title", "text", "expected"),
    [
        ("Just a moment...", "Checking your browser before accessing the site.", CrawlFailureReason.CAPTCHA_DETECTED),
        ("Attention Required! | Cloudflare", "Please complete the CAPTCHA.", CrawlFailureReason.CAPTCHA_DETECTED),
        ("Members", "Please sign in to continue.", CrawlFailureReason.AUTHENTICATION_REQUIRED),
        ("Subscribe", "This article is for subscribers only.", CrawlFailureReason.AUTHENTICATION_REQUIRED),
        ("Access denied", "You have been blocked. Error 1020.", CrawlFailureReason.BLOCKED_BY_SITE),
        ("Report", "How to defeat CAPTCHA farms: a long article. " * 60, None),  # long real content
        ("Advisory", "Patch now.", None),
    ],
)
def test_classify_interstitial(title, text, expected) -> None:
    assert classify_interstitial(title, text) == expected


# ---------------------------------------------------------------------------- change detection


def test_material_change_reasons() -> None:
    base = ExtractedArticle(
        original_url=URL, canonical_url=URL, source_domain="blog.example.org", title="Advisory",
        article_text="Administrators should apply the update and review logs for suspicious sign-ins. " * 3,
    )
    retitled = base.model_copy(update={"title": "Advisory updated"})
    assert is_material_article_change(base, retitled) == (True, "title changed")
    rewritten = base.model_copy(update={"article_text": "Completely different guidance about a different product and vendor entirely. " * 5})
    assert is_material_article_change(base, rewritten) == (True, "article text changed substantially")
    expanded = base.model_copy(update={"article_text": base.article_text + " Additional mitigation details follow here. " * 12})
    assert is_material_article_change(base, expanded)[0] is True
    tweaked = base.model_copy(update={"article_text": base.article_text.replace("review logs", "check logs")})
    assert is_material_article_change(base, tweaked) == (False, None)
    appeared = ExtractedArticle(original_url=URL, canonical_url=URL, source_domain="blog.example.org", title="Advisory")
    assert is_material_article_change(appeared, base) == (True, "article text appeared")
    assert content_hash("") == content_hash("   \n ")


# ---------------------------------------------------------------------------- indicators


def kinds(text: str, url: str = URL) -> set[tuple[str, str]]:
    return {(i.type, i.value) for i in extract_indicators(text, url)}


def test_defanged_indicators_are_refanged_and_marked() -> None:
    text = "Payload at hxxps://evil[.]example/drop from the C2 domain evil[.]example at 198[.]51[.]100[.]7; contact ops[at]evil[.]example"
    assert refang("hxxp://a[.]b[:]443") == "http://a.b:443"
    items = extract_indicators(text, URL)
    found = {(i.type, i.value): i for i in items}
    assert ("url", "https://evil.example/drop") in found
    assert ("ipv4", "198.51.100.7") in found and found[("ipv4", "198.51.100.7")].context.startswith("defanged:")
    assert ("email", "ops@evil.example") in found
    assert ("domain", "evil.example") in found and found[("domain", "evil.example")].context.startswith("defanged:")


def test_hashes_must_be_exact_length_and_are_lowercased() -> None:
    sha256 = "A" * 64
    text = f"Sample {sha256} and a longer hex run {'b' * 70} plus short {'c' * 31}."
    found = kinds(text)
    assert ("sha256", "a" * 64) in found
    assert not any(kind in {"sha1", "md5"} for kind, _ in found)


def test_ip_gating_private_needs_cue_and_times_are_not_ipv6() -> None:
    found = kinds("The C2 server 10.0.0.5 beaconed at 12:30:00 and loopback 127.0.0.1 appeared in a footnote about build 2.4.6.")
    assert ("ipv4", "10.0.0.5") in found
    assert ("ipv4", "127.0.0.1") not in found
    assert not any(kind == "ipv6" for kind, _ in found)
    assert ("ipv4", "1.2.3.4") not in kinds("Firmware update 1.2.3.4 shipped.")
    assert ("ipv4", "8.8.8.8") in kinds("Traffic went to 8.8.8.8.")  # public, no cue needed


def test_domain_and_url_distinctions() -> None:
    found = kinds("The attacker-controlled domain evil.example served https://evil.example/x and setup.exe; see https://blog.example.org/other.")
    assert ("domain", "evil.example") in found and ("url", "https://evil.example/x") in found
    assert ("domain", "setup.exe") not in found
    assert not any(value.startswith("https://blog.example.org") for kind, value in found if kind == "url")
    assert ("domain", "blog.example.org") not in kinds("The domain blog.example.org is ours.")


def test_actor_malware_and_attack_patterns() -> None:
    found = kinds("Storm-0558 and TA505 (not TA0001) deployed IcedID malware, QakBot and Cobalt Strike; T1566.001 and TA0001 observed.")
    assert ("actor", "STORM-0558") in found or ("actor", "Storm-0558") in found
    assert ("actor", "TA505") in found and ("actor", "TA0001") not in found
    assert ("attack", "T1566.001") in found and ("attack", "TA0001") in found
    assert ("malware", "IcedID") in found and ("malware", "QakBot") in found
    assert ("malware", "New") not in kinds("New malware appeared.")


def test_ordering_dedup_context_and_limits() -> None:
    text = "CVE-2026-1001 first, then cve-2026-1002, then CVE-2026-1001 again. " + "x" * 500
    items = extract_indicators(text, URL)
    values = [i.value for i in items if i.type == "cve"]
    assert values == ["CVE-2026-1001", "CVE-2026-1002"]  # first appearance order, case-normalised, deduplicated
    assert ("cve", "CVE-2026-1") not in kinds("CVE-2026-1 is not a real identifier shape")
    assert all(len(i.context) <= 300 and i.source_url == URL for i in items)
    assert extract_indicators("", URL) == [] and extract_indicators("nothing here", URL) == []
    many = " ".join(f"CVE-2026-{n}" for n in range(1000, 1700))
    assert len(extract_indicators(many, URL)) == 500


def test_pathological_input_is_bounded() -> None:
    text = ("a" * 63 + ".") * 3000 + " " + "1.2.3." * 20000
    items = extract_indicators(text, URL)
    assert isinstance(items, list)
