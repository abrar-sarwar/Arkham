"""Discord renderer: embeds per story, limits, splitting, mention/markdown safety, quiet runs."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from arkham.delivery.discord_format import (
    DISCORD_MAX_CONTENT_CHARS,
    DISCORD_MAX_EMBED_TOTAL_CHARS,
    DISCORD_MAX_EMBEDS_PER_MESSAGE,
    SECTION_COLORS,
    DiscordMessage,
    embed_char_count,
    escape_markdown,
    neutralize_mentions,
    render_discord_briefing,
    render_discord_messages,
)
from arkham.intelligence.llm.template import TemplateModel
from arkham.models import BriefingDraft, BriefItem, BriefSection, Confidence, EvidencePack
from arkham.security.urls import canonicalize_url
from tests.test_synthesize import (
    CITRIX_ADVISORY_URL,
    KEV_CATALOG_URL,
    all_events,
    build_pack,
    citrix_kev_event,
    gitea_event,
    paylogix_event,
)

NY = ZoneInfo("America/New_York")
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)  # 08:00 EDT
_URL_RE = re.compile(r"https://[^\s<>\])}]+")


def render(pack: EvidencePack, draft: BriefingDraft | None = None, *, now: datetime = NOW):
    draft = draft or TemplateModel().synthesize(pack).draft
    briefing = render_discord_briefing(draft, pack, generated_by="template", now=now, tz=NY)
    return briefing, render_discord_messages(briefing)


def story_embeds(messages: list[DiscordMessage]) -> list[dict]:
    return [e for m in messages for e in m.embeds if e.get("footer", {}).get("text", "").startswith("E")]


def flattened(messages: list[DiscordMessage]) -> str:
    return "\n".join(m.text for m in messages)


# ---------------------------------------------------------------------------- layout


def test_full_brief_renders_header_and_one_embed_per_story() -> None:
    pack = build_pack([citrix_kev_event(), gitea_event(), paylogix_event()])
    briefing, messages = render(pack)
    assert len(messages) == 1
    header = messages[0].content or ""
    assert "ARKHAM" in header and "Morning Intelligence Brief" in header
    assert "August 26, 2026" in header
    assert "3 events analyzed" in header and "11/12 sources" in header
    stories = story_embeds(messages)
    assert len(stories) == 3
    first = stories[0]
    item = briefing.draft.items[0]
    assert first["author"]["name"] == "CRITICAL"
    assert first["title"] == item.headline
    assert first["url"] == item.source_url == CITRIX_ADVISORY_URL  # citation priority: vendor advisory first
    assert first["color"] == SECTION_COLORS[BriefSection.CRITICAL]
    assert first["description"] == item.why_it_matters
    names = [field["name"] for field in first["fields"]]
    assert names[:2] == ["Affected", "Exploitation"]
    assert any(name.startswith("Evidence") for name in names)
    assert "CONFIRMED" in " ".join(names)
    assert names[-1] == "Source"
    assert first["fields"][-1]["value"] == item.source_url
    affected = next(f for f in first["fields"] if f["name"] == "Affected")
    assert "Citrix" in affected["value"] and "CVE-2026-8452" in affected["value"]
    exploitation = next(f for f in first["fields"] if f["name"] == "Exploitation")
    assert "KEV" in exploitation["value"]
    evidence = next(f for f in first["fields"] if f["name"].startswith("Evidence"))
    assert CITRIX_ADVISORY_URL in evidence["value"] and "[Citrix]" in evidence["value"]
    assert KEV_CATALOG_URL in evidence["value"] and "[CISA]" in evidence["value"]
    assert first["footer"]["text"].startswith("E1")
    assert "Citrix" in first["footer"]["text"]
    assert first["timestamp"].startswith("2026-")
    # Closing embed carries prep/learn, not a story.
    closing = messages[0].embeds[-1]
    assert closing["title"].startswith("Prep")
    assert closing not in stories


def test_material_update_is_marked_in_the_severity_tag() -> None:
    events = [citrix_kev_event()]
    events[0].material_update = "added to CISA KEV"
    _, messages = render(build_pack(events))
    assert story_embeds(messages)[0]["author"]["name"] == "CRITICAL · UPDATE"


def test_sections_have_distinct_colours() -> None:
    assert len(set(SECTION_COLORS.values())) == len(BriefSection)
    assert all(0 <= color <= 0xFFFFFF for color in SECTION_COLORS.values())
    _, messages = render(build_pack(all_events()))
    assert {e["color"] for e in story_embeds(messages)} <= set(SECTION_COLORS.values())


def test_briefing_core_fields_line_up_with_messages() -> None:
    pack = build_pack([citrix_kev_event(), gitea_event()])
    briefing, messages = render(pack)
    assert briefing.title == "Morning Intelligence Brief"
    assert briefing.date_long == "Wednesday, August 26, 2026"
    assert [e.ref for e in briefing.evidence] == [i.ref for i in briefing.draft.items] == ["E1", "E2"]
    assert briefing.messages == [m.text for m in messages]
    assert briefing.text == "\n\n".join(briefing.messages)
    assert briefing.draft.items[0].headline in briefing.text
    assert KEV_CATALOG_URL in briefing.text
    assert briefing.quiet is False and briefing.generated_by == "template"
    assert briefing.events_analyzed == 2 and briefing.sources_ok == 11 and briefing.sources_checked == 12


def test_evening_delivery_hour_changes_the_edition_label() -> None:
    evening = datetime(2026, 8, 26, 23, 0, tzinfo=timezone.utc)  # 19:00 EDT
    briefing, _ = render(build_pack([citrix_kev_event()]), now=evening)
    assert briefing.title == "Evening Intelligence Brief"


# ---------------------------------------------------------------------------- safety


def test_every_payload_disables_all_mentions() -> None:
    _, messages = render(build_pack(all_events()))
    for message in messages:
        assert message.payload()["allowed_mentions"] == {"parse": []}


def test_mentions_in_untrusted_text_are_neutralized() -> None:
    event = citrix_kev_event()
    event.summary = "Patch now <@123456789012345678> <@!123456789012345678> <@&987654321098765432> <#111111111111111111>"
    pack = build_pack([event])
    draft = TemplateModel().synthesize(pack).draft
    draft.items[0].headline = "@everyone CVE-2026-8452 exploited"
    draft.items[0].why_it_matters = "@here patch immediately"
    _, messages = render(pack, draft)
    text = flattened(messages)
    for raw in ("@everyone", "@here", "<@", "<@!", "<@&", "<#"):
        assert raw not in text
    assert "everyone" in text and "here" in text  # still readable, just not a ping
    assert neutralize_mentions("@Everyone @HERE <@&1>") == "@\u200bEveryone @\u200bHERE <\u200b@&1>"


def test_markdown_in_untrusted_text_is_escaped_so_masked_links_cannot_be_forged() -> None:
    event = citrix_kev_event()
    event.summary = "See [CISA advisory](http://evil.example) and **bold** `code` > quote"
    pack = build_pack([event])
    _, messages = render(pack)
    text = flattened(messages)
    # Every un-escaped masked link "[label](url)" must point at an evidence URL; the forged one is escaped.
    links = re.findall(r"(?<!\\)\[[^\]]*\]\(([^)]*)\)", text)
    assert links and all(url in pack.allowed_urls for url in links)
    assert "http://evil.example" not in links
    assert "\\[CISA advisory\\]" in text
    assert "\\*\\*bold\\*\\*" in text
    assert escape_markdown("a_b*c~d`e|f[g]h>i\\j#k") == "a\\_b\\*c\\~d\\`e\\|f\\[g\\]h\\>i\\\\j\\#k"


def test_every_url_in_the_payload_is_an_evidence_url() -> None:
    pack = build_pack(all_events())
    _, messages = render(pack)
    allowed = {canonicalize_url(url) for url in pack.allowed_urls}
    found = {canonicalize_url(u.rstrip(").,")) for u in _URL_RE.findall(flattened(messages))}
    assert found and found <= allowed


def test_control_and_zero_width_characters_are_removed() -> None:
    event = citrix_kev_event()
    event.summary = "Zero\u200bwidth and \x07bell and \u2066isolate"
    _, messages = render(build_pack([event]))
    text = flattened(messages)
    assert "\u200b" not in text.replace("@\u200b", "").replace("<\u200b", "")
    assert "\x07" not in text and "\u2066" not in text


# ---------------------------------------------------------------------------- limits and splitting


def _oversized_pack(count: int) -> EvidencePack:
    events = []
    for index in range(count):
        event = citrix_kev_event() if index % 2 == 0 else gitea_event()
        event.id = f"{event.id}-{index}"
        event.title = f"Story {index + 1}: " + ("critical exposure " * 12).strip()
        event.summary = (f"Sentence {index + 1} of a long advisory body with detail. " * 20).strip()
        event.products = [f"Product {index + 1} " + "x" * 60 for _ in range(5)]
        event.cves = [f"CVE-2026-{10000 + index * 10 + n}" for n in range(6)]
        events.append(event)
    return build_pack(events, max_events=count)


def test_long_brief_splits_into_multiple_messages_without_dropping_stories() -> None:
    pack = _oversized_pack(8)
    briefing, messages = render(pack)
    assert len(messages) >= 2
    stories = story_embeds(messages)
    assert len(stories) == 8 == len(briefing.draft.items)
    assert [e["footer"]["text"].split(" ")[0] for e in stories] == [f"E{i}" for i in range(1, 9)]
    for index, message in enumerate(messages, start=1):
        assert 1 <= len(message.embeds) <= DISCORD_MAX_EMBEDS_PER_MESSAGE
        assert sum(embed_char_count(e) for e in message.embeds) <= DISCORD_MAX_EMBED_TOTAL_CHARS
        assert len(message.content or "") <= DISCORD_MAX_CONTENT_CHARS
        if index > 1:
            assert f"continued {index}/{len(messages)}" in (message.content or "")
    assert len(briefing.messages) == len(messages)
    for story in stories:
        assert story["url"]  # the cited source link survives splitting
        assert story["fields"][-1]["name"] == "Source"


def test_embed_field_limits_hold_for_extreme_inputs() -> None:
    event = citrix_kev_event()
    event.title = "T" * 300
    event.summary = "S" * 2000
    event.products = ["P" * 80] * 5
    event.cves = [f"CVE-2026-{20000 + n}" for n in range(6)]
    pack = build_pack([event])
    draft = TemplateModel().synthesize(pack).draft
    draft.items[0].headline = "H" * 220
    draft.items[0].why_it_matters = "W" * 260
    _, messages = render(pack, draft)
    embed = story_embeds(messages)[0]
    assert len(embed["title"]) <= 256
    assert len(embed["description"]) <= 4096
    assert len(embed["author"]["name"]) <= 256
    assert len(embed["footer"]["text"]) <= 2048
    for field in embed["fields"]:
        assert len(field["name"]) <= 256 and 1 <= len(field["value"]) <= 1024
    assert embed_char_count(embed) <= DISCORD_MAX_EMBED_TOTAL_CHARS
    assert embed["url"] == draft.items[0].source_url


def test_summary_is_bounded_and_ends_cleanly() -> None:
    event = citrix_kev_event()
    event.summary = ("A complete sentence about exploitation. " * 30).strip()
    _, messages = render(build_pack([event]))
    field = next(f for f in story_embeds(messages)[0]["fields"] if f["name"] == "What happened")
    assert len(field["value"]) <= 320
    assert field["value"].endswith(".") or field["value"].endswith("…")


# ---------------------------------------------------------------------------- quiet runs


def test_quiet_brief_is_short_and_has_no_story_embeds() -> None:
    pack = build_pack([gitea_event(), paylogix_event()], quiet=True)
    briefing, messages = render(pack)
    assert briefing.quiet
    assert len(messages) == 1
    content = messages[0].content or ""
    assert "No material updates" in content and "ARKHAM" in content
    assert story_embeds(messages) == []
    assert any(e["title"].startswith("Watch") for e in messages[0].embeds)
    assert sum(embed_char_count(e) for e in messages[0].embeds) < 1500
    assert briefing.draft.items == [] and briefing.evidence == []


def test_empty_draft_on_non_quiet_pack_still_produces_a_valid_message() -> None:
    pack = build_pack([citrix_kev_event()])
    draft = BriefingDraft(items=[], prep=["Patch"], watch=[])
    _, messages = render(pack, draft)
    assert len(messages) == 1 and messages[0].content
    assert story_embeds(messages) == []


def test_items_with_unknown_refs_are_skipped_not_crashed() -> None:
    pack = build_pack([citrix_kev_event()])
    draft = BriefingDraft(
        items=[
            BriefItem(
                ref="E9",
                section=BriefSection.THREAT,
                headline="ghost",
                confidence=Confidence.LOW,
                source_label="x",
                source_url=KEV_CATALOG_URL,
            )
        ]
    )
    briefing, messages = render(pack, draft)
    assert story_embeds(messages) == [] and briefing.draft.items == []
