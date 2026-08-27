"""Tests for SMS encoding detection, segment counting and message splitting.

Sample text comes from the captured CISA KEV feed (tests/fixtures/cisa_kev_sample.json) so the
splitter is exercised on real advisory prose, not invented filler.
"""

from __future__ import annotations

import math
import re

import pytest

from arkham.delivery.sms import (
    GSM7_BASIC,
    GSM7_EXTENDED,
    TWILIO_MAX_BODY,
    MessageStats,
    count_segments,
    encoding_of,
    gsm7_length,
    is_gsm7,
    message_stats,
    split_message,
)
from tests.conftest import load_fixture_json

PREFIX_RE = re.compile(r"^ARKHAM (\d+)/(\d+)\n")


def kev_sections() -> list[str]:
    """Build briefing-style sections from the real KEV fixture entries."""
    data = load_fixture_json("cisa_kev_sample.json")
    sections: list[str] = []
    for vuln in data["vulnerabilities"]:
        sections.append(
            f"{vuln['vulnerabilityName']}\n{vuln['shortDescription']}\n"
            f"{vuln['cveID']} | KEV added {vuln['dateAdded']} | due {vuln['dueDate']}"
        )
    return sections


def kev_required_action() -> str:
    data = load_fixture_json("cisa_kev_sample.json")
    return data["vulnerabilities"][0]["requiredAction"]


def strip_prefix(part: str) -> str:
    m = PREFIX_RE.match(part)
    assert m, f"part lacks ARKHAM prefix: {part[:40]!r}"
    return part[m.end() :]


def assert_well_formed(parts: list[str], limit: int) -> None:
    assert parts, "splitter returned no parts"
    total = len(parts)
    for idx, part in enumerate(parts, start=1):
        assert len(part) <= limit, f"part {idx} is {len(part)} chars > {limit}"
        assert len(part) <= TWILIO_MAX_BODY
        m = PREFIX_RE.match(part)
        assert m, f"part {idx} missing prefix"
        assert int(m.group(1)) == idx
        assert int(m.group(2)) == total
        assert part[m.end() :].strip(), f"part {idx} has an empty body"


# ---------------------------------------------------------------------------- alphabet tables


def test_gsm7_tables_match_gsm_03_38():
    # 128 code points minus the ESC marker (0x1B) that switches to the extension table.
    assert len(GSM7_BASIC) == 127
    assert len(GSM7_EXTENDED) == 10
    assert GSM7_EXTENDED == frozenset("\f^{}\\[~]|€")
    assert "\n" in GSM7_BASIC and "\r" in GSM7_BASIC and " " in GSM7_BASIC
    for ch in "@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ¤¡ÄÖÑÜ§¿äöñüà":
        assert ch in GSM7_BASIC, ch
    assert "\x1b" not in GSM7_BASIC
    assert not (GSM7_BASIC & GSM7_EXTENDED)
    for ch in "`\\{}[]~|^€":
        assert ch not in GSM7_BASIC


# ---------------------------------------------------------------------------- encoding detection


def test_plain_kev_description_is_gsm7():
    sections = kev_sections()
    text = "\n\n".join(sections)
    assert is_gsm7(text)
    assert encoding_of(text) == "GSM-7"
    # The only extension-table characters in the sections are the "|" separators: each costs 2 septets.
    assert text.count("|") == 2 * len(sections)
    assert gsm7_length(text) == len(text) + text.count("|")
    assert gsm7_length(text.replace("|", "-")) == len(text)


def test_curly_quotes_from_kev_required_action_force_ucs2():
    action = kev_required_action()
    assert "’" in action and "“" in action  # real CISA prose uses typographic quotes
    assert not is_gsm7(action)
    assert encoding_of(action) == "UCS-2"


def test_emoji_forces_ucs2():
    assert not is_gsm7("🚨 CRITICAL")
    assert encoding_of("🚨 CRITICAL") == "UCS-2"


def test_euro_sign_is_gsm7_extension_and_counts_double():
    assert is_gsm7("Cost: 5€")
    assert encoding_of("Cost: 5€") == "GSM-7"
    assert gsm7_length("5€") == 3
    assert gsm7_length("[]{}|^~\\€\f") == 20


def test_backtick_is_not_gsm7():
    assert not is_gsm7("`code`")
    assert encoding_of("`code`") == "UCS-2"


def test_empty_text_is_gsm7_with_zero_length():
    assert is_gsm7("")
    assert gsm7_length("") == 0
    assert encoding_of("") == "GSM-7"


# ---------------------------------------------------------------------------- segment counting


@pytest.mark.parametrize(
    ("length", "expected"),
    [(1, 1), (160, 1), (161, 2), (306, 2), (307, 3), (459, 3), (460, 4)],
)
def test_gsm7_segment_boundaries(length, expected):
    assert count_segments("a" * length) == expected


def test_gsm7_extension_characters_count_double_for_segments():
    assert count_segments("€" * 80) == 1  # 160 septets
    assert count_segments("€" * 81) == 2  # 162 septets


@pytest.mark.parametrize(
    ("length", "expected"),
    [(1, 1), (70, 1), (71, 2), (134, 2), (135, 3)],
)
def test_ucs2_segment_boundaries(length, expected):
    assert count_segments("“" * length) == expected


def test_astral_emoji_counts_two_utf16_units():
    assert count_segments("🚨" * 35) == 1  # 70 code units
    assert count_segments("🚨" * 36) == 2  # 72 code units


def test_empty_text_has_no_segments():
    assert count_segments("") == 0


def test_twilio_max_body_constant():
    assert TWILIO_MAX_BODY == 1600


# ---------------------------------------------------------------------------- split_message


def test_split_returns_text_unchanged_when_it_fits():
    text = kev_sections()[0]
    assert split_message(text, max_chars=1500) == [text]
    assert split_message(text, max_chars=len(text)) == [text]


def test_split_empty_text_yields_no_parts():
    assert split_message("", max_chars=1500) == []


def test_split_into_two_parts_with_prefixes_on_section_boundaries():
    sections = kev_sections()[:3]
    text = "\n\n".join(sections)
    limit = max(len(s) for s in sections) + 60  # forces at least two parts, each section fits
    assert len(text) > limit
    parts = split_message(text, max_chars=limit)
    assert len(parts) >= 2
    assert_well_formed(parts, limit)
    assert parts[0].startswith(f"ARKHAM 1/{len(parts)}\n")
    assert parts[-1].startswith(f"ARKHAM {len(parts)}/{len(parts)}\n")
    # Sections are never cut when they fit: the bodies re-join into exactly the original sections.
    recovered = [sec for part in parts for sec in strip_prefix(part).split("\n\n")]
    assert recovered == sections


def test_split_packs_sections_greedily():
    sections = kev_sections()
    text = "\n\n".join(sections)
    parts = split_message(text, max_chars=700)
    assert_well_formed(parts, 700)
    bodies = [strip_prefix(p) for p in parts]
    # Greedy packing: adding the first section of the next part to the previous one would overflow.
    prefix_width = len(f"ARKHAM {len(parts)}/{len(parts)}\n")
    for prev, nxt in zip(bodies, bodies[1:], strict=False):
        first_next = nxt.split("\n\n")[0]
        assert prefix_width + len(prev) + 2 + len(first_next) > 700
    assert "\n\n".join(bodies) == text


def test_giant_single_section_is_split_on_line_boundaries():
    lines = [f"{v.splitlines()[0]}" for v in kev_sections()] * 6
    text = "\n".join(lines)  # one section, no blank lines
    assert "\n\n" not in text
    limit = 400
    assert len(text) > limit
    parts = split_message(text, max_chars=limit)
    assert_well_formed(parts, limit)
    bodies = [strip_prefix(p) for p in parts]
    assert "\n".join(bodies) == text
    for body in bodies:
        for line in body.split("\n"):
            assert line in lines


def test_giant_single_line_is_cut_on_the_limit_as_last_resort():
    text = " ".join(v["shortDescription"] for v in load_fixture_json("cisa_kev_sample.json")["vulnerabilities"])
    text = text.replace("\n", " ")
    limit = 300
    assert len(text) > 2 * limit
    parts = split_message(text, max_chars=limit)
    assert_well_formed(parts, limit)
    bodies = [strip_prefix(p) for p in parts]
    assert "".join(bodies) == text
    prefix_width = len(f"ARKHAM {len(parts)}/{len(parts)}\n")
    for body in bodies[:-1]:
        assert len(body) == limit - prefix_width


def test_hard_limit_caps_parts_even_when_max_chars_is_larger():
    text = "\n\n".join(kev_sections() * 3)
    assert len(text) > 3000
    parts = split_message(text, max_chars=4800)
    assert len(parts) >= 2
    assert_well_formed(parts, TWILIO_MAX_BODY)
    assert "\n\n".join(strip_prefix(p) for p in parts) == text


def test_custom_hard_limit_is_respected():
    text = "\n\n".join(kev_sections())
    parts = split_message(text, max_chars=1500, hard_limit=500)
    assert_well_formed(parts, 500)


def test_blank_sections_never_become_empty_parts():
    sections = kev_sections()[:2]
    text = "\n\n\n\n" + sections[0] + "\n\n\n\n\n" + sections[1] + "\n\n\n"
    limit = len(sections[0]) + 40
    parts = split_message(text, max_chars=limit)
    assert_well_formed(parts, limit)
    assert [strip_prefix(p) for p in parts] == sections


@pytest.mark.parametrize("limit", [300, 333, 410, 512, 777, 1000, 1499, 1600])
def test_prefix_count_matches_part_count_for_many_limits(limit):
    text = "\n\n".join(kev_sections() * 4)
    parts = split_message(text, max_chars=limit)
    assert_well_formed(parts, limit)
    assert len(parts) >= math.ceil(len(text) / limit)


def test_split_rejects_limit_too_small_for_prefix():
    text = "\n\n".join(kev_sections())
    with pytest.raises(ValueError):
        split_message(text, max_chars=10)


def test_split_handles_ucs2_text_by_character_count():
    action = kev_required_action()
    text = "\n\n".join([action] * 4)
    parts = split_message(text, max_chars=600)
    assert_well_formed(parts, 600)
    assert all(encoding_of(p) == "UCS-2" for p in parts)


# ---------------------------------------------------------------------------- message_stats


def test_message_stats_sums_segments_over_parts():
    stats = message_stats(["a" * 160, "a" * 161])
    assert stats == MessageStats(messages=2, segments=3, chars=321, encoding="GSM-7")


def test_message_stats_reports_ucs2_when_any_part_needs_it():
    stats = message_stats(["a" * 100, "🚨" * 36])
    assert stats.messages == 2
    assert stats.segments == 1 + 2
    assert stats.chars == 100 + 36
    assert stats.encoding == "UCS-2"


def test_message_stats_for_no_parts():
    stats = message_stats([])
    assert stats == MessageStats(messages=0, segments=0, chars=0, encoding="GSM-7")


def test_message_stats_on_real_split_output():
    text = "\n\n".join(kev_sections())
    parts = split_message(text, max_chars=1500)
    stats = message_stats(parts)
    assert stats.messages == len(parts)
    assert stats.chars == sum(len(p) for p in parts)
    assert stats.segments == sum(count_segments(p) for p in parts)
    assert stats.encoding == "GSM-7"
