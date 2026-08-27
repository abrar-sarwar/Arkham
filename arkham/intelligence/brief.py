"""Deterministic, phone-sized SMS rendering of a validated briefing draft (legacy Twilio transport only).

The default Discord transport renders the same core :class:`~arkham.models.Briefing` with
:mod:`arkham.delivery.discord_format`; nothing here constrains that path.
"""

from __future__ import annotations

import unicodedata
from datetime import datetime
from zoneinfo import ZoneInfo

from arkham.delivery.sms import GSM7_BASIC, GSM7_EXTENDED, TWILIO_MAX_BODY, split_message
from arkham.models import Briefing, BriefingDraft, BriefItem, BriefSection, EvidencePack
from arkham.security.prompt_injection import sanitize_text, truncate

_EMOJI = {
    BriefSection.CRITICAL: "🚨",
    BriefSection.THREAT: "🌍",
    BriefSection.INCIDENT: "⚠️",
    BriefSection.RESEARCH: "🔬",
    BriefSection.POLICY: "⚖️",
}
_GSM7 = GSM7_BASIC | GSM7_EXTENDED
_ASCII_PUNCTUATION = str.maketrans(
    {
        "\u00a0": " ",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "–": "-",
        "—": "-",
        "…": "...",
        "•": "-",
    }
)


def _gsm_safe(text: str) -> str:
    """Transliterate display text so the no-emoji mode stays in GSM-7."""
    mapped = text.translate(_ASCII_PUNCTUATION)
    output: list[str] = []
    for char in mapped:
        if char in _GSM7:
            output.append(char)
            continue
        ascii_value = unicodedata.normalize("NFKD", char).encode("ascii", "ignore").decode("ascii")
        output.append(ascii_value if ascii_value and all(value in _GSM7 for value in ascii_value) else "?")
    return "".join(output)


def date_label_for(now: datetime, tz: ZoneInfo) -> str:
    return now.astimezone(tz).strftime("%b %d").upper()


def _event_block(item: BriefItem, pack: EvidencePack, *, emoji: bool, compact: bool = False) -> str:
    evidence = pack.refs.get(item.ref)
    marker = (_EMOJI[item.section] + " ") if emoji else ""
    heading = f"{marker}{item.section.value}"
    update = ("UPDATE — " if emoji else "UPDATE - ") if evidence and evidence.material_update else ""
    headline = truncate(sanitize_text(item.headline, 180), 100 if compact else 120)
    why = truncate(sanitize_text(item.why_it_matters, 300), 75 if compact else 100)
    lines = [heading, update + headline]
    if why:
        lines.append(why)
    lines.append(item.confidence.label)
    lines.append(f"Source: {sanitize_text(item.source_label, 40)} {item.source_url}")
    text = "\n".join(lines)
    return text if emoji else _gsm_safe(text)


def _prep_block(draft: BriefingDraft, *, emoji: bool) -> str | None:
    prep = [truncate(sanitize_text(value, 160), 100) for value in draft.prep[:4] if sanitize_text(value, 160)]
    if not prep:
        return None
    heading = "🛡️ PREP" if emoji else "PREP"
    bullet = "•" if emoji else "-"
    text = heading + "\n" + "\n".join(f"{bullet} {value}" for value in prep)
    return text if emoji else _gsm_safe(text)


def _learn_block(draft: BriefingDraft, *, emoji: bool) -> str | None:
    if draft.learn is None:
        return None
    heading = "📚 LEARN TODAY" if emoji else "LEARN TODAY"
    topic = truncate(sanitize_text(draft.learn.topic, 140), 110)
    why = truncate(sanitize_text(draft.learn.why, 220), 100)
    text = heading + "\n" + topic + (f"\nWhy: {why}" if why else "")
    return text if emoji else _gsm_safe(text)


def _watch_block(draft: BriefingDraft, *, emoji: bool) -> str | None:
    watch = [truncate(sanitize_text(value, 120), 80) for value in draft.watch[:4] if sanitize_text(value, 120)]
    if not watch:
        return None
    heading = "👀 QUIET WATCH" if emoji else "QUIET WATCH"
    bullet = "•" if emoji else "-"
    text = heading + "\n" + "\n".join(f"{bullet} {value}" for value in watch)
    return text if emoji else _gsm_safe(text)


def _join(parts: list[str]) -> str:
    return "\n\n".join(part for part in parts if part)


def render_briefing(
    draft: BriefingDraft,
    pack: EvidencePack,
    *,
    emoji: bool,
    max_chars: int,
    generated_by: str,
    hard_limit: int = TWILIO_MAX_BODY,
) -> Briefing:
    """Render in priority order and stop before the configured phone-size budget."""
    header = f"ARKHAM // {pack.date_label}"
    separator = "•" if emoji else "|"
    footer = f"{pack.events_analyzed} events analyzed {separator} {pack.sources_ok}/{pack.sources_checked} sources"
    parts = [header]

    if pack.quiet:
        rendered_items: list[BriefItem] = []
        for optional in (_watch_block(draft, emoji=emoji), _prep_block(draft, emoji=emoji), _learn_block(draft, emoji=emoji)):
            if optional and len(_join([*parts, optional, footer])) <= max_chars:
                parts.append(optional)
    else:
        added = 0
        rendered_items = []
        for item in draft.items:
            block = _event_block(item, pack, emoji=emoji)
            if len(_join([*parts, block, footer])) <= max_chars:
                parts.append(block)
                rendered_items.append(item)
                added += 1
            else:
                break
        if added == 0 and draft.items:
            compact = _event_block(draft.items[0], pack, emoji=emoji, compact=True)
            if len(_join([header, compact, footer])) <= max_chars:
                parts.append(compact)
                rendered_items.append(draft.items[0])
        for optional in (_prep_block(draft, emoji=emoji), _learn_block(draft, emoji=emoji)):
            if optional and len(_join([*parts, optional, footer])) <= max_chars:
                parts.append(optional)

    parts.append(footer)
    text = _join(parts)
    if len(text) > max_chars:
        text = truncate(text, max_chars)
    messages = split_message(text, max_chars=max_chars, hard_limit=hard_limit)
    return Briefing(
        date_label=pack.date_label,
        draft=draft.model_copy(update={"items": rendered_items}),
        evidence=[pack.refs[item.ref] for item in rendered_items if item.ref in pack.refs],
        quiet=pack.quiet,
        events_analyzed=pack.events_analyzed,
        sources_checked=pack.sources_checked,
        sources_ok=pack.sources_ok,
        generated_by=generated_by,
        text=text,
        messages=messages,
    )
