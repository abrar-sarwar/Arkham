"""Discord rendering of the core :class:`~arkham.models.Briefing`: one embed per story.

The renderer is pure (no network) and deterministic. It produces :class:`DiscordMessage` objects whose
``payload()`` is the JSON body for an incoming webhook and whose ``text`` is a plain-text flattening
used for hashing, validation and display. Guarantees:

* every string that originates from the draft or the evidence is sanitised, markdown-escaped and
  mention-neutralised, so article text can neither ping the channel nor forge a masked link;
* every URL in the payload is an evidence URL (the cited source or an evidence source);
* Discord's per-field, per-embed and per-message limits are respected by construction — overflow
  starts a new message rather than dropping a story, and the cited source link always survives;
* ``allowed_mentions`` is ``{"parse": []}`` on every payload (the provider enforces it again).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from arkham.models import (
    Briefing,
    BriefingDraft,
    BriefItem,
    BriefSection,
    EvidenceItem,
    EvidencePack,
    ExploitationStatus,
    KevStatus,
)
from arkham.security.prompt_injection import sanitize_text

# Discord limits (https://discord.com/developers/docs/resources/message#create-message and
# .../resources/message#embed-object-embed-limits).
DISCORD_MAX_CONTENT_CHARS = 2000
DISCORD_MAX_EMBEDS_PER_MESSAGE = 10
DISCORD_MAX_EMBED_TOTAL_CHARS = 6000
EMBED_TITLE_MAX = 256
EMBED_DESCRIPTION_MAX = 4096
EMBED_FIELDS_MAX = 25
EMBED_FIELD_NAME_MAX = 256
EMBED_FIELD_VALUE_MAX = 1024
EMBED_FOOTER_MAX = 2048
EMBED_AUTHOR_MAX = 256

# Arkham's own, tighter budgets so a story stays skimmable on a phone.
SUMMARY_MAX = 300
WHY_MAX = 600
PRODUCTS_MAX = 5
CVES_MAX = 6
EVIDENCE_LINKS_MAX = 3
LIST_ITEMS_MAX = 4
LIST_ITEM_MAX = 200

#: Section -> embed colour. BriefSection is the project's priority taxonomy; colours encode urgency.
SECTION_COLORS: dict[BriefSection, int] = {
    BriefSection.CRITICAL: 0xE53935,  # red
    BriefSection.THREAT: 0xFB8C00,  # orange
    BriefSection.INCIDENT: 0xFDD835,  # amber
    BriefSection.RESEARCH: 0x1E88E5,  # blue
    BriefSection.POLICY: 0x8E24AA,  # purple
}
META_COLOR = 0x546E7A  # blue-grey for prep/learn/watch embeds

ZWSP = "\u200b"
_MENTION_RE = re.compile(r"@(?=everyone|here)", re.I)
_MARKUP_MENTION_RE = re.compile(r"<(?=[@#])")
_MARKDOWN_RE = re.compile(r"([\\*_~`|\[\]>#])")
_KEV_LABEL = {KevStatus.NEWLY_ADDED: "CISA KEV · newly added", KevStatus.LISTED: "CISA KEV listed"}
_EXPLOITATION_LABEL = {
    ExploitationStatus.WIDESPREAD: "widespread exploitation",
    ExploitationStatus.ACTIVE: "active exploitation",
    ExploitationStatus.POC_PUBLIC: "public proof-of-concept",
}
_PUBLISHED_FORMAT = "%Y-%m-%dT%H:%MZ"
_ALLOWED_MENTIONS: dict[str, list[str]] = {"parse": []}


# --------------------------------------------------------------------------------------
# Text safety
# --------------------------------------------------------------------------------------


def neutralize_mentions(text: str) -> str:
    """Break ``@everyone``/``@here`` and ``<@id>``/``<@!id>``/``<@&id>``/``<#id>`` with a zero-width space."""
    return _MARKUP_MENTION_RE.sub("<" + ZWSP, _MENTION_RE.sub("@" + ZWSP, text))


def escape_markdown(text: str) -> str:
    """Backslash-escape Discord markdown so untrusted text renders literally (no masked links, headers…)."""
    return _MARKDOWN_RE.sub(r"\\\1", text)


def _fit(text: str, limit: int) -> str:
    """Hard-bound ``text`` to ``limit`` characters on a word boundary, never ending in a lone backslash."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" \\") + "…"


def safe(text: str | None, limit: int) -> str:
    """sanitize -> escape markdown -> neutralise mentions -> bound length. The order matters."""
    if not text:
        return ""
    cleaned = sanitize_text(text, limit * 2)
    return _fit(neutralize_mentions(escape_markdown(cleaned)), limit)


def _link_safe(url: str) -> bool:
    """Whether ``url`` can sit inside ``[label](url)`` without breaking the markdown."""
    return not any(ch in url for ch in "()<> ")


# --------------------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------------------


@dataclass
class DiscordMessage:
    """One webhook execution: optional ``content`` plus up to ten embeds."""

    content: str | None = None
    embeds: list[dict[str, Any]] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {"allowed_mentions": dict(_ALLOWED_MENTIONS)}
        if self.content:
            body["content"] = self.content
        if self.embeds:
            body["embeds"] = self.embeds
        return body

    @property
    def text(self) -> str:
        """Plain-text flattening of everything a reader sees (used for hashing and validation)."""
        lines: list[str] = []
        if self.content:
            lines.append(self.content)
        for embed in self.embeds:
            lines.extend(_flatten_embed(embed))
        return "\n".join(lines)


def _flatten_embed(embed: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    author = embed.get("author", {}).get("name")
    if author:
        lines.append(author)
    if embed.get("title"):
        lines.append(embed["title"])
    if embed.get("url"):
        lines.append(embed["url"])
    if embed.get("description"):
        lines.append(embed["description"])
    for item in embed.get("fields", []):
        lines.append(f"{item['name']}: {item['value']}")
    footer = embed.get("footer", {}).get("text")
    if footer:
        lines.append(footer)
    return lines


def embed_char_count(embed: dict[str, Any]) -> int:
    """Characters Discord counts against the 6000-per-message embed budget."""
    total = len(embed.get("title") or "") + len(embed.get("description") or "")
    total += len(embed.get("author", {}).get("name") or "") + len(embed.get("footer", {}).get("text") or "")
    for item in embed.get("fields", []):
        total += len(item["name"]) + len(item["value"])
    return total


# --------------------------------------------------------------------------------------
# Embeds
# --------------------------------------------------------------------------------------


def _field(name: str, value: str, *, inline: bool = False) -> dict[str, Any]:
    return {"name": _fit(name, EMBED_FIELD_NAME_MAX), "value": _fit(value, EMBED_FIELD_VALUE_MAX), "inline": inline}


def _affected(evidence: EvidenceItem) -> str:
    lines: list[str] = []
    products = [safe(product, 80) for product in evidence.products[:PRODUCTS_MAX]]
    if products:
        lines.append(", ".join(product for product in products if product))
    cves = [safe(cve, 32) for cve in evidence.cves[:CVES_MAX]]
    if cves:
        lines.append(", ".join(cve for cve in cves if cve))
    return "\n".join(line for line in lines if line)


def _exploitation(evidence: EvidenceItem) -> str:
    parts: list[str] = []
    if evidence.kev_status in _KEV_LABEL:
        parts.append(_KEV_LABEL[evidence.kev_status])
    if evidence.exploitation_status in _EXPLOITATION_LABEL:
        parts.append(_EXPLOITATION_LABEL[evidence.exploitation_status])
    if evidence.cvss_score is not None:
        parts.append(f"CVSS {evidence.cvss_score:g}")
    return " · ".join(parts)


def _evidence_links(evidence: EvidenceItem) -> str:
    """Up to three ``• [label](url)`` bullets; a link is never cut in half to satisfy the field limit."""
    lines: list[str] = []
    for source in evidence.sources[:EVIDENCE_LINKS_MAX]:
        label = safe(source.label, 40) or "source"
        bullet = f"• [{label}]({source.url})" if _link_safe(source.url) else f"• {label} — {source.url}"
        if sum(len(line) + 1 for line in lines) + len(bullet) > EMBED_FIELD_VALUE_MAX:
            break
        lines.append(bullet)
    return "\n".join(lines)


def _published(evidence: EvidenceItem) -> tuple[str, str | None]:
    """Human ``published 2026-08-25 10:00 UTC`` for the footer and an ISO timestamp for Discord."""
    if not evidence.published:
        return "", None
    try:
        when = datetime.strptime(evidence.published, _PUBLISHED_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return "", None
    return f"published {when:%Y-%m-%d %H:%M} UTC", when.isoformat()


def _story_embed(item: BriefItem, evidence: EvidenceItem) -> dict[str, Any]:
    tag = item.section.value + (" · UPDATE" if evidence.material_update else "")
    embed: dict[str, Any] = {
        "author": {"name": _fit(tag, EMBED_AUTHOR_MAX)},
        "title": safe(item.headline, EMBED_TITLE_MAX) or safe(evidence.title, EMBED_TITLE_MAX) or item.ref,
        "url": item.source_url,
        "color": SECTION_COLORS[item.section],
        "fields": [],
    }
    why = safe(item.why_it_matters, WHY_MAX)
    if why:
        embed["description"] = why
    affected = _affected(evidence)
    if affected:
        embed["fields"].append(_field("Affected", affected, inline=True))
    exploitation = _exploitation(evidence)
    if exploitation:
        embed["fields"].append(_field("Exploitation", exploitation, inline=True))
    summary = safe(evidence.summary, SUMMARY_MAX)
    if summary and summary.casefold() != embed["title"].casefold():
        embed["fields"].append(_field("What happened", summary))
    links = _evidence_links(evidence)
    if links:
        embed["fields"].append(_field(f"Evidence · {item.confidence.label}", links))
    else:
        embed["fields"].append(_field("Confidence", item.confidence.label, inline=True))
    embed["fields"].append(_field("Source", item.source_url))
    publisher = safe(evidence.sources[0].label if evidence.sources else item.source_label, 40)
    published_text, timestamp = _published(evidence)
    footer = " · ".join(part for part in (item.ref, publisher, published_text) if part)
    embed["footer"] = {"text": _fit(footer, EMBED_FOOTER_MAX)}
    if timestamp:
        embed["timestamp"] = timestamp
    return _shrink(embed)


def _shrink(embed: dict[str, Any]) -> dict[str, Any]:
    """Defence in depth: bring an embed under the per-message budget by dropping the least vital text."""
    for name in ("What happened", "Affected", "Exploitation"):
        if embed_char_count(embed) <= DISCORD_MAX_EMBED_TOTAL_CHARS:
            break
        embed["fields"] = [item for item in embed["fields"] if item["name"] != name]
    if embed_char_count(embed) > DISCORD_MAX_EMBED_TOTAL_CHARS and embed.get("description"):
        embed["description"] = _fit(embed["description"], 200)
    return embed


def _bullets(values: list[str]) -> str:
    cleaned = [safe(value, LIST_ITEM_MAX) for value in values[:LIST_ITEMS_MAX]]
    return "\n".join(f"• {value}" for value in cleaned if value)


def _prep_learn_embed(draft: BriefingDraft) -> dict[str, Any] | None:
    prep = _bullets(draft.prep)
    learn = draft.learn
    if not prep and learn is None:
        return None
    embed: dict[str, Any] = {"title": "Prep · defensive actions", "color": META_COLOR, "fields": []}
    if prep:
        embed["description"] = _fit(prep, EMBED_DESCRIPTION_MAX)
    if learn is not None:
        topic = safe(learn.topic, 140)
        if learn.technique_id:
            topic = f"{topic} (ATT&CK {safe(learn.technique_id, 20)})".strip()
        why = safe(learn.why, 200)
        value = topic + (f"\n{why}" if why else "")
        if value.strip():
            embed["fields"].append(_field("Learn today", value))
    if not embed["fields"]:
        del embed["fields"]
    return embed


def _watch_embed(draft: BriefingDraft) -> dict[str, Any] | None:
    watch = _bullets(draft.watch)
    if not watch:
        return None
    return {
        "title": "Watch · nothing crossed the briefing threshold",
        "description": _fit(watch, EMBED_DESCRIPTION_MAX),
        "color": META_COLOR,
    }


# --------------------------------------------------------------------------------------
# Packing
# --------------------------------------------------------------------------------------


def _pack(embeds: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Greedy, order-preserving packing under the per-message embed count and character budgets."""
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_chars = 0
    for embed in embeds:
        size = embed_char_count(embed)
        if current and (len(current) >= DISCORD_MAX_EMBEDS_PER_MESSAGE or current_chars + size > DISCORD_MAX_EMBED_TOTAL_CHARS):
            groups.append(current)
            current, current_chars = [], 0
        current.append(embed)
        current_chars += size
    if current:
        groups.append(current)
    return groups


def _edition(local: datetime) -> str:
    if local.hour < 12:
        return "Morning"
    if local.hour < 17:
        return "Afternoon"
    return "Evening"


def _header(briefing: Briefing, stories: int) -> str:
    edition = briefing.title.split(" ")[0] if briefing.title else "Daily"
    first = f"**ARKHAM** · {briefing.title} · {briefing.date_long or briefing.date_label}"
    stats = f"{briefing.events_analyzed} events analyzed · {briefing.sources_ok}/{briefing.sources_checked} sources"
    if briefing.generated_by:
        stats += f" · analyst: {safe(briefing.generated_by, 60)}"
    if briefing.quiet:
        second = f"No material updates this {edition.lower()}. {stats}"
    else:
        second = f"{stories} {'story' if stories == 1 else 'stories'} · {stats}"
    return _fit(f"{first}\n{second}", DISCORD_MAX_CONTENT_CHARS)


def render_discord_messages(briefing: Briefing) -> list[DiscordMessage]:
    """Turn the core briefing into ordered webhook messages (header first, stories in priority order)."""
    by_ref = briefing.evidence_by_ref
    embeds: list[dict[str, Any]] = []
    stories = 0
    if not briefing.quiet:
        for item in briefing.draft.items:
            evidence = by_ref.get(item.ref)
            if evidence is None:
                continue
            embeds.append(_story_embed(item, evidence))
            stories += 1
    else:
        watch = _watch_embed(briefing.draft)
        if watch:
            embeds.append(watch)
    closing = _prep_learn_embed(briefing.draft)
    if closing:
        embeds.append(closing)

    groups = _pack(embeds) or [[]]
    messages = [DiscordMessage(embeds=group) for group in groups]
    messages[0].content = _header(briefing, stories)
    total = len(messages)
    for index, message in enumerate(messages[1:], start=2):
        message.content = f"**ARKHAM** · continued {index}/{total}"
    return messages


def render_discord_briefing(
    draft: BriefingDraft,
    pack: EvidencePack,
    *,
    generated_by: str,
    now: datetime,
    tz: ZoneInfo,
) -> Briefing:
    """Build the core :class:`Briefing` for Discord: every validated story is kept (no SMS budget)."""
    items = [] if pack.quiet else [item for item in draft.items if item.ref in pack.refs]
    evidence = [pack.refs[item.ref] for item in items]
    local = now.astimezone(tz)
    briefing = Briefing(
        date_label=pack.date_label,
        date_long=f"{local:%A}, {local:%B} {local.day}, {local.year}",
        title=f"{_edition(local)} Intelligence Brief",
        draft=draft.model_copy(update={"items": items}),
        evidence=evidence,
        quiet=pack.quiet,
        events_analyzed=pack.events_analyzed,
        sources_checked=pack.sources_checked,
        sources_ok=pack.sources_ok,
        generated_by=generated_by,
    )
    messages = render_discord_messages(briefing)
    briefing.messages = [message.text for message in messages]
    briefing.text = "\n\n".join(briefing.messages)
    return briefing
