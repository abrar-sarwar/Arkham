"""SMS encoding detection, segment counting and multi-part splitting.

Carriers bill by *segment*, and the segment size depends on the alphabet the whole message can be
encoded in: GSM 03.38 (7-bit) fits 160 septets in a single segment and 153 per segment when
concatenated; anything outside that alphabet forces UCS-2 (16-bit) at 70 / 67 UTF-16 code units.
Twilio additionally caps a single API request body at :data:`TWILIO_MAX_BODY` characters, so a
long briefing is split into ``ARKHAM i/N`` parts on section boundaries before delivery.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

TWILIO_MAX_BODY = 1600
"""Maximum characters Twilio accepts in one Messages API body."""

GSM7_SINGLE = 160
GSM7_CONCAT = 153
UCS2_SINGLE = 70
UCS2_CONCAT = 67

PART_PREFIX_FORMAT = "ARKHAM {index}/{total}\n"
_SECTION_SEP = "\n\n"
_LINE_SEP = "\n"
_SECTION_SPLIT_RE = re.compile(r"\n{2,}")
_MAX_PACK_ITERATIONS = 64
_CONSERVATIVE_TOTAL = 9999

# GSM 03.38 default alphabet (3GPP TS 23.038 §6.2.1). Code point 0x1B is the escape marker that
# switches to the extension table; it is not a character and is therefore excluded.
GSM7_BASIC: frozenset[str] = frozenset(
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞÆæßÉ"
    " !\"#¤%&'()*+,-./"
    "0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmno"
    "pqrstuvwxyzäöñüà"
)
"""The 127 printable/whitespace characters of the GSM 03.38 basic table (one septet each)."""

GSM7_EXTENDED: frozenset[str] = frozenset("\f^{}\\[~]|€")
"""GSM 03.38 extension table: each character costs two septets (ESC + code)."""

_GSM7_ALL: frozenset[str] = GSM7_BASIC | GSM7_EXTENDED


def is_gsm7(text: str) -> bool:
    """Return True when every character of ``text`` is representable in GSM 03.38 (basic or extension)."""
    return all(ch in _GSM7_ALL for ch in text)


def gsm7_length(text: str) -> int:
    """Length of ``text`` in GSM-7 septets; extension-table characters count double.

    Callers should check :func:`is_gsm7` first: characters outside both tables count as one so
    the function stays total, but such text cannot actually be sent as GSM-7.
    """
    return sum(2 if ch in GSM7_EXTENDED else 1 for ch in text)


def ucs2_length(text: str) -> int:
    """Length of ``text`` in UTF-16 code units (astral characters such as most emoji count two)."""
    return len(text.encode("utf-16-le")) // 2


def encoding_of(text: str) -> str:
    """Return ``"GSM-7"`` when the text fits the GSM alphabet, otherwise ``"UCS-2"``."""
    return "GSM-7" if is_gsm7(text) else "UCS-2"


def count_segments(text: str) -> int:
    """Number of SMS segments a single message body occupies (0 for an empty body)."""
    if not text:
        return 0
    if is_gsm7(text):
        length = gsm7_length(text)
        return 1 if length <= GSM7_SINGLE else math.ceil(length / GSM7_CONCAT)
    length = ucs2_length(text)
    return 1 if length <= UCS2_SINGLE else math.ceil(length / UCS2_CONCAT)


# --------------------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------------------


def _prefix_width(total: int) -> int:
    """Width of the widest ``ARKHAM i/N`` prefix for ``total`` parts (``i`` is never wider than ``N``)."""
    return len(PART_PREFIX_FORMAT.format(index=total, total=total))


def _chunk_hard(text: str, capacity: int) -> list[str]:
    """Cut ``text`` into consecutive slices of at most ``capacity`` characters."""
    return [text[i : i + capacity] for i in range(0, len(text), capacity)]


def _pack(units: list[str], capacity: int, separator: str) -> list[str]:
    """Greedily pack ``units`` (in order) into strings of at most ``capacity`` characters.

    Units are joined with ``separator``; a unit that is longer than ``capacity`` on its own is
    handed to :func:`_split_oversized` so that the result never exceeds ``capacity``.
    """
    parts: list[str] = []
    current: list[str] = []
    current_len = 0
    for unit in units:
        if not unit:
            continue
        extra = len(unit) if not current else len(separator) + len(unit)
        if current and current_len + extra <= capacity:
            current.append(unit)
            current_len += extra
            continue
        if current:
            parts.append(separator.join(current))
            current, current_len = [], 0
        if len(unit) <= capacity:
            current, current_len = [unit], len(unit)
        else:
            pieces = _split_oversized(unit, capacity, separator)
            parts.extend(pieces[:-1])
            current, current_len = [pieces[-1]], len(pieces[-1])
    if current:
        parts.append(separator.join(current))
    return parts


def _split_oversized(unit: str, capacity: int, separator: str) -> list[str]:
    """Break a unit that does not fit in ``capacity``: by lines first, then on the limit itself."""
    if separator == _SECTION_SEP and _LINE_SEP in unit:
        return _pack(unit.split(_LINE_SEP), capacity, _LINE_SEP)
    return _chunk_hard(unit, capacity)


def _sections(text: str) -> list[str]:
    """Split on blank lines (any run of two or more newlines), dropping sections that would be empty."""
    return [section.strip(_LINE_SEP) for section in _SECTION_SPLIT_RE.split(text) if section.strip()]


def split_message(text: str, *, max_chars: int, hard_limit: int = TWILIO_MAX_BODY) -> list[str]:
    """Split ``text`` into SMS bodies no longer than ``min(max_chars, hard_limit)`` characters.

    A body that already fits is returned unchanged as the only element. Otherwise the text is
    split on blank-line section boundaries and sections are packed greedily into parts, each
    prefixed with ``ARKHAM i/N``; a section that cannot fit on its own is split on line
    boundaries and, as a last resort, on the limit. ``N`` is recomputed until it is stable so
    the prefix width used while packing always matches the final part count. Parts are never
    empty and never exceed ``hard_limit``. An empty or whitespace-only text yields no parts.
    Raises :class:`ValueError` when the limit is too small to hold a prefix plus any text.
    """
    limit = min(max_chars, hard_limit)
    if limit < 1:
        raise ValueError("max_chars and hard_limit must be positive")
    if len(text) <= limit:
        return [text] if text.strip() else []
    sections = _sections(text)
    if not sections:
        return []

    total = 1
    bodies: list[str] = []
    # Starting from N=1, packing with the prefix width for N parts yields >= N parts, and a
    # larger N never shrinks the prefix, so the sequence is monotone and converges quickly.
    for _ in range(_MAX_PACK_ITERATIONS):
        bodies = _pack(sections, _capacity(limit, _prefix_width(total)), _SECTION_SEP)
        if len(bodies) == total:
            break
        total = len(bodies)
    else:
        # Unreachable by the argument above; pack with a prefix width no realistic N exceeds.
        bodies = _pack(sections, _capacity(limit, _prefix_width(_CONSERVATIVE_TOTAL)), _SECTION_SEP)
        total = len(bodies)

    return [PART_PREFIX_FORMAT.format(index=i, total=total) + body for i, body in enumerate(bodies, start=1)]


def _capacity(limit: int, prefix_width: int) -> int:
    """Characters available for the body of one part once the prefix is accounted for."""
    capacity = limit - prefix_width
    if capacity < 1:
        raise ValueError(f"limit {limit} leaves no room for the message prefix")
    return capacity


# --------------------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MessageStats:
    """Cost-relevant facts about a set of SMS bodies."""

    messages: int
    segments: int
    chars: int
    encoding: str


def message_stats(parts: list[str]) -> MessageStats:
    """Aggregate message count, billed segments, characters and the encoding across ``parts``.

    The encoding is ``"UCS-2"`` if any part needs it (that part is billed at UCS-2 rates), and
    ``"GSM-7"`` otherwise, including for an empty list.
    """
    segments = sum(count_segments(part) for part in parts)
    chars = sum(len(part) for part in parts)
    encoding = "UCS-2" if any(not is_gsm7(part) for part in parts) else "GSM-7"
    return MessageStats(messages=len(parts), segments=segments, chars=chars, encoding=encoding)
