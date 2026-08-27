"""CERT-EU (Computer Emergency Response Team for the EU institutions) feed adapter.

CERT-EU publishes RSS 2.0 feeds for security advisories and threat-intelligence products.
Feed quirks handled here or by the base adapter:

* ``<link>`` values are padded with whitespace and newlines (``RssAdapter`` strips them);
* ``<pubDate>`` carries ``CET``/``CEST`` abbreviations (``parse_datetime`` resolves them);
* advisory titles follow ``"<YYYY>-<NNN>: <Severity> Vulnerabilit(y|ies) in <Products>"``.

This module also hosts the small text helpers (:func:`extract_cve_ids`,
:func:`exploitation_hint`) shared by the sibling Tier-1 adapters (NCSC, Google Threat
Intelligence, MSRC, CERT/CC) so that every adapter recognises the same vocabulary.
"""

from __future__ import annotations

import re
from typing import Any

from arkham.security.prompt_injection import sanitize_text
from arkham.sources.rss import TITLE_MAX, RssAdapter

PUBLISHER = "CERT-EU"

#: Upper bound on the amount of sanitized text scanned for CVE ids / exploitation phrases.
FULL_TEXT_MAX = 250_000

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ACTIVE_RE = re.compile(r"actively exploited|exploited in the wild|under active exploitation", re.IGNORECASE)
_POC_RE = re.compile(r"proof[- ]of[- ]concept|\bPoC\b")
_NEGATION_RE = re.compile(r"\b(?:no|not|never|without|nor)\b|n't\b", re.IGNORECASE)
_NEGATION_WINDOW = 40

_ADVISORY_ID_RE = re.compile(r"^(\d{4}-\d{3}):")
_PRODUCTS_RE = re.compile(r"\bin\s+(?:the\s+)?(.+)$", re.IGNORECASE)
_PARENTHETICAL_RE = re.compile(r"\s*\([^)]*\)")
_TRAILING_QUALIFIER_RE = re.compile(r"\s+(?:exploited|actively exploited|under active exploitation)\s*$", re.IGNORECASE)
_PRODUCT_SPLIT_RE = re.compile(r"\s*,\s*|\s+and\s+")
_UPDATED_FLAG_RE = re.compile(r"^\s*\[UPDATED\]", re.IGNORECASE)
MAX_PRODUCTS = 10


def extract_cve_ids(*texts: str | None) -> list[str]:
    """Return the unique, upper-cased CVE identifiers found in ``texts`` in order of first appearance."""
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def exploitation_hint(*texts: str | None) -> str | None:
    """Classify what the source itself asserts about exploitation.

    Returns ``"active"`` when the text states in-the-wild exploitation, ``"poc"`` when it only
    mentions a proof-of-concept exploit, and ``None`` otherwise. A phrase preceded by a negation
    within a short window (``"was not exploited in the wild"``, ``"no evidence it has been
    actively exploited"``) does not count as an assertion.
    """
    text = "\n".join(t for t in texts if t)
    if not text:
        return None
    for match in _ACTIVE_RE.finditer(text):
        preceding = text[max(0, match.start() - _NEGATION_WINDOW) : match.start()]
        if not _NEGATION_RE.search(preceding):
            return "active"
    if _POC_RE.search(text):
        return "poc"
    return None


def split_products(title: str) -> list[str]:
    """Extract vendor/product names from an advisory title such as
    ``"Critical Vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway"``.

    Everything after the first ``"in"`` is taken as the product phrase; parentheticals
    (``("Copy Fail")``), a leading ``"the"`` and trailing status words (``"Exploited"``) are
    dropped; the remainder is split on commas and ``"and"``.
    """
    match = _PRODUCTS_RE.search(title)
    if not match:
        return []
    phrase = _PARENTHETICAL_RE.sub("", match.group(1))
    phrase = _TRAILING_QUALIFIER_RE.sub("", phrase).strip(" .:;-")
    products = [part.strip(" .") for part in _PRODUCT_SPLIT_RE.split(phrase)]
    return [p for p in products if p][:MAX_PRODUCTS]


class CertEuAdapter(RssAdapter):
    """CERT-EU security-advisory / threat-intelligence RSS adapter (Tier 1)."""

    def extra_fields(self, entry: Any) -> dict[str, Any]:
        """Advisory id, affected products, CVE ids and exploitation hint parsed from title and summary."""
        title = sanitize_text(entry.get("title"), TITLE_MAX)
        summary = sanitize_text(entry.get("summary") or entry.get("description") or "", FULL_TEXT_MAX)
        match = _ADVISORY_ID_RE.match(title)
        advisory_id = match.group(1) if match else None
        products = split_products(title[match.end() :]) if match else []
        return {
            "publisher": self.source.publisher or PUBLISHER,
            "advisory_id": advisory_id,
            "products": products,
            "cve_ids": extract_cve_ids(title, summary),
            "exploitation_hint": exploitation_hint(title, summary),
            "advisory_updated": bool(_UPDATED_FLAG_RE.match(summary)),
        }
