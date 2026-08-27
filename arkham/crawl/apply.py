"""Bridge from Arkham Crawl output into the existing ``RawItem -> CyberEvent`` pipeline.

``enrich_raw_item`` returns a *copy* of a feed-discovered :class:`~arkham.models.RawItem` carrying the
bounded, sanitised article text and the structured facts :mod:`arkham.intelligence.normalize`
already understands (``cve_ids``, ``cwes``, ``referenced_links``, ``actor_mentions``, ``malware``,
``products``, ``exploitation_hint``) plus a small ``extra["crawl"]`` record. It never overrides a
stronger fact the adapter already supplied and never changes the item's identity (``raw_hash``).
"""

from __future__ import annotations

from typing import Any

from arkham.crawl.models import ExtractedArticle, FetchMethod
from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text

DEFAULT_MAX_CONTENT_CHARS = 6000
_HINT_RANK = {"": 0, "poc": 1, "active": 2, "widespread": 3, "mass": 3}
_ACTIVE_RE = ("actively exploited", "exploited in the wild", "under active exploitation", "exploitation in the wild")
_MASS_RE = ("mass exploitation",)
_POC_RE = ("proof", "poc", "exploit code", "working exploit", "weaponi")


def _merge(existing: Any, new: list[str], *, limit: int) -> list[str]:
    values: list[str] = []
    for value in [*(existing if isinstance(existing, list) else []), *new]:
        text = str(value).strip()
        if text and text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return values


def _hint(article: ExtractedArticle) -> str:
    phrases = [item.value.lower() for item in article.indicators if item.type in {"exploit_reference", "kev_reference"}]
    if any(any(cue in phrase for cue in _MASS_RE) for phrase in phrases):
        return "widespread"
    if any(item.type == "kev_reference" for item in article.indicators) or any(
        any(cue in phrase for cue in _ACTIVE_RE) for phrase in phrases
    ):
        return "active"
    if any(any(cue in phrase for cue in _POC_RE) for phrase in phrases):
        return "poc"
    return ""


def enrich_raw_item(
    item: RawItem,
    article: ExtractedArticle,
    *,
    method: FetchMethod = FetchMethod.HTTP,
    min_quality: float = 0.0,
    max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS,
) -> RawItem:
    """Return a copy of ``item`` enriched with ``article``; below ``min_quality`` only metadata is recorded."""
    extra: dict[str, Any] = dict(item.extra)
    applied = bool(article.article_text) and article.quality_score >= min_quality
    extra["crawl"] = {
        "applied": applied,
        "fetch_method": method.value,
        "canonical_url": article.canonical_url,
        "quality_score": article.quality_score,
        "content_hash": article.content_hash,
        "indicators": len(article.indicators),
        "injection_flagged": article.injection_flagged,
        "published_at": article.published_at.isoformat() if article.published_at else None,
        "updated_at": article.updated_at.isoformat() if article.updated_at else None,
    }
    update: dict[str, Any] = {"extra": extra}
    if not applied:
        return item.model_copy(update=update)

    by_type: dict[str, list[str]] = {}
    for indicator in article.indicators:
        by_type.setdefault(indicator.type, []).append(indicator.value)
    extra["referenced_links"] = _merge(extra.get("referenced_links"), article.relevant_links, limit=50)
    if by_type.get("cve"):
        extra["cve_ids"] = _merge(extra.get("cve_ids"), by_type["cve"], limit=30)
    if by_type.get("cwe"):
        extra["cwes"] = _merge(extra.get("cwes"), by_type["cwe"], limit=20)
    if by_type.get("actor"):
        extra["actor_mentions"] = _merge(extra.get("actor_mentions"), by_type["actor"], limit=20)
    if by_type.get("malware"):
        extra["malware"] = _merge(extra.get("malware"), by_type["malware"], limit=20)
    if by_type.get("vendor_product"):
        extra["products"] = _merge(extra.get("products"), by_type["vendor_product"], limit=15)
    hint = _hint(article)
    current = str(extra.get("exploitation_hint") or "").casefold()
    if hint and _HINT_RANK.get(hint, 0) > _HINT_RANK.get(current, 0):
        extra["exploitation_hint"] = hint
    content = sanitize_text(article.article_text, max_content_chars)
    if len(content) > len(item.content or ""):
        update["content"] = content
    if item.published_at is None and article.published_at is not None:
        update["published_at"] = article.published_at
    if item.updated_at is None and article.updated_at is not None and article.published_at is not None:
        update["updated_at"] = article.updated_at
    return item.model_copy(update=update)
