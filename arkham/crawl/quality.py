"""Deterministic extraction-quality scoring and block-page classification.

``score_extraction`` maps an :class:`~arkham.crawl.models.ExtractedArticle` to ``0.0..1.0`` from
plain, explainable signals (text length, paragraph count, semantic container, text-to-visible ratio,
title presence, duplicate paragraphs, JavaScript-shell detection). ``needs_browser`` is the
Level-2 decision the design reserves for a future renderer: ``True`` means Level-1 extraction is not
good enough to trust. ``classify_interstitial`` recognises CAPTCHA / login / access-denied pages so a
fetch can be categorised honestly instead of being mistaken for a thin article.
"""

from __future__ import annotations

import re

from arkham.crawl.models import CrawlFailureReason, ExtractedArticle

TARGET_TEXT_CHARS = 600
TARGET_PARAGRAPHS = 4
MIN_USABLE_CHARS = 80
MIN_USABLE_CAP = 0.3
INTERSTITIAL_MAX_CHARS = 1500

_WEIGHTS = {
    "length": 0.30,
    "paragraphs": 0.20,
    "container": 0.15,
    "ratio": 0.15,
    "title": 0.10,
    "unique": 0.10,
}

_CAPTCHA_RE = re.compile(
    r"captcha|verify (?:that )?you are (?:a )?human|are you a robot|checking your browser|"
    r"attention required|just a moment|ddos[- ]protection|browser challenge|prove you are human|"
    r"security check to access|enable javascript and cookies to continue",
    re.I,
)
_AUTH_RE = re.compile(
    r"sign in to continue|log ?in to continue|please (?:sign|log) ?in|login required|subscribers? only|"
    r"subscribe to (?:read|continue)|create an account to|members only|authentication required|"
    r"you must be logged in",
    re.I,
)
_BLOCKED_RE = re.compile(
    r"access denied|request blocked|you have been blocked|error 1020|forbidden|not authorized to access|"
    r"unusual traffic from your (?:computer|network)|rate limit exceeded",
    re.I,
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def score_extraction(article: ExtractedArticle) -> float:
    """Quality in ``0.0..1.0``; empty text or a JavaScript shell scores ``0.0``."""
    text = article.article_text.strip()
    if not text or article.js_shell:
        return 0.0
    chars = len(text)
    length = min(1.0, chars / TARGET_TEXT_CHARS)
    paragraphs = min(1.0, article.paragraph_count / TARGET_PARAGRAPHS)
    container = 1.0 if article.article_container else 0.0
    ratio = min(1.0, chars / article.visible_text_chars) if article.visible_text_chars > 0 else 0.5
    title = 1.0 if article.title.strip() else 0.0
    unique = 1.0 - _clamp(article.duplicate_text_ratio)
    score = (
        _WEIGHTS["length"] * length
        + _WEIGHTS["paragraphs"] * paragraphs
        + _WEIGHTS["container"] * container
        + _WEIGHTS["ratio"] * ratio
        + _WEIGHTS["title"] * title
        + _WEIGHTS["unique"] * unique
    )
    if chars < MIN_USABLE_CHARS:
        score = min(score, MIN_USABLE_CAP)
    return round(_clamp(score), 3)


def needs_browser(article: ExtractedArticle, threshold: float) -> bool:
    """Level-1 extraction is not trustworthy: a JS shell, or a quality score under ``threshold``."""
    return article.js_shell or score_extraction(article) < threshold


def classify_interstitial(title: str, visible_text: str) -> CrawlFailureReason | None:
    """Recognise CAPTCHA / login-wall / access-denied pages (only for short, shell-like documents)."""
    if len(visible_text) > INTERSTITIAL_MAX_CHARS:
        return None
    haystack = f"{title}\n{visible_text}"
    if _CAPTCHA_RE.search(haystack):
        return CrawlFailureReason.CAPTCHA_DETECTED
    if _AUTH_RE.search(haystack):
        return CrawlFailureReason.AUTHENTICATION_REQUIRED
    if _BLOCKED_RE.search(haystack):
        return CrawlFailureReason.BLOCKED_BY_SITE
    return None
