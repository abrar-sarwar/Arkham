"""URL normalization and canonical-link trust rules for Arkham Crawl."""

from __future__ import annotations

from urllib.parse import urlsplit

from arkham.security.urls import UrlValidationError, canonicalize_url, validate_public_url


def normalize_crawl_url(url: str) -> str:
    """Validate a public HTTPS URL and return its deterministic crawl/cache key."""
    return canonicalize_url(validate_public_url(url))


def _related_hosts(left: str, right: str) -> bool:
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def accept_canonical_url(response_url: str, candidate: str | None) -> str | None:
    """Accept a page canonical only when it remains on the validated response host boundary."""
    if not candidate:
        return None
    try:
        response = validate_public_url(response_url)
        canonical = normalize_crawl_url(candidate)
    except (UrlValidationError, ValueError):
        return None
    response_host = (urlsplit(response).hostname or "").lower().removeprefix("www.")
    canonical_host = (urlsplit(canonical).hostname or "").lower().removeprefix("www.")
    return canonical if _related_hosts(response_host, canonical_host) else None

