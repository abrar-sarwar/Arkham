"""Arkham Crawl: native, deterministic, security-hardened article fetching and extraction.

Library layer used by collectors (no paid crawler API, no browser, no JavaScript):

* :mod:`arkham.crawl.fetcher` — one hardened HTTPS GET per URL with robots.txt respect, conditional
  requests, content-type gating and categorised failures (``fetch_page`` / ``fetch_and_extract``).
* :mod:`arkham.crawl.extract` — offline HTML/plain-text extraction into a bounded, sanitised
  :class:`~arkham.crawl.models.ExtractedArticle` (metadata, headings, text, validated links).
* :mod:`arkham.crawl.quality` — deterministic quality score, browser-fallback decision, interstitial
  classification.
* :mod:`arkham.crawl.indicators` — CTI artifact candidates (CVE/CWE/ATT&CK/GHSA, actors, malware, IPs,
  domains, URLs, emails, hashes, products/versions, KEV and exploit references).
* :mod:`arkham.crawl.apply` — ``enrich_raw_item`` feeds the result into the existing normalisation.
"""

from arkham.crawl.models import CrawlMetrics

__all__ = ["CrawlMetrics"]
