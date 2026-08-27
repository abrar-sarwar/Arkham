# Arkham Crawl — Native CTI Crawling Design (2026-08-26)

## Implementation status (2026-08-27)

Implemented and tested (`arkham/crawl/`): `models.py`, `normalize.py`, `extract.py`, `quality.py`,
`indicators.py`, `fetcher.py` (Level-1 fetch + `RobotsPolicy` with an in-memory TTL cache), and
`apply.py` (`enrich_raw_item` → existing normalization). Deviation from the text below: the extractor
is built on the standard-library `html.parser` (container-density selection + noise removal) instead of
Trafilatura — Trafilatura was pinned but never installed or exercised, and the stdlib extractor satisfies
the fixtures and tests with no new dependency; the Playwright extra was removed for the same reason.

Deferred (not required for v1, no tests exist for them): `limiter.py` (per-domain concurrency/delay),
`browser.py` (Level-2 renderer — `needs_browser()` exists but nothing consumes it), `service.py`
(scheduled batch orchestration, Level-0 decisions, cache reuse), the SQLite `crawl_records`/`robots_cache`
tables (`RobotsPolicy.dirty_records()` hands records to a future store), and the runner seam
(`Components.crawl_items`). The `ARKHAM_CRAWL_*` settings for those pieces are validated but unused.
The daily run therefore still works from feed/API records; collectors that need full article text call
`fetch_and_extract` + `enrich_raw_item` directly.

## Goal

Arkham Crawl enriches feed/API discoveries with cached, deterministic article extraction without any paid
crawling API. It minimizes page requests, treats the internet as hostile input, and preserves Arkham's
existing `RawItem -> CyberEvent -> EvidencePack` intelligence contracts.

## Integration boundary

`collect_all()` remains the feed/API discovery layer. The runner passes its `RawItem` list to
`CrawlService.enrich_items()` before raw-item persistence and normalization:

```text
feed/API adapters
  -> URL normalization + in-run URL deduplication
  -> historical raw/crawl lookup
  -> deterministic pre-fetch decision
  -> Level 0 feed/API acceptance OR Level 1 HTTP
  -> Level 2 browser only after poor HTTP extraction
  -> CTI artifacts + sanitized extracted text
  -> existing normalization/enrichment/deduplication/scoring
```

Arkham Crawl enriches copies of `RawItem` through bounded content and structured `extra` fields. Existing
source adapters and downstream intelligence stages do not learn how fetching or rendering works.

## Components

- `crawl/models.py`: fetch methods, failure categories, extracted article/indicator records, cache records,
  robots records, decisions, and persisted run metrics.
- `crawl/normalize.py`: safe URL validation/canonicalization and same-host canonical-link acceptance.
- `crawl/quality.py`: deterministic extraction score and browser-fallback decision.
- `crawl/indicators.py`: cautious CTI artifact candidates with value/type/context/source; extraction never
  labels a candidate malicious.
- `crawl/extract.py`: Trafilatura 2.2 main-text/metadata extraction plus a bounded HTML parser for semantic
  containers, canonical links, headings, and relevant links. Raw HTML is never persisted or sent to a model.
- `crawl/robots.py`: cached `urllib.robotparser` policy and crawl-delay parsing.
- `crawl/limiter.py`: bounded global and per-domain concurrency, minimum inter-request delay, and
  per-domain backoff.
- `crawl/fetcher.py`: Level-1 conditional HTTP, content-type/size/timeout/retry enforcement, and clean
  failure mapping using the existing `SafeHttpClient`.
- `crawl/browser.py`: optional Playwright Chromium renderer with an isolated context, blocked downloads and
  service workers, bounded timeout/concurrency, request interception, public-HTTPS validation, and clean
  shutdown.
- `crawl/service.py`: early decisions, cache reuse, parallel Level-1 execution, conditional revalidation,
  Level-2 escalation, RawItem enrichment, persistence, and metrics.

## Fetch levels and early decisions

Level 0 is accepted when structured API facts or sufficiently informative feed text already establish a
security event. Level-0 items record `fetch_method=feed` and make no article request.

Before Level 1, Arkham validates and canonicalizes the URL, drops exact in-run URL duplicates, checks the
raw hash and crawl cache, and scores title/summary metadata. Tier-1 structured records and explicit CTI
identifiers are never discarded. A generic journalism record with no security signal may be rejected before
fetch and before downstream normalization. A cached URL with the same raw hash reuses the cached sanitized
extraction without a request. A changed discovery uses stored ETag/Last-Modified validators.

Level 1 accepts only HTML/XHTML/plain-text article responses. `304` reuses the cached extraction. A `200`
response is extracted and compared using a SHA-256 hash of normalized extracted text. Identical text is
unchanged even if page chrome or HTML changes.

Level 2 is considered only when Level-1 extraction is below the configured quality threshold or is an
obvious JavaScript shell. It is disabled by default and requires the optional `crawl-browser` dependency plus
an installed Chromium binary. A disabled/unavailable browser produces an observable fallback failure while
the usable feed or HTTP text remains available.

## URL and redirect policy

All fetched URLs pass Arkham's public-URL validation. Canonicalization lowercases scheme/host, removes
fragments and known marketing parameters (`utm_*`, `gclid`, `fbclid`, `mc_cid`, `mc_eid`), orders remaining
query pairs, and normalizes duplicate slashes. Generic parameters such as `id`, `ref`, and `source` are kept
because they may identify the resource. Redirect hops are validated by `SafeHttpClient`. HTML/link-header
canonicals are accepted only when public HTTPS and on the response host or its subdomain boundary.

## Robots policy

Arkham identifies itself with `Arkham-CTI/1.0 (+personal threat-intelligence agent)`. Robots rules are cached
per host in SQLite with retrieval time and status. Explicit `Disallow`, HTTP 401/403, parse failure, timeout,
and transient robots retrieval failure fail closed for article crawling during that run. HTTP 404/410 means
no published robots policy and allows fetching. Cached successful/no-policy rules expire after 24 hours;
cached transient failures expire after 30 minutes. `Crawl-delay` and `Request-rate` are converted into the
effective per-host delay where practical. Arkham never bypasses a denial.

## Rate and retry policy

Defaults are global concurrency 6, per-domain concurrency 1, and a 250 ms minimum gap per host. Limits are
environment-configurable and clamped to safe ranges. Level-1 retries only HTTP 429, 502, 503, and 504, at
most twice. `Retry-After` is honored up to the configured maximum; otherwise bounded exponential delays are
used. A domain backoff is shared by that run. Other 4xx responses, timeouts, malformed content, and unsafe
redirects are not retried. One source or domain never aborts the run.

## Extraction and quality

Trafilatura receives already downloaded HTML; its network fetch functions are not used. Arkham combines its
main text/metadata with locally parsed title, description, author, publication/update timestamps, headings,
canonical URL, semantic-container evidence, paragraph counts, and validated links. Scripts, styles, forms,
navigation, ads, cookie UI, related grids, comments, and footer chrome are excluded. Extracted text is
prompt-injection scanned, neutralized, and bounded before storage or normalization.

Quality is `0.00..1.00`, derived from body length, paragraph/sentence density, semantic article containers,
text-to-visible-content ratio, duplicate paragraph ratio, title/body relation, and JS-shell indicators. The
score is deterministic and fixture-testable. Browser fallback is allowed only below
`ARKHAM_CRAWL_QUALITY_THRESHOLD`.

## CTI extraction and change detection

Deterministic extraction identifies CVE, CWE, ATT&CK, GHSA, public/private IP candidates with contextual
gating, domains, URLs, emails, hashes, explicit actor identifiers, cautiously phrased malware names,
vendor/product mentions, versions, KEV language, and exploit references. Each indicator contains type,
value, a short sanitized context, and the canonical source URL. These are evidence candidates, not malicious
verdicts.

SQLite `crawl_records` stores original/canonical URL, domain, validators, normalized content hash, timestamps,
status/method/quality, bounded article metadata and extracted text, indicators, source raw hash, and failure.
`robots_cache` stores host policy. On changed text, Arkham compares title and CTI-artifact sets plus normalized
text similarity. Material changes annotate the `RawItem`; normalization carries a bounded source-update
marker into `CyberEvent`, and existing history/fingerprint logic makes a previously briefed event eligible
only when the deterministic change is substantive.

## Security and failure boundaries

No page content can change configuration, ranking rules, tools, recipients, destinations, or prompts.
Embedded links are recorded only after validation and are never recursively crawled. Direct and browser
paths reject private/internal/link-local targets; browser requests are intercepted, service workers and
downloads are blocked, and nonessential resource types are aborted. CAPTCHA, authentication, paywall,
robots, rate-limit, site block, and render failures are categorized and reported—never bypassed.

## Observability and configuration

`RunRecord.crawl` persists Level-0 discoveries, URL normalization, duplicates, historical hits, pre-fetch
rejections, conditional requests/304s, HTTP fetches, browser attempts/successes, robots denials, rate limits,
failures, content changes, and enriched items. The normal run summary prints an `Arkham Crawl` section. No
URL bodies, secrets, phone numbers, or full article text enter logs.

Configuration uses `ARKHAM_CRAWL_*` settings for enablement, concurrency, domain delay, quality, browser,
timeouts, retries, cache TTL, and bounded text size. There is no crawler credential or paid API setting.

## Dependencies and deployment

Trafilatura 2.2.0 is a pinned runtime dependency. Playwright 1.62.0 is a pinned optional extra because the
Python package and matching Chromium binary are large. GitHub Actions and AWS remain functional without the
browser extra; Level 0/1 are the production baseline. Operators who enable Level 2 install only Chromium and
its required system libraries. Arkham has no Firecrawl package, key, API call, fallback, documentation, or
quota requirement.

