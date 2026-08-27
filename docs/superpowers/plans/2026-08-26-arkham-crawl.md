# Arkham Crawl Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native cached CTI article crawler, remove every Firecrawl surface, and finish Arkham v1 release verification without redesigning working intelligence or delivery layers.

**Architecture:** Feed/API adapters remain discovery. A runner-injected `CrawlService` enriches selected `RawItem` objects through Level 0 feed reuse, hardened conditional HTTP, and optional bounded Playwright rendering, while SQLite extends the existing state store for articles and robots rules.

**Tech Stack:** Python 3.11+, Pydantic 2, httpx, feedparser, Trafilatura 2.2, optional Playwright 1.62/Chromium, stdlib sqlite3/urllib.robotparser/concurrency, pytest, Ruff.

**Spec:** `docs/superpowers/specs/2026-08-26-arkham-crawl-design.md`

**Status (2026-08-27):** Tasks 1–3 complete (Task 3 with the stdlib extractor instead of Trafilatura);
Task 4 robots policy complete, limiter deferred; Task 5 Level-1 fetcher complete, browser deferred;
Tasks 6–8 (crawl storage tables, service, runner seam) deferred as post-v1; Task 9 documentation and
Firecrawl removal complete; Task 10 verification performed in the v1 release handoff. See the
"Implementation status" section of the spec.

## Global Constraints

- Preserve the `RawItem -> CyberEvent -> EvidencePack -> BriefingDraft -> Briefing -> DeliveryResult` flow.
- Add tests before every production behavior change and observe the expected failure.
- Fetch only explicit source-discovered URLs; never recursively crawl page links.
- Treat all network text as hostile and retain recipient, prompt, URL, and SSRF controls.
- Never bypass robots, authentication, CAPTCHAs, paywalls, access controls, or anti-bot challenges.
- Browser rendering is optional, bounded, isolated, and used only after deterministic quality failure.
- Persist sanitized extracted text, never raw HTML, credentials, rendered briefs, or unmasked recipients.
- No Firecrawl dependency, key, API, documentation, or quota requirement may remain.
- Do not add post-v1 features or provision AWS.

---

### Task 1: Fix the existing fail-closed draft regression

**Files:**
- Modify: `arkham/security/validation.py`
- Test: `tests/test_validation_brief.py`

**Interfaces:**
- Consumes: `BriefingDraft`, `EvidencePack`.
- Produces: `validate_draft()` returning `"draft contains no event cards for non-quiet evidence"` when evidence is non-quiet and nonempty but the draft has no items.

- [ ] Re-run `test_validate_draft_rejects_empty_non_quiet_brief` and confirm the existing assertion fails.
- [ ] Add the smallest empty-item guard without changing quiet-day behavior.
- [ ] Run `tests/test_validation_brief.py` and then the full validation/synthesis tests.

### Task 2: Add crawl contracts, configuration, and safe URL normalization

**Files:**
- Create: `arkham/crawl/__init__.py`
- Create: `arkham/crawl/models.py`
- Create: `arkham/crawl/normalize.py`
- Modify: `arkham/models.py`
- Modify: `arkham/config.py`
- Modify: `arkham/security/urls.py`
- Modify: `.env.example`
- Test: `tests/test_crawl_normalize.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `FetchMethod`, `CrawlFailureReason`, `IndicatorCandidate`, `ExtractedArticle`, `CrawlRecord`, `RobotsRecord`, `CrawlMetrics`, `CrawlBatchResult`, `FetchDecision`; `normalize_crawl_url()` and `accept_canonical_url()`; immutable `Settings.crawl_*`; `RunRecord.crawl`.

- [ ] Add failing table tests for tracking removal, resource query preservation, malformed/private URLs, fragments, host/scheme normalization, duplicate slashes, and same-host canonical acceptance.
- [ ] Add failing configuration tests for defaults, safe bounds, browser enablement, cache TTL, retries, concurrency, delays, text size, and quality threshold.
- [ ] Implement typed crawl contracts and settings with safe validation/clamps expressed as configuration errors.
- [ ] Tighten canonicalization to remove only known marketing parameters while preserving generic `ref`/`source` resource parameters.
- [ ] Run the new tests, existing security/config tests, and Ruff on touched files.

### Task 3: Implement deterministic article extraction, quality, and CTI indicators

**Files:**
- Create: `arkham/crawl/extract.py`
- Create: `arkham/crawl/quality.py`
- Create: `arkham/crawl/indicators.py`
- Add: `tests/fixtures/crawl/*.html`
- Create: `tests/test_crawl_extract.py`
- Create: `tests/test_crawl_indicators.py`
- Modify: `pyproject.toml`
- Modify: `requirements.txt`

**Interfaces:**
- Produces: `extract_article(html, response_url, headers, max_text_chars) -> ExtractedArticle`; `score_extraction(article) -> float`; `needs_browser(article, threshold) -> bool`; `extract_indicators(text, source_url) -> list[IndicatorCandidate]`; `content_hash(text) -> str`; `is_material_article_change(old, new) -> tuple[bool, str | None]`.

- [ ] Add fixtures and failing tests for a normal article, advisory, vendor blog, navigation-heavy page, malformed page, empty body, JS shell, duplicate chrome, canonical/meta/headings/links, and cosmetic HTML change.
- [ ] Add failing literal-expectation tests for CVE/CWE/ATT&CK/GHSA, hashes, IPs, domains, URLs, email, actors, cautious malware/product/version extraction, context, and false-positive exclusions.
- [ ] Pin Trafilatura 2.2.0 and install it; use only its local extraction API, never its downloader.
- [ ] Implement bounded HTML metadata/semantic parsing, Trafilatura main-text extraction, sanitization, content hashing, and deterministic quality scoring.
- [ ] Implement CTI indicator candidates and substantive-change comparison.
- [ ] Run extraction/indicator tests, dependency checks, and Ruff.

### Task 4: Add robots policy and domain-aware limiting

**Files:**
- Create: `arkham/crawl/robots.py`
- Create: `arkham/crawl/limiter.py`
- Create: `tests/test_crawl_robots.py`
- Create: `tests/test_crawl_limiter.py`

**Interfaces:**
- Produces: `RobotsPolicy.check(url, now) -> RobotsDecision`; `RobotsPolicy.dirty_records()`; `DomainLimiter.slot(url, crawl_delay=0)`; `DomainLimiter.backoff(host, seconds)`.

- [ ] Add failing robots tests for allow/disallow, user-agent selection, crawl-delay/request-rate, 404/410 allow, 401/403 deny, timeout/5xx/parse fail-closed, and cache TTL reuse.
- [ ] Add failing limiter tests for global/per-domain concurrency, cross-domain progress, configured/robots delay, shared bounded backoff, and clean release after exception.
- [ ] Implement `urllib.robotparser` evaluation with the exact policy from the design record and no direct storage access from worker threads.
- [ ] Implement a thread-safe semaphore/condition limiter with injected clock/sleeper for deterministic tests.
- [ ] Run robots/limiter tests and Ruff.

### Task 5: Implement Level-1 HTTP and optional Level-2 browser

**Files:**
- Modify: `arkham/http.py`
- Create: `arkham/crawl/fetcher.py`
- Create: `arkham/crawl/browser.py`
- Create: `tests/test_crawl_fetcher.py`
- Create: `tests/test_crawl_browser.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: HTTP errors retaining sanitized response headers; `DirectFetcher.fetch(url, cached, now) -> CrawlFetchResult`; `BrowserRenderer.render(url) -> BrowserResult`; optional `crawl-browser` dependency.

- [ ] Add failing tests for conditional headers/304, ETag/Last-Modified updates, HTML/plain acceptance, invalid content type, decoded oversize response, redirect, 403/404/500, 429 `Retry-After`, bounded 502/503/504 retry, timeout, authentication/CAPTCHA/site-block categorization, and no retry storms.
- [ ] Add failing browser-boundary tests for disabled/unavailable engine, quality-only invocation, timeout/render failure, isolated lifecycle, request interception, service-worker/download blocking, unsafe resource rejection, and metrics-visible outcomes using an injected fake engine.
- [ ] Extend `HttpStatusError` with lower-cased headers without exposing response bodies.
- [ ] Implement Level-1 fetch around `SafeHttpClient`, robots, limiter, content-type enforcement, and bounded retries.
- [ ] Implement Playwright 1.62 as a lazy optional import; use a fresh context, `accept_downloads=False`, `service_workers="block"`, route interception, resource blocking, timeout, and `finally` cleanup.
- [ ] Run HTTP/fetcher/browser/security tests and Ruff.

### Task 6: Extend SQLite crawl memory and conditional reuse

**Files:**
- Modify: `arkham/storage/base.py`
- Modify: `arkham/storage/sqlite.py`
- Create: `tests/test_crawl_storage.py`

**Interfaces:**
- Produces: backward-compatible `Storage.get_crawl_record/save_crawl_record/get_robots_record/save_robots_record`; SQLite `crawl_records` and `robots_cache` tables.

- [ ] Add failing reopen tests for complete crawl metadata, bounded sanitized extracted text, indicator JSON, validators, timestamps, failures, upsert, URL lookup, and robots cache.
- [ ] Add failing migration test opening an existing pre-crawl Arkham database without data loss.
- [ ] Implement parameterized transactional tables/upserts and Pydantic JSON loading; keep default no-op base methods so existing specialized test doubles remain valid.
- [ ] Run storage/corruption/search tests and Ruff.

### Task 7: Implement early filtering and the crawl orchestration service

**Files:**
- Create: `arkham/crawl/service.py`
- Create: `tests/test_crawl_service.py`

**Interfaces:**
- Produces: `CrawlService.enrich_items(items, source_map, storage, now) -> CrawlBatchResult`; `build_crawl_service(settings, http)`.

- [ ] Add failing pipeline tests for Level 0 structured/feed sufficiency, exact in-run URL duplicates, invalid URL isolation, historical same-raw cache reuse, changed-raw conditional request, 304 reuse, unchanged content hash, changed content, material change annotation, pre-fetch rejection, HTTP enrichment, browser escalation only below threshold, browser-disabled fallback, robots denial, and independent item failure.
- [ ] Add failing metrics test covering every `CrawlMetrics` counter with fixed inputs.
- [ ] Implement deterministic decision signals from source tier/category, title/summary, identifiers, recency, structured fields, raw history, and cached crawl state.
- [ ] Implement parallel HTTP work with all storage reads/writes on the caller thread; enrich copies of `RawItem` with bounded sanitized article text and CTI extras.
- [ ] Run crawl service tests and Ruff.

### Task 8: Integrate Arkham Crawl with intelligence history and runner accounting

**Files:**
- Modify: `arkham/runner.py`
- Modify: `arkham/intelligence/normalize.py`
- Modify: `arkham/intelligence/verify.py`
- Modify: `arkham/cli.py`
- Modify: `.github/workflows/arkham-daily.yml`
- Modify: `deploy/aws/handler.py`
- Test: `tests/test_runner.py`
- Test: `tests/test_verify.py`
- Test: `tests/test_pipeline_stages.py`

**Interfaces:**
- Consumes: `Components.crawl_items`, `CrawlBatchResult`.
- Produces: runner order `collect -> crawl -> save raw -> normalize`; persisted/printed crawl metrics; substantive crawl changes enter `CyberEvent` material-update history.

- [ ] Add failing runner tests proving the crawl seam order, enriched items reach normalization, metrics persist, failures isolate, and dry-run never delivers.
- [ ] Add failing history tests showing cosmetic HTML changes stay suppressed and substantive CTI changes produce one material update.
- [ ] Inject the production crawl service through `Components.default()` and add metric summary output without logging URLs or bodies.
- [ ] Carry only bounded crawl update fields into `CyberEvent` and fingerprint/description logic.
- [ ] Thread crawl configuration through workflows and keep browser off unless explicitly enabled and installed.
- [ ] Run runner/intelligence/schedule/workflow tests and Ruff.

### Task 9: Remove Firecrawl and reconcile release documentation

**Files:**
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-26-arkham-design.md`
- Modify: `docs/superpowers/plans/2026-08-26-arkham-v1-recovery.md`
- Modify: `deploy/aws/README.md`
- Create: `tests/test_no_paid_crawler_dependency.py`

**Interfaces:**
- Produces: zero case-insensitive Firecrawl references; runtime metadata/config requiring no paid crawler; accurate v1 recovery checklist and 900-character/emoji-off design record.

- [ ] Add a failing runtime-dependency/config regression assertion for prohibited paid-crawler names.
- [ ] Remove the stale `.firecrawl/` ignore and recovery-plan instruction, then confirm the repository-wide case-insensitive search is empty.
- [ ] Document Arkham Crawl architecture, fetch levels, early decisions, cache/conditional behavior, robots policy, rate limits/retries, browser install/enablement, extraction/indicators, security/failures, metrics, configuration, retention, and no-account requirement.
- [ ] Mark recovery-plan work complete where fresh tests/files prove it; leave credential/deployment checks explicitly external.
- [ ] Correct the design record to 900 characters and emoji disabled by default.
- [ ] Run the dependency regression, documentation command examples, and Ruff.

### Task 10: Full release verification, live dry run, and repository publication

**Files:**
- Modify only files implicated by failing verification.
- Preserve ignored: `data/*.db`, `.env`, caches, logs, browser binaries, build artifacts.

**Interfaces:**
- Produces: fresh full verification, representative crawl metrics, audited initial commit, non-force remote publication, and exact external blockers.

- [ ] Run full pytest, Ruff, compileall, `pip check`, `pip-audit`, CLI/config/source/schedule/history checks, and repository-wide Firecrawl search.
- [ ] Run a representative template-provider live dry run in a fresh ignored SQLite database and inspect crawl/failure/quality/selection metrics without publishing briefing content.
- [ ] Review GitHub Actions for manual/scheduled/quiet/material-update/failure/secret/retry/duplicate-run/duplicate-SMS behavior.
- [ ] Detect real LLM/Twilio readiness using masked configuration; run credentialed validations only if configuration is genuinely ready.
- [ ] Audit `.gitignore`, ignored/untracked/generated files, staged paths, private briefing text, local absolute paths, credentials, phone numbers, keys/tokens, and high-entropy candidates.
- [ ] Inspect remote refs/history before creating history; never force-push meaningful remote history.
- [ ] Stage explicit intentional paths, create the initial commit, re-scan the exact commit, push normally, confirm remote hash/contents, and inspect CI status when authentication permits.
- [ ] Record exact file list, architecture, removal result, live crawl metrics, verification totals, credential blockers, commit hash, push/CI status, and production-readiness verdict.

