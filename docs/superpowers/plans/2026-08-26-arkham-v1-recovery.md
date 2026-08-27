# Arkham v1 Recovery and Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the completed parallel module outputs, integrate every Arkham v1 stage against the frozen contracts, validate live sources, and leave a tested production-ready daily CTI briefing pipeline.

**Architecture:** Preserve the existing `RawItem -> CyberEvent -> EvidencePack -> BriefingDraft -> Briefing -> DeliveryResult` contracts and the injectable runner. Fill only the missing implementations, consolidate overlapping source/delivery work, persist structured state in SQLite, and keep live-source content outside trusted control paths.

**Tech Stack:** Python 3.11+, Pydantic 2, httpx, feedparser, stdlib sqlite3/zoneinfo, pytest, Ruff, GitHub Actions, Twilio REST, OpenAI-compatible and Anthropic REST APIs.

**Spec:** `docs/superpowers/specs/2026-08-26-arkham-design.md`

## Global Constraints

- Work in `/Users/oninactive/dev/Arkham`; do not scaffold or replace the architecture.
- Preserve the frozen model and interface contracts unless a failing integration test proves a compatible correction is required.
- Add regression tests before each behavior change and verify the expected failure before implementation.
- Never print or persist briefing bodies, phone numbers, credentials, environment dumps, or raw sensitive article bodies in production logs/artifacts.
- Live validation must report unavailable, disabled, and credential-gated sources honestly.
- Production delivery must target only `ARKHAM_TO_PHONE`; dry-run must never send.
- External source text is untrusted data and cannot control prompts, URLs, ranking, configuration, delivery, or tools.

---

### Task 1: Recover and inventory the parallel build

**Files:**
- Inspect: `arkham/`, `tests/`, `.github/workflows/`, `deploy/`, `README.md`
- Modify only when a recovered implementation violates an existing contract.

**Interfaces:**
- Consumes: the existing uncommitted repository state and file timestamps.
- Produces: an evidence-backed module/file/conflict/integration inventory.

- [ ] Compare implementation files, tests, imports, registry constructors, and runner defaults.
- [ ] Identify completed module clusters from file timestamps and test contracts.
- [ ] Record missing modules and overlapping behavior before edits.
- [ ] Run untouched pytest, Ruff, compile, CLI help, and dependency checks and preserve their exact failures.

### Task 2: Integrate missing source adapters

**Files:**
- Create: `arkham/sources/certcc.py`
- Create: `arkham/sources/microsoft.py`
- Modify: `arkham/sources/registry.py`
- Test: `tests/test_certcc.py`, `tests/test_microsoft.py`, `tests/test_registry.py`

**Interfaces:**
- Consumes: `SourceAdapter`, `RssAdapter`, `FetchContext`, `RawItem`, the frozen source registry contract.
- Produces: `CertCcAdapter`, `MsrcUpdateGuideAdapter`, helper parsers, and registry construction for both adapters.

- [ ] Run the existing adapter tests to preserve the import failures as RED.
- [ ] Implement CERT/CC Atom parsing, overview extraction, boilerplate removal, CVE/exploitation metadata, and window filtering.
- [ ] Implement MSRC Update Guide revision parsing, informational-only filtering, title/product/vulnerability-class extraction, and stable canonical URLs.
- [ ] Run adapter and registry tests until GREEN, then run Ruff on touched files.

### Task 3: Restore deterministic intelligence stages

**Files:**
- Create: `arkham/intelligence/normalize.py`
- Create: `arkham/intelligence/enrich.py`
- Create: `arkham/intelligence/lexicons.py`
- Create: `arkham/intelligence/deduplicate.py`
- Create: `arkham/intelligence/score.py`
- Create: `arkham/intelligence/verify.py`
- Test: `tests/test_normalize.py`, `tests/test_deduplicate.py`, `tests/test_score.py`, `tests/test_verify.py`

**Interfaces:**
- Consumes: `RawItem`, `CyberEvent`, `StoredEvent`, KEV catalog metadata, canonical URL utilities.
- Produces: `normalize_items`, `enrich_events`, `is_security_relevant`, `deduplicate`, `score_event`, `assign_confidence`, `reconcile_with_history`, and `select_events` with runner-compatible signatures.

- [ ] Add failing normalization tests for structured field copying, publisher identity, event typing, sanitization flags, and real CVE extraction only.
- [ ] Add failing correlation tests for same-CVE/matching canonical URL merges and non-merges for unrelated actor/campaign stories.
- [ ] Implement minimal normalization/enrichment/correlation logic and verify RED to GREEN.
- [ ] Implement the exact deterministic score weights and reasons required by `tests/test_score.py`.
- [ ] Implement confidence, attribution language, fingerprints, material-update descriptions, and diversity-aware selection required by `tests/test_verify.py`.
- [ ] Run all intelligence tests and Ruff.

### Task 4: Implement persistent story memory and historical search

**Files:**
- Create: `arkham/storage/sqlite.py`
- Modify: `arkham/storage/__init__.py`
- Test: `tests/test_storage_sqlite.py`

**Interfaces:**
- Consumes: the complete `Storage` ABC and Pydantic JSON serialization.
- Produces: `SQLiteStorage`, `open_storage(settings)`, persistent source state/raw hashes/events/updates/runs/deliveries/search.

- [ ] Add failing tests for initialization, conditional-fetch state, duplicate raw hashes, event upsert, material updates, brief marking, case-insensitive search, run history, delivery metadata, corruption failure/recovery, and reopen persistence.
- [ ] Implement schema creation and parameterized queries with transactions and WAL-safe operation.
- [ ] Retain normalized structured items/events and hashes; do not add raw article-body retention beyond the existing bounded `RawItem` record contract.
- [ ] Run storage and runner tests, then Ruff.

### Task 5: Complete model providers, validation, and phone briefing rendering

**Files:**
- Create: `arkham/intelligence/llm/openai.py`
- Create: `arkham/intelligence/llm/anthropic.py`
- Modify: `arkham/intelligence/llm/__init__.py`
- Create: `arkham/security/validation.py`
- Create: `arkham/intelligence/brief.py`
- Test: `tests/test_llm_providers.py`, `tests/test_validation.py`, `tests/test_brief.py`

**Interfaces:**
- Consumes: `IntelligenceModel`, `EvidencePack`, `ModelOutput`, `BriefingDraft`, `Briefing`, safe HTTP client, SMS splitting.
- Produces: provider factory, strict provider response parsing, evidence-grounded draft validation, deterministic rendering, rendered-output validation, recipient validation.

- [ ] Add failing provider tests for request shape, timeouts, HTTP failures, malformed JSON, and usage accounting without live credentials.
- [ ] Add failing validation tests for invented CVEs/URLs/refs, confidence inflation, unsupported attribution, hostile instructions, and recipient mismatch.
- [ ] Add failing rendering tests for UPDATE labels, mobile-size output, quiet-day formatting, evidence links, and SMS segmentation.
- [ ] Implement only evidence-grounded provider/validation/rendering behavior; keep `template` as the no-credential dry-run model.
- [ ] Run model, validation, rendering, delivery, and runner tests, then Ruff.

### Task 6: Harden runner metrics and failure isolation

**Files:**
- Modify: `arkham/models.py`
- Modify: `arkham/runner.py`
- Modify: `arkham/sources/collector.py`
- Test: `tests/test_runner.py`, `tests/test_failure_paths.py`

**Interfaces:**
- Consumes: all production stages and `RunRecord`.
- Produces: exact collection/normalization/deduplication/correlation/evidence/selection/brief-size metrics and fail-closed outcomes.

- [ ] Add failing tests for malformed RSS, timeout/500/DNS/oversize/private redirect, empty results, model failures, SMS failures, and one-source degradation.
- [ ] Add explicit run counters needed for the final live report without logging briefing content.
- [ ] Ensure source failures remain isolated while the minimum-trust threshold remains fail-closed.
- [ ] Run runner, collector, HTTP, source, and failure tests.

### Task 7: Validate configured sources live

**Files:**
- Modify: `arkham/sources/registry.py` only for verified endpoint/status corrections.
- Modify: `README.md` source table with observed status and credential requirements.
- Generate locally ignored sanitized check output under `data/` or `/tmp`.

**Interfaces:**
- Consumes: `python -m arkham sources --check`, publisher endpoints, conditional-fetch state.
- Produces: exact per-source healthy/degraded/unavailable/disabled/auth-required results.

- [ ] Use Arkham Crawl (native, no paid crawler) for any supplementary article retrieval.
- [ ] Run all enabled adapters against the 24-hour and bounded extended windows.
- [ ] Inspect publisher, item title/body, timestamps, canonical URLs, redirects, freshness, CVEs, and conditional headers.
- [ ] Keep Sophos disabled if rejected and do not represent the MSRC blog as a feed.
- [ ] Add/update fixture-based regression tests for every endpoint/parser correction.

### Task 8: Perform and inspect the first real dry run

**Files:**
- Use a temporary/local ignored SQLite path.
- Modify intelligence/ranking/rendering files only through new failing regression tests.

**Interfaces:**
- Consumes: the full production pipeline with `LLM_PROVIDER=template` and no delivery credentials.
- Produces: a real August 26, 2026 evidence-grounded dry-run briefing plus exact sanitized metrics.

- [ ] Run `python -m arkham run --dry-run --since 48 --json` against live sources.
- [ ] Inspect duplicate clustering, ranking, recency, attribution language, CVEs, links, summary usefulness, uncertainty, and mobile length.
- [ ] Convert each discovered defect into a failing test before fixing it.
- [ ] Re-run until the briefing is concise, current, deduplicated, and evidence traceable.

### Task 9: Audit production delivery, scheduling, state, and public workflows

**Files:**
- Modify: `.github/workflows/arkham-daily.yml`, `.github/workflows/ci.yml`, `.env.example`, `deploy/aws/*` only when validation finds a defect.
- Test: workflow/config/schedule/delivery tests.

**Interfaces:**
- Consumes: GitHub Actions secrets/variables, dual UTC cron gate, SQLite cache, Twilio provider.
- Produces: metrics-only scheduled execution, credential-free mock SMS verification, persistent state across Actions runs.

- [ ] Audit shell expansion and log surfaces for bodies, numbers, tokens, API keys, environment dumps, and sensitive configuration.
- [ ] Verify 12:00/13:00 UTC crons plus America/New_York gate across EST/EDT and the 20-hour duplicate-send guard.
- [ ] Verify missing-cache first run and cache restore/save behavior.
- [ ] Run Twilio segmentation/retry/error/cost tests with mocks; do not claim a real send without credentials.

### Task 10: Final verification, cleanup, documentation, and second live run

**Files:**
- Modify: `README.md`, `.gitignore`, project files implicated by final checks.
- Remove only temporary/dead artifacts proven unused.

**Interfaces:**
- Consumes: the finished repository and the first live run observations.
- Produces: exact final test/lint/static/config/source/dry-run/search/schedule/security results and interview-ready documentation.

- [ ] Run the full test suite, Ruff, compile/static checks, dependency checks, CLI/config/registry/schedule/search/storage/cost/injection/delivery/failure-path checks.
- [ ] Scan tracked candidate files for secrets, phone numbers, private briefing text, dead imports, duplicate adapters, stale workflows, and accidental artifacts.
- [ ] Finish README architecture, non-goals, security, memory, storage/retention, provider-dependent cost, setup, exact commands, credentials, source statuses, and limitations.
- [ ] Run a second real dry run and compare exact sanitized metrics and briefing quality with the first.
- [ ] Inspect `git diff`, report branch/commit/cleanliness honestly, and produce the requested `ARKHAM V1` handoff with exact totals.
