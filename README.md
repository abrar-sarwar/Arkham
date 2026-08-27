# Arkham

**Arkham is a personal open-source cyber threat intelligence agent that automatically collects, verifies, prioritizes, and summarizes important global cybersecurity developments into a daily briefing delivered to a private Discord channel.**

Every morning at 08:00 America/New_York it checks 23 enabled authoritative, research, and journalism sources, reduces hundreds of records to a few correlated events, explains defender relevance, cites retrieved evidence, and posts a skimmable brief — one embed per story — through a free Discord incoming webhook into a private channel, which your phone then notifies you about. It is a small, auditable intelligence pipeline in which a language model (Gemini by default) may act as an **analyst**, never a **source**.

Delivery is free: a standard Discord webhook needs no bot token, no server, no WebSocket and no paid messaging provider. The legacy Twilio SMS transport remains available behind `ARKHAM_DELIVERY_PROVIDER=twilio` but is no longer required. This README intentionally does not publish a private briefing or invent an illustrative vulnerability.

### What Arkham is not

Arkham is not a SIEM, EDR, XDR, SOC replacement, vulnerability scanner, exploit framework, generic AI chatbot, or stateless RSS reader. It produces a personal, evidence-grounded morning intelligence brief; it does not collect endpoint telemetry, scan infrastructure, block attacks, or make autonomous remediation changes.

---

## Contents

1. [Architecture](#architecture)
2. [Source methodology](#source-methodology)
3. [Confidence methodology](#confidence-methodology)
4. [Ranking methodology](#ranking-methodology)
5. [Event evolution and deduplication](#event-evolution-and-deduplication)
6. [The analyst model](#the-analyst-model)
7. [Security architecture](#security-architecture)
8. [Installation](#installation)
9. [Configuration](#configuration)
10. [Discord setup](#discord-setup)
11. [Local testing and dry runs](#local-testing-and-dry-runs)
12. [Production scheduling](#production-scheduling)
13. [Cost control](#cost-control)
14. [Run history and observability](#run-history-and-observability)
15. [Testing](#testing)
16. [Limitations](#limitations)
17. [Future improvements](#future-improvements)

---

## Architecture

```text
┌───────────────────────────┐
│ Public Cyber Sources      │  CISA KEV, NVD 2.0, CERT-EU, NCSC, CERT/CC, MSRC,
│ CISA / NVD / CERTs / CTI  │  GTIG, Microsoft, Talos, Unit 42, SentinelLabs, ESET, ... journalism
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Collection Layer          │  arkham/sources/*  — one adapter per source, per-source isolation,
│                           │  conditional GET, size/timeout caps, HTML→text sanitisation
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Arkham Crawl              │  arkham/crawl/* — native secure fetch (robots-aware, conditional HTTPS)
│                           │  + offline extraction, quality scoring, IOC candidates; no paid crawler API
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Normalize + Deduplicate   │  arkham/intelligence/normalize.py, deduplicate.py
│                           │  RawItem → CyberEvent; union-find clustering on CVE / URL / title / entities
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Enrich + Verify           │  enrich.py (CVE/CWE/ATT&CK/actors/malware/sectors/geo/KEV/exploitation)
│                           │  verify.py (confidence ladder, claim flags, attribution safety, event history)
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Threat Priority Engine    │  score.py — deterministic, explainable weights (no LLM involved)
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ LLM Intelligence Analyst  │  synthesize.py + llm/* — ONE call (Gemini via its OpenAI-compatible
│ (Gemini)                  │  endpoint) with a structured evidence pack; strict JSON, evidence ids only
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Output Validation         │  security/validation.py — every URL/CVE/confidence label checked
│                           │  against the evidence; placeholders, injection, over-attribution rejected
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Discord Webhook           │  delivery/discord_format.py + discord_webhook.py — one embed per story,
│ → private channel → phone │  Discord limits handled, mentions disabled, bounded retries, URL masked
└───────────────────────────┘
```

Pipeline in code (`arkham/runner.py`):

`collect → Arkham Crawl → normalize → enrich → drop off-topic → deduplicate → assign_confidence → reconcile_with_history → score → select → evidence pack → synthesize (1 LLM call) → validate draft → render (Discord embeds by default) → validate rendered → deliver → record run + cost`

State lives in SQLite behind a `Storage` interface (`arkham/storage/base.py`), so PostgreSQL/Supabase or DynamoDB can replace it without touching business logic. Delivery sits behind a `DeliveryProvider` interface (`arkham/delivery/base.py`): `DiscordWebhookProvider` is the default, `TwilioMessageProvider` is the optional legacy SMS transport, and email/push providers can be added without touching the intelligence layers. GitHub Actions is the scheduler; there is no always-on server.

### Project layout

```text
arkham/
├── arkham/
│   ├── cli.py, runner.py, config.py, models.py, http.py, schedule.py, costs.py, logging_setup.py
│   ├── sources/       base.py registry.py collector.py rss.py cisa.py nvd.py cert_eu.py ncsc.py
│   │                  google_threat_intel.py microsoft.py certcc.py
│   ├── crawl/         fetcher.py extract.py quality.py indicators.py apply.py normalize.py models.py
│   ├── intelligence/  normalize.py enrich.py deduplicate.py score.py verify.py
│   │                  synthesize.py brief.py (SMS renderer) llm/{base,openai,anthropic,template}.py
│   ├── delivery/      base.py discord_format.py discord_webhook.py  sms.py twilio_sms.py (legacy)
│   ├── storage/       base.py sqlite.py
│   └── security/      urls.py prompt_injection.py validation.py
├── tests/             (fixture-driven, no network)
├── deploy/aws/        Lambda + EventBridge Scheduler alternative
├── .github/workflows/ arkham-daily.yml (production schedule), ci.yml
├── scripts/bootstrap.sh
├── .env.example  pyproject.toml  requirements.txt
```

---

## Arkham Crawl

Arkham Crawl (`arkham/crawl/`) is Arkham's own reusable crawl/extraction layer, so no paid crawling service (Firecrawl or otherwise) is required, configured, or referenced at runtime. It is a **library** used by collectors, deliberately small:

```text
URL → fetcher.fetch_page (SafeHttpClient: https-only public hosts, robots.txt, conditional GET,
      content-type gate, size/timeout caps, bounded 429/5xx retries, categorised failures)
    → extract.extract_article (stdlib html.parser: metadata, noise removal, main-content selection,
      headings/paragraphs/lists/code/tables, validated links, sanitised bounded text)
    → quality.score_extraction / needs_browser / classify_interstitial (deterministic heuristics)
    → indicators.extract_indicators (CVE/CWE/ATT&CK/GHSA, actors, malware, IPv4/IPv6, domains, URLs,
      emails, MD5/SHA-1/SHA-256, products/versions, KEV and exploit references; defanged forms refanged)
    → apply.enrich_raw_item → existing RawItem → CyberEvent normalization, dedup, scoring, synthesis
```

What it does: one hardened HTTPS `GET` per URL through the same `SafeHttpClient` the feed adapters use (no second HTTP client); respects `robots.txt` (404/410 = no policy, 401/403/timeouts/parse errors fail closed for a bounded window, results cached per host); accepts only HTML/XHTML/plain text; decodes declared charsets; maps every outcome to a `CrawlFailureReason` (`unsafe_url`, `robots_denied`, `authentication_required`, `captcha_detected`, `blocked_by_site`, `rate_limited`, `not_found`, `http_error`, `timeout`, `oversized_response`, `invalid_content_type`, `browser_disabled` for JavaScript-only shells such as NVD detail pages, `extraction_failed`); extracts deterministic, offline article text with scripts, styles, navigation, asides, footers, forms, cookie/consent/share/related/ad blocks and hidden elements removed; keeps title, description, author, published/updated times (meta, JSON-LD, `<time>`), headings, paragraphs, list items, code blocks and table cells; validates every embedded link as public https and strips tracking parameters; neutralises instruction-like sentences (`injection_flagged`); hashes normalised text and reports whether a re-crawled page changed materially (`is_material_article_change`); scores extraction quality `0.0..1.0` and flags JavaScript shells and interstitials; and emits deduplicated CTI artifact **candidates** (never maliciousness verdicts) with a bounded context snippet. `enrich_raw_item` copies the bounded text and structured facts into the `RawItem.extra` keys the normaliser already understands (`cve_ids`, `cwes`, `referenced_links`, `actor_mentions`, `malware`, `products`, `exploitation_hint`).

What it intentionally does not do: execute JavaScript, drive a browser (`needs_browser` only records that Level-1 extraction is untrustworthy — there is no Level-2 renderer), follow or recursively crawl links found in pages, bypass robots/CAPTCHA/login/paywalls, store raw HTML, fetch from private/loopback/link-local hosts, or run automatically inside the daily pipeline: v1's 23 sources are feeds/APIs whose items already carry summaries, so the scheduled run does not crawl article pages; the crawl layer is the tested seam for adapters that need full text. Indicator extraction is regex/`ipaddress` based and conservative — bare domains need an explicit cue (`domain`, `C2`, `hostname` …) or a defanged spelling, private IPs need an IP-ish cue, loopback/link-local/multicast addresses are never candidates, hashes must be exactly 32/40/64 hex characters. No dependency was added: the extractor is the Python standard library plus Arkham's own sanitiser; the previously declared but never-installed Trafilatura/Playwright pins were removed.

---

## Source methodology

Sources are declared in `arkham/sources/registry.py` (`python -m arkham sources` lists them; `--check` fetches them live). Each has a reliability tier, category, publisher label, and per-source size/timeout caps. The August 26, 2026 live check classified them as follows:

| Status | Category | Sources |
|---|---|---|
| **Healthy/enabled** | Primary / government / vendor | CISA KEV JSON; NIST NVD API 2.0; CERT-EU Security Advisories; CERT-EU Threat Intelligence; UK NCSC Publications; UK NCSC Threat Reports; MSRC Security Update Guide; CERT/CC Vulnerability Notes |
| **Healthy/enabled** | Vendor research / threat intelligence | Google Threat Intelligence Group; Microsoft Security Blog; Cisco Talos; Palo Alto Unit 42; SentinelLabs; ESET WeLiveSecurity; CrowdStrike Blog; Cloudflare Security; GitHub Security; Google Online Security Blog |
| **Healthy/enabled** | Security journalism | BleepingComputer; The Record; SecurityWeek; Krebs on Security; The Hacker News |
| **Degraded** | Vendor research | Microsoft Security Blog intermittently returned HTTP 403 in repeated checks but also completed successful live runs; source failure remains isolated |
| **Disabled intentionally** | Overlap / response size | UK NCSC News overlaps NCSC Publications; Google Project Zero redirects to a valid ~13 MB XML feed and is opt-in to avoid a large daily transfer |
| **Unavailable to Arkham** | Official feeds | CISA Cybersecurity Advisories and CISA Alerts return HTTP 403 to the hardened httpx client even though curl can reach them; Sophos redirects/refuses the configured feed path. They remain registered but disabled rather than being represented as working |

No intelligence source requires authentication. `NVD_API_KEY` is optional and only improves NVD rate limits. The normal MSRC blog was probed separately and did not expose a usable feed; Arkham uses the working MSRC Security Update Guide instead and does not invent a substitute.

Principles:

* **Structured over scraped.** Only JSON APIs, RSS/Atom feeds and official advisories are consumed. No HTML scraping.
* **Primary sources win.** A journalism article that references an advisory is clustered *with* that advisory (via CVE ids and the links inside the article), and the brief cites the advisory. Citation priority: official vendor advisory → government/CERT → original researcher → vendor threat-intel report → journalism.
* **CISA KEV is special.** The full catalog is loaded every run and used to enrich every event; a CVE entering KEV is treated as confirmed exploitation and scores +30.
* **NVD is queried incrementally** by `lastModStartDate/EndDate`, with API-key-aware rate limiting and pagination. Arkham retains CVEs published in the window or added to KEV in the window; metadata-only updates to old high-CVSS records do not become fresh stories.
* **Feeds use conditional GET** (ETag / If-Modified-Since) with state persisted per source.
* **Global coverage without quotas.** Regional sources (CERT-EU, NCSC) and geography extraction (US, China, Russia, Ukraine, Israel, Iran, North Korea, EU, UK, Middle East, APAC, Africa, Latin America, Global) are metadata; importance, not geography, decides what is briefed.
* **Failure isolation.** Each adapter runs in its own thread with its own timeout and never raises; the run continues with the sources that worked and aborts only when fewer than 3 sources succeed.

---

## Confidence methodology

Every event carries `confidence ∈ {CONFIRMED, HIGH, MODERATE, LOW, UNVERIFIED}` with reasons (`arkham/intelligence/verify.py`):

| Level | Assigned when |
|---|---|
| CONFIRMED | A Tier-1 source (CISA, NVD, CERT, vendor advisory) states the vulnerability/exploitation/advisory fact |
| HIGH | Tier-1 source for non-vulnerability facts, or Tier-2 research corroborated by another publisher |
| MODERATE | A single Tier-2 research report, or 3+ independent journalism outlets |
| LOW | Journalism only |
| UNVERIFIED | A criminal group's claim (leak site, ransom note) with no victim or Tier-1 confirmation |

Claims are flagged and phrased accordingly. A ransomware listing becomes *"claimed by \<group\>; independently unconfirmed"*, never *"\<organization\> was breached"*. Victim counts and record counts are flagged `statistic_unverified` unless a Tier-1 source or the victim states them.

**Attribution safety.** Attribution is stored as the attributing source plus its own language and confidence (`attributed_by`, `statement`, `confidence`). The brief may say *"Google assesses the campaign is associated with a China-nexus actor (MODERATE CONFIDENCE)"*; the validator rejects *"China hacked …"* unless the evidence literally supports it. A threat actor's suspected origin is never converted into government sponsorship; `tag:state-backed` requires explicit language from the source.

---

## Ranking methodology

Ranking is deterministic and runs **before** anything reaches the model (`arkham/intelligence/score.py`). Every applied rule leaves a human-readable reason on the event.

| Component | Rule | Points |
|---|---|---|
| Exploitation | Widespread exploitation / active exploitation / public PoC | +35 / +30 / +12 |
| | Confirmed zero-day | +25 |
| | CISA KEV: newly added / listed earlier | +30 / +20 |
| Severity | CVSS ≥ 9 / ≥ 8 / ≥ 7 (+3 for RCE/auth-bypass/priv-esc wording) | +10 / +6 / +3 |
| Source quality | Tier 1 / Tier 2 / Tier 3 primary source | +10 / +6 / +2 |
| Global impact | Major supply-chain impact / critical infrastructure / state-backed (explicit) / major global organization / sensitive sector / global scope | +20 / +15 / +12 / +8 / +4 / +3 |
| Corroboration | 2 publishers / 3+ publishers (+2 when Tier 1 and Tier 2 agree) | +10 / +12 |
| Novelty | Material new development / first time seen / already briefed with nothing new | +10 / +5 / −60 |
| Recency | Published within 12 h / 24 h / 48 h | +5 / +3 / +1 |
| Relevance | Event type base (exploitation 8 … research 3), ransomware +2, off-topic −50 | |

`final_priority_score = clamp(sum, 0, 100)`. The default threshold to be briefed is **35** (`ARKHAM_MIN_PRIORITY_SCORE`). A CVSS 9.8 bug with no exploitation (~25 points) ranks below a CVSS 7.2 bug in KEV (~68 points) — exactly the behaviour the spec asks for. Selection also applies light diversity (vulnerabilities cannot crowd out everything else) and a hard cap of `ARKHAM_MAX_EVENTS` (default 8).

---

## Event evolution and deduplication

**Deduplication** (`deduplicate.py`) uses conservative union-find clustering. Two records merge when they share a CVE, share a canonical source/referenced URL, have near-identical normalized titles within three days, or share a product/organization/malware entity plus strong title similarity within three days. Actor names alone never merge stories. The merged event keeps the best-tier primary source, the union of evidenced entities, the maximum CVSS/KEV/exploitation status, and every corroborating source.

**Evolution.** Each event has a state *fingerprint* (KEV status, exploitation status, CVSS band, PoC availability, zero-day, corroboration band, attribution, confidence). On re-observation the fingerprint is compared with the stored one; a change produces a `material_update` such as *"added to CISA KEV; exploitation escalated active → widespread"*, scores +10, and makes the story eligible again even if it was briefed before. Unchanged stories that were already briefed are suppressed. Every update is stored (`event_updates` table), so the history of a CVE from disclosure → PoC → KEV → mass exploitation is queryable.

Dry runs retain source-fetch metadata and run metrics, but do not mutate event/story memory or delivery history, so a `--dry-run` at 07:50 cannot suppress the 08:00 delivery. On successful delivery, only event cards actually present in the rendered brief are marked briefed (with Discord that is every validated card; with the SMS transport, cards that did not fit the character budget remain eligible).

---

## The analyst model

The model receives an **evidence pack** (`arkham/models.py::EvidencePack`): for each selected event, sanitized title and summary, event type, allowed citation URLs, CVEs, CVSS, KEV/exploitation status, computed confidence, the source's attribution statement, claim flags, actors, malware, ATT&CK techniques, sectors, regions, and the deterministic score with reasons. It must return **strict JSON** (`BriefingDraft`): items referencing evidence ids with a section, headline, why-it-matters, confidence label and a URL chosen from that item's allow-list; a defensive `prep` list; one `learn` topic; and a `watch` list on quiet days. Arkham renders the brief itself.

What the model may do: summarize, compare, categorize, explain importance, derive defensive implications, propose a study topic, compress. What it cannot do — because the validator rejects it — is invent sources, CVEs, actors, dates, victims, attribution, statistics, or mitigations. A rejected draft means **nothing is delivered** (fail closed) and the run is recorded as `no-send` with the reasons.

Providers (`LLM_PROVIDER`): `gemini` — the intended production model, reached through Google's OpenAI-compatible endpoint with `GEMINI_API_KEY` (same hardened provider code as `openai`, JSON mode, temperature 0; `GEMINI_BASE_URL` only if you proxy it); `openai` (any OpenAI-compatible Chat Completions endpoint via `OPENAI_BASE_URL`); `anthropic` (Messages API); and `template` — a deterministic, evidence-only renderer with no network call, used for zero-credential dry runs and as an honest fallback. One call per run; `LLM_MODEL` is required and never hardcoded (pick a current, inexpensive Gemini model id from Google's model list).

---

## Security architecture

Arkham is a security tool, so its own security is part of the design.

| Control | Where |
|---|---|
| No secrets in the repo: `.env` git-ignored, `.env.example` placeholders only; the Discord webhook URL, API keys (and phone numbers for the legacy SMS path) come only from the environment | `.gitignore`, `config.py` |
| Startup validation with exact, secret-free instructions for anything missing | `config.py`, `python -m arkham check-config` |
| Secrets, tokens, webhook URLs and phone numbers masked in every log line (`https://discord.com/api/webhooks/1234****5678/***`, `+1******1234`); the filter is also attached to the HTTP client's own loggers, which would otherwise print request URLs | `logging_setup.py::SecretMaskingFilter` |
| Hardened HTTP client: https-only, public hosts only (no loopback/private/link-local/metadata), credentials in URLs rejected, each redirect hop re-validated, connect/read timeouts, streaming response-size cap | `http.py`, `security/urls.py` |
| All fetched text is DATA: HTML stripped with a non-executing parser, control/zero-width characters removed, bounded length; nothing downloaded is ever executed | `security/prompt_injection.py` |
| Prompt-injection defence in depth: (1) instruction-like sentences neutralized at ingestion and again in the evidence pack, (2) system prompt declares evidence untrusted and forbids following it, (3) output validation only accepts URLs/CVEs/labels that exist in the evidence, (4) injection markers in model output are rejected | `prompt_injection.py`, `synthesize.py`, `validation.py` |
| Environment variables, keys and internal prompts are never placed into evidence or exposed to source content | design |
| Destination injection impossible: every provider takes its destination at construction from settings; `deliver()` has no destination parameter; the masked destination is re-checked against configuration immediately before sending | `delivery/base.py`, `validation.py::validate_recipient` |
| Arkham Crawl fetches only normalised public https URLs through the hardened client, honours robots.txt (failing closed on errors), never executes scripts or follows page links, bounds input/output sizes, and treats all extracted text as untrusted data (sanitised, injection-neutralised) before it can reach the evidence pack | `crawl/fetcher.py`, `crawl/extract.py` |
| Webhook allow-list: `DISCORD_WEBHOOK_URL` must be https, on `discord.com`/`discordapp.com` (or their ptb/canary hosts), shaped `/api/webhooks/<id>/<token>`, with no credentials, query, private/loopback host or odd port; redirects from the webhook are refused, never followed | `security/urls.py::validate_discord_webhook_url`, `delivery/discord_webhook.py` |
| Untrusted article text cannot act in Discord: every payload sets `allowed_mentions: {"parse": []}` (no `@everyone`, `@here`, user or role pings), mention markup is broken with a zero-width space, markdown is escaped so no masked link can be forged, and the provider re-checks that every URL it is about to send is an evidence URL | `delivery/discord_format.py`, `delivery/discord_webhook.py` |
| The webhook URL is a credential: masked in `check-config`, results, run history and errors; scrubbed from exception text; never written to SQLite | `config.py::mask_webhook_url`, `delivery/discord_webhook.py` |
| Never send a bad brief: source count, evidence-grounded URLs and CVEs, valid dates, no duplicates, no unsupported attribution, no placeholders, transport limits, destination equality — all checked before delivery | `validation.py`, `runner.py` |
| Dependencies pinned (`requirements.txt`, `pyproject.toml`); `pip-audit` runs in CI | `requirements*.txt`, `.github/workflows/ci.yml` |
| Least privilege: GitHub Actions job has `contents: read` only and does not persist git credentials; the public CI log never prints the brief, evidence, or state | `.github/workflows/arkham-daily.yml` |
| Trust boundaries: sources → sanitizer → pipeline → model → validator → delivery; each boundary is a module with tests | `tests/` |

---

## Installation

Requirements: Python 3.11+ (developed on 3.14), a Discord server/channel you control (free), and a Gemini API key (or `LLM_PROVIDER=template` for a no-API dry run). No Twilio account, phone number, bot token or always-on server.

```bash
git clone https://github.com/abrar-sarwar/Arkham.git
cd Arkham
./scripts/bootstrap.sh            # venv + pinned deps + copies .env.example to .env (sends nothing)
. .venv/bin/activate
python -m arkham check-config     # tells you exactly what is still missing
```

Manual equivalent: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt && cp .env.example .env`.

---

## Configuration

All configuration is environment variables (`.env` is loaded automatically). See `.env.example` for the full annotated list.

| Variable | Purpose | Default |
|---|---|---|
| `ARKHAM_DELIVERY_PROVIDER` | `discord` (free webhook) \| `twilio` (legacy SMS, paid) | `discord` |
| `DISCORD_WEBHOOK_URL` | Incoming webhook of **your private** Arkham channel. The only destination Arkham will ever post to. **Treat it like a password.** | required for Discord delivery |
| `ARKHAM_TO_PHONE`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_PHONE` | Legacy SMS transport only (ignored unless `ARKHAM_DELIVERY_PROVIDER=twilio`) | — |
| `LLM_PROVIDER` | `gemini` \| `openai` \| `anthropic` \| `template` | `openai` in code; `.env.example` and the workflow default to `gemini` |
| `LLM_MODEL` | Model id (required for API providers; deliberately not defaulted) | — |
| `GEMINI_API_KEY`, `GEMINI_BASE_URL` | Gemini key (https://aistudio.google.com/apikey); base URL only to override Google's OpenAI-compatible endpoint | — |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `ANTHROPIC_API_KEY` | Other provider credentials | — |
| `NVD_API_KEY` | Optional; raises NVD rate limits (free from NIST) | — |
| `ARKHAM_TIMEZONE`, `ARKHAM_DELIVERY_HOUR` | Delivery time | `America/New_York`, `8` |
| `ARKHAM_MAX_EVENTS`, `ARKHAM_MIN_PRIORITY_SCORE` | Briefing shortlist size and priority threshold | `8`, `35` |
| `ARKHAM_MAX_SMS_CHARS`, `ARKHAM_SMS_EMOJI` | Legacy SMS-only: character budget and emoji/GSM-7 choice. The Discord brief has no character budget. | `900`, `false` |
| `LLM_INPUT_PRICE_PER_1M`, `LLM_OUTPUT_PRICE_PER_1M`, `SMS_PRICE_PER_SEGMENT` | Pricing for the cost report (copy from provider pricing pages; blank = "unpriced"). Discord webhooks are free. | — |
| `ARKHAM_LOOKBACK_HOURS`, `ARKHAM_DISABLED_SOURCES`, `ARKHAM_DB_PATH`, `ARKHAM_LOG_LEVEL`, `ARKHAM_LOG_FORMAT` | Window, source toggles, storage, logging | `24`, —, `data/arkham.db`, `INFO`, `text` |

---

## Discord setup

> **Treat the Discord webhook URL like a password.** Anyone with the URL may be able to post into the configured channel. Keep it in `.env` locally and in a GitHub Actions *secret* for scheduled runs; never paste it into source code, a commit, an issue, or a public log. If it leaks, delete the webhook in Discord and create a new one.

1. **Create a private Discord server or private channel.** A new server just for you is simplest (Discord → `+` → Create My Own → For me and my friends). If you use an existing server, create a channel such as `#arkham` and restrict it to yourself.
2. **Create an incoming webhook** for that channel: *Server Settings → Integrations → Webhooks → New Webhook*, name it `Arkham`, choose the channel.
3. **Copy the webhook URL** (*Copy Webhook URL*). It looks like `https://discord.com/api/webhooks/<id>/<token>`.
4. **Put it into local configuration:** `DISCORD_WEBHOOK_URL=...` in `.env` (git-ignored). `ARKHAM_DELIVERY_PROVIDER=discord` is the default, so nothing else is needed for delivery.
5. **Add it to GitHub Actions Secrets** for scheduled runs: repository → *Settings → Secrets and variables → Actions → New repository secret* named `DISCORD_WEBHOOK_URL`.
6. **Configure Gemini:** `LLM_PROVIDER=gemini`, `GEMINI_API_KEY=<key from https://aistudio.google.com/apikey>`, `LLM_MODEL=<current Gemini model id>` — locally in `.env`, and in Actions as the secret `GEMINI_API_KEY` plus the variable `LLM_MODEL` (and `LLM_PROVIDER=gemini` if you change the workflow default).
7. **Run Arkham in dry-run mode:** `python -m arkham check-config` should show `Delivery: ready`; then `python -m arkham run --dry-run` prints the Discord-shaped brief locally and sends nothing.
8. **Run the explicit Discord delivery test:** `python -m arkham test-delivery` posts exactly one small message — *"Arkham delivery test — Discord delivery is configured correctly."* — into the channel. Nothing is ever sent when config is loaded or tests run; only this command and `run --force`/scheduled runs post. Turn on notifications for the channel on your phone.
9. **Enable the scheduled workflow:** push the repository, confirm `DISCORD_WEBHOOK_URL`, `GEMINI_API_KEY` (and optionally `NVD_API_KEY`) are Actions secrets and `LLM_MODEL` is an Actions variable, then run *Arkham daily briefing → Run workflow → test-delivery* once. The two daily crons are already in `.github/workflows/arkham-daily.yml`.

How delivery works: the validated briefing is rendered into Discord **embeds** — a header line (`ARKHAM · Morning Intelligence Brief · <date>` with the run statistics), then one colour-coded embed per story (CRITICAL red, THREAT orange, INCIDENT amber, RESEARCH blue, POLICY purple; `· UPDATE` on material developments) with the headline linked to the cited source, why it matters, *Affected* (products/CVEs), *Exploitation* (KEV, status, CVSS), a bounded *What happened* excerpt, *Evidence · confidence* links, the bare *Source* URL, and the publication time — and a closing *Prep / Learn today* embed. Quiet mornings send one short *"No material updates"* line plus a compact watch list, never a large empty brief. Discord's limits (10 embeds and 6,000 embed characters per message, per-field caps) are enforced by construction: long briefs are split into additional numbered messages rather than dropping a story, and the number of messages is recorded in run history.

Arkham calls the webhook with `POST …?wait=true` over the hardened HTTP client (no library, no bot token, no gateway connection), refuses redirects, and retries only rate limits (honouring `Retry-After`), 5xx responses, timeouts and connection errors — at most 4 attempts per message with exponential backoff — so a transient Discord error cannot become a retry storm. Every payload carries `"allowed_mentions": {"parse": []}`, so article text can never trigger `@everyone`, `@here`, user or role mentions. The webhook URL never appears in logs, results, run history, errors or the database.

### Legacy: Twilio SMS

Set `ARKHAM_DELIVERY_PROVIDER=twilio` plus `ARKHAM_TO_PHONE`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_PHONE` to use the original paid SMS transport (`arkham/delivery/twilio_sms.py`, REST over the hardened client, no SDK). It renders the phone-sized GSM-7 brief (`ARKHAM_MAX_SMS_CHARS`, `ARKHAM_SMS_EMOJI`) and counts segments exactly. It is kept because it is isolated and tested, not because v1 needs it; no Twilio setting is read unless this provider is selected.

---

## Local testing and dry runs

```bash
python -m arkham sources            # registry with tiers
python -m arkham sources --check    # fetch every enabled source live and print the health table
LLM_PROVIDER=template python -m arkham run --dry-run  # zero-credential full pipeline; sends nothing
python -m arkham run --dry-run --show-evidence   # also prints the exact evidence pack the model received
python -m arkham test-delivery      # posts ONE small labelled test message to the configured Discord channel
python -m arkham run --force        # posts a real briefing to the channel now (bypasses the 20-hour guard)
python -m arkham history            # run records: sources, raw, unique, candidates, selected, tokens, delivery
python -m arkham search "APT28"     # search stored events (seed of the future `arkham ask`)
```

A dry run needs the LLM configured **or** `LLM_PROVIDER=template`; it never needs the webhook. `test-delivery` is the only command that sends without running the pipeline, and it must be invoked explicitly — loading configuration or running the test suite never posts to Discord (unit tests use mocked HTTP). Nothing is ever sent during installation.

---

## Production scheduling

### Default: GitHub Actions (no always-on server)

`.github/workflows/arkham-daily.yml` runs the pipeline daily. GitHub cron is UTC-only, so two crons fire (`0 12 * * *` for EDT, `0 13 * * *` for EST) and a zoneinfo-aware gate — `python -m arkham should-run` — lets exactly the 08:00 America/New_York invocation proceed and refuses a second delivery within 20 hours. DST is handled by `zoneinfo`, not by hand; `python -m arkham next-run` prints the cron lines for any timezone/hour.

Setup:

1. Repository → Settings → Secrets and variables → Actions → **Secrets**: `DISCORD_WEBHOOK_URL` (the only delivery secret), `GEMINI_API_KEY`, optionally `NVD_API_KEY`. No Twilio secret is required; another analyst provider needs its key added to the workflow `env` block and `LLM_PROVIDER` set.
2. **Variables**: `LLM_MODEL` (required), optionally `LLM_PROVIDER` (workflow default `gemini`), `ARKHAM_DELIVERY_PROVIDER` (default `discord`), pricing variables, `ARKHAM_DISABLED_SOURCES`.
3. Actions → *Arkham daily briefing* → *Run workflow* with `test-delivery` to post one small test message, `dry-run` to see a brief in the log (**the repository is public: a dry-run prints the brief in a public log; scheduled runs print metrics only**), or `force` to post a real brief now.

Secrets are injected as environment variables only; no step echoes configuration, and Arkham masks the webhook URL in every log line, error and run record (GitHub additionally masks registered secrets in workflow output). Behaviour by scenario: a **quiet run** posts one short "No material updates" message; a **successful delivery** records the message count, attempts and Discord message ids and marks the stories briefed; a **failed delivery** (after bounded retries) fails the job, records the failure, and leaves the stories un-briefed so the next run delivers them; a **workflow retry or manual rerun** restores the same cached state and is refused by the 20-hour delivery guard (`concurrency` also prevents overlapping jobs), so the same briefing is never posted twice.

State (seen events, briefed history, delivery records, ETags) is persisted between runs with `actions/cache` (`data/`), restored from the most recent key each morning. GitHub may delay scheduled jobs by minutes on busy days; the gate tolerates the whole 08:xx hour.

### Alternative: AWS Lambda + EventBridge Scheduler

See [`deploy/aws/README.md`](deploy/aws/README.md): a timezone-aware schedule (`cron(0 8 * * ? *)` with `America/New_York`), a Lambda running `deploy/aws/handler.py`, and SQLite state synced to a private S3 object. AWS charges and free-tier eligibility are account- and region-dependent.

No always-on server is used or needed.

---

## Cost control

* Local deterministic work has no metered Arkham charge: date/URL/duplicate filtering, entity extraction, KEV lookups, scoring, validation, and rendering.
* A run makes zero model calls with `LLM_PROVIDER=template`, or normally one request with the Gemini/OpenAI/Anthropic provider. Token volume varies with the collected evidence.
* Feeds use conditional GET; NVD is incremental; KEV's 1.6 MB catalog is the largest download. Arkham Crawl caches extracted articles and revalidates with ETags.
* Delivery: Discord incoming webhooks are free. A brief is usually one webhook message (up to 10 embeds); long mornings use two or three. The legacy SMS transport bills per carrier segment and is the only reason `SMS_PRICE_PER_SEGMENT` exists.
* Every run prints an **ARKHAM COST REPORT** (calls, tokens, delivery messages, run and monthly estimate). Pricing is configuration (`LLM_*_PRICE_PER_1M`; `SMS_PRICE_PER_SEGMENT` for SMS); nothing is fabricated — unset pricing is reported as "unpriced".
* LLM, GitHub Actions, Lambda, S3, and network charges are provider- and account-dependent. Configure current LLM unit prices in environment variables; Arkham reports `unpriced` when they are absent rather than guessing.

---

## Run history and observability

Every execution records `run_started`, `run_finished`, window, `sources_checked`, `sources_successful`, `raw_items`, `unique_events`, `candidate_events`, `events_selected`, LLM calls/tokens/cost, `delivery_provider`, `delivery_messages`, `delivery_attempts`, `delivery_status` (plus `sms_segments` for the legacy transport), per-source statuses and any error. `python -m arkham history` prints them; the run also prints:

```text
Arkham Run
Sources: 24/26
Raw: 347
Unique: 113
Candidates: 29
Selected: 8
LLM calls: 1 (5,120 in / 610 out tokens)
Delivery: discord sent (2 message(s), 2 attempt(s))
```

Logs are structured (`ARKHAM_LOG_FORMAT=json` for machine parsing) and pass through a masking filter that redacts configured secrets, webhook URLs, token-shaped strings and phone numbers.

### Storage and retention

The default store is `data/arkham.db` (SQLite, git-ignored). GitHub Actions restores/saves `data/` through the Actions cache; the optional AWS deployment syncs the database to one private S3 object.

Arkham retains source ETags/Last-Modified values and health state; raw-item hashes plus source id, external id, title, canonical URL and timestamps; normalized `CyberEvent` records with structured entities, confidence, evidence URLs, fingerprints, first/last seen and briefing counters; material-update records; sanitized run/source/cost metrics; and delivery metadata containing the provider, a masked destination, Discord message ids, message and attempt counts (segment count for SMS) and the briefing hash. This is what enables conditional requests, deduplication, story evolution, search, and delivery guards.

Arkham intentionally does **not** retain raw article bodies, raw feed payloads, rendered brief bodies, the webhook URL, unmasked recipients, API keys, auth tokens, or environment dumps. v1 has no automatic age-based purge: structured event history remains until the user removes the database/cache. Corrupt SQLite files are preserved with a timestamped `.corrupt-*` suffix and a clean database is created so the next run can recover.

### External APIs and services

Core collection uses the public CISA KEV JSON catalog, NVD CVE API 2.0, publisher RSS/Atom endpoints listed above, and publisher article pages fetched by Arkham Crawl (no paid crawler API). Synthesis uses Gemini's OpenAI-compatible endpoint, any other OpenAI-compatible Chat Completions API, or Anthropic Messages; `template` uses no external model. Delivery uses a Discord incoming webhook (Twilio's Messages REST API only for the legacy SMS transport). GitHub Actions and its cache are the default scheduler/state transport. Lambda, EventBridge Scheduler, S3, and AWS IAM are an alternative deployment only.

---

## Testing

```bash
pytest -q          # fixture-driven, no network access
ruff check .
pip-audit -r requirements.txt
```

Tests cover source normalization for every adapter (captured feed samples), CVE/date parsing, URL validation and SSRF protections, HTTP size/timeout/redirect hardening, prompt-injection detection and neutralization, Arkham Crawl (secure fetch and robots policy with mocked origins, extraction of normal/navigation-heavy/JavaScript-shell/malformed/hidden/huge/plain-text documents, quality scoring, interstitial classification, material-change detection, indicator extraction including defanged, private-IP, version and source-domain false-positive cases, and the bridge into normalization), conservative correlation, scoring and KEV prioritization, confidence and attribution handling, failed/hanging sources, Discord delivery (webhook allow-listing and masking, embed layout and limits, multi-message splitting, `allowed_mentions`, `@everyone`/`@here`/role-mention neutralization, markdown escaping, 429/`Retry-After`/5xx/timeout retries with a bounded budget, redirect refusal, delivery metadata, duplicate-send protection, quiet runs, the `test-delivery` command), the legacy SMS encoding/segmentation/splitting and Twilio provider, dry-run behaviour, duplicate suppression between days, material updates, evidence/output validation, storage migration and corruption recovery, search, cost accounting, and scheduling/DST. External services are mocked with `httpx.MockTransport`; the test suite never posts to Discord and does not depend on live network state.

---

## Limitations

* v1 delivers to a single destination by design: one Discord webhook (or, legacy, one phone number). No email, push, dashboard, or mobile app; Discord notifications on your phone are the alert path.
* Entity extraction is conservative and pattern/adapter based. It reliably preserves explicit CVE/CWE ids and structured adapter metadata, but may miss novel actor, victim, malware, sector, or geography names.
* Arkham Crawl is a library layer in v1: the scheduled run works from feed/API records and does not fetch article pages; extraction is heuristic (container density, not a learned model) and indicator candidates are regex-based observations that still need analyst judgement.
* Deduplication is heuristic (CVE/URL/title/entity); no embeddings. Two outlets describing the same incident with very different headlines and no shared CVE/URL may briefly appear as two events until a primary source links them.
* Journalism-only stories are capped at LOW confidence; this is intentional and means some real incidents are phrased as "reported".
* Google Project Zero's feed is ~13 MB and disabled by default. Sophos's configured feed path is unavailable. CISA Advisories/Alerts are disabled because the hardened client receives HTTP 403. The normal MSRC blog has no usable feed; the MSRC Update Guide and Microsoft Security Blog are distinct working sources.
* GitHub Actions scheduling is best-effort (minutes of drift). The AWS path is exact.
* Discord webhooks have no idempotency key: a request that times out after Discord stored the message could be retried into a duplicate embed. Retries are bounded (4 attempts per message) so this is rare and small; the 20-hour guard prevents whole-brief duplicates across runs.
* Anyone holding the webhook URL can post into the channel; rotate it in Discord if it leaks. Arkham never prints or stores it, but it lives in your `.env` and in the Actions secret.
* Legacy SMS only: Twilio trial accounts can only message verified numbers; a successful create response means accepted/queued, not delivered.
* GitHub Actions cache retention is platform-controlled. If the cache is evicted, Arkham starts safely with an empty history; it cannot reconstruct prior briefing memory without a database backup.

---

## Future improvements

The data model already stores everything needed for a searchable personal knowledge base (`python -m arkham search` is the seed):

* `arkham ask APT28`, `arkham ask ransomware this month`, `arkham weekly`, `arkham monthly` — retrieval over stored events with the same evidence-only synthesis.
* Embedding-assisted deduplication for cross-outlet incident matching.
* Additional national CERT feeds (JPCERT, CERT-FR, BSI, ACSC) and vendor PSIRTs via the same `RssAdapter`.
* PostgreSQL/Supabase or DynamoDB storage backend behind the existing `Storage` interface.
* Further delivery providers (email, push) behind `DeliveryProvider` (still one destination).
