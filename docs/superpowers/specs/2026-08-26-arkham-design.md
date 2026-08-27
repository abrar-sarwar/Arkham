# Arkham v1 — Design Record (2026-08-26)

The product specification supplied by the owner is the authoritative requirements document
(46 sections: behaviour, sources, ranking, LLM role, SMS, security, deployment, acceptance tests).
This file records the **concrete engineering decisions** made where that spec leaves latitude,
so they can be reviewed and overridden without re-reading the code.

## Decisions

| Area | Decision | Why |
|---|---|---|
| Language / runtime | Python 3.11+ (developed on 3.14), stdlib `zoneinfo` for America/New_York | Only python3 present on the workstation; zoneinfo handles DST correctly. |
| Dependencies | `httpx`, `feedparser`, `pydantic`, `tzdata` only (pinned). Discord, Twilio and LLM providers are called over their REST APIs with `httpx`, no vendor SDKs; Arkham Crawl's extractor is the stdlib `html.parser` (the planned Trafilatura/Playwright pins were never installed and were removed on 2026-08-27). | Smallest possible supply-chain surface for a security tool; full control of timeouts and response-size caps. |
| Storage | SQLite (stdlib `sqlite3`) behind `arkham.storage.base.Storage` ABC | Zero infrastructure for v1; the ABC is the seam for Postgres/DynamoDB later. |
| LLM providers | `gemini` (intended production model; Google's OpenAI-compatible endpoint through the same `OpenAIModel` code), `openai` (OpenAI-compatible Chat Completions, configurable base URL), `anthropic` (Messages API), `template` (deterministic, evidence-only, no network) | Provider abstraction is real (two wire implementations); `template` lets the first dry-run work with zero credentials and is the honest fallback. |
| Model name | `LLM_MODEL` is required for API providers and never defaulted | Model names deprecate; the spec forbids hardcoding one. |
| Pricing | Read from env (`LLM_*_PRICE_PER_1M`, `SMS_PRICE_PER_SEGMENT` for the legacy SMS path); Discord webhooks are free; report "unpriced" if absent | Spec: do not fabricate pricing. |
| LLM output contract | Model returns strict JSON (`BriefingDraft`) that references evidence ids and picks URLs only from an allow-list; Arkham renders the brief deterministically per transport | Makes validation tractable: every URL/CVE/confidence label is checked against collected evidence before rendering. |
| Prompt-injection defence | All source text is HTML-stripped, control-char-stripped, truncated, injection-pattern-neutralised, and wrapped as tagged `<evidence>` data. System prompt states evidence is untrusted. Output validation rejects anything not grounded in evidence. | Defence in depth: sanitise input, constrain output, validate output. |
| Deduplication | Union-find clustering on CVE ids, canonical URLs, shared organisation+incident tokens, and normalised-title similarity | Deterministic, explainable, no embeddings/API cost. |
| Material updates | Each event has a state fingerprint (KEV status, exploitation status, CVSS band, PoC, source count band, attribution). A changed fingerprint on re-observation = material development (+10) and un-suppresses the story. | Spec §11. |
| Delivery (default) | Discord incoming webhook (`ARKHAM_DELIVERY_PROVIDER=discord`): one embed per story, packed under Discord's limits into as many messages as needed, mentions disabled, markdown escaped, bounded retries. See `2026-08-27-discord-delivery-design.md`. | Free, no bot/WebSocket, works from GitHub Actions; SMS constraints no longer shape the brief. |
| SMS (legacy, optional) | `ARKHAM_DELIVERY_PROVIDER=twilio`: Twilio Messages API. One body up to `ARKHAM_MAX_SMS_CHARS` (default 900); bodies over the cap are split at section boundaries into `ARKHAM 1/N` parts. GSM-7 vs UCS-2 segment counting is exact. Emoji headers are off by default (`ARKHAM_SMS_EMOJI=false`) for cheaper GSM-7 output. | Kept because the provider is isolated and tested; not required for v1. |
| Recipient restriction | Every `DeliveryProvider` takes its destination at construction from settings; `deliver()` has no destination parameter; the masked destination is re-validated against settings immediately before sending. | Prevents recipient injection. |
| Scheduling (production) | GitHub Actions: two UTC crons (12:00 and 13:00) + a `should-run` gate that only proceeds when it is `ARKHAM_DELIVERY_HOUR` in `ARKHAM_TIMEZONE` and no successful run happened in the last 20 h. State DB persisted with `actions/cache`. | Actions cron is UTC-only; the gate makes DST correct without guessing offsets. Repo is public, so the production job logs metrics only, never the brief. |
| Scheduling (alternative) | `deploy/aws/` Lambda handler + EventBridge Scheduler expression with `America/New_York` timezone, documented not provisioned | Spec option B. |
| Collection window | From the last successful run's window end (or `ARKHAM_LOOKBACK_HOURS`), capped at 168 h; NVD is queried incrementally by `lastModStartDate/EndDate`; feeds use conditional GET (ETag / If-Modified-Since). | Spec §6, §17. |
| Sources unavailable | Sophos feed host rejects connections from this network, MSRC blog has no feed. Shipped disabled / omitted with notes; MSRC Update Guide RSS and Microsoft Security blog are used instead. | Verified live on 2026-08-26. |

## Pipeline

`collect → Arkham Crawl → normalize → sanitize → enrich → deduplicate → verify(confidence/claims/attribution) → score → material-update check → select → evidence pack → LLM draft (Gemini) → validate → render (Discord embeds | SMS) → validate rendered → deliver → record run/cost`

## Module map

See README "Architecture". Contracts live in `arkham/models.py`, `arkham/sources/base.py`,
`arkham/storage/base.py`, `arkham/delivery/base.py`, `arkham/intelligence/llm/base.py`.
