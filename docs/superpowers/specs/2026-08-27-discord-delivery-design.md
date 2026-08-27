# Arkham Discord Delivery — Design Record (2026-08-27)

## Goal

Make a free Discord incoming webhook the default Arkham v1 notification transport, replacing paid Twilio
SMS on the default path, while keeping one clean transport abstraction so other providers can be added
later. Nothing upstream of rendering (collection, Arkham Crawl, memory, scoring, Gemini synthesis,
grounding/validation, quiet runs, material-update tracking) changes its behaviour.

```text
feeds / APIs -> Arkham Crawl -> normalization / dedupe -> SQLite memory -> scoring
  -> Gemini (OpenAI-compatible endpoint) -> grounding / validation -> Discord webhook
  -> private Arkham channel -> phone notification
```

## Decisions

| Area | Decision | Why |
|---|---|---|
| Transport abstraction | `arkham.delivery.base.DeliveryProvider`: constructed with its ONE destination; `deliver(briefing) -> DeliveryResult` and `deliver_notice(text)` take no destination parameter; `recipient_masked` exposes a masked destination for the recipient-equality check. `MessageProvider` (SMS-body based) is a `DeliveryProvider` subclass, so Twilio is untouched. | Same recipient-injection guarantee as before, now transport-neutral. |
| Default provider | `ARKHAM_DELIVERY_PROVIDER=discord` (default). `twilio` remains selectable as a legacy, optional, paid provider. | Twilio's REST-only provider is isolated (no SDK dependency, config validated only when selected); deleting it would remove working, tested code for no security gain. |
| Discord API surface | Standard incoming webhook, `POST <webhook>?wait=true` with JSON `{content, embeds, allowed_mentions}`. No bot token, no gateway/WebSocket, no library. | Free, stateless, works from GitHub Actions. `wait=true` returns the created message so ids are recorded and failures are not silent. |
| Webhook URL validation | `arkham.security.urls.validate_discord_webhook_url`: reuses `validate_public_url` (https, no credentials, no loopback/private/link-local hosts, port 443) and then requires host ∈ {discord.com, discordapp.com, ptb.discord.com, canary.discord.com} and path `/api[/vN]/webhooks/<snowflake>/<token>` with no query/fragment. The provider refuses redirects entirely. | A config value that merely contains a URL must not turn Arkham into an SSRF/exfiltration client. |
| Secret handling | The URL and its token are in `Settings.secret_values` (log redaction), `mask_webhook_url` is used in every summary/log/result (`https://discord.com/api/webhooks/1234****7890/***`), the logging filter also redacts any webhook-shaped URL, provider error strings are scrubbed before they reach `DeliveryResult`/`RunRecord`/SQLite. | Anyone holding the URL can post into the channel. |
| Core model vs renderers | `Briefing` is the transport-neutral core (draft, cited evidence, counts, canonical plain `text`, plain-text `messages`). `intelligence/brief.py` stays the SMS renderer (GSM-7 transliteration, 900-char budget, `ARKHAM i/N` splitting) and is used only for Twilio. `delivery/discord_format.py` renders the same core into Discord embeds. | SMS constraints no longer shape the default brief; the intelligence model is unchanged. |
| Discord layout | Message 1 `content` = `**ARKHAM** · Morning Intelligence Brief · <long date>` + stats line. One embed per story: `author` = section tag (CRITICAL/THREAT/INCIDENT/RESEARCH/POLICY, "· UPDATE" on material updates), `title` = headline linked to the cited source, `description` = why it matters, inline fields *Affected* (products/CVEs) and *Exploitation* (KEV/status/CVSS) when present, *What happened* (bounded evidence summary), *Evidence · <confidence>* (masked links to evidence sources), *Source* (bare cited URL), footer `E<n> · <publisher> · published <UTC>`, `timestamp`. Prep/Learn share one closing embed; quiet runs send a short "No material updates" content line plus a compact Watch embed. | Skimmable on mobile; every URL is an evidence URL. |
| Severity colours | Section → colour: CRITICAL red, THREAT orange, INCIDENT amber, RESEARCH blue, POLICY purple, meta blue-grey. | The project's existing priority taxonomy is `BriefSection`; no second severity scale is invented. |
| Limits | Renderer enforces title 256, description 4096, field name 256 / value 1024, footer 2048, author 256, ≤10 embeds and ≤6000 embed characters per message, content ≤2000. Stories are never dropped: overflow starts a new message (`ARKHAM · continued k/N`). Per-field text is truncated on sentence/word boundaries; headline, why-it-matters, confidence and the cited source URL are always kept. `DeliveryResult.messages_sent` and `RunRecord.briefing_messages` record how many messages were required. | Discord limits must never fail a run or silently discard intelligence. |
| Untrusted text | Every string from the draft or evidence is `sanitize_text`-ed, markdown-escaped (`\ * _ ~ \` | [ ] > #`) and mention-neutralised (`@everyone`, `@here`, `<@id>`, `<@!id>`, `<@&id>`, `<#id>` get a zero-width space). Every payload carries `"allowed_mentions": {"parse": []}` — set by the provider, not the renderer, so it cannot be forgotten. Before sending, the provider re-checks that every https URL in the payload is an evidence URL of the briefing (fail closed). | Article text must never ping a channel, forge a masked link, or cite a non-evidence URL. |
| Retries | Bounded: 4 attempts per message (1 + 3 retries). Retry on 429 (honouring `Retry-After`, capped at 30 s), 5xx, timeouts and transport errors; never on other 4xx or on a refused redirect. Backoff 1 s → 2 s → 4 s (cap 30 s). Messages are posted sequentially with a 0.5 s pause. A failure after k messages returns `FAILED` with `messages_sent=k`, `attempts` = total attempts. | No infinite loops, no retry storms; a timed-out request may already have posted (Discord has no idempotency key), so retries are bounded rather than unbounded. |
| Duplicate-send protection | Unchanged: the 20-hour `recently_delivered` guard on the last `SENT` run, `should-run` gate for cron, the workflow `concurrency` group and the Actions cache. `record_delivery` happens immediately after the send. No second dedupe system. | Existing design already covers workflow reruns, retries and restarts. |
| Quiet runs | Unchanged product behaviour: a short quiet brief (watch items + prep/learn) is sent, never a large empty briefing. | Preserve the existing intended behaviour. |
| Metadata | `DeliveryResult` gains `attempts` and `delivered_at`; `RunRecord` gains `delivery_provider`, `delivery_messages`, `delivery_attempts`; SQLite `deliveries` gains `attempts` (idempotent `ALTER TABLE` migration). The webhook URL is never persisted. | Run history stays useful and safe. |
| Test delivery | `python -m arkham test-delivery` posts one small labelled message (`Arkham delivery test` …) through the configured provider. Explicit invocation only; config loading and tests never send. | Verifies the real channel without a full run. |
| Gemini | `LLM_PROVIDER=gemini` + `GEMINI_API_KEY` (+ optional `GEMINI_BASE_URL`, default Google's OpenAI-compatible endpoint) construct the existing `OpenAIModel`; no duplicate provider. `LLM_PROVIDER=openai` with `OPENAI_BASE_URL` still works. | Gemini speaks the OpenAI Chat Completions dialect (JSON mode, temperature, Bearer auth); reusing the provider keeps grounding, validation, citations and quiet-run logic identical. |
| Firecrawl | Absent. Arkham Crawl (`arkham/crawl/`) is the native replacement; nothing in this change adds a crawler dependency. | Design constraint. |

## Out of scope

Email/push providers, a Discord bot, message editing, and the unfinished Arkham Crawl extraction tasks
(`arkham/crawl/extract.py`, `quality.py`, `indicators.py` and their tests) remain future work.
