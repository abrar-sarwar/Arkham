"""Command-line interface: `python -m arkham <command>`."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from arkham import __version__
from arkham.config import ConfigError, Settings, load_settings
from arkham.logging_setup import configure_logging

log = logging.getLogger("arkham")

TEST_DELIVERY_MESSAGE = (
    "Arkham delivery test\n\n"
    "{transport} delivery is configured correctly. This message was sent by an explicit "
    "`python -m arkham test-delivery`; scheduled briefings will arrive in this channel."
)


def _http_client(settings: Settings):  # type: ignore[no-untyped-def]
    """The hardened HTTP client used for delivery commands (tests substitute a mock transport)."""
    from arkham.http import SafeHttpClient

    return SafeHttpClient(
        timeout_seconds=settings.http_timeout_seconds, max_bytes=settings.http_max_bytes, user_agent=settings.user_agent
    )


def _settings(args: argparse.Namespace) -> Settings:
    try:
        settings = load_settings(dotenv_path=args.env_file)
    except ConfigError as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from None
    configure_logging(args.log_level or settings.log_level, settings.log_format, settings.secret_values)
    return settings


def cmd_check_config(args: argparse.Namespace) -> int:
    settings = _settings(args)
    print(f"Arkham {__version__} configuration (secrets masked)")
    for line in settings.summary_lines():
        print("  " + line)
    problems = {"LLM": settings.validate_llm(), "Delivery": settings.validate_delivery()}
    ok = True
    for area, items in problems.items():
        if items:
            ok = False
            print(f"\n{area}: NOT READY")
            for p in items:
                print(f"  - {p}")
        else:
            print(f"\n{area}: ready")
    print(
        "\nDry run needs: LLM ready (or LLM_PROVIDER=template). Live delivery needs: LLM + Delivery ready.\n"
        "Verify the channel without a full run: python -m arkham test-delivery"
    )
    return 0 if ok else 1


def cmd_test_delivery(args: argparse.Namespace) -> int:
    """Send ONE small, clearly labelled message through the configured transport. Explicit invocation only."""
    from arkham.delivery import build_provider

    settings = _settings(args)
    problems = settings.validate_delivery()
    if problems:
        print("Delivery configuration incomplete:\n  - " + "\n  - ".join(problems), file=sys.stderr)
        return 2
    transport = "Discord" if settings.delivery_provider == "discord" else "SMS"
    with _http_client(settings) as http:
        provider = build_provider(settings, http)
        print(f"Sending a delivery test via {provider.name} to {provider.recipient_masked} ...")
        result = provider.deliver_notice(TEST_DELIVERY_MESSAGE.format(transport=transport))
    if result.status.value == "sent":
        print(f"Sent ({result.messages_sent} message, {result.attempts} attempt(s)). Check the channel.")
        return 0
    print(f"Delivery test failed: {result.error}", file=sys.stderr)
    return 1


def cmd_sources(args: argparse.Namespace) -> int:
    from arkham.sources.registry import all_sources, enabled_sources

    settings = _settings(args)
    enabled = {s.id for s in enabled_sources(settings.disabled_sources)}
    print(f"{'id':26} {'tier':5} {'category':14} {'enabled':8} name")
    for s in all_sources():
        flag = "yes" if s.id in enabled else "no"
        print(f"{s.id:26} T{int(s.tier):<4} {s.category.value:14} {flag:8} {s.name}" + (f"  ({s.notes})" if s.notes and s.id not in enabled else ""))
    if not args.check:
        return 0
    from datetime import timedelta

    from arkham.http import SafeHttpClient
    from arkham.sources.collector import collect_all, format_source_table
    from arkham.storage import open_storage

    now = datetime.now(timezone.utc)
    print(f"\nLive check (window {args.hours}h, no state mutation beyond source health)...")
    with SafeHttpClient(timeout_seconds=settings.http_timeout_seconds, max_bytes=settings.http_max_bytes, user_agent=settings.user_agent) as http:
        with open_storage(settings) as storage:
            result = collect_all(
                enabled_sources(settings.disabled_sources),
                http=http,
                storage=storage,
                window_start=now - timedelta(hours=args.hours),
                window_end=now,
                now=now,
                nvd_api_key=settings.nvd_api_key,
            )
    print(format_source_table(result.statuses))
    print(f"Raw items in window: {len(result.items)}")
    return 0 if any(s.ok for s in result.statuses) else 1


def cmd_run(args: argparse.Namespace) -> int:
    from arkham.costs import format_cost_report
    from arkham.runner import RunOptions, execute_run, format_run_summary
    from arkham.storage import open_storage

    settings = _settings(args)
    options = RunOptions(dry_run=args.dry_run, force=args.force, since_hours=args.since, show_evidence=args.show_evidence)
    if args.dry_run and args.force:
        print("--dry-run and --force are mutually exclusive", file=sys.stderr)
        return 2
    with open_storage(settings) as storage:
        outcome = execute_run(settings, options, storage=storage)
    run = outcome.run
    print()
    print(outcome.source_table or "(no sources checked)")
    print()
    if outcome.pack and options.show_evidence:
        print("EVIDENCE PACK (what the analyst model received)")
        print(outcome.pack.model_dump_json(indent=1))
        print()
    if outcome.briefing and (args.dry_run or args.show_brief):
        parts = outcome.briefing.messages
        print(f"BRIEFING ({len(outcome.briefing.text)} chars, {len(parts)} message(s)) — generated by {outcome.briefing.generated_by}")
        print("-" * 60)
        for part in parts:
            print(part)
            print("-" * 60)
        if outcome.briefing.validation_notes:
            print("notes: " + "; ".join(outcome.briefing.validation_notes))
        print()
    print(format_run_summary(run))
    if outcome.cost:
        print()
        print(format_cost_report(outcome.cost, sms_sent=outcome.sent))
    if args.dry_run:
        print(f"\nDry run: nothing was sent (configured {settings.delivery_provider} destination: {settings.recipient_masked}).")
    elif outcome.sent:
        destination = outcome.delivery.recipient_masked if outcome.delivery else settings.recipient_masked
        print(f"\nDelivered via {settings.delivery_provider} to {destination}.")
    if args.json:
        print(run.model_dump_json(indent=1))
    return 0 if run.status == "success" else 1


def cmd_history(args: argparse.Namespace) -> int:
    from arkham.storage import open_storage

    settings = _settings(args)
    with open_storage(settings) as storage:
        runs = storage.list_runs(limit=args.limit)
        deliveries = storage.list_deliveries(limit=args.limit)
    if not runs:
        print("No runs recorded yet.")
        return 0
    print(f"{'started (UTC)':20} {'mode':9} {'status':9} {'src':7} {'raw':5} {'uniq':5} {'cand':5} {'sel':4} {'llm tok':11} {'delivery':24}")
    for r in runs:
        delivery = f"{r.delivery_provider or '-'}:{r.delivery_status.value}({r.delivery_messages} msg"
        delivery += f", {r.sms_segments} seg)" if r.delivery_provider == "twilio" else ")"
        print(
            f"{r.started_at:%Y-%m-%d %H:%M:%S}  {r.mode:9} {r.status:9} {r.sources_successful:>2}/{r.sources_checked:<3} "
            f"{r.raw_items:5} {r.unique_events:5} {r.candidate_events:5} {r.events_selected:4} "
            f"{r.llm_tokens_in:>5}/{r.llm_tokens_out:<5} {delivery}"
        )
        if r.error:
            print(f"    error: {r.error[:160]}")
    if deliveries:
        print("\nDeliveries:")
        for d in deliveries:
            print(
                f"  {d.get('sent_at', '?')}  {d.get('provider')}  {d.get('status')}  messages={d.get('messages_sent')}  "
                f"attempts={d.get('attempts', 0)}  run={d.get('run_id')}"
            )
    return 0


def cmd_should_run(args: argparse.Namespace) -> int:
    from arkham.schedule import should_run
    from arkham.storage import open_storage

    settings = _settings(args)
    now = datetime.now(timezone.utc)
    with open_storage(settings) as storage:
        last = storage.get_last_successful_run(delivered_only=True)
    ok, reason = should_run(now, settings, last)
    print(("RUN" if ok else "SKIP") + f": {reason}")
    return 0 if ok else 3


def cmd_next_run(args: argparse.Namespace) -> int:
    from arkham.schedule import github_cron_lines, next_run_time

    settings = _settings(args)
    now = datetime.now(timezone.utc)
    nxt = next_run_time(now, settings.tzinfo, settings.delivery_hour)
    print(f"Next delivery: {nxt:%Y-%m-%d %H:%M %Z} ({nxt.astimezone(timezone.utc):%H:%M} UTC)")
    print("GitHub Actions cron lines covering standard and daylight time for this timezone/hour:")
    for line in github_cron_lines(settings.tzinfo, settings.delivery_hour, now.year):
        print(f"  - cron: '{line}'")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    from arkham.storage import open_storage

    settings = _settings(args)
    with open_storage(settings) as storage:
        results = storage.search_events(" ".join(args.query), limit=args.limit)
    if not results:
        print("No stored events match.")
        return 0
    for stored in results:
        e = stored.event
        print(f"[{e.final_priority_score:5.1f}] {stored.last_seen:%Y-%m-%d} {e.event_type.value:15} {e.title[:90]}")
        print(f"        {', '.join(e.cves[:4]) or '-'} | {', '.join(e.threat_actors[:3]) or '-'} | {e.confidence.value} | {e.primary_source_url or e.source_url}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arkham", description="Arkham — personal cyber threat intelligence agent")
    parser.add_argument("--env-file", default=".env", help="path to .env (default: .env)")
    parser.add_argument("--log-level", default=None, help="override ARKHAM_LOG_LEVEL")
    parser.add_argument("--version", action="version", version=f"arkham {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="collect, analyze, brief and (unless --dry-run) deliver via the configured provider (Discord by default)")
    p_run.add_argument("--dry-run", action="store_true", help="fetch, analyze, generate and print the briefing; do NOT send")
    p_run.add_argument("--force", action="store_true", help="send even if a briefing was already delivered today")
    p_run.add_argument("--since", type=int, metavar="HOURS", help="override the collection window (1-168 hours)")
    p_run.add_argument("--show-evidence", action="store_true", help="print the evidence pack given to the model")
    p_run.add_argument("--show-brief", action="store_true", help="print the briefing text even when sending (avoid in public CI logs)")
    p_run.add_argument("--json", action="store_true", help="print the run record as JSON")
    p_run.set_defaults(func=cmd_run)

    p_src = sub.add_parser("sources", help="list the source registry; --check fetches every enabled source live")
    p_src.add_argument("--check", action="store_true")
    p_src.add_argument("--hours", type=int, default=24)
    p_src.set_defaults(func=cmd_sources)

    sub.add_parser("check-config", help="validate configuration and print a secret-free summary").set_defaults(func=cmd_check_config)
    sub.add_parser(
        "test-delivery",
        help="send ONE small labelled test message through the configured delivery provider (never automatic)",
    ).set_defaults(func=cmd_test_delivery)

    p_hist = sub.add_parser("history", help="show recent runs and deliveries")
    p_hist.add_argument("--limit", type=int, default=15)
    p_hist.set_defaults(func=cmd_history)

    sub.add_parser("should-run", help="exit 0 only if it is the delivery hour and nothing was delivered recently (scheduler gate)").set_defaults(func=cmd_should_run)
    sub.add_parser("next-run", help="print the next delivery time and matching UTC cron lines").set_defaults(func=cmd_next_run)

    p_search = sub.add_parser("search", help="search stored events (seed of the future `arkham ask`)")
    p_search.add_argument("query", nargs="+")
    p_search.add_argument("--limit", type=int, default=20)
    p_search.set_defaults(func=cmd_search)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except ConfigError as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        return 2
