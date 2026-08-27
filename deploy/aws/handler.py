"""AWS Lambda entry point (alternative deployment; see deploy/aws/README.md).

EventBridge Scheduler invokes this once a day using a timezone-aware schedule
(cron(0 8 * * ? *) with ScheduleExpressionTimezone=America/New_York), so no UTC offset guessing.
State: the SQLite database is synced from/to S3 when ARKHAM_S3_BUCKET is set (boto3 ships with the
Lambda Python runtime). Configuration comes from Lambda environment variables (store secrets in
AWS Secrets Manager / SSM and inject them; never hardcode).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from arkham.config import load_settings
from arkham.logging_setup import configure_logging
from arkham.runner import RunOptions, execute_run, format_run_summary
from arkham.storage import open_storage

log = logging.getLogger("arkham.lambda")

BUCKET = os.environ.get("ARKHAM_S3_BUCKET")
S3_KEY = os.environ.get("ARKHAM_S3_KEY", "arkham/arkham.db")
LOCAL_DB = os.environ.get("ARKHAM_DB_PATH", "/tmp/arkham.db")


def _s3():  # type: ignore[no-untyped-def]
    import boto3  # available in the Lambda runtime; not an Arkham dependency

    return boto3.client("s3")


def _download_state() -> None:
    if not BUCKET:
        return
    try:
        Path(LOCAL_DB).parent.mkdir(parents=True, exist_ok=True)
        _s3().download_file(BUCKET, S3_KEY, LOCAL_DB)
        log.info("state restored from s3://%s/%s", BUCKET, S3_KEY)
    except Exception as exc:  # noqa: BLE001 - first run has no state yet
        log.warning("no prior state restored (%s)", exc.__class__.__name__)


def _upload_state() -> None:
    if not BUCKET or not Path(LOCAL_DB).exists():
        return
    _s3().upload_file(LOCAL_DB, BUCKET, S3_KEY)
    log.info("state saved to s3://%s/%s", BUCKET, S3_KEY)


def lambda_handler(event: dict, context: object) -> dict:
    os.environ.setdefault("ARKHAM_DB_PATH", LOCAL_DB)
    settings = load_settings(dotenv_path=None)
    configure_logging(settings.log_level, "json", settings.secret_values)
    dry_run = bool((event or {}).get("dry_run", False))
    force = bool((event or {}).get("force", False))
    _download_state()
    try:
        with open_storage(settings) as storage:
            outcome = execute_run(settings, RunOptions(dry_run=dry_run, force=force), storage=storage)
    finally:
        _upload_state()
    summary = format_run_summary(outcome.run)
    log.info(summary.replace("\n", " | "))
    return {"status": outcome.run.status, "delivery": outcome.run.delivery_status.value, "run_id": outcome.run.run_id}
