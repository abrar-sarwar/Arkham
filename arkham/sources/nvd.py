"""NVD CVE API 2.0 adapter (incremental by ``lastModified``).

Query strategy
--------------
* ``lastModStartDate`` / ``lastModEndDate`` are the collection window in UTC, formatted
  ``%Y-%m-%dT%H:%M:%S.000`` (NVD treats a missing offset as UTC). NVD caps the range at 120 days,
  so wider windows are clamped from the start side.
* ``resultsPerPage=2000`` with ``startIndex`` pagination until ``startIndex + resultsPerPage >=
  totalResults``, at most :data:`MAX_PAGES` pages per run.
* The ``apiKey`` header is sent only when a key is configured. NVD's published rate limits are
  honoured by sleeping between page requests (6 s without a key, 0.7 s with one) through the
  module attribute :data:`_sleep`, which tests replace. One retry after 6 s on HTTP 503/429/403.

Selection
---------
A CVE is kept when it was *published* inside the window, or its ``cisaExploitAdd`` date falls inside
the window (date granularity). A metadata-only ``lastModified`` refresh is not treated as a new
story, regardless of CVSS: doing so floods a morning brief with old vulnerabilities on a first run.
``vulnStatus == "Rejected"`` is always dropped. Survivors are ordered KEV-first, then CVSS desc,
then newest published, and capped at ``source.max_items``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

from arkham.http import HttpResponse, HttpStatusError
from arkham.models import RawItem
from arkham.security.prompt_injection import sanitize_text
from arkham.security.urls import UrlValidationError, validate_public_url
from arkham.sources.base import FetchContext, FetchResult, SourceAdapter, in_window, parse_datetime

log = logging.getLogger(__name__)

PUBLISHER = "NVD"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
RESULTS_PER_PAGE = 2000
MAX_PAGES = 5
MAX_RANGE = timedelta(days=120)
DELAY_WITHOUT_KEY = 6.0
DELAY_WITH_KEY = 0.7
RETRY_DELAY = 6.0
RETRY_STATUSES = frozenset({503, 429, 403})
REJECTED_STATUSES = ("Rejected",)
MAX_REFERENCES = 15
MAX_PRODUCTS = 5
TITLE_DESCRIPTION_MAX = 110
SUMMARY_MAX = 1200

_NVD_TIME_FMT = "%Y-%m-%dT%H:%M:%S.000"
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_CPE_SPLIT_RE = re.compile(r"(?<!\\):")
_CPE_UNESCAPE_RE = re.compile(r"\\(.)")

_sleep: Callable[[float], None] = time.sleep
"""Sleep function used for rate limiting and retry back-off; patchable in tests."""


# ------------------------------------------------------------------ query building


def _to_utc(value: datetime) -> datetime:
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def build_nvd_params(window_start: datetime, window_end: datetime, start_index: int = 0) -> dict[str, str]:
    """Build the query parameters for one page of the incremental ``lastModified`` query.

    Both bounds are rendered in UTC without an offset; a range wider than 120 days is clamped by
    moving ``lastModStartDate`` forward (NVD rejects wider ranges).
    """
    start = _to_utc(window_start)
    end = _to_utc(window_end)
    if end - start > MAX_RANGE:
        start = end - MAX_RANGE
    return {
        "lastModStartDate": start.strftime(_NVD_TIME_FMT),
        "lastModEndDate": end.strftime(_NVD_TIME_FMT),
        "resultsPerPage": str(RESULTS_PER_PAGE),
        "startIndex": str(max(0, int(start_index))),
    }


# ------------------------------------------------------------------ record helpers


@dataclass(frozen=True)
class CvssInfo:
    """The CVSS metric selected for a CVE (see :func:`select_cvss`)."""

    score: float
    severity: str | None
    vector: str | None
    version: str
    metric_type: str
    source: str


def select_cvss(metrics: Any) -> CvssInfo | None:
    """Pick the most relevant CVSS metric: v4.0, then v3.1, v3.0, v2; ``type == "Primary"`` first within a list."""
    if not isinstance(metrics, dict):
        return None
    for key in _CVSS_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        candidates = [e for e in entries if isinstance(e, dict)]
        chosen = next((e for e in candidates if e.get("type") == "Primary"), candidates[0] if candidates else None)
        if chosen is None:
            continue
        data = chosen.get("cvssData") if isinstance(chosen.get("cvssData"), dict) else {}
        try:
            score = float(data.get("baseScore"))
        except (TypeError, ValueError):
            continue
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        vector = data.get("vectorString")
        return CvssInfo(
            score=score,
            severity=sanitize_text(str(severity), 20).upper() if severity else None,
            vector=sanitize_text(str(vector), 200) if vector else None,
            version=str(data.get("version") or key),
            metric_type=str(chosen.get("type") or ""),
            source=str(chosen.get("source") or ""),
        )
    return None


def english_description(cve: dict[str, Any]) -> str:
    """Return the English description, falling back to the first description of any language."""
    descriptions = [d for d in cve.get("descriptions") or [] if isinstance(d, dict) and d.get("value")]
    for entry in descriptions:
        if entry.get("lang") == "en":
            return str(entry["value"])
    return str(descriptions[0]["value"]) if descriptions else ""


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    """Collect ``CWE-n`` identifiers from ``weaknesses``; NVD placeholders (``NVD-CWE-*``) are skipped."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "").strip().upper() if isinstance(desc, dict) else ""
            if _CWE_RE.match(value) and value not in cwes:
                cwes.append(value)
    return cwes


def extract_references(cve: dict[str, Any], limit: int = MAX_REFERENCES) -> tuple[list[str], list[list[str]]]:
    """Return (urls, tags) for the first ``limit`` unique references that pass URL validation."""
    urls: list[str] = []
    tags: list[list[str]] = []
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        try:
            url = validate_public_url(str(ref.get("url") or ""))
        except UrlValidationError:
            continue
        if url in urls:
            continue
        urls.append(url)
        tags.append([sanitize_text(str(t), 40) for t in (ref.get("tags") or [])[:10] if t])
        if len(urls) >= limit:
            break
    return urls, tags


def _cpe_word(raw: str) -> str:
    text = _CPE_UNESCAPE_RE.sub(r"\1", raw).replace("_", " ").strip()
    if text in ("", "*", "-"):
        return ""
    return sanitize_text(text.title(), 80)


def cpe_to_product(criteria: Any) -> str | None:
    """Turn ``cpe:2.3:part:vendor:product:...`` into ``"Vendor Product"``; ``None`` when unusable."""
    if not isinstance(criteria, str):
        return None
    parts = _CPE_SPLIT_RE.split(criteria)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    product = _cpe_word(parts[4])
    if not product:
        return None
    vendor = _cpe_word(parts[3])
    return f"{vendor} {product}".strip()


def extract_products(cve: dict[str, Any], limit: int = MAX_PRODUCTS) -> list[str]:
    """Unique vendor/product labels from the vulnerable CPE matches in ``configurations``."""
    products: list[str] = []
    for config in cve.get("configurations") or []:
        nodes = config.get("nodes") if isinstance(config, dict) else None
        for node in nodes or []:
            matches = node.get("cpeMatch") if isinstance(node, dict) else None
            for match in matches or []:
                if not isinstance(match, dict) or match.get("vulnerable") is False:
                    continue
                label = cpe_to_product(match.get("criteria"))
                if label and label not in products:
                    products.append(label)
                    if len(products) >= limit:
                        return products
    return products


def _parse_day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value).strip())
    except (TypeError, ValueError):
        return None


def _day_in_window(day: date, ctx: FetchContext) -> bool:
    start_day = ctx.window_start.astimezone(timezone.utc).date()
    end_day = ctx.window_end.astimezone(timezone.utc).date()
    return start_day <= day <= end_day


def accept_cve(cve: dict[str, Any], ctx: FetchContext) -> bool:
    """Selection rule described in the module docstring."""
    if str(cve.get("vulnStatus") or "") in REJECTED_STATUSES:
        return False
    if in_window(parse_datetime(cve.get("published")), ctx):
        return True
    kev_added = _parse_day(cve.get("cisaExploitAdd"))
    return kev_added is not None and _day_in_window(kev_added, ctx)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _priority_key(item: RawItem) -> tuple[int, float, float]:
    """KEV-listed first, then highest CVSS, then most recently published."""
    kev_rank = 0 if item.extra.get("kev") else 1
    score = item.extra.get("cvss_score")
    score_value = float(score) if score is not None else -1.0
    published = item.published_at.timestamp() if item.published_at else float("-inf")
    return (kev_rank, -score_value, -published)


# ------------------------------------------------------------------ adapter


class NvdAdapter(SourceAdapter):
    """Incremental NVD API 2.0 client emitting one :class:`RawItem` per selected CVE."""

    def fetch(self, ctx: FetchContext) -> FetchResult:
        """Run the incremental query for ``ctx``'s window and return the selected CVEs; never raises."""
        started = time.monotonic()
        headers = {"apiKey": ctx.nvd_api_key} if ctx.nvd_api_key else None
        delay = DELAY_WITH_KEY if ctx.nvd_api_key else DELAY_WITHOUT_KEY
        try:
            records = self._collect(ctx, headers, delay)
        except Exception as exc:  # noqa: BLE001 - one broken source must never abort the run
            return self._failure(exc, started)
        items = self._select(records, ctx)
        status = self._status(True, "OK", items=len(items), started=started)
        return FetchResult(items=items, status=status, new_state=self._new_state(None, None, ctx))

    # ------------------------------------------------------------------ HTTP

    def _get(self, ctx: FetchContext, params: dict[str, str], headers: dict[str, str] | None) -> HttpResponse:
        return ctx.http.get(
            self.source.url,
            params=params,
            headers=headers,
            max_bytes=self.source.max_bytes,
            timeout_seconds=self.source.timeout_seconds,
        )

    def _request_page(self, ctx: FetchContext, params: dict[str, str], headers: dict[str, str] | None) -> HttpResponse:
        """GET one page, retrying once after :data:`RETRY_DELAY` on a retryable HTTP status."""
        try:
            return self._get(ctx, params, headers)
        except HttpStatusError as exc:
            if exc.status_code not in RETRY_STATUSES:
                raise
            log.info("%s: HTTP %d from NVD, retrying once after %.0fs", self.source.id, exc.status_code, RETRY_DELAY)
            _sleep(RETRY_DELAY)
            return self._get(ctx, params, headers)

    def _collect(self, ctx: FetchContext, headers: dict[str, str] | None, delay: float) -> dict[str, dict[str, Any]]:
        """Walk the paginated result set; returns ``cve id -> cve record`` (de-duplicated across pages)."""
        records: dict[str, dict[str, Any]] = {}
        start_index = 0
        exhausted = False
        for page in range(MAX_PAGES):
            if page:
                _sleep(delay)
            params = build_nvd_params(ctx.window_start, ctx.window_end, start_index)
            data = json.loads(self._request_page(ctx, params, headers).body)
            if not isinstance(data, dict):
                raise ValueError("NVD response is not a JSON object")
            vulnerabilities = data.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise ValueError("NVD response is missing the 'vulnerabilities' list")
            for wrapper in vulnerabilities:
                cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
                cve_id = str(cve.get("id") or "").strip().upper() if isinstance(cve, dict) else ""
                if not _CVE_RE.match(cve_id):
                    log.debug("%s: skipping record with malformed id %r", self.source.id, cve_id[:40])
                    continue
                records[cve_id] = cve
            total = _as_int(data.get("totalResults"), 0)
            per_page = _as_int(data.get("resultsPerPage"), len(vulnerabilities))
            next_index = _as_int(data.get("startIndex"), start_index) + per_page
            log.debug("%s: page %d fetched %d records (%d/%d)", self.source.id, page + 1, len(vulnerabilities), next_index, total)
            if not vulnerabilities or per_page <= 0 or next_index >= total:
                exhausted = True
                break
            start_index = next_index
        if not exhausted:
            log.warning("%s: stopped after %d pages with more results pending (%d fetched)", self.source.id, MAX_PAGES, len(records))
        return records

    # ------------------------------------------------------------------ selection

    def _select(self, records: dict[str, dict[str, Any]], ctx: FetchContext) -> list[RawItem]:
        items: list[RawItem] = []
        for cve_id, cve in records.items():
            if not accept_cve(cve, ctx):
                continue
            try:
                items.append(self.cve_to_item(cve, ctx))
            except Exception as exc:  # noqa: BLE001 - skip a malformed record, keep the rest
                log.debug("%s: skipping %s: %s", self.source.id, cve_id, exc)
        items.sort(key=_priority_key)
        limit = self.source.max_items
        if len(items) > limit:
            log.info("%s: %d CVEs selected from %d records, keeping top %d (dropped %d)", self.source.id, len(items), len(records), limit, len(items) - limit)
            items = items[:limit]
        else:
            log.info("%s: %d CVEs selected from %d records", self.source.id, len(items), len(records))
        return items

    def cve_to_item(self, cve: dict[str, Any], ctx: FetchContext) -> RawItem:
        """Convert one NVD CVE record into a :class:`RawItem`."""
        cve_id = str(cve["id"]).strip().upper()
        description = english_description(cve)
        cvss = select_cvss(cve.get("metrics"))
        headline = " ".join(sanitize_text(description, TITLE_DESCRIPTION_MAX).split()) or "no description provided"
        title = f"{cve_id}: {headline}"
        if cvss is not None:
            title += f" (CVSS {cvss.score:.1f}{' ' + cvss.severity if cvss.severity else ''})"
        references, reference_tags = extract_references(cve)
        published = parse_datetime(cve.get("published"))
        updated = parse_datetime(cve.get("lastModified"))
        if updated and published and updated < published:
            updated = None

        kev: dict[str, Any] | None = None
        kev_added = _parse_day(cve.get("cisaExploitAdd"))
        if kev_added is not None:
            due = _parse_day(cve.get("cisaActionDue"))
            kev = {
                "date_added": kev_added.isoformat(),
                "due_date": due.isoformat() if due else None,
                "required_action": sanitize_text(str(cve.get("cisaRequiredAction") or ""), 600),
                "vulnerability_name": sanitize_text(str(cve.get("cisaVulnerabilityName") or ""), 240),
            }

        extra: dict[str, Any] = {
            "publisher": PUBLISHER,
            "cve_ids": [cve_id],
            "cvss_score": cvss.score if cvss else None,
            "cvss_severity": cvss.severity if cvss else None,
            "cvss_vector": cvss.vector if cvss else None,
            "cwes": extract_cwes(cve),
            "references": references,
            "reference_tags": reference_tags,
            "products": extract_products(cve),
            "kev": kev,
            "exploitation_hint": "active" if kev else None,
            "vuln_status": sanitize_text(str(cve.get("vulnStatus") or ""), 40) or None,
        }
        return self.base_item(
            external_id=cve_id,
            title=title,
            url=NVD_DETAIL_URL.format(cve=cve_id),
            summary=sanitize_text(description, SUMMARY_MAX),
            published_at=published,
            updated_at=updated,
            fetched_at=ctx.now,
            extra=extra,
        )
