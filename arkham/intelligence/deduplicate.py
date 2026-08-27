"""Conservative cross-publisher event correlation and deduplication."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from arkham.models import CyberEvent, EventType, KevStatus, SourceRef, sha256_hex
from arkham.security.urls import canonicalize_url

_WORD_RE = re.compile(r"[a-z0-9]{3,}")
_STOP = {
    "about",
    "after",
    "against",
    "from",
    "into",
    "security",
    "the",
    "this",
    "with",
    "vulnerability",
}
_TYPE_PRIORITY = {
    EventType.EXPLOITATION: 0,
    EventType.INCIDENT: 1,
    EventType.THREAT_ACTIVITY: 2,
    EventType.VULNERABILITY: 3,
    EventType.ADVISORY: 4,
    EventType.RESEARCH: 5,
    EventType.POLICY: 6,
    EventType.OTHER: 7,
}


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[b] = a


def _urls(event: CyberEvent) -> set[str]:
    values = [event.source_url, event.primary_source_url, *event.referenced_urls]
    values.extend(ref.url for ref in event.corroborating_sources)
    return {canonicalize_url(value) for value in values if value}


def _tokens(title: str) -> set[str]:
    return {word for word in _WORD_RE.findall(title.casefold()) if word not in _STOP}


def _near(left: CyberEvent, right: CyberEvent) -> bool:
    times_left = [value for value in (left.published_at, left.updated_at) if value]
    times_right = [value for value in (right.published_at, right.updated_at) if value]
    if not times_left or not times_right:
        return True
    return abs(max(times_left) - max(times_right)) <= timedelta(days=3)


def _similar(left: CyberEvent, right: CyberEvent) -> bool:
    if set(left.cves) & set(right.cves):
        return True
    if _urls(left) & _urls(right):
        return True
    if not _near(left, right):
        return False
    left_tokens, right_tokens = _tokens(left.title), _tokens(right.title)
    if not left_tokens or not right_tokens:
        return False
    similarity = len(left_tokens & right_tokens) / len(left_tokens | right_tokens)
    if similarity >= 0.9:
        return True
    shared_entities = (
        {value.casefold() for value in left.products + left.organizations + left.malware_families}
        & {value.casefold() for value in right.products + right.organizations + right.malware_families}
    )
    return bool(shared_entities) and similarity >= 0.65


def _source_ref(event: CyberEvent) -> SourceRef:
    return SourceRef(
        source_id="",
        source_name=event.source_name,
        source_tier=event.source_tier,
        url=event.source_url,
        title=event.title,
        published_at=event.published_at,
        publisher=event.publisher,
    )


def _merge_text(target: list[str], values: list[str], *, limit: int = 40) -> None:
    known = {value.casefold() for value in target}
    for value in values:
        if value and value.casefold() not in known:
            target.append(value)
            known.add(value.casefold())
        if len(target) >= limit:
            break


def _primary_key(event: CyberEvent) -> tuple[int, int, float]:
    times = [value.timestamp() for value in (event.updated_at, event.published_at) if value]
    return int(event.source_tier), _TYPE_PRIORITY[event.event_type], -(max(times) if times else 0.0)


def _cluster_id(event: CyberEvent) -> str:
    if event.cves:
        return sha256_hex("cve", min(event.cves).casefold())
    return sha256_hex("url", canonicalize_url(event.primary_source_url or event.source_url))


def _merge_cluster(cluster: list[CyberEvent]) -> CyberEvent:
    primary = min(cluster, key=_primary_key).model_copy(deep=True)
    refs: list[SourceRef] = []
    for event in cluster:
        candidates = [*event.corroborating_sources]
        if not any(canonicalize_url(ref.url) == canonicalize_url(event.source_url) for ref in candidates):
            candidates.append(_source_ref(event))
        for ref in candidates:
            canonical = canonicalize_url(ref.url)
            if not any(canonicalize_url(existing.url) == canonical for existing in refs):
                refs.append(ref.model_copy(deep=True))
        for field in (
            "cves",
            "cwes",
            "products",
            "countries",
            "regions",
            "sectors",
            "organizations",
            "threat_actors",
            "malware_families",
            "referenced_urls",
            "keywords",
            "member_hashes",
        ):
            _merge_text(getattr(primary, field), list(getattr(event, field)))
        primary.event_type = min((primary.event_type, event.event_type), key=lambda value: _TYPE_PRIORITY[value])
        primary.exploitation_status = max(
            (primary.exploitation_status, event.exploitation_status), key=lambda value: value.rank
        )
        primary.kev_status = max(
            (primary.kev_status, event.kev_status),
            key=lambda value: {KevStatus.NOT_LISTED: 0, KevStatus.LISTED: 1, KevStatus.NEWLY_ADDED: 2}[value],
        )
        primary.poc_public = primary.poc_public or event.poc_public
        primary.zero_day = primary.zero_day or event.zero_day
        primary.injection_flagged = primary.injection_flagged or event.injection_flagged
        if primary.cvss_score is None or (event.cvss_score is not None and event.cvss_score > primary.cvss_score):
            primary.cvss_score = event.cvss_score
            primary.cvss_severity = event.cvss_severity
        times = [value for value in (primary.published_at, event.published_at) if value]
        primary.published_at = max(times) if times else None
        updated = [value for value in (primary.updated_at, event.updated_at) if value]
        primary.updated_at = max(updated) if updated else None
        if not primary.summary and event.summary:
            primary.summary = event.summary
        if primary.primary_source_url is None and event.primary_source_url:
            primary.primary_source_url = event.primary_source_url
    primary.corroborating_sources = refs
    primary.id = _cluster_id(primary)
    primary.raw_hash = sha256_hex(*(sorted(primary.member_hashes) or [primary.id]))
    return primary


def deduplicate(events: list[CyberEvent], *, now: datetime) -> list[CyberEvent]:
    """Cluster conservative equivalences; actor names alone never cause a merge."""
    del now  # reserved for future time-decay tuning; event timestamps drive the current guard
    uf = _UnionFind(len(events))
    for left in range(len(events)):
        for right in range(left + 1, len(events)):
            if _similar(events[left], events[right]):
                uf.union(left, right)
    clusters: dict[int, list[CyberEvent]] = {}
    for index, event in enumerate(events):
        clusters.setdefault(uf.find(index), []).append(event)
    merged = [_merge_cluster(cluster) for cluster in clusters.values()]
    return sorted(
        merged,
        key=lambda event: max(
            (value.timestamp() for value in (event.updated_at, event.published_at) if value),
            default=0.0,
        ),
        reverse=True,
    )
