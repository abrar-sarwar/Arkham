"""Declarative registry of every source Arkham collects from, plus lazy adapter construction.

Every entry below was verified live on 2026-08-26. Adapters are referenced as ``"module:Class"``
strings and imported only when :func:`build_adapter` is called, so a missing or broken adapter
module breaks just the sources that use it — never the registry or the rest of the run.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable

from arkham.models import Region, SourceCategory, SourceTier
from arkham.security.urls import UrlValidationError, validate_public_url
from arkham.sources.base import Source, SourceAdapter

VERIFIED_ON = "2026-08-26"

#: Adapter registry key -> ``"module:Class"``. Keys are what :attr:`Source.adapter` refers to.
ADAPTER_PATHS: dict[str, str] = {
    "rss": "arkham.sources.rss:RssAdapter",
    "cisa_kev": "arkham.sources.cisa:CisaKevAdapter",
    "nvd": "arkham.sources.nvd:NvdAdapter",
    "cert_eu": "arkham.sources.cert_eu:CertEuAdapter",
    "ncsc": "arkham.sources.ncsc:NcscAdapter",
    "google_threat_intel": "arkham.sources.google_threat_intel:GoogleThreatIntelAdapter",
    "msrc_update_guide": "arkham.sources.microsoft:MsrcUpdateGuideAdapter",
    "certcc": "arkham.sources.certcc:CertCcAdapter",
}

_REGION_VALUES = frozenset(r.value for r in Region)
_US = [Region.US.value]
_EU = [Region.EU.value]
_UK = [Region.UK.value]


class RegistryError(Exception):
    """An inconsistent registry entry, or an adapter that cannot be resolved/constructed for a source."""


def _source(
    source_id: str,
    name: str,
    *,
    tier: SourceTier,
    category: SourceCategory,
    url: str,
    publisher: str,
    type: str = "rss",  # noqa: A002 - mirrors the Source field name
    adapter: str = "rss",
    enabled: bool = True,
    max_bytes: int | None = None,
    timeout_seconds: float | None = None,
    regions: list[str] | None = None,
    notes: str = "",
    max_items: int = 200,
) -> Source:
    return Source(
        id=source_id,
        name=name,
        type=type,
        tier=tier,
        category=category,
        url=url,
        enabled=enabled,
        adapter=adapter,
        publisher=publisher,
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
        regions=list(regions or []),
        notes=notes,
        max_items=max_items,
    )


_VULN = SourceCategory.VULNERABILITY
_ADV = SourceCategory.ADVISORY
_TI = SourceCategory.THREAT_INTEL
_RES = SourceCategory.RESEARCH
_NEWS = SourceCategory.NEWS
_T1 = SourceTier.PRIMARY
_T2 = SourceTier.RESEARCH
_T3 = SourceTier.JOURNALISM

# ------------------------------------------------------------------ Tier 1: primary / authoritative
_TIER1: list[Source] = [
    _source(
        "cisa-kev",
        "CISA Known Exploited Vulnerabilities",
        tier=_T1,
        category=_VULN,
        type="json",
        adapter="cisa_kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        publisher="CISA",
        max_bytes=12_000_000,
        regions=_US,
    ),
    _source(
        "cisa-advisories",
        "CISA Cybersecurity Advisories",
        tier=_T1,
        category=_ADV,
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        publisher="CISA",
        regions=_US,
        enabled=False,
        notes="official feed returns HTTP 403 to Arkham/httpx clients; KEV remains enabled",
    ),
    _source(
        "cisa-alerts",
        "CISA Alerts",
        tier=_T1,
        category=_ADV,
        url="https://www.cisa.gov/cybersecurity-advisories/alerts.xml",
        publisher="CISA",
        regions=_US,
        enabled=False,
        notes="official feed returns HTTP 403 to Arkham/httpx clients; KEV remains enabled",
    ),
    _source(
        "nvd",
        "NIST National Vulnerability Database",
        tier=_T1,
        category=_VULN,
        type="api",
        adapter="nvd",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        publisher="NVD",
        max_bytes=30_000_000,
        timeout_seconds=60,
    ),
    _source(
        "cert-eu-advisories",
        "CERT-EU Security Advisories",
        tier=_T1,
        category=_ADV,
        adapter="cert_eu",
        url="https://cert.europa.eu/publications/security-advisories-rss",
        publisher="CERT-EU",
        regions=_EU,
    ),
    _source(
        "cert-eu-threat-intel",
        "CERT-EU Threat Intelligence",
        tier=_T1,
        category=_TI,
        adapter="cert_eu",
        url="https://cert.europa.eu/publications/threat-intelligence-rss",
        publisher="CERT-EU",
        regions=_EU,
    ),
    _source(
        "ncsc-all",
        "UK NCSC Publications",
        tier=_T1,
        category=_ADV,
        adapter="ncsc",
        url="https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        publisher="NCSC",
        regions=_UK,
    ),
    _source(
        "ncsc-reports",
        "UK NCSC Threat Reports",
        tier=_T1,
        category=_TI,
        adapter="ncsc",
        url="https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        publisher="NCSC",
        regions=_UK,
    ),
    _source(
        "ncsc-news",
        "UK NCSC News",
        tier=_T1,
        category=_NEWS,
        adapter="ncsc",
        url="https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        publisher="NCSC",
        regions=_UK,
        enabled=False,
        notes="overlaps ncsc-all",
    ),
    _source(
        "msrc-update-guide",
        "Microsoft Security Response Center Update Guide",
        tier=_T1,
        category=_VULN,
        adapter="msrc_update_guide",
        url="https://api.msrc.microsoft.com/update-guide/rss",
        publisher="Microsoft",
        max_bytes=12_000_000,
        max_items=6000,
    ),
    _source(
        "certcc",
        "CERT/CC Vulnerability Notes",
        tier=_T1,
        category=_ADV,
        type="atom",
        adapter="certcc",
        url="https://kb.cert.org/vuls/atomfeed/",
        publisher="CERT/CC",
        regions=_US,
    ),
]

# ------------------------------------------------------------- Tier 2: vendor research / threat intel
_TIER2: list[Source] = [
    _source(
        "google-threat-intel",
        "Google Threat Intelligence Group",
        tier=_T2,
        category=_TI,
        adapter="google_threat_intel",
        url="https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        publisher="Google",
        max_bytes=8_000_000,
    ),
    _source(
        "microsoft-security-blog",
        "Microsoft Security Blog",
        tier=_T2,
        category=_TI,
        url="https://www.microsoft.com/en-us/security/blog/feed/",
        publisher="Microsoft",
    ),
    _source(
        "cisco-talos",
        "Cisco Talos Intelligence",
        tier=_T2,
        category=_TI,
        url="https://blog.talosintelligence.com/rss/",
        publisher="Talos",
        max_bytes=8_000_000,
    ),
    _source(
        "unit42",
        "Palo Alto Networks Unit 42",
        tier=_T2,
        category=_TI,
        url="https://unit42.paloaltonetworks.com/feed/",
        publisher="Unit 42",
    ),
    _source(
        "sentinellabs",
        "SentinelLabs",
        tier=_T2,
        category=_RES,
        url="https://www.sentinelone.com/labs/feed/",
        publisher="SentinelLabs",
    ),
    _source(
        "eset-research",
        "ESET WeLiveSecurity",
        tier=_T2,
        category=_RES,
        url="https://www.welivesecurity.com/en/rss/feed/",
        publisher="ESET",
    ),
    _source(
        "crowdstrike-blog",
        "CrowdStrike Blog",
        tier=_T2,
        category=_RES,
        url="https://www.crowdstrike.com/blog/feed/",
        publisher="CrowdStrike",
    ),
    _source(
        "cloudflare-security",
        "Cloudflare Blog (Security)",
        tier=_T2,
        category=_RES,
        url="https://blog.cloudflare.com/tag/security/rss/",
        publisher="Cloudflare",
    ),
    _source(
        "github-security",
        "GitHub Blog (Security)",
        tier=_T2,
        category=_RES,
        url="https://github.blog/security/feed/",
        publisher="GitHub",
    ),
    _source(
        "google-security-blog",
        "Google Online Security Blog",
        tier=_T2,
        category=_RES,
        url="https://feeds.feedburner.com/GoogleOnlineSecurityBlog",
        publisher="Google",
    ),
    _source(
        "project-zero",
        "Google Project Zero",
        tier=_T2,
        category=_RES,
        type="atom",
        url="https://googleprojectzero.blogspot.com/feeds/posts/default",
        publisher="Google Project Zero",
        enabled=False,
        max_bytes=16_000_000,
        notes="feed is ~13 MB per fetch; enable if desired",
    ),
    _source(
        "sophos-news",
        "Sophos News",
        tier=_T2,
        category=_RES,
        url="https://www.sophos.com/blog/en-us/feed/",
        publisher="Sophos",
        enabled=False,
        notes="host refused connections during verification on 2026-08-26",
    ),
]

# ------------------------------------------------------------------------- Tier 3: journalism
_TIER3: list[Source] = [
    _source(
        "bleepingcomputer",
        "BleepingComputer",
        tier=_T3,
        category=_NEWS,
        url="https://www.bleepingcomputer.com/feed/",
        publisher="BleepingComputer",
    ),
    _source(
        "the-record",
        "The Record (Recorded Future News)",
        tier=_T3,
        category=_NEWS,
        url="https://therecord.media/feed",
        publisher="The Record",
    ),
    _source(
        "securityweek",
        "SecurityWeek",
        tier=_T3,
        category=_NEWS,
        url="https://feeds.feedburner.com/securityweek",
        publisher="SecurityWeek",
    ),
    _source(
        "krebs-on-security",
        "Krebs on Security",
        tier=_T3,
        category=_NEWS,
        url="https://krebsonsecurity.com/feed/",
        publisher="Krebs on Security",
    ),
    _source(
        "the-hacker-news",
        "The Hacker News",
        tier=_T3,
        category=_NEWS,
        url="https://feeds.feedburner.com/TheHackersNews",
        publisher="The Hacker News",
    ),
]

SOURCES: tuple[Source, ...] = tuple(_TIER1 + _TIER2 + _TIER3)


# ------------------------------------------------------------------------------ validation


def validate_sources(sources: Iterable[Source]) -> None:
    """Raise :class:`RegistryError` unless ids are unique, URLs are public https, adapters and regions are known."""
    problems: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source.id in seen:
            problems.append(f"duplicate source id {source.id!r}")
        seen.add(source.id)
        try:
            validate_public_url(source.url)
        except UrlValidationError as exc:
            problems.append(f"{source.id}: invalid url {source.url!r}: {exc}")
        if source.adapter not in ADAPTER_PATHS:
            problems.append(f"{source.id}: unknown adapter key {source.adapter!r}")
        for region in source.regions:
            if region not in _REGION_VALUES:
                problems.append(f"{source.id}: unknown region {region!r}")
    if problems:
        raise RegistryError("invalid source registry:\n  - " + "\n  - ".join(problems))


validate_sources(SOURCES)
_BY_ID: dict[str, Source] = {s.id: s for s in SOURCES}


# --------------------------------------------------------------------------------- lookups


def all_sources() -> list[Source]:
    """Every registered source, in tier order, as independent copies (mutating them never touches the registry)."""
    return [s.model_copy(deep=True) for s in SOURCES]


def get_source(source_id: str) -> Source:
    """Return a copy of one source by id; raise :class:`KeyError` when the id is unknown."""
    try:
        source = _BY_ID[source_id]
    except KeyError:
        raise KeyError(f"unknown source id {source_id!r}") from None
    return source.model_copy(deep=True)


def enabled_sources(disabled: Iterable[str] = ()) -> list[Source]:
    """Sources flagged enabled in the registry minus any ids listed in ``disabled`` (unknown ids are ignored)."""
    off = set(disabled)
    return [s for s in all_sources() if s.enabled and s.id not in off]


# ---------------------------------------------------------------------------- adapter loading


def build_adapter(source: Source) -> SourceAdapter:
    """Instantiate the adapter for ``source`` by lazily importing its ``module:Class`` path.

    Any problem (unknown key, missing module, missing class, wrong type, constructor failure) is raised
    as :class:`RegistryError` with a message naming the source, so callers can fail that source alone.
    """
    path = ADAPTER_PATHS.get(source.adapter)
    if path is None:
        known = ", ".join(sorted(ADAPTER_PATHS))
        raise RegistryError(
            f"source {source.id!r}: unknown adapter key {source.adapter!r} (known keys: {known})"
        )
    module_name, _, class_name = path.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # ImportError, or anything the module raises while importing
        raise RegistryError(
            f"source {source.id!r}: adapter module {module_name!r} could not be imported: {exc.__class__.__name__}: {exc}"
        ) from exc
    cls = getattr(module, class_name, None)
    if cls is None:
        raise RegistryError(
            f"source {source.id!r}: adapter module {module_name!r} has no attribute {class_name!r}"
        )
    if not (isinstance(cls, type) and issubclass(cls, SourceAdapter)):
        raise RegistryError(f"source {source.id!r}: {path!r} is not a SourceAdapter subclass")
    try:
        return cls(source)
    except Exception as exc:
        raise RegistryError(
            f"source {source.id!r}: adapter {path!r} could not be constructed: {exc.__class__.__name__}: {exc}"
        ) from exc
