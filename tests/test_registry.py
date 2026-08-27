"""Tests for the declarative source registry and lazy adapter construction."""

from __future__ import annotations

import pytest

from arkham.models import Region, SourceCategory, SourceTier
from arkham.security.urls import validate_public_url
from arkham.sources import registry
from arkham.sources.base import Source, SourceAdapter
from arkham.sources.registry import (
    ADAPTER_PATHS,
    RegistryError,
    all_sources,
    build_adapter,
    enabled_sources,
    get_source,
)
from arkham.sources.rss import RssAdapter

EXPECTED_ADAPTER_PATHS = {
    "rss": "arkham.sources.rss:RssAdapter",
    "cisa_kev": "arkham.sources.cisa:CisaKevAdapter",
    "nvd": "arkham.sources.nvd:NvdAdapter",
    "cert_eu": "arkham.sources.cert_eu:CertEuAdapter",
    "ncsc": "arkham.sources.ncsc:NcscAdapter",
    "google_threat_intel": "arkham.sources.google_threat_intel:GoogleThreatIntelAdapter",
    "msrc_update_guide": "arkham.sources.microsoft:MsrcUpdateGuideAdapter",
    "certcc": "arkham.sources.certcc:CertCcAdapter",
}

TIER1_IDS = [
    "cisa-kev",
    "cisa-advisories",
    "cisa-alerts",
    "nvd",
    "cert-eu-advisories",
    "cert-eu-threat-intel",
    "ncsc-all",
    "ncsc-reports",
    "ncsc-news",
    "msrc-update-guide",
    "certcc",
]
TIER2_IDS = [
    "google-threat-intel",
    "microsoft-security-blog",
    "cisco-talos",
    "unit42",
    "sentinellabs",
    "eset-research",
    "crowdstrike-blog",
    "cloudflare-security",
    "github-security",
    "google-security-blog",
    "project-zero",
    "sophos-news",
]
TIER3_IDS = ["bleepingcomputer", "the-record", "securityweek", "krebs-on-security", "the-hacker-news"]


# ------------------------------------------------------------------------------- invariants


def test_registry_ids_are_unique() -> None:
    ids = [s.id for s in all_sources()]
    assert len(ids) == len(set(ids))


def test_every_source_url_passes_public_url_validation() -> None:
    for source in all_sources():
        assert validate_public_url(source.url) == source.url, source.id
        assert source.url.startswith("https://"), source.id


def test_registry_order_and_membership() -> None:
    assert [s.id for s in all_sources()] == TIER1_IDS + TIER2_IDS + TIER3_IDS
    tiers = [int(s.tier) for s in all_sources()]
    assert tiers == sorted(tiers)


def test_every_source_has_identity_fields() -> None:
    for source in all_sources():
        assert source.name.strip(), source.id
        assert source.publisher.strip(), source.id
        assert source.type in {"json", "rss", "atom", "api"}, source.id
        assert source.max_items >= 1, source.id
        assert isinstance(source, Source)


def test_every_source_adapter_key_is_registered() -> None:
    for source in all_sources():
        assert source.adapter in ADAPTER_PATHS, f"{source.id} uses unknown adapter {source.adapter!r}"


def test_regions_use_the_region_vocabulary() -> None:
    allowed = {r.value for r in Region}
    for source in all_sources():
        for region in source.regions:
            assert region in allowed, f"{source.id}: {region!r}"


def test_adapter_paths_match_build_brief_exactly() -> None:
    assert ADAPTER_PATHS == EXPECTED_ADAPTER_PATHS
    for path in ADAPTER_PATHS.values():
        module, sep, cls = path.partition(":")
        assert sep == ":" and module.startswith("arkham.sources.") and cls


# ------------------------------------------------------------------------- tier 1 details


def test_cisa_kev_source_is_fully_specified() -> None:
    kev = get_source("cisa-kev")
    assert kev.name == "CISA Known Exploited Vulnerabilities"
    assert kev.type == "json"
    assert kev.tier is SourceTier.PRIMARY
    assert kev.category is SourceCategory.VULNERABILITY
    assert kev.url == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    assert kev.adapter == "cisa_kev"
    assert kev.publisher == "CISA"
    assert kev.max_bytes == 12_000_000
    assert kev.regions == ["US"]
    assert kev.enabled is True


def test_tier1_adapters_and_limits() -> None:
    nvd = get_source("nvd")
    assert nvd.type == "api" and nvd.adapter == "nvd" and nvd.publisher == "NVD"
    assert nvd.max_bytes == 30_000_000 and nvd.timeout_seconds == 60
    assert nvd.url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert nvd.regions == []

    msrc = get_source("msrc-update-guide")
    assert msrc.adapter == "msrc_update_guide" and msrc.publisher == "Microsoft"
    assert msrc.max_bytes == 12_000_000 and msrc.max_items == 6000
    assert msrc.category is SourceCategory.VULNERABILITY

    certcc = get_source("certcc")
    assert certcc.type == "atom" and certcc.adapter == "certcc" and certcc.publisher == "CERT/CC"
    assert certcc.regions == ["US"] and certcc.category is SourceCategory.ADVISORY

    for sid in ("cisa-advisories", "cisa-alerts"):
        s = get_source(sid)
        assert s.adapter == "rss" and s.publisher == "CISA" and s.category is SourceCategory.ADVISORY
        assert s.regions == ["US"]
    for sid, category in (
        ("cert-eu-advisories", SourceCategory.ADVISORY),
        ("cert-eu-threat-intel", SourceCategory.THREAT_INTEL),
    ):
        s = get_source(sid)
        assert s.adapter == "cert_eu" and s.publisher == "CERT-EU" and s.regions == ["EU"]
        assert s.category is category
    for sid, category in (
        ("ncsc-all", SourceCategory.ADVISORY),
        ("ncsc-reports", SourceCategory.THREAT_INTEL),
        ("ncsc-news", SourceCategory.NEWS),
    ):
        s = get_source(sid)
        assert s.adapter == "ncsc" and s.publisher == "NCSC" and s.regions == ["UK"]
        assert s.category is category
    assert get_source("ncsc-news").enabled is False
    assert "overlaps ncsc-all" in get_source("ncsc-news").notes
    for sid in TIER1_IDS:
        assert get_source(sid).tier is SourceTier.PRIMARY


# ------------------------------------------------------------------------- tier 2 / 3 details


def test_tier2_sources() -> None:
    for sid in TIER2_IDS:
        s = get_source(sid)
        assert s.tier is SourceTier.RESEARCH, sid
        assert s.category in (SourceCategory.THREAT_INTEL, SourceCategory.RESEARCH), sid
        if sid != "google-threat-intel":
            assert s.adapter == "rss", sid
    gtig = get_source("google-threat-intel")
    assert (
        gtig.adapter == "google_threat_intel" and gtig.publisher == "Google" and gtig.max_bytes == 8_000_000
    )
    assert gtig.url == "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"
    assert get_source("cisco-talos").max_bytes == 8_000_000
    assert get_source("cisco-talos").publisher == "Talos"
    assert get_source("unit42").publisher == "Unit 42"
    assert get_source("unit42").url == "https://unit42.paloaltonetworks.com/feed/"
    for sid in ("google-threat-intel", "microsoft-security-blog", "cisco-talos", "unit42"):
        assert get_source(sid).category is SourceCategory.THREAT_INTEL
    pz = get_source("project-zero")
    assert pz.type == "atom" and pz.enabled is False and pz.max_bytes == 16_000_000
    assert "13 MB" in pz.notes
    sophos = get_source("sophos-news")
    assert sophos.enabled is False and "2026-08-26" in sophos.notes


def test_tier3_sources_are_journalism_news_over_rss() -> None:
    for sid in TIER3_IDS:
        s = get_source(sid)
        assert s.tier is SourceTier.JOURNALISM, sid
        assert s.category is SourceCategory.NEWS, sid
        assert s.adapter == "rss" and s.type == "rss", sid
        assert s.enabled is True, sid
    assert get_source("bleepingcomputer").url == "https://www.bleepingcomputer.com/feed/"
    assert get_source("the-record").name == "The Record (Recorded Future News)"
    assert get_source("krebs-on-security").publisher == "Krebs on Security"


# --------------------------------------------------------------------------------- lookups


def test_get_source_unknown_raises_key_error() -> None:
    with pytest.raises(KeyError):
        get_source("does-not-exist")


def test_all_sources_returns_independent_copies() -> None:
    first = all_sources()
    first[0].enabled = False
    first[0].notes = "mutated"
    fresh = get_source(first[0].id)
    assert fresh.enabled is True
    assert fresh.notes != "mutated"
    assert all_sources() is not first


def test_enabled_sources_skips_flagged_off_sources() -> None:
    ids = {s.id for s in enabled_sources()}
    assert "cisa-kev" in ids and "unit42" in ids and "bleepingcomputer" in ids
    assert "ncsc-news" not in ids
    assert "project-zero" not in ids
    assert "sophos-news" not in ids
    assert "cisa-advisories" not in ids
    assert "cisa-alerts" not in ids
    assert len(ids) == len(all_sources()) - 5


def test_enabled_sources_honours_disabled_argument() -> None:
    ids = [s.id for s in enabled_sources(disabled=("cisa-kev", "unit42", "not-a-source"))]
    assert "cisa-kev" not in ids and "unit42" not in ids
    assert "nvd" in ids
    assert ids == [s.id for s in all_sources() if s.enabled and s.id not in {"cisa-kev", "unit42"}]
    assert enabled_sources(disabled=iter(["the-record"])) == [
        s for s in enabled_sources() if s.id != "the-record"
    ]


# ------------------------------------------------------------------------------ build_adapter


def test_build_adapter_returns_rss_adapter_for_generic_feeds() -> None:
    for sid in ("unit42", "bleepingcomputer", "cisa-advisories"):
        adapter = build_adapter(get_source(sid))
        assert isinstance(adapter, RssAdapter)
        assert isinstance(adapter, SourceAdapter)
        assert adapter.source.id == sid


def test_build_adapter_unknown_key_raises_registry_error() -> None:
    source = get_source("unit42").model_copy(update={"adapter": "no_such_adapter"})
    with pytest.raises(RegistryError, match="no_such_adapter"):
        build_adapter(source)


def test_build_adapter_missing_module_raises_registry_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(registry.ADAPTER_PATHS, "broken", "arkham.sources.definitely_missing_module:Adapter")
    source = get_source("unit42").model_copy(update={"adapter": "broken"})
    with pytest.raises(RegistryError, match="definitely_missing_module"):
        build_adapter(source)
    # A missing module for one adapter never affects another source.
    assert isinstance(build_adapter(get_source("bleepingcomputer")), RssAdapter)


def test_build_adapter_missing_class_raises_registry_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(registry.ADAPTER_PATHS, "broken", "arkham.sources.rss:NoSuchAdapter")
    source = get_source("unit42").model_copy(update={"adapter": "broken"})
    with pytest.raises(RegistryError, match="NoSuchAdapter"):
        build_adapter(source)


def test_build_adapter_rejects_non_adapter_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(registry.ADAPTER_PATHS, "broken", "arkham.sources.rss:extract_links")
    source = get_source("unit42").model_copy(update={"adapter": "broken"})
    with pytest.raises(RegistryError, match="SourceAdapter"):
        build_adapter(source)


def test_validate_registry_rejects_duplicate_ids_and_bad_urls() -> None:
    base = get_source("unit42")
    with pytest.raises(RegistryError, match="duplicate"):
        registry.validate_sources([base, base.model_copy()])
    bad_url = base.model_copy(update={"id": "bad", "url": "http://unit42.paloaltonetworks.com/feed/"})
    with pytest.raises(RegistryError, match="bad"):
        registry.validate_sources([base, bad_url])
    bad_adapter = base.model_copy(update={"id": "bad", "adapter": "nope"})
    with pytest.raises(RegistryError, match="nope"):
        registry.validate_sources([base, bad_adapter])
    bad_region = base.model_copy(update={"id": "bad", "regions": ["Mars"]})
    with pytest.raises(RegistryError, match="Mars"):
        registry.validate_sources([base, bad_region])
    registry.validate_sources(all_sources())  # the shipped registry is valid
