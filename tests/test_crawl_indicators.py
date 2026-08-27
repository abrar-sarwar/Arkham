from __future__ import annotations

from arkham.crawl.indicators import extract_indicators

URL = "https://research.example.org/report"


def _pairs(text: str) -> set[tuple[str, str]]:
    return {(item.type, item.value) for item in extract_indicators(text, URL)}


def test_extracts_cti_artifact_candidates_without_malicious_verdicts() -> None:
    sha256 = "a" * 64
    sha1 = "b" * 40
    md5 = "c" * 32
    text = (
        "CISA KEV lists CVE-2026-12345 (CWE-787). APT29 and UNC2452 used T1059.001 with FogRAT malware. "
        "The GHSA-abcd-1234-efgh advisory links a proof-of-concept exploit. "
        "Observed indicators include C2 IP 203.0.113.42, C2 IPv6 2001:db8::5, domain evil.example, "
        "URL https://evil.example/payload and contact analyst@example.org. "
        f"Hashes: {sha256} {sha1} {md5}. Microsoft Exchange Server version 15.2.1118.7 is affected."
    )
    pairs = _pairs(text)
    expected = {
        ("cve", "CVE-2026-12345"),
        ("cwe", "CWE-787"),
        ("attack", "T1059.001"),
        ("ghsa", "GHSA-ABCD-1234-EFGH"),
        ("actor", "APT29"),
        ("actor", "UNC2452"),
        ("malware", "FogRAT"),
        ("ipv4", "203.0.113.42"),
        ("ipv6", "2001:db8::5"),
        ("domain", "evil.example"),
        ("url", "https://evil.example/payload"),
        ("email", "analyst@example.org"),
        ("sha256", sha256),
        ("sha1", sha1),
        ("md5", md5),
        ("vendor_product", "Microsoft Exchange Server"),
        ("version", "15.2.1118.7"),
        ("kev_reference", "CISA KEV"),
        ("exploit_reference", "proof-of-concept exploit"),
    }
    assert expected <= pairs
    assert all(item.source_url == URL and len(item.context) <= 300 for item in extract_indicators(text, URL))


def test_indicator_extraction_avoids_version_and_source_domain_false_positives() -> None:
    pairs = _pairs(
        "Version 10.2.3.4 fixes the issue. The report is hosted at research.example.org. "
        "Ordinary prose says example.com without calling it an indicator."
    )
    assert ("ipv4", "10.2.3.4") not in pairs
    assert ("domain", "research.example.org") not in pairs
    assert ("domain", "example.com") not in pairs

