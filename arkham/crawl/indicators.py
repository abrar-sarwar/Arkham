"""Deterministic CTI artifact candidates from extracted text.

Everything here is offline, regex/stdlib based and repeatable. A candidate is an *observation*
("this looks like a CVE id / hash / domain"), never a maliciousness verdict — that judgement is
left to the analyst layers. Defanged spellings (``hxxp://``, ``evil[.]example``, ``1[.]2[.]3[.]4``,
``[:]``, ``[@]``) are refanged before matching so the recorded ``value`` is the normalised form;
the ``context`` of such a candidate is prefixed with ``defanged:`` so the transformation is
explicit.

False-positive controls:

* IP addresses are validated with :mod:`ipaddress`, never by regex alone; version-like numbers
  (``version 10.2.3.4``) are skipped, and non-public addresses need an IP-ish cue nearby.
* A bare domain is only a candidate when the text calls it out (``domain``, ``C2``, ``hostname``,
  ``callback`` ...) or it was defanged; the page's own domain and ordinary prose mentions are not.
* Hashes must be exactly 32/40/64 hex characters and not part of a longer hex run.
* URLs are distinguished from domains (a domain inside a URL is not double-reported), and links
  to the source site itself are ignored.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from arkham.crawl.models import IndicatorCandidate
from arkham.security.prompt_injection import sanitize_text

MAX_INPUT_CHARS = 200_000
MAX_CANDIDATES = 500
CONTEXT_RADIUS = 100
CONTEXT_MAX = 300
DOMAIN_CUE_LOOKBEHIND = 48
IP_CUE_LOOKBEHIND = 40

# --------------------------------------------------------------------------------------
# Refanging (explicit, reversible in spirit: the original is preserved in ``context``)
# --------------------------------------------------------------------------------------

_DEFANG_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bhxxps://", re.I), "https://"),
    (re.compile(r"\bhxxp://", re.I), "http://"),
    (re.compile(r"\bfxp://", re.I), "ftp://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
)
_DEFANG_MARKER_RE = re.compile(r"hxxp|fxp://|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\[:\]|\[@\]|\[at\]", re.I)


def refang(text: str) -> str:
    """Convert common defanged spellings back to their literal form."""
    for pattern, replacement in _DEFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


# --------------------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------------------

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.I)
_ATTACK_RE = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA00\d{2})\b")
_GHSA_RE = re.compile(r"\bGHSA(?:-[A-Za-z0-9]{4}){3}\b", re.I)
_ACTOR_RE = re.compile(
    r"\b(?:APT\d{1,3}|UNC\d{3,5}|FIN\d{1,2}|TA\d{3}(?!\d)|DEV-\d{3,4}|Storm-\d{3,4}|UAT-\d{3,5}|TAG-\d{2,3}|"
    r"Volt Typhoon|Salt Typhoon|Flax Typhoon|Sandworm|Lazarus(?: Group)?|Kimsuky|Turla|Gamaredon|"
    r"Scattered Spider|Midnight Blizzard|Cozy Bear|Fancy Bear|MuddyWater|Charming Kitten|Mustang Panda|"
    r"Silk Typhoon|Forest Blizzard|Star Blizzard|Emerald Sleet|Evil Corp|Black Basta|LockBit|Cl0p|Clop|"
    r"BlackCat|ALPHV|Akira|Qilin|RansomHub|Medusa|Play|Rhysida|Hunters International|Scattered Spider)\b"
)
_MALWARE_SUFFIX_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9]{1,30}(?:RAT|Loader|Stealer|Locker|Bot|Miner|Backdoor|Trojan|Worm|Wiper|"
    r"Dropper|Injector|Crypt(?:er|or)|Ransom))\b"
)
_MALWARE_CUE_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9\-]{2,30})\s+(?:malware|ransomware|backdoor|trojan|infostealer|stealer|loader|"
    r"botnet|rootkit|wiper|implant|RAT)\b"
)
_MALWARE_STOPWORDS = frozenset(
    {
        "the", "this", "that", "new", "a", "an", "another", "custom", "novel", "known", "unknown", "same",
        "several", "multiple", "additional", "windows", "linux", "android", "macos", "mac", "ios", "mobile",
        "banking", "modular", "commodity", "destructive", "targeted", "advanced", "simple", "wormable",
        "fileless", "python", "powershell", "javascript", "java", "golang", "rust", "dotnet", "net",
    }
)
_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?!\w|\.\d)")  # "8.8.8.8." ok, "1.2.3.4.5" not
_IPV6_RE = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
_VERSION_PREFIX_RE = re.compile(
    r"(?:\b(?:version|versions|ver|v|release|build|firmware|update|patch)\.?|<=|>=|<|>)\s*$", re.I
)
_IP_CUE_RE = re.compile(
    r"\b(?:ip|ips|ipv4|ipv6|c2|c&c|cnc|command|control|server|servers|address|addresses|beacon|host|"
    r"hosts|callback|listener|attacker|infrastructure|ioc|iocs|indicator|indicators|scanning|source)\b",
    re.I,
)
_DOMAIN_RE = re.compile(
    r"(?<![\w@/.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-]|\.[a-z])", re.I
)
_DOMAIN_CUE_RE = re.compile(
    r"\b(?:domain|domains|subdomain|subdomains|hostname|hostnames|host|hosts|fqdn|c2|c&c|cnc|"
    r"command[- ]and[- ]control|callback|callbacks|beacon|beacons|resolv\w*|infrastructure|ioc|iocs|"
    r"indicator\w*|malicious|attacker[- ]controlled|phishing|payload|staging|exfil\w*|dns|typosquat\w*|"
    r"lookalike|registered|sinkhole\w*|delivery)\b",
    re.I,
)
_FILE_EXTENSIONS = frozenset(
    "exe dll pdf doc docx xls xlsx ppt pptx js json xml html htm php asp aspx txt zip rar gz tar py sh bat "
    "ps1 dat bin log csv png jpg jpeg gif svg css md yml yaml ini cfg conf sys tmp iso img apk jar msi lnk "
    "vbs wsf hta scr cab dmg pkg deb rpm ts tsx jsx sql db bak old new min map lock toml rst".split()
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'()\[\]{}]+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
_SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{64})(?![A-Fa-f0-9])")
_SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{40})(?![A-Fa-f0-9])")
_MD5_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
_PRODUCT_VERSION_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z0-9+#\-]{1,30}\s+){1,4})(?:version|versions|ver\.?|v\.?|release|build)\s+(\d+(?:\.\d+){1,5})"
)
_VERSION_RE = re.compile(
    r"(?:\b(?:version|versions|ver|v|release|build|firmware)\.?\s*|<=\s*|>=\s*|<\s*|>\s*|\bbefore\s+|"
    r"\bprior to\s+|\bthrough\s+|\bup to\s+)(\d+(?:\.\d+){1,5})\b",
    re.I,
)
_KEV_RE = re.compile(
    r"\b(?:CISA\s+KEV|KEV\s+catalog|Known\s+Exploited\s+Vulnerabilit(?:y|ies)(?:\s+catalog)?)\b", re.I
)
_EXPLOIT_RE = re.compile(
    r"\b(?:proof[- ]of[- ]concept(?:\s+(?:exploit|code))?|PoC(?:\s+(?:exploit|code))?|"
    r"exploit(?:ation)?\s+(?:code|in\s+the\s+wild|module|kit)|actively\s+exploited|exploited\s+in\s+the\s+wild|"
    r"under\s+active\s+exploitation|working\s+exploit|weaponi[sz]ed|zero[- ]day|0[- ]day|mass\s+exploitation)\b",
    re.I,
)
_SOURCE_TOKENS_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class _Hit:
    type: str
    value: str
    start: int
    end: int


def _source_domain(source_url: str) -> str:
    host = (urlsplit(source_url.strip()).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _same_site(host: str, source_domain: str) -> bool:
    if not source_domain or not host:
        return False
    host = host[4:] if host.startswith("www.") else host
    return host == source_domain or host.endswith("." + source_domain) or source_domain.endswith("." + host)


def _window(text: str, start: int, end: int, radius: int = 60) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)]


# --------------------------------------------------------------------------------------
# Per-type scanners
# --------------------------------------------------------------------------------------


def _simple(pattern: re.Pattern[str], text: str, kind: str, *, upper: bool = False, lower: bool = False) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in pattern.finditer(text):
        value = match.group(1) if match.groups() else match.group(0)
        if upper:
            value = value.upper()
        if lower:
            value = value.lower()
        hits.append(_Hit(kind, value, match.start(), match.end()))
    return hits


def _actors(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _ACTOR_RE.finditer(text):
        value = match.group(0)
        if re.match(r"(?:APT|UNC|FIN|TA|UAT|DEV|TAG)", value, re.I):
            value = value.upper()
        hits.append(_Hit("actor", value, match.start(), match.end()))
    return hits


def _malware(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _MALWARE_SUFFIX_RE.finditer(text):
        name = match.group(1)
        if name.lower() in _MALWARE_STOPWORDS or name.isupper() or name.islower():
            continue
        hits.append(_Hit("malware", name, match.start(1), match.end(1)))
    for match in _MALWARE_CUE_RE.finditer(text):
        name = match.group(1)
        if name.lower() in _MALWARE_STOPWORDS:
            continue
        hits.append(_Hit("malware", name, match.start(1), match.end(1)))
    return hits


def _ip_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, text: str, start: int) -> bool:
    """Public addresses always; RFC1918-style private ranges only with a preceding IP-ish cue; never
    loopback, link-local, multicast, unspecified or reserved addresses (they are never an observable)."""
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    if address.is_global:
        return True
    return _IP_CUE_RE.search(text[max(0, start - IP_CUE_LOOKBEHIND) : start]) is not None


def _ipv4(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _IPV4_RE.finditer(text):
        candidate = match.group(1)
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if _VERSION_PREFIX_RE.search(text[max(0, match.start() - 24) : match.start()]):
            continue  # "version 10.2.3.4"
        if not _ip_allowed(address, text, match.start()):
            continue
        hits.append(_Hit("ipv4", str(address), match.start(1), match.end(1)))
    return hits


def _ipv6(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _IPV6_RE.finditer(text):
        candidate = match.group(1)
        if candidate.count(":") < 2 or candidate == "::":
            continue
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if not _ip_allowed(address, text, match.start()):
            continue
        hits.append(_Hit("ipv6", address.compressed, match.start(1), match.end(1)))
    return hits


def _urls(text: str, source_url: str, source_domain: str) -> list[_Hit]:
    hits: list[_Hit] = []
    normalized_source = source_url.strip().rstrip("/").lower()
    for match in _URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:!?'\"")
        host = (urlsplit(value).hostname or "").lower()
        if not host or "." not in host:
            continue
        if _same_site(host, source_domain) or value.rstrip("/").lower() == normalized_source:
            continue
        hits.append(_Hit("url", value, match.start(), match.start() + len(value)))
    return hits


def _domains(text: str, original: str, source_domain: str, masked: list[tuple[int, int]]) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _DOMAIN_RE.finditer(text):
        start, end = match.start(1), match.end(1)
        if any(a <= start < b for a, b in masked):
            continue  # part of a URL or an email address
        value = match.group(1).lower()
        labels = value.split(".")
        if labels[-1] in _FILE_EXTENSIONS or len(labels) < 2:
            continue
        if _same_site(value, source_domain):
            continue
        defanged = _looks_defanged(original, value)
        if not defanged and not _DOMAIN_CUE_RE.search(text[max(0, start - DOMAIN_CUE_LOOKBEHIND) : start]):
            continue  # the text must introduce it as a domain/host/C2 (cue precedes the candidate)
        hits.append(_Hit("domain", value, start, end))
    return hits


def _looks_defanged(original: str, value: str) -> bool:
    """Whether ``value`` (already refanged) appears in the original text in a defanged spelling."""
    if not _DEFANG_MARKER_RE.search(original):
        return False
    escaped = re.escape(value).replace(r"\.", "\x00").replace(":", "\x01")
    pattern = escaped.replace("\x00", r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\])").replace("\x01", r"(?::|\[:\])")
    return re.search(pattern, original, re.I) is not None and re.search(re.escape(value), original, re.I) is None


def _products_and_versions(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for match in _PRODUCT_VERSION_RE.finditer(text):
        product = _SOURCE_TOKENS_RE.sub(" ", match.group(1)).strip()
        if product and product.lower() not in {"the", "a", "an", "this"}:
            hits.append(_Hit("vendor_product", product, match.start(1), match.end(1)))
        hits.append(_Hit("version", match.group(2), match.start(2), match.end(2)))
    for match in _VERSION_RE.finditer(text):
        hits.append(_Hit("version", match.group(1), match.start(1), match.end(1)))
    return hits


def _phrases(pattern: re.Pattern[str], text: str, kind: str) -> list[_Hit]:
    return [
        _Hit(kind, _SOURCE_TOKENS_RE.sub(" ", match.group(0)).strip(), match.start(), match.end())
        for match in pattern.finditer(text)
    ]


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def extract_indicators(text: str, source_url: str) -> list[IndicatorCandidate]:
    """Return deduplicated CTI artifact candidates in order of first appearance.

    ``source_url`` is the page the text came from: links/domains belonging to that site are not
    reported, and every candidate records it so the observation stays traceable.
    """
    if not text:
        return []
    original = text[:MAX_INPUT_CHARS]
    refanged = refang(original)
    source_domain = _source_domain(source_url)

    hits: list[_Hit] = []
    hits += _simple(_CVE_RE, refanged, "cve", upper=True)
    hits += _simple(_CWE_RE, refanged, "cwe", upper=True)
    hits += _simple(_ATTACK_RE, refanged, "attack", upper=True)
    hits += _simple(_GHSA_RE, refanged, "ghsa", upper=True)
    hits += _actors(refanged)
    hits += _malware(refanged)
    hits += _ipv4(refanged)
    hits += _ipv6(refanged)
    url_hits = _urls(refanged, source_url, source_domain)
    email_hits = _simple(_EMAIL_RE, refanged, "email", lower=True)
    masked = [(h.start, h.end) for h in url_hits + email_hits]
    masked += [(m.start(), m.end()) for m in _URL_RE.finditer(refanged)]  # also same-site URLs
    hits += url_hits
    hits += email_hits
    hits += _domains(refanged, original, source_domain, masked)
    hits += _simple(_SHA256_RE, refanged, "sha256", lower=True)
    hits += _simple(_SHA1_RE, refanged, "sha1", lower=True)
    hits += _simple(_MD5_RE, refanged, "md5", lower=True)
    hits += _products_and_versions(refanged)
    hits += _phrases(_KEV_RE, refanged, "kev_reference")
    hits += _phrases(_EXPLOIT_RE, refanged, "exploit_reference")

    seen: set[tuple[str, str]] = set()
    candidates: list[IndicatorCandidate] = []
    for hit in sorted(hits, key=lambda h: (h.start, h.type, h.value)):
        key = (hit.type, hit.value.casefold())
        if key in seen:
            continue
        seen.add(key)
        excerpt = sanitize_text(refanged[max(0, hit.start - CONTEXT_RADIUS) : hit.end + CONTEXT_RADIUS], CONTEXT_MAX)
        if hit.type in {"domain", "url", "ipv4", "ipv6", "email"} and _looks_defanged(original, hit.value):
            excerpt = ("defanged: " + excerpt)[:CONTEXT_MAX]
        candidates.append(IndicatorCandidate(type=hit.type, value=hit.value, context=excerpt, source_url=source_url))
        if len(candidates) >= MAX_CANDIDATES:
            break
    return candidates
