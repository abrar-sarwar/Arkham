"""URL validation and canonicalisation.

Every URL Arkham fetches or forwards to the user must pass :func:`validate_public_url`:
https only, no credentials, no loopback/private/link-local hosts, sane length.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
_TRACKING_PARAMS = re.compile(
    r"^(utm_(?:source|medium|campaign|term|content|id)|fbclid|gclid|mc_cid|mc_eid|s_cid|cmp|mkt_tok|_hsenc|_hsmi|oly_[a-z_]+)$",
    re.I,
)
_BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal"}

#: Exact hosts that serve Discord's incoming-webhook API. No wildcard/subdomain matching on purpose.
DISCORD_WEBHOOK_HOSTS: frozenset[str] = frozenset(
    {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
)
#: ``/api/webhooks/<snowflake>/<token>`` with an optional API version segment; nothing else.
DISCORD_WEBHOOK_PATH_RE = re.compile(r"^/api/(?:v\d{1,2}/)?webhooks/(\d{15,22})/([A-Za-z0-9_\-]{32,128})$")


class UrlValidationError(ValueError):
    pass


def validate_discord_webhook_url(url: str) -> str:
    """Return ``url`` (stripped) only if it is a genuine Discord incoming-webhook endpoint.

    Builds on :func:`validate_public_url` (https, no credentials, public host, standard port) and
    then requires an exact Discord host and the ``/api[/vN]/webhooks/<id>/<token>`` path with no
    query string or fragment. Error messages never include the URL or its token.
    """
    try:
        u = validate_public_url(url)
    except UrlValidationError as exc:
        raise UrlValidationError(f"not a usable https URL ({exc})") from None
    parts = urlsplit(u)
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in DISCORD_WEBHOOK_HOSTS:
        raise UrlValidationError("host is not a Discord webhook host (expected discord.com)")
    if parts.query or parts.fragment:
        raise UrlValidationError("webhook URL must not carry a query string or fragment")
    if not DISCORD_WEBHOOK_PATH_RE.match(parts.path):
        raise UrlValidationError("path is not of the form /api/webhooks/<id>/<token>")
    return u


def validate_public_url(url: str, *, allow_http: bool = False) -> str:
    """Return the URL stripped of whitespace if it is a safe, public https URL; raise otherwise."""
    if not isinstance(url, str):
        raise UrlValidationError("URL must be a string")
    u = url.strip()
    if not u or len(u) > MAX_URL_LENGTH:
        raise UrlValidationError("URL empty or too long")
    if any(ch.isspace() or ord(ch) < 32 for ch in u):
        raise UrlValidationError("URL contains whitespace or control characters")
    parts = urlsplit(u)
    scheme = parts.scheme.lower()
    if scheme != "https" and not (allow_http and scheme == "http"):
        raise UrlValidationError(f"Unsupported URL scheme {parts.scheme!r}")
    if parts.username or parts.password or "@" in parts.netloc:
        raise UrlValidationError("URL must not contain credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or host in _BLOCKED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
        raise UrlValidationError("URL host is not public")
    if "." not in host:
        raise UrlValidationError("URL host must be a fully qualified domain")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    ):
        raise UrlValidationError("URL host is a non-public IP address")
    if parts.port not in (None, 443) and not (allow_http and parts.port == 80):
        raise UrlValidationError("Non-standard port not allowed")
    return u


def is_valid_public_url(url: str) -> bool:
    try:
        validate_public_url(url)
        return True
    except UrlValidationError:
        return False


def canonicalize_url(url: str) -> str:
    """Canonical form for deduplication and citation: lower-case host, no fragment/tracking params, no trailing slash."""
    u = url.strip()
    parts = urlsplit(u)
    host = (parts.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=False) if not _TRACKING_PARAMS.match(k)]
    query.sort()
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower() or "https", netloc, path, urlencode(query), ""))


def display_url(url: str) -> str:
    """Compact URL for SMS: keeps scheme + host + path, drops query/fragment/tracking noise."""
    parts = urlsplit(url.strip())
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=False) if not _TRACKING_PARAMS.match(k)]
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query) if query else "", ""))
