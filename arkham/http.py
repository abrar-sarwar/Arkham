"""Hardened HTTP client used by every source adapter and delivery/LLM provider.

Guarantees: https-only public URLs (validated at every redirect hop), connect/read timeouts,
hard response-size cap enforced while streaming, conditional GET support, no automatic
execution of anything downloaded — bodies are returned as bytes for the caller to parse.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

from arkham.security.urls import UrlValidationError, validate_public_url

log = logging.getLogger(__name__)

MAX_REDIRECTS = 5


class HttpError(Exception):
    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class ResponseTooLarge(HttpError):
    pass


class HttpTimeout(HttpError):
    pass


class RedirectRefused(HttpError):
    """A redirect was received while redirects were disabled for the request."""


class HttpStatusError(HttpError):
    def __init__(self, status_code: int, url: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"HTTP {status_code} from {url}")
        self.status_code = status_code
        self.url = url
        self.headers = dict(headers or {})  # lower-cased response headers (e.g. retry-after); never the body

    def retry_after_seconds(self) -> float | None:
        """Parse a numeric ``Retry-After`` header; None when absent or not a number."""
        value = self.headers.get("retry-after")
        if value is None:
            return None
        try:
            seconds = float(value.strip())
        except ValueError:
            return None
        return seconds if seconds >= 0 else None


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    not_modified: bool = False

    @property
    def etag(self) -> str | None:
        return self.headers.get("etag")

    @property
    def last_modified(self) -> str | None:
        return self.headers.get("last-modified")

    def text(self, fallback_encoding: str = "utf-8") -> str:
        return self.body.decode(fallback_encoding, errors="replace")


class SafeHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        max_bytes: int = 8 * 1024 * 1024,
        user_agent: str = "Arkham-CTI/1.0",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)),
            follow_redirects=False,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            transport=transport,
            http2=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeHttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: object | None = None,
        max_bytes: int | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        auth: tuple[str, str] | None = None,
        timeout_seconds: float | None = None,
        follow_redirects: bool = True,
    ) -> HttpResponse:
        limit = max_bytes or self.max_bytes
        req_headers = dict(headers or {})
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified
        current = validate_public_url(url)
        timeout = httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)) if timeout_seconds else None
        for _hop in range(MAX_REDIRECTS + 1):
            try:
                with self._client.stream(
                    method,
                    current,
                    headers=req_headers,
                    params=params,
                    data=data,
                    json=json,
                    auth=auth,
                    timeout=timeout or httpx.USE_CLIENT_DEFAULT,
                ) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                        if not follow_redirects:
                            raise RedirectRefused(f"Refusing redirect (HTTP {resp.status_code}); redirects are disabled for this request")
                        target = str(httpx.URL(current).join(resp.headers["location"]))
                        try:
                            current = validate_public_url(target)
                        except UrlValidationError as exc:
                            raise HttpError(f"Refusing redirect to unsafe URL: {exc}") from exc
                        if resp.status_code == 303 or (resp.status_code in (301, 302) and method.upper() == "POST"):
                            method, data, json = "GET", None, None
                        continue
                    if resp.status_code == 304:
                        return HttpResponse(url=current, status_code=304, headers=_lower(resp.headers), not_modified=True)
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise ResponseTooLarge(f"Declared content-length {declared} exceeds limit {limit} for {current}")
                    chunks: list[bytes] = []
                    received = 0
                    for chunk in resp.iter_bytes():
                        received += len(chunk)
                        if received > limit:
                            raise ResponseTooLarge(f"Response exceeded {limit} bytes for {current}")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    if resp.status_code >= 400:
                        raise HttpStatusError(resp.status_code, current, _lower(resp.headers))
                    return HttpResponse(url=current, status_code=resp.status_code, headers=_lower(resp.headers), body=body)
            except httpx.TimeoutException as exc:
                raise HttpTimeout(f"Timeout after {timeout_seconds or self.timeout_seconds}s fetching {current}") from exc
            except httpx.HTTPError as exc:
                raise HttpError(
                    f"HTTP transport error for {current}: {exc.__class__.__name__}: {exc}",
                    transient=True,
                ) from exc
        raise HttpError(f"Too many redirects fetching {url}")

    def get(self, url: str, **kwargs: object) -> HttpResponse:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def post(self, url: str, **kwargs: object) -> HttpResponse:
        return self.request("POST", url, **kwargs)  # type: ignore[arg-type]


def _lower(headers: httpx.Headers) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}
