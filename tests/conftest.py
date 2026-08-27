"""Shared pytest fixtures. Tests never hit the network: every HTTP call goes through httpx.MockTransport."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from arkham.http import SafeHttpClient

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def window(now: datetime) -> tuple[datetime, datetime]:
    return now - timedelta(hours=24), now


def load_fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_fixture_json(name: str):
    return json.loads(load_fixture_text(name))


class RouteTable:
    """Map URL prefixes -> (status, body, headers) for httpx.MockTransport."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, int, bytes, dict[str, str]]] = []
        self.requests: list[httpx.Request] = []

    def add(self, url_prefix: str, body: str | bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.routes.append((url_prefix, status, data, headers or {}))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        for prefix, status, body, headers in self.routes:
            if url.startswith(prefix):
                return httpx.Response(status, content=body, headers=headers, request=request)
        return httpx.Response(404, content=b"not found", request=request)

    def client(self, **kwargs) -> SafeHttpClient:
        return SafeHttpClient(transport=httpx.MockTransport(self.handler), **kwargs)


@pytest.fixture
def routes() -> RouteTable:
    return RouteTable()
