"""Deterministic, offline article extraction from already-fetched HTML (or plain text).

Design: a small, forgiving HTML tree built on the stdlib ``html.parser`` (no JavaScript, no browser,
no secondary fetches, no third-party parser), then

1. **metadata** from ``<title>``/``<h1>``, ``<meta>`` (description, author, article:* times), JSON-LD
   (``headline``/``datePublished``/``dateModified``/``author``) and ``<link rel=canonical>``;
2. **noise removal** — scripts, styles, templates, embeds, forms, navigation, asides, footers, cookie/
   consent/share/related/ad blocks, hidden elements;
3. **main-content selection** — the densest semantic container (``<article>``, ``<main>``,
   ``role=main``, ``itemprop=articleBody``, or a content-like ``div``/``section``), else the body;
4. **text assembly** — headings, paragraphs, list items, code, quotes and table cells as blocks;
5. **safety** — control/zero-width characters removed, instruction-like sentences neutralised
   (``injection_flagged``), links validated as public https and canonicalised, all sizes bounded;
6. **signals** for :mod:`arkham.crawl.quality` and CTI candidates from :mod:`arkham.crawl.indicators`.

Raw HTML is never stored; the returned :class:`~arkham.crawl.models.ExtractedArticle` holds only
bounded, sanitised text and structured facts.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from arkham.crawl.indicators import extract_indicators
from arkham.crawl.models import ExtractedArticle
from arkham.crawl.normalize import accept_canonical_url, normalize_crawl_url
from arkham.crawl.quality import score_extraction
from arkham.security.prompt_injection import normalize_whitespace, sanitize_for_model, sanitize_text
from arkham.security.urls import UrlValidationError, canonicalize_url, display_url, validate_public_url

log = logging.getLogger(__name__)

DEFAULT_MAX_TEXT_CHARS = 50_000
DEFAULT_MAX_HTML_CHARS = 4 * 1024 * 1024
MAX_LINKS = 50
MAX_HEADINGS = 40
MAX_JSON_LD_CHARS = 64 * 1024
TITLE_MAX = 300
DESCRIPTION_MAX = 500
AUTHOR_MAX = 120
HEADING_MAX = 200
JS_SHELL_MAX_VISIBLE_CHARS = 300
MATERIAL_SIMILARITY = 0.85

_VOID_TAGS = frozenset(
    "area base br col embed hr img input link meta param source track wbr command keygen menuitem".split()
)
_BLOCK_TAGS = frozenset(
    "address article aside blockquote body dd details dialog div dl dt fieldset figcaption figure footer form "
    "h1 h2 h3 h4 h5 h6 header hgroup hr li main nav ol p pre section table tbody td tfoot th thead tr ul".split()
)
_DROP_TAGS = frozenset(
    "script style noscript template svg math iframe frame frameset object embed applet canvas video audio "
    "picture source track form button input select textarea option datalist meter progress nav aside footer "
    "menu dialog map area".split()
)
_TEXT_BLOCK_TAGS = frozenset("p h1 h2 h3 h4 h5 h6 li pre blockquote td th dt dd figcaption".split())
_PARAGRAPH_TAGS = frozenset("p li blockquote td dd".split())
_HEADING_TAGS = frozenset("h1 h2 h3 h4 h5 h6".split())
_AUTO_CLOSE_TAGS = _HEADING_TAGS | {"p", "dt", "dd"}
_CONTAINER_TAGS = frozenset({"article", "main"})
_CONTENT_HINT_RE = re.compile(r"article|content|post|entry|story|body|main|advisory|bulletin|release", re.I)
_NOISE_CLASS_RE = re.compile(
    r"(?:^|[-_ ])(?:cookie|cookies|consent|gdpr|banner|subscribe|subscription|newsletter|sidebar|side-bar|"
    r"related|share|sharing|social|comment|comments|promo|promotion|advert|advertisement|ads|ad|sponsor|"
    r"sponsored|breadcrumb|breadcrumbs|popup|modal|overlay|paywall|signup|login|recommend|recommended|"
    r"trending|widget|toolbar|skip-link|screen-reader)(?:$|[-_ ])",
    re.I,
)
_NOISE_ROLES = frozenset(
    "navigation banner contentinfo complementary dialog alertdialog search menu menubar toolbar".split()
)
_HIDDEN_STYLE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)
_HTML_SNIFF_RE = re.compile(r"<(?:!doctype|html|head|body|article|main|div|p|h1|section|meta|title)\b", re.I)
_TITLE_SPLIT_RE = re.compile(r"\s+[|\-–—:»·]\s+")
_WS_RE = re.compile(r"[ \t\r\f\v ]+")
_SHELL_TEXT_RE = re.compile(
    r"loading|enable javascript|javascript is required|requires javascript|please enable|"
    r"you need to enable javascript",
    re.I,
)
_APP_ROOT_RE = re.compile(r"^(?:app|root|__next|__nuxt|main-app|react-root|spa)$", re.I)


# --------------------------------------------------------------------------------------
# A tiny forgiving DOM
# --------------------------------------------------------------------------------------


class _Node:
    __slots__ = ("attrs", "children", "parent", "tag")

    def __init__(self, tag: str, attrs: dict[str, str], parent: _Node | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.children: list[_Node | str] = []

    def attr(self, name: str) -> str:
        return self.attrs.get(name, "") or ""

    def iter(self):  # type: ignore[no-untyped-def]
        yield self
        for child in self.children:
            if isinstance(child, _Node):
                yield from child.iter()

    def find_all(self, *tags: str) -> list[_Node]:
        wanted = set(tags)
        return [node for node in self.iter() if node.tag in wanted]

    def first(self, tag: str) -> _Node | None:
        for node in self.iter():
            if node.tag == tag:
                return node
        return None


class _TreeBuilder(HTMLParser):
    """Lenient tree builder: implicit ``<p>``/``<li>`` closing, stray end tags ignored, EOF closes all."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("document", {}, None)
        self._open: list[_Node] = [self.root]

    @property
    def current(self) -> _Node:
        return self._open[-1]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in _BLOCK_TAGS and self.current.tag in _AUTO_CLOSE_TAGS:
            self._close(self.current.tag)  # HTML5-style implicit end of an open <p>/<h1>..<h6>
        if tag == "li" and self.current.tag == "li":
            self._close("li")
        if tag in {"td", "th"} and self.current.tag in {"td", "th"}:
            self._close(self.current.tag)
        node = _Node(tag, {k.lower(): (v or "") for k, v in attrs}, self.current)
        self.current.children.append(node)
        if tag not in _VOID_TAGS:
            self._open.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag.lower(), {k.lower(): (v or "") for k, v in attrs}, self.current)
        self.current.children.append(node)

    def handle_endtag(self, tag: str) -> None:
        self._close(tag.lower())

    def _close(self, tag: str) -> None:
        for index in range(len(self._open) - 1, 0, -1):
            if self._open[index].tag == tag:
                del self._open[index:]
                return

    def handle_data(self, data: str) -> None:
        if data:
            self.current.children.append(data)

    def handle_comment(self, data: str) -> None:  # comments are never content
        return


def _parse(html: str) -> _Node:
    builder = _TreeBuilder()
    try:
        builder.feed(html)
        builder.close()
    except Exception as exc:  # pragma: no cover - HTMLParser is lenient; never let markup crash extraction
        log.debug("html parse stopped early: %s", exc.__class__.__name__)
    return builder.root


# --------------------------------------------------------------------------------------
# Noise classification
# --------------------------------------------------------------------------------------


def _is_hidden(node: _Node) -> bool:
    if "hidden" in node.attrs or node.attr("aria-hidden").strip().lower() == "true":
        return True
    return bool(_HIDDEN_STYLE_RE.search(node.attr("style")))


def _is_noise(node: _Node, *, in_container: bool) -> bool:
    if node.tag in _DROP_TAGS or _is_hidden(node):
        return True
    if node.tag == "header" and not in_container:
        return True
    if node.attr("role").strip().lower() in _NOISE_ROLES:
        return True
    tokens = f"{node.attr('class')} {node.attr('id')}"
    return bool(tokens.strip()) and bool(_NOISE_CLASS_RE.search(tokens))


def _is_invisible(node: _Node) -> bool:
    """Elements a reader can never see (used for the visible-text baseline)."""
    return node.tag in {"script", "style", "noscript", "template", "svg", "math", "head", "title", "meta", "link"} or _is_hidden(node)


# --------------------------------------------------------------------------------------
# Text collection
# --------------------------------------------------------------------------------------


def _collapse(text: str) -> str:
    return _WS_RE.sub(" ", text.replace("\n", " ")).strip()


def _inline_text(node: _Node, skip) -> str:  # type: ignore[no-untyped-def]
    parts: list[str] = []
    for child in node.children:
        if isinstance(child, str):
            parts.append(child)
        elif child.tag == "br":
            parts.append(" ")
        elif not skip(child):
            parts.append(_inline_text(child, skip))
    return "".join(parts)


def _visible_text(root: _Node) -> str:
    return _collapse(_inline_text(root, _is_invisible))


class _Blocks:
    def __init__(self) -> None:
        self.blocks: list[str] = []
        self.headings: list[str] = []
        self.paragraphs = 0
        self.links: list[str] = []

    def add(self, tag: str, text: str) -> None:
        cleaned = text if tag == "pre" else _collapse(text)
        if tag == "pre":
            cleaned = "\n".join(line.rstrip() for line in cleaned.strip("\n").splitlines()).strip()
        if not cleaned:
            return
        if tag in _HEADING_TAGS:
            heading = sanitize_text(cleaned, HEADING_MAX)
            if heading and len(self.headings) < MAX_HEADINGS:
                self.headings.append(heading)
        if tag in _PARAGRAPH_TAGS and len(cleaned.split()) >= 3:
            self.paragraphs += 1
        if tag == "li":
            cleaned = "- " + cleaned
        self.blocks.append(cleaned)


def _collect(node: _Node, out: _Blocks, *, in_container: bool) -> None:
    for child in node.children:
        if isinstance(child, str):
            continue
        if _is_noise(child, in_container=in_container):
            continue
        if child.tag == "a":
            href = child.attr("href")
            if href and len(out.links) < MAX_LINKS * 4:
                out.links.append(href)
        if child.tag in _TEXT_BLOCK_TAGS:
            for anchor in child.find_all("a"):
                href = anchor.attr("href")
                if href and len(out.links) < MAX_LINKS * 4:
                    out.links.append(href)
            text = _inline_text(child, lambda n: _is_noise(n, in_container=True))
            out.add(child.tag, text)
            continue
        direct = "".join(part for part in child.children if isinstance(part, str))
        has_block_child = any(isinstance(part, _Node) and part.tag in _BLOCK_TAGS for part in child.children)
        if child.tag in _BLOCK_TAGS and not has_block_child:
            text = _inline_text(child, lambda n: _is_noise(n, in_container=True))
            out.add(child.tag, text)
            continue
        if _collapse(direct):
            out.add(child.tag, direct)
        _collect(child, out, in_container=in_container)


# --------------------------------------------------------------------------------------
# Container selection
# --------------------------------------------------------------------------------------


def _is_semantic_container(node: _Node) -> bool:
    if node.tag in _CONTAINER_TAGS:
        return True
    return node.attr("role").strip().lower() == "main" or node.attr("itemprop").strip().lower() == "articlebody"


def _container_score(node: _Node) -> int:
    probe = _Blocks()
    _collect(node, probe, in_container=True)
    return sum(len(block) for block in probe.blocks)


def _choose_container(root: _Node) -> tuple[_Node | None, bool]:
    candidates: list[tuple[int, int, int, _Node]] = []
    depth_of: dict[int, int] = {}

    def walk(node: _Node, depth: int) -> None:
        depth_of[id(node)] = depth
        for child in node.children:
            if isinstance(child, _Node):
                walk(child, depth + 1)

    walk(root, 0)
    for node in root.iter():
        if _is_noise(node, in_container=False):
            continue
        semantic = _is_semantic_container(node)
        hinted = node.tag in {"div", "section"} and bool(
            _CONTENT_HINT_RE.search(f"{node.attr('class')} {node.attr('id')}")
        )
        if not (semantic or hinted):
            continue
        score = _container_score(node)
        if score <= 0:
            continue
        priority = 2 if node.tag == "article" else (1 if semantic else 0)
        candidates.append((score, priority, depth_of.get(id(node), 0), node))
    if not candidates:
        return None, False
    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    best = candidates[0][3]
    return best, _is_semantic_container(best)


# --------------------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------------------


def _meta(root: _Node) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in root.find_all("meta"):
        key = (node.attr("property") or node.attr("name") or node.attr("itemprop")).strip().lower()
        content = node.attr("content").strip()
        if key and content and key not in values:
            values[key] = content
    return values


def _json_ld(root: _Node) -> dict[str, Any]:
    """Bounded read of JSON-LD blocks for headline/description/author/dates (never executed)."""
    found: dict[str, Any] = {}
    for node in root.find_all("script"):
        if "ld+json" not in node.attr("type").lower():
            continue
        raw = "".join(part for part in node.children if isinstance(part, str)).strip()
        if not raw or len(raw) > MAX_JSON_LD_CHARS:
            continue
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):  # invalid or pathologically nested JSON-LD is ignored
            continue
        for entry in _iter_ld(data, 0):
            for key in ("headline", "description", "datePublished", "dateModified"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip() and key not in found:
                    found[key] = value.strip()
            author = entry.get("author")
            name = _author_name(author)
            if name and "author" not in found:
                found["author"] = name
    return found


def _iter_ld(data: Any, depth: int):  # type: ignore[no-untyped-def]
    if depth > 4:
        return
    if isinstance(data, dict):
        yield data
        for key in ("@graph", "mainEntity", "mainEntityOfPage"):
            if key in data:
                yield from _iter_ld(data[key], depth + 1)
    elif isinstance(data, list):
        for item in data[:20]:
            yield from _iter_ld(item, depth + 1)


def _author_name(author: Any) -> str:
    if isinstance(author, str):
        return author.strip()
    if isinstance(author, dict):
        name = author.get("name")
        return name.strip() if isinstance(name, str) else ""
    if isinstance(author, list):
        names = [_author_name(entry) for entry in author[:5]]
        return ", ".join(name for name in names if name)
    return ""


def parse_datetime(value: str | None) -> datetime | None:
    """ISO-8601 (``Z`` accepted), RFC 2822 or bare ``YYYY-MM-DD``; naive values are taken as UTC."""
    if not value:
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            parsed = None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _clean_title(raw: str) -> str:
    """Strip a site-name suffix/prefix: keep the longest segment around ``|``, ``–``, ``—``, ``:``."""
    segments = [segment.strip() for segment in _TITLE_SPLIT_RE.split(raw) if segment.strip()]
    if not segments:
        return raw.strip()
    return max(segments, key=len)


def _title(root: _Node, container: _Node | None, meta: dict[str, str], ld: dict[str, Any]) -> str:
    h1_node = (container.first("h1") if container is not None else None) or root.first("h1")
    h1 = sanitize_text(_collapse(_inline_text(h1_node, _is_invisible)), TITLE_MAX) if h1_node is not None else ""
    title_node = root.first("title")
    page_title = sanitize_text(_collapse(_inline_text(title_node, lambda n: False)), TITLE_MAX) if title_node else ""
    og = sanitize_text(meta.get("og:title") or meta.get("twitter:title") or "", TITLE_MAX)
    headline = sanitize_text(str(ld.get("headline") or ""), TITLE_MAX)
    if h1 and len(h1) >= 4:  # an <h1> in the content is the strongest signal
        return h1
    for candidate in (headline, og):
        if candidate:
            return _clean_title(candidate)
    if page_title:
        return _clean_title(page_title)
    return h1


def _canonical(root: _Node, response_url: str) -> str:
    candidate = ""
    for node in root.find_all("link"):
        if node.attr("rel").strip().lower() == "canonical" and node.attr("href").strip():
            candidate = node.attr("href").strip()
            break
    if not candidate:
        candidate = _meta(root).get("og:url", "")
    accepted = accept_canonical_url(response_url, candidate) if candidate else None
    if accepted:
        return accepted
    try:
        return normalize_crawl_url(response_url)
    except (UrlValidationError, ValueError):
        return response_url.strip()


def _domain(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _links(hrefs: list[str], base: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    canonical_self = canonicalize_url(base) if base else ""
    for href in hrefs:
        href = href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        try:
            absolute = validate_public_url(urljoin(base, href))
            canonical = canonicalize_url(absolute)
        except (UrlValidationError, ValueError):
            continue
        if canonical == canonical_self or canonical in seen:
            continue
        seen.add(canonical)
        out.append(display_url(absolute))  # host kept as published, tracking parameters and fragment dropped
        if len(out) >= MAX_LINKS:
            break
    return out


def _language(root: _Node, meta: dict[str, str]) -> str | None:
    html = root.first("html")
    raw = (html.attr("lang") if html is not None else "") or meta.get("og:locale", "")
    match = re.match(r"([A-Za-z]{2,3})", raw.strip())
    return match.group(1).lower() if match else None


def _js_shell(root: _Node, visible_chars: int) -> bool:
    body = root.first("body") or root
    scripts = [n for n in root.find_all("script") if n.attr("src") or any(isinstance(c, str) and c.strip() for c in n.children)]
    if not scripts or visible_chars >= JS_SHELL_MAX_VISIBLE_CHARS:
        return False
    has_app_root = any(_APP_ROOT_RE.match(n.attr("id").strip()) for n in body.find_all("div", "main", "section"))
    noscript = any(_SHELL_TEXT_RE.search(_inline_text(n, lambda _n: False)) for n in root.find_all("noscript"))
    text = _visible_text(body)
    return has_app_root or noscript or bool(_SHELL_TEXT_RE.search(text)) or visible_chars < 40


# --------------------------------------------------------------------------------------
# Hashing and change detection
# --------------------------------------------------------------------------------------


def _normalized_text(text: str) -> str:
    return " ".join(text.split())


def content_hash(text: str) -> str:
    """SHA-256 of whitespace-normalised text so cosmetic reflows do not count as change."""
    return hashlib.sha256(_normalized_text(text or "").encode("utf-8", "replace")).hexdigest()


def is_material_article_change(old: ExtractedArticle, new: ExtractedArticle) -> tuple[bool, str | None]:
    """Whether ``new`` is a substantive development over ``old`` and, if so, a short reason."""
    old_text, new_text = _normalized_text(old.article_text), _normalized_text(new.article_text)
    old_title, new_title = _normalized_text(old.title).casefold(), _normalized_text(new.title).casefold()
    if content_hash(old_text) == content_hash(new_text) and old_title == new_title:
        return False, None
    old_artifacts = {(item.type, item.value.casefold()) for item in old.indicators}
    new_artifacts = {(item.type, item.value.casefold()) for item in new.indicators}
    if old_artifacts != new_artifacts:
        return True, "source CTI artifacts changed"
    if old_title and new_title and old_title != new_title:
        return True, "title changed"
    if not old_text or not new_text:
        return (True, "article text appeared") if new_text and not old_text else (False, None)
    ratio = difflib.SequenceMatcher(None, old_text[:20_000], new_text[:20_000], autojunk=False).ratio()
    if ratio < MATERIAL_SIMILARITY:
        return True, "article text changed substantially"
    if len(new_text) - len(old_text) > max(300, int(0.2 * len(old_text))):
        return True, "article text expanded substantially"
    return False, None


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def _content_type(headers: Mapping[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.lower()
    return ""


def _empty(response_url: str, canonical: str, *, language: str | None = None) -> ExtractedArticle:
    return ExtractedArticle(
        original_url=response_url, canonical_url=canonical, source_domain=_domain(canonical), language=language,
        content_hash=content_hash(""),
    )


def _plain_text_article(text: str, response_url: str, canonical: str, max_text_chars: int) -> ExtractedArticle:
    scan = sanitize_for_model(text, max_text_chars)
    blocks = [block for block in scan.cleaned.split("\n\n") if block.strip()]
    article = ExtractedArticle(
        original_url=response_url,
        canonical_url=canonical,
        source_domain=_domain(canonical),
        title=sanitize_text(blocks[0], TITLE_MAX) if blocks and len(blocks[0]) <= TITLE_MAX else "",
        article_text=scan.cleaned,
        paragraph_count=sum(1 for block in blocks if len(block.split()) >= 3),
        visible_text_chars=len(_normalized_text(text)),
        content_hash=content_hash(scan.cleaned),
        indicators=extract_indicators(scan.cleaned, canonical),
        injection_flagged=scan.flagged,
    )
    article.quality_score = score_extraction(article)
    return article


def extract_article(
    html: str,
    *,
    response_url: str,
    headers: Mapping[str, str],
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    max_html_chars: int = DEFAULT_MAX_HTML_CHARS,
) -> ExtractedArticle:
    """Extract bounded, sanitised article content from fetched ``html`` (never raises).

    ``headers`` are the lower-or-mixed-case response headers; only ``content-type`` is consulted.
    A ``text/plain`` body (or one that does not look like HTML) is treated as plain text. Output text
    is capped at ``max_text_chars``; input is capped at ``max_html_chars`` before parsing.
    """
    text_in = (html or "")[: max(0, max_html_chars)]
    content_type = _content_type(headers)
    is_html = "html" in content_type or "xml" in content_type or (not content_type.startswith("text/plain") and bool(_HTML_SNIFF_RE.search(text_in[:4096])))
    if not text_in.strip():
        canonical = _safe_canonical(response_url)
        return _empty(response_url, canonical)
    if not is_html:
        return _plain_text_article(text_in, response_url, _safe_canonical(response_url), max_text_chars)

    root = _parse(text_in)
    meta = _meta(root)
    ld = _json_ld(root)
    canonical = _canonical(root, response_url)
    body = root.first("body") or root
    visible = _visible_text(body)
    container, semantic = _choose_container(body)
    extraction_root = container if container is not None else body

    blocks = _Blocks()
    _collect(extraction_root, blocks, in_container=container is not None)
    raw_text = "\n\n".join(blocks.blocks)
    scan = sanitize_for_model(raw_text, max_text_chars)
    article_text = normalize_whitespace(scan.cleaned)

    normalized_blocks = [_normalized_text(block).casefold() for block in blocks.blocks if _normalized_text(block)]
    duplicate_ratio = 0.0
    if len(normalized_blocks) > 1:
        duplicate_ratio = 1.0 - len(set(normalized_blocks)) / len(normalized_blocks)

    published = parse_datetime(
        meta.get("article:published_time") or meta.get("og:published_time") or meta.get("datepublished")
        or ld.get("datePublished") or meta.get("date") or meta.get("dc.date") or _first_time(root)
    )
    updated = parse_datetime(
        meta.get("article:modified_time") or meta.get("og:updated_time") or meta.get("datemodified")
        or ld.get("dateModified")
    )
    author_raw = meta.get("author") or ld.get("author") or meta.get("article:author") or ""
    if author_raw.startswith(("http://", "https://")):
        author_raw = ""
    description_raw = meta.get("description") or meta.get("og:description") or meta.get("twitter:description") or ld.get("description") or ""

    article = ExtractedArticle(
        original_url=response_url,
        canonical_url=canonical,
        source_domain=_domain(canonical),
        title=_title(root, container, meta, ld),
        description=sanitize_text(str(description_raw), DESCRIPTION_MAX),
        author=sanitize_text(str(author_raw), AUTHOR_MAX),
        published_at=published,
        updated_at=updated,
        article_text=article_text,
        headings=blocks.headings,
        relevant_links=_links(blocks.links, canonical),
        language=_language(root, meta),
        paragraph_count=blocks.paragraphs,
        visible_text_chars=len(visible),
        article_container=semantic,
        js_shell=_js_shell(root, len(visible)),
        duplicate_text_ratio=duplicate_ratio,
        content_hash=content_hash(article_text),
        indicators=extract_indicators(article_text, canonical),
        injection_flagged=scan.flagged,
    )
    article.quality_score = score_extraction(article)
    return article


def _first_time(root: _Node) -> str:
    for node in root.find_all("time"):
        value = node.attr("datetime").strip()
        if value:
            return value
    return ""


def _safe_canonical(response_url: str) -> str:
    try:
        return normalize_crawl_url(response_url)
    except (UrlValidationError, ValueError):
        return response_url.strip()
