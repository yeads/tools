#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Download a public ChatGPT share as Markdown."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests


DEFAULT_TIMEOUT = 30.0
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/140.0.0.0 Safari/537.36"
)
ENQUEUE_RE = re.compile(
    r"(?:window\.)?__reactRouterContext\.streamController\.enqueue"
    r"\((\"(?:\\.|[^\"\\])*\")\)"
)
ANNOTATION_RE = re.compile("\ue200([a-zA-Z_]+)\ue202(.*?)\ue201", re.DOTALL)


class SharePageParser(HTMLParser):
    """Collect script contents without requiring an HTML dependency."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_script = False
        self._chunks: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            self._in_script = True
            self._chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self.scripts.append("".join(self._chunks))
            self._in_script = False
            self._chunks = []


class FlattenedDataDecoder:
    """Decode the reference table emitted by ChatGPT's React Router loader."""

    _SPECIAL_NUMBERS = {
        -1: None,
        -2: None,
        -3: math.nan,
        -4: math.inf,
        -5: None,
        -6: -0.0,
    }

    def __init__(self, values: list[Any]) -> None:
        self.values = values
        self.memo: dict[int, Any] = {}

    def decode(self) -> Any:
        return self._decode_reference(0)

    def decode_reference(self, reference: int) -> Any:
        return self._decode_reference(reference)

    def _decode_reference(self, reference: Any) -> Any:
        # bool is a subclass of int in Python, but is a literal here.
        if isinstance(reference, bool) or not isinstance(reference, int):
            return reference
        if reference < 0:
            return self._SPECIAL_NUMBERS.get(reference)
        if reference >= len(self.values):
            raise ValueError(f"invalid data reference: {reference}")
        if reference in self.memo:
            return self.memo[reference]

        value = self.values[reference]
        if isinstance(value, dict):
            result: dict[Any, Any] = {}
            self.memo[reference] = result
            for encoded_key, encoded_value in value.items():
                key = self._decode_key(encoded_key)
                result[key] = self._decode_reference(encoded_value)
            return result

        if isinstance(value, list):
            # Tagged values (for example deferred promises) are irrelevant to
            # conversation data. Preserve their payload in a harmless form.
            if value and isinstance(value[0], str):
                result = {
                    "__type__": value[0],
                    "value": [self._decode_reference(item) for item in value[1:]],
                }
                self.memo[reference] = result
                return result
            result_list: list[Any] = []
            self.memo[reference] = result_list
            result_list.extend(self._decode_reference(item) for item in value)
            return result_list

        return value

    def _decode_key(self, key: str) -> Any:
        if key.startswith("_") and key[1:].isdigit():
            return self._decode_reference(int(key[1:]))
        return key


def validate_share_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"chatgpt.com", "www.chatgpt.com"}:
        raise ValueError("URL must be an https://chatgpt.com/share/... link")
    if not re.fullmatch(r"/share/[^/]+/?", parsed.path):
        raise ValueError("URL must point to a ChatGPT share page")
    return url


def fetch_share_page(url: str, timeout: float, proxy: str | None) -> str:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html"})

    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        response = session.get(url, timeout=timeout, proxies=proxies)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"could not download share page: {exc}") from exc

    if "text/html" not in response.headers.get("Content-Type", ""):
        raise RuntimeError("ChatGPT returned an unexpected response instead of HTML")
    return response.text


def extract_stream_payloads(html: str) -> list[str]:
    parser = SharePageParser()
    parser.feed(html)
    payloads: list[str] = []
    for script in parser.scripts:
        for match in ENQUEUE_RE.finditer(script):
            try:
                payloads.append(json.loads(match.group(1)))
            except json.JSONDecodeError:
                continue
    return payloads


def extract_conversation(html: str) -> dict[str, Any]:
    errors: list[str] = []
    for payload in extract_stream_payloads(html):
        for line in payload.splitlines():
            if not line.startswith("["):
                continue
            try:
                values = json.loads(line)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                errors.append(str(exc))
                continue

            title_refs = [index for index, value in enumerate(values) if value == "title"]
            linear_refs = [
                index for index, value in enumerate(values) if value == "linear_conversation"
            ]
            decoder = FlattenedDataDecoder(values)
            for candidate in values:
                if not isinstance(candidate, dict):
                    continue
                for title_ref in title_refs:
                    title_value_ref = candidate.get(f"_{title_ref}")
                    if not isinstance(title_value_ref, int):
                        continue
                    for linear_ref in linear_refs:
                        linear_value_ref = candidate.get(f"_{linear_ref}")
                        if not isinstance(linear_value_ref, int):
                            continue
                        try:
                            title = decoder.decode_reference(title_value_ref)
                            linear = decoder.decode_reference(linear_value_ref)
                        except (TypeError, ValueError, RecursionError) as exc:
                            errors.append(str(exc))
                            continue
                        if isinstance(title, str) and isinstance(linear, list):
                            return {"title": title, "linear_conversation": linear}

    detail = f" ({errors[-1]})" if errors else ""
    raise RuntimeError(
        "could not find conversation data; the link may be private, expired, "
        f"or ChatGPT's page format may have changed{detail}"
    )


def reference_replacement(reference: dict[str, Any]) -> str:
    kind = reference.get("type")
    alt = reference.get("alt")

    if kind == "image_group":
        urls = reference.get("safe_urls") or []
        return "\n\n".join(
            f"![Image {index}]({url})" for index, url in enumerate(urls, start=1)
        )
    if kind == "entity":
        return str(alt or reference.get("name") or reference.get("prompt_text") or "")
    if kind == "url":
        if alt:
            return str(alt)
        item = reference.get("item") or {}
        title = reference.get("title") or item.get("title") or item.get("url") or "Link"
        url = item.get("url") or next(iter(reference.get("safe_urls") or []), "")
        return f"[{title}]({url})" if url else str(title)
    if kind == "grouped_webpages":
        if alt:
            return str(alt)
        links = []
        for item in reference.get("items") or []:
            if item.get("url"):
                links.append(f"[{item.get('title') or item['url']}]({item['url']})")
        return " (" + ", ".join(links) + ")" if links else ""
    if kind == "sources_footnote":
        return ""
    return str(alt or "")


def clean_annotations(text: str, metadata: dict[str, Any]) -> str:
    for reference in metadata.get("content_references") or []:
        if not isinstance(reference, dict):
            continue
        matched = reference.get("matched_text")
        if isinstance(matched, str) and matched and matched in text:
            text = text.replace(matched, reference_replacement(reference), 1)

    def fallback(match: re.Match[str]) -> str:
        kind, payload = match.groups()
        if kind == "entity":
            try:
                entity = json.loads(payload)
                if isinstance(entity, list) and len(entity) > 1:
                    return str(entity[1])
            except json.JSONDecodeError:
                pass
        if kind == "url":
            return payload.split("\ue202", 1)[0]
        return ""

    return ANNOTATION_RE.sub(fallback, text).strip()


def render_part(part: Any) -> str:
    if isinstance(part, str):
        return part
    if not isinstance(part, dict):
        return ""

    # Multimodal user messages may contain either a direct URL or an asset
    # pointer that is meaningful only inside ChatGPT.
    url = part.get("url") or part.get("image_url")
    if isinstance(url, dict):
        url = url.get("url")
    if not url:
        url = part.get("asset_pointer")
    if url:
        alt = part.get("alt") or "Image"
        return f"![{alt}]({url})"
    return str(part.get("text") or "")


def message_markdown(message: dict[str, Any]) -> str:
    content = message.get("content") or {}
    content_type = content.get("content_type")
    if content_type not in {"text", "multimodal_text"}:
        return ""
    parts = content.get("parts") or []
    text = "\n\n".join(filter(None, (render_part(part) for part in parts)))
    return clean_annotations(text, message.get("metadata") or {})


def conversation_to_markdown(conversation: dict[str, Any]) -> str:
    title = conversation.get("title", "").strip()
    output: list[str] = [f"# {title}", ""] if title else []

    for node in conversation.get("linear_conversation", []):
        if not isinstance(node, dict) or not isinstance(node.get("message"), dict):
            continue
        message = node["message"]
        role = (message.get("author") or {}).get("role")
        if role not in {"user", "assistant"}:
            continue
        body = message_markdown(message)
        if not body:
            continue
        output.extend(
            ["##### You said:" if role == "user" else "###### ChatGPT said:", "", body, ""]
        )

    if not output:
        raise RuntimeError("the share contains no exportable user or assistant messages")
    return "\n".join(output).rstrip() + "\n"


def sanitize_filename(title: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", title)
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return (name[:200] or "conversation") + ".md"


def default_output_path(title: str) -> Path:
    candidate = Path(sanitize_filename(title))
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    counter = 1
    while True:
        candidate = Path(f"{stem} ({counter}){suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Save a public ChatGPT share page as Markdown."
    )
    parser.add_argument("url", help="https://chatgpt.com/share/... URL")
    parser.add_argument("-o", "--output", type=Path, help="output file (default: title.md)")
    parser.add_argument(
        "--proxy",
        help="HTTP(S) proxy URL; requests also honors http_proxy/https_proxy automatically",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="request timeout in seconds"
    )
    parser.add_argument("-f", "--force", action="store_true", help="overwrite an existing -o file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        url = validate_share_url(args.url)
        if args.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        html = fetch_share_page(url, args.timeout, args.proxy)
        conversation = extract_conversation(html)
        markdown = conversation_to_markdown(conversation)
        output = args.output or default_output_path(conversation.get("title", ""))
        if output.exists() and not args.force:
            raise RuntimeError(f"output already exists: {output} (use --force to overwrite)")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown, encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"gptdump: error: {exc}", file=sys.stderr)
        return 1

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
