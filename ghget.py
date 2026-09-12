#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Download one or more files from GitHub by delegating to wget."""

from __future__ import annotations

import os
import sys
from typing import Sequence

import requests


GITHUB_HOSTS = {"github.com", "www.github.com"}
RAW_GITHUB_HOST = "raw.githubusercontent.com"
FILE_MARKERS = {"blob", "tree"}


class GitHubURLError(ValueError):
    """Raised when a URL is not a supported GitHub file URL."""


def to_raw_url(url: str) -> str:
    """Convert a github.com file URL to its raw.githubusercontent.com equivalent."""
    parsed = requests.utils.urlparse(url)

    if parsed.scheme not in {"http", "https"} or parsed.hostname not in GITHUB_HOSTS:
        raise GitHubURLError(f"not a GitHub URL: {url}")
    if parsed.username or parsed.password or parsed.port:
        raise GitHubURLError(
            f"GitHub URLs with credentials or custom ports are not supported: {url}"
        )

    # /OWNER/REPOSITORY/(blob|tree)/REVISION/PATH/TO/FILE
    parts = parsed.path.split("/")
    if len(parts) < 6 or parts[0] != "" or parts[3] not in FILE_MARKERS:
        raise GitHubURLError(
            "unsupported GitHub file URL (expected /blob/ or /tree/): " + url
        )

    owner, repository, revision = parts[1], parts[2], parts[4]
    file_parts = parts[5:]
    if not owner or not repository or not revision or not all(file_parts):
        raise GitHubURLError(f"incomplete GitHub file URL: {url}")

    raw_path = "/" + "/".join([owner, repository, revision, *file_parts])
    return requests.utils.urlunparse(
        ("https", RAW_GITHUB_HOST, raw_path, "", parsed.query, "")
    )


def translate_arguments(arguments: Sequence[str]) -> list[str]:
    """Rewrite URL arguments while leaving every wget option untouched."""
    translated: list[str] = []
    found_url = False

    for argument in arguments:
        parsed = requests.utils.urlparse(argument)
        if "://" in argument and parsed.scheme:
            found_url = True
            translated.append(to_raw_url(argument))
        else:
            translated.append(argument)

    # With no URL, defer to wget. This keeps commands such as --help and
    # --version fully compatible with wget.
    return translated if found_url else list(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    wget_arguments = translate_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        os.execvp("wget", ["wget", *wget_arguments])
    except FileNotFoundError:
        print("ghget.py: wget was not found; install wget first", file=sys.stderr)
        return 127
    except OSError as error:
        print(f"ghget.py: unable to run wget: {error}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GitHubURLError as error:
        print(f"ghget.py: {error}", file=sys.stderr)
        raise SystemExit(2)
