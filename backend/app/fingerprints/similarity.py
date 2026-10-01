"""Similarity primitives: SimHash, title normalisation, Jaccard and edit distance."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
_TITLE_NOISE_RE = re.compile(r"[\W_]+", re.UNICODE)


def tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def shingles(items: list[str], size: int = 3) -> list[str]:
    if len(items) < size:
        return [" ".join(items)] if items else []
    return [" ".join(items[i : i + size]) for i in range(len(items) - size + 1)]


def simhash(features: Iterable[str], bits: int = 64) -> int:
    vector = [0] * bits
    count = 0
    for feature in features:
        count += 1
        h = int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "big")
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1
    if count == 0:
        return 0
    value = 0
    for i in range(bits):
        if vector[i] > 0:
            value |= 1 << i
    return value


def simhash_hex(features: Iterable[str]) -> str:
    return f"{simhash(features):016x}"


def simhash_similarity(a: str | None, b: str | None) -> float:
    """0..1 similarity of two 64-bit hex simhashes."""
    if not a or not b:
        return 0.0
    try:
        distance = bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 0.0
    return 1.0 - distance / 64.0


def normalize_title(title: str | None) -> str:
    if not title:
        return ""
    return " ".join(_TITLE_NOISE_RE.sub(" ", title.lower()).split())


def title_hash(title: str | None) -> str | None:
    norm = normalize_title(title)
    return hashlib.sha1(norm.encode("utf-8")).hexdigest() if len(norm) >= 3 else None  # noqa: S324


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def string_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return 1.0 - levenshtein(a, b) / max(len(a), len(b))
